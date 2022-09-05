// SPDX-License-Identifier: GPL-2.0
/*
 * GXP user command interface.
 *
 * Copyright (C) 2022 Google LLC
 */

#include <linux/bitops.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <uapi/linux/sched/types.h>

#include "gxp-config.h"
#include "gxp-internal.h"
#include "gxp-mailbox.h"
#include "gxp-mailbox-driver.h"
#include "gxp-mcu.h"
#include "gxp-uci.h"
#include "gxp.h"

#define CIRCULAR_QUEUE_WRAP_BIT BIT(15)

#define MBOX_CMD_QUEUE_NUM_ENTRIES 1024
#define MBOX_RESP_QUEUE_NUM_ENTRIES 1024

static void gxp_uci_mailbox_manager_release_unconsumed_async_resps(
	struct gxp_virtual_device *vd)
{
	struct gxp_async_response *cur, *nxt;
	struct gxp_uci_async_response *uci_async_resp;
	unsigned long flags;

	/*
	 * Cleanup any unconsumed responses.
	 * Since VD is releasing, it is not necessary to lock here.
	 * Do it anyway for consistency.
	 */
	spin_lock_irqsave(&vd->mailbox_resp_queues[UCI_RESOURCE_ID].lock,
			  flags);
	list_for_each_entry_safe (
		cur, nxt, &vd->mailbox_resp_queues[UCI_RESOURCE_ID].queue,
		list_entry) {
		list_del(&cur->list_entry);
		uci_async_resp = container_of(
			cur, struct gxp_uci_async_response, async_response);
		kfree(uci_async_resp);
	}
	spin_unlock_irqrestore(&vd->mailbox_resp_queues[UCI_RESOURCE_ID].lock,
			       flags);
}

static void gxp_uci_mailbox_manager_set_ops(struct gxp_mailbox_manager *mgr)
{
	/*
	 * Most mailbox manager operators are used by the `gxp-common-platform.c` when the device
	 * uses direct mode. The only one that should be implemented among them from the UCI is the
	 * `release_unconsumed_async_resps` operator which is used by the `gxp-vd.c` in both direct
	 * and MCU mode.
	 */
	mgr->release_unconsumed_async_resps =
		gxp_uci_mailbox_manager_release_unconsumed_async_resps;
}

static u64 gxp_uci_get_cmd_elem_seq(struct gcip_mailbox *mailbox, void *cmd)
{
	struct gxp_uci_command *elem = cmd;

	return elem->seq;
}

static u32 gxp_uci_get_cmd_elem_code(struct gcip_mailbox *mailbox, void *cmd)
{
	struct gxp_uci_command *elem = cmd;

	return (u32)elem->type;
}

static void gxp_uci_set_cmd_elem_seq(struct gcip_mailbox *mailbox, void *cmd,
				     u64 seq)
{
	struct gxp_uci_command *elem = cmd;

	elem->seq = seq;
}

static u64 gxp_uci_get_resp_elem_seq(struct gcip_mailbox *mailbox, void *resp)
{
	struct gxp_uci_response *elem = resp;

	return elem->seq;
}

static void gxp_uci_set_resp_elem_seq(struct gcip_mailbox *mailbox, void *resp,
				      u64 seq)
{
	struct gxp_uci_response *elem = resp;

	elem->seq = seq;
}

static u16 gxp_uci_get_resp_elem_status(struct gcip_mailbox *mailbox,
					void *resp)
{
	struct gxp_uci_response *elem = resp;

	return elem->code;
}

static void gxp_uci_set_resp_elem_status(struct gcip_mailbox *mailbox,
					 void *resp, u16 status)
{
	struct gxp_uci_response *elem = resp;

	elem->code = status;
}

static void gxp_uci_handle_async_resp_arrived(
	struct gcip_mailbox *mailbox,
	struct gcip_mailbox_async_response *async_gcip_resp)
{
	struct gxp_uci_async_response *async_uci_resp = async_gcip_resp->data;
	struct gxp_async_response *async_resp = &async_uci_resp->async_response;
	unsigned long flags;

	/*
	 * If dest_queue is a null pointer, it means we don't care the response
	 * of the command. Skip it.
	 */
	if (!async_resp->dest_queue)
		return;

	spin_lock_irqsave(async_resp->dest_queue_lock, flags);

	list_add_tail(&async_resp->list_entry, async_resp->dest_queue);
	/*
	 * Marking the dest_queue as NULL indicates the
	 * response was handled in case its timeout
	 * handler fired between acquiring the
	 * wait_list_lock and cancelling the timeout.
	 */
	async_resp->dest_queue = NULL;

	if (async_resp->eventfd) {
		gxp_eventfd_signal(async_resp->eventfd);
		gxp_eventfd_put(async_resp->eventfd);
	}

	wake_up(async_resp->dest_queue_waitq);

	spin_unlock_irqrestore(async_resp->dest_queue_lock, flags);
}

static void gxp_uci_handle_async_resp_timedout(
	struct gcip_mailbox *mailbox,
	struct gcip_mailbox_async_response *async_gcip_resp)
{
	struct gxp_uci_async_response *async_uci_resp = async_gcip_resp->data;
	struct gxp_async_response *async_resp = &async_uci_resp->async_response;
	unsigned long flags;

	/*
	 * Check if this response still has a valid destination queue. While an in-progress call
	 * the `gxp_uci_handle_async_resp_arrived()` callback to handle the response and remove
	 * it from the wait_list with holding the wait_list_lock, the timeout can be expired and it
	 * will try to remove the response from the wait_list waiting for acquiring the
	 * wait_list_lock. If this happens, this callback will be called with the destination queue
	 * of response as a NULL, otherwise as not NULL.
	 */
	spin_lock_irqsave(async_resp->dest_queue_lock, flags);
	if (async_resp->dest_queue) {
		async_uci_resp->resp.code = GXP_RESP_CANCELLED;
		list_add_tail(&async_resp->list_entry, async_resp->dest_queue);
		spin_unlock_irqrestore(async_resp->dest_queue_lock, flags);

		if (async_resp->eventfd) {
			gxp_eventfd_signal(async_resp->eventfd);
			gxp_eventfd_put(async_resp->eventfd);
		}

		wake_up(async_resp->dest_queue_waitq);
	} else {
		spin_unlock_irqrestore(async_resp->dest_queue_lock, flags);
	}
}

static void
gxp_uci_flush_async_resp(struct gcip_mailbox *mailbox,
			 struct gcip_mailbox_async_response *async_gcip_resp)
{
	struct gxp_uci_async_response *async_uci_resp = async_gcip_resp->data;
	struct gxp_async_response *async_resp = &async_uci_resp->async_response;
	unsigned long flags;

	spin_lock_irqsave(async_resp->dest_queue_lock, flags);
	async_resp->dest_queue = NULL;
	spin_unlock_irqrestore(async_resp->dest_queue_lock, flags);
}

static void gxp_uci_release_async_resp_data(void *data)
{
	struct gxp_uci_async_response *async_uci_resp = data;

	kfree(async_uci_resp);
}

static const struct gcip_mailbox_ops gxp_uci_gcip_mbx_ops = {
	.get_cmd_queue_head = gxp_mailbox_gcip_ops_get_cmd_queue_head,
	.get_cmd_queue_tail = gxp_mailbox_gcip_ops_get_cmd_queue_tail,
	.inc_cmd_queue_tail = gxp_mailbox_gcip_ops_inc_cmd_queue_tail,
	.acquire_cmd_queue_lock = gxp_mailbox_gcip_ops_acquire_cmd_queue_lock,
	.release_cmd_queue_lock = gxp_mailbox_gcip_ops_release_cmd_queue_lock,
	.get_cmd_elem_seq = gxp_uci_get_cmd_elem_seq,
	.set_cmd_elem_seq = gxp_uci_set_cmd_elem_seq,
	.get_cmd_elem_code = gxp_uci_get_cmd_elem_code,
	.get_resp_queue_size = gxp_mailbox_gcip_ops_get_resp_queue_size,
	.get_resp_queue_head = gxp_mailbox_gcip_ops_get_resp_queue_head,
	.get_resp_queue_tail = gxp_mailbox_gcip_ops_get_resp_queue_tail,
	.inc_resp_queue_head = gxp_mailbox_gcip_ops_inc_resp_queue_head,
	.acquire_resp_queue_lock = gxp_mailbox_gcip_ops_acquire_resp_queue_lock,
	.release_resp_queue_lock = gxp_mailbox_gcip_ops_release_resp_queue_lock,
	.get_resp_elem_seq = gxp_uci_get_resp_elem_seq,
	.set_resp_elem_seq = gxp_uci_set_resp_elem_seq,
	.get_resp_elem_status = gxp_uci_get_resp_elem_status,
	.set_resp_elem_status = gxp_uci_set_resp_elem_status,
	.acquire_wait_list_lock = gxp_mailbox_gcip_ops_acquire_wait_list_lock,
	.release_wait_list_lock = gxp_mailbox_gcip_ops_release_wait_list_lock,
	.wait_for_cmd_queue_not_full =
		gxp_mailbox_gcip_ops_wait_for_cmd_queue_not_full,
	.after_enqueue_cmd = gxp_mailbox_gcip_ops_after_enqueue_cmd,
	.after_fetch_resps = gxp_mailbox_gcip_ops_after_fetch_resps,
	.handle_async_resp_arrived = gxp_uci_handle_async_resp_arrived,
	.handle_async_resp_timedout = gxp_uci_handle_async_resp_timedout,
	.flush_async_resp = gxp_uci_flush_async_resp,
	.release_async_resp_data = gxp_uci_release_async_resp_data,
};

static int gxp_uci_allocate_resources(struct gxp_mailbox *mailbox,
				      struct gxp_virtual_device *vd,
				      uint virt_core)
{
	struct gxp_uci *uci = mailbox->data;
	struct gxp_mcu *mcu = uci->mcu;
	int ret;

	/* Allocate and initialize the command queue */
	ret = gxp_mcu_mem_alloc_data(mcu, &uci->cmd_queue_mem,
				     sizeof(struct gxp_uci_command) *
					     MBOX_CMD_QUEUE_NUM_ENTRIES);
	if (ret)
		goto err_cmd_queue;
	mailbox->cmd_queue = uci->cmd_queue_mem.vaddr;
	mailbox->cmd_queue_device_addr = uci->cmd_queue_mem.daddr;
	mailbox->cmd_queue_size = MBOX_CMD_QUEUE_NUM_ENTRIES;
	mailbox->cmd_queue_tail = 0;

	/* Allocate and initialize the response queue */
	ret = gxp_mcu_mem_alloc_data(mcu, &uci->resp_queue_mem,
				     sizeof(struct gxp_uci_response) *
					     MBOX_RESP_QUEUE_NUM_ENTRIES);
	if (ret)
		goto err_resp_queue;
	mailbox->resp_queue = uci->resp_queue_mem.vaddr;
	mailbox->resp_queue_device_addr = uci->resp_queue_mem.daddr;
	mailbox->resp_queue_size = MBOX_RESP_QUEUE_NUM_ENTRIES;
	mailbox->resp_queue_head = 0;

	/* Allocate and initialize the mailbox descriptor */
	ret = gxp_mcu_mem_alloc_data(mcu, &uci->descriptor_mem,
				     sizeof(struct gxp_mailbox_descriptor));
	if (ret)
		goto err_descriptor;

	mailbox->descriptor = uci->descriptor_mem.vaddr;
	mailbox->descriptor_device_addr = uci->descriptor_mem.daddr;
	mailbox->descriptor->cmd_queue_device_addr = uci->cmd_queue_mem.daddr;
	mailbox->descriptor->resp_queue_device_addr = uci->resp_queue_mem.daddr;
	mailbox->descriptor->cmd_queue_size = mailbox->cmd_queue_size;
	mailbox->descriptor->resp_queue_size = mailbox->resp_queue_size;

	return 0;

err_descriptor:
	gxp_mcu_mem_free_data(mcu, &uci->resp_queue_mem);
err_resp_queue:
	gxp_mcu_mem_free_data(mcu, &uci->cmd_queue_mem);
err_cmd_queue:
	return -ENOMEM;
}

static void gxp_uci_release_resources(struct gxp_mailbox *mailbox,
				      struct gxp_virtual_device *vd,
				      uint virt_core)
{
	struct gxp_uci *uci = mailbox->data;

	gxp_mcu_mem_free_data(uci->mcu, &uci->descriptor_mem);
	gxp_mcu_mem_free_data(uci->mcu, &uci->resp_queue_mem);
	gxp_mcu_mem_free_data(uci->mcu, &uci->cmd_queue_mem);
}

static int gxp_uci_init_consume_responses_work(struct gxp_mailbox *mailbox)
{
	struct gxp_uci *uci = mailbox->data;
	struct gcip_mailbox_args args = {
		.dev = mailbox->gxp->dev,
		.queue_wrap_bit = CIRCULAR_QUEUE_WRAP_BIT,
		.cmd_queue = mailbox->cmd_queue,
		.cmd_elem_size = sizeof(struct gxp_uci_command),
		.resp_queue = mailbox->resp_queue,
		.resp_elem_size = sizeof(struct gxp_uci_response),
		.timeout = MAILBOX_TIMEOUT,
		.ops = &gxp_uci_gcip_mbx_ops,
		.data = mailbox,
	};
	int ret;

	uci->gcip_mbx = kzalloc(sizeof(*uci->gcip_mbx), GFP_KERNEL);
	if (!uci->gcip_mbx)
		return -ENOMEM;

	/* Initialize gcip_mailbox */
	ret = gcip_mailbox_init(uci->gcip_mbx, &args);
	if (ret) {
		kfree(uci->gcip_mbx);
		return ret;
	}

	return 0;
}

static void gxp_uci_release_consume_responses_work(struct gxp_mailbox *mailbox)
{
	struct gxp_uci *uci = mailbox->data;

	/* Release gcip_mailbox */
	gcip_mailbox_release(uci->gcip_mbx);
	kfree(uci->gcip_mbx);
}

static void gxp_uci_consume_responses_work(struct gxp_mailbox *mailbox)
{
	struct gxp_uci *uci = mailbox->data;

	gcip_mailbox_consume_responses_work(uci->gcip_mbx);
}

static struct gxp_mailbox_ops gxp_uci_gxp_mbx_ops = {
	.allocate_resources = gxp_uci_allocate_resources,
	.release_resources = gxp_uci_release_resources,
	.init_consume_responses_work = gxp_uci_init_consume_responses_work,
	.release_consume_responses_work =
		gxp_uci_release_consume_responses_work,
	.consume_responses_work = gxp_uci_consume_responses_work,
};

int gxp_uci_init(struct gxp_mcu *mcu)
{
	struct gxp_dev *gxp = mcu->gxp;
	struct gxp_uci *uci = &mcu->uci;
	struct gxp_mailbox_args mbx_args = {
		.ops = &gxp_uci_gxp_mbx_ops,
		.data = uci,
	};

	uci->gxp = gxp;
	uci->mcu = mcu;
	uci->gxp_mbx = gxp_mailbox_alloc(gxp->mailbox_mgr, NULL, 0,
					 UCI_MAILBOX_ID, &mbx_args);
	if (IS_ERR(uci->gxp_mbx))
		return PTR_ERR(uci->gxp_mbx);
	gxp_uci_mailbox_manager_set_ops(gxp->mailbox_mgr);

	return 0;
}

void gxp_uci_exit(struct gxp_uci *uci)
{
	gxp_mailbox_release(uci->gxp->mailbox_mgr, NULL, 0, uci->gxp_mbx);
	uci->gxp_mbx = NULL;
}

int gxp_uci_send_command(struct gxp_uci *uci, struct gxp_uci_command *cmd,
			 struct list_head *resp_queue, spinlock_t *queue_lock,
			 wait_queue_head_t *queue_waitq,
			 struct gxp_eventfd *eventfd)
{
	struct gxp_uci_async_response *async_uci_resp;
	struct gxp_async_response *async_resp;
	int ret;

	async_uci_resp = kzalloc(sizeof(*async_uci_resp), GFP_KERNEL);
	if (!async_uci_resp)
		return -ENOMEM;

	async_resp = &async_uci_resp->async_response;
	async_uci_resp->uci = uci;

	/*
	 * If the command is a wakelock command, keep dest_queue as a null
	 * pointer to indicate that we will not expose the response to the
	 * client.
	 */
	if (cmd->type != WAKELOCK_COMMAND)
		async_resp->dest_queue = resp_queue;
	async_resp->dest_queue_lock = queue_lock;
	async_resp->dest_queue_waitq = queue_waitq;
	if (eventfd && gxp_eventfd_get(eventfd))
		async_resp->eventfd = eventfd;
	else
		async_resp->eventfd = NULL;

	async_uci_resp->async_gcip_resp = gcip_mailbox_put_cmd(
		uci->gcip_mbx, cmd, &async_uci_resp->resp, async_uci_resp);
	if (IS_ERR(async_uci_resp->async_gcip_resp)) {
		ret = PTR_ERR(async_uci_resp->async_gcip_resp);
		goto err_free_resp;
	}

	return 0;

err_free_resp:
	kfree(async_uci_resp);
	return ret;
}

int gxp_uci_wait_async_response(struct mailbox_resp_queue *uci_resp_queue,
				u64 *resp_seq, u32 *resp_retval,
				u16 *error_code)
{
	long timeout;
	struct gxp_async_response *async_resp;
	struct gxp_uci_async_response *uci_async_resp;

	spin_lock_irq(&uci_resp_queue->lock);

	/*
	 * The "exclusive" version of wait_event is used since each wake
	 * corresponds to the addition of exactly one new response to be
	 * consumed. Therefore, only one waiting responsecan ever proceed
	 * per wake event.
	 */
	timeout = wait_event_interruptible_lock_irq_timeout_exclusive(
		uci_resp_queue->waitq, !list_empty(&uci_resp_queue->queue),
		uci_resp_queue->lock, msecs_to_jiffies(MAILBOX_TIMEOUT));
	if (timeout <= 0) {
		spin_unlock_irq(&uci_resp_queue->lock);
		/* unusual case - this only happens when there is no command pushed */
		return timeout ? -ETIMEDOUT : timeout;
	}
	async_resp = list_first_entry(&uci_resp_queue->queue,
				      struct gxp_async_response, list_entry);
	uci_async_resp = container_of(async_resp, struct gxp_uci_async_response,
				      async_response);

	/* Pop the front of the response list */
	list_del(&(async_resp->list_entry));

	spin_unlock_irq(&uci_resp_queue->lock);

	*resp_seq = uci_async_resp->resp.seq;
	switch (uci_async_resp->resp.code) {
	case GXP_RESP_OK:
		*error_code = GXP_RESPONSE_ERROR_NONE;
		/* payload is only valid if code == GXP_RESP_OK */
		*resp_retval = uci_async_resp->resp.payload;
		break;
	case GXP_RESP_CANCELLED:
		*error_code = GXP_RESPONSE_ERROR_TIMEOUT;
		break;
	default:
		/* No other code values are valid at this point */
		dev_err(uci_async_resp->uci->gxp->dev,
			"Completed response had invalid code %hu\n",
			uci_async_resp->resp.code);
		*error_code = GXP_RESPONSE_ERROR_INTERNAL;
		break;
	}

	/*
	 * We must be absolutely sure the timeout work has been cancelled
	 * and/or completed before freeing the async response object.
	 * There are 3 possible cases when we arrive at this point:
	 *   1) The response arrived normally and the timeout was cancelled
	 *   2) The response timedout and its timeout handler finished
	 *   3) The response handler and timeout handler raced, and the response
	 *      handler "cancelled" the timeout handler while it was already in
	 *      progress.
	 *
	 * This call handles case #3, and ensures any in-process timeout
	 * handler (which may reference the `gxp_async_response`) has
	 * been able to exit cleanly.
	 */
	gcip_mailbox_cancel_async_resp_timeout(uci_async_resp->async_gcip_resp);
	gcip_mailbox_release_async_resp(uci_async_resp->async_gcip_resp);

	return 0;
}
