// SPDX-License-Identifier: GPL-2.0
/*
 * GXP mailbox.
 *
 * Copyright (C) 2021 Google LLC
 */

#include <linux/bitops.h>
#include <linux/dma-mapping.h>
#include <linux/io.h>
#include <linux/iommu.h>
#include <linux/kthread.h>
#include <linux/moduleparam.h>
#include <linux/slab.h>
#include <uapi/linux/sched/types.h>

#include "gxp-dma.h"
#include "gxp-internal.h"
#include "gxp-mailbox.h"
#include "gxp-mailbox-driver.h"
#include "gxp-pm.h"
#include "gxp.h"

/*
 * TODO(b/237908672): gxp-mailbox must be able to be compiled without gcip-mailbox on the old
 * chip.
 */

/* Timeout of 8s by default to account for slower emulation platforms */
int gxp_mbx_timeout = 8000;
module_param_named(mbx_timeout, gxp_mbx_timeout, int, 0660);

#define CIRCULAR_QUEUE_WRAP_BIT BIT(15)

#define MBOX_CMD_QUEUE_NUM_ENTRIES 1024
#define MBOX_CMD_QUEUE_SIZE                                                    \
	(sizeof(struct gxp_command) * MBOX_CMD_QUEUE_NUM_ENTRIES)

#define MBOX_RESP_QUEUE_NUM_ENTRIES 1024
#define MBOX_RESP_QUEUE_SIZE                                                   \
	(sizeof(struct gxp_response) * MBOX_RESP_QUEUE_NUM_ENTRIES)

/*
 * Following codes are the implementation of the mailbox manager for the legacy mailbox. They will
 * be compiled only when the `GXP_HAS_DCI` is not defined.
 */

#ifndef GXP_HAS_DCI

static struct gxp_mailbox *
gxp_mailbox_manager_allocate_mailbox(struct gxp_mailbox_manager *mgr,
				     struct gxp_virtual_device *vd,
				     uint virt_core, u8 core_id)
{
	struct gxp_mailbox *mailbox = gxp_mailbox_alloc(
		mgr, vd, virt_core, core_id, &gxp_mailbox_default_args);

	if (!IS_ERR(mailbox))
		gxp_mailbox_generate_device_interrupt(mailbox, BIT(0));
	return mailbox;
}

static int gxp_mailbox_manager_execute_cmd(struct gxp_mailbox *mailbox,
					   u16 cmd_code, u8 cmd_priority,
					   u64 cmd_daddr, u32 cmd_size,
					   u32 cmd_flags, u64 *resp_seq,
					   u16 *resp_status)
{
	struct gxp_command cmd;
	struct gxp_response resp;
	struct buffer_descriptor buffer;
	int ret;

	/* Pack the command structure */
	buffer.address = cmd_daddr;
	buffer.size = cmd_size;
	buffer.flags = cmd_flags;
	/* cmd.seq is assigned by mailbox implementation */
	cmd.code = cmd_code; /* All IOCTL commands are dispatch */
	cmd.priority = cmd_priority; /* currently unused */
	cmd.buffer_descriptor = buffer;

	ret = gxp_mailbox_execute_cmd(mailbox, &cmd, &resp);

	/* resp.seq and resp.status can be updated even though it failed to process the command */
	if (resp_seq)
		*resp_seq = resp.seq;
	if (resp_status)
		*resp_status = resp.status;

	return ret;
}

static int gxp_mailbox_manager_execute_cmd_async(
	struct gxp_client *client, struct gxp_mailbox *mailbox, int virt_core,
	u16 cmd_code, u8 cmd_priority, u64 cmd_daddr, u32 cmd_size,
	u32 cmd_flags, struct gxp_power_states power_states, u64 *cmd_seq)
{
	struct gxp_command cmd;
	struct buffer_descriptor buffer;
	struct mailbox_resp_queue *resp_queue =
		&client->vd->mailbox_resp_queues[virt_core];
	struct gxp_eventfd *eventfd = client->mb_eventfds[virt_core];
	int ret;

	/* Pack the command structure */
	buffer.address = cmd_daddr;
	buffer.size = cmd_size;
	buffer.flags = cmd_flags;
	/* cmd.seq is assigned by mailbox implementation */
	cmd.code = cmd_code; /* All IOCTL commands are dispatch */
	cmd.priority = cmd_priority; /* currently unused */
	cmd.buffer_descriptor = buffer;

	ret = gxp_mailbox_execute_cmd_async(mailbox, &cmd, &resp_queue->queue,
					    &resp_queue->lock,
					    &resp_queue->waitq, power_states,
					    eventfd);

	if (cmd_seq)
		*cmd_seq = cmd.seq;

	return ret;
}

static int gxp_mailbox_manager_wait_async_resp(struct gxp_client *client,
					       int virt_core, u64 *resp_seq,
					       u16 *resp_status,
					       u32 *resp_retval,
					       u16 *error_code)
{
	struct gxp_async_response *resp_ptr;
	struct mailbox_resp_queue *resp_queue =
		&client->vd->mailbox_resp_queues[virt_core];
	long timeout;

	spin_lock_irq(&resp_queue->lock);

	/*
	 * The "exclusive" version of wait_event is used since each wake
	 * corresponds to the addition of exactly one new response to be
	 * consumed. Therefore, only one waiting response ioctl can ever
	 * proceed per wake event.
	 */
	timeout = wait_event_interruptible_lock_irq_timeout_exclusive(
		resp_queue->waitq, !list_empty(&resp_queue->queue),
		resp_queue->lock, msecs_to_jiffies(MAILBOX_TIMEOUT));
	if (timeout <= 0) {
		spin_unlock_irq(&resp_queue->lock);
		/* unusual case - this only happens when there is no command pushed */
		return timeout ? -ETIMEDOUT : timeout;
	}
	resp_ptr = list_first_entry(&resp_queue->queue,
				    struct gxp_async_response, list_entry);

	/* Pop the front of the response list */
	list_del(&(resp_ptr->list_entry));

	spin_unlock_irq(&resp_queue->lock);

	if (resp_seq)
		*resp_seq = resp_ptr->resp.seq;
	if (resp_status)
		*resp_status = resp_ptr->resp.status;

	switch (resp_ptr->resp.status) {
	case GXP_RESP_OK:
		if (error_code)
			*error_code = GXP_RESPONSE_ERROR_NONE;
		/* retval is only valid if status == GXP_RESP_OK */
		if (resp_retval)
			*resp_retval = resp_ptr->resp.retval;
		break;
	case GXP_RESP_CANCELLED:
		if (error_code)
			*error_code = GXP_RESPONSE_ERROR_TIMEOUT;
		break;
	default:
		/* No other status values are valid at this point */
		WARN(true, "Completed response had invalid status %hu",
		     resp_ptr->resp.status);
		if (error_code)
			*error_code = GXP_RESPONSE_ERROR_INTERNAL;
		break;
	}

	/*
	 * We must be absolutely sure the timeout work has been cancelled
	 * and/or completed before freeing the `gxp_async_response`.
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
	cancel_delayed_work_sync(&resp_ptr->timeout_work);
	kfree(resp_ptr);

	return 0;
}

static void gxp_mailbox_manager_release_unconsumed_async_resps(
	struct gxp_virtual_device *vd)
{
	struct gxp_async_response *cur, *nxt;
	int i;
	unsigned long flags;

	/* Cleanup any unconsumed responses */
	for (i = 0; i < vd->num_cores; i++) {
		/*
		 * Since VD is releasing, it is not necessary to lock here.
		 * Do it anyway for consistency.
		 */
		spin_lock_irqsave(&vd->mailbox_resp_queues[i].lock, flags);
		list_for_each_entry_safe (cur, nxt,
					  &vd->mailbox_resp_queues[i].queue,
					  list_entry) {
			list_del(&cur->list_entry);
			kfree(cur);
		}
		spin_unlock_irqrestore(&vd->mailbox_resp_queues[i].lock, flags);
	}
}

static void gxp_mailbox_manager_set_ops(struct gxp_mailbox_manager *mgr)
{
	mgr->allocate_mailbox = gxp_mailbox_manager_allocate_mailbox;
	mgr->release_mailbox = gxp_mailbox_release;
	mgr->reset_mailbox = gxp_mailbox_reset;
	mgr->execute_cmd = gxp_mailbox_manager_execute_cmd;
	mgr->execute_cmd_async = gxp_mailbox_manager_execute_cmd_async;
	mgr->wait_async_resp = gxp_mailbox_manager_wait_async_resp;
	mgr->release_unconsumed_async_resps =
		gxp_mailbox_manager_release_unconsumed_async_resps;
}
#endif /* !GXP_HAS_DCI */

/*
 * Fetches and handles responses, then wakes up threads that are waiting for a
 * response.
 *
 * Note: this worker is scheduled in the IRQ handler, to prevent use-after-free
 * or race-condition bugs, gxp_mailbox_release() must be called before free the
 * mailbox.
 */
static void gxp_mailbox_consume_responses_work(struct kthread_work *work)
{
	struct gxp_mailbox *mailbox =
		container_of(work, struct gxp_mailbox, response_work);
	mailbox->ops->consume_responses_work(mailbox);
}

/*
 * IRQ handler of GXP mailbox.
 *
 * Puts the gxp_mailbox_consume_responses_work() into the system work queue.
 */
static inline void gxp_mailbox_handle_irq(struct gxp_mailbox *mailbox)
{
	kthread_queue_work(&mailbox->response_worker, &mailbox->response_work);
}

/* Priority level for realtime worker threads */
#define GXP_RT_THREAD_PRIORITY 2
static struct task_struct *create_response_rt_thread(struct device *dev,
						     void *data, int core_id)
{
	static const struct sched_param param = {
		.sched_priority = GXP_RT_THREAD_PRIORITY,
	};
	struct task_struct *task = kthread_create(kthread_worker_fn, data,
						  "gxp_response_%d", core_id);

	if (!IS_ERR(task)) {
		wake_up_process(task);
		if (sched_setscheduler(task, SCHED_FIFO, &param))
			dev_warn(dev, "response task %d not set to RT prio",
				 core_id);
		else
			dev_dbg(dev, "response task %d set to RT prio: %i",
				core_id, param.sched_priority);
	}

	return task;
}

static int gxp_mailbox_set_ops(struct gxp_mailbox *mailbox,
			       struct gxp_mailbox_ops *ops)
{
	if (!ops) {
		dev_err(mailbox->gxp->dev, "Incomplete gxp_mailbox ops.\n");
		return -EINVAL;
	}

	if (!ops->init_consume_responses_work ||
	    !ops->release_consume_responses_work ||
	    !ops->consume_responses_work) {
		dev_err(mailbox->gxp->dev,
			"Incomplete gxp_mailbox consume_responses_work ops.\n");
		return -EINVAL;
	}

	mailbox->ops = ops;

	return 0;
}

static inline void gxp_mailbox_set_data(struct gxp_mailbox *mailbox, void *data)
{
	mailbox->data = data;
}

static struct gxp_mailbox *create_mailbox(struct gxp_mailbox_manager *mgr,
					  struct gxp_virtual_device *vd,
					  uint virt_core, u8 core_id,
					  const struct gxp_mailbox_args *args)
{
	struct gxp_mailbox *mailbox;
	int ret;

	if (!args) {
		dev_err(mgr->gxp->dev, "Incomplete gxp_mailbox args.\n");
		ret = -EINVAL;
		goto err_args;
	}

	mailbox = kzalloc(sizeof(*mailbox), GFP_KERNEL);
	if (!mailbox) {
		ret = -ENOMEM;
		goto err_mailbox;
	}

	mailbox->core_id = core_id;
	mailbox->gxp = mgr->gxp;
	mailbox->csr_reg_base = mgr->get_mailbox_csr_base(mgr->gxp, core_id);
	mailbox->data_reg_base = mgr->get_mailbox_data_base(mgr->gxp, core_id);
	gxp_mailbox_set_data(mailbox, args->data);

	ret = gxp_mailbox_set_ops(mailbox, args->ops);
	if (ret)
		goto err_set_ops;

	ret = mailbox->ops->allocate_resources(mailbox, vd, virt_core);
	if (ret)
		goto err_allocate_resources;

	mutex_init(&mailbox->cmd_queue_lock);
	mutex_init(&mailbox->resp_queue_lock);
	kthread_init_worker(&mailbox->response_worker);
	mailbox->response_thread = create_response_rt_thread(
		mailbox->gxp->dev, &mailbox->response_worker, core_id);
	if (IS_ERR(mailbox->response_thread)) {
		ret = -ENOMEM;
		goto err_thread;
	}

	/* Initialize driver before interacting with its registers */
	gxp_mailbox_driver_init(mailbox);

	return mailbox;

err_thread:
	mailbox->ops->release_resources(mailbox, vd, virt_core);
err_allocate_resources:
err_set_ops:
	kfree(mailbox);
err_mailbox:
err_args:
	return ERR_PTR(ret);
}

static void release_mailbox(struct gxp_mailbox *mailbox,
			    struct gxp_virtual_device *vd, uint virt_core)
{
	mailbox->ops->release_resources(mailbox, vd, virt_core);
	kthread_flush_worker(&mailbox->response_worker);
	if (mailbox->response_thread)
		kthread_stop(mailbox->response_thread);
	kfree(mailbox);
}

static int enable_mailbox(struct gxp_mailbox *mailbox)
{
	int ret;

	gxp_mailbox_write_descriptor(mailbox, mailbox->descriptor_device_addr);
	gxp_mailbox_write_cmd_queue_head(mailbox, 0);
	gxp_mailbox_write_cmd_queue_tail(mailbox, 0);
	gxp_mailbox_write_resp_queue_head(mailbox, 0);
	gxp_mailbox_write_resp_queue_tail(mailbox, 0);

	ret = mailbox->ops->init_consume_responses_work(mailbox);
	if (ret)
		return ret;

	mailbox->handle_irq = gxp_mailbox_handle_irq;
	mutex_init(&mailbox->wait_list_lock);
	kthread_init_work(&mailbox->response_work,
			  gxp_mailbox_consume_responses_work);

	/* Only enable interrupts once everything has been setup */
	gxp_mailbox_driver_enable_interrupts(mailbox);
	/* Enable the mailbox */
	gxp_mailbox_write_status(mailbox, 1);

	return 0;
}

struct gxp_mailbox *gxp_mailbox_alloc(struct gxp_mailbox_manager *mgr,
				      struct gxp_virtual_device *vd,
				      uint virt_core, u8 core_id,
				      const struct gxp_mailbox_args *args)
{
	struct gxp_mailbox *mailbox;
	int ret;

	mailbox = create_mailbox(mgr, vd, virt_core, core_id, args);
	if (IS_ERR(mailbox))
		return mailbox;

	ret = enable_mailbox(mailbox);
	if (ret) {
		release_mailbox(mailbox, vd, virt_core);
		return ERR_PTR(ret);
	}

	return mailbox;
}

void gxp_mailbox_release(struct gxp_mailbox_manager *mgr,
			 struct gxp_virtual_device *vd, uint virt_core,
			 struct gxp_mailbox *mailbox)
{
	int i;

	if (!mailbox) {
		dev_err(mgr->gxp->dev,
			"Attempt to release nonexistent mailbox\n");
		return;
	}

	/*
	 * Halt the mailbox driver by preventing any incoming requests..
	 * This must happen before the mailbox itself is cleaned-up/released
	 * to make sure the mailbox does not disappear out from under the
	 * mailbox driver. This also halts all incoming responses/interrupts.
	 */
	gxp_mailbox_driver_disable_interrupts(mailbox);

	/* Halt and flush any traffic */
	kthread_cancel_work_sync(&mailbox->response_work);
	for (i = 0; i < GXP_MAILBOX_INT_BIT_COUNT; i++) {
		if (mailbox->interrupt_handlers[i])
			cancel_work_sync(mailbox->interrupt_handlers[i]);
	}

	mailbox->ops->release_consume_responses_work(mailbox);

	/* Reset the mailbox HW */
	gxp_mailbox_reset_hw(mailbox);

	/* Cleanup now that all mailbox interactions are finished */
	gxp_mailbox_driver_exit(mailbox);

	/*
	 * At this point all users of the mailbox have been halted or are
	 * waiting on gxp->vd_semaphore, which this function's caller has
	 * locked for writing.
	 * It is now safe to clear the manager's mailbox pointer.
	 */
	mgr->mailboxes[mailbox->core_id] = NULL;

	/* Clean up resources */
	release_mailbox(mailbox, vd, virt_core);
}

void gxp_mailbox_reset(struct gxp_mailbox *mailbox)
{
	dev_notice(mailbox->gxp->dev, "%s not yet implemented\n", __func__);
}

int gxp_mailbox_register_interrupt_handler(struct gxp_mailbox *mailbox,
					   u32 int_bit,
					   struct work_struct *handler)
{
	/* Bit 0 is reserved for incoming mailbox responses */
	if (int_bit == 0 || int_bit >= GXP_MAILBOX_INT_BIT_COUNT)
		return -EINVAL;

	mailbox->interrupt_handlers[int_bit] = handler;

	return 0;
}

int gxp_mailbox_unregister_interrupt_handler(struct gxp_mailbox *mailbox,
					     u32 int_bit)
{
	/* Bit 0 is reserved for incoming mailbox responses */
	if (int_bit == 0 || int_bit >= GXP_MAILBOX_INT_BIT_COUNT)
		return -EINVAL;

	mailbox->interrupt_handlers[int_bit] = NULL;

	return 0;
}

/*
 * Following codes are the implementation of legacy mailbox. They will be compiled only when the
 * `GXP_HAS_DCI` is not defined. The logic is identical with before refactoring but the only one
 * difference is that the interface of `gxp_mailbox_ops` and `gxp_mailbox_args` are applied.
 */

#ifndef GXP_HAS_DCI
static int gxp_mailbox_ops_allocate_resources(struct gxp_mailbox *mailbox,
					      struct gxp_virtual_device *vd,
					      uint virt_core)
{
	/* Allocate and initialize the command queue */
	mailbox->cmd_queue = (struct gxp_command *)gxp_dma_alloc_coherent(
		mailbox->gxp, vd->domain,
		sizeof(struct gxp_command) * MBOX_CMD_QUEUE_NUM_ENTRIES,
		&(mailbox->cmd_queue_device_addr), GFP_KERNEL, 0);
	if (!mailbox->cmd_queue)
		goto err_cmd_queue;

	mailbox->cmd_queue_size = MBOX_CMD_QUEUE_NUM_ENTRIES;
	mailbox->cmd_queue_tail = 0;

	/* Allocate and initialize the response queue */
	mailbox->resp_queue = (struct gxp_response *)gxp_dma_alloc_coherent(
		mailbox->gxp, vd->domain,
		sizeof(struct gxp_response) * MBOX_RESP_QUEUE_NUM_ENTRIES,
		&(mailbox->resp_queue_device_addr), GFP_KERNEL, 0);
	if (!mailbox->resp_queue)
		goto err_resp_queue;

	mailbox->resp_queue_size = MBOX_RESP_QUEUE_NUM_ENTRIES;
	mailbox->resp_queue_head = 0;

	/* Allocate and initialize the mailbox descriptor */
	mailbox->descriptor =
		(struct gxp_mailbox_descriptor *)gxp_dma_alloc_coherent(
			mailbox->gxp, vd->domain,
			sizeof(struct gxp_mailbox_descriptor),
			&(mailbox->descriptor_device_addr), GFP_KERNEL, 0);
	if (!mailbox->descriptor)
		goto err_descriptor;

	mailbox->descriptor->cmd_queue_device_addr =
		mailbox->cmd_queue_device_addr;
	mailbox->descriptor->resp_queue_device_addr =
		mailbox->resp_queue_device_addr;
	mailbox->descriptor->cmd_queue_size = mailbox->cmd_queue_size;
	mailbox->descriptor->resp_queue_size = mailbox->resp_queue_size;

	return 0;

err_descriptor:
	gxp_dma_free_coherent(
		mailbox->gxp, vd->domain,
		sizeof(struct gxp_response) * mailbox->resp_queue_size,
		mailbox->resp_queue, mailbox->resp_queue_device_addr);
err_resp_queue:
	gxp_dma_free_coherent(
		mailbox->gxp, vd->domain,
		sizeof(struct gxp_command) * mailbox->cmd_queue_size,
		mailbox->cmd_queue, mailbox->cmd_queue_device_addr);
err_cmd_queue:
	return -ENOMEM;
}

static void gxp_mailbox_ops_release_resources(struct gxp_mailbox *mailbox,
					      struct gxp_virtual_device *vd,
					      uint virt_core)
{
	gxp_dma_free_coherent(
		mailbox->gxp, vd->domain,
		sizeof(struct gxp_command) * mailbox->cmd_queue_size,
		mailbox->cmd_queue, mailbox->cmd_queue_device_addr);
	gxp_dma_free_coherent(
		mailbox->gxp, vd->domain,
		sizeof(struct gxp_response) * mailbox->resp_queue_size,
		mailbox->resp_queue, mailbox->resp_queue_device_addr);
	gxp_dma_free_coherent(mailbox->gxp, vd->domain,
			      sizeof(struct gxp_mailbox_descriptor),
			      mailbox->descriptor,
			      mailbox->descriptor_device_addr);
}

static int
gxp_mailbox_ops_init_consume_responses_work(struct gxp_mailbox *mailbox)
{
	mailbox->cur_seq = 0;
	init_waitqueue_head(&mailbox->wait_list_waitq);
	INIT_LIST_HEAD(&mailbox->wait_list);

	return 0;
}

static void
gxp_mailbox_ops_release_consume_responses_work(struct gxp_mailbox *mailbox)
{
	struct gxp_mailbox_wait_list *cur, *nxt;
	struct gxp_async_response *async_resp;
	struct list_head resps_to_flush;
	unsigned long flags;

	/*
	 * At this point only async responses should be pending. Flush them all
	 * from the `wait_list` at once so any remaining timeout workers
	 * waiting on `wait_list_lock` will know their responses have been
	 * handled already.
	 */
	INIT_LIST_HEAD(&resps_to_flush);
	mutex_lock(&mailbox->wait_list_lock);
	list_for_each_entry_safe (cur, nxt, &mailbox->wait_list, list) {
		list_del(&cur->list);
		if (cur->is_async) {
			list_add_tail(&cur->list, &resps_to_flush);
			/*
			 * Clear the response's destination queue so that if the
			 * timeout worker is running, it won't try to process
			 * this response after `wait_list_lock` is released.
			 */
			async_resp = container_of(
				cur->resp, struct gxp_async_response, resp);
			spin_lock_irqsave(async_resp->dest_queue_lock, flags);
			async_resp->dest_queue = NULL;
			spin_unlock_irqrestore(async_resp->dest_queue_lock,
					       flags);

		} else {
			dev_warn(
				mailbox->gxp->dev,
				"Unexpected synchronous command pending on mailbox release\n");
			kfree(cur);
		}
	}
	mutex_unlock(&mailbox->wait_list_lock);

	/*
	 * Cancel the timeout timer of and free any responses that were still in
	 * the `wait_list` above.
	 */
	list_for_each_entry_safe (cur, nxt, &resps_to_flush, list) {
		list_del(&cur->list);
		async_resp = container_of(cur->resp, struct gxp_async_response,
					  resp);
		cancel_delayed_work_sync(&async_resp->timeout_work);
		kfree(async_resp);
		kfree(cur);
	}
}

/*
 * Pops the wait_list until the sequence number of @resp is found, and copies
 * @resp to the found entry.
 *
 * Entries in wait_list should have sequence number in increasing order, but
 * the responses arriving and being handled may be out-of-order.
 *
 * Iterate over the wait_list, comparing #cur->resp->seq with @resp->seq:
 * 1. #cur->resp->seq > @resp->seq:
 *   - Nothing to do, either @resp is invalid or its command timed out.
 *   - We're done.
 * 2. #cur->resp->seq == @resp->seq:
 *   - Copy @resp, pop the head.
 *   - If #cur->resp has a destination queue, push it to that queue
 *   - We're done.
 * 3. #cur->resp->seq < @resp->seq:
 *   - @resp has arrived out of sequence order.
 *   - Leave #cur->resp in the wait_list.
 *   - Keep iterating unless the list is exhausted.
 */
static void gxp_mailbox_handle_response(struct gxp_mailbox *mailbox,
					const struct gxp_response *resp)
{
	struct gxp_mailbox_wait_list *cur, *nxt;
	struct gxp_async_response *async_resp;
	unsigned long flags;

	mutex_lock(&mailbox->wait_list_lock);

	list_for_each_entry_safe (cur, nxt, &mailbox->wait_list, list) {
		if (cur->resp->seq > resp->seq) {
			/*
			 * This response has already timed out and been removed
			 * from the wait list (or this is an invalid response).
			 * Drop it.
			 */
			break;
		}
		if (cur->resp->seq == resp->seq) {
			memcpy(cur->resp, resp, sizeof(*resp));
			list_del(&cur->list);
			if (cur->is_async) {
				async_resp =
					container_of(cur->resp,
						     struct gxp_async_response,
						     resp);

				cancel_delayed_work(&async_resp->timeout_work);
				gxp_pm_update_requested_power_states(
					async_resp->mailbox->gxp,
					async_resp->requested_states,
					off_states);

				spin_lock_irqsave(async_resp->dest_queue_lock,
						  flags);

				list_add_tail(&async_resp->list_entry,
					      async_resp->dest_queue);
				/*
				 * Marking the dest_queue as NULL indicates the
				 * response was handled in case its timeout
				 * handler fired between acquiring the
				 * wait_list_lock and cancelling the timeout.
				 */
				async_resp->dest_queue = NULL;

				/*
				 * Don't release the dest_queue_lock until both
				 * any eventfd has been signaled and any waiting
				 * thread has been woken. Otherwise one thread
				 * might consume and free the response before
				 * this function is done with it.
				 */
				if (async_resp->eventfd) {
					gxp_eventfd_signal(async_resp->eventfd);
					gxp_eventfd_put(async_resp->eventfd);
				}

				wake_up(async_resp->dest_queue_waitq);

				spin_unlock_irqrestore(
					async_resp->dest_queue_lock, flags);
			}
			kfree(cur);
			break;
		}
	}

	mutex_unlock(&mailbox->wait_list_lock);
}

/*
 * Fetches elements in the response queue.
 *
 * Returns the pointer of fetched response elements.
 * @total_ptr will be the number of elements fetched.
 *
 * Returns -ENOMEM if failed on memory allocation.
 * Returns NULL if the response queue is empty.
 */
static struct gxp_response *
gxp_mailbox_fetch_responses(struct gxp_mailbox *mailbox, u32 *total_ptr)
{
	u32 head;
	u32 tail;
	u32 count;
	u32 i;
	u32 j;
	u32 total = 0;
	const u32 size = mailbox->resp_queue_size;
	const struct gxp_response *queue = mailbox->resp_queue;
	struct gxp_response *ret = NULL;
	struct gxp_response *prev_ptr = NULL;

	mutex_lock(&mailbox->resp_queue_lock);

	head = mailbox->resp_queue_head;
	/* loop until our head equals to CSR tail */
	while (1) {
		tail = gxp_mailbox_read_resp_queue_tail(mailbox);
		count = gxp_circ_queue_cnt(head, tail, size,
					   CIRCULAR_QUEUE_WRAP_BIT);
		if (count == 0)
			break;

		prev_ptr = ret;
		ret = krealloc(prev_ptr, (total + count) * sizeof(*queue),
			       GFP_KERNEL);
		/*
		 * Out-of-memory, we can return the previously fetched responses
		 * if any, or ENOMEM otherwise.
		 */
		if (!ret) {
			if (!prev_ptr)
				ret = ERR_PTR(-ENOMEM);
			else
				ret = prev_ptr;
			break;
		}
		/* copy responses */
		j = CIRCULAR_QUEUE_REAL_INDEX(head, CIRCULAR_QUEUE_WRAP_BIT);
		for (i = 0; i < count; i++) {
			memcpy(&ret[total], &queue[j], sizeof(*queue));
			ret[total].status = GXP_RESP_OK;
			j = (j + 1) % size;
			total++;
		}
		head = gxp_circ_queue_inc(head, count, size,
					  CIRCULAR_QUEUE_WRAP_BIT);
	}
	gxp_mailbox_inc_resp_queue_head_locked(mailbox, total,
					       CIRCULAR_QUEUE_WRAP_BIT);

	mutex_unlock(&mailbox->resp_queue_lock);
	/*
	 * Now that the response queue has been drained, send an interrupt
	 * to the device in case firmware was waiting for us to consume
	 * responses.
	 */
	if (total == size) {
		/* TODO(b/190868834) define interrupt bits */
		gxp_mailbox_generate_device_interrupt(mailbox, BIT(0));
	}

	*total_ptr = total;
	return ret;
}

/*
 * Fetches and handles responses, then wakes up threads that are waiting for a
 * response.
 *
 * Note: this worker is scheduled in the IRQ handler, to prevent use-after-free
 * or race-condition bugs, gxp_mailbox_release() must be called before free the
 * mailbox.
 */
static void gxp_mailbox_ops_consume_responses_work(struct gxp_mailbox *mailbox)
{
	struct gxp_response *responses;
	u32 i;
	u32 count = 0;

	/* fetch responses and bump RESP_QUEUE_HEAD */
	responses = gxp_mailbox_fetch_responses(mailbox, &count);
	if (IS_ERR(responses)) {
		dev_err(mailbox->gxp->dev,
			"GXP Mailbox failed on fetching responses: %ld",
			PTR_ERR(responses));
		return;
	}

	for (i = 0; i < count; i++)
		gxp_mailbox_handle_response(mailbox, &responses[i]);
	/*
	 * Responses handled, wake up threads that are waiting for a response.
	 */
	wake_up(&mailbox->wait_list_waitq);
	kfree(responses);
}

/* Default operators for the DSP mailbox */
struct gxp_mailbox_ops gxp_mailbox_default_ops = {
	.allocate_resources = gxp_mailbox_ops_allocate_resources,
	.release_resources = gxp_mailbox_ops_release_resources,
	.init_consume_responses_work =
		gxp_mailbox_ops_init_consume_responses_work,
	.release_consume_responses_work =
		gxp_mailbox_ops_release_consume_responses_work,
	.consume_responses_work = gxp_mailbox_ops_consume_responses_work,
};

/* Default arguments for the DSP mailbox */
const struct gxp_mailbox_args gxp_mailbox_default_args = {
	.ops = &gxp_mailbox_default_ops,
	.data = NULL,
};

/*
 * Adds @resp to @mailbox->wait_list.
 *
 * wait_list is a FIFO queue, with sequence number in increasing order.
 *
 * Returns 0 on success, or -ENOMEM if failed on allocation.
 */
static int gxp_mailbox_push_wait_resp(struct gxp_mailbox *mailbox,
				      struct gxp_response *resp, bool is_async)
{
	struct gxp_mailbox_wait_list *entry =
		kzalloc(sizeof(*entry), GFP_KERNEL);

	if (!entry)
		return -ENOMEM;
	entry->resp = resp;
	entry->is_async = is_async;
	mutex_lock(&mailbox->wait_list_lock);
	list_add_tail(&entry->list, &mailbox->wait_list);
	mutex_unlock(&mailbox->wait_list_lock);

	return 0;
}

/*
 * Removes the response previously pushed with gxp_mailbox_push_wait_resp().
 *
 * This is used when the kernel gives up waiting for the response.
 */
static void gxp_mailbox_del_wait_resp(struct gxp_mailbox *mailbox,
				      struct gxp_response *resp)
{
	struct gxp_mailbox_wait_list *cur;

	mutex_lock(&mailbox->wait_list_lock);

	list_for_each_entry (cur, &mailbox->wait_list, list) {
		if (cur->resp->seq > resp->seq) {
			/*
			 * Sequence numbers in wait_list are in increasing
			 * order. This case implies no entry in the list
			 * matches @resp's sequence number.
			 */
			break;
		}
		if (cur->resp->seq == resp->seq) {
			list_del(&cur->list);
			kfree(cur);
			break;
		}
	}

	mutex_unlock(&mailbox->wait_list_lock);
}

static int gxp_mailbox_enqueue_cmd(struct gxp_mailbox *mailbox,
				   struct gxp_command *cmd,
				   struct gxp_response *resp,
				   bool resp_is_async)
{
	int ret;
	u32 tail;
	struct gxp_command *cmd_queue = mailbox->cmd_queue;

	mutex_lock(&mailbox->cmd_queue_lock);

	cmd->seq = mailbox->cur_seq;
	/*
	 * The lock ensures mailbox->cmd_queue_tail cannot be changed by
	 * other processes (this method should be the only one to modify the
	 * value of tail), therefore we can remember its value here and use it
	 * in various places below.
	 */
	tail = mailbox->cmd_queue_tail;

	/*
	 * If the cmd queue is full, it's up to the caller to retry.
	 */
	if (gxp_mailbox_read_cmd_queue_head(mailbox) ==
	    (tail ^ CIRCULAR_QUEUE_WRAP_BIT)) {
		ret = -EAGAIN;
		goto out;
	}

	if (resp) {
		/*
		 * Add @resp to the wait_list only if the cmd can be pushed
		 * successfully.
		 */
		resp->seq = cmd->seq;
		resp->status = GXP_RESP_WAITING;
		ret = gxp_mailbox_push_wait_resp(mailbox, resp, resp_is_async);
		if (ret)
			goto out;
	}
	/* size of cmd_queue is a multiple of sizeof(*cmd) */
	memcpy(cmd_queue +
		       CIRCULAR_QUEUE_REAL_INDEX(tail, CIRCULAR_QUEUE_WRAP_BIT),
	       cmd, sizeof(*cmd));
	gxp_mailbox_inc_cmd_queue_tail_locked(mailbox, 1,
					      CIRCULAR_QUEUE_WRAP_BIT);
	/* triggers doorbell */
	/* TODO(b/190868834) define interrupt bits */
	gxp_mailbox_generate_device_interrupt(mailbox, BIT(0));
	/* bumps sequence number after the command is sent */
	mailbox->cur_seq++;
	ret = 0;
out:
	mutex_unlock(&mailbox->cmd_queue_lock);
	if (ret)
		dev_err(mailbox->gxp->dev, "%s: ret=%d", __func__, ret);

	return ret;
}

void gxp_mailbox_init(struct gxp_mailbox_manager *mgr)
{
	gxp_mailbox_manager_set_ops(mgr);
}

int gxp_mailbox_execute_cmd(struct gxp_mailbox *mailbox,
			    struct gxp_command *cmd, struct gxp_response *resp)
{
	int ret;

	ret = gxp_mailbox_enqueue_cmd(mailbox, cmd, resp,
				      /* resp_is_async = */ false);
	if (ret)
		return ret;
	ret = wait_event_timeout(mailbox->wait_list_waitq,
				 resp->status != GXP_RESP_WAITING,
				 msecs_to_jiffies(MAILBOX_TIMEOUT));
	if (!ret) {
		dev_notice(mailbox->gxp->dev, "%s: event wait timeout",
			   __func__);
		gxp_mailbox_del_wait_resp(mailbox, resp);
		return -ETIMEDOUT;
	}
	if (resp->status != GXP_RESP_OK) {
		dev_notice(mailbox->gxp->dev, "%s: resp status=%u", __func__,
			   resp->status);
		return -ENOMSG;
	}

	return resp->retval;
}

static void async_cmd_timeout_work(struct work_struct *work)
{
	struct gxp_async_response *async_resp = container_of(
		work, struct gxp_async_response, timeout_work.work);
	unsigned long flags;

	/*
	 * This function will acquire the mailbox wait_list_lock. This means if
	 * response processing is in progress, it will complete before this
	 * response can be removed from the wait list.
	 *
	 * Once this function has the wait_list_lock, no future response
	 * processing will begin until this response has been removed.
	 */
	gxp_mailbox_del_wait_resp(async_resp->mailbox, &async_resp->resp);

	/*
	 * Check if this response still has a valid destination queue, in case
	 * an in-progress call to `gxp_mailbox_handle_response()` completed
	 * the response while `gxp_mailbox_del_wait_resp()` was waiting for
	 * the wait_list_lock.
	 */
	spin_lock_irqsave(async_resp->dest_queue_lock, flags);
	if (async_resp->dest_queue) {
		async_resp->resp.status = GXP_RESP_CANCELLED;
		list_add_tail(&async_resp->list_entry, async_resp->dest_queue);
		spin_unlock_irqrestore(async_resp->dest_queue_lock, flags);

		gxp_pm_update_requested_power_states(
			async_resp->mailbox->gxp, async_resp->requested_states,
			off_states);

		if (async_resp->eventfd) {
			gxp_eventfd_signal(async_resp->eventfd);
			gxp_eventfd_put(async_resp->eventfd);
		}

		wake_up(async_resp->dest_queue_waitq);
	} else {
		spin_unlock_irqrestore(async_resp->dest_queue_lock, flags);
	}
}

int gxp_mailbox_execute_cmd_async(struct gxp_mailbox *mailbox,
				  struct gxp_command *cmd,
				  struct list_head *resp_queue,
				  spinlock_t *queue_lock,
				  wait_queue_head_t *queue_waitq,
				  struct gxp_power_states power_states,
				  struct gxp_eventfd *eventfd)
{
	struct gxp_async_response *async_resp;
	int ret;

	async_resp = kzalloc(sizeof(*async_resp), GFP_KERNEL);
	if (!async_resp)
		return -ENOMEM;

	async_resp->mailbox = mailbox;
	async_resp->dest_queue = resp_queue;
	async_resp->dest_queue_lock = queue_lock;
	async_resp->dest_queue_waitq = queue_waitq;
	async_resp->requested_states = power_states;
	if (eventfd && gxp_eventfd_get(eventfd))
		async_resp->eventfd = eventfd;
	else
		async_resp->eventfd = NULL;

	INIT_DELAYED_WORK(&async_resp->timeout_work, async_cmd_timeout_work);
	schedule_delayed_work(&async_resp->timeout_work,
			      msecs_to_jiffies(MAILBOX_TIMEOUT));

	gxp_pm_update_requested_power_states(mailbox->gxp, off_states,
					     power_states);
	ret = gxp_mailbox_enqueue_cmd(mailbox, cmd, &async_resp->resp,
				      /* resp_is_async = */ true);
	if (ret)
		goto err_free_resp;

	return 0;

err_free_resp:
	gxp_pm_update_requested_power_states(mailbox->gxp, power_states,
					     off_states);
	cancel_delayed_work_sync(&async_resp->timeout_work);
	kfree(async_resp);
	return ret;
}
#endif /* !GXP_HAS_DCI */
