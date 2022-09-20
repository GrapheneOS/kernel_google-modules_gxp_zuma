// SPDX-License-Identifier: GPL-2.0
/*
 * Kernel Control Interface, implements the protocol between DSP Kernel driver and MCU firmware.
 *
 * Copyright (C) 2022 Google LLC
 */

#include <linux/delay.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/types.h>

#include "gxp-config.h"
#include "gxp-dma.h"
#include "gxp-kci.h"
#include "gxp-lpm.h"
#include "gxp-mailbox-driver.h"
#include "gxp-mailbox.h"
#include "gxp-mcu.h"
#include "gxp-pm.h"
#include "gxp-usage-stats.h"

/* Timeout for KCI responses from the firmware (milliseconds) */
#ifdef GXP_KCI_TIMEOUT

#define KCI_TIMEOUT GXP_KCI_TIMEOUT

#elif IS_ENABLED(CONFIG_GXP_TEST)
/* fake-firmware could respond in a short time */
#define KCI_TIMEOUT (200)
#else
/* 5 secs. */
#define KCI_TIMEOUT (5000)
#endif

#define GXP_MCU_USAGE_BUFFER_SIZE 4096

#define CIRCULAR_QUEUE_WRAP_BIT BIT(15)

#define MBOX_CMD_QUEUE_NUM_ENTRIES 1024
#define MBOX_RESP_QUEUE_NUM_ENTRIES 1024

/* Callback functions for struct gcip_kci. */

static u32 gxp_kci_get_cmd_queue_head(struct gcip_kci *kci)
{
	struct gxp_kci *gkci = gcip_kci_get_data(kci);

	return gxp_mailbox_read_cmd_queue_head(gkci->mailbox);
}

static u32 gxp_kci_get_cmd_queue_tail(struct gcip_kci *kci)
{
	struct gxp_kci *gkci = gcip_kci_get_data(kci);

	return gkci->mailbox->cmd_queue_tail;
}

static void gxp_kci_inc_cmd_queue_tail(struct gcip_kci *kci, u32 inc)
{
	struct gxp_kci *gkci = gcip_kci_get_data(kci);

	gxp_mailbox_inc_cmd_queue_tail_nolock(gkci->mailbox, inc,
					      CIRCULAR_QUEUE_WRAP_BIT);
}

static u32 gxp_kci_get_resp_queue_size(struct gcip_kci *kci)
{
	struct gxp_kci *gkci = gcip_kci_get_data(kci);

	return gkci->mailbox->resp_queue_size;
}

static u32 gxp_kci_get_resp_queue_head(struct gcip_kci *kci)
{
	struct gxp_kci *gkci = gcip_kci_get_data(kci);

	return gkci->mailbox->resp_queue_head;
}

static u32 gxp_kci_get_resp_queue_tail(struct gcip_kci *kci)
{
	struct gxp_kci *gkci = gcip_kci_get_data(kci);

	return gxp_mailbox_read_resp_queue_tail(gkci->mailbox);
}

static void gxp_kci_inc_resp_queue_head(struct gcip_kci *kci, u32 inc)
{
	struct gxp_kci *gkci = gcip_kci_get_data(kci);

	gxp_mailbox_inc_resp_queue_head_nolock(gkci->mailbox, inc,
					       CIRCULAR_QUEUE_WRAP_BIT);
}

/* Handle one incoming request from firmware. */
static void
gxp_reverse_kci_handle_response(struct gcip_kci *kci,
				struct gcip_kci_response_element *resp)
{
	struct gxp_kci *gkci = gcip_kci_get_data(kci);
	struct gxp_dev *gxp = gkci->mailbox->gxp;

	if (resp->code <= GCIP_RKCI_CHIP_CODE_LAST) {
		/* TODO(b/239638427): Handle reverse kci */
		dev_dbg(gxp->dev, "Reverse KCI received: %#x", resp->code);
		return;
	}

	switch (resp->code) {
	case GCIP_RKCI_FIRMWARE_CRASH:
		/* TODO(b/239638427): Handle firmware crash */
		dev_dbg(gxp->dev, "MCU firmware is crashed");
		break;
	case GCIP_RKCI_JOB_LOCKUP:
		/* TODO(b/239638427): Handle job lookup */
		dev_dbg(gxp->dev, "Job lookup received from MCU firmware");
		break;
	default:
		dev_warn(gxp->dev, "%s: Unrecognized KCI request: %#x\n",
			 __func__, resp->code);
	}
}

static int gxp_kci_update_usage_wrapper(struct gcip_kci *kci)
{
	struct gxp_kci *gkci = gcip_kci_get_data(kci);

	return gxp_kci_update_usage(gkci);
}

static inline void
gxp_kci_trigger_doorbell(struct gcip_kci *kci,
			 enum gcip_kci_doorbell_reason reason)
{
	struct gxp_kci *gkci = gcip_kci_get_data(kci);

	/* triggers doorbell */
	gxp_mailbox_generate_device_interrupt(gkci->mailbox, BIT(0));
}

static const struct gcip_kci_ops kci_ops = {
	.get_cmd_queue_head = gxp_kci_get_cmd_queue_head,
	.get_cmd_queue_tail = gxp_kci_get_cmd_queue_tail,
	.inc_cmd_queue_tail = gxp_kci_inc_cmd_queue_tail,
	.get_resp_queue_size = gxp_kci_get_resp_queue_size,
	.get_resp_queue_head = gxp_kci_get_resp_queue_head,
	.get_resp_queue_tail = gxp_kci_get_resp_queue_tail,
	.inc_resp_queue_head = gxp_kci_inc_resp_queue_head,
	.trigger_doorbell = gxp_kci_trigger_doorbell,
	.reverse_kci_handle_response = gxp_reverse_kci_handle_response,
	.update_usage = gxp_kci_update_usage_wrapper,
};

/* Callback functions for struct gxp_mailbox. */

static int gxp_kci_allocate_resources(struct gxp_mailbox *mailbox,
				      struct gxp_virtual_device *vd,
				      uint virt_core)
{
	struct gxp_kci *gkci = mailbox->data;
	int ret;

	/* Allocate and initialize the command queue */
	ret = gxp_mcu_mem_alloc_data(gkci->mcu, &gkci->cmd_queue_mem,
				     sizeof(struct gcip_kci_command_element) *
					     MBOX_CMD_QUEUE_NUM_ENTRIES);
	if (ret)
		goto err_cmd_queue;
	mailbox->cmd_queue = gkci->cmd_queue_mem.vaddr;
	mailbox->cmd_queue_device_addr = gkci->cmd_queue_mem.daddr;
	mailbox->cmd_queue_size = MBOX_CMD_QUEUE_NUM_ENTRIES;
	mailbox->cmd_queue_tail = 0;

	/* Allocate and initialize the response queue */
	ret = gxp_mcu_mem_alloc_data(gkci->mcu, &gkci->resp_queue_mem,
				     sizeof(struct gcip_kci_response_element) *
					     MBOX_RESP_QUEUE_NUM_ENTRIES);
	if (ret)
		goto err_resp_queue;
	mailbox->resp_queue = gkci->resp_queue_mem.vaddr;
	mailbox->resp_queue_device_addr = gkci->resp_queue_mem.daddr;
	mailbox->resp_queue_size = MBOX_CMD_QUEUE_NUM_ENTRIES;
	mailbox->resp_queue_head = 0;

	/* Allocate and initialize the mailbox descriptor */
	ret = gxp_mcu_mem_alloc_data(gkci->mcu, &gkci->descriptor_mem,
				     sizeof(struct gxp_mailbox_descriptor));
	if (ret)
		goto err_descriptor;

	mailbox->descriptor = gkci->descriptor_mem.vaddr;
	mailbox->descriptor_device_addr = gkci->descriptor_mem.daddr;
	mailbox->descriptor->cmd_queue_device_addr =
		mailbox->cmd_queue_device_addr;
	mailbox->descriptor->resp_queue_device_addr =
		mailbox->resp_queue_device_addr;
	mailbox->descriptor->cmd_queue_size = mailbox->cmd_queue_size;
	mailbox->descriptor->resp_queue_size = mailbox->resp_queue_size;

	return 0;

err_descriptor:
	gxp_mcu_mem_free_data(gkci->mcu, &gkci->resp_queue_mem);
err_resp_queue:
	gxp_mcu_mem_free_data(gkci->mcu, &gkci->cmd_queue_mem);
err_cmd_queue:
	return -ENOMEM;
}

static void gxp_kci_release_resources(struct gxp_mailbox *mailbox,
				      struct gxp_virtual_device *vd,
				      uint virt_core)
{
	struct gxp_kci *gkci = mailbox->data;

	gxp_mcu_mem_free_data(gkci->mcu, &gkci->descriptor_mem);
	gxp_mcu_mem_free_data(gkci->mcu, &gkci->resp_queue_mem);
	gxp_mcu_mem_free_data(gkci->mcu, &gkci->cmd_queue_mem);
}

static int gxp_kci_init_consume_responses_work(struct gxp_mailbox *mailbox)
{
	struct gxp_kci *gkci = mailbox->data;
	struct gcip_kci_args kci_args = {
		.dev = gkci->gxp->dev,
		.cmd_queue = mailbox->cmd_queue,
		.resp_queue = mailbox->resp_queue,
		.queue_wrap_bit = CIRCULAR_QUEUE_WRAP_BIT,
		.rkci_buffer_size = REVERSE_KCI_BUFFER_SIZE,
		.timeout = KCI_TIMEOUT,
		.ops = &kci_ops,
		.data = gkci,
	};
	int ret;

	gkci->kci = kzalloc(sizeof(*gkci->kci), GFP_KERNEL);
	if (!gkci->kci)
		return -ENOMEM;

	ret = gcip_kci_init(gkci->kci, &kci_args);
	if (ret) {
		kfree(gkci->kci);
		return ret;
	}

	return 0;
}

static void gxp_kci_release_consume_responses_work(struct gxp_mailbox *mailbox)
{
	struct gxp_kci *gkci = mailbox->data;

	/* Release gcip_kci. */
	gxp_kci_cancel_work_queues(gkci);
	gcip_kci_release(gkci->kci);
	kfree(gkci->kci);
	gkci->kci = NULL;
}

static void gxp_kci_consume_responses_work(struct gxp_mailbox *mailbox)
{
	struct gxp_kci *gkci = mailbox->data;

	gcip_kci_handle_irq(gkci->kci);
}

static struct gxp_mailbox_ops mbx_ops = {
	.allocate_resources = gxp_kci_allocate_resources,
	.release_resources = gxp_kci_release_resources,
	.init_consume_responses_work = gxp_kci_init_consume_responses_work,
	.release_consume_responses_work =
		gxp_kci_release_consume_responses_work,
	.consume_responses_work = gxp_kci_consume_responses_work,
};

int gxp_kci_init(struct gxp_mcu *mcu)
{
	struct gxp_dev *gxp = mcu->gxp;
	struct gxp_kci *gkci = &mcu->kci;
	struct gxp_mailbox_args mbx_args = {
		.ops = &mbx_ops,
		.data = gkci,
	};

	gkci->gxp = gxp;
	gkci->mcu = mcu;
	gkci->mailbox = gxp_mailbox_alloc(gxp->mailbox_mgr, NULL, 0,
					  KCI_MAILBOX_ID, &mbx_args);
	if (IS_ERR(gkci->mailbox))
		return PTR_ERR(gkci->mailbox);

	return 0;
}

int gxp_kci_reinit(struct gxp_kci *gkci)
{
	dev_notice(gkci->gxp->dev, "%s not yet implemented\n", __func__);
	return 0;
}

void gxp_kci_cancel_work_queues(struct gxp_kci *gkci)
{
	gcip_kci_cancel_work_queues(gkci->kci);
}

void gxp_kci_exit(struct gxp_kci *gkci)
{
	if (IS_GXP_TEST && (!gkci || !gkci->mailbox))
		return;
	gxp_mailbox_release(gkci->gxp->mailbox_mgr, NULL, 0, gkci->mailbox);
	gkci->mailbox = NULL;
}

enum gcip_fw_flavor gxp_kci_fw_info(struct gxp_kci *gkci,
				    struct gcip_fw_info *fw_info)
{
	struct gxp_dev *gxp = gkci->gxp;
	struct gcip_kci_command_element cmd = {
		.code = GCIP_KCI_CODE_FIRMWARE_INFO,
		.dma = {
			.address = 0,
			.size = 0,
		},
	};
	enum gcip_fw_flavor flavor = GCIP_FW_FLAVOR_UNKNOWN;
	struct gxp_mapped_resource buf;
	int ret;

	buf.paddr = 0;
	ret = gxp_mcu_mem_alloc_data(gkci->mcu, &buf, sizeof(*fw_info));
	/* If allocation failed still try handshake without full fw_info */
	if (ret) {
		dev_warn(gxp->dev, "%s: error setting up fw info buffer: %d",
			 __func__, ret);
		memset(fw_info, 0, sizeof(*fw_info));
	} else {
		memset(buf.vaddr, 0, sizeof(*fw_info));
		cmd.dma.address = buf.daddr;
		cmd.dma.size = sizeof(*fw_info);
	}

	ret = gcip_kci_send_cmd(gkci->kci, &cmd);
	if (buf.paddr) {
		memcpy(fw_info, buf.vaddr, sizeof(*fw_info));
		gxp_mcu_mem_free_data(gkci->mcu, &buf);
	}

	if (ret == GCIP_KCI_ERROR_OK) {
		switch (fw_info->fw_flavor) {
		case GCIP_FW_FLAVOR_BL1:
		case GCIP_FW_FLAVOR_SYSTEST:
		case GCIP_FW_FLAVOR_PROD_DEFAULT:
		case GCIP_FW_FLAVOR_CUSTOM:
			flavor = fw_info->fw_flavor;
			break;
		default:
			dev_dbg(gxp->dev, "unrecognized fw flavor %#x\n",
				fw_info->fw_flavor);
		}
	} else {
		dev_dbg(gxp->dev, "firmware flavor query returns %d\n", ret);
		if (ret < 0)
			flavor = ret;
		else
			flavor = -EIO;
	}

	return flavor;
}

int gxp_kci_update_usage(struct gxp_kci *gkci)
{
	struct gxp_power_manager *power_mgr = gkci->gxp->power_mgr;
	struct gxp_mcu_firmware *fw = &gkci->mcu->fw;
	int ret = -EAGAIN;

	/* Quick return if device is already powered down. */
	if (power_mgr->curr_state == AUR_OFF ||
	    !gxp_lpm_is_powered(gkci->gxp, GXP_MCU_CORE_ID))
		return -EAGAIN;

	/*
	 * Lockout change in f/w load/unload status during usage update.
	 * Skip usage update if the firmware is being updated now or is not
	 * valid.
	 */
	if (!mutex_trylock(&fw->lock))
		return -EAGAIN;

	if (fw->status != GCIP_FW_VALID)
		goto fw_unlock;

	/*
	 * This function may run in a worker that is being canceled when the
	 * device is powering down, and the power down code holds the PM lock.
	 * Using trylock to prevent cancel_work_sync() waiting forever.
	 */
	if (!mutex_trylock(&power_mgr->pm_lock))
		goto fw_unlock;

	if (power_mgr->curr_state != AUR_OFF &&
	    gxp_lpm_is_powered(gkci->gxp, GXP_MCU_CORE_ID))
		ret = gxp_kci_update_usage_locked(gkci);
	mutex_unlock(&power_mgr->pm_lock);

fw_unlock:
	mutex_unlock(&fw->lock);

	return ret;
}

int gxp_kci_update_usage_locked(struct gxp_kci *gkci)
{
	struct gxp_dev *gxp = gkci->gxp;
	struct gcip_kci_command_element cmd = {
		.code = GCIP_KCI_CODE_GET_USAGE,
		.dma = {
			.address = 0,
			.size = 0,
		},
	};
	struct gxp_mapped_resource buf;
	int ret;

	if (!gkci || !gkci->kci)
		return -ENODEV;

	ret = gxp_mcu_mem_alloc_data(gkci->mcu, &buf,
				     GXP_MCU_USAGE_BUFFER_SIZE);
	if (ret) {
		dev_warn_once(gxp->dev, "%s: failed to allocate usage buffer",
			      __func__);
		return -ENOMEM;
	}

	cmd.dma.address = buf.daddr;
	cmd.dma.size = GXP_MCU_USAGE_BUFFER_SIZE;
	memset(buf.vaddr, 0, sizeof(struct gxp_usage_header));
	ret = gcip_kci_send_cmd(gkci->kci, &cmd);

	if (ret == GCIP_KCI_ERROR_UNIMPLEMENTED ||
	    ret == GCIP_KCI_ERROR_UNAVAILABLE)
		dev_dbg(gxp->dev, "firmware does not report usage\n");
	else if (ret == GCIP_KCI_ERROR_OK)
		gxp_usage_stats_process_buffer(gxp, buf.vaddr);
	else if (ret != -ETIMEDOUT)
		dev_warn_once(gxp->dev, "%s: error %d", __func__, ret);

	gxp_mcu_mem_free_data(gkci->mcu, &buf);

	return ret;
}

int gxp_kci_map_log_buffer(struct gxp_kci *gkci, dma_addr_t daddr, u32 size)
{
	struct gcip_kci_command_element cmd = {
		.code = GCIP_KCI_CODE_MAP_LOG_BUFFER,
		.dma = {
			.address = daddr,
			.size = size,
		},
	};

	if (!gkci || !gkci->kci)
		return -ENODEV;

	return gcip_kci_send_cmd(gkci->kci, &cmd);
}

int gxp_kci_map_trace_buffer(struct gxp_kci *gkci, dma_addr_t daddr, u32 size)
{
	struct gcip_kci_command_element cmd = {
		.code = GCIP_KCI_CODE_MAP_TRACE_BUFFER,
		.dma = {
			.address = daddr,
			.size = size,
		},
	};

	if (!gkci || !gkci->kci)
		return -ENODEV;

	return gcip_kci_send_cmd(gkci->kci, &cmd);
}

int gxp_kci_shutdown(struct gxp_kci *gkci)
{
	struct gcip_kci_command_element cmd = {
		.code = GCIP_KCI_CODE_SHUTDOWN,
	};

	if (!gkci || !gkci->kci)
		return -ENODEV;

	return gcip_kci_send_cmd(gkci->kci, &cmd);
}

int gxp_kci_allocate_vmbox(struct gxp_kci *gkci, u8 num_cores, u8 client_id,
			   u8 slice_index)
{
	struct gcip_kci_command_element cmd = {
		.code = GCIP_KCI_CODE_ALLOCATE_VMBOX,
	};
	struct gxp_kci_allocate_vmbox_detail *detail;
	struct gxp_mapped_resource buf;
	int ret;

	if (!gkci || !gkci->kci)
		return -ENODEV;

	ret = gxp_mcu_mem_alloc_data(gkci->mcu, &buf, sizeof(*detail));
	if (ret)
		return -ENOMEM;

	detail = buf.vaddr;
	detail->num_cores = num_cores;
	detail->client_id = client_id;
	detail->slice_index = slice_index;

	cmd.dma.address = buf.daddr;
	cmd.dma.size = sizeof(*detail);

	ret = gcip_kci_send_cmd(gkci->kci, &cmd);
	gxp_mcu_mem_free_data(gkci->mcu, &buf);

	return ret;
}

int gxp_kci_release_vmbox(struct gxp_kci *gkci, u8 client_id)
{
	struct gcip_kci_command_element cmd = {
		.code = GCIP_KCI_CODE_RELEASE_VMBOX,
	};
	struct gxp_kci_release_vmbox_detail *detail;
	struct gxp_mapped_resource buf;
	int ret;

	if (!gkci || !gkci->kci)
		return -ENODEV;

	ret = gxp_mcu_mem_alloc_data(gkci->mcu, &buf, sizeof(*detail));
	if (ret)
		return -ENOMEM;

	detail = buf.vaddr;
	detail->client_id = client_id;

	cmd.dma.address = buf.daddr;
	cmd.dma.size = sizeof(*detail);

	ret = gcip_kci_send_cmd(gkci->kci, &cmd);
	gxp_mcu_mem_free_data(gkci->mcu, &buf);

	return ret;
}

int gxp_kci_resp_rkci_ack(struct gxp_kci *gkci,
			  struct gcip_kci_response_element *rkci_cmd)
{
	struct gcip_kci_command_element cmd = {
		.seq = rkci_cmd->seq,
		.code = GCIP_KCI_CODE_RKCI_ACK,
	};

	if (!gkci || !gkci->kci)
		return -ENODEV;

	return gcip_kci_send_cmd(gkci->kci, &cmd);
}
