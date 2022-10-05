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

#include <gcip/gcip-telemetry.h>

#include "gxp-config.h"
#include "gxp-dma.h"
#include "gxp-kci.h"
#include "gxp-lpm.h"
#include "gxp-mailbox-driver.h"
#include "gxp-mailbox.h"
#include "gxp-mcu.h"
#include "gxp-pm.h"
#include "gxp-usage-stats.h"

#define GXP_MCU_USAGE_BUFFER_SIZE 4096

#define CIRCULAR_QUEUE_WRAP_BIT BIT(15)

#define MBOX_CMD_QUEUE_NUM_ENTRIES 1024
#define MBOX_RESP_QUEUE_NUM_ENTRIES 1024

/* Callback functions for struct gcip_kci. */

static u32 gxp_kci_get_cmd_queue_head(struct gcip_kci *kci)
{
	struct gxp_mailbox *mbx = gcip_kci_get_data(kci);

	return gxp_mailbox_read_cmd_queue_head(mbx);
}

static u32 gxp_kci_get_cmd_queue_tail(struct gcip_kci *kci)
{
	struct gxp_mailbox *mbx = gcip_kci_get_data(kci);

	return mbx->cmd_queue_tail;
}

static void gxp_kci_inc_cmd_queue_tail(struct gcip_kci *kci, u32 inc)
{
	struct gxp_mailbox *mbx = gcip_kci_get_data(kci);

	gxp_mailbox_inc_cmd_queue_tail_nolock(mbx, inc,
					      CIRCULAR_QUEUE_WRAP_BIT);
}

static u32 gxp_kci_get_resp_queue_size(struct gcip_kci *kci)
{
	struct gxp_mailbox *mbx = gcip_kci_get_data(kci);

	return mbx->resp_queue_size;
}

static u32 gxp_kci_get_resp_queue_head(struct gcip_kci *kci)
{
	struct gxp_mailbox *mbx = gcip_kci_get_data(kci);

	return mbx->resp_queue_head;
}

static u32 gxp_kci_get_resp_queue_tail(struct gcip_kci *kci)
{
	struct gxp_mailbox *mbx = gcip_kci_get_data(kci);

	return gxp_mailbox_read_resp_queue_tail(mbx);
}

static void gxp_kci_inc_resp_queue_head(struct gcip_kci *kci, u32 inc)
{
	struct gxp_mailbox *mbx = gcip_kci_get_data(kci);

	gxp_mailbox_inc_resp_queue_head_nolock(mbx, inc,
					       CIRCULAR_QUEUE_WRAP_BIT);
}

/* Handle one incoming request from firmware. */
static void
gxp_reverse_kci_handle_response(struct gcip_kci *kci,
				struct gcip_kci_response_element *resp)
{
	struct gxp_mailbox *mbx = gcip_kci_get_data(kci);
	struct gxp_dev *gxp = mbx->gxp;

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
	struct gxp_mailbox *mbx = gcip_kci_get_data(kci);
	struct gxp_kci *gkci = mbx->data;

	return gxp_kci_update_usage(gkci);
}

static inline void
gxp_kci_trigger_doorbell(struct gcip_kci *kci,
			 enum gcip_kci_doorbell_reason reason)
{
	struct gxp_mailbox *mbx = gcip_kci_get_data(kci);

	/* triggers doorbell */
	gxp_mailbox_generate_device_interrupt(mbx, BIT(0));
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
	mailbox->cmd_queue_buf.vaddr = gkci->cmd_queue_mem.vaddr;
	mailbox->cmd_queue_buf.dsp_addr = gkci->cmd_queue_mem.daddr;
	mailbox->cmd_queue_size = MBOX_CMD_QUEUE_NUM_ENTRIES;
	mailbox->cmd_queue_tail = 0;

	/* Allocate and initialize the response queue */
	ret = gxp_mcu_mem_alloc_data(gkci->mcu, &gkci->resp_queue_mem,
				     sizeof(struct gcip_kci_response_element) *
					     MBOX_RESP_QUEUE_NUM_ENTRIES);
	if (ret)
		goto err_resp_queue;
	mailbox->resp_queue_buf.vaddr = gkci->resp_queue_mem.vaddr;
	mailbox->resp_queue_buf.dsp_addr = gkci->resp_queue_mem.daddr;
	mailbox->resp_queue_size = MBOX_CMD_QUEUE_NUM_ENTRIES;
	mailbox->resp_queue_head = 0;

	/* Allocate and initialize the mailbox descriptor */
	ret = gxp_mcu_mem_alloc_data(gkci->mcu, &gkci->descriptor_mem,
				     sizeof(struct gxp_mailbox_descriptor));
	if (ret)
		goto err_descriptor;

	mailbox->descriptor_buf.vaddr = gkci->descriptor_mem.vaddr;
	mailbox->descriptor_buf.dsp_addr = gkci->descriptor_mem.daddr;
	mailbox->descriptor = (struct gxp_mailbox_descriptor *)mailbox->descriptor_buf.vaddr;
	mailbox->descriptor->cmd_queue_device_addr =
		mailbox->cmd_queue_buf.dsp_addr;
	mailbox->descriptor->resp_queue_device_addr =
		mailbox->resp_queue_buf.dsp_addr;
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

static struct gxp_mailbox_ops mbx_ops = {
	.allocate_resources = gxp_kci_allocate_resources,
	.release_resources = gxp_kci_release_resources,
	.gcip_ops.kci = &kci_ops,
};

int gxp_kci_init(struct gxp_mcu *mcu)
{
	struct gxp_dev *gxp = mcu->gxp;
	struct gxp_kci *gkci = &mcu->kci;
	struct gxp_mailbox_args mbx_args = {
		.type = GXP_MBOX_TYPE_KCI,
		.ops = &mbx_ops,
		.queue_wrap_bit = CIRCULAR_QUEUE_WRAP_BIT,
		.data = gkci,
	};

	gkci->gxp = gxp;
	gkci->mcu = mcu;
	gkci->mbx = gxp_mailbox_alloc(gxp->mailbox_mgr, NULL, 0, KCI_MAILBOX_ID,
				      &mbx_args);
	if (IS_ERR(gkci->mbx))
		return PTR_ERR(gkci->mbx);

	return 0;
}

int gxp_kci_reinit(struct gxp_kci *gkci)
{
	dev_notice(gkci->gxp->dev, "%s not yet implemented\n", __func__);
	return 0;
}

void gxp_kci_cancel_work_queues(struct gxp_kci *gkci)
{
	gcip_kci_cancel_work_queues(gkci->mbx->mbx_impl.gcip_kci);
}

void gxp_kci_exit(struct gxp_kci *gkci)
{
	if (IS_GXP_TEST && (!gkci || !gkci->mbx))
		return;
	gxp_mailbox_release(gkci->gxp->mailbox_mgr, NULL, 0, gkci->mbx);
	gkci->mbx = NULL;
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

	ret = gcip_kci_send_cmd(gkci->mbx->mbx_impl.gcip_kci, &cmd);
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

void gxp_kci_update_usage_async(struct gxp_kci *gkci)
{
	gcip_kci_update_usage_async(gkci->mbx->mbx_impl.gcip_kci);
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

	if (!gkci || !gkci->mbx->mbx_impl.gcip_kci)
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
	ret = gcip_kci_send_cmd(gkci->mbx->mbx_impl.gcip_kci, &cmd);

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

int gxp_kci_map_mcu_log_buffer(struct gcip_telemetry_kci_args *args)
{
	struct gcip_kci_command_element cmd = {
		.code = GCIP_KCI_CODE_MAP_LOG_BUFFER,
		.dma = {
			.address = args->addr,
			.size = args->size,
		},
	};

	return gcip_kci_send_cmd(args->kci, &cmd);
}

int gxp_kci_map_mcu_trace_buffer(struct gcip_telemetry_kci_args *args)
{
	struct gcip_kci_command_element cmd = {
		.code = GCIP_KCI_CODE_MAP_TRACE_BUFFER,
		.dma = {
			.address = args->addr,
			.size = args->size,
		},
	};

	return gcip_kci_send_cmd(args->kci, &cmd);
}

int gxp_kci_shutdown(struct gxp_kci *gkci)
{
	struct gcip_kci_command_element cmd = {
		.code = GCIP_KCI_CODE_SHUTDOWN,
	};

	if (!gkci || !gkci->mbx->mbx_impl.gcip_kci)
		return -ENODEV;

	return gcip_kci_send_cmd(gkci->mbx->mbx_impl.gcip_kci, &cmd);
}

int gxp_kci_allocate_vmbox(struct gxp_kci *gkci, u8 client_id, u8 num_cores,
			   u8 slice_index, u8 tpu_client_id, u8 operation)
{
	struct gcip_kci_command_element cmd = {
		.code = GCIP_KCI_CODE_ALLOCATE_VMBOX,
	};
	struct gxp_kci_allocate_vmbox_detail *detail;
	struct gxp_mapped_resource buf;
	int ret;

	if (!gkci || !gkci->mbx->mbx_impl.gcip_kci)
		return -ENODEV;

	ret = gxp_mcu_mem_alloc_data(gkci->mcu, &buf, sizeof(*detail));
	if (ret)
		return -ENOMEM;

	detail = buf.vaddr;
	detail->operation = operation;
	detail->client_id = client_id;

	if (detail->operation & KCI_ALLOCATE_VMBOX_OP_ALLOCATE_VMBOX) {
		detail->num_cores = num_cores;
		detail->slice_index = slice_index;
	}

	if (detail->operation & KCI_ALLOCATE_VMBOX_OP_LINK_OFFLOAD_VMBOX) {
		detail->offload_client_id = tpu_client_id;
		detail->offload_type = KCI_ALLOCATE_VMBOX_OFFLOAD_TYPE_TPU;
	}

	cmd.dma.address = buf.daddr;
	cmd.dma.size = sizeof(*detail);

	ret = gcip_kci_send_cmd(gkci->mbx->mbx_impl.gcip_kci, &cmd);
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

	if (!gkci || !gkci->mbx->mbx_impl.gcip_kci)
		return -ENODEV;

	ret = gxp_mcu_mem_alloc_data(gkci->mcu, &buf, sizeof(*detail));
	if (ret)
		return -ENOMEM;

	detail = buf.vaddr;
	detail->client_id = client_id;

	cmd.dma.address = buf.daddr;
	cmd.dma.size = sizeof(*detail);

	ret = gcip_kci_send_cmd(gkci->mbx->mbx_impl.gcip_kci, &cmd);
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

	if (!gkci || !gkci->mbx->mbx_impl.gcip_kci)
		return -ENODEV;

	return gcip_kci_send_cmd(gkci->mbx->mbx_impl.gcip_kci, &cmd);
}
