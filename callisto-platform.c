// SPDX-License-Identifier: GPL-2.0
/*
 * Platform device driver for Callisto.
 *
 * Copyright (C) 2022 Google LLC
 */

#include <linux/device.h>
#include <linux/io.h>
#include <linux/mod_devicetable.h>
#include <linux/platform_device.h>

#include <gcip/gcip-telemetry.h>

#include "callisto-platform.h"

#include "gxp-common-platform.c"
#include "gxp-kci.h"
#include "gxp-mcu-telemetry.h"
#include "gxp-uci.h"
#include "gxp-usage-stats.h"

#if IS_ENABLED(CONFIG_GXP_TEST)
char *callisto_work_mode_name = "direct";
#else
static char *callisto_work_mode_name = "direct";
#endif

module_param_named(work_mode, callisto_work_mode_name, charp, 0660);

static char *zuma_revision = "a0";
module_param_named(chip_rev, zuma_revision, charp, 0660);

static int callisto_platform_parse_dt(struct platform_device *pdev,
				      struct gxp_dev *gxp)
{
	struct resource *r;
	void *addr;

	/*
	 * Setting BAAW is required for having correct base for CSR accesses.
	 *
	 * BAAW is supposed to be set by bootloader. On production we simply
	 * don't include the register base in DTS to skip this procedure.
	 */
	r = platform_get_resource_byname(pdev, IORESOURCE_MEM, "baaw");
	if (!IS_ERR_OR_NULL(r)) {
		addr = devm_ioremap_resource(gxp->dev, r);
		/* start address */
		writel(0x0, addr + 0x0);
		/* Window - size */
		writel(0x8000000, addr + 0x4);
		/* Window - target */
		writel(0, addr + 0x8);
		/* Window - enable */
		writel(0x80000003, addr + 0xc);
	}
	return 0;
}

static int callisto_platform_after_probe(struct gxp_dev *gxp)
{
	struct callisto_dev *callisto = to_callisto_dev(gxp);

	if (gxp_is_direct_mode(gxp))
		return 0;

	gxp_usage_stats_init(gxp);
	return gxp_mcu_init(gxp, &callisto->mcu);
}

static void callisto_platform_before_remove(struct gxp_dev *gxp)
{
	struct callisto_dev *callisto = to_callisto_dev(gxp);

	if (gxp_is_direct_mode(gxp))
		return;

	gxp_mcu_exit(&callisto->mcu);
	gxp_usage_stats_exit(gxp);
}

static int gxp_ioctl_uci_command_helper(struct gxp_client *client,
					struct gxp_mailbox_command_ioctl *ibuf)
{
	struct gxp_dev *gxp = client->gxp;
	struct callisto_dev *callisto = to_callisto_dev(gxp);
	struct gxp_uci_command cmd;
	int ret;

	down_read(&client->semaphore);

	if (!check_client_has_available_vd(client, "GXP_MAILBOX_COMMAND")) {
		ret = -ENODEV;
		goto out;
	}

	/* Caller must hold BLOCK wakelock */
	if (!client->has_block_wakelock) {
		dev_err(gxp->dev,
			"GXP_MAILBOX_COMMAND requires the client hold a BLOCK wakelock\n");
		ret = -ENODEV;
		goto out;
	}

	/* Use at least one core for the command */
	if (ibuf->num_cores == 0)
		ibuf->num_cores = 1;

	/* Pack the command structure */
	cmd.core_command_params.address = ibuf->device_address;
	cmd.core_command_params.size = ibuf->size;
	cmd.core_command_params.num_cores = ibuf->num_cores;
	/* Plus 1 to align with power states in MCU firmware. */
	cmd.core_command_params.dsp_operating_point = ibuf->gxp_power_state + 1;
	cmd.core_command_params.memory_operating_point = ibuf->memory_power_state;
	/* cmd.seq is assigned by mailbox implementation */
	cmd.type = CORE_COMMAND;

	/* TODO(b/248179414): Remove core assignment when MCU fw re-enable sticky core scheduler. */
	down_read(&gxp->vd_semaphore);
	cmd.priority = gxp_vd_virt_core_to_phys_core(client->vd, ibuf->virtual_core_id);
	up_read(&gxp->vd_semaphore);
	if (cmd.priority < 0) {
		dev_err(gxp->dev,
			"Mailbox command failed: Invalid virtual core id (%u)\n",
			ibuf->virtual_core_id);
		ret = -EINVAL;
		goto out;
	}

	cmd.client_id = client->vd->client_id;

	/*
	 * TODO(b/248196344): Use the only one permitted eventfd for the virtual device
	 * when MCU fw re-enable sticky core scheduler.
	 */
	ret = gxp_uci_send_command(
		&callisto->mcu.uci, &cmd,
		&client->vd->mailbox_resp_queues[UCI_RESOURCE_ID].queue,
		&client->vd->mailbox_resp_queues[UCI_RESOURCE_ID].lock,
		&client->vd->mailbox_resp_queues[UCI_RESOURCE_ID].waitq,
		client->mb_eventfds[ibuf->virtual_core_id]);
	if (ret) {
		dev_err(gxp->dev, "Failed to enqueue mailbox command (ret=%d)\n",
			ret);
		goto out;
	}
	ibuf->sequence_number = cmd.seq;

out:
	up_read(&client->semaphore);
	return ret;
}

static int gxp_ioctl_uci_command(struct gxp_client *client,
				 struct gxp_mailbox_command_ioctl __user *argp)
{
	struct gxp_mailbox_command_ioctl ibuf;
	int ret;

	if (copy_from_user(&ibuf, argp, sizeof(ibuf)))
		return -EFAULT;

	ret = gxp_ioctl_uci_command_helper(client, &ibuf);
	if (ret)
		return ret;

	if (copy_to_user(argp, &ibuf, sizeof(ibuf)))
		return -EFAULT;

	return 0;
}

static int
gxp_ioctl_uci_response(struct gxp_client *client,
		       struct gxp_mailbox_response_ioctl __user *argp)
{
	struct gxp_mailbox_response_ioctl ibuf;
	int ret = 0;

	if (copy_from_user(&ibuf, argp, sizeof(ibuf)))
		return -EFAULT;

	down_read(&client->semaphore);

	if (!check_client_has_available_vd(client, "GXP_MAILBOX_RESPONSE")) {
		ret = -ENODEV;
		goto out;
	}

	/* Caller must hold BLOCK wakelock */
	if (!client->has_block_wakelock) {
		dev_err(client->gxp->dev,
			"GXP_MAILBOX_RESPONSE requires the client hold a BLOCK wakelock\n");
		ret = -ENODEV;
		goto out;
	}

	ret = gxp_uci_wait_async_response(
		&client->vd->mailbox_resp_queues[UCI_RESOURCE_ID],
		&ibuf.sequence_number, &ibuf.cmd_retval, &ibuf.error_code);
	if (ret)
		goto out;

	if (copy_to_user(argp, &ibuf, sizeof(ibuf)))
		ret = -EFAULT;

out:
	up_read(&client->semaphore);

	return ret;
}

static inline enum gcip_telemetry_type to_gcip_telemetry_type(u8 type)
{
	if (type == GXP_TELEMETRY_TYPE_LOGGING)
		return GCIP_TELEMETRY_LOG;
	else
		return GCIP_TELEMETRY_TRACE;
}

static int gxp_register_mcu_telemetry_eventfd(
	struct gxp_client *client,
	struct gxp_register_telemetry_eventfd_ioctl __user *argp)
{
	struct gxp_mcu *mcu = gxp_mcu_of(client->gxp);
	struct gxp_register_telemetry_eventfd_ioctl ibuf;

	if (copy_from_user(&ibuf, argp, sizeof(ibuf)))
		return -EFAULT;

	return gxp_mcu_telemetry_register_eventfd(
		mcu, to_gcip_telemetry_type(ibuf.type), ibuf.eventfd);
}

static int gxp_unregister_mcu_telemetry_eventfd(
	struct gxp_client *client,
	struct gxp_register_telemetry_eventfd_ioctl __user *argp)
{
	struct gxp_mcu *mcu = gxp_mcu_of(client->gxp);
	struct gxp_register_telemetry_eventfd_ioctl ibuf;

	if (copy_from_user(&ibuf, argp, sizeof(ibuf)))
		return -EFAULT;

	return gxp_mcu_telemetry_unregister_eventfd(
		mcu, to_gcip_telemetry_type(ibuf.type));
}

static long callisto_platform_ioctl(struct file *file, uint cmd, ulong arg)
{
	struct gxp_client *client = file->private_data;
	void __user *argp = (void __user *)arg;
	long ret;

	if (gxp_is_direct_mode(client->gxp))
		return -ENOTTY;
	switch (cmd) {
	case GXP_MAILBOX_COMMAND:
		ret = gxp_ioctl_uci_command(client, argp);
		break;
	case GXP_MAILBOX_RESPONSE:
		ret = gxp_ioctl_uci_response(client, argp);
		break;
	case GXP_REGISTER_MCU_TELEMETRY_EVENTFD:
		ret = gxp_register_mcu_telemetry_eventfd(client, argp);
		break;
	case GXP_UNREGISTER_MCU_TELEMETRY_EVENTFD:
		ret = gxp_unregister_mcu_telemetry_eventfd(client, argp);
		break;
	default:
		ret = -ENOTTY; /* unknown command */
	}

	return ret;
}

static int callisto_platform_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct gxp_client *client = file->private_data;
	struct gxp_mcu *mcu = gxp_mcu_of(client->gxp);
	int ret;

	if (gxp_is_direct_mode(client->gxp))
		return -EOPNOTSUPP;

	switch (vma->vm_pgoff << PAGE_SHIFT) {
	case GXP_MMAP_MCU_LOG_BUFFER_OFFSET:
		ret = gxp_mcu_telemetry_mmap_buffer(mcu, GCIP_TELEMETRY_LOG,
						    vma);
		break;
	case GXP_MMAP_MCU_TRACE_BUFFER_OFFSET:
		ret = gxp_mcu_telemetry_mmap_buffer(mcu, GCIP_TELEMETRY_TRACE,
						    vma);
		break;
	default:
		ret = -EOPNOTSUPP; /* unknown offset */
	}

	return ret;
}

static int callisto_request_power_states(struct gxp_client *client,
					 struct gxp_power_states power_states)
{
	struct gxp_dev *gxp = client->gxp;
	struct callisto_dev *callisto = to_callisto_dev(gxp);
	struct gxp_uci_command cmd;
	int ret;

	if (gxp_is_direct_mode(gxp))
		return -EOPNOTSUPP;

	/* Plus 1 to align with power states in MCU firmware. */
	cmd.wakelock_command_params.dsp_operating_point = power_states.power + 1;
	cmd.wakelock_command_params.memory_operating_point = power_states.memory;
	cmd.type = WAKELOCK_COMMAND;
	cmd.priority = 0; /* currently unused */
	cmd.client_id = client->vd->client_id;

	ret = gxp_uci_send_command(
		&callisto->mcu.uci, &cmd,
		&client->vd->mailbox_resp_queues[UCI_RESOURCE_ID].queue,
		&client->vd->mailbox_resp_queues[UCI_RESOURCE_ID].lock,
		&client->vd->mailbox_resp_queues[UCI_RESOURCE_ID].waitq,
		client->mb_eventfds[UCI_RESOURCE_ID]);
	return ret;
}

static int callisto_platform_after_vd_block_ready(struct gxp_dev *gxp,
						  struct gxp_virtual_device *vd)
{
	struct gxp_kci *kci = &(to_callisto_dev(gxp)->mcu.kci);
	int pasid, ret;
	u8 operation = KCI_ALLOCATE_VMBOX_OP_ALLOCATE_VMBOX;

	if (gxp_is_direct_mode(gxp))
		return 0;

	if (vd->tpu_client_id >= 0)
		operation |= KCI_ALLOCATE_VMBOX_OP_LINK_OFFLOAD_VMBOX;

	pasid = gxp_iommu_aux_get_pasid(gxp, vd->domain);
	/* TODO(b/255706432): Adopt vd->slice_index after the firmware supports this. */
	ret = gxp_kci_allocate_vmbox(kci, pasid, vd->num_cores,
				     /*slice_index=*/0, vd->tpu_client_id,
				     operation);
	if (ret) {
		if (ret != GCIP_KCI_ERROR_UNIMPLEMENTED) {
			dev_err(gxp->dev,
				"Failed to allocate VMBox for client %d, TPU client %d: %d",
				pasid, vd->tpu_client_id, ret);
			return ret;
		}

		/*
		 * TODO(241057541): Remove this conditional branch after the firmware side
		 * implements handling allocate_vmbox command.
		 */
		dev_info(
			gxp->dev,
			"Allocating VMBox is not implemented from the firmware side");
	}

	vd->client_id = pasid;

	return 0;
}

static void
callisto_platform_before_vd_block_unready(struct gxp_dev *gxp,
					  struct gxp_virtual_device *vd)
{
	struct gxp_kci *kci = &(to_callisto_dev(gxp)->mcu.kci);
	int ret;

	if (gxp_is_direct_mode(gxp))
		return;

	if (vd->client_id < 0)
		return;

	ret = gxp_kci_release_vmbox(kci, vd->client_id);
	if (ret) {
		/*
		 * TODO(241057541): Remove this conditional branch after the firmware side
		 * implements handling allocate_vmbox command.
		 */
		if (ret == GCIP_KCI_ERROR_UNIMPLEMENTED)
			dev_info(
				gxp->dev,
				"Releasing VMBox is not implemented from the firmware side");
		else
			dev_err(gxp->dev,
				"Failed to release VMBox for client %d: %d",
				vd->client_id, ret);
	}

	vd->client_id = -1;
}

static int callisto_wakelock_after_blk_on(struct gxp_dev *gxp)
{
	struct gxp_mcu_firmware *mcu_fw = gxp_mcu_firmware_of(gxp);

	if (gxp_is_direct_mode(gxp))
		return 0;
	return gxp_mcu_firmware_run(mcu_fw);
}

static void callisto_wakelock_before_blk_off(struct gxp_dev *gxp)
{
	struct gxp_mcu_firmware *mcu_fw = gxp_mcu_firmware_of(gxp);

	if (gxp_is_direct_mode(gxp))
		return;
	gxp_mcu_firmware_stop(mcu_fw);
}

static int callisto_after_map_tpu_mbx_queue(struct gxp_dev *gxp,
					    struct gxp_client *client)
{
	struct gxp_kci *kci = &(to_callisto_dev(gxp)->mcu.kci);
	int tpu_client_id = -1, ret;

	/*
	 * TODO(b/247923533): Get a client ID from the TPU kernel driver and remove this workaround
	 * condition.
	 */
	if (tpu_client_id < 0)
		return 0;

	if (client->vd->client_id >= 0) {
		ret = gxp_kci_allocate_vmbox(
			kci, client->vd->client_id, 0, 0, tpu_client_id,
			KCI_ALLOCATE_VMBOX_OP_LINK_OFFLOAD_VMBOX);
		if (ret) {
			if (ret != GCIP_KCI_ERROR_UNIMPLEMENTED) {
				dev_err(gxp->dev,
					"Failed to link TPU VMbox client %d, TPU client %d: %d",
					client->vd->client_id, tpu_client_id,
					ret);
				return ret;
			}

			/*
			 * TODO(241057541): Remove this conditional branch after the firmware side
			 * implements handling allocate_vmbox command.
			 */
			dev_info(
				gxp->dev,
				"Linking TPU VNMBox is not implemented from the firmware side");
		}
	}

	client->vd->tpu_client_id = tpu_client_id;

	return 0;
}

static void callisto_before_unmap_tpu_mbx_queue(struct gxp_dev *gxp,
						struct gxp_client *client)
{
	/*
	 * We don't have to care about the case that the client releases a TPU vmbox which is
	 * linked to the DSP client without notifying the DSP MCU firmware because the client will
	 * always release the DSP vmbox earlier than the TPU vmbox. (i.e, the `release_vmbox` KCI
	 * command will be always sent to the DSP MCU firmware to release the DSP vmbox before
	 * releasing the TPU vmbox and the firmware will stop TPU offloading.) Also, from Callisto,
	 * we don't have to care about mapping/unmapping the TPU mailbox buffer here neither.
	 * Therefore, just unset the TPU client ID here.
	 */
	client->vd->tpu_client_id = -1;
}

static int gxp_platform_probe(struct platform_device *pdev)
{
	struct callisto_dev *callisto =
		devm_kzalloc(&pdev->dev, sizeof(*callisto), GFP_KERNEL);

	if (!callisto)
		return -ENOMEM;

	callisto->mode = callisto_dev_parse_work_mode(callisto_work_mode_name);

	callisto->gxp.parse_dt = callisto_platform_parse_dt;
	callisto->gxp.after_probe = callisto_platform_after_probe;
	callisto->gxp.before_remove = callisto_platform_before_remove;
	callisto->gxp.handle_ioctl = callisto_platform_ioctl;
	callisto->gxp.handle_mmap = callisto_platform_mmap;
	callisto->gxp.after_vd_block_ready =
		callisto_platform_after_vd_block_ready;
	callisto->gxp.before_vd_block_unready =
		callisto_platform_before_vd_block_unready;
	callisto->gxp.request_power_states = callisto_request_power_states;
	callisto->gxp.wakelock_after_blk_on = callisto_wakelock_after_blk_on;
	callisto->gxp.wakelock_before_blk_off =
		callisto_wakelock_before_blk_off;
	callisto->gxp.after_map_tpu_mbx_queue =
		callisto_after_map_tpu_mbx_queue;
	callisto->gxp.before_unmap_tpu_mbx_queue =
		callisto_before_unmap_tpu_mbx_queue;

	return gxp_common_platform_probe(pdev, &callisto->gxp);
}

static int gxp_platform_remove(struct platform_device *pdev)
{
	return gxp_common_platform_remove(pdev);
}

static const struct of_device_id gxp_of_match[] = {
	{ .compatible = "google,gxp", },
	{ .compatible = "google,gxp-zuma", },
	{ /* end of list */ },
};
MODULE_DEVICE_TABLE(of, gxp_of_match);

static struct platform_driver gxp_platform_driver = {
	.probe = gxp_platform_probe,
	.remove = gxp_platform_remove,
	.driver = {
			.name = GXP_DRIVER_NAME,
			.of_match_table = of_match_ptr(gxp_of_match),
#if IS_ENABLED(CONFIG_PM_SLEEP)
			.pm = &gxp_pm_ops,
#endif
		},
};

static int __init gxp_platform_init(void)
{
	gxp_common_platform_reg_sscd();
	return platform_driver_register(&gxp_platform_driver);
}

static void __exit gxp_platform_exit(void)
{
	platform_driver_unregister(&gxp_platform_driver);
	gxp_common_platform_unreg_sscd();
}

struct gxp_mcu *gxp_mcu_of(struct gxp_dev *gxp)
{
	return &(to_callisto_dev(gxp)->mcu);
}

struct gxp_mcu_firmware *gxp_mcu_firmware_of(struct gxp_dev *gxp)
{
	return &(to_callisto_dev(gxp)->mcu.fw);
}

bool gxp_is_direct_mode(struct gxp_dev *gxp)
{
	struct callisto_dev *callisto = to_callisto_dev(gxp);

	return callisto->mode == DIRECT;
}

enum gxp_chip_revision gxp_get_chip_revision(struct gxp_dev *gxp)
{
	if (!strcmp(zuma_revision, "a0"))
		return GXP_CHIP_A0;
	if (!strcmp(zuma_revision, "b0"))
		return GXP_CHIP_B0;
	return GXP_CHIP_ANY;
}

enum callisto_work_mode callisto_dev_parse_work_mode(const char *work_mode)
{
	if (!strcmp(work_mode, "mcu"))
		return MCU;
	return DIRECT;
}

MODULE_DESCRIPTION("Google GXP platform driver");
MODULE_LICENSE("GPL v2");
MODULE_INFO(gitinfo, GIT_REPO_TAG);
module_init(gxp_platform_init);
module_exit(gxp_platform_exit);
