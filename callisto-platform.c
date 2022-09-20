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

#include "callisto-platform.h"

#include "gxp-common-platform.c"
#include "gxp-kci.h"
#include "gxp-uci.h"
#include "gxp-usage-stats.h"

#if IS_ENABLED(CONFIG_GXP_TEST)
char *callisto_work_mode_name = "direct";
#else
static char *callisto_work_mode_name = "direct";
#endif

module_param_named(work_mode, callisto_work_mode_name, charp, 0660);

/*
 * TODO(b/245238253):
 * Set default to "B0/any" once we have most folks move to use B0 samples.
 */
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
	if (cmd.priority < 0) {
		dev_err(gxp->dev,
			"Mailbox command failed: Invalid virtual core id (%u)\n",
			ibuf->virtual_core_id);
		ret = -EINVAL;
		up_read(&gxp->vd_semaphore);
		goto out;
	}
	up_read(&gxp->vd_semaphore);

	cmd.client_id = iommu_aux_get_pasid(client->vd->domain, gxp->dev);

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
	default:
		ret = -ENOTTY; /* unknown command */
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
	cmd.client_id = iommu_aux_get_pasid(client->vd->domain, gxp->dev);

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

	if (gxp_is_direct_mode(gxp))
		return 0;

	pasid = iommu_aux_get_pasid(vd->domain, gxp->dev);
	ret = gxp_kci_allocate_vmbox(kci, vd->num_cores, pasid,
				     vd->slice_index);
	if (ret) {
		/*
		 * TODO(241057541): Remove this conditional branch after the firmware side
		 * implements handling allocate_vmbox command.
		 */
		if (ret == GCIP_KCI_ERROR_UNIMPLEMENTED) {
			dev_info(
				gxp->dev,
				"Allocating vmbox is not implemented from the firmware side");
			return 0;
		}
		dev_err(gxp->dev, "Failed to allocate virtual mailbox: ret=%d",
			ret);
	}

	return ret;
}

static void
callisto_platform_before_vd_block_unready(struct gxp_dev *gxp,
					  struct gxp_virtual_device *vd)
{
	struct gxp_kci *kci = &(to_callisto_dev(gxp)->mcu.kci);
	int pasid, ret;

	if (gxp_is_direct_mode(gxp))
		return;

	pasid = iommu_aux_get_pasid(vd->domain, gxp->dev);
	ret = gxp_kci_release_vmbox(kci, pasid);
	if (ret) {
		/*
		 * TODO(241057541): Remove this conditional branch after the firmware side
		 * implements handling allocate_vmbox command.
		 */
		if (ret == GCIP_KCI_ERROR_UNIMPLEMENTED) {
			dev_info(
				gxp->dev,
				"Releasing vmbox is not implemented from the firmware side");
			return;
		}
		dev_err(gxp->dev, "Failed to release virtual mailbox: ret=%d",
			ret);
	}
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
	callisto->gxp.after_vd_block_ready =
		callisto_platform_after_vd_block_ready;
	callisto->gxp.before_vd_block_unready =
		callisto_platform_before_vd_block_unready;
	callisto->gxp.request_power_states = callisto_request_power_states;
	callisto->gxp.wakelock_after_blk_on = callisto_wakelock_after_blk_on;
	callisto->gxp.wakelock_before_blk_off =
		callisto_wakelock_before_blk_off;

	return gxp_common_platform_probe(pdev, &callisto->gxp);
}

static int gxp_platform_remove(struct platform_device *pdev)
{
	return gxp_common_platform_remove(pdev);
}

static const struct of_device_id gxp_of_match[] = {
	{ .compatible = "google,gxp", },
	{ .compatible = "google,gxp-gs301", },
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
