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
#include "gxp-uci.h"
#include "gxp-usage-stats.h"

char *callisto_work_mode_name = "direct";
module_param_named(work_mode, callisto_work_mode_name, charp, 0660);

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
	cmd.priority = 0; /* currently unused */
	cmd.client_id = iommu_aux_get_pasid(client->vd->domain, gxp->dev);

	ret = gxp_uci_send_command(
		&callisto->mcu.uci, &cmd,
		&client->vd->mailbox_resp_queues[UCI_RESOURCE_ID].queue,
		&client->vd->mailbox_resp_queues[UCI_RESOURCE_ID].lock,
		&client->vd->mailbox_resp_queues[UCI_RESOURCE_ID].waitq,
		client->mb_eventfds[UCI_RESOURCE_ID]);
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

static int gxp_ioctl_uci_command_compat(
	struct gxp_client *client,
	struct gxp_mailbox_command_compat_ioctl __user *argp)
{
	struct gxp_mailbox_command_compat_ioctl ibuf;
	struct gxp_mailbox_command_ioctl mailbox_command_buf;
	int ret;

	if (copy_from_user(&ibuf, argp, sizeof(ibuf)))
		return -EFAULT;

	mailbox_command_buf.num_cores = ibuf.num_cores;
	mailbox_command_buf.sequence_number = ibuf.sequence_number;
	mailbox_command_buf.device_address = ibuf.device_address;
	mailbox_command_buf.size = ibuf.size;
	mailbox_command_buf.flags = ibuf.flags;
	mailbox_command_buf.gxp_power_state = GXP_POWER_STATE_OFF;
	mailbox_command_buf.memory_power_state = MEMORY_POWER_STATE_UNDEFINED;
	mailbox_command_buf.power_flags = 0;

	ret = gxp_ioctl_uci_command_helper(client, &mailbox_command_buf);
	if (ret)
		return ret;

	ibuf.sequence_number = mailbox_command_buf.sequence_number;

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
	case GXP_MAILBOX_COMMAND_COMPAT:
		ret = gxp_ioctl_uci_command_compat(client, argp);
		break;
	case GXP_MAILBOX_RESPONSE:
		ret = gxp_ioctl_uci_response(client, argp);
		break;
	default:
		ret = -ENOTTY; /* unknown command */
	}

	return ret;
}

static int callisto_request_power_states(struct gxp_client *client, uint power_state,
				  uint memory_power_state, bool low_clkmux)
{
	struct gxp_dev *gxp = client->gxp;
	struct callisto_dev *callisto = to_callisto_dev(gxp);
	struct gxp_uci_command cmd;
	int ret;

	if (gxp_is_direct_mode(gxp))
		return -EOPNOTSUPP;

	/* Plus 1 to align with power states in MCU firmware. */
	cmd.wakelock_command_params.dsp_operating_point = power_state + 1;
	cmd.wakelock_command_params.memory_operating_point = memory_power_state;
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
	callisto->gxp.request_power_states = callisto_request_power_states;

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

struct gxp_mcu_firmware *gxp_mcu_firmware_of(struct gxp_dev *gxp)
{
	return &(to_callisto_dev(gxp)->mcu.fw);
}

bool gxp_is_direct_mode(struct gxp_dev *gxp)
{
	struct callisto_dev *callisto = to_callisto_dev(gxp);

	return callisto->mode == DIRECT;
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
