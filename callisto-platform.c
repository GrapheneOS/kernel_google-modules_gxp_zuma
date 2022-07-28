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
#include "gxp-usage-stats.h"

static char *callisto_work_mode_name = "direct";
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

	gxp_usage_stats_init(gxp);
	return gxp_mcu_init(gxp, &callisto->mcu);
}

static void callisto_platform_before_remove(struct gxp_dev *gxp)
{
	struct callisto_dev *callisto = to_callisto_dev(gxp);

	gxp_mcu_exit(&callisto->mcu);
	gxp_usage_stats_exit(gxp);
}

static long callisto_platform_ioctl(struct file *file, uint cmd, ulong arg)
{
	struct gxp_client *client = file->private_data;
	long ret;

	if (gxp_is_direct_mode(client->gxp))
		return -ENOTTY;
	switch (cmd) {
	default:
		ret = -ENOTTY; /* unknown command */
	}

	return ret;
}

static int gxp_platform_probe(struct platform_device *pdev)
{
	struct callisto_dev *callisto =
		devm_kzalloc(&pdev->dev, sizeof(*callisto), GFP_KERNEL);

	if (!callisto)
		return -ENOMEM;

	callisto->gxp.parse_dt = callisto_platform_parse_dt;
	callisto->gxp.after_probe = callisto_platform_after_probe;
	callisto->gxp.before_remove = callisto_platform_before_remove;
	callisto->gxp.handle_ioctl = callisto_platform_ioctl;
	if (!strcmp(callisto_work_mode_name, "mcu"))
		callisto->mode = MCU;
	else
		callisto->mode = DIRECT;

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

MODULE_DESCRIPTION("Google GXP platform driver");
MODULE_LICENSE("GPL v2");
MODULE_INFO(gitinfo, GIT_REPO_TAG);
module_init(gxp_platform_init);
module_exit(gxp_platform_exit);
