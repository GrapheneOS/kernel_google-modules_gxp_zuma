// SPDX-License-Identifier: GPL-2.0
/*
 * Platform device driver for devices with MCU support.
 *
 * Copyright (C) 2022 Google LLC
 */

#include <linux/moduleparam.h>

#include "gxp-internal.h"
#include "gxp-mcu-fs.h"
#include "gxp-mcu-platform.h"
#include "gxp-mcu.h"
#include "gxp-usage-stats.h"

#if IS_ENABLED(CONFIG_GXP_TEST)
char *gxp_work_mode_name = "direct";
#else
static char *gxp_work_mode_name = "direct";
#endif

module_param_named(work_mode, gxp_work_mode_name, charp, 0660);

static char *chip_rev = "a0";
module_param(chip_rev, charp, 0660);

struct gxp_mcu *gxp_mcu_of(struct gxp_dev *gxp)
{
	return &(to_mcu_dev(gxp)->mcu);
}

struct gxp_mcu_firmware *gxp_mcu_firmware_of(struct gxp_dev *gxp)
{
	return &(gxp_mcu_of(gxp)->fw);
}

bool gxp_is_direct_mode(struct gxp_dev *gxp)
{
	struct gxp_mcu_dev *mcu_dev = to_mcu_dev(gxp);

	return mcu_dev->mode == DIRECT;
}

enum gxp_chip_revision gxp_get_chip_revision(struct gxp_dev *gxp)
{
	if (!strcmp(chip_rev, "a0"))
		return GXP_CHIP_A0;
	if (!strcmp(chip_rev, "b0"))
		return GXP_CHIP_B0;
	return GXP_CHIP_ANY;
}

int gxp_mcu_platform_after_probe(struct gxp_dev *gxp)
{
	if (gxp_is_direct_mode(gxp))
		return 0;

	gxp_usage_stats_init(gxp);
	return gxp_mcu_init(gxp, gxp_mcu_of(gxp));
}

void gxp_mcu_platform_before_remove(struct gxp_dev *gxp)
{
	if (gxp_is_direct_mode(gxp))
		return;

	gxp_mcu_exit(gxp_mcu_of(gxp));
	gxp_usage_stats_exit(gxp);
}

void gxp_mcu_dev_init(struct gxp_mcu_dev *mcu_dev)
{
	struct gxp_dev *gxp = &mcu_dev->gxp;

	mcu_dev->mode = gxp_dev_parse_work_mode(gxp_work_mode_name);
	gxp->after_probe = gxp_mcu_platform_after_probe;
	gxp->before_remove = gxp_mcu_platform_before_remove;
	gxp->handle_ioctl = gxp_mcu_ioctl;
	gxp->handle_mmap = gxp_mcu_mmap;
}

enum gxp_work_mode gxp_dev_parse_work_mode(const char *work_mode)
{
	if (!strcmp(work_mode, "mcu"))
		return MCU;
	return DIRECT;
}
