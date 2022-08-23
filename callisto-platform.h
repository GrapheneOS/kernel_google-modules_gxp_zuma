/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Platform device driver for Callisto.
 *
 * Copyright (C) 2022 Google LLC
 */

#ifndef __CALLISTO_PLATFORM_H__
#define __CALLISTO_PLATFORM_H__

#include "gxp-internal.h"
#include "gxp-mcu.h"

#define to_callisto_dev(gxp) container_of(gxp, struct callisto_dev, gxp)

extern char *callisto_work_mode_name;

enum callisto_work_mode {
	MCU = 0,
	DIRECT = 1,
};

struct callisto_dev {
	struct gxp_dev gxp;
	struct gxp_mcu mcu;
	enum callisto_work_mode mode;
};

enum callisto_work_mode callisto_dev_parse_work_mode(const char *work_mode);

#endif /* __CALLISTO_PLATFORM_H__ */
