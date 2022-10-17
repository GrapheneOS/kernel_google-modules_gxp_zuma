/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Callisto LPM chip-dependent settings.
 *
 * Copyright (C) 2022 Google LLC
 */

#ifndef __CALLISTO_LPM_H__
#define __CALLISTO_LPM_H__

enum gxp_lpm_psm {
	LPM_PSM_CORE0 = 0,
	LPM_PSM_CORE1 = LPM_PSM_CORE0 + 1,
	LPM_PSM_CORE2 = LPM_PSM_CORE0 + 2,
	LPM_PSM_MCU,
	LPM_PSM_TOP,
	LPM_NUM_PSMS,
};

#define CORE_TO_PSM(core) (LPM_PSM_CORE0 + (core))

#endif /* __CALLISTO_LPM_H__ */
