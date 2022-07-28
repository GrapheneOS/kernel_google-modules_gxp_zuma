/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Callisto LPM chip-dependent settings.
 *
 * Copyright (C) 2022 Google LLC
 */

#ifndef __CALLISTO_LPM_H__
#define __CALLISTO_LPM_H__

/* The index of MCU PSM. */
#define LPM_MCU_PSM 3
/* The index of TOP PSM. */
#define LPM_TOP_PSM 4
/* Total number of PSMs. 3 for cores + 1 for MCU + 1 for TOP. */
#define LPM_NUM_PSMS 5

#endif /* __CALLISTO_LPM_H__ */
