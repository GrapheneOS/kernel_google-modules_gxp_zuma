/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Include all configuration files for Callisto.
 *
 * Copyright (C) 2022 Google LLC
 */

#ifndef __CALLISTO_CONFIG_H__
#define __CALLISTO_CONFIG_H__

#define GXP_DRIVER_NAME "gxp_callisto"
#define DSP_FIRMWARE_DEFAULT_PREFIX "gxp_callisto_fw_core"
#define GXP_DEFAULT_MCU_FIRMWARE "google/gxp-callisto.fw"

/*
 * From soc/gs/include/dt-bindings/clock/zuma.h
 *   #define ACPM_DVFS_AUR 0x0B040013
 */
#define AUR_DVFS_DOMAIN 19

#define GXP_NUM_CORES 3
/* three for cores, one for KCI, and one for UCI */
#define GXP_NUM_MAILBOXES (GXP_NUM_CORES + 2)
/* Indexes of the mailbox reg in device tree */
#define KCI_MAILBOX_ID (GXP_NUM_CORES)
#define UCI_MAILBOX_ID (GXP_NUM_CORES + 1)

/* three for cores, one for MCU */
#define GXP_NUM_WAKEUP_DOORBELLS (GXP_NUM_CORES + 1)

/* TODO(b/234098135): remove this when FW supports suspend / resume */
#define DISABLE_VD_SUSPEND_RESUME_SUPPORT
/*
 * Can be coherent with AP
 *
 * Linux IOMMU-DMA APIs optimise cache operations based on "dma-coherent"
 * property in DT. Handle "dma-coherent" property in driver itself instead of
 * specifying in DT so as to support both coherent and non-coherent buffers.
 */
#define GXP_IS_DMA_COHERENT

#include "config-pwr-state.h"
#include "context.h"
#include "csrs.h"
#include "iova.h"
#include "lpm.h"

#endif /* __CALLISTO_CONFIG_H__ */
