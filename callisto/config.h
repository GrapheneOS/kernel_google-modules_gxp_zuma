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

#define GXP_NUM_CORES 3
/* three for cores, one for KCI, and one for UCI */
#define GXP_NUM_MAILBOXES (GXP_NUM_CORES + 2)
/* three for cores, one for MCU */
#define GXP_NUM_WAKEUP_DOORBELLS (GXP_NUM_CORES + 1)
/* Use the last mailbox for UCI */
#define UCI_MAILBOX_ID (GXP_NUM_CORES + 1)

/* TODO(b/234098135): remove this when FW supports suspend / resume */
#define DISABLE_VD_SUSPEND_RESUME_SUPPORT

#include "context.h"
#include "csrs.h"
#include "iova.h"
#include "lpm.h"

#endif /* __CALLISTO_CONFIG_H__ */
