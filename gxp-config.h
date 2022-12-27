/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Include all configuration files for GXP.
 *
 * Copyright (C) 2020 Google LLC
 */

#ifndef __GXP_CONFIG_H__
#define __GXP_CONFIG_H__

#if IS_ENABLED(CONFIG_CALLISTO)

#include "callisto/config.h"

#else /* unknown */

#error "Unknown GXP config"

#endif /* unknown */

#if defined(CONFIG_GXP_ZEBU) || defined(CONFIG_GXP_IP_ZEBU)
#define GXP_TIME_DELAY_FACTOR 20
#else
#define GXP_TIME_DELAY_FACTOR 1
#endif

#define DOORBELL_COUNT 32

#define SYNC_BARRIER_COUNT 16

#ifndef GXP_USE_LEGACY_MAILBOX
#define GXP_USE_LEGACY_MAILBOX 0
#endif

#ifndef GXP_HAS_LAP
#define GXP_HAS_LAP 1
#endif

#ifndef GXP_HAS_MCU
#define GXP_HAS_MCU 1
#endif

#endif /* __GXP_CONFIG_H__ */
