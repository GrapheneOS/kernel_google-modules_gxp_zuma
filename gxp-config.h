/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Include all configuration files for GXP.
 *
 * Copyright (C) 2020 Google LLC
 */

#ifndef __GXP_CONFIG_H__
#define __GXP_CONFIG_H__

#include <gcip/gcip-config.h>

#if IS_ENABLED(CONFIG_CALLISTO)

#include "callisto/config.h"

#else /* unknown */

#error "Unknown GXP config"

#endif /* unknown */

#if IS_ENABLED(CONFIG_GXP_ZEBU)
#define GXP_TIME_DELAY_FACTOR 100
#elif IS_ENABLED(CONFIG_GXP_IP_ZEBU)
#define GXP_TIME_DELAY_FACTOR 500
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

/*
 * Only supports interop with TPU when
 * 1. Unit testing, or
 * 2. Production on Android (to exclude vanilla Linux for bringup) but not GEM5.
 */
#define HAS_TPU_EXT ((IS_ENABLED(CONFIG_GXP_TEST) || GCIP_IS_GKI) &&		\
		    !IS_ENABLED(CONFIG_GXP_GEM5) &&				\
		    !IS_ENABLED(CONFIG_GXP_IP_ZEBU) &&				\
		    !IS_ENABLED(CONFIG_GXP_ZEBU))

#endif /* __GXP_CONFIG_H__ */
