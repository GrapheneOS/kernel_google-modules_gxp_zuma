/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Structures and helpers for managing GXP MicroController Unit.
 *
 * Copyright (C) 2022 Google LLC
 */

#ifndef __GXP_MCU_H__
#define __GXP_MCU_H__

#include <gcip/gcip-mem-pool.h>

#include "gxp-kci.h"
#include "gxp-mcu-firmware.h"
#include "gxp-uci.h"

struct gxp_dev;
struct gxp_mapped_resource;

struct gxp_mcu {
	struct gxp_dev *gxp;
	struct gxp_mcu_firmware fw;
	/* instruction remapped data region */
	struct gcip_mem_pool remap_data_pool;
	/* secure region (memory inaccessible by non-secure AP (us)) */
	struct gcip_mem_pool remap_secure_pool;
	struct gxp_uci uci;
	struct gxp_kci kci;
};

/*
 * Initializes all fields in @mcu.
 *
 * Returns 0 on success, a negative errno on failure.
 */
int gxp_mcu_init(struct gxp_dev *gxp, struct gxp_mcu *mcu);
/* cleans up resources in @mcu */
void gxp_mcu_exit(struct gxp_mcu *mcu);
/*
 * A wrapper function to allocate memory from @mcu->remap_data_pool.
 *
 * Returns 0 on success, a negative errno otherwise.
 */
int gxp_mcu_mem_alloc_data(struct gxp_mcu *mcu, struct gxp_mapped_resource *mem, size_t size);
/*
 * Free memory allocated by gxp_mcu_mem_alloc_data().
 */
void gxp_mcu_mem_free_data(struct gxp_mcu *mcu, struct gxp_mapped_resource *mem);

#endif /* __GXP_MCU_H__ */
