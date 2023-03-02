/* SPDX-License-Identifier: GPL-2.0 */
/*
 * GXP MicroController Unit firmware management.
 *
 * Copyright (C) 2022 Google LLC
 */

#ifndef __GXP_MCU_FIRMWARE_H__
#define __GXP_MCU_FIRMWARE_H__

#include <linux/mutex.h>

#include <gcip/gcip-firmware.h>
#include <gcip/gcip-image-config.h>

#include "gxp-internal.h"

struct gxp_mcu_firmware {
	struct gxp_dev *gxp;
	/* resource for MCU firmware image */
	struct gxp_mapped_resource image_buf;

	struct mutex lock; /* lock to protect fields below */
	enum gcip_fw_status status;
	struct gcip_fw_info fw_info;
	struct gcip_image_config_parser cfg_parser;
	const char *name; /* the firmware name last loaded */
	bool is_signed;
};

/*
 * Initializes @mcu_fw.
 *
 * Returns 0 on success, a negative errno on failure.
 */
int gxp_mcu_firmware_init(struct gxp_dev *gxp, struct gxp_mcu_firmware *mcu_fw);
/* cleans up resources in @mcu_fw */
void gxp_mcu_firmware_exit(struct gxp_mcu_firmware *mcu_fw);

/*
 * Loads and runs the MCU firmware. The firmware is ready to serve when this
 * call succeeds.
 *
 * Returns 0 on success, a negative errno on failure.
 */
int gxp_mcu_firmware_run(struct gxp_mcu_firmware *mcu_fw);

/*
 * Stops the running MCU firmware.
 */
void gxp_mcu_firmware_stop(struct gxp_mcu_firmware *mcu_fw);

/*
 * Returns the pointer of MCU firmware associated with the GXP device object.
 *
 * This function is NOT implemented in gxp-mcu-firmware.c. Instead, it shall be
 * implemented in *-platform.c as a chip-dependent implementation.
 *
 * It's okay to not implement this function for chips without MCU support,
 * because in this case this function will never be used.
 */
struct gxp_mcu_firmware *gxp_mcu_firmware_of(struct gxp_dev *gxp);

/*
 * Handles the MCU firmware crash. It will handle the crash only when the @crash_type is
 * GCIP_FW_CRASH_UNRECOVERABLE_FAULT or GCIP_FW_CRASH_HW_WDG_TIMEOUT. Otherwise, it will ignore
 * that crash.
 *
 * This function will be called from the `gxp-kci.c` when GCIP_RKCI_FIRMWARE_CRASH RKCI is received
 * from the MCU firmware side or from the HW watchdog IRQ handler.
 */
void gxp_mcu_firmware_crash_handler(struct gxp_dev *gxp,
				    enum gcip_fw_crash_type crash_type);

#endif /* __GXP_MCU_FIRMWARE_H__ */
