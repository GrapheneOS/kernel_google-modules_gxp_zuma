// SPDX-License-Identifier: GPL-2.0
/*
 * Platform device driver for devices with MCU support.
 *
 * Copyright (C) 2022 Google LLC
 */

#include <linux/moduleparam.h>

#include "gxp-config.h"
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

static int gxp_mcu_request_power_states(struct gxp_client *client,
					struct gxp_power_states power_states)
{
	struct gxp_dev *gxp = client->gxp;
	struct gxp_mcu *mcu = gxp_mcu_of(gxp);
	struct gxp_uci_command cmd;
	int ret;

	if (gxp_is_direct_mode(gxp))
		return -EOPNOTSUPP;

	/* Plus 1 to align with power states in MCU firmware. */
	cmd.wakelock_command_params.dsp_operating_point =
		power_states.power + 1;
	cmd.wakelock_command_params.memory_operating_point =
		power_states.memory;
	cmd.type = WAKELOCK_COMMAND;
	cmd.client_id = client->vd->client_id;

	ret = gxp_uci_send_command(
		&mcu->uci, client->vd, &cmd,
		&client->vd->mailbox_resp_queues[UCI_RESOURCE_ID].wait_queue,
		&client->vd->mailbox_resp_queues[UCI_RESOURCE_ID].dest_queue,
		&client->vd->mailbox_resp_queues[UCI_RESOURCE_ID].lock,
		&client->vd->mailbox_resp_queues[UCI_RESOURCE_ID].waitq,
		client->mb_eventfds[UCI_RESOURCE_ID]);
	return ret;
}

static int allocate_vmbox(struct gxp_dev *gxp, struct gxp_virtual_device *vd)
{
	struct gxp_kci *kci = &(gxp_mcu_of(gxp)->kci);
	int client_id, ret;

	if (vd->is_secure)
		client_id = SECURE_CLIENT_ID;
	else
		client_id = gxp_iommu_aux_get_pasid(gxp, vd->domain);

	ret = gxp_kci_allocate_vmbox(kci, client_id, vd->num_cores,
				     vd->slice_index, vd->first_open);
	if (ret) {
		if (ret != GCIP_KCI_ERROR_UNIMPLEMENTED) {
			dev_err(gxp->dev,
				"Failed to allocate VMBox for client %d, TPU client %d: %d",
				client_id, vd->tpu_client_id, ret);
			return ret;
		}

		/*
		 * TODO(241057541): Remove this conditional branch after the firmware side
		 * implements handling allocate_vmbox command.
		 */
		dev_info(
			gxp->dev,
			"Allocating VMBox is not implemented from the firmware side");
	}

	vd->client_id = client_id;
	vd->first_open = false;

	return 0;
}

static void release_vmbox(struct gxp_dev *gxp, struct gxp_virtual_device *vd)
{
	struct gxp_kci *kci = &(gxp_mcu_of(gxp)->kci);
	int ret;

	if (vd->client_id < 0)
		return;

	ret = gxp_kci_release_vmbox(kci, vd->client_id);
	if (ret) {
		/*
		 * TODO(241057541): Remove this conditional branch after the firmware side
		 * implements handling allocate_vmbox command.
		 */
		if (ret == GCIP_KCI_ERROR_UNIMPLEMENTED)
			dev_info(
				gxp->dev,
				"Releasing VMBox is not implemented from the firmware side");
		else
			dev_err(gxp->dev,
				"Failed to release VMBox for client %d: %d",
				vd->client_id, ret);
	}

	vd->client_id = -1;
}

static int gxp_mcu_link_offload_vmbox(struct gxp_dev *gxp,
				      struct gxp_virtual_device *vd,
				      u32 offload_client_id,
				      u8 offload_chip_type)
{
	struct gxp_kci *kci = &(gxp_mcu_of(gxp)->kci);
	int ret;

	ret = gxp_kci_link_unlink_offload_vmbox(
		kci, vd->client_id, offload_client_id, offload_chip_type, true);
	if (ret) {
		if (ret != GCIP_KCI_ERROR_UNIMPLEMENTED) {
			dev_err(gxp->dev,
				"Failed to link offload VMBox for client %d, offload client %u, offload chip type %d: %d",
				vd->client_id, offload_client_id,
				offload_chip_type, ret);
			return ret;
		}

		/*
		 * TODO(241057541): Remove this conditional branch after the firmware side
		 * implements handling link_offload_vmbox command.
		 */
		dev_info(
			gxp->dev,
			"Linking offload VMBox is not implemented from the firmware side");
	}

	return 0;
}

static void gxp_mcu_unlink_offload_vmbox(struct gxp_dev *gxp,
					 struct gxp_virtual_device *vd,
					 u32 offload_client_id,
					 u8 offload_chip_type)
{
	struct gxp_kci *kci = &(gxp_mcu_of(gxp)->kci);
	int ret;

	ret = gxp_kci_link_unlink_offload_vmbox(kci, vd->client_id,
						offload_client_id,
						offload_chip_type, false);
	if (ret) {
		/*
		 * TODO(241057541): Remove this conditional branch after the firmware side
		 * implements handling allocate_vmbox command.
		 */
		if (ret == GCIP_KCI_ERROR_UNIMPLEMENTED)
			dev_info(
				gxp->dev,
				"Unlinking offload VMBox is not implemented from the firmware side");
		else
			dev_err(gxp->dev,
				"Failed to unlink offload VMBox for client %d, offload client %u, offload chip type %d: %d",
				vd->client_id, offload_client_id,
				offload_chip_type, ret);
	}
}

static int gxp_mcu_platform_after_vd_block_ready(struct gxp_dev *gxp,
						 struct gxp_virtual_device *vd)
{
	int ret;

	if (gxp_is_direct_mode(gxp))
		return 0;

	ret = allocate_vmbox(gxp, vd);
	if (ret)
		return ret;

	if (vd->tpu_client_id >= 0) {
		ret = gxp_mcu_link_offload_vmbox(
			gxp, vd, vd->tpu_client_id,
			GCIP_KCI_OFFLOAD_CHIP_TYPE_TPU);
		if (ret)
			goto err_release_vmbox;
	}

	return 0;

err_release_vmbox:
	release_vmbox(gxp, vd);
	return ret;
}

static void
gxp_mcu_platform_before_vd_block_unready(struct gxp_dev *gxp,
					 struct gxp_virtual_device *vd)
{
	if (gxp_is_direct_mode(gxp))
		return;
	if (vd->client_id < 0 || vd->state == GXP_VD_UNAVAILABLE)
		return;
	if (vd->tpu_client_id >= 0)
		gxp_mcu_unlink_offload_vmbox(gxp, vd, vd->tpu_client_id,
					     GCIP_KCI_OFFLOAD_CHIP_TYPE_TPU);
	release_vmbox(gxp, vd);
}

static int gxp_mcu_wakelock_after_blk_on(struct gxp_dev *gxp)
{
	struct gxp_mcu_firmware *mcu_fw = gxp_mcu_firmware_of(gxp);

	if (gxp_is_direct_mode(gxp))
		return 0;
	return gxp_mcu_firmware_run(mcu_fw);
}

static void gxp_mcu_wakelock_before_blk_off(struct gxp_dev *gxp)
{
	struct gxp_mcu_firmware *mcu_fw = gxp_mcu_firmware_of(gxp);

	if (gxp_is_direct_mode(gxp))
		return;
	gxp_mcu_firmware_stop(mcu_fw);
}

#if HAS_TPU_EXT

static int get_tpu_client_id(struct gxp_client *client)
{
	struct gxp_dev *gxp = client->gxp;
	struct edgetpu_ext_offload_info offload_info;
	struct edgetpu_ext_client_info tpu_info;
	int ret;

	tpu_info.tpu_file = client->tpu_file;
	ret = edgetpu_ext_driver_cmd(gxp->tpu_dev.dev,
				     EDGETPU_EXTERNAL_CLIENT_TYPE_DSP,
				     START_OFFLOAD, &tpu_info, &offload_info);
	if (ret)
		return ret;

	return offload_info.client_id;
}

static int gxp_mcu_after_map_tpu_mbx_queue(struct gxp_dev *gxp,
					   struct gxp_client *client)
{
	struct gxp_virtual_device *vd = client->vd;
	int tpu_client_id = -1, ret;

	if (gxp_is_direct_mode(gxp))
		return 0;

	tpu_client_id = get_tpu_client_id(client);
	if (tpu_client_id < 0) {
		dev_err(gxp->dev, "Failed to get a TPU client ID: %d",
			tpu_client_id);
		return tpu_client_id;
	}

	if (vd->client_id >= 0) {
		ret = gxp_mcu_link_offload_vmbox(
			gxp, vd, tpu_client_id, GCIP_KCI_OFFLOAD_CHIP_TYPE_TPU);
		if (ret)
			return ret;
	}

	vd->tpu_client_id = tpu_client_id;

	return 0;
}

static void gxp_mcu_before_unmap_tpu_mbx_queue(struct gxp_dev *gxp,
					       struct gxp_client *client)
{
	struct gxp_virtual_device *vd = client->vd;

	if (vd->client_id >= 0 && vd->tpu_client_id >= 0)
		gxp_mcu_unlink_offload_vmbox(gxp, vd, vd->tpu_client_id,
					     GCIP_KCI_OFFLOAD_CHIP_TYPE_TPU);
	vd->tpu_client_id = -1;
}

#endif /* HAS_TPU_EXT */

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
	gxp->after_vd_block_ready = gxp_mcu_platform_after_vd_block_ready;
	gxp->before_vd_block_unready = gxp_mcu_platform_before_vd_block_unready;
	gxp->request_power_states = gxp_mcu_request_power_states;
	gxp->wakelock_after_blk_on = gxp_mcu_wakelock_after_blk_on;
	gxp->wakelock_before_blk_off = gxp_mcu_wakelock_before_blk_off;
#if HAS_TPU_EXT
	gxp->after_map_tpu_mbx_queue = gxp_mcu_after_map_tpu_mbx_queue;
	gxp->before_unmap_tpu_mbx_queue = gxp_mcu_before_unmap_tpu_mbx_queue;
#endif
}

enum gxp_work_mode gxp_dev_parse_work_mode(const char *work_mode)
{
	if (!strcmp(work_mode, "mcu"))
		return MCU;
	return DIRECT;
}
