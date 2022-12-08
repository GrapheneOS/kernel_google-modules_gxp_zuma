// SPDX-License-Identifier: GPL-2.0
/*
 * Platform device driver for Callisto.
 *
 * Copyright (C) 2022 Google LLC
 */

#include <linux/device.h>
#include <linux/io.h>
#include <linux/mod_devicetable.h>
#include <linux/platform_device.h>

#include "callisto-platform.h"

#include "gxp-common-platform.c"
#include "gxp-kci.h"
#include "gxp-mcu-fs.h"
#include "gxp-uci.h"
#include "gxp-usage-stats.h"

#if IS_ENABLED(CONFIG_GXP_TEST)
char *callisto_work_mode_name = "direct";
#else
static char *callisto_work_mode_name = "direct";
#endif

module_param_named(work_mode, callisto_work_mode_name, charp, 0660);

static char *zuma_revision = "a0";
module_param_named(chip_rev, zuma_revision, charp, 0660);

static int callisto_platform_parse_dt(struct platform_device *pdev,
				      struct gxp_dev *gxp)
{
	struct resource *r;
	void *addr;

	/*
	 * Setting BAAW is required for having correct base for CSR accesses.
	 *
	 * BAAW is supposed to be set by bootloader. On production we simply
	 * don't include the register base in DTS to skip this procedure.
	 */
	r = platform_get_resource_byname(pdev, IORESOURCE_MEM, "baaw");
	if (!IS_ERR_OR_NULL(r)) {
		addr = devm_ioremap_resource(gxp->dev, r);
		/* start address */
		writel(0x0, addr + 0x0);
		/* Window - size */
		writel(0x8000000, addr + 0x4);
		/* Window - target */
		writel(0, addr + 0x8);
		/* Window - enable */
		writel(0x80000003, addr + 0xc);
	}
	return 0;
}

static int callisto_platform_after_probe(struct gxp_dev *gxp)
{
	struct callisto_dev *callisto = to_callisto_dev(gxp);

	if (gxp_is_direct_mode(gxp))
		return 0;

	gxp_usage_stats_init(gxp);
	return gxp_mcu_init(gxp, &callisto->mcu);
}

static void callisto_platform_before_remove(struct gxp_dev *gxp)
{
	struct callisto_dev *callisto = to_callisto_dev(gxp);

	if (gxp_is_direct_mode(gxp))
		return;

	gxp_mcu_exit(&callisto->mcu);
	gxp_usage_stats_exit(gxp);
}

static int callisto_request_power_states(struct gxp_client *client,
					 struct gxp_power_states power_states)
{
	struct gxp_dev *gxp = client->gxp;
	struct callisto_dev *callisto = to_callisto_dev(gxp);
	struct gxp_uci_command cmd;
	int ret;

	if (gxp_is_direct_mode(gxp))
		return -EOPNOTSUPP;

	/* Plus 1 to align with power states in MCU firmware. */
	cmd.wakelock_command_params.dsp_operating_point = power_states.power + 1;
	cmd.wakelock_command_params.memory_operating_point = power_states.memory;
	cmd.type = WAKELOCK_COMMAND;
	cmd.priority = 0; /* currently unused */
	cmd.client_id = client->vd->client_id;

	ret = gxp_uci_send_command(
		&callisto->mcu.uci, client->vd, &cmd,
		&client->vd->mailbox_resp_queues[UCI_RESOURCE_ID].queue,
		&client->vd->mailbox_resp_queues[UCI_RESOURCE_ID].lock,
		&client->vd->mailbox_resp_queues[UCI_RESOURCE_ID].waitq,
		client->mb_eventfds[UCI_RESOURCE_ID]);
	return ret;
}

static int callisto_platform_after_vd_block_ready(struct gxp_dev *gxp,
						  struct gxp_virtual_device *vd)
{
	struct gxp_kci *kci = &(to_callisto_dev(gxp)->mcu.kci);
	int pasid, ret;
	u8 operation = KCI_ALLOCATE_VMBOX_OP_ALLOCATE_VMBOX;

	if (gxp_is_direct_mode(gxp))
		return 0;

	if (vd->tpu_client_id >= 0)
		operation |= KCI_ALLOCATE_VMBOX_OP_LINK_OFFLOAD_VMBOX;

	pasid = gxp_iommu_aux_get_pasid(gxp, vd->domain);
	/* TODO(b/255706432): Adopt vd->slice_index after the firmware supports this. */
	ret = gxp_kci_allocate_vmbox(kci, pasid, vd->num_cores,
				     /*slice_index=*/0, vd->tpu_client_id,
				     operation);
	if (ret) {
		if (ret != GCIP_KCI_ERROR_UNIMPLEMENTED) {
			dev_err(gxp->dev,
				"Failed to allocate VMBox for client %d, TPU client %d: %d",
				pasid, vd->tpu_client_id, ret);
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

	vd->client_id = pasid;

	return 0;
}

static void
callisto_platform_before_vd_block_unready(struct gxp_dev *gxp,
					  struct gxp_virtual_device *vd)
{
	struct gxp_kci *kci = &(to_callisto_dev(gxp)->mcu.kci);
	int ret;

	if (gxp_is_direct_mode(gxp))
		return;

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

static int callisto_wakelock_after_blk_on(struct gxp_dev *gxp)
{
	struct gxp_mcu_firmware *mcu_fw = gxp_mcu_firmware_of(gxp);

	if (gxp_is_direct_mode(gxp))
		return 0;
	return gxp_mcu_firmware_run(mcu_fw);
}

static void callisto_wakelock_before_blk_off(struct gxp_dev *gxp)
{
	struct gxp_mcu_firmware *mcu_fw = gxp_mcu_firmware_of(gxp);

	if (gxp_is_direct_mode(gxp))
		return;
	gxp_mcu_firmware_stop(mcu_fw);
}

static int callisto_after_map_tpu_mbx_queue(struct gxp_dev *gxp,
					    struct gxp_client *client)
{
	struct gxp_kci *kci = &(to_callisto_dev(gxp)->mcu.kci);
	int tpu_client_id = -1, ret;

	/*
	 * TODO(b/247923533): Get a client ID from the TPU kernel driver and remove this workaround
	 * condition.
	 */
	if (tpu_client_id < 0)
		return 0;

	if (client->vd->client_id >= 0) {
		ret = gxp_kci_allocate_vmbox(
			kci, client->vd->client_id, 0, 0, tpu_client_id,
			KCI_ALLOCATE_VMBOX_OP_LINK_OFFLOAD_VMBOX);
		if (ret) {
			if (ret != GCIP_KCI_ERROR_UNIMPLEMENTED) {
				dev_err(gxp->dev,
					"Failed to link TPU VMbox client %d, TPU client %d: %d",
					client->vd->client_id, tpu_client_id,
					ret);
				return ret;
			}

			/*
			 * TODO(241057541): Remove this conditional branch after the firmware side
			 * implements handling allocate_vmbox command.
			 */
			dev_info(
				gxp->dev,
				"Linking TPU VNMBox is not implemented from the firmware side");
		}
	}

	client->vd->tpu_client_id = tpu_client_id;

	return 0;
}

static void callisto_before_unmap_tpu_mbx_queue(struct gxp_dev *gxp,
						struct gxp_client *client)
{
	/*
	 * We don't have to care about the case that the client releases a TPU vmbox which is
	 * linked to the DSP client without notifying the DSP MCU firmware because the client will
	 * always release the DSP vmbox earlier than the TPU vmbox. (i.e, the `release_vmbox` KCI
	 * command will be always sent to the DSP MCU firmware to release the DSP vmbox before
	 * releasing the TPU vmbox and the firmware will stop TPU offloading.) Also, from Callisto,
	 * we don't have to care about mapping/unmapping the TPU mailbox buffer here neither.
	 * Therefore, just unset the TPU client ID here.
	 */
	client->vd->tpu_client_id = -1;
}

static int gxp_platform_probe(struct platform_device *pdev)
{
	struct callisto_dev *callisto =
		devm_kzalloc(&pdev->dev, sizeof(*callisto), GFP_KERNEL);

	if (!callisto)
		return -ENOMEM;

	callisto->mode = callisto_dev_parse_work_mode(callisto_work_mode_name);

	callisto->gxp.parse_dt = callisto_platform_parse_dt;
	callisto->gxp.after_probe = callisto_platform_after_probe;
	callisto->gxp.before_remove = callisto_platform_before_remove;
	callisto->gxp.handle_ioctl = gxp_mcu_ioctl;
	callisto->gxp.handle_mmap = gxp_mcu_mmap;
	callisto->gxp.after_vd_block_ready =
		callisto_platform_after_vd_block_ready;
	callisto->gxp.before_vd_block_unready =
		callisto_platform_before_vd_block_unready;
	callisto->gxp.request_power_states = callisto_request_power_states;
	callisto->gxp.wakelock_after_blk_on = callisto_wakelock_after_blk_on;
	callisto->gxp.wakelock_before_blk_off =
		callisto_wakelock_before_blk_off;
	callisto->gxp.after_map_tpu_mbx_queue =
		callisto_after_map_tpu_mbx_queue;
	callisto->gxp.before_unmap_tpu_mbx_queue =
		callisto_before_unmap_tpu_mbx_queue;

	return gxp_common_platform_probe(pdev, &callisto->gxp);
}

static int gxp_platform_remove(struct platform_device *pdev)
{
	return gxp_common_platform_remove(pdev);
}

static const struct of_device_id gxp_of_match[] = {
	{ .compatible = "google,gxp", },
	{ .compatible = "google,gxp-zuma", },
	{ /* end of list */ },
};
MODULE_DEVICE_TABLE(of, gxp_of_match);

static struct platform_driver gxp_platform_driver = {
	.probe = gxp_platform_probe,
	.remove = gxp_platform_remove,
	.driver = {
			.name = GXP_DRIVER_NAME,
			.of_match_table = of_match_ptr(gxp_of_match),
#if IS_ENABLED(CONFIG_PM_SLEEP)
			.pm = &gxp_pm_ops,
#endif
		},
};

static int __init gxp_platform_init(void)
{
	gxp_common_platform_reg_sscd();
	return platform_driver_register(&gxp_platform_driver);
}

static void __exit gxp_platform_exit(void)
{
	platform_driver_unregister(&gxp_platform_driver);
	gxp_common_platform_unreg_sscd();
}

struct gxp_mcu *gxp_mcu_of(struct gxp_dev *gxp)
{
	return &(to_callisto_dev(gxp)->mcu);
}

struct gxp_mcu_firmware *gxp_mcu_firmware_of(struct gxp_dev *gxp)
{
	return &(to_callisto_dev(gxp)->mcu.fw);
}

bool gxp_is_direct_mode(struct gxp_dev *gxp)
{
	struct callisto_dev *callisto = to_callisto_dev(gxp);

	return callisto->mode == DIRECT;
}

enum gxp_chip_revision gxp_get_chip_revision(struct gxp_dev *gxp)
{
	if (!strcmp(zuma_revision, "a0"))
		return GXP_CHIP_A0;
	if (!strcmp(zuma_revision, "b0"))
		return GXP_CHIP_B0;
	return GXP_CHIP_ANY;
}

enum callisto_work_mode callisto_dev_parse_work_mode(const char *work_mode)
{
	if (!strcmp(work_mode, "mcu"))
		return MCU;
	return DIRECT;
}

MODULE_DESCRIPTION("Google GXP platform driver");
MODULE_LICENSE("GPL v2");
MODULE_INFO(gitinfo, GIT_REPO_TAG);
module_init(gxp_platform_init);
module_exit(gxp_platform_exit);
