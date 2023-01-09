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
#include "gxp-kci.h"
#include "gxp-mcu-fs.h"
#include "gxp-uci.h"

#include "gxp-common-platform.c"

void gxp_iommu_setup_shareability(struct gxp_dev *gxp)
{
	void __iomem *addr = gxp->sysreg_shareability;

	if (IS_ERR_OR_NULL(addr))
		return;

	writel_relaxed(SHAREABLE_WRITE | SHAREABLE_READ | INNER_SHAREABLE,
		       addr + GXP_SYSREG_AUR0_SHAREABILITY);
	writel_relaxed(SHAREABLE_WRITE | SHAREABLE_READ | INNER_SHAREABLE,
		       addr + GXP_SYSREG_AUR1_SHAREABILITY);
}

static int callisto_platform_parse_dt(struct platform_device *pdev,
				      struct gxp_dev *gxp)
{
	struct resource *r;
	void *addr;
	struct device *dev = gxp->dev;
	int ret;
	u32 reg;

	/*
	 * Setting BAAW is required for having correct base for CSR accesses.
	 *
	 * BAAW is supposed to be set by bootloader. On production we simply
	 * don't include the register base in DTS to skip this procedure.
	 */
	r = platform_get_resource_byname(pdev, IORESOURCE_MEM, "baaw");
	if (!IS_ERR_OR_NULL(r)) {
		addr = devm_ioremap_resource(dev, r);
		/* start address */
		writel(0x0, addr + 0x0);
		/* Window - size */
		writel(0x8000000, addr + 0x4);
		/* Window - target */
		writel(0, addr + 0x8);
		/* Window - enable */
		writel(0x80000003, addr + 0xc);
	}

	if (!of_find_property(dev->of_node, "gxp,shareability", NULL)) {
		ret = -ENODEV;
		goto err;
	}
	ret = of_property_read_u32_index(dev->of_node,
					 "gxp,shareability", 0, &reg);
	if (ret)
		goto err;
	gxp->sysreg_shareability = devm_ioremap(dev, reg, PAGE_SIZE);
	if (!gxp->sysreg_shareability)
		ret = -ENOMEM;
err:
	if (ret)
		dev_warn(dev, "Failed to enable shareability: %d\n", ret);

	return 0;
}

static int callisto_request_power_states(struct gxp_client *client,
					 struct gxp_power_states power_states)
{
	struct gxp_dev *gxp = client->gxp;
	struct gxp_mcu *mcu = gxp_mcu_of(gxp);
	struct gxp_uci_command cmd;
	int ret;

	if (gxp_is_direct_mode(gxp))
		return -EOPNOTSUPP;

	/* Plus 1 to align with power states in MCU firmware. */
	cmd.wakelock_command_params.dsp_operating_point = power_states.power + 1;
	cmd.wakelock_command_params.memory_operating_point = power_states.memory;
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

static int link_offload_vmbox(struct gxp_dev *gxp,
			      struct gxp_virtual_device *vd,
			      u32 offload_client_id, u8 offload_chip_type)
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

static void unlink_offload_vmbox(struct gxp_dev *gxp,
				 struct gxp_virtual_device *vd,
				 u32 offload_client_id, u8 offload_chip_type)
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

static int callisto_platform_after_vd_block_ready(struct gxp_dev *gxp,
						  struct gxp_virtual_device *vd)
{
	int ret;

	if (gxp_is_direct_mode(gxp))
		return 0;

	ret = allocate_vmbox(gxp, vd);
	if (ret)
		return ret;

	if (vd->tpu_client_id >= 0) {
		ret = link_offload_vmbox(gxp, vd, vd->tpu_client_id,
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
callisto_platform_before_vd_block_unready(struct gxp_dev *gxp,
					  struct gxp_virtual_device *vd)
{
	if (gxp_is_direct_mode(gxp))
		return;
	if (vd->client_id < 0 || vd->state == GXP_VD_UNAVAILABLE)
		return;
	if (vd->tpu_client_id >= 0)
		unlink_offload_vmbox(gxp, vd, vd->tpu_client_id,
				     GCIP_KCI_OFFLOAD_CHIP_TYPE_TPU);
	release_vmbox(gxp, vd);
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

#ifdef HAS_TPU_EXT

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

static int callisto_after_map_tpu_mbx_queue(struct gxp_dev *gxp,
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
		ret = link_offload_vmbox(gxp, vd, tpu_client_id,
					 GCIP_KCI_OFFLOAD_CHIP_TYPE_TPU);
		if (ret)
			return ret;
	}

	vd->tpu_client_id = tpu_client_id;

	return 0;
}

static void callisto_before_unmap_tpu_mbx_queue(struct gxp_dev *gxp,
						struct gxp_client *client)
{
	struct gxp_virtual_device *vd = client->vd;

	if (vd->client_id >= 0 && vd->tpu_client_id >= 0)
		unlink_offload_vmbox(gxp, vd, vd->tpu_client_id,
				     GCIP_KCI_OFFLOAD_CHIP_TYPE_TPU);
	vd->tpu_client_id = -1;
}

#endif /* HAS_TPU_EXT */

static int gxp_platform_probe(struct platform_device *pdev)
{
	struct callisto_dev *callisto =
		devm_kzalloc(&pdev->dev, sizeof(*callisto), GFP_KERNEL);
	struct gxp_mcu_dev *mcu_dev = &callisto->mcu_dev;
	struct gxp_dev *gxp;

	if (!callisto)
		return -ENOMEM;

	gxp_mcu_dev_init(mcu_dev);

	gxp = &mcu_dev->gxp;
	gxp->parse_dt = callisto_platform_parse_dt;
	gxp->after_vd_block_ready = callisto_platform_after_vd_block_ready;
	gxp->before_vd_block_unready =
		callisto_platform_before_vd_block_unready;
	gxp->request_power_states = callisto_request_power_states;
	gxp->wakelock_after_blk_on = callisto_wakelock_after_blk_on;
	gxp->wakelock_before_blk_off = callisto_wakelock_before_blk_off;
#ifdef HAS_TPU_EXT
	gxp->after_map_tpu_mbx_queue = callisto_after_map_tpu_mbx_queue;
	gxp->before_unmap_tpu_mbx_queue = callisto_before_unmap_tpu_mbx_queue;
#endif

	return gxp_common_platform_probe(pdev, gxp);
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

MODULE_DESCRIPTION("Google GXP platform driver");
MODULE_LICENSE("GPL v2");
MODULE_INFO(gitinfo, GIT_REPO_TAG);
module_init(gxp_platform_init);
module_exit(gxp_platform_exit);
