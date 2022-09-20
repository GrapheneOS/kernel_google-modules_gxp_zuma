// SPDX-License-Identifier: GPL-2.0
/*
 * GXP MicroController Unit firmware management.
 *
 * Copyright (C) 2022 Google LLC
 */

#include <linux/device.h>
#include <linux/firmware.h>
#include <linux/io.h>
#include <linux/lockdep.h>
#include <linux/mutex.h>
#include <linux/resource.h>
#include <linux/string.h>

#include <gcip/gcip-image-config.h>

#include "gxp-bpm.h"
#include "gxp-config.h"
#include "gxp-doorbell.h"
#include "gxp-internal.h"
#include "gxp-kci.h"
#include "gxp-lpm.h"
#include "gxp-mcu-firmware.h"
#include "gxp-mcu.h"
#include "gxp-pm.h"
#include "gxp-wakelock.h"

static const char signature_magic_string[] = "DSPF";

/*
 * Programs instruction remap CSRs.
 */
static void program_iremap_csr(struct gxp_dev *gxp,
			       struct gxp_mapped_resource *buf)
{
	dev_info(gxp->dev, "Program instruction remap CSRs");
	gxp_write_32(gxp, GXP_REG_CFGVECTABLE0, buf->daddr);

	gxp_write_32(gxp, GXP_REG_IREMAP_LOW, buf->daddr);
	gxp_write_32(gxp, GXP_REG_IREMAP_HIGH, buf->daddr + buf->size);
	gxp_write_32(gxp, GXP_REG_IREMAP_TARGET, buf->daddr);
	gxp_write_32(gxp, GXP_REG_IREMAP_ENABLE, 1);
}

/*
 * Check whether the firmware file is signed or not.
 */
static bool is_signed_firmware(const struct firmware *fw)
{
	if (fw->size < MCU_SIGNATURE_SIZE)
		return false;

	if (strncmp(fw->data + MCU_SIGNATURE_HEADER_OFFSET,
		    signature_magic_string, strlen(signature_magic_string)))
		return false;

	return true;
}

/*
 * Loads firmware image to memory.
 */
static int gxp_mcu_firmware_load_locked(struct gxp_mcu_firmware *mcu_fw,
					const char *name)
{
	int ret;
	struct gxp_dev *gxp = mcu_fw->gxp;
	struct device *dev = gxp->dev;
	struct gcip_image_config *imgcfg;
	const struct firmware *fw;
	size_t offset, size;

	lockdep_assert_held(&mcu_fw->lock);
	ret = request_firmware(&fw, name, dev);
	if (ret) {
		dev_err(dev, "request firmware '%s' failed: %d", name, ret);
		return ret;
	}

	mcu_fw->is_signed = is_signed_firmware(fw);

	if (mcu_fw->is_signed) {
		offset = MCU_SIGNATURE_SIZE;
		size = fw->size - MCU_SIGNATURE_SIZE;
	} else {
		offset = 0;
		size = fw->size;
	}

	if (size > mcu_fw->image_buf.size) {
		dev_err(dev, "firmware %s size %#zx exceeds buffer size %#llx",
			name, size, mcu_fw->image_buf.size);
		ret = -ENOSPC;
		goto out_release_firmware;
	}

	if (mcu_fw->is_signed) {
		imgcfg = (struct gcip_image_config *)(fw->data +
						      MCU_IMAGE_CONFIG_OFFSET);
		ret = gcip_image_config_parse(&mcu_fw->cfg_parser, imgcfg);
		if (ret)
			dev_err(dev, "image config parsing failed: %d", ret);
	} else
		ret = iommu_map(iommu_get_domain_for_dev(gxp->dev),
				mcu_fw->image_buf.daddr,
				mcu_fw->image_buf.paddr, mcu_fw->image_buf.size,
				IOMMU_READ | IOMMU_WRITE);

	if (ret)
		goto out_release_firmware;

	memcpy(mcu_fw->image_buf.vaddr, fw->data + offset, size);

	if (!gxp->gsa_dev)
		program_iremap_csr(gxp, &mcu_fw->image_buf);
	gxp_bpm_configure(gxp, GXP_MCU_CORE_ID, INST_BPM_OFFSET,
			  BPM_EVENT_READ_XFER);

out_release_firmware:
	release_firmware(fw);
	return ret;
}

/*
 * Reverts gxp_mcu_firmware_load_locked. The firmware must be not running when
 * calling this method.
 */
static void gxp_mcu_firmware_unload_locked(struct gxp_mcu_firmware *mcu_fw)
{
	lockdep_assert_held(&mcu_fw->lock);
	if (mcu_fw->is_signed)
		gcip_image_config_clear(&mcu_fw->cfg_parser);
	else
		iommu_unmap(iommu_get_domain_for_dev(mcu_fw->gxp->dev),
			    mcu_fw->image_buf.daddr, mcu_fw->image_buf.size);
}

static int gxp_mcu_firmware_handshake(struct gxp_mcu_firmware *mcu_fw)
{
	struct gxp_dev *gxp = mcu_fw->gxp;
	struct gxp_mcu *mcu = container_of(mcu_fw, struct gxp_mcu, fw);
	enum gcip_fw_flavor fw_flavor;

	dev_dbg(gxp->dev, "Detecting MCU firmware info...");
	mcu_fw->fw_info.fw_build_time = 0;
	mcu_fw->fw_info.fw_flavor = GCIP_FW_FLAVOR_UNKNOWN;
	mcu_fw->fw_info.fw_changelist = 0;
	fw_flavor = gxp_kci_fw_info(&mcu->kci, &mcu_fw->fw_info);
	if (fw_flavor < 0) {
		dev_err(gxp->dev, "MCU firmware handshake failed: %d",
			fw_flavor);
		mcu_fw->fw_info.fw_flavor = GCIP_FW_FLAVOR_UNKNOWN;
		mcu_fw->fw_info.fw_changelist = 0;
		mcu_fw->fw_info.fw_build_time = 0;
		return fw_flavor;
	}

	dev_info(gxp->dev, "loaded %s MCU firmware (%u)",
		 gcip_fw_flavor_str(fw_flavor), mcu_fw->fw_info.fw_changelist);

	gxp_bpm_stop(gxp, GXP_MCU_CORE_ID);
	dev_notice(gxp->dev, "MCU Instruction read transactions: 0x%x\n",
		   gxp_bpm_read_counter(gxp, GXP_MCU_CORE_ID, INST_BPM_OFFSET));
	return 0;
}

static void gxp_mcu_firmware_stop_locked(struct gxp_mcu_firmware *mcu_fw)
{
	struct gxp_dev *gxp = mcu_fw->gxp;
	struct gxp_mcu *mcu = container_of(mcu_fw, struct gxp_mcu, fw);
	int ret;

	lockdep_assert_held(&mcu_fw->lock);
	ret = gxp_kci_shutdown(&mcu->kci);
	if (ret)
		dev_warn(gxp->dev, "KCI shutdown failed: %d", ret);
	gxp_lpm_down(gxp, GXP_MCU_CORE_ID);
	gxp_mcu_firmware_unload_locked(mcu_fw);
}

/*
 * Runs the firmware without checking current status.
 *
 * The firmware status would be set as GCIP_FW_LOADING when this function is
 * working, and set as GCIP_FW_VALID/INVALID on finished.
 *
 * @mcu_fw->name will be set to @name if firmware handshake succeeds, set to
 * NULL otherwise.
 *
 * Caller holds firmware lock.
 */
static int gxp_mcu_firmware_run_locked(struct gxp_mcu_firmware *mcu_fw,
				       const char *name)
{
	int ret;
	struct gxp_dev *gxp = mcu_fw->gxp;

	lockdep_assert_held(&mcu_fw->lock);

	if (!name)
		name = GXP_DEFAULT_MCU_FIRMWARE;
	mcu_fw->status = GCIP_FW_LOADING;

	ret = gxp_mcu_firmware_load_locked(mcu_fw, name);
	if (ret)
		goto err_invalid;
	ret = gxp_lpm_up(gxp, GXP_MCU_CORE_ID);
	if (ret)
		goto err_unload;
	/* Raise wakeup doorbell */
	dev_notice(gxp->dev, "Raising doorbell %d interrupt\n",
		   CORE_WAKEUP_DOORBELL(GXP_MCU_CORE_ID));
	gxp_doorbell_enable_for_core(gxp, CORE_WAKEUP_DOORBELL(GXP_MCU_CORE_ID),
				     GXP_MCU_CORE_ID);
	gxp_doorbell_set(gxp, CORE_WAKEUP_DOORBELL(GXP_MCU_CORE_ID));

	ret = gxp_mcu_firmware_handshake(mcu_fw);
	if (ret)
		goto err_lpm_down;
	dev_info(gxp->dev, "MCU firmware %s run succeeded", name);

	mcu_fw->status = GCIP_FW_VALID;
	mcu_fw->name = name;
	return 0;

err_lpm_down:
	gxp_lpm_down(gxp, GXP_MCU_CORE_ID);
err_unload:
	gxp_mcu_firmware_unload_locked(mcu_fw);
err_invalid:
	mcu_fw->status = GCIP_FW_INVALID;
	mcu_fw->name = NULL;
	return ret;
}

static int gxp_mcu_firmware_restart_locked(struct gxp_mcu_firmware *mcu_fw)
{
	/* TODO(b/233159020): implement restart */
	return gxp_mcu_firmware_run_locked(mcu_fw, mcu_fw->name);
}

static int init_mcu_firmware_buf(struct gxp_dev *gxp,
				 struct gxp_mapped_resource *buf)
{
	struct resource r;
	int ret;

	ret = gxp_acquire_rmem_resource(gxp, &r, "gxp-mcu-fw-region");
	if (ret)
		return ret;
	buf->size = resource_size(&r);
	buf->paddr = r.start;
	buf->daddr = GXP_IREMAP_CODE_BASE;
	buf->vaddr =
		devm_memremap(gxp->dev, buf->paddr, buf->size, MEMREMAP_WC);
	if (IS_ERR(buf->vaddr))
		ret = PTR_ERR(buf->vaddr);
	return ret;
}

static char *fw_name_from_buf(struct gxp_dev *gxp, const char *buf)
{
	size_t len;
	char *name;

	len = strlen(buf);
	/* buf from sysfs attribute contains the last line feed character */
	if (len == 0 || buf[len - 1] != '\n')
		return ERR_PTR(-EINVAL);

	name = devm_kstrdup(gxp->dev, buf, GFP_KERNEL);
	if (!name)
		return ERR_PTR(-ENOMEM);
	/* name should not contain the last line feed character */
	name[len - 1] = '\0';
	return name;
}

static ssize_t load_firmware_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	struct gxp_dev *gxp = dev_get_drvdata(dev);
	struct gxp_mcu_firmware *mcu_fw = gxp_mcu_firmware_of(gxp);
	int ret;
	const char *name;

	mutex_lock(&mcu_fw->lock);
	name = mcu_fw->name;
	/* name can be NULL when the last MCU firmware run failed */
	if (!name)
		name = "[none]";
	ret = scnprintf(buf, PAGE_SIZE, "%s\n", name);
	mutex_unlock(&mcu_fw->lock);
	return ret;
}

static ssize_t load_firmware_store(struct device *dev,
				   struct device_attribute *attr,
				   const char *buf, size_t count)
{
	struct gxp_dev *gxp = dev_get_drvdata(dev);
	struct gxp_mcu_firmware *mcu_fw = gxp_mcu_firmware_of(gxp);
	int ret;
	char *name;
	const char *last_name;

	/* early return without holding a lock when the FW run is ongoing */
	if (mcu_fw->status == GCIP_FW_LOADING)
		return -EBUSY;
	name = fw_name_from_buf(gxp, buf);
	if (IS_ERR(name))
		return PTR_ERR(name);
	if (gxp->wakelock_mgr->count) {
		dev_err(gxp->dev,
			"Reject firmware loading because wakelocks are holding");
		return -EBUSY;
		/*
		 * Note: it's still possible a wakelock is acquired by
		 * clients after the check above, but this function is for
		 * development purpose only, we don't insist on preventing
		 * race condition bugs.
		 */
	}
	dev_info(gxp->dev, "loading firmware %s from SysFS", name);
	last_name = mcu_fw->name;
	mcu_fw->name = name;
	ret = gxp_wakelock_acquire(gxp);
	if (ret) {
		dev_err(gxp->dev, "loading firmware %s failed: %d", name, ret);
		mcu_fw->name = last_name;
	} else {
		gxp_wakelock_release(gxp);
	}
	return ret < 0 ? ret : count;
}

static DEVICE_ATTR_RW(load_firmware);

static struct attribute *dev_attrs[] = {
	&dev_attr_load_firmware.attr,
	NULL,
};

static const struct attribute_group firmware_attr_group = {
	.attrs = dev_attrs,
};

static int image_config_map(void *data, dma_addr_t daddr, phys_addr_t paddr,
			    size_t size, unsigned int flags)
{
	struct gxp_dev *gxp = data;
	const bool ns = !(flags & GCIP_IMAGE_CONFIG_FLAGS_SECURE);

	if (ns) {
		dev_err(gxp->dev, "image config NS mappings are not supported");
		return -EINVAL;
	}
	return iommu_map(iommu_get_domain_for_dev(gxp->dev), daddr, paddr, size,
			 IOMMU_READ | IOMMU_WRITE);
}

static void image_config_unmap(void *data, dma_addr_t daddr, size_t size,
			       unsigned int flags)
{
	struct gxp_dev *gxp = data;

	iommu_unmap(iommu_get_domain_for_dev(gxp->dev), daddr, size);
}

int gxp_mcu_firmware_init(struct gxp_dev *gxp, struct gxp_mcu_firmware *mcu_fw)
{
	static const struct gcip_image_config_ops image_config_parser_ops = {
		.map = image_config_map,
		.unmap = image_config_unmap,
	};
	int ret;

	ret = gcip_image_config_parser_init(
		&mcu_fw->cfg_parser, &image_config_parser_ops, gxp->dev, gxp);
	if (unlikely(ret)) {
		dev_err(gxp->dev, "failed to init config parser: %d", ret);
		return ret;
	}
	ret = init_mcu_firmware_buf(gxp, &mcu_fw->image_buf);
	if (ret) {
		dev_err(gxp->dev, "failed to init MCU firmware buffer: %d",
			ret);
		return ret;
	}
	mcu_fw->gxp = gxp;
	mcu_fw->status = GCIP_FW_INVALID;
	mcu_fw->name = GXP_DEFAULT_MCU_FIRMWARE;
	mutex_init(&mcu_fw->lock);
	ret = device_add_group(gxp->dev, &firmware_attr_group);
	if (ret)
		dev_err(gxp->dev, "failed to create firmware device group");
	return ret;
}

void gxp_mcu_firmware_exit(struct gxp_mcu_firmware *mcu_fw)
{
	if (IS_GXP_TEST && (!mcu_fw || !mcu_fw->gxp))
		return;
	device_remove_group(mcu_fw->gxp->dev, &firmware_attr_group);
}

int gxp_mcu_firmware_run(struct gxp_mcu_firmware *mcu_fw)
{
	int ret;

	mutex_lock(&mcu_fw->lock);
	if (mcu_fw->status == GCIP_FW_VALID)
		ret = gxp_mcu_firmware_restart_locked(mcu_fw);
	else
		ret = gxp_mcu_firmware_run_locked(mcu_fw, mcu_fw->name);
	mutex_unlock(&mcu_fw->lock);
	return ret;
}

void gxp_mcu_firmware_stop(struct gxp_mcu_firmware *mcu_fw)
{
	mutex_lock(&mcu_fw->lock);
	gxp_mcu_firmware_stop_locked(mcu_fw);
	mutex_unlock(&mcu_fw->lock);
}
