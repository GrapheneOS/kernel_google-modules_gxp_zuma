// SPDX-License-Identifier: GPL-2.0-only
/*
 * GXP MicroController Unit firmware management.
 *
 * Copyright (C) 2022 Google LLC
 */

#include <linux/device.h>
#include <linux/firmware.h>
#include <linux/gsa/gsa_dsp.h>
#include <linux/io.h>
#include <linux/lockdep.h>
#include <linux/mutex.h>
#include <linux/resource.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <gcip/gcip-common-image-header.h>
#include <gcip/gcip-image-config.h>
#include <gcip/gcip-pm.h>
#include <gcip/gcip-thermal.h>

#include "gxp-bpm.h"
#include "gxp-config.h"
#include "gxp-dma.h"
#include "gxp-doorbell.h"
#include "gxp-firmware-loader.h"
#include "gxp-internal.h"
#include "gxp-kci.h"
#include "gxp-lpm.h"
#include "gxp-mcu-firmware.h"
#include "gxp-mcu.h"
#include "gxp-pm.h"

/* Value of Magic field in the common header "DSPF' as a 32-bit LE int */
#define GXP_FW_MAGIC 0x46505344

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
static bool is_signed_firmware(const struct firmware *fw,
			       const struct gcip_common_image_header *hdr)
{
	if (fw->size < GCIP_FW_HEADER_SIZE)
		return false;

	if (hdr->common.magic != GXP_FW_MAGIC)
		return false;

	return true;
}

int gxp_mcu_firmware_load(struct gxp_dev *gxp, char *fw_name,
			  const struct firmware **fw)
{
	int ret;
	struct gxp_mcu_firmware *mcu_fw = gxp_mcu_firmware_of(gxp);
	struct device *dev = gxp->dev;
	struct gcip_image_config *imgcfg;
	struct gcip_common_image_header *hdr;
	size_t offset, size;
	bool is_signed;

	mutex_lock(&mcu_fw->lock);
	if (mcu_fw->status == GCIP_FW_LOADING ||
	    mcu_fw->status == GCIP_FW_VALID) {
		dev_info(gxp->dev, "MCU firmware is loaded, skip loading");
		goto out;
	}

	mcu_fw->status = GCIP_FW_LOADING;
	if (fw_name == NULL)
		fw_name = GXP_DEFAULT_MCU_FIRMWARE;
	dev_info(gxp->dev, "MCU firmware %s loading", fw_name);

	ret = request_firmware(fw, fw_name, dev);
	if (ret) {
		dev_err(dev, "request firmware '%s' failed: %d", fw_name, ret);
		goto err_out;
	}

	hdr = (struct gcip_common_image_header *)(*fw)->data;

	is_signed = is_signed_firmware(*fw, hdr);

	if (is_signed) {
		offset = GCIP_FW_HEADER_SIZE;
		size = (*fw)->size - GCIP_FW_HEADER_SIZE;
	} else {
		offset = 0;
		size = (*fw)->size;
	}

	if (size > mcu_fw->image_buf.size) {
		dev_err(dev, "firmware %s size %#zx exceeds buffer size %#llx",
			fw_name, size, mcu_fw->image_buf.size);
		ret = -ENOSPC;
		goto err_release_firmware;
	}

	if (is_signed) {
		imgcfg = get_image_config_from_hdr(hdr);
		if (!imgcfg) {
			dev_err(dev, "Unsupported image header generation");
			ret = -EINVAL;
			goto err_release_firmware;
		}
		ret = gcip_image_config_parse(&mcu_fw->cfg_parser, imgcfg);
		if (ret)
			dev_err(dev, "image config parsing failed: %d", ret);
		mcu_fw->is_secure = !gcip_image_config_is_ns(imgcfg);
	} else {
		ret = gxp_iommu_map(gxp, gxp_iommu_get_domain_for_dev(gxp),
				    mcu_fw->image_buf.daddr,
				    mcu_fw->image_buf.paddr,
				    mcu_fw->image_buf.size,
				    IOMMU_READ | IOMMU_WRITE);
		mcu_fw->is_secure = false;
	}

	if (ret)
		goto err_release_firmware;

	memcpy(mcu_fw->image_buf.vaddr, (*fw)->data + offset, size);
out:
	mutex_unlock(&mcu_fw->lock);
	return 0;

err_release_firmware:
	release_firmware(*fw);
err_out:
	mcu_fw->status = GCIP_FW_INVALID;
	mutex_unlock(&mcu_fw->lock);
	return ret;
}

void gxp_mcu_firmware_unload(struct gxp_dev *gxp, const struct firmware *fw)
{
	struct gcip_common_image_header *hdr;
	struct gxp_mcu_firmware *mcu_fw = gxp_mcu_firmware_of(gxp);
	bool is_signed;

	mutex_lock(&mcu_fw->lock);
	if (mcu_fw->status == GCIP_FW_INVALID) {
		dev_err(mcu_fw->gxp->dev, "Failed to unload MCU firmware");
		mutex_unlock(&mcu_fw->lock);
		return;
	}
	hdr = (struct gcip_common_image_header *)fw->data;
	is_signed = is_signed_firmware(fw, hdr);
	if (is_signed)
		gcip_image_config_clear(&mcu_fw->cfg_parser);
	else
		gxp_iommu_unmap(mcu_fw->gxp,
				gxp_iommu_get_domain_for_dev(mcu_fw->gxp),
				mcu_fw->image_buf.daddr,
				mcu_fw->image_buf.size);
	mcu_fw->status = GCIP_FW_INVALID;
	mutex_unlock(&mcu_fw->lock);
}

static int gxp_mcu_firmware_handshake(struct gxp_mcu_firmware *mcu_fw)
{
	struct gxp_dev *gxp = mcu_fw->gxp;
	struct gxp_mcu *mcu = container_of(mcu_fw, struct gxp_mcu, fw);
	enum gcip_fw_flavor fw_flavor;
	int ret;

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

	ret = gxp_mcu_telemetry_kci(mcu);
	if (ret)
		dev_warn(gxp->dev, "telemetry KCI error: %d", ret);

	ret = gcip_thermal_restore_on_powering(gxp->thermal);
	if (ret)
		dev_warn(gxp->dev, "thermal restore error: %d", ret);

	return 0;
}

static void gxp_mcu_firmware_stop_locked(struct gxp_mcu_firmware *mcu_fw)
{
	struct gxp_dev *gxp = mcu_fw->gxp;
	struct gxp_mcu *mcu = container_of(mcu_fw, struct gxp_mcu, fw);
	int ret;

	lockdep_assert_held(&mcu_fw->lock);

	gxp_lpm_enable_state(gxp, CORE_TO_PSM(GXP_MCU_CORE_ID), LPM_PG_STATE);

	/* Clear doorbell to refuse non-expected interrupts */
	gxp_doorbell_clear(gxp, CORE_WAKEUP_DOORBELL(GXP_MCU_CORE_ID));

	ret = gxp_kci_shutdown(&mcu->kci);
	if (ret)
		dev_warn(gxp->dev, "KCI shutdown failed: %d", ret);

	if (!gxp_lpm_wait_state_eq(gxp, CORE_TO_PSM(GXP_MCU_CORE_ID),
				   LPM_PG_STATE))
		dev_warn(gxp->dev,
			 "MCU PSM transition to PS3 fails, current state: %u\n",
			 gxp_lpm_get_state(gxp, CORE_TO_PSM(GXP_MCU_CORE_ID)));
	if (mcu_fw->is_secure)
		gsa_send_dsp_cmd(gxp->gsa_dev, GSA_DSP_SHUTDOWN);
}

static int gxp_mcu_firmware_power_up(struct gxp_mcu_firmware *mcu_fw)
{
	struct gxp_dev *gxp = mcu_fw->gxp;
	int ret;
	int state;

	gxp_bpm_configure(gxp, GXP_MCU_CORE_ID, INST_BPM_OFFSET,
			  BPM_EVENT_READ_XFER);

	ret = gxp_lpm_up(gxp, GXP_MCU_CORE_ID);
	if (ret)
		return ret;

	if (mcu_fw->is_secure) {
		state = gsa_send_dsp_cmd(gxp->gsa_dev, GSA_DSP_START);
		if (state != GSA_DSP_STATE_RUNNING)
			goto err_lpm_down;
	} else {
		program_iremap_csr(gxp, &mcu_fw->image_buf);
		/* Raise wakeup doorbell */
		dev_dbg(gxp->dev, "Raising doorbell %d interrupt\n",
			CORE_WAKEUP_DOORBELL(GXP_MCU_CORE_ID));
		gxp_doorbell_enable_for_core(
			gxp, CORE_WAKEUP_DOORBELL(GXP_MCU_CORE_ID),
			GXP_MCU_CORE_ID);
		gxp_doorbell_set(gxp, CORE_WAKEUP_DOORBELL(GXP_MCU_CORE_ID));
	}

	ret = gxp_mcu_firmware_handshake(mcu_fw);
	if (ret)
		goto err_mcu_shutdown;
	dev_info(gxp->dev, "MCU firmware run succeeded");

	return ret;

err_mcu_shutdown:
	if (mcu_fw->is_secure)
		gsa_send_dsp_cmd(gxp->gsa_dev, GSA_DSP_SHUTDOWN);
err_lpm_down:
	gxp_lpm_down(gxp, GXP_MCU_CORE_ID);
	return ret;
}

/*
 * Caller must hold firmware lock.
 */
static int gxp_mcu_firmware_run_locked(struct gxp_mcu_firmware *mcu_fw)
{
	int ret;

	lockdep_assert_held(&mcu_fw->lock);

	ret = gxp_mcu_firmware_power_up(mcu_fw);
	if (ret)
		return ret;

	mcu_fw->status = GCIP_FW_VALID;
	return 0;
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
	ssize_t ret;
	char *firmware_name = gxp_firmware_loader_get_mcu_fw_name(gxp);

	ret = scnprintf(buf, PAGE_SIZE, "%s\n", firmware_name);
	kfree(firmware_name);
	return ret;
}

static ssize_t load_firmware_store(struct device *dev,
				   struct device_attribute *attr,
				   const char *buf, size_t count)
{
	struct gxp_dev *gxp = dev_get_drvdata(dev);
	int ret;
	char *name;

	name = fw_name_from_buf(gxp, buf);
	if (IS_ERR(name))
		return PTR_ERR(name);
	if (gcip_pm_is_powered(gxp->power_mgr->pm)) {
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
	/*
	 * It's possible a race condition bug here that someone opens a gxp
	 * device and loads the firmware between below unload/load functions in
	 * another thread, but this interface is only for developer debugging.
	 * We don't insist on preventing the race condition bug.
	 */
	gxp_firmware_loader_unload(gxp);
	gxp_firmware_loader_set_mcu_fw_name(gxp, name);
	ret = gxp_firmware_loader_load_if_needed(gxp);
	if (ret) {
		dev_err(gxp->dev, "Failed to load MCU firmware: %s\n", name);
		return ret;
	}
	return count;
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

	return gxp_iommu_map(gxp, gxp_iommu_get_domain_for_dev(gxp), daddr,
			     paddr, size, IOMMU_READ | IOMMU_WRITE);
}

static void image_config_unmap(void *data, dma_addr_t daddr, size_t size,
			       unsigned int flags)
{
	struct gxp_dev *gxp = data;

	gxp_iommu_unmap(gxp, gxp_iommu_get_domain_for_dev(gxp), daddr, size);
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
	if (mcu_fw->status == GCIP_FW_INVALID)
		ret = -EINVAL;
	else
		ret = gxp_mcu_firmware_run_locked(mcu_fw);
	mutex_unlock(&mcu_fw->lock);
	return ret;
}

void gxp_mcu_firmware_stop(struct gxp_mcu_firmware *mcu_fw)
{
	mutex_lock(&mcu_fw->lock);
	gxp_mcu_firmware_stop_locked(mcu_fw);
	mutex_unlock(&mcu_fw->lock);
}

void gxp_mcu_firmware_crash_handler(struct gxp_dev *gxp,
				    enum gcip_fw_crash_type crash_type)
{
	struct gxp_mcu_firmware *mcu_fw = gxp_mcu_firmware_of(gxp);
	struct gxp_client *client;
	struct gcip_pm *pm = gxp->power_mgr->pm;
	int ret;

	dev_err(gxp->dev, "MCU firmware is crashed, crash_type=%d", crash_type);

	if (crash_type != GCIP_FW_CRASH_UNRECOVERABLE_FAULT &&
	    crash_type != GCIP_FW_CRASH_HW_WDG_TIMEOUT)
		return;

	dev_err(gxp->dev, "Unrecoverable MCU firmware fault, handle it");

	/*
	 * Prevent @gxp->client_list is being changed while handling the crash.
	 * The user cannot open or close a fd until this function releases the lock.
	 */
	mutex_lock(&gxp->client_list_lock);

	/*
	 * Hold @client->semaphore first to prevent deadlock.
	 * By holding this lock, clients cannot proceed most IOCTLs.
	 */
	list_for_each_entry (client, &gxp->client_list, list_entry) {
		down_write(&client->semaphore);
	}

	/*
	 * Holding @client->semaphore will block the most client actions, but let's make sure
	 * it by holding the locks directly related to the actions we want to block accordingly.
	 * For example, in the case of the block wakelock, the debug dump can try to acquire it
	 * which cannot be blocked by holding @client->semaphore.
	 */

	/*
	 * We have to block allocating a new vd by the runtime. Otherwise, if it is holding the
	 * block wakelock, it will try to send a `allocate_vmbox` KCI to the crashed MCU firmware.
	 *
	 * The runtime cannot allocate a new virtual device or closing its client until this
	 * function releases the lock.
	 */
	down_write(&gxp->vd_semaphore);

	/*
	 * Holding the PM lock due to the reasons listed below.
	 *   1. As we are recovering the MCU firmware, we should block the PM requests (e.g.,
	 *      acquiring or releasing the block wakelock) until the rescuing is finished.
	 *   2. Restarting the MCU firmware might involve restore functions (e.g.,
	 *      gcip_thermal_restore_on_powering) which require the caller to hold the PM lock.
	 */
	gcip_pm_lock(pm);

	/*
	 * By the race, if all clients left earlier than this handler, all block wakleock should be
	 * already released and the BLK is turned off. We don't have to rescue the MCU firmware.
	 */
	if (!gcip_pm_is_powered(pm)) {
		dev_info(
			gxp->dev,
			"The block wakelock is already released, skip restarting MCU firmware");
		goto out_unlock_pm;
	}

	/*
	 * Discard all pending/unconsumed UCI responses and change the state of all virtual devices
	 * to GXP_VD_UNAVAILABLE. From now on, all clients cannot request new UCI commands.
	 */
	list_for_each_entry (client, &gxp->client_list, list_entry) {
		if (client->has_block_wakelock && client->vd) {
			gxp_vd_invalidate(gxp, client->vd);
			client->vd->mcu_crashed = true;
		}
	}

	/* Turn off and on the MCU PSM and restart the MCU firmware. */
	mutex_lock(&mcu_fw->lock);

	gxp_lpm_down(gxp, GXP_MCU_CORE_ID);

	if (!gxp_lpm_wait_state_eq(gxp, CORE_TO_PSM(GXP_MCU_CORE_ID),
				   LPM_PG_STATE)) {
		dev_warn(
			gxp->dev,
			"MCU PSM transition to PS3 fails, current state: %u. Falling back to power cycle AUR block.\n",
			gxp_lpm_get_state(gxp, CORE_TO_PSM(GXP_MCU_CORE_ID)));
		ret = gxp_pm_blk_reboot(gxp, 5000);
		if (ret)
			goto out;
	}

	ret = gxp_mcu_firmware_run_locked(mcu_fw);
	if (ret)
		dev_err(gxp->dev, "Failed to run MCU firmware (ret=%d)\n", ret);

out:
	mutex_unlock(&mcu_fw->lock);
out_unlock_pm:
	gcip_pm_unlock(pm);
	up_write(&gxp->vd_semaphore);
	list_for_each_entry (client, &gxp->client_list, list_entry) {
		up_write(&client->semaphore);
	}
	mutex_unlock(&gxp->client_list_lock);
}
