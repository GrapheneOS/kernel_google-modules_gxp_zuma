// SPDX-License-Identifier: GPL-2.0
/*
 * Structures and helpers for managing GXP MicroController Unit.
 *
 * Copyright (C) 2022 Google LLC
 */

#include <linux/iommu.h>
#include <linux/sizes.h>

#include <gcip/gcip-mem-pool.h>

#include "gxp-config.h"
#include "gxp-internal.h"
#include "gxp-mailbox.h"
#include "gxp-mcu-firmware.h"
#include "gxp-mcu.h"
#include "gxp-uci.h"

/* Allocates the MCU <-> cores shared buffer region. */
static int gxp_alloc_shared_buffer(struct gxp_dev *gxp, struct gxp_mcu *mcu)
{
	const size_t size = GXP_SHARED_BUFFER_SIZE * GXP_NUM_CORES;
	phys_addr_t paddr;
	struct gxp_mapped_resource *res = &mcu->gxp->shared_buf;

	paddr = gcip_mem_pool_alloc(&mcu->remap_data_pool, size);
	if (!paddr)
		return -ENOMEM;
	res->paddr = paddr;
	res->size = size;
	res->daddr = GXP_IOVA_SHARED_BUFFER;
	return 0;
}

static void gxp_free_shared_buffer(struct gxp_mcu *mcu)
{
	struct gxp_mapped_resource *res = &mcu->gxp->shared_buf;

	gcip_mem_pool_free(&mcu->remap_data_pool, res->paddr, res->size);
}

/*
 * Initializes memory pools, must be called after @mcu->fw has been initialized
 * to have a valid image_buf.
 */
static int gxp_mcu_mem_pools_init(struct gxp_dev *gxp, struct gxp_mcu *mcu)
{
	phys_addr_t iremap_paddr = mcu->fw.image_buf.paddr;
	int ret;

	ret = gcip_mem_pool_init(&mcu->remap_data_pool, gxp->dev,
				 iremap_paddr + GXP_IREMAP_DATA_OFFSET,
				 GXP_IREMAP_DATA_SIZE, SZ_4K);
	if (ret)
		return ret;
	ret = gcip_mem_pool_init(&mcu->remap_secure_pool, gxp->dev,
				 iremap_paddr + GXP_IREMAP_SECURE_OFFSET,
				 GXP_IREMAP_SECURE_SIZE, SZ_4K);
	if (ret) {
		gcip_mem_pool_exit(&mcu->remap_data_pool);
		return ret;
	}
	return 0;
}

static void gxp_mcu_unmap_resources(struct gxp_mcu *mcu)
{
	struct gxp_dev *gxp = mcu->gxp;
	struct iommu_domain *domain = iommu_get_domain_for_dev(gxp->dev);
	int i;

	for (i = GXP_NUM_CORES; i < GXP_NUM_MAILBOXES; i++)
		iommu_unmap(domain, gxp->mbx[i].daddr, gxp->mbx[i].size);
}

static int gxp_mcu_map_resources(struct gxp_dev *gxp, struct gxp_mcu *mcu)
{
	struct iommu_domain *domain = iommu_get_domain_for_dev(gxp->dev);
	int i, ret;

	for (i = GXP_NUM_CORES; i < GXP_NUM_MAILBOXES; i++) {
		gxp->mbx[i].daddr = GXP_MCU_NS_MAILBOX(i - GXP_NUM_CORES);
		ret = iommu_map(domain, gxp->mbx[i].daddr,
				gxp->mbx[i].paddr +
					MAILBOX_DEVICE_INTERFACE_OFFSET,
				gxp->mbx[i].size, IOMMU_READ | IOMMU_WRITE);
		if (ret)
			goto err;
	}

	return ret;

err:
	/*
	 * Attempt to unmap all resources.
	 * Any resource that hadn't been mapped yet will cause `iommu_unmap()`
	 * to return immediately, so its safe to try to unmap everything.
	 */
	gxp_mcu_unmap_resources(mcu);
	return ret;
}

static void gxp_mcu_mem_pools_exit(struct gxp_mcu *mcu)
{
	gcip_mem_pool_exit(&mcu->remap_secure_pool);
	gcip_mem_pool_exit(&mcu->remap_data_pool);
}

int gxp_mcu_mem_alloc_data(struct gxp_mcu *mcu, struct gxp_mapped_resource *mem, size_t size)
{
	size_t offset;
	phys_addr_t paddr;

	paddr = gcip_mem_pool_alloc(&mcu->remap_data_pool, size);
	if (!paddr)
		return -ENOMEM;
	offset = gcip_mem_pool_offset(&mcu->remap_data_pool, paddr);
	mem->size = size;
	mem->paddr = paddr;
	mem->vaddr = offset + (mcu->fw.image_buf.vaddr + GXP_IREMAP_DATA_OFFSET);
	mem->daddr = offset + (mcu->fw.image_buf.daddr + GXP_IREMAP_DATA_OFFSET);
	return 0;
}

void gxp_mcu_mem_free_data(struct gxp_mcu *mcu, struct gxp_mapped_resource *mem)
{
	gcip_mem_pool_free(&mcu->remap_data_pool, mem->paddr, mem->size);
	mem->size = 0;
	mem->paddr = 0;
	mem->vaddr = NULL;
	mem->daddr = 0;
}

int gxp_mcu_init(struct gxp_dev *gxp, struct gxp_mcu *mcu)
{
	int ret;

	mcu->gxp = gxp;
	ret = gxp_mcu_firmware_init(gxp, &mcu->fw);
	if (ret)
		return ret;
	ret = gxp_mcu_mem_pools_init(gxp, mcu);
	if (ret)
		goto err_fw_exit;
	ret = gxp_alloc_shared_buffer(gxp, mcu);
	if (ret)
		goto err_pools_exit;
	ret = gxp_mcu_map_resources(gxp, mcu);
	if (ret)
		goto err_free_shared_buffer;
	ret = gxp_uci_init(mcu);
	if (ret)
		goto err_mcu_unmap_resources;
	ret = gxp_kci_init(mcu);
	if (ret)
		goto err_uci_exit;
	return 0;

err_uci_exit:
	gxp_uci_exit(&mcu->uci);
err_mcu_unmap_resources:
	gxp_mcu_unmap_resources(mcu);
err_free_shared_buffer:
	gxp_free_shared_buffer(mcu);
err_pools_exit:
	gxp_mcu_mem_pools_exit(mcu);
err_fw_exit:
	gxp_mcu_firmware_exit(&mcu->fw);
	return ret;
}

void gxp_mcu_exit(struct gxp_mcu *mcu)
{
	gxp_kci_exit(&mcu->kci);
	gxp_uci_exit(&mcu->uci);
	gxp_mcu_unmap_resources(mcu);
	gxp_free_shared_buffer(mcu);
	gxp_mcu_mem_pools_exit(mcu);
	gxp_mcu_firmware_exit(&mcu->fw);
}