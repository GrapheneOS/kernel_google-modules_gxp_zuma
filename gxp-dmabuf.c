// SPDX-License-Identifier: GPL-2.0
/*
 * Support for using dma-bufs.
 *
 * Copyright (C) 2022 Google LLC
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/version.h>

#include <gcip/gcip-config.h>
#include <gcip/gcip-iommu.h>

#include "gxp-dma.h"
#include "gxp-dmabuf.h"

#include <trace/events/gxp.h>

/* Mapping destructor for gxp_mapping_put() to call */
static void destroy_dmabuf_mapping(struct gxp_mapping *mapping)
{
	dma_addr_t device_address = mapping->gcip_mapping->device_address;
	size_t size = mapping->gcip_mapping->size;

	trace_gxp_mapping_destroy_start(device_address, size);

	gcip_iommu_mapping_unmap(mapping->gcip_mapping);
	kfree(mapping);

	trace_gxp_mapping_destroy_end(device_address, size);
}

struct gxp_mapping *gxp_dmabuf_map(struct gxp_dev *gxp, struct gcip_iommu_domain *domain, int fd,
				   u32 flags)
{
	struct gxp_mapping *mapping;
	struct gcip_iommu_mapping *gcip_mapping;
	u64 gcip_map_flags;

	trace_gxp_dmabuf_mapping_create_start(fd);

	/* Skip CPU cache syncs while mapping this dmabuf. */
	gcip_map_flags = gxp_dma_encode_gcip_map_flags(flags, 0) |
			 GCIP_MAP_FLAGS_DMA_ATTR_TO_FLAGS(DMA_ATTR_SKIP_CPU_SYNC);

	mapping = kzalloc(sizeof(*mapping), GFP_KERNEL);
	if (!mapping)
		return ERR_PTR(-ENOMEM);

	gcip_mapping = gcip_iommu_domain_map_dma_buf(domain, fd, gcip_map_flags);
	if (IS_ERR(gcip_mapping)) {
		dev_err(gxp->dev, "Failed to map dma-buf (ret=%ld)\n", PTR_ERR(gcip_mapping));
		kfree(mapping);
		return ERR_CAST(gcip_mapping);
	}

	/* dma-buf mappings are indicated by a host_address of 0 */
	mapping->host_address = 0;
	mapping->gcip_mapping = gcip_mapping;
	mapping->size = gcip_mapping->size;
	mapping->destructor = destroy_dmabuf_mapping;
	mapping->gxp = gxp;
	refcount_set(&mapping->refcount, 1);

	trace_gxp_dmabuf_mapping_create_end(gcip_mapping->device_address, gcip_mapping->size);

	return mapping;
}

MODULE_IMPORT_NS(DMA_BUF);
