// SPDX-License-Identifier: GPL-2.0
/*
 * GXP IOMMU domain allocator.
 *
 * Copyright (C) 2022 Google LLC
 */

#include <linux/idr.h>
#include <linux/iommu.h>
#include <linux/slab.h>

#include "gxp-dma.h"
#include "gxp-domain-pool.h"
#include "gxp-internal.h"

static struct gxp_iommu_domain *gxp_domain_alloc(struct gxp_dev *gxp)
{
	struct iommu_domain *domain;
	struct gxp_iommu_domain *gdomain;

	gdomain = kmalloc(sizeof(*gdomain), GFP_KERNEL);
	if (!gdomain)
		return ERR_PTR(-ENOMEM);

	domain = iommu_domain_alloc(gxp->dev->bus);
	if (!domain) {
		kfree(gdomain);
		return ERR_PTR(-ENOMEM);
	}
	gdomain->domain = domain;

	return gdomain;
}

static void gxp_domain_free(struct gxp_iommu_domain *gdomain)
{
	iommu_domain_free(gdomain->domain);
	kfree(gdomain);
}

int gxp_domain_pool_init(struct gxp_dev *gxp, struct gxp_domain_pool *pool,
			 unsigned int size)
{
	unsigned int i;
	struct gxp_iommu_domain *gdomain;
	int __maybe_unused ret;

	pool->size = size;
	pool->gxp = gxp;

	if (!size)
		return 0;

	dev_dbg(pool->gxp->dev, "Initializing domain pool with %u domains\n", size);

	ida_init(&pool->idp);
	pool->array = vzalloc(sizeof(*pool->array) * size);
	if (!pool->array) {
		dev_err(gxp->dev, "Failed to allocate memory for domain pool array\n");
		return -ENOMEM;
	}
	for (i = 0; i < size; i++) {
		gdomain = gxp_domain_alloc(pool->gxp);
		if (IS_ERR(gdomain)) {
			dev_err(pool->gxp->dev,
				"Failed to allocate gxp iommu domain %d of %u\n",
				i + 1, size);
			gxp_domain_pool_destroy(pool);
			return -ENOMEM;
		}
#if IS_ENABLED(CONFIG_GXP_GEM5)
		/*
		 * Gem5 uses arm-smmu-v3 which requires domain finalization to do iommu map. Calling
		 * iommu_aux_attach_device to finalize the allocated domain and detach the device
		 * right after that.
		 */
		ret = iommu_aux_attach_device(gdomain->domain, pool->gxp->dev);
		if (ret) {
			dev_err(gxp->dev,
				"Failed to attach device to iommu domain %d of %u, ret=%d\n",
				i + 1, size, ret);
			gxp_domain_free(gdomain);
			gxp_domain_pool_destroy(pool);
			return ret;
		}

		iommu_aux_detach_device(gdomain->domain, pool->gxp->dev);
#endif /* CONFIG_GXP_GEM5 */

		pool->array[i] = gdomain;
	}
	return 0;
}

struct gxp_iommu_domain *gxp_domain_pool_alloc(struct gxp_domain_pool *pool)
{
	int id;

	if (!pool->size)
		return gxp_domain_alloc(pool->gxp);

	id = ida_alloc_max(&pool->idp, pool->size - 1, GFP_KERNEL);

	if (id < 0) {
		dev_err(pool->gxp->dev,
			"No more domains available from pool of size %u\n",
			pool->size);
		return NULL;
	}

	dev_dbg(pool->gxp->dev, "Allocated domain from pool with id = %d\n", id);

	return pool->array[id];
}

void gxp_domain_pool_free(struct gxp_domain_pool *pool, struct gxp_iommu_domain *gdomain)
{
	int id;

	if (!pool->size) {
		gxp_domain_free(gdomain);
		return;
	}
	for (id = 0; id < pool->size; id++) {
		if (pool->array[id] == gdomain) {
			dev_dbg(pool->gxp->dev, "Released domain from pool with id = %d\n", id);
			ida_free(&pool->idp, id);
			return;
		}
	}
	dev_err(pool->gxp->dev, "%s: domain not found in pool", __func__);
}

void gxp_domain_pool_destroy(struct gxp_domain_pool *pool)
{
	int i;

	if (!pool->size)
		return;

	dev_dbg(pool->gxp->dev, "Destroying domain pool with %u domains\n", pool->size);

	for (i = 0; i < pool->size; i++) {
		if (pool->array[i])
			gxp_domain_free(pool->array[i]);
	}

	ida_destroy(&pool->idp);
	vfree(pool->array);
}
