// SPDX-License-Identifier: GPL-2.0
/*
 * GXP support for DMA fence.
 *
 * Copyright (C) 2023 Google LLC
 */

#include <linux/slab.h>

#include <gcip/gcip-dma-fence.h>

#include "gxp-dma-fence.h"
#include "gxp-internal.h"
#include "gxp-vd.h"
#include "gxp.h"

static const char *gxp_get_driver_name(struct dma_fence *fence)
{
	return GXP_NAME;
}

static void gxp_dma_fence_release(struct dma_fence *fence)
{
	struct gxp_dma_fence *gxp_fence = to_gxp_fence(fence);

	gcip_dma_fence_exit(&gxp_fence->gfence);
	kfree(gxp_fence);
}

static const struct dma_fence_ops gxp_dma_fence_ops = {
	.get_driver_name = gxp_get_driver_name,
	.get_timeline_name = gcip_dma_fence_get_timeline_name,
	.wait = dma_fence_default_wait,
	.enable_signaling = gcip_dma_fence_always_true,
	.release = gxp_dma_fence_release,
};

int gxp_dma_fence_create(struct gxp_dev *gxp, struct gxp_virtual_device *vd,
			 struct gxp_create_sync_fence_data *datap)
{
	struct gcip_dma_fence_data data = {
		.timeline_name = datap->timeline_name,
		.ops = &gxp_dma_fence_ops,
		.seqno = datap->seqno,
	};
	struct gxp_dma_fence *gxp_fence =
		kzalloc(sizeof(*gxp_fence), GFP_KERNEL);
	int ret;

	if (!gxp_fence)
		return -ENOMEM;

	/* TODO(b/264855736): add VD association support */

	ret = gcip_dma_fence_init(gxp->gfence_mgr, &gxp_fence->gfence, &data);
	if (!ret)
		datap->fence = data.fence;
	/*
	 * We don't need to kfree(gxp_fence) on error because that's called in
	 * gxp_dma_fence_release.
	 */

	return ret;
}
