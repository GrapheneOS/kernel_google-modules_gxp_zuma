// SPDX-License-Identifier: GPL-2.0-only
/*
 * Abstracted interface for fences.
 *
 * Copyright (C) 2023 Google LLC
 */

#include <linux/dma-fence.h>
#include <linux/slab.h>
#include <linux/sync_file.h>

#include <gcip/gcip-dma-fence.h>
#include <gcip/iif/iif-fence.h>
#include <gcip/iif/iif-signaler-submission-watier.h>
#include <gcip/iif/iif.h>

#include "gxp-fence.h"

static struct gxp_fence *gxp_fence_alloc(enum gxp_fence_type type)
{
	struct gxp_fence *fence = kzalloc(sizeof(*fence), GFP_KERNEL);

	if (!fence)
		return NULL;

	fence->type = type;
	kref_init(&fence->kref);

	return fence;
}

static void gxp_fence_free(struct kref *kref)
{
	struct gxp_fence *fence = container_of(kref, struct gxp_fence, kref);

	switch (fence->type) {
	case GXP_INTER_IP_FENCE:
		iif_fence_put(fence->fence.iif);
		break;
	case GXP_IN_KERNEL_FENCE:
		dma_fence_put(fence->fence.ikf);
		break;
	}

	kfree(fence);
}

static void gxp_fence_release_iif(struct iif_fence *iif_fence)
{
	kfree(iif_fence);
}

static const struct iif_fence_ops iif_fence_ops = {
	.on_release = gxp_fence_release_iif,
};

int gxp_fence_create_iif(struct gxp_dev *gxp, enum gxp_iif_ip_type signaler_ip,
			 unsigned int total_signalers)
{
	struct iif_fence *iif_fence;
	enum iif_ip_type iif_signaler_ip = (enum iif_ip_type)signaler_ip;
	int fd, ret;

	if (!gxp->iif_mgr)
		return -ENODEV;

	if (iif_signaler_ip >= IIF_IP_NUM)
		return -EINVAL;

	iif_fence = kzalloc(sizeof(*iif_fence), GFP_KERNEL);
	if (!iif_fence)
		return -ENOMEM;

	ret = iif_fence_init(gxp->iif_mgr, iif_fence, &iif_fence_ops, iif_signaler_ip,
			     total_signalers);
	if (ret) {
		kfree(iif_fence);
		return ret;
	}

	fd = iif_fence_install_fd(iif_fence);

	/*
	 * If `iif_fence_install_fd` succeeds, the IIF sync file holds a reference to the fence and
	 * it's fine to release one here.
	 * If it fails, `iif_fence_put` will release all reference counts and the release callback
	 * will be executed to free @fence.
	 */
	iif_fence_put(iif_fence);

	return fd;
}

static struct gxp_fence *gxp_fence_fdget_iif(int fd)
{
	struct gxp_fence *fence;
	struct iif_fence *iif_fence;

	iif_fence = iif_fence_fdget(fd);
	if (IS_ERR(iif_fence))
		return ERR_CAST(iif_fence);

	fence = gxp_fence_alloc(GXP_INTER_IP_FENCE);
	if (!fence) {
		iif_fence_put(iif_fence);
		return ERR_PTR(-ENOMEM);
	}

	fence->fence.iif = iif_fence;

	return fence;
}

static struct gxp_fence *gxp_fence_fdget_ikf(int fd)
{
	struct gxp_fence *fence;
	struct dma_fence *dma_fence;

	dma_fence = sync_file_get_fence(fd);
	if (!dma_fence)
		return ERR_PTR(-EBADF);

	fence = gxp_fence_alloc(GXP_IN_KERNEL_FENCE);
	if (!fence) {
		dma_fence_put(dma_fence);
		return ERR_PTR(-ENOMEM);
	}

	fence->fence.ikf = dma_fence;

	return fence;
}

struct gxp_fence *gxp_fence_fdget(int fd)
{
	struct gxp_fence *fence;

	fence = gxp_fence_fdget_iif(fd);
	if (!IS_ERR(fence))
		return fence;

	fence = gxp_fence_fdget_ikf(fd);
	if (!IS_ERR(fence))
		return fence;

	return ERR_PTR(-EINVAL);
}

struct gxp_fence *gxp_fence_get(struct gxp_fence *fence)
{
	if (fence)
		kref_get(&fence->kref);
	return fence;
}

void gxp_fence_put(struct gxp_fence *fence)
{
	if (fence)
		kref_put(&fence->kref, gxp_fence_free);
}

int gxp_fence_submit_signaler(struct gxp_fence *fence)
{
	if (fence->type == GXP_INTER_IP_FENCE)
		return iif_fence_submit_signaler(fence->fence.iif);
	return -EOPNOTSUPP;
}

int gxp_fence_submit_waiter(struct gxp_fence *fence)
{
	if (fence->type == GXP_INTER_IP_FENCE)
		return iif_fence_submit_waiter(fence->fence.iif, IIF_IP_DSP);
	return -EOPNOTSUPP;
}

void gxp_fence_signal(struct gxp_fence *fence, int errno)
{
	switch (fence->type) {
	case GXP_INTER_IP_FENCE:
		iif_fence_signal(fence->fence.iif);
		break;
	case GXP_IN_KERNEL_FENCE:
		gcip_signal_dma_fence_with_status(fence->fence.ikf, errno, false);
		break;
	}
}

void gxp_fence_waited(struct gxp_fence *fence)
{
	if (fence->type == GXP_INTER_IP_FENCE)
		iif_fence_waited(fence->fence.iif);
}

/*
 * A proxy callback which is compatible with iif-fence interface and will be called when
 * @iif_fence finishes the signaler submission. This callback simply redirects to @cb->func.
 */
static void gxp_fence_iif_all_signaler_submitted(struct iif_fence *iif_fence,
						 struct iif_fence_all_signaler_submitted_cb *iif_cb)
{
	struct gxp_fence_all_signaler_submitted_cb *cb =
		container_of(iif_cb, struct gxp_fence_all_signaler_submitted_cb, iif_cb);

	cb->func(cb->fence, cb);
}

int gxp_fence_add_all_signaler_submitted_cb(struct gxp_fence *fence,
					    struct gxp_fence_all_signaler_submitted_cb *cb,
					    gxp_fence_all_signaler_submitted_cb_t func)
{
	/*
	 * If @fence is not IIF, let it always treat the situation as all signalers are
	 * already submitted.
	 */
	if (fence->type != GXP_INTER_IP_FENCE)
		return -EPERM;

	cb->func = func;
	cb->fence = fence;
	INIT_LIST_HEAD(&cb->iif_cb.node);

	return iif_fence_add_all_signaler_submitted_callback(fence->fence.iif, &cb->iif_cb,
							     gxp_fence_iif_all_signaler_submitted);
}

bool gxp_fence_remove_all_signaler_submitted_cb(struct gxp_fence *fence,
						struct gxp_fence_all_signaler_submitted_cb *cb)
{
	if (fence->type != GXP_INTER_IP_FENCE)
		return true;
	return iif_fence_remove_all_signaler_submitted_callback(fence->fence.iif, &cb->iif_cb);
}

/* Returns the ID of @fence if @fence is IIF. */
int gxp_fence_get_iif_id(struct gxp_fence *fence)
{
	if (fence->type == GXP_INTER_IP_FENCE)
		return fence->fence.iif->id;
	return -EINVAL;
}

int gxp_fence_wait_signaler_submission(struct gxp_fence **fences, int num_fences,
				       unsigned int eventfd, int *remaining_signalers)
{
	struct iif_fence **iif_fences;
	int i, ret;

	iif_fences = kcalloc(num_fences, sizeof(*iif_fences), GFP_KERNEL);
	if (!iif_fences)
		return -ENOMEM;

	for (i = 0; i < num_fences; i++) {
		if (fences[i]->type != GXP_INTER_IP_FENCE) {
			ret = -EINVAL;
			goto out;
		}
		iif_fences[i] = fences[i]->fence.iif;
	}

	ret = iif_wait_signaler_submission(iif_fences, num_fences, eventfd, remaining_signalers);
out:
	kfree(iif_fences);
	return ret;
}

int gxp_fence_get_status(struct gxp_fence *fence)
{
	switch (fence->type) {
	case GXP_INTER_IP_FENCE:
		return iif_fence_get_signal_status(fence->fence.iif);
	case GXP_IN_KERNEL_FENCE:
		return dma_fence_get_status(fence->fence.ikf);
	}

	return -EOPNOTSUPP;
}
