/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Abstracted interface for fences.
 *
 * Copyright (C) 2023 Google LLC
 */

#ifndef __GXP_FENCE_H__
#define __GXP_FENCE_H__

#include <linux/kref.h>

#include <gcip/iif/iif-fence.h>

#include "gxp-internal.h"
#include "gxp.h"

struct gxp_fence;
struct gxp_fence_ops;
struct gxp_fence_all_signaler_submitted_cb;

/* The callback which will be called when all signalers have been submitted to @fence. */
typedef void (*gxp_fence_all_signaler_submitted_cb_t)(
	struct gxp_fence *fence, struct gxp_fence_all_signaler_submitted_cb *cb);

enum gxp_fence_type {
	GXP_INTER_IP_FENCE,
	GXP_IN_KERNEL_FENCE,
};

/* Abstracted fence structure. */
struct gxp_fence {
	union {
		struct iif_fence *iif;
		struct dma_fence *ikf;
	} fence;
	/* The type of fence. */
	enum gxp_fence_type type;
	/* Reference count. */
	struct kref kref;
};

/* Abstracted all signaler submitted callback structure. */
struct gxp_fence_all_signaler_submitted_cb {
	/* IIF callback instance. */
	struct iif_fence_all_signaler_submitted_cb iif_cb;
	/* The actual callback function. */
	gxp_fence_all_signaler_submitted_cb_t func;
	/* Fence object. */
	struct gxp_fence *fence;
};

/*
 * Creates an IIF fence and bind a file descriptor to it.
 *
 * Returns the fd of the fence on success. Otherwise, returns a negative errno.
 */
int gxp_fence_create_iif(struct gxp_dev *gxp, enum gxp_iif_ip_type signaler_ip,
			 unsigned int total_signalers);

/*
 * Gets a fence from @fd and increments its reference count.
 *
 * Returns the fence pointer on success. Otherwise, returns an error pointer.
 */
struct gxp_fence *gxp_fence_fdget(int fd);

/* Increments the reference count of @fence. */
struct gxp_fence *gxp_fence_get(struct gxp_fence *fence);

/* Puts the fence and decrements its reference count. */
void gxp_fence_put(struct gxp_fence *fence);

/*
 * Submits a signaler.
 *
 * This function is only meaningful when the fence type is GXP_INTER_IP_FENCE.
 *
 * Returns 0 if the submission succeeds. Otherwise, returns a negative errno.
 */
int gxp_fence_submit_signaler(struct gxp_fence *fence);

/*
 * Submits a waiter.
 * Note that the waiter submission will not be done when not all signalers have been submitted.
 *
 * This function is only meaningful when the fence type is GXP_INTER_IP_FENCE.
 *
 * Returns the number of remaining signalers to be submitted. (i.e., the submission actually
 * has been succeeded when the function returns 0.) Otherwise, returns a negative errno if it fails
 * with other reasons.
 */
int gxp_fence_submit_waiter(struct gxp_fence *fence);

/*
 * Signals @fence. If all signalers have signaled the fence, it will notify polling FDs.
 *
 * If @fence is going to signaled with an error, one can pass @errno to let @fence notice it.
 */
void gxp_fence_signal(struct gxp_fence *fence, int errno);

/*
 * Notifies @fence that a command which waited the fence has finished their work.
 *
 * This function is only meaningful when the fence type is GXP_INTER_IP_FENCE.
 */
void gxp_fence_waited(struct gxp_fence *fence);

/*
 * Registers a callback which will be called when all signalers are submitted for @fence and
 * returns the number of remaining signalers to be submitted to @cb->remaining_signalers. Once the
 * callback is called, it will be automatically unregistered from @fence.
 *
 * This function is only meaningful when the fence type is GXP_INTER_IP_FENCE.
 *
 * Returns 0 if succeeded. If all signalers are already submitted, returns -EPERM.
 */
int gxp_fence_add_all_signaler_submitted_cb(struct gxp_fence *fence,
					    struct gxp_fence_all_signaler_submitted_cb *cb,
					    gxp_fence_all_signaler_submitted_cb_t func);

/*
 * Unregisters the callback which is registered by the callback above. Calling this function with
 * @cb which has never been added will cause unexpected action.
 *
 * This function is only meaningful when the fence type is GXP_INTER_IP_FENCE.
 *
 * Returns true if the callback is removed before its being called.
 */
bool gxp_fence_remove_all_signaler_submitted_cb(struct gxp_fence *fence,
						struct gxp_fence_all_signaler_submitted_cb *cb);

/* Returns the ID of @fence if @fence is IIF. Otherwise, returns -EINVAL. */
int gxp_fence_get_iif_id(struct gxp_fence *fence);

/*
 * Waits on @fences to complete the signaler submission. If at least one of @fences have remaining
 * signalers to be submitted, it will register @eventfd and will trigger it once all fences have
 * finishes the submission. Also, the number of remaining signalers of each fence will be returned
 * to @remaining_signalers in the same order with @fences.
 *
 * If @eventfd is `GXP_FENCE_REMAINING_SIGNALERS_NO_REGISTER_EVENTFD`, this function won't wait on
 * @fences to finish signaler submission and will simply return the number of remaining signalers of
 * each fence.
 *
 * This function is only meaningful when fences are IIF.
 *
 * Returns 0 on success. Otherwise, returns a negative errno.
 */
int gxp_fence_wait_signaler_submission(struct gxp_fence **fences, int num_fences,
				       unsigned int eventfd, int *remaining_signalers);
/*
 * Returns the signal completion status of @fence.
 *
 * Returns 0 if the fence has not yet been signaled, 1 if the fence has been signaled without an
 * error condition, or a negative error code if the fence has been completed in err.
 */
int gxp_fence_get_status(struct gxp_fence *fence);

#endif /* __GXP_FENCE_H__ */
