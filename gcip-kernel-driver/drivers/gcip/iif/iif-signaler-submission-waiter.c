// SPDX-License-Identifier: GPL-2.0-only
/*
 * The interface for waiting on multiple inter-IP fences to complete the signaler submission.
 *
 * Copyright (C) 2023 Google LLC
 */

#include <linux/eventfd.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#include <gcip/iif/iif-fence.h>
#include <gcip/iif/iif-signaler-submission-watier.h>

static struct iif_signaler_submission_waiter *
iif_signaler_submission_waiter_alloc(unsigned int eventfd, int pending_fences)
{
	struct iif_signaler_submission_waiter *waiter;

	waiter = kzalloc(sizeof(*waiter), GFP_KERNEL);
	if (!waiter)
		return ERR_PTR(-ENOMEM);

	waiter->ctx = eventfd_ctx_fdget((int)eventfd);
	if (IS_ERR(waiter->ctx)) {
		kfree(waiter);
		return ERR_CAST(waiter->ctx);
	}

	waiter->pending_fences = pending_fences;

	INIT_LIST_HEAD(&waiter->cb_list);
	kref_init(&waiter->kref);
	spin_lock_init(&waiter->lock);

	return waiter;
}

static void iif_all_signaler_submission_waiter_free(struct kref *kref)
{
	struct iif_signaler_submission_waiter *waiter =
		container_of(kref, struct iif_signaler_submission_waiter, kref);

	eventfd_ctx_put(waiter->ctx);
	kfree(waiter);
}

struct iif_signaler_submission_waiter *
iif_all_signaler_submission_waiter_get(struct iif_signaler_submission_waiter *waiter)
{
	kref_get(&waiter->kref);
	return waiter;
}

void iif_all_signaler_submission_waiter_put(struct iif_signaler_submission_waiter *waiter)
{
	kref_put(&waiter->kref, iif_all_signaler_submission_waiter_free);
}

static void all_signaler_submitted(struct iif_fence *fence,
				   struct iif_fence_all_signaler_submitted_cb *fence_cb)
{
	struct iif_signaler_submission_waiter_cb *cb =
		container_of(fence_cb, struct iif_signaler_submission_waiter_cb, fence_cb);
	struct iif_signaler_submission_waiter *waiter = cb->waiter;
	unsigned long flags;

	spin_lock_irqsave(&waiter->lock, flags);

	/*
	 * The `iif_all_signaler_submission_waiter_cancel` function will delete @cb from
	 * @watier->cb_list, decrement the refcount of @waiter and release @cb instead.
	 */
	if (waiter->cancel) {
		spin_unlock_irqrestore(&waiter->lock, flags);
		return;
	}

	list_del(&cb->node);

	/*
	 * - The callback will be executed asynchronously even while `iif_wait_signaler_submission`
	 *   function is still registering callbacks for each fence. In this case, even though
	 *   @waiter->cb_list is empty, we must not trigger the eventfd since not all callbacks are
	 *   registered yet (waiter->pending_fences is non-zero).
	 *
	 * - If waiter->pending_fences is 0, it means that we have finished registering callbacks
	 *   for all fences and the waiter should wait on @waiter->cb_list to be empty.
	 *
	 * - If there is no more fence to register the callback and all fences have finished the
	 *   signaler submission, we can signal the eventfd.
	 */
	if (!waiter->pending_fences && list_empty(&waiter->cb_list))
		eventfd_signal(waiter->ctx, 1);

	spin_unlock_irqrestore(&waiter->lock, flags);

	iif_all_signaler_submission_waiter_put(waiter);
	kfree(cb);
}

static int iif_all_signaler_submission_waiter_wait(struct iif_signaler_submission_waiter *waiter,
						   struct iif_fence *fence,
						   int *remaining_signalers)
{
	struct iif_signaler_submission_waiter_cb *cb;
	int ret;

	cb = kzalloc(sizeof(*cb), GFP_KERNEL);
	if (!cb)
		return -ENOMEM;

	cb->waiter = iif_all_signaler_submission_waiter_get(waiter);
	/*
	 * Don't call `iif_fence_get` to prevent @fence from being not released forever if the
	 * runtime never submits signalers somehow.
	 */
	cb->fence = fence;

	spin_lock(&waiter->lock);
	list_add_tail(&cb->node, &waiter->cb_list);
	spin_unlock(&waiter->lock);

	ret = iif_fence_add_all_signaler_submitted_callback(fence, &cb->fence_cb,
							    all_signaler_submitted);

	spin_lock(&waiter->lock);

	if (ret && ret != -EPERM)
		goto out_list_del;

	/*
	 * @fence has been successfully registered the callback or already finished the
	 * signaler submission.
	 */
	waiter->pending_fences--;

	/* (ret = -EPERM) Already all signalers are submitted and the callback is not registered. */
	if (ret) {
		*remaining_signalers = 0;
		ret = 0;
		goto out_list_del;
	}

	/* (ret = 0) The callback is registered and there are remaining signalers. */
	*remaining_signalers = cb->fence_cb.remaining_signalers;

	spin_unlock(&waiter->lock);

	return 0;

out_list_del:
	list_del(&cb->node);
	spin_unlock(&waiter->lock);

	iif_all_signaler_submission_waiter_put(waiter);
	kfree(cb);

	return ret;
}

static void iif_all_signaler_submission_waiter_cancel(struct iif_signaler_submission_waiter *waiter)
{
	struct iif_signaler_submission_waiter_cb *cur, *tmp;

	spin_lock(&waiter->lock);
	waiter->cancel = true;
	spin_unlock(&waiter->lock);

	/* From now on, @waiter->cb_list won't be changed. */

	list_for_each_entry_safe(cur, tmp, &waiter->cb_list, node) {
		iif_fence_remove_all_signaler_submitted_callback(cur->fence, &cur->fence_cb);
		list_del(&cur->node);
		iif_all_signaler_submission_waiter_put(waiter);
		kfree(cur);
	}
}

int iif_wait_signaler_submission(struct iif_fence **fences, int num_fences, unsigned int eventfd,
				 int *remaining_signalers)
{
	struct iif_signaler_submission_waiter *waiter;
	int i, ret = 0;

	if (eventfd == IIF_NO_REGISTER_EVENTFD) {
		for (i = 0; i < num_fences; i++)
			remaining_signalers[i] = iif_fence_unsubmitted_signalers(fences[i]);
		return 0;
	}

	waiter = iif_signaler_submission_waiter_alloc(eventfd, num_fences);
	if (IS_ERR(waiter))
		return PTR_ERR(waiter);

	for (i = 0; i < num_fences; i++) {
		ret = iif_all_signaler_submission_waiter_wait(waiter, fences[i],
							      &remaining_signalers[i]);
		if (ret) {
			iif_all_signaler_submission_waiter_cancel(waiter);
			break;
		}
	}

	iif_all_signaler_submission_waiter_put(waiter);

	return ret;
}