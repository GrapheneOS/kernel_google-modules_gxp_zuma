// SPDX-License-Identifier: GPL-2.0-only
/*
 * Common file system operations for devices with MCU support.
 *
 * Copyright (C) 2022 Google LLC
 */

#include <linux/bits.h>
#include <linux/fs.h>
#include <linux/mm_types.h>
#include <linux/rwsem.h>
#include <linux/slab.h>

#include <gcip/gcip-telemetry.h>

#include "gxp-client.h"
#include "gxp-fence.h"
#include "gxp-internal.h"
#include "gxp-mcu-fs.h"
#include "gxp-mcu-telemetry.h"
#include "gxp-mcu.h"
#include "gxp-uci.h"
#include "gxp.h"

#define GXP_UCI_NULL_COMMAND_FLAG BIT(0)

static int gxp_ioctl_uci_command_compat(struct gxp_client *client,
					struct gxp_mailbox_uci_command_compat_ioctl __user *argp)
{
	struct gxp_mailbox_uci_command_compat_ioctl ibuf;
	struct gxp_dev *gxp = client->gxp;
	struct gxp_mcu *mcu = gxp_mcu_of(gxp);
	struct gxp_uci_command cmd = {};
	int ret;

	if (copy_from_user(&ibuf, argp, sizeof(ibuf)))
		return -EFAULT;

	down_read(&client->semaphore);

	if (!gxp_client_has_available_vd(client, "GXP_MAILBOX_UCI_COMMAND_COMPAT")) {
		ret = -ENODEV;
		goto out;
	}

	/* Caller must hold BLOCK wakelock */
	if (!client->has_block_wakelock) {
		dev_err(gxp->dev,
			"GXP_MAILBOX_UCI_COMMAND_COMPAT requires the client hold a BLOCK wakelock\n");
		ret = -ENODEV;
		goto out;
	}

	memcpy(cmd.opaque, ibuf.opaque, sizeof(cmd.opaque));

	cmd.client_id = client->vd->client_id;

	ret = gxp_uci_send_command(&mcu->uci, client->vd, &cmd, NULL, NULL, NULL,
				   &client->vd->mailbox_resp_queues[UCI_RESOURCE_ID].wait_queue,
				   &client->vd->mailbox_resp_queues[UCI_RESOURCE_ID].dest_queue,
				   &client->vd->mailbox_resp_queues[UCI_RESOURCE_ID].lock,
				   &client->vd->mailbox_resp_queues[UCI_RESOURCE_ID].waitq,
				   client->mb_eventfds[UCI_RESOURCE_ID], 0);

	up_read(&client->semaphore);

	if (ret) {
		dev_err(gxp->dev,
			"Failed to enqueue mailbox command (ret=%d)\n", ret);
		return ret;
	}
	ibuf.sequence_number = cmd.seq;

	if (copy_to_user(argp, &ibuf, sizeof(ibuf)))
		return -EFAULT;

	return 0;
out:
	up_read(&client->semaphore);
	return ret;
}

/*
 * Finds IIF fences from @fences and copies its ID to a new allocated array. The array will be
 * returned. The number of IIF fences will be returned to @iif_fences_size.
 *
 * This function will return the array of inter-IP fence IDs and the size of array will be returned
 * to @iif_fences_size. If there is no IIF in @uci_fences, it will return NULL. Otherwise, it will
 * return an errno pointer.
 */
static uint16_t *get_iif_fences_id(struct gxp_uci_fences *uci_fences, uint32_t *iif_fences_size)
{
	uint16_t *iif_fences;
	int i, j;

	if (!uci_fences)
		return NULL;

	*iif_fences_size = 0;

	for (i = 0; i < uci_fences->size; i++) {
		if (uci_fences->fences[i]->type == GXP_INTER_IP_FENCE)
			(*iif_fences_size)++;
	}

	if (!(*iif_fences_size))
		return NULL;

	iif_fences = kcalloc(*iif_fences_size, sizeof(*iif_fences), GFP_KERNEL);
	if (!iif_fences)
		return ERR_PTR(-ENOMEM);

	for (i = 0, j = 0; i < uci_fences->size; i++) {
		if (uci_fences->fences[i]->type == GXP_INTER_IP_FENCE)
			iif_fences[j++] = gxp_fence_get_iif_id(uci_fences->fences[i]);
	}

	return iif_fences;
}

/**
 * create_and_send_uci_cmd() - Create and put the UCI command into the queue.
 * @client: The client which request the UCI command.
 * @cmd_seq: The specified sequence number used for this uci command.
 * @flags: Same as gxp_mailbox_uci_command_ioctl.
 * @opaque: Same as gxp_mailbox_uci_command_ioctl.
 * @timeout_ms: Same as gxp_mailbox_uci_command_ioctl.
 * @in_fences: Same as gxp_mailbox_uci_command_ioctl.
 * @out_fences: Same as gxp_mailbox_uci_command_ioctl.
 *
 * Following tasks will be done in this function:
 * 1. Check the client and its virtual device to see if they are still available.
 * 2. Prepare UCI command object.
 * 3. Prepare UCI additional info.
 * 4. Put the UCI command into the queue.
 *
 * Return: 0 on success or errno on failure.
 */
static int create_and_send_uci_cmd(struct gxp_client *client, u64 cmd_seq, u32 flags, u8 *opaque,
				   u32 timeout_ms, struct gxp_uci_fences *in_fences,
				   struct gxp_uci_fences *out_fences)
{
	struct gxp_dev *gxp = client->gxp;
	struct gxp_mcu *mcu = gxp_mcu_of(gxp);
	struct gxp_uci_command cmd = {};
	struct gxp_uci_additional_info additional_info = {};
	uint16_t *in_iif_fences, *out_iif_fences;
	uint32_t in_iif_fences_size, out_iif_fences_size;
	int ret;

	down_read(&client->semaphore);

	if (!gxp_client_has_available_vd(client, "GXP_MAILBOX_UCI_COMMAND")) {
		ret = -ENODEV;
		goto out;
	}

	/* Caller must hold BLOCK wakelock */
	if (!client->has_block_wakelock) {
		dev_err(gxp->dev,
			"GXP_MAILBOX_UCI_COMMAND requires the client hold a BLOCK wakelock\n");
		ret = -ENODEV;
		goto out;
	}

	in_iif_fences = get_iif_fences_id(in_fences, &in_iif_fences_size);
	if (IS_ERR(in_iif_fences)) {
		ret = PTR_ERR(in_iif_fences);
		goto out;
	}

	out_iif_fences = get_iif_fences_id(out_fences, &out_iif_fences_size);
	if (IS_ERR(out_iif_fences)) {
		ret = PTR_ERR(out_iif_fences);
		goto err_put_in_iif_fences;
	}

	memcpy(cmd.opaque, opaque, sizeof(cmd.opaque));

	cmd.client_id = client->vd->client_id;
	cmd.seq = cmd_seq;

	if (flags & GXP_UCI_NULL_COMMAND_FLAG)
		cmd.type = NULL_COMMAND;

	gxp_uci_fill_additional_info(&additional_info, in_iif_fences, in_iif_fences_size,
				     out_iif_fences, out_iif_fences_size, timeout_ms, NULL, 0);

	ret = gxp_uci_send_command(&mcu->uci, client->vd, &cmd, &additional_info, in_fences,
				   out_fences,
				   &client->vd->mailbox_resp_queues[UCI_RESOURCE_ID].wait_queue,
				   &client->vd->mailbox_resp_queues[UCI_RESOURCE_ID].dest_queue,
				   &client->vd->mailbox_resp_queues[UCI_RESOURCE_ID].lock,
				   &client->vd->mailbox_resp_queues[UCI_RESOURCE_ID].waitq,
				   client->mb_eventfds[UCI_RESOURCE_ID],
				   GCIP_MAILBOX_CMD_FLAGS_SKIP_ASSIGN_SEQ);

	kfree(out_iif_fences);
	kfree(in_iif_fences);

	if (ret)
		dev_err(gxp->dev, "Failed to enqueue mailbox command (ret=%d)\n", ret);

	goto out;

err_put_in_iif_fences:
	kfree(in_iif_fences);
out:
	up_read(&client->semaphore);
	return ret;
}

/**
 * uci_cmd_work_func() - A work_func_t wrapper function to call create_and_send_uci_cmd.
 * @work: The work object which owns this function.
 */
static void uci_cmd_work_func(struct work_struct *work)
{
	struct gxp_uci_cmd_work *uci_work = container_of(work, struct gxp_uci_cmd_work, work);
	struct gxp_client *client = uci_work->client;
	u64 cmd_seq = uci_work->cmd_seq;
	u32 flags = uci_work->flags;
	u8 *opaque = uci_work->opaque;
	u32 timeout_ms = uci_work->timeout_ms;
	struct gxp_uci_fences *in_fences = uci_work->in_fences;
	struct gxp_uci_fences *out_fences = uci_work->out_fences;
	int ret;

	ret = create_and_send_uci_cmd(client, cmd_seq, flags, opaque, timeout_ms, in_fences,
				      out_fences);
	if (ret)
		dev_err(client->gxp->dev, "Failed to process uci command in work func (ret=%d)",
			ret);

	gxp_uci_cmd_work_destroy(uci_work);
}

static int gxp_ioctl_uci_command(struct gxp_client *client,
				 struct gxp_mailbox_uci_command_ioctl __user *argp)
{
	struct gxp_mcu *mcu = gxp_mcu_of(client->gxp);
	struct gxp_mailbox_uci_command_ioctl ibuf;
	struct gxp_uci_fences *in_fences, *out_fences;
	bool in_kernel_fence_signaled = true;
	u64 cmd_seq;
	int ret;

	if (copy_from_user(&ibuf, argp, sizeof(ibuf)))
		return -EFAULT;

	cmd_seq = gcip_mailbox_inc_seq_num(mcu->uci.mbx->mbx_impl.gcip_mbx, 1);

	in_fences = gxp_uci_fences_create(client->gxp, ibuf.in_fences, true);
	if (IS_ERR(in_fences))
		return PTR_ERR(in_fences);

	out_fences = gxp_uci_fences_create(client->gxp, ibuf.out_fences, false);
	if (IS_ERR(out_fences)) {
		gxp_uci_fences_put(in_fences);
		return PTR_ERR(out_fences);
	}

	if (in_fences->size && in_fences->fences[0]->type == GXP_IN_KERNEL_FENCE) {
		struct dma_fence *polled_dma_fence = NULL;

		/* TODO(b/264015258): Utilize dma_fence_array and set polled_dma_fence. */

		ret = gxp_uci_cmd_work_create_and_schedule(polled_dma_fence, client, &ibuf, cmd_seq,
							   in_fences, out_fences,
							   uci_cmd_work_func);
		/*
		 * If @ret is -ENOENT, it means that @polled_dma_fence is already signaled and the
		 * poll callback is not registered to the fence. We don't have to treat it as an
		 * error and can execute the `create_and_send_uci_cmd` function directly.
		 */
		if (ret && ret != -ENOENT) {
			dev_err(client->gxp->dev,
				"Failed to create a work waiting on in-kernel fence (ret=%d)", ret);
			goto out;
		}
		if (!ret)
			in_kernel_fence_signaled = false;
		ret = 0;
	}

	if (!in_fences->size || in_fences->fences[0]->type != GXP_IN_KERNEL_FENCE ||
	    in_kernel_fence_signaled) {
		ret = create_and_send_uci_cmd(client, cmd_seq, ibuf.flags, ibuf.opaque,
					      ibuf.timeout_ms, in_fences, out_fences);
		if (ret)
			goto out;
	}

	ibuf.sequence_number = cmd_seq;

	if (copy_to_user(argp, &ibuf, sizeof(ibuf)))
		ret = -EFAULT;

out:
	gxp_uci_fences_put(out_fences);
	gxp_uci_fences_put(in_fences);
	return ret;
}

static int
gxp_ioctl_uci_response(struct gxp_client *client,
		       struct gxp_mailbox_uci_response_ioctl __user *argp)
{
	struct gxp_mailbox_uci_response_ioctl ibuf;
	int ret = 0;

	if (copy_from_user(&ibuf, argp, sizeof(ibuf)))
		return -EFAULT;

	down_read(&client->semaphore);

	if (!client->vd) {
		dev_err(client->gxp->dev,
			"GXP_MAILBOX_UCI_RESPONSE requires the client allocate a VIRTUAL_DEVICE\n");
		ret = -ENODEV;
		goto out;
	}

	/* Caller must hold BLOCK wakelock */
	if (!client->has_block_wakelock) {
		dev_err(client->gxp->dev,
			"GXP_MAILBOX_UCI_RESPONSE requires the client hold a BLOCK wakelock\n");
		ret = -ENODEV;
		goto out;
	}

	ret = gxp_uci_wait_async_response(
		&client->vd->mailbox_resp_queues[UCI_RESOURCE_ID],
		&ibuf.sequence_number, &ibuf.error_code, ibuf.opaque);
	if (ret)
		goto out;

	if (copy_to_user(argp, &ibuf, sizeof(ibuf)))
		ret = -EFAULT;

out:
	up_read(&client->semaphore);

	return ret;
}

static int gxp_ioctl_set_device_properties(
	struct gxp_dev *gxp,
	struct gxp_set_device_properties_ioctl __user *argp)
{
	struct gxp_dev_prop *device_prop = &gxp->device_prop;
	struct gxp_set_device_properties_ioctl ibuf;

	if (copy_from_user(&ibuf, argp, sizeof(ibuf)))
		return -EFAULT;

	mutex_lock(&device_prop->lock);

	memcpy(&device_prop->opaque, &ibuf.opaque, sizeof(device_prop->opaque));
	device_prop->initialized = true;

	mutex_unlock(&device_prop->lock);

	return 0;
}

static int gxp_ioctl_create_iif_fence(struct gxp_client *client,
				      struct gxp_create_iif_fence_ioctl __user *argp)
{
	struct gxp_create_iif_fence_ioctl ibuf;
	int fd;

	if (copy_from_user(&ibuf, argp, sizeof(ibuf)))
		return -EFAULT;

	fd = gxp_fence_create_iif(client->gxp, ibuf.signaler_ip, ibuf.total_signalers);
	if (fd < 0)
		return fd;

	ibuf.fence = fd;

	if (copy_to_user(argp, &ibuf, sizeof(ibuf)))
		return -EFAULT;

	return 0;
}

static int
gxp_ioctl_fence_remaining_signalers(struct gxp_client *client,
				    struct gxp_fence_remaining_signalers_ioctl __user *argp)
{
	struct gxp_fence_remaining_signalers_ioctl ibuf;
	struct gxp_fence **fences;
	int i, ret;

	if (copy_from_user(&ibuf, argp, sizeof(ibuf)))
		return -EFAULT;

	down_write(&client->semaphore);

	if (!gxp_client_has_available_vd(client, "GXP_FENCE_REMAINING_SIGNALERS")) {
		ret = -ENODEV;
		goto err_up_write;
	}

	fences = kcalloc(GXP_MAX_FENCES_PER_UCI_COMMAND, sizeof(*fences), GFP_KERNEL);
	if (!fences) {
		ret = -ENOMEM;
		goto err_up_write;
	}

	for (i = 0; i < GXP_MAX_FENCES_PER_UCI_COMMAND; i++) {
		if (ibuf.fences[i] == GXP_FENCE_ARRAY_TERMINATION)
			break;

		fences[i] = gxp_fence_fdget(ibuf.fences[i]);
		if (IS_ERR(fences[i])) {
			ret = PTR_ERR(fences[i]);
			goto err_free_fences;
		}
	}

	ret = gxp_fence_wait_signaler_submission(fences, i, ibuf.eventfd, ibuf.remaining_signalers);
	if (ret)
		goto err_free_fences;

	kfree(fences);
	up_write(&client->semaphore);

	if (copy_to_user(argp, &ibuf, sizeof(ibuf)))
		return -EFAULT;

	return 0;

err_free_fences:
	kfree(fences);
err_up_write:
	up_write(&client->semaphore);
	return ret;
}

static inline enum gcip_telemetry_type to_gcip_telemetry_type(u8 type)
{
	if (type == GXP_TELEMETRY_TYPE_LOGGING)
		return GCIP_TELEMETRY_LOG;
	else
		return GCIP_TELEMETRY_TRACE;
}

static int
gxp_ioctl_register_mcu_telemetry_eventfd(struct gxp_client *client,
					 struct gxp_register_telemetry_eventfd_ioctl __user *argp)
{
	struct gxp_mcu *mcu = gxp_mcu_of(client->gxp);
	struct gxp_register_telemetry_eventfd_ioctl ibuf;

	if (copy_from_user(&ibuf, argp, sizeof(ibuf)))
		return -EFAULT;

	return gxp_mcu_telemetry_register_eventfd(
		mcu, to_gcip_telemetry_type(ibuf.type), ibuf.eventfd);
}

static int
gxp_ioctl_unregister_mcu_telemetry_eventfd(struct gxp_client *client,
					   struct gxp_register_telemetry_eventfd_ioctl __user *argp)
{
	struct gxp_mcu *mcu = gxp_mcu_of(client->gxp);
	struct gxp_register_telemetry_eventfd_ioctl ibuf;

	if (copy_from_user(&ibuf, argp, sizeof(ibuf)))
		return -EFAULT;

	return gxp_mcu_telemetry_unregister_eventfd(
		mcu, to_gcip_telemetry_type(ibuf.type));
}

long gxp_mcu_ioctl(struct file *file, uint cmd, ulong arg)
{
	struct gxp_client *client = file->private_data;
	void __user *argp = (void __user *)arg;
	long ret;

	if (gxp_is_direct_mode(client->gxp))
		return -ENOTTY;
	switch (cmd) {
	case GXP_MAILBOX_COMMAND:
		ret = -EOPNOTSUPP;
		break;
	case GXP_MAILBOX_RESPONSE:
		ret = -EOPNOTSUPP;
		break;
	case GXP_REGISTER_MCU_TELEMETRY_EVENTFD:
		ret = gxp_ioctl_register_mcu_telemetry_eventfd(client, argp);
		break;
	case GXP_UNREGISTER_MCU_TELEMETRY_EVENTFD:
		ret = gxp_ioctl_unregister_mcu_telemetry_eventfd(client, argp);
		break;
	case GXP_MAILBOX_UCI_COMMAND_COMPAT:
		ret = gxp_ioctl_uci_command_compat(client, argp);
		break;
	case GXP_MAILBOX_UCI_COMMAND:
		ret = gxp_ioctl_uci_command(client, argp);
		break;
	case GXP_MAILBOX_UCI_RESPONSE:
		ret = gxp_ioctl_uci_response(client, argp);
		break;
	case GXP_SET_DEVICE_PROPERTIES:
		ret = gxp_ioctl_set_device_properties(client->gxp, argp);
		break;
	case GXP_CREATE_IIF_FENCE:
		ret = gxp_ioctl_create_iif_fence(client, argp);
		break;
	case GXP_FENCE_REMAINING_SIGNALERS:
		ret = gxp_ioctl_fence_remaining_signalers(client, argp);
		break;
	default:
		ret = -ENOTTY; /* unknown command */
	}

	return ret;
}

int gxp_mcu_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct gxp_client *client = file->private_data;
	struct gxp_mcu *mcu = gxp_mcu_of(client->gxp);
	int ret;

	if (gxp_is_direct_mode(client->gxp))
		return -EOPNOTSUPP;

	switch (vma->vm_pgoff << PAGE_SHIFT) {
	case GXP_MMAP_MCU_LOG_BUFFER_OFFSET:
		ret = gxp_mcu_telemetry_mmap_buffer(mcu, GCIP_TELEMETRY_LOG,
						    vma);
		break;
	case GXP_MMAP_MCU_TRACE_BUFFER_OFFSET:
		ret = gxp_mcu_telemetry_mmap_buffer(mcu, GCIP_TELEMETRY_TRACE,
						    vma);
		break;
	default:
		ret = -EOPNOTSUPP; /* unknown offset */
	}

	return ret;
}
