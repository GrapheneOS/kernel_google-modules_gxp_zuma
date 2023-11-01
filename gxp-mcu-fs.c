// SPDX-License-Identifier: GPL-2.0-only
/*
 * Common file system operations for devices with MCU support.
 *
 * Copyright (C) 2022 Google LLC
 */

#include <linux/fs.h>
#include <linux/mm_types.h>
#include <linux/rwsem.h>

#include <gcip/gcip-telemetry.h>

#include "gxp-client.h"
#include "gxp-internal.h"
#include "gxp-mcu-fs.h"
#include "gxp-mcu-telemetry.h"
#include "gxp-mcu.h"
#include "gxp-uci.h"
#include "gxp.h"

#define GXP_UCI_NULL_COMMAND_FLAG (1 << 0)

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

	ret = gxp_uci_send_command(&mcu->uci, client->vd, &cmd, NULL,
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

static int gxp_ioctl_uci_command(struct gxp_client *client,
				 struct gxp_mailbox_uci_command_ioctl __user *argp)
{
	struct gxp_mailbox_uci_command_ioctl ibuf;
	struct gxp_dev *gxp = client->gxp;
	struct gxp_mcu *mcu = gxp_mcu_of(gxp);
	struct gxp_uci_command cmd = {};
	struct gxp_uci_additional_info additional_info = {};
	int ret;

	if (copy_from_user(&ibuf, argp, sizeof(ibuf)))
		return -EFAULT;

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

	memcpy(cmd.opaque, ibuf.opaque, sizeof(cmd.opaque));

	cmd.client_id = client->vd->client_id;

	if (ibuf.flags & GXP_UCI_NULL_COMMAND_FLAG)
		cmd.type = NULL_COMMAND;

	/*
	 * TODO(b/296162006): Get fence IDs of in/out-fence FDs in ibuf via IIF driver.
	 *                    After that, pass them to this function.
	 */
	gxp_uci_fill_additional_info(&additional_info, NULL, 0, NULL, 0, ibuf.timeout_ms, NULL, 0);

	ret = gxp_uci_send_command(&mcu->uci, client->vd, &cmd, &additional_info,
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
