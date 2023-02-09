// SPDX-License-Identifier: GPL-2.0
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

static int
gxp_ioctl_uci_command(struct gxp_client *client,
		      struct gxp_mailbox_uci_command_ioctl __user *argp)
{
	struct gxp_mailbox_uci_command_ioctl ibuf;
	struct gxp_dev *gxp = client->gxp;
	struct gxp_mcu *mcu = gxp_mcu_of(gxp);
	struct gxp_uci_command cmd = {};
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

	ret = gxp_uci_send_command(
		&mcu->uci, client->vd, &cmd,
		&client->vd->mailbox_resp_queues[UCI_RESOURCE_ID].wait_queue,
		&client->vd->mailbox_resp_queues[UCI_RESOURCE_ID].dest_queue,
		&client->vd->mailbox_resp_queues[UCI_RESOURCE_ID].lock,
		&client->vd->mailbox_resp_queues[UCI_RESOURCE_ID].waitq,
		client->mb_eventfds[UCI_RESOURCE_ID]);

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

	if (!gxp_client_has_available_vd(client, "GXP_MAILBOX_UCI_RESPONSE")) {
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

static int gxp_ioctl_uci_command_helper(struct gxp_client *client,
					struct gxp_mailbox_command_ioctl *ibuf)
{
	struct gxp_dev *gxp = client->gxp;
	struct gxp_mcu *mcu = gxp_mcu_of(gxp);
	struct gxp_uci_command cmd;
	int ret;

	if (ibuf->virtual_core_id >= GXP_NUM_CORES)
		return -EINVAL;
	down_read(&client->semaphore);

	if (!gxp_client_has_available_vd(client, "GXP_MAILBOX_COMMAND")) {
		ret = -ENODEV;
		goto out;
	}

	/* Caller must hold BLOCK wakelock */
	if (!client->has_block_wakelock) {
		dev_err(gxp->dev,
			"GXP_MAILBOX_COMMAND requires the client hold a BLOCK wakelock\n");
		ret = -ENODEV;
		goto out;
	}

	/* Use at least one core for the command */
	if (ibuf->num_cores == 0)
		ibuf->num_cores = 1;

	/* Pack the command structure */
	cmd.core_command_params.address = ibuf->device_address;
	cmd.core_command_params.size = ibuf->size;
	cmd.core_command_params.num_cores = ibuf->num_cores;
	/* Plus 1 to align with power states in MCU firmware. */
	cmd.core_command_params.dsp_operating_point = ibuf->gxp_power_state + 1;
	cmd.core_command_params.memory_operating_point =
		ibuf->memory_power_state;
	/* cmd.seq is assigned by mailbox implementation */
	cmd.type = CORE_COMMAND;

	/* TODO(b/248179414): Remove core assignment when MCU fw re-enable sticky core scheduler. */
	{
		int core;

		down_read(&gxp->vd_semaphore);
		core = gxp_vd_virt_core_to_phys_core(client->vd,
						     ibuf->virtual_core_id);
		up_read(&gxp->vd_semaphore);
		if (core < 0) {
			dev_err(gxp->dev,
				"Mailbox command failed: Invalid virtual core id (%u)\n",
				ibuf->virtual_core_id);
			ret = -EINVAL;
			goto out;
		}
		cmd.core_id = core;
	}

	cmd.client_id = client->vd->client_id;

	/*
	 * TODO(b/248196344): Use the only one permitted eventfd for the virtual device
	 * when MCU fw re-enable sticky core scheduler.
	 */
	ret = gxp_uci_send_command(
		&mcu->uci, client->vd, &cmd,
		&client->vd->mailbox_resp_queues[UCI_RESOURCE_ID].wait_queue,
		&client->vd->mailbox_resp_queues[UCI_RESOURCE_ID].dest_queue,
		&client->vd->mailbox_resp_queues[UCI_RESOURCE_ID].lock,
		&client->vd->mailbox_resp_queues[UCI_RESOURCE_ID].waitq,
		client->mb_eventfds[ibuf->virtual_core_id]);
	if (ret) {
		dev_err(gxp->dev,
			"Failed to enqueue mailbox command (ret=%d)\n", ret);
		goto out;
	}
	ibuf->sequence_number = cmd.seq;

out:
	up_read(&client->semaphore);
	return ret;
}

static int
gxp_ioctl_uci_command_legacy(struct gxp_client *client,
			     struct gxp_mailbox_command_ioctl __user *argp)
{
	struct gxp_mailbox_command_ioctl ibuf;
	int ret;

	if (copy_from_user(&ibuf, argp, sizeof(ibuf)))
		return -EFAULT;

	ret = gxp_ioctl_uci_command_helper(client, &ibuf);
	if (ret)
		return ret;

	if (copy_to_user(argp, &ibuf, sizeof(ibuf)))
		return -EFAULT;

	return 0;
}

static int
gxp_ioctl_uci_response_legacy(struct gxp_client *client,
			      struct gxp_mailbox_response_ioctl __user *argp)
{
	struct gxp_mailbox_response_ioctl ibuf;
	int ret = 0;

	if (copy_from_user(&ibuf, argp, sizeof(ibuf)))
		return -EFAULT;

	down_read(&client->semaphore);

	if (!gxp_client_has_available_vd(client, "GXP_MAILBOX_RESPONSE")) {
		ret = -ENODEV;
		goto out;
	}

	/* Caller must hold BLOCK wakelock */
	if (!client->has_block_wakelock) {
		dev_err(client->gxp->dev,
			"GXP_MAILBOX_RESPONSE requires the client hold a BLOCK wakelock\n");
		ret = -ENODEV;
		goto out;
	}

	ret = gxp_uci_wait_async_response(
		&client->vd->mailbox_resp_queues[UCI_RESOURCE_ID],
		&ibuf.sequence_number, &ibuf.error_code, NULL);
	if (ret)
		goto out;

	ibuf.cmd_retval = 0;
	if (copy_to_user(argp, &ibuf, sizeof(ibuf)))
		ret = -EFAULT;

out:
	up_read(&client->semaphore);

	return ret;
}

static inline enum gcip_telemetry_type to_gcip_telemetry_type(u8 type)
{
	if (type == GXP_TELEMETRY_TYPE_LOGGING)
		return GCIP_TELEMETRY_LOG;
	else
		return GCIP_TELEMETRY_TRACE;
}

static int gxp_register_mcu_telemetry_eventfd(
	struct gxp_client *client,
	struct gxp_register_telemetry_eventfd_ioctl __user *argp)
{
	struct gxp_mcu *mcu = gxp_mcu_of(client->gxp);
	struct gxp_register_telemetry_eventfd_ioctl ibuf;

	if (copy_from_user(&ibuf, argp, sizeof(ibuf)))
		return -EFAULT;

	return gxp_mcu_telemetry_register_eventfd(
		mcu, to_gcip_telemetry_type(ibuf.type), ibuf.eventfd);
}

static int gxp_unregister_mcu_telemetry_eventfd(
	struct gxp_client *client,
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
		ret = gxp_ioctl_uci_command_legacy(client, argp);
		break;
	case GXP_MAILBOX_RESPONSE:
		ret = gxp_ioctl_uci_response_legacy(client, argp);
		break;
	case GXP_REGISTER_MCU_TELEMETRY_EVENTFD:
		ret = gxp_register_mcu_telemetry_eventfd(client, argp);
		break;
	case GXP_UNREGISTER_MCU_TELEMETRY_EVENTFD:
		ret = gxp_unregister_mcu_telemetry_eventfd(client, argp);
		break;
	case GXP_MAILBOX_UCI_COMMAND:
		ret = gxp_ioctl_uci_command(client, argp);
		break;
	case GXP_MAILBOX_UCI_RESPONSE:
		ret = gxp_ioctl_uci_response(client, argp);
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
