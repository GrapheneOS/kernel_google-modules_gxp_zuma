/* SPDX-License-Identifier: GPL-2.0 */
/*
 * GXP client structure.
 *
 * Copyright (C) 2022 Google LLC
 */
#ifndef __GXP_CLIENT_H__
#define __GXP_CLIENT_H__

#include <linux/file.h>
#include <linux/rwsem.h>
#include <linux/sched.h>
#include <linux/types.h>

#include "gxp-internal.h"
#include "gxp-eventfd.h"
#include "gxp-vd.h"

/* Holds state belonging to a client */
struct gxp_client {
	struct list_head list_entry;
	struct gxp_dev *gxp;

	/*
	 * Protects all state of this client instance.
	 * Any operation that requires a client hold a particular wakelock must
	 * lock this semaphore for reading for the duration of that operation.
	 */
	struct rw_semaphore semaphore;

	bool has_block_wakelock;
	bool has_vd_wakelock;
	/* Value is one of the GXP_POWER_STATE_* values from gxp.h. */
	uint requested_power_state;
	/* Value is one of the MEMORY_POWER_STATE_* values from gxp.h. */
	uint requested_memory_power_state;
	bool requested_low_clkmux;

	struct gxp_virtual_device *vd;
	struct file *tpu_file;
	struct gxp_tpu_mbx_desc mbx_desc;

	struct gxp_eventfd *mb_eventfds[GXP_NUM_CORES];

	/* client process thread group ID is really the main process ID. */
	pid_t tgid;
	/* client process ID is really the thread ID, may be transient. */
	pid_t pid;

	/*
	 * Indicates whether the driver needs to disable telemetry when this
	 * client closes. For when the client fails to disable telemetry itself.
	 */
	bool enabled_telemetry_logging;
	bool enabled_telemetry_tracing;
};

/*
 * Allocates and initializes a client container.
 */
struct gxp_client *gxp_client_create(struct gxp_dev *gxp);

/*
 * Frees up the client container cleaning up any wakelocks, virtual devices, or
 * TPU mailboxes it holds.
 */
void gxp_client_destroy(struct gxp_client *client);
/**
 * gxp_client_allocate_virtual_device() - Allocates a virtual device for the
 * client.
 *
 * @client: The client to allocate a virtual device
 * @core_count: The requested core count of the virtual device.
 *
 * The caller must have locked client->semaphore.
 *
 * Return:
 * * 0          - Success
 * * -EINVAL    - A virtual device of the client has been allocated
 * * Otherwise  - Errno returned by virtual device allocation
 */
int gxp_client_allocate_virtual_device(struct gxp_client *client, uint core_count);
/**
 * gxp_client_acquire_block_wakelock() - Acquires a block wakelock and requests
 * power votes.
 *
 * @client: The client to acquire wakelock and request power votes.
 * @acquired_wakelock: True if block wakelock has been acquired by this client.
 * @power_state: The requested power state.
 * @memory_power_state: The requested memory power state.
 * @low_clkmux: Specify whether the vote is requested with low frequency CLKMUX
 *              flag. Will take no effect if the @power_state is AUR_OFF.
 *
 * The caller must have locked client->semaphore.
 *
 * Return:
 * * 0          - Success
 * * Otherwise  - Errno returned by block wakelock acquisition
 */
int gxp_client_acquire_block_wakelock(struct gxp_client *client,
				      bool *acquired_wakelock, uint power_state,
				      uint memory_power_state, bool low_clkmux);
/**
 * gxp_client_release_block_wakelock() - Releases the holded block wakelock and
 * revokes the power votes.
 *
 * The caller must have locked client->semaphore.
 */
void gxp_client_release_block_wakelock(struct gxp_client *client);
/**
 * gxp_client_acquire_vd_wakelock() - Acquires a VD wakelock for the current
 * virtual device to start the virtual device or resume it if it's suspended.
 *
 * The caller must have locked client->semaphore.
 *
 * Return:
 * * 0          - Success
 * * -EINVAL    - No holded block wakelock
 * * -ENODEV    - VD state is unavailable
 */
int gxp_client_acquire_vd_wakelock(struct gxp_client *client);
/**
 * gxp_client_release_vd_wakelock() - Releases the holded VD wakelock to suspend
 * the current virtual device.
 *
 * The caller must have locked client->semaphore.
 */
void gxp_client_release_vd_wakelock(struct gxp_client *client);

#endif /* __GXP_CLIENT_H__ */
