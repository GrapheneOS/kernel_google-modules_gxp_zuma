/* SPDX-License-Identifier: GPL-2.0 */
/*
 * GXP virtual device manager.
 *
 * Copyright (C) 2021-2022 Google LLC
 */

#ifndef __GXP_VD_H__
#define __GXP_VD_H__

#include <linux/iommu.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/rwsem.h>
#include <linux/scatterlist.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/wait.h>

#include "gxp-internal.h"
#include "gxp-mapping.h"

/* TODO(b/259192112): set to 8 once the runtime has added the credit limit. */
#define GXP_COMMAND_CREDIT_PER_VD 256

/* A special client ID for secure workloads pre-agreed with MCU firmware. */
#define SECURE_CLIENT_ID (3 << 10)

struct mailbox_resp_queue {
	/* Queue of waiting async responses */
	struct list_head wait_queue;
	/* Queue of arrived async responses */
	struct list_head dest_queue;
	/* Lock protecting access to the `queue` */
	spinlock_t lock;
	/* Waitqueue to wait on if the queue is empty */
	wait_queue_head_t waitq;
};

enum gxp_virtual_device_state {
	GXP_VD_OFF,
	GXP_VD_READY,
	GXP_VD_RUNNING,
	GXP_VD_SUSPENDED,
	/*
	 * If the virtual device is in the unavailable state, it won't be changed
	 * back no matter what we do.
	 * Note: this state will only be set on suspend/resume failure.
	 */
	GXP_VD_UNAVAILABLE,
};

struct gxp_virtual_device {
	struct gxp_dev *gxp;
	uint num_cores;
	void *fw_app;
	struct gxp_iommu_domain *domain;
	struct mailbox_resp_queue *mailbox_resp_queues;
	struct rb_root mappings_root;
	struct rw_semaphore mappings_semaphore;
	enum gxp_virtual_device_state state;
	/*
	 * Record the gxp->power_mgr->blk_switch_count when the vd was
	 * suspended. Use this information to know whether the block has been
	 * restarted and therefore we need to re-program CSRs in the resume
	 * process.
	 */
	u64 blk_switch_count_when_suspended;
	/*
	 * @domain of each virtual device will map a slice of shared buffer. It stores which index
	 * of slice is used by this VD.
	 */
	int slice_index;
	/*
	 * The SG table that holds the firmware data region.
	 */
	struct sg_table *fwdata_sgt;
	uint core_list;
	/*
	 * The ID of DSP client. -1 if it is not allocated.
	 * This is allocated by the DSP kernel driver, but will be set to this variable only when
	 * the client of this vd acquires the block wakelock successfully. (i.e, after the kernel
	 * driver allocates a virtual mailbox with the firmware side successfully by sending the
	 * `allocate_vmbox` KCI command.)
	 */
	int client_id;
	/*
	 * The ID of TPU client. -1 if it is not allocated.
	 * This ID will be fetched from the TPU kernel driver.
	 */
	int tpu_client_id;
	/*
	 * Protects credit. Use a spin lock because the critical section of
	 * using @credit is pretty small.
	 */
	spinlock_t credit_lock;
	/*
	 * Credits for sending mailbox commands. It's initialized as
	 * GXP_COMMAND_CREDIT_PER_VD. The value is decreased on sending
	 * mailbox commands; increased on receiving mailbox responses.
	 * Mailbox command requests are rejected when this value reaches 0.
	 *
	 * Only used in MCU mode.
	 */
	uint credit;
	/* Whether it's the first time allocating a VMBox for this VD. */
	bool first_open;
	bool is_secure;
};

/*
 * TODO(b/193180931) cleanup the relationship between the internal GXP modules.
 * For example, whether or not gxp_vd owns the gxp_fw module, and if so, if
 * other modules are expected to access the gxp_fw directly or only via gxp_vd.
 */
/*
 * Initializes the device management subsystem and allocates resources for it.
 * This is expected to be called once per driver lifecycle.
 */
void gxp_vd_init(struct gxp_dev *gxp);

/*
 * Tears down the device management subsystem.
 * This is expected to be called once per driver lifecycle.
 */
void gxp_vd_destroy(struct gxp_dev *gxp);

/**
 * gxp_vd_allocate() - Allocate and initialize a struct gxp_virtual_device
 * @gxp: The GXP device the virtual device will belong to
 * @requested_cores: The number of cores the virtual device will have
 *
 * The state of VD is initialized to GXP_VD_OFF.
 *
 * The caller must have locked gxp->vd_semaphore for writing.
 *
 * Return: The virtual address of the virtual device or an ERR_PTR on failure
 * * -EINVAL - The number of requested cores was invalid
 * * -ENOMEM - Unable to allocate the virtual device
 * * -EBUSY  - Not enough iommu domains available or insufficient physical
 *	       cores to be assigned to @vd
 * * -ENOSPC - There is no more available shared slices
 */
struct gxp_virtual_device *gxp_vd_allocate(struct gxp_dev *gxp,
					   u16 requested_cores);

/**
 * gxp_vd_release() - Cleanup and free a struct gxp_virtual_device
 * @vd: The virtual device to be released
 *
 * The caller must have locked gxp->vd_semaphore for writing.
 *
 * A virtual device must be stopped before it can be released.
 */
void gxp_vd_release(struct gxp_virtual_device *vd);

/**
 * gxp_vd_run() - Run a virtual device on physical cores
 * @vd: The virtual device to run
 *
 * The state of @vd should be GXP_VD_OFF or GXP_VD_READY before calling this
 * function. If this function runs successfully, the state becomes
 * GXP_VD_RUNNING. Otherwise, it would be GXP_VD_UNAVAILABLE.
 *
 * The caller must have locked gxp->vd_semaphore.
 *
 * Return:
 * * 0         - Success
 * * -EINVAL   - The VD is not in GXP_VD_READY state
 * * Otherwise - Errno returned by firmware running
 */
int gxp_vd_run(struct gxp_virtual_device *vd);

/**
 * gxp_vd_stop() - Stop a running virtual device
 * @vd: The virtual device to stop
 *
 * The state of @vd will be GXP_VD_OFF.
 *
 * The caller must have locked gxp->vd_semaphore.
 */
void gxp_vd_stop(struct gxp_virtual_device *vd);

/*
 * Returns the physical core ID for the specified virtual_core belonging to
 * this virtual device or -EINVAL if this virtual core is not running on a
 * physical core.
 *
 * The caller must have locked gxp->vd_semaphore for reading.
 */
int gxp_vd_virt_core_to_phys_core(struct gxp_virtual_device *vd, u16 virt_core);

/*
 * Acquires the physical core IDs assigned to the virtual device.
 *
 * The caller must have locked gxp->vd_semaphore for reading.
 */
uint gxp_vd_phys_core_list(struct gxp_virtual_device *vd);

/**
 * gxp_vd_mapping_store() - Store a mapping in a virtual device's records
 * @vd: The virtual device @map was created for and will be stored in
 * @map: The mapping to store
 *
 * Acquires a reference to @map if it was successfully stored
 *
 * Return:
 * * 0: Success
 * * -EINVAL: @map is already stored in @vd's records
 */
int gxp_vd_mapping_store(struct gxp_virtual_device *vd,
			 struct gxp_mapping *map);

/**
 * gxp_vd_mapping_remove() - Remove a mapping from a virtual device's records
 * @vd: The VD to remove @map from
 * @map: The mapping to remove
 *
 * Releases a reference to @map if it was successfully removed
 */
void gxp_vd_mapping_remove(struct gxp_virtual_device *vd,
			   struct gxp_mapping *map);

/**
 * gxp_vd_mapping_search() - Obtain a reference to the mapping starting at the
 *                           specified device address
 * @vd: The virtual device to search for the mapping
 * @device_address: The starting device address of the mapping to find
 *
 * Obtains a reference to the returned mapping
 *
 * Return: A pointer to the mapping if found; NULL otherwise
 */
struct gxp_mapping *gxp_vd_mapping_search(struct gxp_virtual_device *vd,
					  dma_addr_t device_address);

/**
 * gxp_vd_mapping_search_in_range() - Obtain a reference to the mapping which
 *                                    contains the specified device address
 * @vd: The virtual device to search for the mapping
 * @device_address: A device address contained in the buffer the mapping to
 *                  find describes.
 *
 * Obtains a reference to the returned mapping
 *
 * Return: A pointer to the mapping if found; NULL otherwise
 */
struct gxp_mapping *
gxp_vd_mapping_search_in_range(struct gxp_virtual_device *vd,
			       dma_addr_t device_address);

/**
 * gxp_vd_mapping_search_host() - Obtain a reference to the mapping starting at
 *                                the specified user-space address
 * @vd: The virtual device to search for the mapping
 * @host_address: The starting user-space address of the mapping to find
 *
 * Obtains a reference to the returned mapping
 *
 * Return: A pointer to the mapping if found; NULL otherwise
 */
struct gxp_mapping *gxp_vd_mapping_search_host(struct gxp_virtual_device *vd,
					       u64 host_address);

/**
 * gxp_vd_suspend() - Suspend a running virtual device
 * @vd: The virtual device to suspend
 *
 * The state of @vd should be GXP_VD_RUNNING before calling this function.
 * If the suspension runs successfully on all cores, the state becomes
 * GXP_VD_SUSPENDED. Otherwise, it would be GXP_VD_UNAVAILABLE.
 *
 * The caller must have locked gxp->vd_semaphore for writing.
 */
void gxp_vd_suspend(struct gxp_virtual_device *vd);

/**
 * gxp_vd_resume() - Resume a suspended virtual device
 * @vd: The virtual device to resume
 *
 * The state of @vd should be GXP_VD_SUSPENDED before calling this function.
 * If the resumption runs successfully on all cores, the state becomes
 * GXP_VD_RUNNING. Otherwise, it would be GXP_VD_UNAVAILABLE.
 *
 * The caller must have locked gxp->vd_semaphore for writing.
 *
 * Return:
 * * 0          - Success
 * * -ETIMEDOUT - Fail to power on physical cores
 */
int gxp_vd_resume(struct gxp_virtual_device *vd);

/**
 * gxp_vd_block_ready() - This is called after the block wakelock is acquired.
 * Does required setup for serving VD such as attaching its IOMMU domain.
 *
 * @vd: The virtual device to prepare the resources
 *
 * The state of @vd should be GXP_VD_OFF before calling this function.
 * If this function runs successfully, the state becomes GXP_VD_READY.
 *
 * Return:
 * * 0          - Success
 * * -EINVAL    - The VD is not in GXP_VD_OFF state
 * * Otherwise  - Errno returned by IOMMU domain attachment
 */
int gxp_vd_block_ready(struct gxp_virtual_device *vd);

/**
 * gxp_vd_block_unready() - This is called before one or both of the virtual device and block
 * wakelock is going to be released.
 *
 * @vd: The virtual device to release the resources
 *
 * This function must be called only when the client holds the block wakelock and allocated a
 * virtual device. It doesn't have a dependency on the state of @vd, but also doesn't change the
 * state.
 */
void gxp_vd_block_unready(struct gxp_virtual_device *vd);

/*
 * Checks whether the virtual device has a positive credit, and use 1 credit when
 * yes.
 *
 * Returns true when there is enough credit, false otherwise.
 */
bool gxp_vd_has_and_use_credit(struct gxp_virtual_device *vd);
/*
 * Releases the credit.
 */
void gxp_vd_release_credit(struct gxp_virtual_device *vd);

#endif /* __GXP_VD_H__ */
