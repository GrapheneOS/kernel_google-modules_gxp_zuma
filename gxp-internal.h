/* SPDX-License-Identifier: GPL-2.0 */
/*
 * GXP driver common internal definitions.
 *
 * Copyright (C) 2021 Google LLC
 */
#ifndef __GXP_INTERNAL_H__
#define __GXP_INTERNAL_H__

#include <linux/debugfs.h>
#include <linux/delay.h>
#include <linux/firmware.h>
#include <linux/idr.h>
#include <linux/io.h>
#include <linux/iommu.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>
#include <linux/rwsem.h>
#include <linux/spinlock.h>

#include "gxp-config.h"

/* Holds Client's TPU mailboxes info used during mapping */
struct gxp_tpu_mbx_desc {
	uint phys_core_list;
	size_t cmdq_size, respq_size;
};

/* ioremapped resource */
struct gxp_mapped_resource {
	void __iomem *vaddr;		 /* starting virtual address */
	phys_addr_t paddr;		 /* starting physical address */
	dma_addr_t daddr;		 /* starting device address */
	resource_size_t size;		 /* size in bytes */
};

/* Structure to hold TPU device info */
struct gxp_tpu_dev {
	struct device *dev;
	phys_addr_t mbx_paddr;
};

/* Forward declarations from submodules */
struct gxp_client;
struct gxp_mailbox_manager;
struct gxp_debug_dump_manager;
struct gxp_domain_pool;
struct gxp_dma_manager;
struct gxp_fw_data_manager;
struct gxp_power_manager;
struct gxp_telemetry_manager;
struct gxp_thermal_manager;
struct gxp_wakelock_manager;
struct gxp_usage_stats;

struct gxp_dev {
	struct device *dev;		 /* platform bus device */
	struct miscdevice misc_dev;	 /* misc device structure */
	struct dentry *d_entry;		 /* debugfs dir for this device */
	struct gxp_mapped_resource regs; /* ioremapped CSRs */
	struct gxp_mapped_resource mbx[GXP_NUM_MAILBOXES]; /* mailbox CSRs */
	struct gxp_mapped_resource fwbufs[GXP_NUM_CORES]; /* FW carveout */
	struct gxp_mapped_resource fwdatabuf; /* Shared FW data carveout */
	struct gxp_mapped_resource cmu; /* CMU CSRs */
	struct gxp_mailbox_manager *mailbox_mgr;
	struct gxp_power_manager *power_mgr;
	struct gxp_debug_dump_manager *debug_dump_mgr;
	struct gxp_firmware_manager *firmware_mgr;
	/*
	 * Lock to ensure only one thread at a time is ever calling
	 * `pin_user_pages_fast()` during mapping, otherwise it will fail.
	 */
	struct mutex pin_user_pages_lock;
	/*
	 * Reader/writer lock protecting usage of virtual cores assigned to
	 * physical cores.
	 * A writer is any function creating or destroying a virtual core, or
	 * running or stopping one on a physical core.
	 * A reader is any function making use of or interacting with a virtual
	 * core without starting or stopping it on a physical core.
	 * The fields `core_to_vd[]` and `firmware_running` are also protected
	 * by this lock.
	 */
	struct rw_semaphore vd_semaphore;
	struct gxp_virtual_device *core_to_vd[GXP_NUM_CORES];
	struct gxp_client *debugfs_client;
	struct mutex debugfs_client_lock;
	bool debugfs_wakelock_held;
	struct gxp_thermal_manager *thermal_mgr;
	struct gxp_dma_manager *dma_mgr;
	struct gxp_fw_data_manager *data_mgr;
	struct gxp_tpu_dev tpu_dev;
	struct gxp_telemetry_manager *telemetry_mgr;
	struct gxp_wakelock_manager *wakelock_mgr;
	/*
	 * Pointer to GSA device for firmware authentication.
	 * May be NULL if the chip does not support firmware authentication
	 */
	struct device *gsa_dev;
	u32 memory_per_core;
	struct gxp_domain_pool *domain_pool;
	struct list_head client_list;
	struct mutex client_list_lock;
	/*
	 * Buffer shared across firmware.
	 * Its paddr is 0 if the shared buffer is not available.
	 * Its vaddr is always 0 as this region is not expected to be accessible
	 * to us.
	 */
	struct gxp_mapped_resource shared_buf;
	/*
	 * If the @shared_buf is used as split slices, it will keep track of
	 * which indexes of slices are used by ID allocator.
	 */
	struct ida shared_slice_idp;
	size_t shared_slice_size; /* The size of each slice. */
	/*
	 * The total number of slices.
	 * It can be zero if there is no shared buffer support.
	 */
	unsigned int num_shared_slices;
	struct gxp_usage_stats *usage_stats; /* Stores the usage stats */

	/* callbacks for chip-dependent implementations */

	/*
	 * For parsing chip-dependent device tree attributes.
	 *
	 * Called as the first step in the common device probing procedure.
	 *
	 * Do NOT use non-device managed allocations in this function, to
	 * prevent memory leak when the probe procedure fails.
	 *
	 * Return a non-zero value can fail the probe procedure.
	 *
	 * This callback is optional.
	 */
	int (*parse_dt)(struct platform_device *pdev, struct gxp_dev *gxp);
	/*
	 * Called when common device probing procedure is done.
	 *
	 * Return a non-zero value can fail the probe procedure.
	 *
	 * This callback is optional.
	 */
	int (*after_probe)(struct gxp_dev *gxp);
	/*
	 * Called before common device removal procedure.
	 *
	 * This callback is optional.
	 */
	void (*before_remove)(struct gxp_dev *gxp);
	/*
	 * Device ioctl handler for chip-dependent ioctl calls.
	 * Should return -ENOTTY when the ioctl should be handled by common
	 * device ioctl handler.
	 *
	 * This callback is optional.
	 */
	long (*handle_ioctl)(struct file *file, uint cmd, ulong arg);
	/*
	 * Called when allocating a virtual device is done.
	 *
	 * Return a non-zero value can fail the vd allocation.
	 *
	 * This callback is optional.
	 */
	int (*after_allocate_vd)(struct gxp_dev *gxp,
				 struct gxp_virtual_device *vd);
	/*
	 * Called before releasing the virtual device.
	 *
	 * This callback is optional.
	 */
	void (*before_release_vd)(struct gxp_dev *gxp,
				  struct gxp_virtual_device *vd);
};

/* GXP device IO functions */

static inline u32 gxp_read_32(struct gxp_dev *gxp, uint reg_offset)
{
	return readl(gxp->regs.vaddr + reg_offset);
}

static inline void gxp_write_32(struct gxp_dev *gxp, uint reg_offset, u32 value)
{
	writel(value, gxp->regs.vaddr + reg_offset);
}

static inline int gxp_acquire_rmem_resource(struct gxp_dev *gxp,
					    struct resource *r, char *phandle)
{
	int ret;
	struct device_node *np;

	np = of_parse_phandle(gxp->dev->of_node, phandle, 0);
	if (IS_ERR_OR_NULL(np)) {
		dev_err(gxp->dev, "Failed to find \"%s\" reserved memory\n",
			phandle);
		return -ENODEV;
	}

	ret = of_address_to_resource(np, 0, r);
	of_node_put(np);

	return ret;
}

/*
 * To specify whether AP and DSP cores directly communicate by the core mailboxes.
 * All platform drivers of each chip should implement this.
 */
bool gxp_is_direct_mode(struct gxp_dev *gxp);

#endif /* __GXP_INTERNAL_H__ */
