// SPDX-License-Identifier: GPL-2.0
/*
 * GXP firmware data manager.
 *
 * Copyright (C) 2021 Google LLC
 */

#include <linux/bitops.h>
#include <linux/dma-mapping.h>
#include <linux/genalloc.h>

#include "gxp-debug-dump.h"
#include "gxp-firmware-data.h"
#include "gxp-firmware-loader.h"
#include "gxp-firmware.h" /* gxp_core_boot */
#include "gxp-host-device-structs.h"
#include "gxp-internal.h"
#include "gxp-range-alloc.h"
#include "gxp-vd.h"
#include "gxp.h"

/*
 * The minimum alignment order (power of 2) of allocations in the firmware data
 * region.
 */
#define FW_DATA_STORAGE_ORDER 3

/* A byte pattern to pre-populate the FW region with */
#define FW_DATA_DEBUG_PATTERN 0x66

/* IDs for dedicated doorbells used by some system components */
#define DOORBELL_ID_CORE_WAKEUP(__core__) (0 + __core__)

/* IDs for dedicated sync barriers used by some system components */
#define SYNC_BARRIER_ID_UART 1

/* Default application parameters */
#define DEFAULT_APP_ID 1
#define DEFAULT_APP_USER_MEM_SIZE (120 * 1024)
#define DEFAULT_APP_USER_MEM_ALIGNMENT 8
#define DEFAULT_APP_THREAD_COUNT 2
#define DEFAULT_APP_TCM_PER_BANK (100 * 1024)
#define DEFAULT_APP_USER_DOORBELL_COUNT 2
#define DEFAULT_APP_USER_BARRIER_COUNT 2

/* Core-to-core mailbox communication constants */
#define CORE_TO_CORE_MBX_CMD_COUNT 10
#define CORE_TO_CORE_MBX_RSP_COUNT 10

/* A block allocator managing and partitioning a memory region for device use */
struct fw_memory_allocator {
	struct gen_pool *pool;
	struct gxp_dev *gxp;
	void *base_host_addr;
	uint32_t base_device_addr;
};

/* A memory region allocated for device use */
struct fw_memory {
	void *host_addr;
	uint32_t device_addr;
	size_t sz;
};

/*
 * Holds information about system-wide HW and memory resources given to the FWs
 * of GXP devices.
 */
struct gxp_fw_data_manager {
	/* Host-side pointers for book keeping */
	void *fw_data_virt;
	struct gxp_system_descriptor *system_desc;

	/* Doorbells allocator and reserved doorbell IDs */
	struct range_alloc *doorbell_allocator;
	int core_wakeup_doorbells[GXP_NUM_WAKEUP_DOORBELLS];
	int semaphore_doorbells[GXP_NUM_CORES];

	/* Sync barriers allocator and reserved sync barrier IDs */
	struct range_alloc *sync_barrier_allocator;
	int uart_sync_barrier;
	int timer_regions_barrier;
	int watchdog_region_barrier;
	int uart_region_barrier;
	int doorbell_regions_barrier;
	int sync_barrier_regions_barrier;
	int semaphores_regions_barrier;

	/* System-wide device memory resources */
	struct fw_memory_allocator *allocator;
	struct fw_memory sys_desc_mem;
	struct fw_memory wdog_mem;
	struct fw_memory core_telemetry_mem;
	struct fw_memory debug_dump_mem;

	/*
	 * A host-view of the System configuration descriptor. This same desc
	 * is provided to all VDs and all cores. This is the R/O section.
	 */
	struct gxp_system_descriptor_ro *sys_desc_ro;
	/*
	 * A host-view of the System configuration descriptor. This same desc
	 * is provided to all VDs and all cores. This is the R/W section.
	 */
	struct gxp_system_descriptor_rw *sys_desc_rw;
};

/* A container holding information for a single GXP application. */
struct app_metadata {
	struct gxp_fw_data_manager *mgr;
	struct gxp_virtual_device *vd;
	uint application_id;
	uint core_count;
	uint core_list; /* bitmap of cores allocated to this app */

	/* Per-app doorbell IDs */
	int user_doorbells_count;
	int *user_doorbells;

	/* Per-app sync barrier IDs */
	int user_barriers_count;
	int *user_barriers;

	/* Per-app memory regions */
	struct fw_memory user_mem;
	struct fw_memory doorbells_mem;
	struct fw_memory sync_barriers_mem;
	struct fw_memory semaphores_mem;
	struct fw_memory cores_mem;
	struct fw_memory core_cmd_queues_mem[GXP_NUM_CORES];
	struct fw_memory core_rsp_queues_mem[GXP_NUM_CORES];
	struct fw_memory app_mem;
};

static struct fw_memory_allocator *mem_alloc_create(struct gxp_dev *gxp,
						    void *host_base,
						    uint32_t device_base,
						    size_t size)
{
	struct fw_memory_allocator *allocator;
	int ret = 0;

	allocator = kzalloc(sizeof(*allocator), GFP_KERNEL);
	if (!allocator)
		return ERR_PTR(-ENOMEM);

	/*
	 * Use a genpool to allocate and free chunks of the virtual address
	 * space reserved for FW data. The genpool doesn't use the passed
	 * addresses internally to access any data, thus it is safe to use it to
	 * manage memory that the host may not be able to access directly.
	 * The allocator also records the host-side address so that the code
	 * here can access and populate data in this region.
	 */
	allocator->gxp = gxp;
	allocator->pool = gen_pool_create(FW_DATA_STORAGE_ORDER, /*nid=*/-1);
	if (!allocator->pool) {
		dev_err(gxp->dev, "Failed to create memory pool\n");
		kfree(allocator);
		return ERR_PTR(-ENOMEM);
	}

	ret = gen_pool_add(allocator->pool, device_base, size, /*nid=*/-1);
	if (ret) {
		dev_err(gxp->dev, "Failed to add memory to pool (ret = %d)\n",
			ret);
		gen_pool_destroy(allocator->pool);
		kfree(allocator);
		return ERR_PTR(ret);
	}
	allocator->base_host_addr = host_base;
	allocator->base_device_addr = device_base;

	return allocator;
}

static int mem_alloc_allocate(struct fw_memory_allocator *allocator,
			      struct fw_memory *mem, size_t size,
			      uint8_t alignment)
{
	struct genpool_data_align data = { .align = alignment };
	uint32_t dev_addr;

	dev_addr = gen_pool_alloc_algo(allocator->pool, size,
				       gen_pool_first_fit_align, &data);
	if (!dev_addr)
		return -ENOMEM;

	mem->host_addr = allocator->base_host_addr +
			 (dev_addr - allocator->base_device_addr);
	mem->device_addr = dev_addr;
	mem->sz = size;

	return 0;
}

static void mem_alloc_free(struct fw_memory_allocator *allocator,
			   struct fw_memory *mem)
{
	gen_pool_free(allocator->pool, mem->device_addr, mem->sz);
}

static void mem_alloc_destroy(struct fw_memory_allocator *allocator)
{
	WARN_ON(gen_pool_avail(allocator->pool) !=
		gen_pool_size(allocator->pool));
	gen_pool_destroy(allocator->pool);
	kfree(allocator);
}

static struct fw_memory init_doorbells(struct app_metadata *app)
{
	struct gxp_doorbells_descriptor *db_region;
	struct fw_memory mem;
	uint32_t mem_size;
	uint32_t doorbell_count;
	int i;

	doorbell_count = app->user_doorbells_count;
	mem_size = sizeof(*db_region) +
		   doorbell_count * sizeof(db_region->doorbells[0]);

	mem_alloc_allocate(app->mgr->allocator, &mem, mem_size,
			   __alignof__(struct gxp_doorbells_descriptor));

	db_region = mem.host_addr;
	db_region->application_id = app->application_id;
	db_region->protection_barrier = app->mgr->doorbell_regions_barrier;
	db_region->num_items = doorbell_count;
	for (i = 0; i < doorbell_count; i++) {
		db_region->doorbells[i].users_count = 0;
		db_region->doorbells[i].hw_doorbell_idx =
			app->user_doorbells[i];
	}

	return mem;
}

static struct fw_memory init_sync_barriers(struct app_metadata *app)
{
	struct gxp_sync_barriers_descriptor *sb_region;
	struct fw_memory mem;
	uint32_t mem_size;
	uint32_t barrier_count;
	int i;

	barrier_count = app->user_barriers_count;
	mem_size = sizeof(*sb_region) +
		   barrier_count * sizeof(sb_region->barriers[0]);

	mem_alloc_allocate(app->mgr->allocator, &mem, mem_size,
			   __alignof__(struct gxp_sync_barriers_descriptor));

	sb_region = mem.host_addr;
	sb_region->application_id = app->application_id;
	sb_region->protection_barrier = app->mgr->sync_barrier_regions_barrier;
	sb_region->num_items = barrier_count;
	for (i = 0; i < barrier_count; i++) {
		sb_region->barriers[i].users_count = 0;
		sb_region->barriers[i].hw_barrier_idx = app->user_barriers[i];
	}

	return mem;
}

static struct fw_memory init_watchdog(struct gxp_fw_data_manager *mgr)
{
	struct gxp_watchdog_descriptor *wd_region;
	struct fw_memory mem;

	mem_alloc_allocate(mgr->allocator, &mem, sizeof(*wd_region),
			   __alignof__(struct gxp_watchdog_descriptor));

	wd_region = mem.host_addr;
	wd_region->protection_barrier = mgr->watchdog_region_barrier;
	wd_region->target_value = 0;
	wd_region->participating_cores = 0;
	wd_region->responded_cores = 0;
	wd_region->tripped = 0;

	return mem;
}

static struct fw_memory init_core_telemetry(struct gxp_fw_data_manager *mgr)
{
	struct gxp_core_telemetry_descriptor *tel_region;
	struct fw_memory mem;

	mem_alloc_allocate(mgr->allocator, &mem, sizeof(*tel_region),
			   __alignof__(struct gxp_core_telemetry_descriptor));

	tel_region = mem.host_addr;

	/*
	 * Core telemetry is disabled for now.
	 * Subsuequent calls to the FW data module can be used to populate or
	 * depopulate the descriptor pointers on demand.
	 */
	memset(tel_region, 0x00, sizeof(*tel_region));

	return mem;
}

static struct fw_memory init_debug_dump(struct gxp_dev *gxp)
{
	struct fw_memory mem;

	if (gxp->debug_dump_mgr) {
		mem.host_addr = gxp->debug_dump_mgr->buf.vaddr;
		mem.device_addr = gxp->debug_dump_mgr->buf.dsp_addr;
		mem.sz = gxp->debug_dump_mgr->buf.size;
	} else {
		mem.host_addr = 0;
		mem.device_addr = 0;
		mem.sz = 0;
	}

	return mem;
}

static struct fw_memory init_app_user_memory(struct app_metadata *app,
					     int memory_size)
{
	struct fw_memory mem;

	mem_alloc_allocate(app->mgr->allocator, &mem, memory_size,
			   DEFAULT_APP_USER_MEM_ALIGNMENT);

	return mem;
}

static struct fw_memory init_app_semaphores(struct app_metadata *app)
{
	struct gxp_semaphores_descriptor *sm_region;
	struct fw_memory mem;
	uint32_t mem_size;
	uint32_t semaphore_count;
	int core;
	int i;

	semaphore_count = NUM_SYSTEM_SEMAPHORES;
	mem_size = sizeof(*sm_region) +
		   semaphore_count * sizeof(sm_region->semaphores[0]);

	mem_alloc_allocate(app->mgr->allocator, &mem, mem_size,
			   __alignof__(struct gxp_semaphores_descriptor));

	sm_region = mem.host_addr;
	sm_region->application_id = app->application_id;
	sm_region->protection_barrier = app->mgr->semaphores_regions_barrier;

	core = 0;
	for (i = 0; i < GXP_NUM_CORES; i++) {
		if (app->core_list & BIT(i))
			sm_region->wakeup_doorbells[core++] =
				app->mgr->semaphore_doorbells[i];
		sm_region->woken_pending_semaphores[i] = 0;
	}

	sm_region->num_items = semaphore_count;
	for (i = 0; i < semaphore_count; i++) {
		sm_region->semaphores[i].users_count = 0;
		sm_region->semaphores[i].count = 0;
		sm_region->semaphores[i].waiters = 0;
	}

	return mem;
}

static struct fw_memory init_app_cores(struct app_metadata *app)
{
	struct gxp_cores_descriptor *cd_region;
	struct gxp_queue_info *q_info;
	struct fw_memory mem;
	uint32_t mem_size;
	int semaphore_id;
	int core_count;
	int i;
	const int cmd_queue_items = CORE_TO_CORE_MBX_CMD_COUNT;
	const int resp_queue_items = CORE_TO_CORE_MBX_RSP_COUNT;

	/* Core info structures. */
	core_count = app->core_count;
	mem_size =
		sizeof(*cd_region) + core_count * sizeof(cd_region->cores[0]);

	mem_alloc_allocate(app->mgr->allocator, &mem, mem_size,
			   __alignof__(struct gxp_cores_descriptor));

	cd_region = mem.host_addr;
	cd_region->num_items = core_count;

	/* Command and response queues. */
	semaphore_id = 0;
	for (i = 0; i < core_count; i++) {
		/* Allocate per-core command queue storage. */
		mem_size = cmd_queue_items *
			   sizeof(struct gxp_core_to_core_command);
		mem_alloc_allocate(
			app->mgr->allocator, &app->core_cmd_queues_mem[i],
			mem_size, __alignof__(struct gxp_core_to_core_command));

		/* Update per-core command queue info. */
		q_info = &cd_region->cores[i].incoming_commands_queue;
		q_info->header.storage =
			app->core_cmd_queues_mem[i].device_addr;
		q_info->header.head_idx = 0;
		q_info->header.tail_idx = 0;
		q_info->header.element_size =
			sizeof(struct gxp_core_to_core_command);
		q_info->header.elements_count = cmd_queue_items;
		q_info->access_sem_id = semaphore_id++;
		q_info->posted_slots_sem_id = semaphore_id++;
		q_info->free_slots_sem_id = semaphore_id++;

		/* Allocate per-core response queue storage. */
		mem_size = resp_queue_items *
			   sizeof(struct gxp_core_to_core_response);
		mem_alloc_allocate(
			app->mgr->allocator, &app->core_rsp_queues_mem[i],
			mem_size,
			__alignof__(struct gxp_core_to_core_response));

		/* Update per-core response queue info. */
		q_info = &cd_region->cores[i].incoming_responses_queue;
		q_info->header.storage =
			app->core_rsp_queues_mem[i].device_addr;
		q_info->header.head_idx = 0;
		q_info->header.tail_idx = 0;
		q_info->header.element_size =
			sizeof(struct gxp_core_to_core_response);
		q_info->header.elements_count = resp_queue_items;
		q_info->access_sem_id = semaphore_id++;
		q_info->posted_slots_sem_id = semaphore_id++;
		q_info->free_slots_sem_id = semaphore_id++;
	}

	return mem;
}

static struct fw_memory init_application(struct app_metadata *app)
{
	struct gxp_application_descriptor *app_region;
	struct fw_memory mem;
	const int user_mem_size = DEFAULT_APP_USER_MEM_SIZE;

	/* App's system memory. */
	app->user_mem = init_app_user_memory(app, user_mem_size);

	/* App's doorbells region. */
	app->doorbells_mem = init_doorbells(app);

	/* App's  sync barriers region. */
	app->sync_barriers_mem = init_sync_barriers(app);

	/* App's semaphores region. */
	app->semaphores_mem = init_app_semaphores(app);

	/* App's cores info and core-to-core queues. */
	app->cores_mem = init_app_cores(app);

	/* App's descriptor. */
	mem_alloc_allocate(app->mgr->allocator, &mem, sizeof(*app_region),
			   __alignof__(struct gxp_application_descriptor));
	app_region = mem.host_addr;
	app_region->application_id = app->application_id;
	app_region->core_count = app->core_count;
	app_region->cores_mask = app->core_list;
	app_region->threads_count = DEFAULT_APP_THREAD_COUNT;
	app_region->tcm_memory_per_bank = DEFAULT_APP_TCM_PER_BANK;
	app_region->system_memory_size = user_mem_size;
	app_region->system_memory_addr = app->user_mem.device_addr;
	app_region->doorbells_dev_addr = app->doorbells_mem.device_addr;
	app_region->sync_barriers_dev_addr = app->sync_barriers_mem.device_addr;
	app_region->semaphores_dev_addr = app->semaphores_mem.device_addr;
	app_region->cores_info_dev_addr = app->cores_mem.device_addr;

	return mem;
}

static struct app_metadata *gxp_fw_data_create_app_legacy(struct gxp_dev *gxp,
							  uint core_list)
{
	struct gxp_fw_data_manager *mgr = gxp->data_mgr;
	struct app_metadata *app;
	void *err;
	int i;

	app = kzalloc(sizeof(*app), GFP_KERNEL);
	if (!app)
		return ERR_PTR(-ENOMEM);

	/* Create resource and memory allocations for new app */
	app->mgr = mgr;
	app->application_id = DEFAULT_APP_ID;
	app->core_count = hweight_long(core_list);
	app->core_list = core_list;

	/* User doorbells */
	app->user_doorbells_count = DEFAULT_APP_USER_DOORBELL_COUNT;
	app->user_doorbells =
		kcalloc(app->user_doorbells_count, sizeof(int), GFP_KERNEL);
	if (!app->user_doorbells) {
		err = ERR_PTR(-ENOMEM);
		goto err_user_doorbells;
	}

	for (i = 0; i < app->user_doorbells_count; i++) {
		range_alloc_get_any(mgr->doorbell_allocator,
				    &app->user_doorbells[i]);
	}

	/* User sync barrier */
	app->user_barriers_count = DEFAULT_APP_USER_BARRIER_COUNT;
	app->user_barriers =
		kcalloc(app->user_barriers_count, sizeof(int), GFP_KERNEL);
	if (!app->user_barriers) {
		err = ERR_PTR(-ENOMEM);
		goto err_user_barriers;
	}

	for (i = 0; i < app->user_barriers_count; i++) {
		range_alloc_get_any(mgr->sync_barrier_allocator,
				    &app->user_barriers[i]);
	}

	/* Application region. */
	app->app_mem = init_application(app);
	for (i = 0; i < GXP_NUM_CORES; i++) {
		if (core_list & BIT(i)) {
			mgr->system_desc->app_descriptor_dev_addr[i] =
				app->app_mem.device_addr;
		}
	}

	return app;

err_user_barriers:
	for (i = 0; i < app->user_doorbells_count; i++)
		range_alloc_put(mgr->doorbell_allocator,
				app->user_doorbells[i]);
	kfree(app->user_doorbells);
err_user_doorbells:
	kfree(app);

	return err;
}

static void gxp_fw_data_destroy_app_legacy(struct gxp_dev *gxp,
					   struct app_metadata *app)
{
	struct gxp_fw_data_manager *mgr = gxp->data_mgr;
	int i;

	for (i = 0; i < app->user_doorbells_count; i++)
		range_alloc_put(mgr->doorbell_allocator,
				app->user_doorbells[i]);
	kfree(app->user_doorbells);

	for (i = 0; i < app->user_barriers_count; i++)
		range_alloc_put(mgr->sync_barrier_allocator,
				app->user_barriers[i]);
	kfree(app->user_barriers);

	mem_alloc_free(mgr->allocator, &app->user_mem);
	mem_alloc_free(mgr->allocator, &app->doorbells_mem);
	mem_alloc_free(mgr->allocator, &app->sync_barriers_mem);
	mem_alloc_free(mgr->allocator, &app->semaphores_mem);
	mem_alloc_free(mgr->allocator, &app->cores_mem);
	for (i = 0; i < app->core_count; i++) {
		mem_alloc_free(mgr->allocator, &app->core_cmd_queues_mem[i]);
		mem_alloc_free(mgr->allocator, &app->core_rsp_queues_mem[i]);
	}
	mem_alloc_free(mgr->allocator, &app->app_mem);

	kfree(app);
}

/*
 * Here assumes sys_cfg contains gxp_system_descriptor_ro in the first page and
 * gxp_system_descriptor_rw in the second page.
 */
static void set_system_cfg_region(struct gxp_dev *gxp, void *sys_cfg)
{
	struct gxp_system_descriptor_ro *des_ro = sys_cfg;
	struct gxp_system_descriptor_rw *des_rw = sys_cfg + PAGE_SIZE;
	struct gxp_core_telemetry_descriptor *descriptor =
		gxp->data_mgr->core_telemetry_mem.host_addr;
	struct telemetry_descriptor_ro *tel_ro;
	struct telemetry_descriptor_rw *tel_rw;
	struct core_telemetry_descriptor *tel_des;
	int i;

	if (gxp->debug_dump_mgr)
		des_ro->debug_dump_dev_addr = gxp->debug_dump_mgr->buf.dsp_addr;
	else
		des_ro->debug_dump_dev_addr = 0;

#define COPY_FIELDS(des, ro, rw)                                               \
	do {                                                                   \
		ro->host_status = des->host_status;                            \
		ro->buffer_addr = des->buffer_addr;                            \
		ro->buffer_size = des->buffer_size;                            \
		rw->device_status = des->device_status;                        \
		rw->data_available = des->watermark_level;                     \
	} while (0)
	for (i = 0; i < GXP_NUM_CORES; i++) {
		tel_ro = &des_ro->telemetry_desc.per_core_loggers[i];
		tel_rw = &des_rw->telemetry_desc.per_core_loggers[i];
		tel_des = &descriptor->per_core_loggers[i];
		COPY_FIELDS(tel_des, tel_ro, tel_rw);
		tel_ro = &des_ro->telemetry_desc.per_core_tracers[i];
		tel_rw = &des_rw->telemetry_desc.per_core_tracers[i];
		tel_des = &descriptor->per_core_tracers[i];
		COPY_FIELDS(tel_des, tel_ro, tel_rw);
	}
#undef COPY_FIELDS

	/* Update the global descriptors. */
	gxp->data_mgr->sys_desc_ro = des_ro;
	gxp->data_mgr->sys_desc_rw = des_rw;
}

static struct app_metadata *
_gxp_fw_data_create_app(struct gxp_dev *gxp, struct gxp_virtual_device *vd)
{
	struct app_metadata *app;
	struct gxp_host_control_region *core_cfg;
	struct gxp_job_descriptor job;
	struct gxp_vd_descriptor *vd_desc;
	int i;

	/*
	 * If we are able to know where sys_cfg's virt is on init() then we
	 * don't need this here, but to keep compatibility with
	 * !use_per_vd_config, we keep gxp_fw_data_init() doing the
	 * initialization of legacy mode, and have here copy the values to the
	 * config region.
	 */
	if (vd->vdid == 1)
		set_system_cfg_region(gxp, vd->sys_cfg.vaddr);
	app = kzalloc(sizeof(*app), GFP_KERNEL);
	if (!app)
		return ERR_PTR(-ENOMEM);

	if (!gxp_core_boot(gxp)) {
		dev_info(gxp->dev, "Skip setting VD and core CFG");
		return app;
	}
	/* Set up VD config region. */
	vd_desc = vd->vd_cfg.vaddr;
	vd_desc->application_id = DEFAULT_APP_ID;
	vd_desc->vd_is_initialized = 0;
	/* Set up core config region. */
	job.workers_count = vd->num_cores;
	for (i = 0; i < ARRAY_SIZE(job.worker_to_fw); i++) {
		/*
		 * Kernel-initiated workloads always act like the entire VD is
		 * one giant N-core job where N is the number of cores allocated
		 * to that VD.
		 * The MCU, on the other hand, can have multiple jobs dispatched
		 * to the same VD at the same time.
		 */
		if (i < job.workers_count)
			job.worker_to_fw[i] = i;
		else
			job.worker_to_fw[i] = -1;
	}
	/* Give each VD a unique HW resources slot. */
	job.hardware_resources_slot = gxp_vd_hw_slot_id(vd);
	/* Assign the same job descriptor to all cores in this VD */
	for (i = 0; i < GXP_NUM_CORES; i++) {
		core_cfg = vd->core_cfg.vaddr +
			   vd->core_cfg.size / GXP_NUM_CORES * i;
		core_cfg->job_descriptor = job;
	}

	return app;
}

static void _gxp_fw_data_destroy_app(struct gxp_dev *gxp,
				     struct app_metadata *app)
{
	kfree(app);
}

int gxp_fw_data_init(struct gxp_dev *gxp)
{
	struct gxp_fw_data_manager *mgr;
	int res;
	int i;

	mgr = devm_kzalloc(gxp->dev, sizeof(*mgr), GFP_KERNEL);
	if (!mgr)
		return -ENOMEM;
	gxp->data_mgr = mgr;

	/*
	 * TODO (b/200169232) Using memremap until devm_memremap is added to
	 * the GKI ABI
	 */
	mgr->fw_data_virt = memremap(gxp->fwdatabuf.paddr, gxp->fwdatabuf.size,
				     MEMREMAP_WC);

	if (IS_ERR_OR_NULL(mgr->fw_data_virt)) {
		dev_err(gxp->dev, "Failed to map fw data region\n");
		res = -ENODEV;
		goto err;
	}
	gxp->fwdatabuf.vaddr = mgr->fw_data_virt;

	/* Instantiate the doorbells allocator with all doorbells */
	mgr->doorbell_allocator =
		range_alloc_create(/*start=*/0, DOORBELL_COUNT);
	if (IS_ERR(mgr->doorbell_allocator)) {
		dev_err(gxp->dev, "Failed to create doorbells allocator\n");
		res = PTR_ERR(mgr->doorbell_allocator);
		mgr->doorbell_allocator = NULL;
		goto err;
	}

	/* Instantiate the sync barriers allocator with all sync barriers */
	mgr->sync_barrier_allocator =
		range_alloc_create(/*start=*/0, SYNC_BARRIER_COUNT);
	if (IS_ERR(mgr->sync_barrier_allocator)) {
		dev_err(gxp->dev, "Failed to create sync barriers allocator\n");
		res = PTR_ERR(mgr->sync_barrier_allocator);
		mgr->sync_barrier_allocator = NULL;
		goto err;
	}

	/* Allocate doorbells */

	/* Pinned: Cores wakeup doorbell */
	for (i = 0; i < GXP_NUM_WAKEUP_DOORBELLS; i++) {
		mgr->core_wakeup_doorbells[i] = DOORBELL_ID_CORE_WAKEUP(i);
		res = range_alloc_get(mgr->doorbell_allocator,
				      mgr->core_wakeup_doorbells[i]);
		if (res)
			goto err;
	}

	/* Semaphores operation doorbells */
	for (i = 0; i < GXP_NUM_CORES; i++) {
		range_alloc_get_any(mgr->doorbell_allocator,
				    &mgr->semaphore_doorbells[i]);
	}

	/* Allocate sync barriers */

	/* Pinned: UART sync barrier */
	mgr->uart_sync_barrier = SYNC_BARRIER_ID_UART;
	mgr->uart_region_barrier = SYNC_BARRIER_ID_UART;
	res = range_alloc_get(mgr->sync_barrier_allocator,
			      mgr->uart_sync_barrier);
	if (res)
		goto err;

	/* Doorbell regions for all apps */
	res = range_alloc_get_any(mgr->sync_barrier_allocator,
				  &mgr->doorbell_regions_barrier);
	if (res)
		goto err;

	/* Sync barrier regions for all apps */
	res = range_alloc_get_any(mgr->sync_barrier_allocator,
				  &mgr->sync_barrier_regions_barrier);
	if (res)
		goto err;

	/* Timer regions for all apps */
	res = range_alloc_get_any(mgr->sync_barrier_allocator,
				  &mgr->timer_regions_barrier);
	if (res)
		goto err;

	/* Watchdog regions for all apps */
	res = range_alloc_get_any(mgr->sync_barrier_allocator,
				  &mgr->watchdog_region_barrier);
	if (res)
		goto err;

	/* Semaphore regions for all apps */
	res = range_alloc_get_any(mgr->sync_barrier_allocator,
				  &mgr->semaphores_regions_barrier);
	if (res)
		goto err;

	/* Shared firmware data memory region */
	mgr->allocator =
		mem_alloc_create(gxp, mgr->fw_data_virt, gxp->fwdatabuf.daddr,
				 gxp->fwdatabuf.size);
	if (IS_ERR(mgr->allocator)) {
		dev_err(gxp->dev,
			"Failed to create the FW data memory allocator\n");
		res = PTR_ERR(mgr->allocator);
		mgr->allocator = NULL;
		goto err;
	}

	/* Populate the region with a pre-defined pattern. */
	memset(mgr->fw_data_virt, FW_DATA_DEBUG_PATTERN, gxp->fwdatabuf.size);

	/* Allocate the root system descriptor from the region */
	mem_alloc_allocate(mgr->allocator, &mgr->sys_desc_mem,
			   sizeof(struct gxp_system_descriptor),
			   __alignof__(struct gxp_system_descriptor));
	mgr->system_desc = mgr->sys_desc_mem.host_addr;

	/* Allocate the watchdog descriptor from the region */
	mgr->wdog_mem = init_watchdog(mgr);
	mgr->system_desc->watchdog_dev_addr = mgr->wdog_mem.device_addr;

	/* Allocate the descriptor for device-side core telemetry */
	mgr->core_telemetry_mem = init_core_telemetry(mgr);
	mgr->system_desc->core_telemetry_dev_addr =
		mgr->core_telemetry_mem.device_addr;

	/* Set the debug dump region parameters if available */
	mgr->debug_dump_mem = init_debug_dump(gxp);
	mgr->system_desc->debug_dump_dev_addr = mgr->debug_dump_mem.device_addr;

	return res;

err:
	range_alloc_destroy(mgr->sync_barrier_allocator);
	range_alloc_destroy(mgr->doorbell_allocator);
	devm_kfree(gxp->dev, mgr);
	return res;
}

void *gxp_fw_data_create_app(struct gxp_dev *gxp, struct gxp_virtual_device *vd)
{
	struct app_metadata *app;

	if (gxp_fw_data_use_per_vd_config(vd))
		app = _gxp_fw_data_create_app(gxp, vd);
	else
		app = gxp_fw_data_create_app_legacy(gxp, vd->core_list);

	if (IS_ERR(app))
		return app;
	app->vd = vd;

	return app;
}

void gxp_fw_data_destroy_app(struct gxp_dev *gxp, void *application)
{
	struct app_metadata *app = application;

	if (!app)
		return;
	if (gxp_fw_data_use_per_vd_config(app->vd))
		return _gxp_fw_data_destroy_app(gxp, app);
	return gxp_fw_data_destroy_app_legacy(gxp, app);
}

void gxp_fw_data_destroy(struct gxp_dev *gxp)
{
	struct gxp_fw_data_manager *mgr = gxp->data_mgr;

	mem_alloc_free(mgr->allocator, &mgr->core_telemetry_mem);
	mem_alloc_free(mgr->allocator, &mgr->wdog_mem);
	mem_alloc_free(mgr->allocator, &mgr->sys_desc_mem);
	mem_alloc_destroy(mgr->allocator);

	range_alloc_destroy(mgr->sync_barrier_allocator);
	range_alloc_destroy(mgr->doorbell_allocator);

	/* TODO (b/200169232) Remove this once we're using devm_memremap */
	if (mgr->fw_data_virt) {
		memunmap(mgr->fw_data_virt);
		mgr->fw_data_virt = NULL;
	}

	devm_kfree(gxp->dev, mgr);
	gxp->data_mgr = NULL;
}

int gxp_fw_data_set_core_telemetry_descriptors(struct gxp_dev *gxp, u8 type,
					       u32 host_status,
					       struct gxp_coherent_buf *buffers,
					       u32 per_buffer_size)
{
	struct gxp_core_telemetry_descriptor *descriptor =
		gxp->data_mgr->core_telemetry_mem.host_addr;
	struct core_telemetry_descriptor *core_descriptors;
	uint core;
	bool enable;

	if (type == GXP_TELEMETRY_TYPE_LOGGING)
		core_descriptors = descriptor->per_core_loggers;
	else if (type == GXP_TELEMETRY_TYPE_TRACING)
		core_descriptors = descriptor->per_core_tracers;
	else
		return -EINVAL;

	enable = (host_status & GXP_CORE_TELEMETRY_HOST_STATUS_ENABLED);

	if (enable) {
		/* Validate that the provided IOVAs are addressable (i.e. 32-bit) */
		for (core = 0; core < GXP_NUM_CORES; core++) {
			if (buffers && buffers[core].dsp_addr > U32_MAX &&
			    buffers[core].size == per_buffer_size)
				return -EINVAL;
		}

		for (core = 0; core < GXP_NUM_CORES; core++) {
			core_descriptors[core].host_status = host_status;
			core_descriptors[core].buffer_addr =
				(u32)buffers[core].dsp_addr;
			core_descriptors[core].buffer_size = per_buffer_size;
		}
	} else {
		for (core = 0; core < GXP_NUM_CORES; core++) {
			core_descriptors[core].host_status = host_status;
			core_descriptors[core].buffer_addr = 0;
			core_descriptors[core].buffer_size = 0;
		}
	}

	return 0;
}

static u32
gxp_fw_data_get_core_telemetry_device_status_legacy(struct gxp_dev *gxp,
						    uint core, u8 type)
{
	struct gxp_core_telemetry_descriptor *descriptor =
		gxp->data_mgr->core_telemetry_mem.host_addr;

	switch (type) {
	case GXP_TELEMETRY_TYPE_LOGGING:
		return descriptor->per_core_loggers[core].device_status;
	case GXP_TELEMETRY_TYPE_TRACING:
		return descriptor->per_core_tracers[core].device_status;
	default:
		return 0;
	}
}

static u32 _gxp_fw_data_get_core_telemetry_device_status(struct gxp_dev *gxp,
							 uint core, u8 type)
{
	struct gxp_system_descriptor_rw *des_rw = gxp->data_mgr->sys_desc_rw;

	switch (type) {
	case GXP_TELEMETRY_TYPE_LOGGING:
		return des_rw->telemetry_desc.per_core_loggers[core]
			.device_status;
	case GXP_TELEMETRY_TYPE_TRACING:
		return des_rw->telemetry_desc.per_core_tracers[core]
			.device_status;
	default:
		return 0;
	}
}

u32 gxp_fw_data_get_core_telemetry_device_status(struct gxp_dev *gxp, uint core,
						 u8 type)
{
	if (core >= GXP_NUM_CORES)
		return 0;

	if (gxp->fw_loader_mgr->core_img_cfg.config_version >=
	    FW_DATA_PROTOCOL_PER_VD_CONFIG) {
		return _gxp_fw_data_get_core_telemetry_device_status(gxp, core,
								     type);
	} else {
		return gxp_fw_data_get_core_telemetry_device_status_legacy(
			gxp, core, type);
	}
}
