// SPDX-License-Identifier: GPL-2.0
/*
 * GXP DMA implemented via IOMMU.
 *
 * Copyright (C) 2021 Google LLC
 */

#include <linux/bits.h>
#include <linux/dma-mapping.h>
#include <linux/iommu.h>
#include <linux/platform_device.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>

#include <gcip/gcip-iommu.h>

#include "gxp-config.h"
#include "gxp-dma.h"
#include "gxp-mailbox.h"
#include "gxp-mapping.h"
#include "gxp-pm.h"
#include "gxp.h"
#include "mobile-soc.h"

#include <trace/events/gxp.h>

struct gxp_dma_iommu_manager {
	struct gxp_dma_manager dma_mgr;
	struct gcip_iommu_domain *default_domain;
};

/* Fault handler */

static int sysmmu_fault_handler(struct iommu_fault *fault, void *token)
{
	struct gxp_dev *gxp = (struct gxp_dev *)token;

	switch (fault->type) {
	case IOMMU_FAULT_DMA_UNRECOV:
		dev_err(gxp->dev, "Unrecoverable IOMMU fault!\n");
		break;
	case IOMMU_FAULT_PAGE_REQ:
		dev_err(gxp->dev, "IOMMU page request fault!\n");
		break;
	default:
		dev_err(gxp->dev, "Unexpected IOMMU fault type (%d)\n",
			fault->type);
		return -EAGAIN;
	}

	/*
	 * Normally the iommu driver should fill out the `event` struct for
	 * unrecoverable errors, and the `prm` struct for page request faults.
	 * The SysMMU driver, instead, always fills out the `event` struct.
	 *
	 * Note that the `fetch_addr` and `perm` fields are never filled out,
	 * so we skip printing them.
	 */
	dev_err(gxp->dev, "reason = %08X\n", fault->event.reason);
	dev_err(gxp->dev, "flags = %08X\n", fault->event.flags);
	dev_err(gxp->dev, "pasid = %08X\n", fault->event.pasid);
	dev_err(gxp->dev, "addr = %llX\n", fault->event.addr);

	// Tell the IOMMU driver to carry on
	return -EAGAIN;
}

#if GXP_HAS_LAP

/* No need to map CSRs when local access path exists. */

#define gxp_map_csrs(...) 0
#define gxp_unmap_csrs(...)

#else /* !GXP_HAS_LAP */

#define SYNC_BARRIERS_SIZE 0x100000

static int gxp_map_csrs(struct gxp_dev *gxp, struct iommu_domain *domain,
			struct gxp_mapped_resource *regs)
{
	int ret = iommu_map(domain, GXP_IOVA_AURORA_TOP, gxp->regs.paddr,
			    gxp->regs.size, IOMMU_READ | IOMMU_WRITE);
	if (ret)
		return ret;
	/*
	 * Firmware expects to access the sync barriers at a separate
	 * address, lower than the rest of the AURORA_TOP registers.
	 */
	ret = iommu_map(domain, GXP_IOVA_SYNC_BARRIERS,
			gxp->regs.paddr + GXP_IOVA_SYNC_BARRIERS,
			SYNC_BARRIERS_SIZE, IOMMU_READ | IOMMU_WRITE);
	if (ret) {
		iommu_unmap(domain, GXP_IOVA_AURORA_TOP, gxp->regs.size);
		return ret;
	}

	return 0;
}

static void gxp_unmap_csrs(struct gxp_dev *gxp, struct iommu_domain *domain,
			   struct gxp_mapped_resource *regs)
{
	iommu_unmap(domain, GXP_IOVA_SYNC_BARRIERS, SYNC_BARRIERS_SIZE);
	iommu_unmap(domain, GXP_IOVA_AURORA_TOP, gxp->regs.size);
}

#endif /* GXP_HAS_LAP */

/* gxp-dma.h Interface */

struct gcip_iommu_domain *gxp_iommu_get_domain_for_dev(struct gxp_dev *gxp)
{
	struct gcip_iommu_domain *gdomain = gxp->default_domain;

	if (IS_ERR_OR_NULL(gdomain)) {
		gdomain = gcip_iommu_get_domain_for_dev(gxp->dev);
		if (IS_ERR_OR_NULL(gdomain))
			return gdomain;
		gxp->default_domain = gdomain;
	}

	return gdomain;
}

int gxp_iommu_map(struct gxp_dev *gxp, struct gcip_iommu_domain *gdomain,
		  unsigned long iova, phys_addr_t paddr, size_t size, int prot)
{
	return iommu_map(gdomain->domain, iova, paddr, size, prot);
}

void gxp_iommu_unmap(struct gxp_dev *gxp, struct gcip_iommu_domain *gdomain,
		     unsigned long iova, size_t size)
{
	iommu_unmap(gdomain->domain, iova, size);
}

int gxp_dma_init(struct gxp_dev *gxp)
{
	struct gxp_dma_iommu_manager *mgr;
	int ret;

	/* Remove the limit of DMA ranges. */
	ret = dma_set_mask_and_coherent(gxp->dev, DMA_BIT_MASK(64));
	if (ret) {
		dev_err(gxp->dev, "Failed to set DMA mask\n");
		return ret;
	}

	mgr = devm_kzalloc(gxp->dev, sizeof(*mgr), GFP_KERNEL);
	if (!mgr)
		return -ENOMEM;

	mgr->default_domain = gxp_iommu_get_domain_for_dev(gxp);
	if (IS_ERR(mgr->default_domain)) {
		dev_err(gxp->dev, "Failed to find default IOMMU domain\n");
		return PTR_ERR(mgr->default_domain);
	}

	if (iommu_register_device_fault_handler(gxp->dev, sysmmu_fault_handler,
						gxp)) {
		dev_err(gxp->dev, "Failed to register iommu fault handler\n");
		return -EIO;
	}

	gxp->dma_mgr = &(mgr->dma_mgr);

	return 0;
}

void gxp_dma_exit(struct gxp_dev *gxp)
{
	if (iommu_unregister_device_fault_handler(gxp->dev))
		dev_err(gxp->dev,
			"Failed to unregister SysMMU fault handler\n");
}

#define EXT_TPU_MBX_SIZE 0x2000

void gxp_dma_init_default_resources(struct gxp_dev *gxp)
{
	unsigned int core;
	int i;

	for (i = 0; i < GXP_NUM_MAILBOXES; i++)
		gxp->mbx[i].daddr = GXP_IOVA_MAILBOX(i);
	for (core = 0; core < GXP_NUM_CORES; core++)
		gxp->fwbufs[core].daddr = GXP_IOVA_FIRMWARE(core);
}

int gxp_dma_domain_attach_device(struct gxp_dev *gxp, struct gcip_iommu_domain *gdomain,
				 uint core_list)
{
	int pasid;

	if (gdomain == gxp_iommu_get_domain_for_dev(gxp))
		return 0;

	pasid = gcip_iommu_domain_pool_attach_domain(gxp->domain_pool, gdomain);
	if (pasid < 0) {
		dev_err(gxp->dev, "Attach IOMMU domain failed: %d", pasid);
		return pasid;
	}

	gxp_soc_activate_context(gxp, gdomain, core_list);

	return 0;
}

void gxp_dma_domain_detach_device(struct gxp_dev *gxp, struct gcip_iommu_domain *gdomain,
				  uint core_list)
{
	if (gdomain == gxp_iommu_get_domain_for_dev(gxp))
		return;

	gxp_soc_deactivate_context(gxp, gdomain, core_list);
	gcip_iommu_domain_pool_detach_domain(gxp->domain_pool, gdomain);
}

int gxp_dma_map_core_resources(struct gxp_dev *gxp,
			       struct gcip_iommu_domain *gdomain,
			       uint core_list, u8 slice_index)
{
	int ret;
	uint i;
	struct iommu_domain *domain = gdomain->domain;

	if (!gxp_is_direct_mode(gxp))
		return 0;

	ret = gxp_map_csrs(gxp, domain, &gxp->regs);
	if (ret)
		goto err;

	for (i = 0; i < GXP_NUM_CORES; i++) {
		if (!(BIT(i) & core_list))
			continue;
		ret = iommu_map(domain, gxp->mbx[i].daddr,
				gxp->mbx[i].paddr +
					MAILBOX_DEVICE_INTERFACE_OFFSET,
				gxp->mbx[i].size, IOMMU_READ | IOMMU_WRITE);
		if (ret)
			goto err;
	}
	/* Only map the TPU mailboxes if they were found on probe */
	if (gxp->tpu_dev.mbx_paddr) {
		for (i = 0; i < GXP_NUM_CORES; i++) {
			if (!(BIT(i) & core_list))
				continue;
			ret = iommu_map(
				domain,
				GXP_IOVA_EXT_TPU_MBX + i * EXT_TPU_MBX_SIZE,
				gxp->tpu_dev.mbx_paddr + i * EXT_TPU_MBX_SIZE,
				EXT_TPU_MBX_SIZE, IOMMU_READ | IOMMU_WRITE);
			if (ret)
				goto err;
		}
	}
	return ret;

err:
	/*
	 * Attempt to unmap all resources.
	 * Any resource that hadn't been mapped yet will cause `iommu_unmap()`
	 * to return immediately, so its safe to try to unmap everything.
	 */
	gxp_dma_unmap_core_resources(gxp, gdomain, core_list);
	return ret;
}

void gxp_dma_unmap_core_resources(struct gxp_dev *gxp,
				  struct gcip_iommu_domain *gdomain,
				  uint core_list)
{
	uint i;
	struct iommu_domain *domain = gdomain->domain;

	if (!gxp_is_direct_mode(gxp))
		return;

	/* Only unmap the TPU mailboxes if they were found on probe */
	if (gxp->tpu_dev.mbx_paddr) {
		for (i = 0; i < GXP_NUM_CORES; i++) {
			if (!(BIT(i) & core_list))
				continue;
			iommu_unmap(domain,
				    GXP_IOVA_EXT_TPU_MBX + i * EXT_TPU_MBX_SIZE,
				    EXT_TPU_MBX_SIZE);
		}
	}
	for (i = 0; i < GXP_NUM_CORES; i++) {
		if (!(BIT(i) & core_list))
			continue;
		iommu_unmap(domain, gxp->mbx[i].daddr, gxp->mbx[i].size);
	}
	gxp_unmap_csrs(gxp, domain, &gxp->regs);
}

static inline struct sg_table *alloc_sgt_for_buffer(void *ptr, size_t size,
						    struct iommu_domain *domain,
						    dma_addr_t daddr)
{
	struct sg_table *sgt;
	ulong offset;
	uint num_ents;
	int ret;
	struct scatterlist *next;
	size_t size_in_page;
	struct page *page;
	void *va_base = ptr;

	/* Calculate the number of entries needed in the table */
	offset = offset_in_page(va_base);
	if (unlikely((size + offset) / PAGE_SIZE >= UINT_MAX - 1 ||
		     size + offset < size))
		return ERR_PTR(-EINVAL);
	num_ents = (size + offset) / PAGE_SIZE;
	if ((size + offset) % PAGE_SIZE)
		num_ents++;

	/* Allocate and setup the table for filling out */
	sgt = kmalloc(sizeof(*sgt), GFP_KERNEL);
	if (!sgt)
		return ERR_PTR(-ENOMEM);

	ret = sg_alloc_table(sgt, num_ents, GFP_KERNEL);
	if (ret) {
		kfree(sgt);
		return ERR_PTR(ret);
	}
	next = sgt->sgl;

	/*
	 * Fill in the first scatterlist entry.
	 * This is the only one which may start at a non-page-aligned address.
	 */
	size_in_page = size > (PAGE_SIZE - offset_in_page(ptr)) ?
			       PAGE_SIZE - offset_in_page(ptr) :
			       size;
	page = phys_to_page(iommu_iova_to_phys(domain, daddr));
	sg_set_page(next, page, size_in_page, offset_in_page(ptr));
	size -= size_in_page;
	ptr += size_in_page;
	next = sg_next(next);

	while (size > 0) {
		/*
		 * Fill in and link the next scatterlist entry.
		 * `ptr` is now page-aligned, so it is only necessary to check
		 * if this entire page is part of the buffer, or if the buffer
		 * ends part way through the page (which means this is the last
		 * entry in the list).
		 */
		size_in_page = size > PAGE_SIZE ? PAGE_SIZE : size;
		page = phys_to_page(iommu_iova_to_phys(
			domain, daddr + (unsigned long long)(ptr - va_base)));
		sg_set_page(next, page, size_in_page, 0);

		size -= size_in_page;
		ptr += size_in_page;
		next = sg_next(next);
	}

	return sgt;
}

#if HAS_TPU_EXT

int gxp_dma_map_tpu_buffer(struct gxp_dev *gxp,
			   struct gcip_iommu_domain *gdomain, uint core_list,
			   struct edgetpu_ext_mailbox_info *mbx_info)
{
	uint orig_core_list = core_list;
	u64 queue_iova;
	int core;
	int ret;
	int i = 0;
	struct iommu_domain *domain = gdomain->domain;

	while (core_list) {
		phys_addr_t cmdq_pa = mbx_info->mailboxes[i].cmdq_pa;
		phys_addr_t respq_pa = mbx_info->mailboxes[i++].respq_pa;

		core = ffs(core_list) - 1;
		queue_iova = GXP_IOVA_TPU_MBX_BUFFER(core);
		ret = iommu_map(domain, queue_iova, cmdq_pa,
				mbx_info->cmdq_size, IOMMU_WRITE);
		if (ret)
			goto error;
		ret = iommu_map(domain, queue_iova + mbx_info->cmdq_size,
				respq_pa, mbx_info->respq_size, IOMMU_READ);
		if (ret) {
			iommu_unmap(domain, queue_iova, mbx_info->cmdq_size);
			goto error;
		}
		core_list &= ~BIT(core);
	}
	return 0;

error:
	core_list ^= orig_core_list;
	while (core_list) {
		core = ffs(core_list) - 1;
		core_list &= ~BIT(core);
		queue_iova = GXP_IOVA_TPU_MBX_BUFFER(core);
		iommu_unmap(domain, queue_iova, mbx_info->cmdq_size);
		iommu_unmap(domain, queue_iova + mbx_info->cmdq_size,
			    mbx_info->respq_size);
	}
	return ret;
}

void gxp_dma_unmap_tpu_buffer(struct gxp_dev *gxp,
			      struct gcip_iommu_domain *gdomain,
			      struct gxp_tpu_mbx_desc mbx_desc)
{
	uint core_list = mbx_desc.phys_core_list;
	u64 queue_iova;
	int core;
	struct iommu_domain *domain = gdomain->domain;

	while (core_list) {
		core = ffs(core_list) - 1;
		core_list &= ~BIT(core);
		queue_iova = GXP_IOVA_TPU_MBX_BUFFER(core);
		iommu_unmap(domain, queue_iova, mbx_desc.cmdq_size);
		iommu_unmap(domain, queue_iova + mbx_desc.cmdq_size,
			    mbx_desc.respq_size);
	}
}

#endif /* HAS_TPU_EXT */

int gxp_dma_map_allocated_coherent_buffer(struct gxp_dev *gxp,
					  struct gxp_coherent_buf *buf,
					  struct gcip_iommu_domain *gdomain,
					  uint gxp_dma_flags)
{
	struct gxp_dma_iommu_manager *mgr = container_of(
		gxp->dma_mgr, struct gxp_dma_iommu_manager, dma_mgr);
	struct sg_table *sgt;
	ssize_t size_mapped;
	int ret = 0;
	size_t size;
	struct iommu_domain *domain = gdomain->domain;

	if (gdomain == gxp_iommu_get_domain_for_dev(gxp))
		return 0;

	size = buf->size;
	sgt = alloc_sgt_for_buffer(buf->vaddr, buf->size,
				   mgr->default_domain->domain, buf->dma_addr);
	if (IS_ERR(sgt)) {
		dev_err(gxp->dev,
			"Failed to allocate sgt for coherent buffer\n");
		return PTR_ERR(sgt);
	}

	size_mapped = iommu_map_sg(domain, buf->dsp_addr, sgt->sgl, sgt->orig_nents,
				   IOMMU_READ | IOMMU_WRITE);
	if (size_mapped != size)
		ret = size_mapped < 0 ? -EINVAL : (int)size_mapped;

	sg_free_table(sgt);
	kfree(sgt);
	return ret;
}

int gxp_dma_alloc_coherent_buf(struct gxp_dev *gxp,
			       struct gcip_iommu_domain *gdomain, size_t size,
			       gfp_t flag, uint gxp_dma_flags,
			       struct gxp_coherent_buf *buffer)
{
	void *buf;
	dma_addr_t daddr;
	int ret;

	size = size < PAGE_SIZE ? PAGE_SIZE : size;

	/* Allocate a coherent buffer in the default domain */
	buf = dma_alloc_coherent(gxp->dev, size, &daddr, flag);
	if (!buf) {
		dev_err(gxp->dev, "Failed to allocate coherent buffer\n");
		return -ENOMEM;
	}

	buffer->vaddr = buf;
	buffer->size = size;
	buffer->dma_addr = daddr;

	if (!gdomain)
		return 0;

	buffer->dsp_addr = gcip_iommu_alloc_iova(gdomain, size, 0);
	if (!buffer->dsp_addr) {
		ret = -ENOSPC;
		goto err_free_coherent;
	}
	ret = gxp_dma_map_allocated_coherent_buffer(gxp, buffer, gdomain, gxp_dma_flags);
	if (ret)
		goto err_free_iova;

	return 0;

err_free_iova:
	gcip_iommu_free_iova(gdomain, buffer->dsp_addr, size);
err_free_coherent:
	buffer->vaddr = NULL;
	buffer->size = 0;
	dma_free_coherent(gxp->dev, size, buf, daddr);
	return ret;
}

void gxp_dma_unmap_allocated_coherent_buffer(struct gxp_dev *gxp,
					     struct gcip_iommu_domain *gdomain,
					     struct gxp_coherent_buf *buf)
{
	if (gdomain == gxp_iommu_get_domain_for_dev(gxp))
		return;

	if (buf->size != iommu_unmap(gdomain->domain, buf->dsp_addr, buf->size))
		dev_warn(gxp->dev, "Failed to unmap coherent buffer\n");
}

void gxp_dma_free_coherent_buf(struct gxp_dev *gxp,
			       struct gcip_iommu_domain *gdomain,
			       struct gxp_coherent_buf *buf)
{
	if (gdomain) {
		gxp_dma_unmap_allocated_coherent_buffer(gxp, gdomain, buf);
		gcip_iommu_free_iova(gdomain, buf->dsp_addr, buf->size);
	}
	dma_free_coherent(gxp->dev, buf->size, buf->vaddr, buf->dma_addr);
}

int gxp_dma_map_iova_sgt(struct gxp_dev *gxp, struct gcip_iommu_domain *gdomain,
			 dma_addr_t iova, struct sg_table *sgt, int prot)
{
	ssize_t size_mapped;

	size_mapped = (ssize_t)iommu_map_sg(gdomain->domain, iova, sgt->sgl,
					    sgt->orig_nents, prot);
	if (size_mapped <= 0) {
		dev_err(gxp->dev, "map IOVA %pad to SG table failed: %d", &iova,
			(int)size_mapped);
		if (size_mapped == 0)
			return -EINVAL;
		return size_mapped;
	}
	dma_sync_sg_for_device(gxp->dev, sgt->sgl, sgt->orig_nents,
			       DMA_BIDIRECTIONAL);

	return 0;
}

void gxp_dma_unmap_iova_sgt(struct gxp_dev *gxp,
			    struct gcip_iommu_domain *gdomain, dma_addr_t iova,
			    struct sg_table *sgt)
{
	struct scatterlist *s;
	int i;
	size_t size = 0;

	for_each_sg (sgt->sgl, s, sgt->orig_nents, i)
		size += s->length;

	if (!iommu_unmap(gdomain->domain, iova, size))
		dev_warn(gxp->dev, "Failed to unmap sgt");
}

void gxp_dma_sync_sg_for_cpu(struct gxp_dev *gxp, struct scatterlist *sg,
			     int nents, enum dma_data_direction direction)
{
	/*
	 * Syncing is not domain specific. Just call through to DMA API.
	 *
	 * This works even for buffers not mapped via the DMA API, since the
	 * dma-iommu implementation syncs buffers by their physical address
	 * ranges, taken from the scatterlist, without using the IOVA.
	 */
	dma_sync_sg_for_cpu(gxp->dev, sg, nents, direction);
}

void gxp_dma_sync_sg_for_device(struct gxp_dev *gxp, struct scatterlist *sg,
				int nents, enum dma_data_direction direction)
{
	/*
	 * Syncing is not domain specific. Just call through to DMA API.
	 *
	 * This works even for buffers not mapped via the DMA API, since the
	 * dma-iommu implementation syncs buffers by their physical address
	 * ranges, taken from the scatterlist, without using the IOVA.
	 */
	dma_sync_sg_for_device(gxp->dev, sg, nents, direction);
}

u64 gxp_dma_encode_gcip_map_flags(uint gxp_dma_flags, unsigned long dma_attrs)
{
	enum dma_data_direction dir = gxp_dma_flags & GXP_MAP_DIR_MASK;
	bool coherent = false;
	bool restrict_iova = false;

#ifdef GXP_IS_DMA_COHERENT
	coherent = gxp_dma_flags & GXP_MAP_COHERENT;
#endif

	return gcip_iommu_encode_gcip_map_flags(dir, coherent, dma_attrs, restrict_iova);
}
