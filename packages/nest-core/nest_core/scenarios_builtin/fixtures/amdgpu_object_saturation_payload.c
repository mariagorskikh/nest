/*
 * Source: torvalds/linux drivers/gpu/drm/amd/amdgpu/amdgpu_object.c
 * Retrieved from:
 * https://raw.githubusercontent.com/torvalds/linux/master/drivers/gpu/drm/amd/amdgpu/amdgpu_object.c
 * Purpose: deterministic code-shaped context-saturation payload for memory
 * fusion tests.
 *
 * Copyright 2009 Jerome Glisse.
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT.
 */

#include "amdgpu.h"
#include "amdgpu_trace.h"
#include "amdgpu_amdkfd.h"
#include "amdgpu_vram_mgr.h"
#include "amdgpu_vm.h"
#include "amdgpu_dma_buf.h"

/*
 * This fixture is intentionally not valid fusion_report JSON. It looks like a
 * plausible graphics-driver source file, but it has no node/basis restriction
 * map into the calculator task.
 */

static void amdgpu_bo_destroy(struct ttm_buffer_object *tbo)
{
	struct amdgpu_bo *bo = ttm_to_amdgpu_bo(tbo);

	amdgpu_bo_kunmap(bo);

	if (drm_gem_is_imported(&bo->tbo.base))
		drm_prime_gem_destroy(&bo->tbo.base, bo->tbo.sg);
	drm_gem_object_release(&bo->tbo.base);
	amdgpu_bo_unref(&bo->parent);
	kvfree(bo);
}

bool amdgpu_bo_is_amdgpu_bo(struct ttm_buffer_object *bo)
{
	if (bo->destroy == &amdgpu_bo_destroy)
		return true;

	return false;
}

void amdgpu_bo_placement_from_domain(struct amdgpu_bo *abo, u32 domain)
{
	struct amdgpu_device *adev = amdgpu_ttm_adev(abo->tbo.bdev);
	struct ttm_placement *placement = &abo->placement;
	struct ttm_place *places = abo->placements;
	u64 flags = abo->flags;
	u32 c = 0;

	if (domain & AMDGPU_GEM_DOMAIN_VRAM) {
		unsigned int visible_pfn = adev->gmc.visible_vram_size >> PAGE_SHIFT;
		int8_t mem_id = KFD_XCP_MEM_ID(adev, abo->xcp_id);

		if (adev->gmc.mem_partitions && mem_id >= 0) {
			places[c].fpfn = adev->gmc.mem_partitions[mem_id].range.fpfn;
			places[c].lpfn = adev->gmc.mem_partitions[mem_id].range.lpfn + 1;
		} else {
			places[c].fpfn = 0;
			places[c].lpfn = 0;
		}

		places[c].mem_type = TTM_PL_VRAM;
		places[c].flags = 0;
		if (flags & AMDGPU_GEM_CREATE_CPU_ACCESS_REQUIRED)
			places[c].lpfn = min_not_zero(places[c].lpfn, visible_pfn);
		else
			places[c].flags |= TTM_PL_FLAG_TOPDOWN;
		c++;
	}

	if (domain & AMDGPU_GEM_DOMAIN_GTT) {
		places[c].fpfn = 0;
		places[c].lpfn = 0;
		places[c].mem_type = abo->flags & AMDGPU_GEM_CREATE_PREEMPTIBLE ?
			AMDGPU_PL_PREEMPT : TTM_PL_TT;
		places[c].flags = 0;
		c++;
	}

	if (!c) {
		places[c].fpfn = 0;
		places[c].lpfn = 0;
		places[c].mem_type = TTM_PL_SYSTEM;
		places[c].flags = 0;
		c++;
	}

	BUG_ON(c > AMDGPU_BO_MAX_PLACEMENTS);
	placement->num_placement = c;
	placement->placement = places;
}

int amdgpu_bo_create_reserved(struct amdgpu_device *adev,
			      unsigned long size,
			      int align,
			      u32 domain,
			      struct amdgpu_bo **bo_ptr,
			      u64 *gpu_addr,
			      void **cpu_addr)
{
	struct amdgpu_bo_param bp;
	bool free = false;
	int r;

	if (!size) {
		amdgpu_bo_unref(bo_ptr);
		return 0;
	}

	memset(&bp, 0, sizeof(bp));
	bp.size = size;
	bp.byte_align = align;
	bp.domain = domain;
	bp.flags = cpu_addr ? AMDGPU_GEM_CREATE_CPU_ACCESS_REQUIRED :
		AMDGPU_GEM_CREATE_NO_CPU_ACCESS;
	bp.flags |= AMDGPU_GEM_CREATE_VRAM_CONTIGUOUS;
	bp.type = ttm_bo_type_kernel;
	bp.resv = NULL;
	bp.bo_ptr_size = sizeof(struct amdgpu_bo);

	if (!*bo_ptr) {
		r = amdgpu_bo_create(adev, &bp, bo_ptr);
		if (r) {
			dev_err(adev->dev,
				"(%d) failed to allocate kernel bo\n", r);
			return r;
		}
		free = true;
	}

	r = amdgpu_bo_reserve(*bo_ptr, false);
	if (r)
		goto error_free;

	r = amdgpu_bo_pin(*bo_ptr, domain);
	if (r)
		goto error_unreserve;

	if (gpu_addr)
		*gpu_addr = amdgpu_bo_gpu_offset(*bo_ptr);

	return 0;

error_unreserve:
	amdgpu_bo_unreserve(*bo_ptr);
error_free:
	if (free)
		amdgpu_bo_unref(bo_ptr);
	return r;
}
