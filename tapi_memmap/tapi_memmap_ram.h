/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief RAM occupancy and free space
 *
 * @defgroup tapi_memmap_ram RAM layout
 * @ingroup tapi_memmap
 * @{
 *
 * The question a firmware author asks of an image: given the RAM the
 * target has, how much does this image take and how much is left, and
 * does it fit. The image contributes the loadable segments; the target
 * contributes the RAM regions, which the file does not know - a linker
 * script does, and so does the chip's data sheet, so the caller gives
 * them.
 *
 * Occupancy is the union of the loadable segments' memory ranges - so
 * two segments that share a page are not counted twice, and the
 * @c .bss part of a segment (its @a memsz beyond its @a filesz) counts,
 * because it takes RAM. Whether a segment counts against a region is
 * decided by its @a vaddr or its @a paddr, the caller's choice: on a
 * target that copies from flash to RAM, @a vaddr is what sits in RAM
 * once running and @a paddr is what sits in flash.
 *
 * @code
 * tapi_memmap_region ram = { .base = 0x80000000, .size = 512 * 1024 };
 * tapi_memmap_usage usage;
 *
 * CHECK_RC(tapi_memmap_ram_usage(&image, &ram, 1, TAPI_MEMMAP_BY_VADDR,
 *                                &usage));
 * if (!usage.fits)
 *     TEST_VERDICT("The image overflows RAM by %" PRIu64 " bytes",
 *                  usage.overflow);
 * RING("%" PRIu64 " of %" PRIu64 " bytes free",
 *      usage.free, usage.total);
 * tapi_memmap_usage_free(&usage);
 * @endcode
 */

#ifndef __TSF_TAPI_MEMMAP_RAM_H__
#define __TSF_TAPI_MEMMAP_RAM_H__

#include "te_defs.h"
#include "te_errno.h"
#include "te_vector.h"

#include "tapi_memmap.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Which address of a segment places it. */
typedef enum tapi_memmap_by {
    /** By where it runs (@a vaddr): what is in RAM once running. */
    TAPI_MEMMAP_BY_VADDR = 0,
    /** By where it loads from (@a paddr): what is in flash/ROM. */
    TAPI_MEMMAP_BY_PADDR,
} tapi_memmap_by;

/** A region of the target's address space. */
typedef struct tapi_memmap_region {
    /** Its base address. */
    uint64_t base;
    /** Its size in bytes. */
    uint64_t size;
    /** A name for the log, e.g. @c "RAM", @c "FLASH"; may be @c NULL. */
    const char *name;
} tapi_memmap_region;

/** A free or used span within the regions. */
typedef struct tapi_memmap_span {
    /** Its start. */
    uint64_t start;
    /** One past its end. */
    uint64_t end;
    /** @c true when it is free, @c false when it is used. */
    bool free;
} tapi_memmap_span;

/** What an image takes of a set of regions. */
typedef struct tapi_memmap_usage {
    /** The total size of the regions. */
    uint64_t total;
    /** How much of it the image's segments take. */
    uint64_t used;
    /** How much is free. */
    uint64_t free;
    /** @c true when every counted segment fell inside a region. */
    bool fits;
    /**
     * When it does not fit, how many bytes of segment fell outside the
     * regions; @c 0 when it fits.
     */
    uint64_t overflow;
    /**
     * @c true when two segments overlapped each other - an image that
     * cannot be right, whatever the RAM.
     */
    bool overlap;
    /**
     * The spans, free and used, in address order, covering the regions
     * with no gaps. A vector of #tapi_memmap_span.
     */
    te_vec spans;
} tapi_memmap_usage;

/**
 * Work out what @p image takes of @p regions.
 *
 * @param[in]  image        The image.
 * @param[in]  regions      The regions.
 * @param[in]  n_regions    How many.
 * @param[in]  by           Place a segment by its @a vaddr or @a paddr.
 * @param[out] usage        The result; release with
 *                          tapi_memmap_usage_free().
 *
 * @return Status code.
 * @retval TE_EINVAL        A region has zero size, or the regions
 *                          overlap each other.
 */
extern te_errno tapi_memmap_ram_usage(const tapi_memmap_image *image,
                                      const tapi_memmap_region *regions,
                                      size_t n_regions, tapi_memmap_by by,
                                      tapi_memmap_usage *usage);

/**
 * The largest free span in a computed usage - where a heap or a buffer
 * of a given size could go.
 *
 * @param[in]  usage        A usage from tapi_memmap_ram_usage().
 * @param[out] start        The span's start, or @c NULL.
 * @param[out] size         The span's size, or @c NULL.
 *
 * @return @c true when there is any free span.
 */
extern bool tapi_memmap_ram_largest_free(const tapi_memmap_usage *usage,
                                         uint64_t *start, uint64_t *size);

/**
 * Write a usage into the log, one line per span.
 *
 * @param usage     The usage.
 */
extern void tapi_memmap_usage_log(const tapi_memmap_usage *usage);

/**
 * Release a usage.
 *
 * @param usage     The usage.
 */
extern void tapi_memmap_usage_free(tapi_memmap_usage *usage);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSF_TAPI_MEMMAP_RAM_H__ */

/**@} <!-- END tapi_memmap_ram --> */
