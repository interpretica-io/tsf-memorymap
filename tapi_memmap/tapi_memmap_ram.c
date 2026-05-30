/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief RAM occupancy and free space
 *
 * Occupancy is the union of the loadable segments' memory ranges,
 * clipped to the regions, so shared pages count once and @c .bss - the
 * part of a segment beyond its file bytes - counts, because it takes
 * RAM. The spans, free and used, are produced by sweeping the region
 * from its base and emitting each gap and each run of occupancy.
 */

#define TE_LGR_USER "TAPI MEMMAP"

#include "te_config.h"

#include <stdlib.h>
#include <string.h>

#include "logger_api.h"
#include "te_string.h"
#include "te_vector.h"

#include "tapi_memmap.h"
#include "tapi_memmap_ram.h"

/** One occupied interval, clipped to a region. */
typedef struct ram_interval {
    uint64_t a;
    uint64_t b;
} ram_interval;

/** Order intervals by start. */
static int
ram_interval_cmp(const void *x, const void *y)
{
    const ram_interval *ix = x;
    const ram_interval *iy = y;

    if (ix->a < iy->a)
        return -1;
    if (ix->a > iy->a)
        return 1;
    return 0;
}

/** Append a span to the usage. */
static void
ram_span(tapi_memmap_usage *usage, uint64_t start, uint64_t end, bool free)
{
    tapi_memmap_span span = { .start = start, .end = end, .free = free };

    if (end > start)
        TE_VEC_APPEND(&usage->spans, span);
}

/* See description in tapi_memmap_ram.h */
te_errno
tapi_memmap_ram_usage(const tapi_memmap_image *image,
                      const tapi_memmap_region *regions, size_t n_regions,
                      tapi_memmap_by by, tapi_memmap_usage *usage)
{
    te_vec intervals = TE_VEC_INIT(ram_interval);
    const tapi_memmap_seg *seg;
    ram_interval *iv;
    size_t i;
    size_t r;
    te_errno rc = 0;

    memset(usage, 0, sizeof(*usage));
    usage->spans = (te_vec)TE_VEC_INIT(tapi_memmap_span);
    usage->fits = true;

    for (r = 0; r < n_regions; r++)
    {
        if (regions[r].size == 0)
        {
            ERROR("RAM region %zu has zero size", r);
            rc = TE_RC(TE_TAPI, TE_EINVAL);
            goto out;
        }
        usage->total += regions[r].size;

        for (i = 0; i < r; i++)
        {
            uint64_t a1 = regions[r].base;
            uint64_t b1 = regions[r].base + regions[r].size;
            uint64_t a2 = regions[i].base;
            uint64_t b2 = regions[i].base + regions[i].size;

            if (a1 < b2 && a2 < b1)
            {
                ERROR("RAM regions %zu and %zu overlap", i, r);
                rc = TE_RC(TE_TAPI, TE_EINVAL);
                goto out;
            }
        }
    }

    /*
     * Every loadable segment's memory range, and how much of it falls
     * outside the regions. A segment placed by paddr or vaddr per the
     * caller; memsz, so .bss is counted.
     */
    TAPI_MEMMAP_FOREACH_LOAD(image, seg)
    {
        uint64_t a = by == TAPI_MEMMAP_BY_PADDR ? seg->paddr : seg->vaddr;
        uint64_t b = a + seg->memsz;
        uint64_t inside = 0;

        if (seg->memsz == 0)
            continue;

        for (r = 0; r < n_regions; r++)
        {
            uint64_t ra = regions[r].base;
            uint64_t rb = regions[r].base + regions[r].size;
            uint64_t ca = a > ra ? a : ra;
            uint64_t cb = b < rb ? b : rb;

            if (ca < cb)
            {
                ram_interval clip = { .a = ca, .b = cb };

                TE_VEC_APPEND(&intervals, clip);
                inside += cb - ca;
            }
        }

        if (inside < seg->memsz)
        {
            usage->fits = false;
            usage->overflow += seg->memsz - inside;
        }
    }

    if (te_vec_size(&intervals) > 1)
    {
        qsort(te_vec_get(&intervals, 0), te_vec_size(&intervals),
              sizeof(ram_interval), ram_interval_cmp);
    }

    /*
     * Sweep each region, emitting free gaps and used runs. The
     * intervals are sorted across all regions; a region's sweep only
     * looks at the intervals that fall in it, which is what the
     * clipping above guarantees.
     */
    for (r = 0; r < n_regions; r++)
    {
        uint64_t base = regions[r].base;
        uint64_t end = regions[r].base + regions[r].size;
        uint64_t cursor = base;

        TE_VEC_FOREACH(&intervals, iv)
        {
            uint64_t a = iv->a;
            uint64_t b = iv->b;

            if (b <= base || a >= end)
                continue;

            if (a > cursor)
            {
                ram_span(usage, cursor, a, true);
                usage->free += a - cursor;
            }
            if (a < cursor)
                usage->overlap = true;

            if (b > cursor)
            {
                uint64_t used_from = a > cursor ? a : cursor;

                ram_span(usage, used_from, b, false);
                usage->used += b - used_from;
                cursor = b;
            }
        }

        if (cursor < end)
        {
            ram_span(usage, cursor, end, true);
            usage->free += end - cursor;
        }
    }

out:
    te_vec_free(&intervals);
    if (rc != 0)
        tapi_memmap_usage_free(usage);

    return rc;
}

/* See description in tapi_memmap_ram.h */
bool
tapi_memmap_ram_largest_free(const tapi_memmap_usage *usage, uint64_t *start,
                             uint64_t *size)
{
    const tapi_memmap_span *span;
    uint64_t best_start = 0;
    uint64_t best_size = 0;

    TE_VEC_FOREACH(&usage->spans, span)
    {
        if (span->free && span->end - span->start > best_size)
        {
            best_size = span->end - span->start;
            best_start = span->start;
        }
    }

    if (best_size == 0)
        return false;

    if (start != NULL)
        *start = best_start;
    if (size != NULL)
        *size = best_size;

    return true;
}

/* See description in tapi_memmap_ram.h */
void
tapi_memmap_usage_log(const tapi_memmap_usage *usage)
{
    const tapi_memmap_span *span;

    RING("RAM usage: %" PRIu64 " of %" PRIu64 " bytes used, %" PRIu64
         " free%s%s", usage->used, usage->total, usage->free,
         usage->fits ? "" : " (does not fit)",
         usage->overlap ? " (segments overlap)" : "");

    TE_VEC_FOREACH(&usage->spans, span)
    {
        RING("  %s [0x%" PRIx64 "..0x%" PRIx64 "] %" PRIu64 " bytes",
             span->free ? "free" : "used", span->start, span->end,
             span->end - span->start);
    }
}

/* See description in tapi_memmap_ram.h */
void
tapi_memmap_usage_free(tapi_memmap_usage *usage)
{
    te_vec_free(&usage->spans);
    memset(usage, 0, sizeof(*usage));
}
