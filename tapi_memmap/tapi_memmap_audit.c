/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief What a memory map is worth
 */

#define TE_LGR_USER "TAPI MEMMAP"

#include "te_config.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "logger_api.h"
#include "te_string.h"
#include "te_vector.h"

#include "tapi_memmap.h"
#include "tapi_memmap_proc.h"
#include "tapi_memmap_audit.h"

/* See description in tapi_memmap_audit.h */
te_errno
tapi_memmap_audit_image(const tapi_memmap_image *image, const char *subject,
                        tapi_cybersec_report *report)
{
    const tapi_memmap_seg *seg;
    unsigned int wx = 0;
    size_t i;

    for (i = 0; i < te_vec_size(&image->segments); i++)
    {
        seg = te_vec_get((te_vec *)&image->segments, i);

        if (seg->type == TAPI_MEMMAP_SEG_LOAD &&
            (seg->perms & TAPI_MEMMAP_W) && (seg->perms & TAPI_MEMMAP_X))
        {
            wx++;
        }

        if (seg->type == TAPI_MEMMAP_SEG_GNU_STACK &&
            (seg->perms & TAPI_MEMMAP_X))
        {
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_MEDIUM,
                                     "memmap.exec-stack", subject,
                                     "The stack is marked executable "
                                     "(GNU_STACK has the execute bit)");
        }
    }

    /*
     * One finding for the image, not one per segment: the count is in
     * the detail, but the verdict must not carry a number that varies,
     * so the subject is the image and the check is stable.
     */
    if (wx != 0)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
                                 "memmap.wx-segment", subject,
                                 "%u loadable segment(s) are writable and "
                                 "executable at once", wx);
    }

    return 0;
}

/* See description in tapi_memmap_audit.h */
te_errno
tapi_memmap_audit_proc(const te_vec *maps, const char *subject,
                       tapi_cybersec_report *report)
{
    const tapi_memmap_mapping *m;
    unsigned int wx = 0;

    TE_VEC_FOREACH(maps, m)
    {
        bool w = (m->perms & TAPI_MEMMAP_W) != 0;
        bool x = (m->perms & TAPI_MEMMAP_X) != 0;

        if (w && x && m->backing == TAPI_MEMMAP_BACK_STACK)
        {
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
                                     "memmap.exec-writable-stack", subject,
                                     "The process stack is writable and "
                                     "executable");
        }
        else if (w && x)
        {
            wx++;
        }
    }

    if (wx != 0)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
                                 "memmap.wx-mapping", subject,
                                 "%u mapping(s) are writable and executable "
                                 "at once", wx);
    }

    return 0;
}
