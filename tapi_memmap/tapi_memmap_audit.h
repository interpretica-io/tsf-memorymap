/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief What a memory map is worth
 *
 * @defgroup tapi_memmap_audit Memory-map security posture
 * @ingroup tapi_memmap
 * @{
 *
 * The one thing a memory map says about security, from both directions:
 * memory that is writable and executable at the same time. In a binary
 * it is a @c LOAD segment with both bits - a loader that honours it
 * gives the program a region it can write code into and then run, which
 * is what an exploit wants. In a running process it is a mapping with
 * both bits, which is the same thing observed live, plus an executable
 * stack or heap.
 *
 * These are reported through
 * [tsf-cybersec](https://github.com/interpretica-io/tsf-cybersec),
 * alongside what @c tapi_binscan reports about how a binary was built;
 * this is the memory-map view, which sees the segment flags directly
 * and, for a foreign-architecture image, without running anything.
 *
 * | Finding | Severity | Read from |
 * |---|---|---|
 * | @c memmap.wx-segment | high | a @c LOAD segment that is W and X |
 * | @c memmap.exec-stack | medium | @c GNU_STACK carries the execute bit |
 * | @c memmap.wx-mapping | high | a live mapping that is W and X |
 * | @c memmap.exec-writable-stack | high | the live stack is writable and executable |
 *
 * @code
 * tapi_cybersec_report report;
 *
 * tapi_cybersec_report_init(&report);
 * CHECK_RC(tapi_memmap_audit_image(&image, "/lib/firmware/app.elf",
 *                                  &report));
 * tapi_cybersec_report_log(&report);
 * @endcode
 */

#ifndef __TSF_TAPI_MEMMAP_AUDIT_H__
#define __TSF_TAPI_MEMMAP_AUDIT_H__

#include <sys/types.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_vector.h"
#include "tapi_job.h"

#include "tapi_cybersec.h"
#include "tapi_memmap.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Audit the memory image of a binary and add what is wrong to
 * @p report.
 *
 * @param[in]  image    The image, from tapi_memmap_elf_read().
 * @param[in]  subject  What to name the findings after, e.g. the path;
 *                      must not carry anything that varies between runs.
 * @param[out] report   Report to append findings to.
 *
 * @return Status code.
 */
extern te_errno tapi_memmap_audit_image(const tapi_memmap_image *image,
                                        const char *subject,
                                        tapi_cybersec_report *report);

/**
 * Audit the memory map of a running process and add what is wrong to
 * @p report.
 *
 * @param[in]  maps     The mappings, from tapi_memmap_proc_read().
 * @param[in]  subject  What to name the findings after.
 * @param[out] report   Report to append findings to.
 *
 * @return Status code.
 */
extern te_errno tapi_memmap_audit_proc(const te_vec *maps,
                                       const char *subject,
                                       tapi_cybersec_report *report);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSF_TAPI_MEMMAP_AUDIT_H__ */

/**@} <!-- END tapi_memmap_audit --> */
