/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief The memory map of a running process
 *
 * @defgroup tapi_memmap_proc Process maps
 * @ingroup tapi_memmap
 * @{
 *
 * The mappings of a process that is running on the agent, from the
 * operating system: each range, its permissions, what backs it (a
 * file, the heap, the stack, or anonymous memory) and how much of it
 * is resident. This is necessarily the agent's own architecture,
 * because the process is running on it - unlike @ref tapi_memmap_elf,
 * which reads a file of any architecture.
 *
 * On Linux it is @c /proc/PID/maps, with the resident size added from
 * @c /proc/PID/smaps. On macOS it is @c vmmap. Windows is not covered:
 * its per-region view needs a debugger API, not a command.
 *
 * @code
 * te_vec maps = TE_VEC_INIT(tapi_memmap_mapping);
 * const tapi_memmap_mapping *m;
 *
 * CHECK_RC(tapi_memmap_proc_read(rpcs, pid, 30000, &maps));
 * TE_VEC_FOREACH(&maps, m)
 *     if ((m->perms & TAPI_MEMMAP_W) && (m->perms & TAPI_MEMMAP_X))
 *         TEST_VERDICT("A writable, executable mapping at 0x%" PRIx64,
 *                      m->start);
 * tapi_memmap_mappings_free(&maps);
 * @endcode
 */

#ifndef __TSF_TAPI_MEMMAP_PROC_H__
#define __TSF_TAPI_MEMMAP_PROC_H__

#include <sys/types.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_vector.h"
#include "tapi_job.h"
#include "rcf_rpc.h"

#include "tapi_memmap.h"

#ifdef __cplusplus
extern "C" {
#endif

/** What backs a mapping. */
typedef enum tapi_memmap_backing {
    /** A file. */
    TAPI_MEMMAP_BACK_FILE = 0,
    /** The heap. */
    TAPI_MEMMAP_BACK_HEAP,
    /** The stack. */
    TAPI_MEMMAP_BACK_STACK,
    /** The vDSO or a similar kernel-provided region. */
    TAPI_MEMMAP_BACK_VDSO,
    /** Anonymous memory (no file, no special name). */
    TAPI_MEMMAP_BACK_ANON,
} tapi_memmap_backing;

/** One mapping of a running process. */
typedef struct tapi_memmap_mapping {
    /** Its start address. */
    uint64_t start;
    /** One past its end. */
    uint64_t end;
    /** Permissions: a mask of @c TAPI_MEMMAP_R/W/X. */
    unsigned int perms;
    /** @c true when it is shared, @c false when private (copy-on-write). */
    bool shared;
    /** Offset into the backing file. */
    uint64_t offset;
    /** What backs it. */
    tapi_memmap_backing backing;
    /** The backing file's path, or the name in brackets, or @c NULL. */
    char *path;
    /** Resident bytes, or @c -1 when not known (no smaps). */
    int64_t rss;
} tapi_memmap_mapping;

/**
 * Read the memory map of a process on the agent.
 *
 * On Linux the agent's @c /proc/PID/{smaps,maps} is read directly over
 * RPC (a native @c open()/read()); macOS, having no @c /proc, runs the
 * @c vmmap tool over a job factory made from the same RPC server.
 *
 * @param[in]  rpcs         RPC server on the agent.
 * @param[in]  pid          Process id on the agent.
 * @param[in]  timeout_ms   Timeout for the macOS tool path, ms.
 * @param[out] maps         Vector of #tapi_memmap_mapping to append to;
 *                          release with tapi_memmap_mappings_free().
 *
 * @return Status code.
 * @retval TE_ENOENT        There is no such process.
 * @retval TE_EOPNOTSUPP    The agent is neither Linux nor macOS.
 */
extern te_errno tapi_memmap_proc_read(rcf_rpc_server *rpcs, pid_t pid,
                                      int timeout_ms, te_vec *maps);

/**
 * The total size and resident size of a process's mappings.
 *
 * @param[in]  maps         Mappings from tapi_memmap_proc_read().
 * @param[out] total        Sum of the mapping sizes, or @c NULL.
 * @param[out] resident     Sum of the resident sizes, or @c NULL;
 *                          counts only mappings whose RSS is known.
 */
extern void tapi_memmap_proc_totals(const te_vec *maps, uint64_t *total,
                                    uint64_t *resident);

/**
 * Spell out a backing kind.
 *
 * @param backing   The kind.
 *
 * @return A static string, never @c NULL.
 */
extern const char *tapi_memmap_backing2str(tapi_memmap_backing backing);

/**
 * Write a process's mappings into the log.
 *
 * @param maps      The mappings.
 */
extern void tapi_memmap_mappings_log(const te_vec *maps);

/**
 * Release a vector of mappings.
 *
 * @param maps      Vector of #tapi_memmap_mapping.
 */
extern void tapi_memmap_mappings_free(te_vec *maps);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSF_TAPI_MEMMAP_PROC_H__ */

/**@} <!-- END tapi_memmap_proc --> */
