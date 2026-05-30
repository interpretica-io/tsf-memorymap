/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief The memory image of an ELF binary
 *
 * @defgroup tapi_memmap_elf ELF images
 * @ingroup tapi_memmap
 * @{
 *
 * Reading a binary's memory image out of the file. The file is on the
 * agent; it is fetched to the engine and parsed there, by a reader
 * that is agnostic to class, byte order and machine - so a riscv64
 * image is read the same on any agent, whether or not the agent could
 * run it.
 *
 * @code
 * tapi_memmap_image image;
 * const tapi_memmap_seg *seg;
 *
 * CHECK_RC(tapi_memmap_elf_read(factory, "/lib/firmware/app.elf", 30000,
 *                               &image));
 * TAPI_MEMMAP_FOREACH_LOAD(&image, seg)
 *     RING("LOAD vaddr 0x%" PRIx64 " memsz %" PRIu64,
 *          seg->vaddr, seg->memsz);
 * tapi_memmap_image_free(&image);
 * @endcode
 */

#ifndef __TSF_TAPI_MEMMAP_ELF_H__
#define __TSF_TAPI_MEMMAP_ELF_H__

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "te_vector.h"
#include "tapi_job.h"

#include "tapi_memmap.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Read the memory image of an ELF file that is on the agent.
 *
 * @param[in]  factory      Job factory, for the agent the file is on.
 * @param[in]  path         Path to the ELF file on the agent.
 * @param[in]  timeout_ms   Timeout, ms.
 * @param[out] image        The image; release with
 *                          tapi_memmap_image_free().
 *
 * @return Status code.
 * @retval TE_ENOENT        There is no such file.
 * @retval TE_EBADF         The file is not an ELF, or is truncated.
 */
extern te_errno tapi_memmap_elf_read(tapi_job_factory_t *factory,
                                     const char *path, int timeout_ms,
                                     tapi_memmap_image *image);

/**
 * Parse the memory image from ELF bytes already in memory.
 *
 * For a test that has the bytes itself - built them, or read them
 * another way - rather than a file on the agent.
 *
 * @param[in]  bytes        The ELF file's bytes.
 * @param[in]  len          How many.
 * @param[out] image        The image; release with
 *                          tapi_memmap_image_free().
 *
 * @return Status code.
 * @retval TE_EBADF         Not an ELF, or truncated.
 */
extern te_errno tapi_memmap_elf_parse(const uint8_t *bytes, size_t len,
                                      tapi_memmap_image *image);

/**
 * Find a section by name.
 *
 * @param image     The image.
 * @param name      Section name, e.g. @c ".bss".
 *
 * @return The section, or @c NULL.
 */
extern const tapi_memmap_sec *tapi_memmap_section(
                                    const tapi_memmap_image *image,
                                    const char *name);

/**
 * Write an image into the log, one line per loadable segment.
 *
 * @param image     The image.
 */
extern void tapi_memmap_image_log(const tapi_memmap_image *image);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSF_TAPI_MEMMAP_ELF_H__ */

/**@} <!-- END tapi_memmap_elf --> */
