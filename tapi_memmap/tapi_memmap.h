/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief Memory maps from a test
 *
 * @defgroup tapi_memmap Memory maps (tapi_memmap)
 * @{
 *
 * Two kinds of memory map, read on a Test Agent:
 *
 * - the memory image of a **binary**, read out of the file itself:
 *   where an ELF's segments load in the address space, how much RAM
 *   they take, and - from that and the RAM the target has - how much
 *   RAM is free. This is static: it reads the file, it does not run
 *   it, so it works on a binary for **any** architecture the agent can
 *   only store and not execute - a riscv64 firmware image read on an
 *   x86 agent, say. See @ref tapi_memmap_elf and @ref tapi_memmap_ram.
 * - the memory map of a running **process**, from the operating
 *   system: the mappings, their permissions and what backs each. This
 *   is necessarily same-architecture, because the process is running.
 *   See @ref tapi_memmap_proc.
 *
 * and an audit (@ref tapi_memmap_audit) over both: a segment or a
 * mapping that is writable and executable at once, an executable stack.
 *
 * @section tapi_memmap_arch Any architecture, read not run
 *
 * The ELF reader interprets every field by the file's own class
 * (ELF32/ELF64) and byte order, taken from @c e_ident, and never by
 * the agent's. @c e_machine is kept as a fact, not acted on. So the
 * free-RAM question a firmware author asks - "does this image fit in
 * the chip's RAM, and how much is left" - is answered on whatever
 * agent is to hand, cross-built target and all.
 *
 * A segment carries two addresses, and the difference matters on an
 * embedded target: @a vaddr is where it runs, @a paddr is where it is
 * loaded from. Code copied from flash to RAM at start-up has a
 * @a paddr in flash and a @a vaddr in RAM; @ref tapi_memmap_ram lets
 * you ask the occupancy either way.
 *
 * @code
 * tapi_memmap_image image;
 *
 * CHECK_RC(tapi_memmap_elf_read(factory, "/lib/firmware/app.elf", 30000,
 *                               &image));
 * RING("%s image, entry 0x%" PRIx64,
 *      tapi_memmap_machine2str(image.machine), image.entry);
 * tapi_memmap_image_free(&image);
 * @endcode
 */

#ifndef __TSF_TAPI_MEMMAP_H__
#define __TSF_TAPI_MEMMAP_H__

#include <inttypes.h>
#include <sys/types.h>

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "te_vector.h"
#include "tapi_job.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Default timeout for one memory-map operation, ms. */
#define TAPI_MEMMAP_TIMEOUT_MS 30000

/** A permission bit of a segment or mapping. */
#define TAPI_MEMMAP_R (1u << 0)  /**< Readable. */
#define TAPI_MEMMAP_W (1u << 1)  /**< Writable. */
#define TAPI_MEMMAP_X (1u << 2)  /**< Executable. */

/** The kind of a program segment, the ones worth telling apart. */
typedef enum tapi_memmap_seg_type {
    /** Anything not named below. */
    TAPI_MEMMAP_SEG_OTHER = 0,
    /** A loadable segment: it occupies memory. */
    TAPI_MEMMAP_SEG_LOAD,
    /** The dynamic section. */
    TAPI_MEMMAP_SEG_DYNAMIC,
    /** The interpreter path. */
    TAPI_MEMMAP_SEG_INTERP,
    /** A note. */
    TAPI_MEMMAP_SEG_NOTE,
    /** The stack-permission marker (@c GNU_STACK). */
    TAPI_MEMMAP_SEG_GNU_STACK,
} tapi_memmap_seg_type;

/** One loadable (or other) segment of a binary. */
typedef struct tapi_memmap_seg {
    /** Its kind. */
    tapi_memmap_seg_type type;
    /** The raw program-header type, for a segment @a type does not name. */
    uint32_t raw_type;
    /** Permissions: a mask of @c TAPI_MEMMAP_R/W/X. */
    unsigned int perms;
    /** Offset of its bytes in the file. */
    uint64_t offset;
    /** Virtual address: where it runs. */
    uint64_t vaddr;
    /** Physical/load address: where it is loaded from. */
    uint64_t paddr;
    /** How many bytes it has in the file. */
    uint64_t filesz;
    /**
     * How many bytes it takes in memory. Never less than @a filesz;
     * the excess is zero-filled (@c .bss) - it costs RAM and no file.
     */
    uint64_t memsz;
    /** Alignment. */
    uint64_t align;
} tapi_memmap_seg;

/** One section of a binary. */
typedef struct tapi_memmap_sec {
    /** Its name, e.g. @c ".text", @c ".bss". */
    char *name;
    /** The raw section type. */
    uint32_t type;
    /** Its flags. */
    uint64_t flags;
    /** Its address, or @c 0 when it is not allocated. */
    uint64_t addr;
    /** Its offset in the file. */
    uint64_t offset;
    /** Its size. */
    uint64_t size;
} tapi_memmap_sec;

/** The memory image of a binary. */
typedef struct tapi_memmap_image {
    /** @c true for ELF64, @c false for ELF32. */
    bool is64;
    /** @c true for big-endian. */
    bool big_endian;
    /** The ELF type: 2 = executable, 3 = shared object/PIE. */
    uint16_t elf_type;
    /** The machine (@c e_machine), e.g. 243 for RISC-V. */
    uint16_t machine;
    /** The entry point. */
    uint64_t entry;
    /** Vector of #tapi_memmap_seg, in file order. */
    te_vec segments;
    /** Vector of #tapi_memmap_sec, in file order. */
    te_vec sections;
} tapi_memmap_image;

/**
 * Spell out a machine (@c e_machine).
 *
 * @param machine   The value.
 *
 * @return A static string, never @c NULL (@c "unknown" for one it does
 *         not name).
 */
extern const char *tapi_memmap_machine2str(uint16_t machine);

/**
 * Write @p perms as @c "rwx".
 *
 * @param[in]  perms    A mask of @c TAPI_MEMMAP_R/W/X.
 * @param[out] dest     A buffer of at least 4 bytes.
 */
extern void tapi_memmap_perms2str(unsigned int perms, char *dest);

/**
 * Iterate the loadable segments of an image.
 *
 * @param image_    The @c tapi_memmap_image pointer.
 * @param seg_      A @c const @c tapi_memmap_seg pointer, set each turn.
 */
#define TAPI_MEMMAP_FOREACH_LOAD(image_, seg_)                              \
    for (size_t tapi_memmap_i_ = 0;                                        \
         tapi_memmap_i_ < te_vec_size(&(image_)->segments) &&              \
         (((seg_) = te_vec_get((te_vec *)&(image_)->segments,              \
                               tapi_memmap_i_)) != NULL || true);          \
         tapi_memmap_i_++)                                                 \
        if ((seg_)->type == TAPI_MEMMAP_SEG_LOAD)

/**
 * Release an image.
 *
 * @param image     The image.
 */
extern void tapi_memmap_image_free(tapi_memmap_image *image);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSF_TAPI_MEMMAP_H__ */

/**@} <!-- END tapi_memmap --> */
