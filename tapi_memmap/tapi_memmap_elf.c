/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief The memory image of an ELF binary
 *
 * The file is fetched from the agent to the engine and the bytes are
 * handed to @ref tapi_memmap_elfcore, a pure reader that carries no TE
 * dependency and is agnostic to class, byte order and machine. Keeping
 * the reader pure is what lets it be unit-tested on its own and be
 * sure, before any of this, that a riscv64 image parses the same as a
 * native one.
 */

#define TE_LGR_USER "TAPI MEMMAP"

#include "te_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "logger_api.h"
#include "te_alloc.h"
#include "te_string.h"
#include "te_vector.h"
#include "tapi_cfg_base.h"
#include "tapi_file.h"
#include "rcf_api.h"

#include "tapi_memmap.h"
#include "tapi_memmap_elf.h"
#include "tapi_memmap_elfcore.h"

/* See description in tapi_memmap.h */
const char *
tapi_memmap_machine2str(uint16_t machine)
{
    return elfcore_machine_str(machine);
}

/* See description in tapi_memmap.h */
void
tapi_memmap_perms2str(unsigned int perms, char *dest)
{
    dest[0] = (perms & TAPI_MEMMAP_R) ? 'r' : '-';
    dest[1] = (perms & TAPI_MEMMAP_W) ? 'w' : '-';
    dest[2] = (perms & TAPI_MEMMAP_X) ? 'x' : '-';
    dest[3] = '\0';
}

/** Map a program-header type to the kind this library names. */
static tapi_memmap_seg_type
memmap_seg_type(uint32_t raw)
{
    switch (raw)
    {
        case ELFCORE_PT_LOAD:
            return TAPI_MEMMAP_SEG_LOAD;
        case ELFCORE_PT_DYNAMIC:
            return TAPI_MEMMAP_SEG_DYNAMIC;
        case ELFCORE_PT_INTERP:
            return TAPI_MEMMAP_SEG_INTERP;
        case ELFCORE_PT_NOTE:
            return TAPI_MEMMAP_SEG_NOTE;
        case ELFCORE_PT_GNU_STACK:
            return TAPI_MEMMAP_SEG_GNU_STACK;
        default:
            return TAPI_MEMMAP_SEG_OTHER;
    }
}

/** Turn ELF PF_* into TAPI_MEMMAP_* permissions. */
static unsigned int
memmap_perms(uint32_t flags)
{
    unsigned int perms = 0;

    if (flags & ELFCORE_R)
        perms |= TAPI_MEMMAP_R;
    if (flags & ELFCORE_W)
        perms |= TAPI_MEMMAP_W;
    if (flags & ELFCORE_X)
        perms |= TAPI_MEMMAP_X;

    return perms;
}

/* See description in tapi_memmap_elf.h */
te_errno
tapi_memmap_elf_parse(const uint8_t *bytes, size_t len,
                      tapi_memmap_image *image)
{
    elfcore core;
    const char *err;
    unsigned i;

    memset(image, 0, sizeof(*image));
    image->segments = (te_vec)TE_VEC_INIT(tapi_memmap_seg);
    image->sections = (te_vec)TE_VEC_INIT(tapi_memmap_sec);

    err = elfcore_parse(bytes, len, &core);
    if (err != NULL)
    {
        ERROR("Not a usable ELF image: %s", err);
        return TE_RC(TE_TAPI, TE_EBADF);
    }

    image->is64 = core.is64;
    image->big_endian = core.big_endian;
    image->elf_type = core.type;
    image->machine = core.machine;
    image->entry = core.entry;

    for (i = 0; i < core.n_seg; i++)
    {
        const elfcore_seg *cs = &core.seg[i];
        tapi_memmap_seg seg = {
            .type = memmap_seg_type(cs->type),
            .raw_type = cs->type,
            .perms = memmap_perms(cs->flags),
            .offset = cs->offset,
            .vaddr = cs->vaddr,
            .paddr = cs->paddr,
            .filesz = cs->filesz,
            .memsz = cs->memsz,
            .align = cs->align,
        };

        TE_VEC_APPEND(&image->segments, seg);
    }

    for (i = 0; i < core.n_sec; i++)
    {
        const elfcore_sec *cs = &core.sec[i];
        tapi_memmap_sec sec = {
            .name = TE_STRDUP(cs->name),
            .type = cs->type,
            .flags = cs->flags,
            .addr = cs->addr,
            .offset = cs->offset,
            .size = cs->size,
        };

        TE_VEC_APPEND(&image->sections, sec);
    }

    return 0;
}

/* See description in tapi_memmap_elf.h */
te_errno
tapi_memmap_elf_read(tapi_job_factory_t *factory, const char *path,
                     int timeout_ms, tapi_memmap_image *image)
{
    const char *ta = tapi_job_factory_ta(factory);
    te_string local = TE_STRING_INIT;
    char *tmp_dir;
    uint8_t *bytes = NULL;
    long len;
    FILE *fp;
    te_errno rc;

    UNUSED(timeout_ms);

    memset(image, 0, sizeof(*image));

    if (ta == NULL)
    {
        ERROR("Cannot determine the agent behind the job factory");
        return TE_RC(TE_TAPI, TE_EINVAL);
    }

    /* The engine's own temporary directory: the file lands here. */
    tmp_dir = getenv("TE_TMP");
    tapi_file_make_custom_pathname(&local, tmp_dir != NULL ? tmp_dir : "/tmp",
                                   ".elf");

    rc = rcf_ta_get_file(ta, 0, path, local.ptr);
    if (rc != 0)
    {
        ERROR("Failed to fetch %s from TA %s: %r", path, ta, rc);
        te_string_free(&local);
        return TE_RC_GET_ERROR(rc) == TE_ENOENT ?
               TE_RC(TE_TAPI, TE_ENOENT) : rc;
    }

    fp = fopen(local.ptr, "rb");
    if (fp == NULL)
    {
        ERROR("Cannot open the fetched image %s", local.ptr);
        rc = TE_RC(TE_TAPI, TE_EIO);
        goto out;
    }

    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (len <= 0)
    {
        fclose(fp);
        ERROR("The image %s is empty", path);
        rc = TE_RC(TE_TAPI, TE_EBADF);
        goto out;
    }

    bytes = TE_ALLOC(len);
    if (fread(bytes, 1, len, fp) != (size_t)len)
    {
        fclose(fp);
        ERROR("Short read of the image %s", path);
        rc = TE_RC(TE_TAPI, TE_EIO);
        goto out;
    }
    fclose(fp);

    rc = tapi_memmap_elf_parse(bytes, (size_t)len, image);

out:
    free(bytes);
    unlink(local.ptr);
    te_string_free(&local);

    return rc;
}

/* See description in tapi_memmap_elf.h */
const tapi_memmap_sec *
tapi_memmap_section(const tapi_memmap_image *image, const char *name)
{
    const tapi_memmap_sec *sec;

    TE_VEC_FOREACH(&image->sections, sec)
    {
        if (sec->name != NULL && strcmp(sec->name, name) == 0)
            return sec;
    }

    return NULL;
}

/* See description in tapi_memmap_elf.h */
void
tapi_memmap_image_log(const tapi_memmap_image *image)
{
    const tapi_memmap_seg *seg;

    RING("%s %s image, machine %s, entry 0x%" PRIx64 ", %u segments",
         image->is64 ? "ELF64" : "ELF32",
         image->big_endian ? "big-endian" : "little-endian",
         tapi_memmap_machine2str(image->machine), image->entry,
         (unsigned)te_vec_size(&image->segments));

    TAPI_MEMMAP_FOREACH_LOAD(image, seg)
    {
        char perms[4];

        tapi_memmap_perms2str(seg->perms, perms);
        RING("  LOAD %s vaddr 0x%" PRIx64 " paddr 0x%" PRIx64
             " filesz %" PRIu64 " memsz %" PRIu64 " (bss %" PRIu64 ")",
             perms, seg->vaddr, seg->paddr, seg->filesz, seg->memsz,
             seg->memsz - seg->filesz);
    }
}

/* See description in tapi_memmap.h */
void
tapi_memmap_image_free(tapi_memmap_image *image)
{
    tapi_memmap_sec *sec;

    TE_VEC_FOREACH(&image->sections, sec)
        free(sec->name);
    te_vec_free(&image->sections);
    te_vec_free(&image->segments);
    memset(image, 0, sizeof(*image));
}
