/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/* Pure, dependency-free ELF memory-map parser core.
 * Architecture/endian/class agnostic: it reads e_ident and interprets
 * every field by the file's own class and byte order, never the host's.
 * This same file is compiled both into the TE library and into a
 * standalone unit test. */
#ifndef __TSF_TAPI_MEMMAP_ELFCORE_H__
#define __TSF_TAPI_MEMMAP_ELFCORE_H__

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define ELFCORE_MAX_SEG 128
#define ELFCORE_MAX_SEC 256

/* Segment permission flags (PF_*). */
#define ELFCORE_X 0x1
#define ELFCORE_W 0x2
#define ELFCORE_R 0x4

typedef struct elfcore_seg {
    uint32_t type;      /* p_type */
    uint32_t flags;     /* p_flags: ELFCORE_R/W/X */
    uint64_t offset;    /* p_offset */
    uint64_t vaddr;     /* p_vaddr */
    uint64_t paddr;     /* p_paddr (load address; embedded flash/RAM) */
    uint64_t filesz;    /* p_filesz */
    uint64_t memsz;     /* p_memsz (>= filesz; the excess is .bss) */
    uint64_t align;     /* p_align */
} elfcore_seg;

typedef struct elfcore_sec {
    uint32_t name_off;  /* index into shstrtab */
    char name[64];      /* resolved name, truncated */
    uint32_t type;      /* sh_type */
    uint64_t flags;     /* sh_flags */
    uint64_t addr;      /* sh_addr */
    uint64_t offset;    /* sh_offset */
    uint64_t size;      /* sh_size */
} elfcore_sec;

typedef struct elfcore {
    bool is64;
    bool big_endian;
    uint16_t type;      /* e_type: 2=EXEC, 3=DYN... */
    uint16_t machine;   /* e_machine: 243=RISC-V, 183=AArch64, 62=x86-64 */
    uint64_t entry;     /* e_entry */
    unsigned n_seg;
    elfcore_seg seg[ELFCORE_MAX_SEG];
    unsigned n_sec;
    elfcore_sec sec[ELFCORE_MAX_SEC];
} elfcore;

/* Program header types worth naming. */
#define ELFCORE_PT_LOAD    1
#define ELFCORE_PT_DYNAMIC 2
#define ELFCORE_PT_INTERP  3
#define ELFCORE_PT_NOTE    4
#define ELFCORE_PT_GNU_STACK 0x6474e551

/* Parse @p buf (@p len bytes) into @p out.
 * @return NULL on success, or a static error string. */
const char *elfcore_parse(const uint8_t *buf, size_t len, elfcore *out);

/* The machine name for an e_machine value, never NULL. */
const char *elfcore_machine_str(uint16_t machine);

#endif
