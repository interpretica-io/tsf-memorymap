/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
#include "tapi_memmap_elfcore.h"
#include <string.h>

/* Endian-aware readers over a bounds-checked cursor. */
static uint16_t rd16(const uint8_t *p, bool be)
{
    return be ? (uint16_t)((p[0] << 8) | p[1])
              : (uint16_t)((p[1] << 8) | p[0]);
}
static uint32_t rd32(const uint8_t *p, bool be)
{
    return be ? ((uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
                 (uint32_t)p[2] << 8 | p[3])
              : ((uint32_t)p[3] << 24 | (uint32_t)p[2] << 16 |
                 (uint32_t)p[1] << 8 | p[0]);
}
static uint64_t rd64(const uint8_t *p, bool be)
{
    uint64_t hi, lo;

    if (be)
    {
        hi = rd32(p, true);
        lo = rd32(p + 4, true);
    }
    else
    {
        lo = rd32(p, false);
        hi = rd32(p + 4, false);
    }
    return (hi << 32) | lo;
}

const char *
elfcore_machine_str(uint16_t machine)
{
    switch (machine)
    {
        case 3:   return "x86";
        case 8:   return "MIPS";
        case 20:  return "PowerPC";
        case 21:  return "PowerPC64";
        case 40:  return "ARM";
        case 62:  return "x86-64";
        case 183: return "AArch64";
        case 224: return "AMDGPU";
        case 243: return "RISC-V";
        case 258: return "LoongArch";
        default:  return "unknown";
    }
}

const char *
elfcore_parse(const uint8_t *buf, size_t len, elfcore *out)
{
    bool be;
    bool is64;
    uint64_t phoff, shoff;
    uint16_t phentsize, phnum, shentsize, shnum, shstrndx;
    const uint8_t *sh_str_hdr;
    uint64_t shstr_off = 0;
    uint64_t shstr_size = 0;
    unsigned i;

    memset(out, 0, sizeof(*out));

    if (len < 64 || buf[0] != 0x7f || buf[1] != 'E' || buf[2] != 'L' ||
        buf[3] != 'F')
    {
        return "not an ELF file";
    }

    if (buf[4] == 1)
        is64 = false;
    else if (buf[4] == 2)
        is64 = true;
    else
        return "bad EI_CLASS";

    if (buf[5] == 1)
        be = false;
    else if (buf[5] == 2)
        be = true;
    else
        return "bad EI_DATA";

    out->is64 = is64;
    out->big_endian = be;
    out->type = rd16(buf + 16, be);
    out->machine = rd16(buf + 18, be);

    if (is64)
    {
        if (len < 64)
            return "truncated ELF64 header";
        out->entry = rd64(buf + 24, be);
        phoff = rd64(buf + 32, be);
        shoff = rd64(buf + 40, be);
        phentsize = rd16(buf + 54, be);
        phnum = rd16(buf + 56, be);
        shentsize = rd16(buf + 58, be);
        shnum = rd16(buf + 60, be);
        shstrndx = rd16(buf + 62, be);
    }
    else
    {
        if (len < 52)
            return "truncated ELF32 header";
        out->entry = rd32(buf + 24, be);
        phoff = rd32(buf + 28, be);
        shoff = rd32(buf + 32, be);
        phentsize = rd16(buf + 42, be);
        phnum = rd16(buf + 44, be);
        shentsize = rd16(buf + 46, be);
        shnum = rd16(buf + 48, be);
        shstrndx = rd16(buf + 50, be);
    }

    /* Program headers. */
    for (i = 0; i < phnum && out->n_seg < ELFCORE_MAX_SEG; i++)
    {
        uint64_t off = phoff + (uint64_t)i * phentsize;
        const uint8_t *p = buf + off;
        elfcore_seg *s = &out->seg[out->n_seg];

        if (off + phentsize > len || phentsize < (is64 ? 56 : 32))
            break;

        if (is64)
        {
            s->type = rd32(p + 0, be);
            s->flags = rd32(p + 4, be);
            s->offset = rd64(p + 8, be);
            s->vaddr = rd64(p + 16, be);
            s->paddr = rd64(p + 24, be);
            s->filesz = rd64(p + 32, be);
            s->memsz = rd64(p + 40, be);
            s->align = rd64(p + 48, be);
        }
        else
        {
            s->type = rd32(p + 0, be);
            s->offset = rd32(p + 4, be);
            s->vaddr = rd32(p + 8, be);
            s->paddr = rd32(p + 12, be);
            s->filesz = rd32(p + 16, be);
            s->memsz = rd32(p + 20, be);
            s->flags = rd32(p + 24, be);
            s->align = rd32(p + 28, be);
        }
        out->n_seg++;
    }

    /* Section headers, and their names from the shstrtab section. */
    if (shnum != 0 && shstrndx < shnum &&
        shoff + (uint64_t)shstrndx * shentsize + shentsize <= len &&
        shentsize >= (is64 ? 64 : 40))
    {
        sh_str_hdr = buf + shoff + (uint64_t)shstrndx * shentsize;
        if (is64)
        {
            shstr_off = rd64(sh_str_hdr + 24, be);
            shstr_size = rd64(sh_str_hdr + 32, be);
        }
        else
        {
            shstr_off = rd32(sh_str_hdr + 16, be);
            shstr_size = rd32(sh_str_hdr + 20, be);
        }
        if (shstr_off > len || shstr_off + shstr_size > len)
        {
            shstr_off = 0;
            shstr_size = 0;
        }
    }

    for (i = 0; i < shnum && out->n_sec < ELFCORE_MAX_SEC; i++)
    {
        uint64_t off = shoff + (uint64_t)i * shentsize;
        const uint8_t *p = buf + off;
        elfcore_sec *s = &out->sec[out->n_sec];

        if (shentsize < (is64 ? 64 : 40) || off + shentsize > len)
            break;

        s->name_off = rd32(p + 0, be);
        if (is64)
        {
            s->type = rd32(p + 4, be);
            s->flags = rd64(p + 8, be);
            s->addr = rd64(p + 16, be);
            s->offset = rd64(p + 24, be);
            s->size = rd64(p + 32, be);
        }
        else
        {
            s->type = rd32(p + 4, be);
            s->flags = rd32(p + 8, be);
            s->addr = rd32(p + 12, be);
            s->offset = rd32(p + 16, be);
            s->size = rd32(p + 20, be);
        }

        s->name[0] = '\0';
        if (shstr_size != 0 && s->name_off < shstr_size)
        {
            const char *nm = (const char *)buf + shstr_off + s->name_off;
            size_t max = shstr_size - s->name_off;
            size_t n = 0;

            while (n < max && n < sizeof(s->name) - 1 && nm[n] != '\0')
            {
                s->name[n] = nm[n];
                n++;
            }
            s->name[n] = '\0';
        }
        out->n_sec++;
    }

    return NULL;
}
