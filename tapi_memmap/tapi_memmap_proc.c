/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief The memory map of a running process
 *
 * @c /proc/PID/maps and @c /proc/PID/smaps are read with @c cat rather
 * than fetched as files: they are kernel-generated, report a size of
 * zero, and a file copy would come back empty. The resident size of
 * each mapping is taken from @c smaps, whose blocks begin with the same
 * "start-end perms ..." header line as @c maps and then list @c Rss.
 */

#define TE_LGR_USER "TAPI MEMMAP"

#include "te_config.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "logger_api.h"
#include "te_alloc.h"
#include "te_str.h"
#include "te_string.h"
#include "te_vector.h"

#include "tapi_job_opt.h"
#include "tapi_devtool_run.h"
#include "tapi_memmap.h"
#include "tapi_memmap_proc.h"

/** A plain argument vector for tapi_devtool_run. */
typedef struct memmap_args {
    size_t n_args;
    const char **args;
} memmap_args;

static const tapi_job_opt_bind memmap_arg_binds[] = TAPI_JOB_OPT_SET(
    TAPI_JOB_OPT_ARRAY_PTR(memmap_args, n_args, args,
        TAPI_JOB_OPT_CONTENT(TAPI_JOB_OPT_STRING, NULL, false))
);

/** Run a program on the agent and capture stdout; @p ok is exit==0. */
static te_errno
memmap_run(tapi_job_factory_t *factory, const char *program,
           const char **args, size_t n_args, int timeout_ms,
           te_string *out, bool *ok)
{
    memmap_args opt = { .n_args = n_args, .args = args };
    tapi_devtool_output output;
    tapi_devtool_run run = TAPI_DEVTOOL_RUN_INIT;
    te_errno rc;

    rc = tapi_devtool_run_init(&run, factory, program, program,
                               memmap_arg_binds, &opt, NULL);
    if (rc != 0)
        return rc;

    rc = tapi_devtool_run_start(&run);
    if (rc == 0)
        rc = tapi_devtool_run_wait(&run, timeout_ms);
    if (rc != 0)
    {
        tapi_devtool_run_fini(&run);
        return rc;
    }

    tapi_devtool_run_get_output(&run, &output);
    if (output.out != NULL)
        te_string_append(out, "%s", output.out);
    *ok = output.status.type == TAPI_JOB_STATUS_EXITED &&
          output.status.value == 0;

    return tapi_devtool_run_fini(&run);
}

/* See description in tapi_memmap_proc.h */
const char *
tapi_memmap_backing2str(tapi_memmap_backing backing)
{
    switch (backing)
    {
        case TAPI_MEMMAP_BACK_FILE:
            return "file";
        case TAPI_MEMMAP_BACK_HEAP:
            return "heap";
        case TAPI_MEMMAP_BACK_STACK:
            return "stack";
        case TAPI_MEMMAP_BACK_VDSO:
            return "vdso";
        default:
            return "anon";
    }
}

/** Classify a maps pathname field. */
static tapi_memmap_backing
memmap_classify(const char *path)
{
    if (path == NULL || *path == '\0')
        return TAPI_MEMMAP_BACK_ANON;
    if (strcmp(path, "[heap]") == 0)
        return TAPI_MEMMAP_BACK_HEAP;
    if (strcmp(path, "[stack]") == 0 || strncmp(path, "[stack:", 7) == 0)
        return TAPI_MEMMAP_BACK_STACK;
    if (strcmp(path, "[vdso]") == 0 || strcmp(path, "[vvar]") == 0 ||
        strcmp(path, "[vsyscall]") == 0)
        return TAPI_MEMMAP_BACK_VDSO;
    if (path[0] == '[')
        return TAPI_MEMMAP_BACK_ANON;
    return TAPI_MEMMAP_BACK_FILE;
}

/**
 * Parse one "start-end perms offset dev inode path" header line.
 *
 * @return @c true when it was such a line.
 */
static bool
memmap_parse_header(const char *line, tapi_memmap_mapping *m)
{
    unsigned long long start;
    unsigned long long end;
    unsigned long long offset;
    char perms[8] = "";
    int consumed = 0;
    const char *p;

    if (sscanf(line, "%llx-%llx %7s %llx %*x:%*x %*u %n",
               &start, &end, perms, &offset, &consumed) < 4)
    {
        return false;
    }

    memset(m, 0, sizeof(*m));
    m->start = start;
    m->end = end;
    m->offset = offset;
    m->rss = -1;
    if (perms[0] == 'r')
        m->perms |= TAPI_MEMMAP_R;
    if (perms[1] == 'w')
        m->perms |= TAPI_MEMMAP_W;
    if (perms[2] == 'x')
        m->perms |= TAPI_MEMMAP_X;
    m->shared = perms[3] == 's';

    /* The path is the rest of the line after the fields, trimmed. */
    p = line + consumed;
    while (*p == ' ' || *p == '\t')
        p++;
    if (*p != '\0' && *p != '\n')
    {
        size_t len = strcspn(p, "\r\n");

        m->path = TE_STRNDUP(p, len);
    }
    m->backing = memmap_classify(m->path);

    return true;
}

/** Read Linux /proc/PID/maps and smaps. */
static te_errno
memmap_linux(tapi_job_factory_t *factory, pid_t pid, int timeout_ms,
             te_vec *maps)
{
    te_string path = TE_STRING_INIT;
    te_string out = TE_STRING_INIT;
    const char *args[1];
    const char *line;
    tapi_memmap_mapping *last = NULL;
    bool ok = false;
    te_errno rc;

    /*
     * smaps is a superset of maps: the same header lines, each followed
     * by fields including Rss. Reading it alone gives both the map and
     * the resident size.
     */
    te_string_append(&path, "/proc/%d/smaps", (int)pid);
    args[0] = path.ptr;
    rc = memmap_run(factory, "cat", args, 1, timeout_ms, &out, &ok);
    if (rc != 0)
        goto out;

    if (!ok || out.len == 0)
    {
        /* No smaps (or no process): fall back to maps, RSS unknown. */
        te_string_reset(&path);
        te_string_reset(&out);
        te_string_append(&path, "/proc/%d/maps", (int)pid);
        args[0] = path.ptr;
        rc = memmap_run(factory, "cat", args, 1, timeout_ms, &out, &ok);
        if (rc != 0)
            goto out;
        if (!ok)
        {
            rc = TE_RC(TE_TAPI, TE_ENOENT);
            goto out;
        }
    }

    for (line = te_string_value(&out); line != NULL && *line != '\0'; )
    {
        tapi_memmap_mapping m;

        if (memmap_parse_header(line, &m))
        {
            TE_VEC_APPEND(maps, m);
            last = te_vec_get(maps, te_vec_size(maps) - 1);
        }
        else if (last != NULL && strncmp(line, "Rss:", 4) == 0)
        {
            unsigned long long kb = 0;

            if (sscanf(line + 4, " %llu", &kb) == 1)
                last->rss = (int64_t)kb * 1024;
        }

        line = strchr(line, '\n');
        if (line != NULL)
            line++;
    }

    if (te_vec_size(maps) == 0)
        rc = TE_RC(TE_TAPI, TE_ENOENT);

out:
    te_string_free(&path);
    te_string_free(&out);

    return rc;
}

/**
 * Read macOS vmmap. Best-effort: vmmap's format is columnar and
 * versioned, and this has not been run against a Mac; the first suite
 * to use it on macOS should expect to adjust the parse.
 */
static te_errno
memmap_macos(tapi_job_factory_t *factory, pid_t pid, int timeout_ms,
             te_vec *maps)
{
    te_string out = TE_STRING_INIT;
    te_string pidstr = TE_STRING_INIT;
    const char *args[2];
    const char *line;
    bool ok = false;
    te_errno rc;

    te_string_append(&pidstr, "%d", (int)pid);
    args[0] = "-interleaved";
    args[1] = pidstr.ptr;
    rc = memmap_run(factory, "vmmap", args, 2, timeout_ms, &out, &ok);
    if (rc != 0)
        goto out;
    if (!ok)
    {
        rc = TE_RC(TE_TAPI, TE_ENOENT);
        goto out;
    }

    /*
     * Lines like "__TEXT  000...-000...  [ 32K] r-x/r-x SM=COW  /path".
     * The address range and the r-x/max column are what is read.
     */
    for (line = te_string_value(&out); line != NULL && *line != '\0'; )
    {
        unsigned long long start;
        unsigned long long end;
        char cur[8] = "";
        const char *dash = strstr(line, "-0x");
        char region[64] = "";

        if (dash != NULL &&
            sscanf(line, "%63s %llx-%llx", region, &start, &end) == 3 &&
            strstr(line, "/") != NULL)
        {
            const char *perm = strstr(line, "] ");
            tapi_memmap_mapping m;

            memset(&m, 0, sizeof(m));
            m.start = start;
            m.end = end;
            m.rss = -1;
            if (perm != NULL && sscanf(perm + 2, "%7s", cur) == 1)
            {
                if (cur[0] == 'r')
                    m.perms |= TAPI_MEMMAP_R;
                if (cur[1] == 'w')
                    m.perms |= TAPI_MEMMAP_W;
                if (cur[2] == 'x')
                    m.perms |= TAPI_MEMMAP_X;
            }
            m.backing = TAPI_MEMMAP_BACK_FILE;
            m.path = TE_STRDUP(region);
            TE_VEC_APPEND(maps, m);
        }

        line = strchr(line, '\n');
        if (line != NULL)
            line++;
    }

    if (te_vec_size(maps) == 0)
        rc = TE_RC(TE_TAPI, TE_ENOENT);

out:
    te_string_free(&out);
    te_string_free(&pidstr);

    return rc;
}

/* See description in tapi_memmap_proc.h */
te_errno
tapi_memmap_proc_read(tapi_job_factory_t *factory, pid_t pid, int timeout_ms,
                      te_vec *maps)
{
    te_string out = TE_STRING_INIT;
    const char *uname_args[1] = { "-s" };
    bool ok = false;
    te_errno rc;

    /* Which OS: uname -s says Linux or Darwin. */
    rc = memmap_run(factory, "uname", uname_args, 1, timeout_ms, &out, &ok);
    if (rc != 0)
    {
        te_string_free(&out);
        return rc;
    }

    if (strstr(te_string_value(&out), "Linux") != NULL)
        rc = memmap_linux(factory, pid, timeout_ms, maps);
    else if (strstr(te_string_value(&out), "Darwin") != NULL)
        rc = memmap_macos(factory, pid, timeout_ms, maps);
    else
    {
        ERROR("Reading a process map needs Linux or macOS");
        rc = TE_RC(TE_TAPI, TE_EOPNOTSUPP);
    }

    te_string_free(&out);

    return rc;
}

/* See description in tapi_memmap_proc.h */
void
tapi_memmap_proc_totals(const te_vec *maps, uint64_t *total,
                        uint64_t *resident)
{
    const tapi_memmap_mapping *m;
    uint64_t t = 0;
    uint64_t r = 0;

    TE_VEC_FOREACH(maps, m)
    {
        t += m->end - m->start;
        if (m->rss >= 0)
            r += (uint64_t)m->rss;
    }

    if (total != NULL)
        *total = t;
    if (resident != NULL)
        *resident = r;
}

/* See description in tapi_memmap_proc.h */
void
tapi_memmap_mappings_log(const te_vec *maps)
{
    const tapi_memmap_mapping *m;

    TE_VEC_FOREACH(maps, m)
    {
        char perms[4];

        tapi_memmap_perms2str(m->perms, perms);
        RING("0x%" PRIx64 "-0x%" PRIx64 " %s%c %-6s %s rss=%" PRId64,
             m->start, m->end, perms, m->shared ? 's' : 'p',
             tapi_memmap_backing2str(m->backing),
             m->path != NULL ? m->path : "-", m->rss);
    }
}

/* See description in tapi_memmap_proc.h */
void
tapi_memmap_mappings_free(te_vec *maps)
{
    tapi_memmap_mapping *m;

    TE_VEC_FOREACH(maps, m)
        free(m->path);
    te_vec_free(maps);
}
