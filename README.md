# tsf-memorymap

Memory maps from a test suite, packaged as an external Test Environment
(TE) repository.

Library:

- `tapi_memmap` — engine-side, built as a shared library. Two kinds of
  memory map, read on a Test Agent:
  - `tapi_memmap_elf` — the memory image of a **binary**, read out of
    the ELF file itself: which segments load where, how much memory
    each takes, the sections and the entry point;
  - `tapi_memmap_ram` — from that image and the RAM a target has, how
    much RAM the image occupies and how much is **free**, with the free
    and used spans;
  - `tapi_memmap_proc` — the memory map of a running **process** from
    the operating system: the mappings, their permissions, what backs
    each and how much is resident;
  - `tapi_memmap_audit` — a W^X audit over both, reported through
    tsf-cybersec.

TE has no notion of a memory map of its own.

## The point: read any ELF, without running it

A binary for another architecture — a riscv64 firmware image on an x86
agent — cannot be run there, so its memory map is read **statically,
out of the file**. The ELF reader interprets every field by the file's
own class (ELF32/ELF64) and byte order, taken from `e_ident`, never by
the agent's; `e_machine` is kept as a fact, not acted on. So the
question a firmware author asks — *does this image fit in the chip's
RAM, and how much is left* — is answered on whatever agent is to hand.

```c
tapi_memmap_image image;
tapi_memmap_region ram = { .base = 0x80000000, .size = 512 * 1024,
                           .name = "RAM" };
tapi_memmap_usage usage;

CHECK_RC(tapi_memmap_elf_read(factory, "/lib/firmware/app.elf", 30000,
                              &image));
CHECK_RC(tapi_memmap_ram_usage(&image, &ram, 1, TAPI_MEMMAP_BY_VADDR,
                               &usage));
if (!usage.fits)
    TEST_VERDICT("The image overflows RAM by %" PRIu64 " bytes",
                 usage.overflow);
RING("%" PRIu64 " of %" PRIu64 " bytes free", usage.free, usage.total);
tapi_memmap_usage_free(&usage);
tapi_memmap_image_free(&image);
```

### vaddr and paddr are not the same thing

A segment carries two addresses, and on an embedded target the
difference matters: `vaddr` is where it runs, `paddr` is where it is
loaded from. Code copied from flash to RAM at start-up has its `paddr`
in flash and its `vaddr` in RAM. `tapi_memmap_ram_usage()` takes
`TAPI_MEMMAP_BY_VADDR` or `TAPI_MEMMAP_BY_PADDR`, so you can ask "what
sits in RAM once running" and "what sits in flash" of the same image.

### .bss costs RAM and no file

A `LOAD` segment's `memsz` can exceed its `filesz`; the excess is the
zero-filled `.bss`, which takes RAM but occupies nothing in the file.
The free-RAM computation counts `memsz`, so a large `.bss` is charged
against RAM as it should be.

## Usage

Declare the repositories in an external libraries catalog and pass it
to `dispatcher.sh --external=external.yml`:

```yaml
repositories:
  - name: tsf_devtool
    url: https://github.com/interpretica-io/tsf-devtool.git
    ref: <tag>
    libs:
      - tapi_devtool
  - name: tsf_cybersec
    url: https://github.com/interpretica-io/tsf-cybersec.git
    ref: <tag>
    libs:
      - tapi_cybersec
  - name: tsf_memorymap
    url: https://github.com/interpretica-io/tsf-memorymap.git
    ref: <tag>
    libs:
      - tapi_memmap
```

Bind them in `builder.conf`:

```
TE_EXT_REPO_USE([tsf_devtool], [], [tapi_devtool])
TE_EXT_REPO_USE([tsf_cybersec], [], [tapi_cybersec])
TE_EXT_REPO_USE([tsf_memorymap], [], [tapi_memmap])
```

Then add `tapi_memmap` to `te_libs` in the suite's `meson.build`.
Reading a binary needs only that the file be on the agent; reading a
process map needs an **RPC** job factory (`ta_rpcprovider`), because it
reads what a command printed.

## Where each thing runs

- **The ELF image and the RAM math** are computed on the engine. The
  file is fetched from the agent and parsed there; the parser is a
  pure, dependency-free reader (`tapi_memmap_elfcore`) so it can be — and
  was — unit-tested on its own against binaries of several
  architectures before any of this ran.
- **The process map** is read on the agent. On Linux it is
  `/proc/PID/maps` with the resident size added from `/proc/PID/smaps`;
  these are read with `cat`, not fetched as files, because the kernel
  reports them as zero-length and a file copy comes back empty. On
  macOS it is `vmmap`. Windows is not covered: a per-region view there
  needs a debugger API, not a command.

## What the posture is worth

`tapi_memmap_audit_image()` and `tapi_memmap_audit_proc()` report
[tsf-cybersec](https://github.com/interpretica-io/tsf-cybersec)
findings for the one thing a memory map says about security: memory
that is writable and executable at once.

| Finding | Severity | Read from |
|---|---|---|
| `memmap.wx-segment` | high | a `LOAD` segment that is W and X |
| `memmap.exec-stack` | medium | `GNU_STACK` carries the execute bit |
| `memmap.wx-mapping` | high | a live mapping that is W and X |
| `memmap.exec-writable-stack` | high | the live stack is writable and executable |

This is the memory-map view, which sees the segment flags directly and,
for a foreign-architecture image, without running anything — next to
what `tapi_binscan` reports about how a binary was built.

## What was verified, and what was not

**The ELF reader — verified against real binaries of several
architectures.** The pure core was unit-tested outside TE against a
riscv64 freestanding image (RISC-V, ELF64, a single `rwx` `LOAD` at
`0x80000000`, a 128 KiB `.bss`), a second riscv64 image linked with its
`.data` at a `paddr` in flash and a `vaddr` in RAM (the flash-to-RAM
case, `paddr` ≠ `vaddr`), and an AArch64 executable — parsing the
class, byte order, machine, entry, segments and sections of each, and
computing the free RAM against a region to the byte.

**The whole library — verified through a Test Agent (Debian 12).** A TE
suite with a real agent (`Agt_A`, `ta_rpcprovider`) ran every call
through the job factory, and all tests passed:

- `elf` — a riscv64 image parsed from its bytes as ELF64,
  little-endian, machine RISC-V, entry `0x80000000`, its one `LOAD`
  segment read as `rwx` at `0x7ffff000` with a 128 KiB `.bss`, and its
  `.bss` section found by name; the flash-to-RAM image read with its
  `.data` at vaddr `0x80000000` and paddr `0x20010000`; an image read
  back from a file put on the agent; and a text file refused with
  `TE_EBADF`.
- `ram` — over a 512 KiB region the flat image's segment came out at
  135648 bytes used and 388640 free, the largest free span at
  `0x800201e0`; the flash-to-RAM image by paddr took 0 of RAM (it loads
  from flash) and by vaddr took its 131080-byte `.data`; and a 128 KiB
  image in a 64 KiB region was reported as overflowing.
- `audit` — the RWX image raised `memmap.wx-segment`; the clean image
  raised nothing.
- `proc` — the RPC server's own map was read live: a stack and
  executable file-backed code present, 505 MiB mapped with 7.8 MiB
  resident (the resident size proving `smaps` was read), the W^X audit
  run over it, and a non-existent pid returning `TE_ENOENT`.

The pure ELF reader was additionally unit-tested outside TE, before any
of the above, against the same riscv64 fixtures and an AArch64
executable, computing every field and the free RAM to the byte.

## Scope

- **Reading a binary changes nothing** — it is a file read and a parse.
- **Reading a process map reads only** — `cat /proc/PID/*` or `vmmap`,
  no more.
- **The RAM regions are the caller's to give.** The ELF does not carry
  the size of the chip's RAM; a linker script and the data sheet do, so
  `tapi_memmap_ram_usage()` takes the regions as an argument.
