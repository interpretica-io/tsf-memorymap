# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Interpretica Unipessoal Lda
#
# External TE library (see TE_EXT_REPO): engine-side memory maps - the
# memory image of a binary read out of the ELF for any architecture, the
# free RAM that leaves on a target, the memory map of a running process,
# and a W^X audit over both. Built as a shared library on the engine
# platform only, like tapi_bt: it calls tapi and tapi_job, engine
# libraries with no static variant, so a static build of it would fail
# the configure.

if get_option('engine')
    build_lib_shared = true
endif
build_lib_static = false
install_lib = install_dev

headers += files(
    'tapi_memmap.h',
    'tapi_memmap_audit.h',
    'tapi_memmap_elf.h',
    'tapi_memmap_proc.h',
    'tapi_memmap_ram.h',
)

# tapi_memmap_elfcore.h is internal to this library and is not installed.
sources += files(
    'tapi_memmap_audit.c',
    'tapi_memmap_elf.c',
    'tapi_memmap_elfcore.c',
    'tapi_memmap_proc.c',
    'tapi_memmap_ram.c',
)

te_libs += [
    'tapi',
    'tapi_job',
    'tapi_rpc',
    'tapi_devtool',
    'tapi_cybersec',
]
