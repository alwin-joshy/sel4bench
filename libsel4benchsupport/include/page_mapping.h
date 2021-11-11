/*
 * Copyright 2017, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <sel4bench/sel4bench.h>
#include <sel4utils/process.h>

#define RUNS 16
#define TESTS ARRAY_SIZE(page_mapping_benchmark_params)
#define NPHASE ARRAY_SIZE(phase_name)

typedef struct benchmark_params {
    /* name of the function we are benchmarking */
    const char *name;
    const int   npage;
} benchmark_params_t;

/* array of benchmarks to run */
static const
benchmark_params_t page_mapping_benchmark_params[] = {
    {
        .name   = "map 1",
        .npage  = 1,
    },
    {
        .name   = "map 2",
        .npage  = 2,
    },
    {
        .name   = "map 4",
        .npage  = 4,
    },
    {
        .name   = "map 8",
        .npage  = 8,
    },
    {
        .name   = "map 16",
        .npage  = 16,
    },
    {
        .name   = "map 32",
        .npage  = 32,
    },
    {
        .name   = "map 64",
        .npage  = 64,
    },
    {
        .name   = "map 128",
        .npage  = 128,
    },
    {
        .name   = "map 256",
        .npage  = 256,
    },
    {
        .name   = "map 512",
        .npage  = 512,
    },
    {
        .name   = "map 1024",
        .npage  = 1024,
    },
    {
        .name   = "map 2048",
        .npage  = 2048,
    },
};

char *phase_name[] = {
    "Prepare Page Tables",
    "Allocate Pages",
    "Mapping",
    "Map again at a different vaddr (including cap copy)",
    "Protect Pages one by one as Read Only",
    "Protect Pages in range as Read Only",
    "Unprotect Pages",
    "Unmap Pages using range_unmap",
    "Unmap pages one by one with page_unmap"
};

typedef struct page_mapping_results {
    /* Raw results from benchmarking. These get checked for sanity */
    ccnt_t overhead_benchmarks[RUNS];
    ccnt_t benchmarks_result[TESTS][NPHASE][RUNS];
} page_mapping_results_t;
