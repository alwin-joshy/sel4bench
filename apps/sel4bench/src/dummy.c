/*
 * Copyright 2017, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "benchmark.h"
#include "processing.h"
#include "json.h"

#include <dummy.h>
#include <stdio.h>

static json_t *dummy_process(void *results) {
	dummy_results_t *raw_results = results;

	result_desc_t desc = {
		.stable = true,
		.name = "dummy"
	};

	result_t result = process_result(N_RUNS, raw_results->results, desc);

    result_set_t set = {
        .name = "dummy",
        .n_results = 1,
        .n_extra_cols = 0,
        .results = &result
    };

	json_t *array = json_array();
	json_array_append_new(array, result_set_to_json(set));

	return array;
}

static benchmark_t dummy_benchmark = {
	.name = "dummy",
	.enabled = config_set(CONFIG_APP_DUMMYBENCH),
	.results_pages = BYTES_TO_SIZE_BITS_PAGES(sizeof(dummy_results_t), seL4_PageBits),
	.process = dummy_process,
	.init = blank_init
};

benchmark_t *dummy_benchmark_new(void)
{
    return &dummy_benchmark;
}