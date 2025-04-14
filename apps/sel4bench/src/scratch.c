/*
 * Copyright 2017, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include "benchmark.h"
#include "processing.h"
#include "json.h"

#include <sel4/sel4.h>
#include <scratch.h>
#include <stdio.h>

static json_t *scratch_process(void *results)
{
	scratch_results_t *raw_results = results;

	result_desc_t desc = {
		.stable = false,
		.overhead = 0,
        .ignored = N_IGNORED
		// .name "idk",
	};

	json_t *array = json_array();
	result_t result = process_result(NUM_RUNS, raw_results->copier_flush, desc);

	result_set_t set = {
		.name = "copy (cache clean/invalidate)",
		.n_results = 1,
		.n_extra_cols = 0,
		.results = &result,
	};

	json_array_append_new(array, result_set_to_json(set));

	set.name = "copy (no cache clean/invalidate)";
	result = process_result(NUM_RUNS, raw_results->copier_no_flush, desc);
	json_array_append_new(array, result_set_to_json(set));

	set.name = "remap";
	result = process_result(NUM_RUNS, raw_results->remap, desc);
	json_array_append_new(array, result_set_to_json(set));

	return array;
}

static benchmark_t scratch_benchmark = {
	.name = "scratch",
	.enabled = config_set(CONFIG_APP_SCRATCHBENCH),
	.results_pages = BYTES_TO_SIZE_BITS_PAGES(sizeof(scratch_results_t), seL4_PageBits),
	.process = scratch_process,
	.init = blank_init
};

benchmark_t *scratch_benchmark_new(void) {
	return &scratch_benchmark;
}