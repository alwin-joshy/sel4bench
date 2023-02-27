#pragma once

#include <sel4bench/sel4bench.h>

#define N_RUNS 10

typedef struct {
	ccnt_t results[N_RUNS + 1];
} dummy_results_t;