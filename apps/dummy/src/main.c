
#include <autoconf.h>
#include <sel4benchfault/gen_config.h>
#include <stdio.h>

#include <sel4/sel4.h>
#include <sel4bench/arch/sel4bench.h>
#include <utils/ud.h>
#include <sel4runtime.h>
#include <muslcsys/vsyscall.h>
#include <utils/attribute.h>

#include <benchmark.h>
#include <dummy.h>

static void run_dummy_benchmark(dummy_results_t *results) {
	
	for (int i = 0; i < N_RUNS; i++) {
		results->results[i] = 10;
	}
}


static env_t *env;

void CONSTRUCTOR(MUSLCSYS_WITH_VSYSCALL_PRIORITY) init_env(void)
{
    static size_t object_freq[seL4_ObjectTypeCount] = {0};

    env = benchmark_get_env(
              sel4runtime_argc(),
              sel4runtime_argv(),
              sizeof(dummy_results_t),
              object_freq
          );
}

int main(int argc, char **argv) {
	UNUSED int error;
	dummy_results_t *results;
	results = (dummy_results_t *) env->results;

	sel4bench_init();

	run_dummy_benchmark(results);

	benchmark_finished(EXIT_SUCCESS);
	return 0;
}