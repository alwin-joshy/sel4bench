#define ZF_LOG_LEVEL ZF_LOG_INFO

#include <autoconf.h>
#include <sel4benchscratch/gen_config.h>
#include <allocman/vka.h>
#include <allocman/bootstrap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <sel4/sel4.h>
#include <sel4/syscalls.h>
#include <sel4bench/sel4bench.h>
#include <sel4utils/process.h>
#include <string.h>
#include <utils/util.h>
#include <vka/vka.h>

#include <benchmark.h>
#include <scratch.h>

#define NUM_CLIENT_ARGS 1

#define NUM_COPY_SERVER_ARGS 3

#define NUM_REMAP_SERVER_ARGS 3 + NUM_RUNS
#define REMAP_CAP_BASE 3

// #define NUM_ARGS MAX(NUM_CLIENT_ARGS, MAX(NUM_COPY_SERVER_ARGS, NUM_REMAP_SERVER_ARGS))
#define NUM_ARGS (3 + NUM_RUNS)

typedef struct helper_thread {
    sel4utils_process_t process;
    seL4_CPtr untyped;
    seL4_CPtr result_ep;
    seL4_CPtr ntfn;
    int npage;
    char *argv[NUM_ARGS];
    char argv_strings[NUM_ARGS][WORD_STRING_SIZE];
} helper_thread_t;

#define TEST_VADDR_BASE 0xA0000000
#define DATA_VADDR_BASE 0xB0000000
#define REMAP_TEST_VADDR_BASE 0xC0000000

static bool data_page_mapped = false;

#define LINE_INDEX(a) (a >> CONFIG_L1_CACHE_LINE_SIZE_BITS)


void cache_clean_and_invalidate(unsigned long start, unsigned long end)
{
#if defined(CONFIG_ARCH_AARCH64)
    unsigned long vaddr;
    unsigned long index;

    assert(start != end);

    /* If the end address is not on a cache line boundary, we want to perform
     * the cache operation on that cache line as well. */
    unsigned long end_rounded = ROUND_UP(end, 1 << CONFIG_L1_CACHE_LINE_SIZE_BITS);

    for (index = LINE_INDEX(start); index < LINE_INDEX(end_rounded); index++) {
        vaddr = index << CONFIG_L1_CACHE_LINE_SIZE_BITS;
        asm volatile("dc civac, %0" : : "r"(vaddr));
    }
    asm volatile("dsb sy" ::: "memory");
#elif defined(CONFIG_ARCH_RISCV)
    /* While not all RISC-V platforms are DMA cache-cohernet,
     * we assume we are targeting one that is and so there is nothing to do. */
#else
// #error "Unknown architecture for cache_clean_and_invalidate"
#endif
}

void copy_fn(int argc, char **argv) {
	assert(argc == NUM_COPY_SERVER_ARGS);
	seL4_CPtr ntfn = atoi(argv[0]);
	seL4_CPtr result_ep = atoi(argv[1]);
	bool do_flush = atoi(argv[2]);

	seL4_Wait(ntfn, NULL);
	for (int i = 0; i < NUM_RUNS; i++) {
		ccnt_t start_time, end_time;
		SEL4BENCH_READ_CCNT(start_time);

		char *buffer = (char *) TEST_VADDR_BASE + (PAGE_SIZE_4K * i);
		memcpy(buffer, (void *) DATA_VADDR_BASE, 1500);

		if (do_flush) {
			cache_clean_and_invalidate((seL4_Word) buffer, (seL4_Word) buffer + 1500);
		}

		seL4_NBSendWait(ntfn, seL4_MessageInfo_new(0, 0, 0, 0), ntfn, NULL);

		SEL4BENCH_READ_CCNT(end_time);
		seL4_SetMR(0, end_time - start_time);
		send_result(result_ep, end_time - start_time);
	}

	seL4_Wait(ntfn, NULL);
}

void remap_fn(int argc, char **argv) {
	assert(argc == NUM_REMAP_SERVER_ARGS);
	seL4_CPtr ntfn = atoi(argv[0]);
	seL4_CPtr result_ep = atoi(argv[1]);
	seL4_CPtr client_vspace = atoi(argv[2]);

	seL4_Wait(ntfn, NULL);
	for (int i = 0; i < NUM_RUNS; i++) {
		ccnt_t start_time, end_time;
		seL4_CPtr page_cap = atoi(argv[REMAP_CAP_BASE + i]);

		SEL4BENCH_READ_CCNT(start_time);

		seL4_ARCH_Page_Unmap(page_cap);
		seL4_ARCH_Page_Map(page_cap, client_vspace, TEST_VADDR_BASE + (PAGE_SIZE_4K * i),
						   seL4_AllRights, seL4_ARCH_Default_VMAttributes);

		seL4_NBSendWait(ntfn, seL4_MessageInfo_new(0, 0, 0, 0), ntfn, NULL);

		SEL4BENCH_READ_CCNT(end_time);
		seL4_SetMR(0, end_time - start_time);
		send_result(result_ep, end_time - start_time);
	}

	seL4_Wait(ntfn, NULL);
}


void client_fn(int argc, char **argv) {
	assert(argc == 1);
	seL4_CPtr ntfn = atoi(argv[0]);

	for (int i = 0; i < NUM_RUNS + 1; i++) {
		seL4_NBSendWait(ntfn, seL4_MessageInfo_new(0, 0, 0, 0), ntfn, NULL);

		char *buffer = (char *) TEST_VADDR_BASE + (PAGE_SIZE_4K * i);
		uint64_t xsum = 0;
		for (int i = 0; i < 1500; i++) {
			xsum += buffer[i];
		}
		assert(xsum == 97623);
	}

	seL4_Wait(ntfn, NULL);
}


static void run_bench_child_proc(env_t *env,
                                 cspacepath_t *result_ep_path,
                                 ccnt_t result[NUM_RUNS],
                                 helper_thread_t *client_proc,
                                 helper_thread_t *server_proc,
                                 uint64_t num_server_args
                                )
{

    if (benchmark_spawn_process(&server_proc->process, &env->delegate_vka, &env->vspace,
                                num_server_args, server_proc->argv, 1) != 0) {
        ZF_LOGF("Failed to spawn server\n");
    }

    if (benchmark_spawn_process(&client_proc->process, &env->delegate_vka, &env->vspace,
                                NUM_CLIENT_ARGS, client_proc->argv, 1) != 0) {
        ZF_LOGF("Failed to spawn client\n");
    }

    /* Get result from benchmarking process */
    for (int i = 0; i < NUM_RUNS; i++) {
        result[i] = get_result(result_ep_path->capPtr);
    }
}


static void run_copier_benchmark(env_t *env, ccnt_t results[NUM_RUNS], bool do_flush)
{
	helper_thread_t server_proc, client_proc;
	cspacepath_t ntfn_path, done_ep_path;

  	vka_object_t done_ep = {0};
    UNUSED int error = vka_alloc_endpoint(&env->slab_vka, &done_ep);
    assert(error == 0);
    vka_cspace_make_path(&env->slab_vka, done_ep.cptr, &done_ep_path);

	vka_object_t ntfn = {0};
    error = vka_alloc_notification(&env->slab_vka, &ntfn);
    assert(error == 0);
    vka_cspace_make_path(&env->slab_vka, ntfn.cptr, &ntfn_path);

	/* Create mapper/copier thread */
    benchmark_shallow_clone_process(env, &server_proc.process, seL4_MaxPrio - 1, &copy_fn, "copier");
    server_proc.ntfn = sel4utils_copy_path_to_process(&server_proc.process, ntfn_path);
    server_proc.result_ep = sel4utils_copy_path_to_process(&server_proc.process, done_ep_path);
    sel4utils_create_word_args(server_proc.argv_strings, server_proc.argv, NUM_COPY_SERVER_ARGS,
    						   server_proc.ntfn, server_proc.result_ep, do_flush);


	/* Create client/reader thread */
	benchmark_shallow_clone_process(env, &client_proc.process, seL4_MaxPrio - 2, client_fn, "client");
    client_proc.ntfn = sel4utils_copy_path_to_process(&client_proc.process, ntfn_path);
    sel4utils_create_word_args(client_proc.argv_strings, client_proc.argv, NUM_CLIENT_ARGS, client_proc.ntfn);

    // Allocate the data page and map it into self and server
    if (!data_page_mapped) {
    	reservation_t own_data_res = vspace_reserve_range_at(&env->vspace, (void *) DATA_VADDR_BASE,
    													 	 PAGE_SIZE_4K, seL4_AllRights, 1);
	    seL4_CPtr data_frame_cap = vka_alloc_frame_leaky(&env->slab_vka, PAGE_BITS_4K);
		vspace_map_pages_at_vaddr(&env->vspace, &data_frame_cap, NULL, (void *) DATA_VADDR_BASE, 1,
								  PAGE_BITS_4K, own_data_res);
		memcpy((void *) DATA_VADDR_BASE, random_data, random_data_len);
		data_page_mapped = true;
    }

    reservation_t server_data_res = vspace_reserve_range_at(&server_proc.process.vspace, (void *) DATA_VADDR_BASE,
														PAGE_SIZE_4K, seL4_AllRights, 1);
	vspace_share_mem_at_vaddr(&env->vspace, &server_proc.process.vspace, (void *) DATA_VADDR_BASE,
							  1, PAGE_BITS_4K, (void *) DATA_VADDR_BASE, server_data_res);


    /* Allocate frames and map them into both the client and the server */
    reservation_t server_res = vspace_reserve_range_at(&server_proc.process.vspace, (void *) TEST_VADDR_BASE, NUM_RUNS * PAGE_SIZE_4K,
										 seL4_AllRights, 1);
    assert(server_res.res != 0);

    reservation_t client_res = vspace_reserve_range_at(&client_proc.process.vspace, (void *) TEST_VADDR_BASE, NUM_RUNS * PAGE_SIZE_4K,
										 seL4_AllRights, 1);
    assert(client_res.res != 0);

    seL4_CPtr frame_caps[NUM_RUNS] = {0};
    for (int i = 0; i < NUM_RUNS; i++) {
    	frame_caps[i] = vka_alloc_frame_leaky(&env->slab_vka, PAGE_BITS_4K);
    }

	vspace_map_pages_at_vaddr(&server_proc.process.vspace, frame_caps, NULL, (void *) TEST_VADDR_BASE, NUM_RUNS, PAGE_BITS_4K, server_res);
	vspace_share_mem_at_vaddr(&server_proc.process.vspace, &client_proc.process.vspace, (void *) TEST_VADDR_BASE,
							  NUM_RUNS, PAGE_BITS_4K,  (void *) TEST_VADDR_BASE, client_res);

	run_bench_child_proc(env, &done_ep_path, results, &client_proc, &server_proc, NUM_COPY_SERVER_ARGS);
}


static void run_remap_benchmark(env_t *env, ccnt_t results[NUM_RUNS])
{
	helper_thread_t server_proc, client_proc;

	cspacepath_t ntfn_path, done_ep_path, client_vspace_path;
    vka_object_t done_ep = {0};
    UNUSED int error = vka_alloc_endpoint(&env->slab_vka, &done_ep);
    assert(error == 0);
    vka_cspace_make_path(&env->slab_vka, done_ep.cptr, &done_ep_path);

	vka_object_t ntfn = {0};
    error = vka_alloc_notification(&env->slab_vka, &ntfn);
    assert(error == 0);
    vka_cspace_make_path(&env->slab_vka, ntfn.cptr, &ntfn_path);

	/* Create client/reader thread */
	benchmark_shallow_clone_process(env, &client_proc.process, seL4_MaxPrio - 2, client_fn, "client");
    client_proc.ntfn = sel4utils_copy_path_to_process(&client_proc.process, ntfn_path);
    sel4utils_create_word_args(client_proc.argv_strings, client_proc.argv, NUM_CLIENT_ARGS, client_proc.ntfn);
    vka_cspace_make_path(&env->slab_vka, vspace_get_root(&client_proc.process.vspace), &client_vspace_path);


	/* Create mapper/copier thread */
    benchmark_shallow_clone_process(env, &server_proc.process, seL4_MaxPrio - 1, &remap_fn, "remapper");
    server_proc.ntfn = sel4utils_copy_path_to_process(&server_proc.process, ntfn_path);
    server_proc.result_ep = sel4utils_copy_path_to_process(&server_proc.process, done_ep_path);
    seL4_CPtr server_proc_client_vspace = sel4utils_copy_path_to_process(&server_proc.process, client_vspace_path);
    sel4utils_create_word_args(server_proc.argv_strings, server_proc.argv, REMAP_CAP_BASE,
    						   server_proc.ntfn, server_proc.result_ep, server_proc_client_vspace);

    /* Create and map a whole bunch of pages into the server */
    seL4_CPtr frame_caps[NUM_RUNS] = {0};
    cspacepath_t frame_cap_path[NUM_RUNS] = {0};
    seL4_CPtr server_frame_caps[NUM_RUNS] = {0};

    for (int i = 0; i < NUM_RUNS; i++) {
    	frame_caps[i] = vka_alloc_frame_leaky(&env->slab_vka, PAGE_BITS_4K);
    	vka_cspace_make_path(&env->slab_vka, ntfn.cptr, &frame_cap_path[i]);
    }


    /* Map them into the server */
    reservation_t server_res = vspace_reserve_range_at(&server_proc.process.vspace, (void *) TEST_VADDR_BASE,
    												   NUM_RUNS * PAGE_SIZE_4K, seL4_AllRights, 1);
    assert(server_res.res != 0);
	vspace_map_pages_at_vaddr(&server_proc.process.vspace, frame_caps, NULL, (void *) TEST_VADDR_BASE, NUM_RUNS,
					      PAGE_BITS_4K, server_res);
	for (int i = 0; i < NUM_RUNS; i++) {
		server_frame_caps[i] = sel4utils_copy_path_to_process(&server_proc.process, frame_cap_path[i]);
	}

    /* Map them into the harness and fill them with data */
    reservation_t own_data_res = vspace_reserve_range_at(&env->vspace, (void *) REMAP_TEST_VADDR_BASE,
											 			PAGE_SIZE_4K * NUM_RUNS, seL4_AllRights, 1);
    assert(own_data_res.res != 0);
	vspace_share_mem_at_vaddr(&server_proc.process.vspace, &env->vspace, (void *) TEST_VADDR_BASE,
						  	   NUM_RUNS, PAGE_BITS_4K,  (void *) REMAP_TEST_VADDR_BASE, server_res);
	for (int i = 0; i < NUM_RUNS; i++) {
		memcpy((void *) REMAP_TEST_VADDR_BASE + (i * PAGE_SIZE_4K), random_data, random_data_len);
	}

	/* Put them into the argv */
	for (int i = 0; i < NUM_RUNS; i++) {
		server_proc.argv[REMAP_CAP_BASE + i] = server_proc.argv_strings[REMAP_CAP_BASE + i];
        snprintf(server_proc.argv[REMAP_CAP_BASE + i], WORD_STRING_SIZE, "%"PRIuPTR"", server_frame_caps[i]);
	}

	run_bench_child_proc(env, &done_ep_path, results, &client_proc, &server_proc, NUM_REMAP_SERVER_ARGS);
}

static void run_scratch_benchmark(env_t *env, scratch_results_t *results) {
	cspacepath_t done_ep_path;

#ifdef CONFIG_ARCH_AARCH64
	/* Run copier benchmark (with cache clean/invalidate) */
	run_copier_benchmark(env, results->copier_flush, true);
#endif /* CONFIG_ARCH_AARCH64 */

	/* Run copier benchmark (no cache clean/invalidate) */
    run_copier_benchmark(env, results->copier_no_flush, false);

	/* Run remap benchmarks */
	run_remap_benchmark(env, results->remap);


	printf("Done start copier bench!!!\n");
}

int main(int argc, char **argv) {
    env_t *env;
    UNUSED int error;
    scratch_results_t *results;

    static size_t object_freq[seL4_ObjectTypeCount] = {

    };

    env = benchmark_get_env(argc, argv, sizeof(scratch_results_t), object_freq);
    results = (scratch_results_t *) env->results;

    sel4bench_init();

    run_scratch_benchmark(env, results);

    benchmark_finished(EXIT_SUCCESS);

    return 0;
}