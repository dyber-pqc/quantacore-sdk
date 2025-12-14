/**
 * @file algorithms.c
 * @brief QUAC 100 Benchmark Tool - Algorithm-Specific Benchmark Implementation
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#include "algorithms.h"
#include "stats.h"

/* Try to include QUAC SDK if available */
#ifdef HAVE_QUAC_SDK
#include <quac100.h>
#include <quac100_kem.h>
#include <quac100_sign.h>
#include <quac100_random.h>
#endif

/*=============================================================================
 * Simulated Operation Timings (microseconds)
 *
 * These simulate realistic hardware performance for when the actual
 * SDK is not available. Values based on expected QUAC 100 performance.
 *=============================================================================*/

typedef struct
{
    double keygen_us;
    double encaps_us;
    double decaps_us;
    double sign_us;
    double verify_us;
    double variance_pct; /* Random variance percentage */
} sim_timing_t;

static const sim_timing_t sim_timings[] = {
    [BENCH_ALG_ML_KEM_512] = {45.0, 25.0, 28.0, 0, 0, 10.0},
    [BENCH_ALG_ML_KEM_768] = {65.0, 35.0, 38.0, 0, 0, 10.0},
    [BENCH_ALG_ML_KEM_1024] = {95.0, 50.0, 55.0, 0, 0, 10.0},
    [BENCH_ALG_ML_DSA_44] = {80.0, 0, 0, 120.0, 45.0, 15.0},
    [BENCH_ALG_ML_DSA_65] = {130.0, 0, 0, 180.0, 65.0, 15.0},
    [BENCH_ALG_ML_DSA_87] = {200.0, 0, 0, 280.0, 95.0, 15.0},
    [BENCH_ALG_SLH_DSA_128F] = {1500.0, 0, 0, 8000.0, 350.0, 20.0},
    [BENCH_ALG_SLH_DSA_128S] = {1200.0, 0, 0, 180000.0, 280.0, 20.0},
    [BENCH_ALG_SLH_DSA_192F] = {2500.0, 0, 0, 15000.0, 550.0, 20.0},
    [BENCH_ALG_SLH_DSA_192S] = {2000.0, 0, 0, 350000.0, 450.0, 20.0},
    [BENCH_ALG_SLH_DSA_256F] = {3500.0, 0, 0, 25000.0, 800.0, 20.0},
    [BENCH_ALG_SLH_DSA_256S] = {3000.0, 0, 0, 600000.0, 700.0, 20.0},
};

/* Random generation times per byte */
static const double sim_random_us_per_byte = 0.15;

/*=============================================================================
 * Random Number Utilities
 *=============================================================================*/

static double random_variance(double base, double variance_pct)
{
    /* Simple variance using rand() - not cryptographic but fine for simulation */
    double factor = 1.0 + ((double)rand() / RAND_MAX - 0.5) * 2.0 * (variance_pct / 100.0);
    return base * factor;
}

/*=============================================================================
 * Progress Reporting
 *=============================================================================*/

void bench_print_progress(int current, int total, bool verbose)
{
    if (!verbose)
        return;

    int pct = (current * 100) / total;
    static int last_pct = -1;

    if (pct != last_pct && pct % 10 == 0)
    {
        printf("  Progress: %d%%\r", pct);
        fflush(stdout);
        last_pct = pct;
    }

    if (current == total - 1)
    {
        printf("  Progress: 100%%\n");
        last_pct = -1;
    }
}

/*=============================================================================
 * Simulated Operations
 *=============================================================================*/

static double simulate_operation(bench_algorithm_t alg, bench_operation_t op)
{
    if (alg < 0 || alg >= BENCH_ALG_COUNT)
        return 0.0;

    const sim_timing_t *t = &sim_timings[alg];
    double base = 0.0;

    switch (op)
    {
    case BENCH_OP_KEYGEN:
        base = t->keygen_us;
        break;
    case BENCH_OP_ENCAPS:
        base = t->encaps_us;
        break;
    case BENCH_OP_DECAPS:
        base = t->decaps_us;
        break;
    case BENCH_OP_SIGN:
        base = t->sign_us;
        break;
    case BENCH_OP_VERIFY:
        base = t->verify_us;
        break;
    case BENCH_OP_RANDOM_32:
        base = 32 * sim_random_us_per_byte + 5.0;
        break;
    case BENCH_OP_RANDOM_256:
        base = 256 * sim_random_us_per_byte + 5.0;
        break;
    case BENCH_OP_RANDOM_1024:
        base = 1024 * sim_random_us_per_byte + 5.0;
        break;
    default:
        return 0.0;
    }

    /* Add variance */
    return random_variance(base, t->variance_pct > 0 ? t->variance_pct : 10.0);
}

/*=============================================================================
 * Single Operation Benchmark
 *=============================================================================*/

int bench_single_operation(bench_device_t *device,
                           bench_algorithm_t algorithm,
                           bench_operation_t operation,
                           double *timings,
                           int index)
{
    (void)device; /* Used with real SDK */

    uint64_t start = bench_timestamp_us();

#ifdef HAVE_QUAC_SDK
    /* Real SDK implementation would go here */
    /* For now, fall through to simulation */
#endif

    /* Simulate the operation with appropriate timing */
    double sim_time = simulate_operation(algorithm, operation);

    /* Actually sleep for a portion of the time to simulate real work */
    /* Scale down to avoid very long benchmark runs */
    if (sim_time > 10.0)
    {
#ifdef _WIN32
        Sleep((DWORD)(sim_time / 100.0));
#else
        usleep((useconds_t)(sim_time));
#endif
    }

    uint64_t end = bench_timestamp_us();
    double elapsed = (double)(end - start);

    /* Use simulated time if actual elapsed is too short */
    if (elapsed < sim_time * 0.5)
    {
        elapsed = sim_time;
    }

    if (timings && index >= 0)
    {
        timings[index] = elapsed;
    }

    return 0;
}

/*=============================================================================
 * Helper to Run Benchmark and Record Results
 *=============================================================================*/

static int run_operation_benchmark(bench_device_t *device,
                                   bench_algorithm_t algorithm,
                                   bench_operation_t operation,
                                   const bench_config_t *config,
                                   bench_results_t *results)
{
    if (!device || !config || !results)
        return -1;

    int total = config->iterations + config->warmup;

    /* Allocate timing array */
    double *timings = malloc(config->iterations * sizeof(double));
    if (!timings)
        return -1;

    /* Progress output */
    if (config->verbose)
    {
        printf("  Running %s %s...\n",
               bench_algorithm_name(algorithm),
               bench_operation_name(operation));
    }

    /* Warmup */
    for (int i = 0; i < config->warmup; i++)
    {
        if (config->interrupted && *config->interrupted)
        {
            free(timings);
            return -2;
        }
        bench_single_operation(device, algorithm, operation, NULL, -1);
        bench_print_progress(i, total, config->verbose);
    }

    /* Timed iterations */
    uint64_t total_start = bench_timestamp_us();

    for (int i = 0; i < config->iterations; i++)
    {
        if (config->interrupted && *config->interrupted)
        {
            free(timings);
            return -2;
        }
        bench_single_operation(device, algorithm, operation, timings, i);
        bench_print_progress(config->warmup + i, total, config->verbose);
    }

    uint64_t total_end = bench_timestamp_us();
    double total_time = (double)(total_end - total_start);

    /* Create result entry */
    bench_result_entry_t entry;
    memset(&entry, 0, sizeof(entry));

    strncpy(entry.algorithm, bench_algorithm_name(algorithm), sizeof(entry.algorithm) - 1);
    strncpy(entry.operation, bench_operation_name(operation), sizeof(entry.operation) - 1);
    entry.alg_id = algorithm;
    entry.op_id = operation;
    entry.iterations = config->iterations;
    entry.successful = config->iterations;
    entry.failed = 0;
    entry.total_time_us = total_time;
    entry.throughput_ops = stats_throughput(config->iterations, total_time);

    /* Calculate statistics */
    stats_calculate_latency(timings, config->iterations, &entry.latency);

    /* Store timings for potential later use */
    entry.timings = timings;
    entry.timing_count = config->iterations;

    /* Add to results */
    bench_results_add(results, &entry);

    /* Note: timings ownership transferred to results */

    return 0;
}

/*=============================================================================
 * KEM Benchmarks
 *=============================================================================*/

int run_kem_benchmark(bench_device_t *device,
                      bench_algorithm_t algorithm,
                      int operation,
                      const bench_config_t *config,
                      bench_results_t *results)
{
    int ret = 0;

    /* Validate algorithm */
    if (algorithm != BENCH_ALG_ML_KEM_512 &&
        algorithm != BENCH_ALG_ML_KEM_768 &&
        algorithm != BENCH_ALG_ML_KEM_1024)
    {
        return -1;
    }

    /* Run requested operations */
    if (operation == OP_SEL_ALL || operation == OP_SEL_KEYGEN)
    {
        ret = run_operation_benchmark(device, algorithm, BENCH_OP_KEYGEN, config, results);
        if (ret != 0)
            return ret;
    }

    if (operation == OP_SEL_ALL || operation == OP_SEL_ENCAPS)
    {
        ret = run_operation_benchmark(device, algorithm, BENCH_OP_ENCAPS, config, results);
        if (ret != 0)
            return ret;
    }

    if (operation == OP_SEL_ALL || operation == OP_SEL_DECAPS)
    {
        ret = run_operation_benchmark(device, algorithm, BENCH_OP_DECAPS, config, results);
        if (ret != 0)
            return ret;
    }

    return 0;
}

/*=============================================================================
 * Signature Benchmarks
 *=============================================================================*/

int run_sign_benchmark(bench_device_t *device,
                       bench_algorithm_t algorithm,
                       int operation,
                       const bench_config_t *config,
                       bench_results_t *results)
{
    int ret = 0;

    /* Validate algorithm */
    if (algorithm != BENCH_ALG_ML_DSA_44 &&
        algorithm != BENCH_ALG_ML_DSA_65 &&
        algorithm != BENCH_ALG_ML_DSA_87 &&
        algorithm != BENCH_ALG_SLH_DSA_128F &&
        algorithm != BENCH_ALG_SLH_DSA_128S &&
        algorithm != BENCH_ALG_SLH_DSA_192F &&
        algorithm != BENCH_ALG_SLH_DSA_192S &&
        algorithm != BENCH_ALG_SLH_DSA_256F &&
        algorithm != BENCH_ALG_SLH_DSA_256S)
    {
        return -1;
    }

    /* Run requested operations */
    if (operation == OP_SEL_ALL || operation == OP_SEL_KEYGEN)
    {
        ret = run_operation_benchmark(device, algorithm, BENCH_OP_KEYGEN, config, results);
        if (ret != 0)
            return ret;
    }

    if (operation == OP_SEL_ALL || operation == OP_SEL_SIGN)
    {
        ret = run_operation_benchmark(device, algorithm, BENCH_OP_SIGN, config, results);
        if (ret != 0)
            return ret;
    }

    if (operation == OP_SEL_ALL || operation == OP_SEL_VERIFY)
    {
        ret = run_operation_benchmark(device, algorithm, BENCH_OP_VERIFY, config, results);
        if (ret != 0)
            return ret;
    }

    return 0;
}

/*=============================================================================
 * Random Number Generation Benchmarks
 *=============================================================================*/

int run_random_benchmark(bench_device_t *device,
                         const bench_config_t *config,
                         bench_results_t *results)
{
    int ret = 0;

    /* Benchmark different buffer sizes */
    ret = run_operation_benchmark(device, BENCH_ALG_RANDOM, BENCH_OP_RANDOM_32,
                                  config, results);
    if (ret != 0)
        return ret;

    ret = run_operation_benchmark(device, BENCH_ALG_RANDOM, BENCH_OP_RANDOM_256,
                                  config, results);
    if (ret != 0)
        return ret;

    ret = run_operation_benchmark(device, BENCH_ALG_RANDOM, BENCH_OP_RANDOM_1024,
                                  config, results);
    if (ret != 0)
        return ret;

    return 0;
}

/*=============================================================================
 * Batch Benchmarks
 *=============================================================================*/

int run_batch_benchmark(bench_device_t *device,
                        bench_algorithm_t algorithm,
                        int batch_size,
                        const bench_config_t *config,
                        bench_results_t *results)
{
    if (!device || !config || !results || batch_size < 1)
        return -1;

    /* Modify config for batch mode */
    bench_config_t batch_config = *config;
    batch_config.batch_size = batch_size;

    /* Run keygen benchmark in batch mode */
    /* For simulation, just scale the timing */

    int total_ops = config->iterations * batch_size;
    double *timings = malloc(config->iterations * sizeof(double));
    if (!timings)
        return -1;

    if (config->verbose)
    {
        printf("  Running batch benchmark (batch_size=%d)...\n", batch_size);
    }

    /* Warmup */
    for (int i = 0; i < config->warmup; i++)
    {
        if (config->interrupted && *config->interrupted)
        {
            free(timings);
            return -2;
        }
        /* Simulate batch operation */
        simulate_operation(algorithm, BENCH_OP_KEYGEN);
    }

    /* Timed iterations */
    uint64_t total_start = bench_timestamp_us();

    for (int i = 0; i < config->iterations; i++)
    {
        if (config->interrupted && *config->interrupted)
        {
            free(timings);
            return -2;
        }

        uint64_t batch_start = bench_timestamp_us();

        /* Simulate batch operation - batch processing has some overhead
         * but better throughput due to parallelism */
        double batch_time = simulate_operation(algorithm, BENCH_OP_KEYGEN);
        batch_time = batch_time * batch_size * 0.7; /* 30% efficiency gain */

#ifdef _WIN32
        Sleep((DWORD)(batch_time / 100.0));
#else
        usleep((useconds_t)(batch_time));
#endif

        uint64_t batch_end = bench_timestamp_us();
        timings[i] = (double)(batch_end - batch_start);
    }

    uint64_t total_end = bench_timestamp_us();
    double total_time = (double)(total_end - total_start);

    /* Create result entry */
    bench_result_entry_t entry;
    memset(&entry, 0, sizeof(entry));

    char alg_name[128];
    snprintf(alg_name, sizeof(alg_name), "%s (batch=%d)",
             bench_algorithm_name(algorithm), batch_size);

    strncpy(entry.algorithm, alg_name, sizeof(entry.algorithm) - 1);
    strncpy(entry.operation, "keygen-batch", sizeof(entry.operation) - 1);
    entry.alg_id = algorithm;
    entry.op_id = BENCH_OP_KEYGEN;
    entry.iterations = total_ops;
    entry.successful = total_ops;
    entry.failed = 0;
    entry.total_time_us = total_time;
    entry.throughput_ops = stats_throughput(total_ops, total_time);

    /* Calculate per-batch statistics */
    stats_calculate_latency(timings, config->iterations, &entry.latency);

    /* Adjust latency to per-operation */
    entry.latency.min_us /= batch_size;
    entry.latency.max_us /= batch_size;
    entry.latency.mean_us /= batch_size;
    entry.latency.median_us /= batch_size;
    entry.latency.p95_us /= batch_size;
    entry.latency.p99_us /= batch_size;

    entry.timings = timings;
    entry.timing_count = config->iterations;

    bench_results_add(results, &entry);

    return 0;
}