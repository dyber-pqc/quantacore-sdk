/**
 * @file algorithms.h
 * @brief QUAC 100 Benchmark Tool - Algorithm-Specific Benchmarks
 *
 * Benchmark implementations for KEM, signature, and random algorithms.
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC_BENCH_ALGORITHMS_H
#define QUAC_BENCH_ALGORITHMS_H

#include "benchmark.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*=============================================================================
 * Operation Selection (from main.c)
 *=============================================================================*/

/* These match the enum in main.c */
#define OP_SEL_ALL 0
#define OP_SEL_KEYGEN 1
#define OP_SEL_ENCAPS 2
#define OP_SEL_DECAPS 3
#define OP_SEL_SIGN 4
#define OP_SEL_VERIFY 5
#define OP_SEL_RANDOM 6

    /*=============================================================================
     * KEM Benchmarks
     *=============================================================================*/

    /**
     * @brief Run KEM algorithm benchmark
     *
     * Benchmarks keygen, encaps, and decaps operations for the specified
     * KEM algorithm.
     *
     * @param device Device to benchmark
     * @param algorithm KEM algorithm (ML-KEM-512/768/1024)
     * @param operation Operation filter (OP_SEL_ALL, OP_SEL_KEYGEN, etc.)
     * @param config Benchmark configuration
     * @param results Output results container
     * @return 0 on success
     */
    int run_kem_benchmark(bench_device_t *device,
                          bench_algorithm_t algorithm,
                          int operation,
                          const bench_config_t *config,
                          bench_results_t *results);

    /*=============================================================================
     * Signature Benchmarks
     *=============================================================================*/

    /**
     * @brief Run signature algorithm benchmark
     *
     * Benchmarks keygen, sign, and verify operations for the specified
     * signature algorithm.
     *
     * @param device Device to benchmark
     * @param algorithm Signature algorithm (ML-DSA, SLH-DSA)
     * @param operation Operation filter
     * @param config Benchmark configuration
     * @param results Output results container
     * @return 0 on success
     */
    int run_sign_benchmark(bench_device_t *device,
                           bench_algorithm_t algorithm,
                           int operation,
                           const bench_config_t *config,
                           bench_results_t *results);

    /*=============================================================================
     * Random Number Generation Benchmarks
     *=============================================================================*/

    /**
     * @brief Run QRNG benchmark
     *
     * Benchmarks random number generation at various buffer sizes.
     *
     * @param device Device to benchmark
     * @param config Benchmark configuration
     * @param results Output results container
     * @return 0 on success
     */
    int run_random_benchmark(bench_device_t *device,
                             const bench_config_t *config,
                             bench_results_t *results);

    /*=============================================================================
     * Batch Benchmarks
     *=============================================================================*/

    /**
     * @brief Run batch operation benchmark
     *
     * Benchmarks operations in batch mode to measure throughput scaling.
     *
     * @param device Device to benchmark
     * @param algorithm Algorithm to test
     * @param batch_size Number of operations per batch
     * @param config Benchmark configuration
     * @param results Output results container
     * @return 0 on success
     */
    int run_batch_benchmark(bench_device_t *device,
                            bench_algorithm_t algorithm,
                            int batch_size,
                            const bench_config_t *config,
                            bench_results_t *results);

    /*=============================================================================
     * Utility Functions
     *=============================================================================*/

    /**
     * @brief Run a single benchmark iteration
     *
     * Internal helper to run one benchmark operation and record timing.
     *
     * @param device Device handle
     * @param algorithm Algorithm ID
     * @param operation Operation ID
     * @param timings Output timing array
     * @param index Current iteration index
     * @return 0 on success, negative on error
     */
    int bench_single_operation(bench_device_t *device,
                               bench_algorithm_t algorithm,
                               bench_operation_t operation,
                               double *timings,
                               int index);

    /**
     * @brief Print progress indicator
     *
     * @param current Current iteration
     * @param total Total iterations
     * @param verbose Verbose mode enabled
     */
    void bench_print_progress(int current, int total, bool verbose);

#ifdef __cplusplus
}
#endif

#endif /* QUAC_BENCH_ALGORITHMS_H */