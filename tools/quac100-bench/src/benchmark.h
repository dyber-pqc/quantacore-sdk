/**
 * @file benchmark.h
 * @brief QUAC 100 Benchmark Tool - Core Benchmark Engine
 *
 * Core benchmarking infrastructure including timing, device management,
 * and result collection.
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC_BENCH_BENCHMARK_H
#define QUAC_BENCH_BENCHMARK_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <signal.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /*=============================================================================
     * Constants
     *=============================================================================*/

#define MAX_ALGORITHM_NAME 64
#define MAX_OPERATION_NAME 32
#define MAX_DEVICE_NAME 64
#define MAX_VERSION_STRING 32
#define MAX_SERIAL_NUMBER 64
#define MAX_RESULTS 128

    /*=============================================================================
     * Algorithm Identifiers
     *=============================================================================*/

    typedef enum
    {
        BENCH_ALG_UNKNOWN = 0,

        /* KEM algorithms */
        BENCH_ALG_ML_KEM_512,
        BENCH_ALG_ML_KEM_768,
        BENCH_ALG_ML_KEM_1024,

        /* Signature algorithms */
        BENCH_ALG_ML_DSA_44,
        BENCH_ALG_ML_DSA_65,
        BENCH_ALG_ML_DSA_87,

        /* SLH-DSA variants */
        BENCH_ALG_SLH_DSA_128F,
        BENCH_ALG_SLH_DSA_128S,
        BENCH_ALG_SLH_DSA_192F,
        BENCH_ALG_SLH_DSA_192S,
        BENCH_ALG_SLH_DSA_256F,
        BENCH_ALG_SLH_DSA_256S,

        /* Random */
        BENCH_ALG_RANDOM,

        BENCH_ALG_COUNT
    } bench_algorithm_t;

    /*=============================================================================
     * Operation Types
     *=============================================================================*/

    typedef enum
    {
        BENCH_OP_UNKNOWN = 0,
        BENCH_OP_KEYGEN,
        BENCH_OP_ENCAPS,
        BENCH_OP_DECAPS,
        BENCH_OP_SIGN,
        BENCH_OP_VERIFY,
        BENCH_OP_RANDOM_32,
        BENCH_OP_RANDOM_256,
        BENCH_OP_RANDOM_1024,
        BENCH_OP_COUNT
    } bench_operation_t;

    /*=============================================================================
     * Device Information
     *=============================================================================*/

    typedef struct
    {
        char name[MAX_DEVICE_NAME];
        char firmware_version[MAX_VERSION_STRING];
        char serial_number[MAX_SERIAL_NUMBER];
        int index;
        bool available;
        bool is_simulator;
    } device_info_t;

    /*=============================================================================
     * Latency Statistics
     *=============================================================================*/

    typedef struct
    {
        double min_us;
        double max_us;
        double mean_us;
        double median_us;
        double stddev_us;
        double p95_us;
        double p99_us;
        double p999_us;
    } latency_stats_t;

    /*=============================================================================
     * Single Result Entry
     *=============================================================================*/

    typedef struct
    {
        char algorithm[MAX_ALGORITHM_NAME];
        char operation[MAX_OPERATION_NAME];

        bench_algorithm_t alg_id;
        bench_operation_t op_id;

        int iterations;
        int successful;
        int failed;

        double total_time_us;
        double throughput_ops;

        latency_stats_t latency;

        /* Raw timing data for percentile calculations */
        double *timings;
        int timing_count;
    } bench_result_entry_t;

    /*=============================================================================
     * Results Collection
     *=============================================================================*/

    typedef struct
    {
        /* Device info */
        device_info_t device;

        /* Benchmark parameters */
        int iterations;
        int warmup;
        int threads;
        int batch_size;

        /* Timestamp */
        time_t timestamp;

        /* Results array */
        bench_result_entry_t *entries;
        int entry_count;
        int entry_capacity;
    } bench_results_t;

    /*=============================================================================
     * Benchmark Configuration
     *=============================================================================*/

    typedef struct
    {
        int iterations;
        int warmup;
        int threads;
        int batch_size;
        bool verbose;
        volatile sig_atomic_t *interrupted;
    } bench_config_t;

    /*=============================================================================
     * Opaque Types
     *=============================================================================*/

    typedef struct bench_context bench_context_t;
    typedef struct bench_device bench_device_t;

    /*=============================================================================
     * Context Management
     *=============================================================================*/

    /**
     * @brief Initialize benchmark context
     * @return Context handle or NULL on failure
     */
    bench_context_t *bench_init(void);

    /**
     * @brief Cleanup benchmark context
     * @param ctx Context handle
     */
    void bench_cleanup(bench_context_t *ctx);

    /*=============================================================================
     * Device Management
     *=============================================================================*/

    /**
     * @brief Get number of available devices
     * @param ctx Context handle
     * @return Number of devices
     */
    int bench_get_device_count(bench_context_t *ctx);

    /**
     * @brief Get device information
     * @param ctx Context handle
     * @param index Device index
     * @param info Output device information
     * @return 0 on success
     */
    int bench_get_device_info(bench_context_t *ctx, int index, device_info_t *info);

    /**
     * @brief Open a hardware device
     * @param ctx Context handle
     * @param index Device index
     * @return Device handle or NULL
     */
    bench_device_t *bench_open_device(bench_context_t *ctx, int index);

    /**
     * @brief Open the software simulator
     * @param ctx Context handle
     * @return Device handle or NULL
     */
    bench_device_t *bench_open_simulator(bench_context_t *ctx);

    /**
     * @brief Close a device
     * @param device Device handle
     */
    void bench_close_device(bench_device_t *device);

    /**
     * @brief Get device info from open device
     * @param device Device handle
     * @param info Output device information
     * @return 0 on success
     */
    int bench_get_device_info_from_device(bench_device_t *device, device_info_t *info);

    /*=============================================================================
     * Results Management
     *=============================================================================*/

    /**
     * @brief Create results container
     * @return Results handle or NULL
     */
    bench_results_t *bench_results_create(void);

    /**
     * @brief Destroy results container
     * @param results Results handle
     */
    void bench_results_destroy(bench_results_t *results);

    /**
     * @brief Add a result entry
     * @param results Results container
     * @param entry Entry to add
     * @return 0 on success
     */
    int bench_results_add(bench_results_t *results, const bench_result_entry_t *entry);

    /**
     * @brief Load results from file
     * @param filename Path to results file
     * @return Results handle or NULL
     */
    bench_results_t *bench_results_load(const char *filename);

    /**
     * @brief Save results to file
     * @param results Results handle
     * @param filename Output path
     * @return 0 on success
     */
    int bench_results_save(const bench_results_t *results, const char *filename);

    /*=============================================================================
     * Timing Utilities
     *=============================================================================*/

    /**
     * @brief Get current timestamp in microseconds
     * @return Timestamp in microseconds
     */
    uint64_t bench_timestamp_us(void);

    /**
     * @brief Get algorithm name string
     * @param alg Algorithm ID
     * @return Algorithm name
     */
    const char *bench_algorithm_name(bench_algorithm_t alg);

    /**
     * @brief Get operation name string
     * @param op Operation ID
     * @return Operation name
     */
    const char *bench_operation_name(bench_operation_t op);

#ifdef __cplusplus
}
#endif

#endif /* QUAC_BENCH_BENCHMARK_H */