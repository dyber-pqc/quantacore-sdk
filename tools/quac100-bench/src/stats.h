/**
 * @file stats.h
 * @brief QUAC 100 Benchmark Tool - Statistics Module
 *
 * Statistical analysis functions for benchmark results including
 * mean, median, standard deviation, and percentile calculations.
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC_BENCH_STATS_H
#define QUAC_BENCH_STATS_H

#include <stddef.h>
#include "benchmark.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /*=============================================================================
     * Basic Statistics
     *=============================================================================*/

    /**
     * @brief Calculate minimum value
     * @param data Array of values
     * @param count Number of values
     * @return Minimum value
     */
    double stats_min(const double *data, size_t count);

    /**
     * @brief Calculate maximum value
     * @param data Array of values
     * @param count Number of values
     * @return Maximum value
     */
    double stats_max(const double *data, size_t count);

    /**
     * @brief Calculate arithmetic mean
     * @param data Array of values
     * @param count Number of values
     * @return Mean value
     */
    double stats_mean(const double *data, size_t count);

    /**
     * @brief Calculate median value
     * @param data Array of values (will be modified/sorted)
     * @param count Number of values
     * @return Median value
     */
    double stats_median(double *data, size_t count);

    /**
     * @brief Calculate standard deviation
     * @param data Array of values
     * @param count Number of values
     * @return Standard deviation
     */
    double stats_stddev(const double *data, size_t count);

    /**
     * @brief Calculate variance
     * @param data Array of values
     * @param count Number of values
     * @return Variance
     */
    double stats_variance(const double *data, size_t count);

    /*=============================================================================
     * Percentile Calculations
     *=============================================================================*/

    /**
     * @brief Calculate percentile value
     * @param data Array of values (will be modified/sorted)
     * @param count Number of values
     * @param percentile Percentile (0-100)
     * @return Percentile value
     */
    double stats_percentile(double *data, size_t count, double percentile);

    /**
     * @brief Calculate P95 (95th percentile)
     * @param data Array of values
     * @param count Number of values
     * @return P95 value
     */
    double stats_p95(double *data, size_t count);

    /**
     * @brief Calculate P99 (99th percentile)
     * @param data Array of values
     * @param count Number of values
     * @return P99 value
     */
    double stats_p99(double *data, size_t count);

    /**
     * @brief Calculate P99.9 (99.9th percentile)
     * @param data Array of values
     * @param count Number of values
     * @return P99.9 value
     */
    double stats_p999(double *data, size_t count);

    /*=============================================================================
     * Full Statistics Calculation
     *=============================================================================*/

    /**
     * @brief Calculate all latency statistics
     * @param data Array of timing values in microseconds
     * @param count Number of values
     * @param stats Output statistics structure
     */
    void stats_calculate_latency(double *data, size_t count, latency_stats_t *stats);

    /**
     * @brief Calculate throughput from total time
     * @param iterations Number of operations
     * @param total_time_us Total elapsed time in microseconds
     * @return Operations per second
     */
    double stats_throughput(int iterations, double total_time_us);

    /*=============================================================================
     * Comparison Utilities
     *=============================================================================*/

    /**
     * @brief Calculate percentage change
     * @param baseline Baseline value
     * @param current Current value
     * @return Percentage change (positive = improvement)
     */
    double stats_percent_change(double baseline, double current);

    /**
     * @brief Calculate speedup factor
     * @param baseline Baseline value
     * @param current Current value
     * @return Speedup factor (>1 = faster)
     */
    double stats_speedup(double baseline, double current);

#ifdef __cplusplus
}
#endif

#endif /* QUAC_BENCH_STATS_H */