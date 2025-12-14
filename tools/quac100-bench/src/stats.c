/**
 * @file stats.c
 * @brief QUAC 100 Benchmark Tool - Statistics Module Implementation
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <float.h>

#include "stats.h"

/*=============================================================================
 * Sorting Utility
 *=============================================================================*/

static int compare_double(const void *a, const void *b)
{
    double da = *(const double *)a;
    double db = *(const double *)b;

    if (da < db)
        return -1;
    if (da > db)
        return 1;
    return 0;
}

static void sort_double_array(double *data, size_t count)
{
    qsort(data, count, sizeof(double), compare_double);
}

/*=============================================================================
 * Basic Statistics
 *=============================================================================*/

double stats_min(const double *data, size_t count)
{
    if (!data || count == 0)
        return 0.0;

    double min = DBL_MAX;
    for (size_t i = 0; i < count; i++)
    {
        if (data[i] < min)
        {
            min = data[i];
        }
    }
    return min;
}

double stats_max(const double *data, size_t count)
{
    if (!data || count == 0)
        return 0.0;

    double max = -DBL_MAX;
    for (size_t i = 0; i < count; i++)
    {
        if (data[i] > max)
        {
            max = data[i];
        }
    }
    return max;
}

double stats_mean(const double *data, size_t count)
{
    if (!data || count == 0)
        return 0.0;

    double sum = 0.0;
    for (size_t i = 0; i < count; i++)
    {
        sum += data[i];
    }
    return sum / (double)count;
}

double stats_median(double *data, size_t count)
{
    if (!data || count == 0)
        return 0.0;

    /* Work on a copy to preserve original */
    double *sorted = malloc(count * sizeof(double));
    if (!sorted)
        return 0.0;

    memcpy(sorted, data, count * sizeof(double));
    sort_double_array(sorted, count);

    double median;
    if (count % 2 == 0)
    {
        /* Average of two middle values */
        median = (sorted[count / 2 - 1] + sorted[count / 2]) / 2.0;
    }
    else
    {
        /* Middle value */
        median = sorted[count / 2];
    }

    free(sorted);
    return median;
}

double stats_variance(const double *data, size_t count)
{
    if (!data || count < 2)
        return 0.0;

    double mean = stats_mean(data, count);
    double sum_sq = 0.0;

    for (size_t i = 0; i < count; i++)
    {
        double diff = data[i] - mean;
        sum_sq += diff * diff;
    }

    /* Sample variance (n-1 denominator) */
    return sum_sq / (double)(count - 1);
}

double stats_stddev(const double *data, size_t count)
{
    return sqrt(stats_variance(data, count));
}

/*=============================================================================
 * Percentile Calculations
 *=============================================================================*/

double stats_percentile(double *data, size_t count, double percentile)
{
    if (!data || count == 0)
        return 0.0;
    if (percentile < 0)
        percentile = 0;
    if (percentile > 100)
        percentile = 100;

    /* Work on a copy */
    double *sorted = malloc(count * sizeof(double));
    if (!sorted)
        return 0.0;

    memcpy(sorted, data, count * sizeof(double));
    sort_double_array(sorted, count);

    /* Linear interpolation method */
    double rank = (percentile / 100.0) * (count - 1);
    size_t lower = (size_t)floor(rank);
    size_t upper = (size_t)ceil(rank);

    double result;
    if (lower == upper)
    {
        result = sorted[lower];
    }
    else
    {
        double frac = rank - lower;
        result = sorted[lower] * (1.0 - frac) + sorted[upper] * frac;
    }

    free(sorted);
    return result;
}

double stats_p95(double *data, size_t count)
{
    return stats_percentile(data, count, 95.0);
}

double stats_p99(double *data, size_t count)
{
    return stats_percentile(data, count, 99.0);
}

double stats_p999(double *data, size_t count)
{
    return stats_percentile(data, count, 99.9);
}

/*=============================================================================
 * Full Statistics Calculation
 *=============================================================================*/

void stats_calculate_latency(double *data, size_t count, latency_stats_t *stats)
{
    if (!data || count == 0 || !stats)
    {
        if (stats)
            memset(stats, 0, sizeof(*stats));
        return;
    }

    stats->min_us = stats_min(data, count);
    stats->max_us = stats_max(data, count);
    stats->mean_us = stats_mean(data, count);
    stats->median_us = stats_median(data, count);
    stats->stddev_us = stats_stddev(data, count);
    stats->p95_us = stats_p95(data, count);
    stats->p99_us = stats_p99(data, count);
    stats->p999_us = stats_p999(data, count);
}

double stats_throughput(int iterations, double total_time_us)
{
    if (total_time_us <= 0)
        return 0.0;

    /* Convert to operations per second */
    return (double)iterations / (total_time_us / 1000000.0);
}

/*=============================================================================
 * Comparison Utilities
 *=============================================================================*/

double stats_percent_change(double baseline, double current)
{
    if (baseline == 0)
        return 0.0;

    /* For latency: negative change is improvement (faster) */
    /* For throughput: positive change is improvement (more ops/s) */
    return ((baseline - current) / baseline) * 100.0;
}

double stats_speedup(double baseline, double current)
{
    if (current == 0)
        return 0.0;

    /* For latency comparisons: baseline/current gives speedup */
    return baseline / current;
}