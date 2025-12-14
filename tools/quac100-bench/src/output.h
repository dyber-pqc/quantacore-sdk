/**
 * @file output.h
 * @brief QUAC 100 Benchmark Tool - Output Formatting Module
 *
 * Output formatting for benchmark results in various formats:
 * text, JSON, CSV, and Markdown.
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC_BENCH_OUTPUT_H
#define QUAC_BENCH_OUTPUT_H

#include <stdio.h>
#include "benchmark.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /*=============================================================================
     * Output Format
     *=============================================================================*/

    typedef enum
    {
        OUTPUT_FMT_TEXT = 0,
        OUTPUT_FMT_JSON,
        OUTPUT_FMT_CSV,
        OUTPUT_FMT_MARKDOWN
    } output_format_t;

    /*=============================================================================
     * Output Context
     *=============================================================================*/

    typedef struct output_context output_context_t;

    /*=============================================================================
     * Output Management
     *=============================================================================*/

    /**
     * @brief Create output context
     * @param filename Output filename (NULL for stdout)
     * @param format Output format
     * @return Output context or NULL on failure
     */
    output_context_t *output_create(const char *filename, output_format_t format);

    /**
     * @brief Destroy output context
     * @param ctx Output context
     */
    void output_destroy(output_context_t *ctx);

    /*=============================================================================
     * Result Output
     *=============================================================================*/

    /**
     * @brief Write benchmark results
     * @param ctx Output context
     * @param results Benchmark results
     * @param device Device that was benchmarked
     */
    void output_write_results(output_context_t *ctx,
                              const bench_results_t *results,
                              const bench_device_t *device);

    /**
     * @brief Write comparison between current and baseline results
     * @param ctx Output context
     * @param current Current results
     * @param baseline Baseline results
     */
    void output_write_comparison(output_context_t *ctx,
                                 const bench_results_t *current,
                                 const bench_results_t *baseline);

    /*=============================================================================
     * Format-Specific Writers
     *=============================================================================*/

    /**
     * @brief Write results as plain text
     */
    void output_write_text(FILE *f, const bench_results_t *results,
                           const device_info_t *device);

    /**
     * @brief Write results as JSON
     */
    void output_write_json(FILE *f, const bench_results_t *results,
                           const device_info_t *device);

    /**
     * @brief Write results as CSV
     */
    void output_write_csv(FILE *f, const bench_results_t *results,
                          const device_info_t *device);

    /**
     * @brief Write results as Markdown
     */
    void output_write_markdown(FILE *f, const bench_results_t *results,
                               const device_info_t *device);

    /*=============================================================================
     * Utility Functions
     *=============================================================================*/

    /**
     * @brief Format number with thousands separator
     * @param value Number to format
     * @param buffer Output buffer
     * @param size Buffer size
     * @return Pointer to buffer
     */
    char *output_format_number(double value, char *buffer, size_t size);

    /**
     * @brief Format duration in appropriate units
     * @param us Duration in microseconds
     * @param buffer Output buffer
     * @param size Buffer size
     * @return Pointer to buffer
     */
    char *output_format_duration(double us, char *buffer, size_t size);

    /**
     * @brief Format throughput with units
     * @param ops_per_sec Operations per second
     * @param buffer Output buffer
     * @param size Buffer size
     * @return Pointer to buffer
     */
    char *output_format_throughput(double ops_per_sec, char *buffer, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* QUAC_BENCH_OUTPUT_H */