/**
 * @file output.c
 * @brief QUAC 100 Benchmark Tool - Output Formatting Implementation
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "output.h"
#include "stats.h"

/*=============================================================================
 * Output Context Structure
 *=============================================================================*/

struct output_context
{
    FILE *file;
    output_format_t format;
    bool owns_file;
};

/*=============================================================================
 * Output Management
 *=============================================================================*/

output_context_t *output_create(const char *filename, output_format_t format)
{
    output_context_t *ctx = calloc(1, sizeof(output_context_t));
    if (!ctx)
        return NULL;

    ctx->format = format;

    if (filename && filename[0])
    {
        ctx->file = fopen(filename, "w");
        if (!ctx->file)
        {
            free(ctx);
            return NULL;
        }
        ctx->owns_file = true;
    }
    else
    {
        ctx->file = stdout;
        ctx->owns_file = false;
    }

    return ctx;
}

void output_destroy(output_context_t *ctx)
{
    if (!ctx)
        return;

    if (ctx->owns_file && ctx->file)
    {
        fclose(ctx->file);
    }

    free(ctx);
}

/*=============================================================================
 * Utility Functions
 *=============================================================================*/

char *output_format_number(double value, char *buffer, size_t size)
{
    if (!buffer || size == 0)
        return buffer;

    /* Format with commas as thousands separator */
    char temp[64];
    snprintf(temp, sizeof(temp), "%.0f", value);

    int len = strlen(temp);
    int commas = (len - 1) / 3;
    int result_len = len + commas;

    if ((size_t)result_len >= size)
    {
        /* Fall back to simple format */
        snprintf(buffer, size, "%.0f", value);
        return buffer;
    }

    int j = result_len;
    buffer[j--] = '\0';

    int count = 0;
    for (int i = len - 1; i >= 0; i--)
    {
        buffer[j--] = temp[i];
        count++;
        if (count == 3 && i > 0)
        {
            buffer[j--] = ',';
            count = 0;
        }
    }

    return buffer;
}

char *output_format_duration(double us, char *buffer, size_t size)
{
    if (!buffer || size == 0)
        return buffer;

    if (us < 1.0)
    {
        snprintf(buffer, size, "%.2f ns", us * 1000.0);
    }
    else if (us < 1000.0)
    {
        snprintf(buffer, size, "%.2f µs", us);
    }
    else if (us < 1000000.0)
    {
        snprintf(buffer, size, "%.2f ms", us / 1000.0);
    }
    else
    {
        snprintf(buffer, size, "%.2f s", us / 1000000.0);
    }

    return buffer;
}

char *output_format_throughput(double ops_per_sec, char *buffer, size_t size)
{
    if (!buffer || size == 0)
        return buffer;

    if (ops_per_sec < 1000.0)
    {
        snprintf(buffer, size, "%.1f ops/s", ops_per_sec);
    }
    else if (ops_per_sec < 1000000.0)
    {
        snprintf(buffer, size, "%.2f Kops/s", ops_per_sec / 1000.0);
    }
    else
    {
        snprintf(buffer, size, "%.2f Mops/s", ops_per_sec / 1000000.0);
    }

    return buffer;
}

/*=============================================================================
 * Text Output
 *=============================================================================*/

void output_write_text(FILE *f, const bench_results_t *results,
                       const device_info_t *device)
{
    char buf[64];
    char time_buf[64];

    /* Header */
    fprintf(f, "QUAC 100 Benchmark Results\n");
    fprintf(f, "==========================\n\n");

    /* Device info */
    if (device)
    {
        fprintf(f, "Device: %s\n", device->name);
        fprintf(f, "Firmware: %s\n", device->firmware_version);
        fprintf(f, "Serial: %s\n", device->serial_number);
    }

    /* Timestamp */
    struct tm *tm_info = localtime(&results->timestamp);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
    fprintf(f, "Date: %s\n", time_buf);
    fprintf(f, "\n");

    /* Parameters */
    fprintf(f, "Parameters:\n");
    fprintf(f, "  Iterations: %s\n", output_format_number(results->iterations, buf, sizeof(buf)));
    fprintf(f, "  Warmup: %d\n", results->warmup);
    fprintf(f, "  Threads: %d\n", results->threads);
    fprintf(f, "  Batch size: %d\n\n", results->batch_size);

    /* Results */
    for (int i = 0; i < results->entry_count; i++)
    {
        const bench_result_entry_t *e = &results->entries[i];

        fprintf(f, "%s %s\n", e->algorithm, e->operation);
        fprintf(f, "----------------------------------------\n");
        fprintf(f, "  Iterations:  %s\n",
                output_format_number(e->iterations, buf, sizeof(buf)));
        fprintf(f, "  Total time:  %s\n",
                output_format_duration(e->total_time_us, buf, sizeof(buf)));
        fprintf(f, "  Throughput:  %s\n",
                output_format_throughput(e->throughput_ops, buf, sizeof(buf)));
        fprintf(f, "  Latency:\n");
        fprintf(f, "    Min:       %s\n",
                output_format_duration(e->latency.min_us, buf, sizeof(buf)));
        fprintf(f, "    Max:       %s\n",
                output_format_duration(e->latency.max_us, buf, sizeof(buf)));
        fprintf(f, "    Mean:      %s\n",
                output_format_duration(e->latency.mean_us, buf, sizeof(buf)));
        fprintf(f, "    Median:    %s\n",
                output_format_duration(e->latency.median_us, buf, sizeof(buf)));
        fprintf(f, "    Std Dev:   %s\n",
                output_format_duration(e->latency.stddev_us, buf, sizeof(buf)));
        fprintf(f, "    P95:       %s\n",
                output_format_duration(e->latency.p95_us, buf, sizeof(buf)));
        fprintf(f, "    P99:       %s\n",
                output_format_duration(e->latency.p99_us, buf, sizeof(buf)));
        fprintf(f, "\n");
    }
}

/*=============================================================================
 * JSON Output
 *=============================================================================*/

static void json_escape_string(FILE *f, const char *str)
{
    while (*str)
    {
        switch (*str)
        {
        case '"':
            fprintf(f, "\\\"");
            break;
        case '\\':
            fprintf(f, "\\\\");
            break;
        case '\n':
            fprintf(f, "\\n");
            break;
        case '\r':
            fprintf(f, "\\r");
            break;
        case '\t':
            fprintf(f, "\\t");
            break;
        default:
            fputc(*str, f);
            break;
        }
        str++;
    }
}

void output_write_json(FILE *f, const bench_results_t *results,
                       const device_info_t *device)
{
    char time_buf[64];

    fprintf(f, "{\n");

    /* Device */
    fprintf(f, "  \"device\": {\n");
    if (device)
    {
        fprintf(f, "    \"name\": \"");
        json_escape_string(f, device->name);
        fprintf(f, "\",\n");
        fprintf(f, "    \"firmware\": \"%s\",\n", device->firmware_version);
        fprintf(f, "    \"serial\": \"%s\",\n", device->serial_number);
        fprintf(f, "    \"simulator\": %s\n", device->is_simulator ? "true" : "false");
    }
    fprintf(f, "  },\n");

    /* Timestamp */
    struct tm *tm_info = gmtime(&results->timestamp);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%dT%H:%M:%SZ", tm_info);
    fprintf(f, "  \"timestamp\": \"%s\",\n", time_buf);

    /* Parameters */
    fprintf(f, "  \"parameters\": {\n");
    fprintf(f, "    \"iterations\": %d,\n", results->iterations);
    fprintf(f, "    \"warmup\": %d,\n", results->warmup);
    fprintf(f, "    \"threads\": %d,\n", results->threads);
    fprintf(f, "    \"batch_size\": %d\n", results->batch_size);
    fprintf(f, "  },\n");

    /* Results array */
    fprintf(f, "  \"results\": [\n");

    for (int i = 0; i < results->entry_count; i++)
    {
        const bench_result_entry_t *e = &results->entries[i];

        fprintf(f, "    {\n");
        fprintf(f, "      \"algorithm\": \"%s\",\n", e->algorithm);
        fprintf(f, "      \"operation\": \"%s\",\n", e->operation);
        fprintf(f, "      \"iterations\": %d,\n", e->iterations);
        fprintf(f, "      \"successful\": %d,\n", e->successful);
        fprintf(f, "      \"failed\": %d,\n", e->failed);
        fprintf(f, "      \"total_time_us\": %.2f,\n", e->total_time_us);
        fprintf(f, "      \"throughput_ops\": %.2f,\n", e->throughput_ops);
        fprintf(f, "      \"latency_us\": {\n");
        fprintf(f, "        \"min\": %.3f,\n", e->latency.min_us);
        fprintf(f, "        \"max\": %.3f,\n", e->latency.max_us);
        fprintf(f, "        \"mean\": %.3f,\n", e->latency.mean_us);
        fprintf(f, "        \"median\": %.3f,\n", e->latency.median_us);
        fprintf(f, "        \"stddev\": %.3f,\n", e->latency.stddev_us);
        fprintf(f, "        \"p95\": %.3f,\n", e->latency.p95_us);
        fprintf(f, "        \"p99\": %.3f,\n", e->latency.p99_us);
        fprintf(f, "        \"p999\": %.3f\n", e->latency.p999_us);
        fprintf(f, "      }\n");
        fprintf(f, "    }%s\n", (i < results->entry_count - 1) ? "," : "");
    }

    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
}

/*=============================================================================
 * CSV Output
 *=============================================================================*/

void output_write_csv(FILE *f, const bench_results_t *results,
                      const device_info_t *device)
{
    (void)device; /* Device info not included in CSV */

    /* Header */
    fprintf(f, "algorithm,operation,iterations,successful,failed,"
               "total_time_us,throughput_ops,"
               "lat_min_us,lat_max_us,lat_mean_us,lat_median_us,"
               "lat_stddev_us,lat_p95_us,lat_p99_us,lat_p999_us\n");

    /* Data rows */
    for (int i = 0; i < results->entry_count; i++)
    {
        const bench_result_entry_t *e = &results->entries[i];

        fprintf(f, "%s,%s,%d,%d,%d,%.2f,%.2f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f\n",
                e->algorithm,
                e->operation,
                e->iterations,
                e->successful,
                e->failed,
                e->total_time_us,
                e->throughput_ops,
                e->latency.min_us,
                e->latency.max_us,
                e->latency.mean_us,
                e->latency.median_us,
                e->latency.stddev_us,
                e->latency.p95_us,
                e->latency.p99_us,
                e->latency.p999_us);
    }
}

/*=============================================================================
 * Markdown Output
 *=============================================================================*/

void output_write_markdown(FILE *f, const bench_results_t *results,
                           const device_info_t *device)
{
    char buf[64];
    char time_buf[64];

    fprintf(f, "# QUAC 100 Benchmark Results\n\n");

    /* Device info */
    if (device)
    {
        fprintf(f, "## Device Information\n\n");
        fprintf(f, "| Property | Value |\n");
        fprintf(f, "|----------|-------|\n");
        fprintf(f, "| Name | %s |\n", device->name);
        fprintf(f, "| Firmware | %s |\n", device->firmware_version);
        fprintf(f, "| Serial | %s |\n", device->serial_number);
        fprintf(f, "| Type | %s |\n\n", device->is_simulator ? "Simulator" : "Hardware");
    }

    /* Timestamp */
    struct tm *tm_info = localtime(&results->timestamp);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
    fprintf(f, "**Date:** %s\n\n", time_buf);

    /* Parameters */
    fprintf(f, "## Test Parameters\n\n");
    fprintf(f, "| Parameter | Value |\n");
    fprintf(f, "|-----------|-------|\n");
    fprintf(f, "| Iterations | %s |\n", output_format_number(results->iterations, buf, sizeof(buf)));
    fprintf(f, "| Warmup | %d |\n", results->warmup);
    fprintf(f, "| Threads | %d |\n", results->threads);
    fprintf(f, "| Batch Size | %d |\n\n", results->batch_size);

    /* Summary table */
    fprintf(f, "## Results Summary\n\n");
    fprintf(f, "| Algorithm | Operation | Throughput | Mean Latency | P99 Latency |\n");
    fprintf(f, "|-----------|-----------|------------|--------------|-------------|\n");

    for (int i = 0; i < results->entry_count; i++)
    {
        const bench_result_entry_t *e = &results->entries[i];

        char tput[32], mean[32], p99[32];
        output_format_throughput(e->throughput_ops, tput, sizeof(tput));
        output_format_duration(e->latency.mean_us, mean, sizeof(mean));
        output_format_duration(e->latency.p99_us, p99, sizeof(p99));

        fprintf(f, "| %s | %s | %s | %s | %s |\n",
                e->algorithm, e->operation, tput, mean, p99);
    }

    fprintf(f, "\n");

    /* Detailed results */
    fprintf(f, "## Detailed Results\n\n");

    for (int i = 0; i < results->entry_count; i++)
    {
        const bench_result_entry_t *e = &results->entries[i];

        fprintf(f, "### %s - %s\n\n", e->algorithm, e->operation);
        fprintf(f, "| Metric | Value |\n");
        fprintf(f, "|--------|-------|\n");
        fprintf(f, "| Iterations | %d |\n", e->iterations);
        fprintf(f, "| Throughput | %s |\n",
                output_format_throughput(e->throughput_ops, buf, sizeof(buf)));
        fprintf(f, "| Min | %s |\n",
                output_format_duration(e->latency.min_us, buf, sizeof(buf)));
        fprintf(f, "| Max | %s |\n",
                output_format_duration(e->latency.max_us, buf, sizeof(buf)));
        fprintf(f, "| Mean | %s |\n",
                output_format_duration(e->latency.mean_us, buf, sizeof(buf)));
        fprintf(f, "| Median | %s |\n",
                output_format_duration(e->latency.median_us, buf, sizeof(buf)));
        fprintf(f, "| Std Dev | %s |\n",
                output_format_duration(e->latency.stddev_us, buf, sizeof(buf)));
        fprintf(f, "| P95 | %s |\n",
                output_format_duration(e->latency.p95_us, buf, sizeof(buf)));
        fprintf(f, "| P99 | %s |\n",
                output_format_duration(e->latency.p99_us, buf, sizeof(buf)));
        fprintf(f, "\n");
    }
}

/*=============================================================================
 * Main Output Functions
 *=============================================================================*/

void output_write_results(output_context_t *ctx,
                          const bench_results_t *results,
                          const bench_device_t *device)
{
    if (!ctx || !results)
        return;

    device_info_t device_info;
    const device_info_t *info = NULL;

    if (device)
    {
        if (bench_get_device_info_from_device((bench_device_t *)device, &device_info) == 0)
        {
            info = &device_info;
        }
    }

    switch (ctx->format)
    {
    case OUTPUT_FMT_JSON:
        output_write_json(ctx->file, results, info);
        break;
    case OUTPUT_FMT_CSV:
        output_write_csv(ctx->file, results, info);
        break;
    case OUTPUT_FMT_MARKDOWN:
        output_write_markdown(ctx->file, results, info);
        break;
    case OUTPUT_FMT_TEXT:
    default:
        output_write_text(ctx->file, results, info);
        break;
    }
}

void output_write_comparison(output_context_t *ctx,
                             const bench_results_t *current,
                             const bench_results_t *baseline)
{
    if (!ctx || !current || !baseline)
        return;

    fprintf(ctx->file, "\n");
    fprintf(ctx->file, "Comparison with Baseline\n");
    fprintf(ctx->file, "========================\n\n");

    fprintf(ctx->file, "| Algorithm | Operation | Current | Baseline | Change |\n");
    fprintf(ctx->file, "|-----------|-----------|---------|----------|--------|\n");

    for (int i = 0; i < current->entry_count; i++)
    {
        const bench_result_entry_t *ce = &current->entries[i];

        /* Find matching baseline entry */
        const bench_result_entry_t *be = NULL;
        for (int j = 0; j < baseline->entry_count; j++)
        {
            if (strcmp(baseline->entries[j].algorithm, ce->algorithm) == 0 &&
                strcmp(baseline->entries[j].operation, ce->operation) == 0)
            {
                be = &baseline->entries[j];
                break;
            }
        }

        if (be)
        {
            double change = stats_percent_change(be->latency.mean_us, ce->latency.mean_us);
            char current_buf[32], baseline_buf[32];

            output_format_duration(ce->latency.mean_us, current_buf, sizeof(current_buf));
            output_format_duration(be->latency.mean_us, baseline_buf, sizeof(baseline_buf));

            const char *sign = change >= 0 ? "+" : "";
            const char *status = change > 5 ? "🟢" : (change < -5 ? "🔴" : "🟡");

            fprintf(ctx->file, "| %s | %s | %s | %s | %s%.1f%% %s |\n",
                    ce->algorithm, ce->operation,
                    current_buf, baseline_buf,
                    sign, change, status);
        }
        else
        {
            char current_buf[32];
            output_format_duration(ce->latency.mean_us, current_buf, sizeof(current_buf));
            fprintf(ctx->file, "| %s | %s | %s | N/A | - |\n",
                    ce->algorithm, ce->operation, current_buf);
        }
    }

    fprintf(ctx->file, "\n");
}