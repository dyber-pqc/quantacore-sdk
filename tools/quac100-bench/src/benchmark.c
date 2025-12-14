/**
 * @file benchmark.c
 * @brief QUAC 100 Benchmark Tool - Core Benchmark Engine Implementation
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/time.h>
#include <unistd.h>
#endif

#include "benchmark.h"

/* Try to include QUAC SDK if available */
#ifdef HAVE_QUAC_SDK
#include <quac100.h>
#endif

/*=============================================================================
 * Internal Structures
 *=============================================================================*/

struct bench_context
{
    void *sdk_handle;
    bool initialized;
    int device_count;
};

struct bench_device
{
    void *handle;
    device_info_t info;
    bool is_simulator;
};

/*=============================================================================
 * Timing Implementation
 *=============================================================================*/

uint64_t bench_timestamp_us(void)
{
#ifdef _WIN32
    LARGE_INTEGER freq, counter;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&counter);
    return (uint64_t)((counter.QuadPart * 1000000) / freq.QuadPart);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
#endif
}

/*=============================================================================
 * Name Lookup Tables
 *=============================================================================*/

static const char *algorithm_names[] = {
    [BENCH_ALG_UNKNOWN] = "Unknown",
    [BENCH_ALG_ML_KEM_512] = "ML-KEM-512",
    [BENCH_ALG_ML_KEM_768] = "ML-KEM-768",
    [BENCH_ALG_ML_KEM_1024] = "ML-KEM-1024",
    [BENCH_ALG_ML_DSA_44] = "ML-DSA-44",
    [BENCH_ALG_ML_DSA_65] = "ML-DSA-65",
    [BENCH_ALG_ML_DSA_87] = "ML-DSA-87",
    [BENCH_ALG_SLH_DSA_128F] = "SLH-DSA-128f",
    [BENCH_ALG_SLH_DSA_128S] = "SLH-DSA-128s",
    [BENCH_ALG_SLH_DSA_192F] = "SLH-DSA-192f",
    [BENCH_ALG_SLH_DSA_192S] = "SLH-DSA-192s",
    [BENCH_ALG_SLH_DSA_256F] = "SLH-DSA-256f",
    [BENCH_ALG_SLH_DSA_256S] = "SLH-DSA-256s",
    [BENCH_ALG_RANDOM] = "QRNG",
};

static const char *operation_names[] = {
    [BENCH_OP_UNKNOWN] = "Unknown",
    [BENCH_OP_KEYGEN] = "keygen",
    [BENCH_OP_ENCAPS] = "encaps",
    [BENCH_OP_DECAPS] = "decaps",
    [BENCH_OP_SIGN] = "sign",
    [BENCH_OP_VERIFY] = "verify",
    [BENCH_OP_RANDOM_32] = "random-32",
    [BENCH_OP_RANDOM_256] = "random-256",
    [BENCH_OP_RANDOM_1024] = "random-1024",
};

const char *bench_algorithm_name(bench_algorithm_t alg)
{
    if (alg < 0 || alg >= BENCH_ALG_COUNT)
    {
        return "Unknown";
    }
    return algorithm_names[alg];
}

const char *bench_operation_name(bench_operation_t op)
{
    if (op < 0 || op >= BENCH_OP_COUNT)
    {
        return "Unknown";
    }
    return operation_names[op];
}

/*=============================================================================
 * Context Management
 *=============================================================================*/

bench_context_t *bench_init(void)
{
    bench_context_t *ctx = calloc(1, sizeof(bench_context_t));
    if (!ctx)
    {
        return NULL;
    }

#ifdef HAVE_QUAC_SDK
    /* Initialize real SDK */
    if (quac_init(&ctx->sdk_handle) != QUAC_SUCCESS)
    {
        /* Fall back to simulation mode */
        ctx->sdk_handle = NULL;
    }
#else
    ctx->sdk_handle = NULL;
#endif

    ctx->initialized = true;
    ctx->device_count = 1; /* At least simulator */

    return ctx;
}

void bench_cleanup(bench_context_t *ctx)
{
    if (!ctx)
        return;

#ifdef HAVE_QUAC_SDK
    if (ctx->sdk_handle)
    {
        quac_shutdown(ctx->sdk_handle);
    }
#endif

    free(ctx);
}

/*=============================================================================
 * Device Management
 *=============================================================================*/

int bench_get_device_count(bench_context_t *ctx)
{
    if (!ctx)
        return 0;

#ifdef HAVE_QUAC_SDK
    if (ctx->sdk_handle)
    {
        uint32_t count = 0;
        if (quac_get_device_count(ctx->sdk_handle, &count) == QUAC_SUCCESS)
        {
            return (int)count;
        }
    }
#endif

    /* Simulator always available */
    return 1;
}

int bench_get_device_info(bench_context_t *ctx, int index, device_info_t *info)
{
    if (!ctx || !info)
        return -1;

    memset(info, 0, sizeof(*info));
    info->index = index;

#ifdef HAVE_QUAC_SDK
    if (ctx->sdk_handle)
    {
        quac_device_info_t sdk_info;
        if (quac_get_device_info(ctx->sdk_handle, index, &sdk_info) == QUAC_SUCCESS)
        {
            strncpy(info->name, sdk_info.name, sizeof(info->name) - 1);
            strncpy(info->firmware_version, sdk_info.firmware_version,
                    sizeof(info->firmware_version) - 1);
            strncpy(info->serial_number, sdk_info.serial_number,
                    sizeof(info->serial_number) - 1);
            info->available = true;
            info->is_simulator = false;
            return 0;
        }
    }
#endif

    /* Simulator info */
    strncpy(info->name, "QUAC 100 Simulator", sizeof(info->name) - 1);
    strncpy(info->firmware_version, "1.0.0-sim", sizeof(info->firmware_version) - 1);
    strncpy(info->serial_number, "SIM-00000000", sizeof(info->serial_number) - 1);
    info->available = true;
    info->is_simulator = true;

    return 0;
}

bench_device_t *bench_open_device(bench_context_t *ctx, int index)
{
    if (!ctx)
        return NULL;

    bench_device_t *device = calloc(1, sizeof(bench_device_t));
    if (!device)
        return NULL;

#ifdef HAVE_QUAC_SDK
    if (ctx->sdk_handle)
    {
        if (quac_open_device(ctx->sdk_handle, index, &device->handle) == QUAC_SUCCESS)
        {
            bench_get_device_info(ctx, index, &device->info);
            device->is_simulator = false;
            return device;
        }
    }
#endif

    /* Fall back to simulator */
    device->handle = NULL;
    device->is_simulator = true;
    bench_get_device_info(ctx, 0, &device->info);

    return device;
}

bench_device_t *bench_open_simulator(bench_context_t *ctx)
{
    if (!ctx)
        return NULL;

    bench_device_t *device = calloc(1, sizeof(bench_device_t));
    if (!device)
        return NULL;

    device->handle = NULL;
    device->is_simulator = true;

    strncpy(device->info.name, "QUAC 100 Simulator", sizeof(device->info.name) - 1);
    strncpy(device->info.firmware_version, "1.0.0-sim",
            sizeof(device->info.firmware_version) - 1);
    strncpy(device->info.serial_number, "SIM-00000000",
            sizeof(device->info.serial_number) - 1);
    device->info.index = 0;
    device->info.available = true;
    device->info.is_simulator = true;

    return device;
}

void bench_close_device(bench_device_t *device)
{
    if (!device)
        return;

#ifdef HAVE_QUAC_SDK
    if (device->handle)
    {
        quac_close_device(device->handle);
    }
#endif

    free(device);
}

int bench_get_device_info_from_device(bench_device_t *device, device_info_t *info)
{
    if (!device || !info)
        return -1;

    memcpy(info, &device->info, sizeof(device_info_t));
    return 0;
}

/*=============================================================================
 * Results Management
 *=============================================================================*/

bench_results_t *bench_results_create(void)
{
    bench_results_t *results = calloc(1, sizeof(bench_results_t));
    if (!results)
        return NULL;

    results->entry_capacity = 32;
    results->entries = calloc(results->entry_capacity, sizeof(bench_result_entry_t));
    if (!results->entries)
    {
        free(results);
        return NULL;
    }

    results->entry_count = 0;

    return results;
}

void bench_results_destroy(bench_results_t *results)
{
    if (!results)
        return;

    /* Free timing arrays */
    for (int i = 0; i < results->entry_count; i++)
    {
        free(results->entries[i].timings);
    }

    free(results->entries);
    free(results);
}

int bench_results_add(bench_results_t *results, const bench_result_entry_t *entry)
{
    if (!results || !entry)
        return -1;

    /* Expand if needed */
    if (results->entry_count >= results->entry_capacity)
    {
        int new_capacity = results->entry_capacity * 2;
        bench_result_entry_t *new_entries = realloc(
            results->entries,
            new_capacity * sizeof(bench_result_entry_t));
        if (!new_entries)
            return -1;

        results->entries = new_entries;
        results->entry_capacity = new_capacity;
    }

    /* Copy entry */
    memcpy(&results->entries[results->entry_count], entry, sizeof(bench_result_entry_t));

    /* Copy timings array if present */
    if (entry->timings && entry->timing_count > 0)
    {
        results->entries[results->entry_count].timings =
            malloc(entry->timing_count * sizeof(double));
        if (results->entries[results->entry_count].timings)
        {
            memcpy(results->entries[results->entry_count].timings,
                   entry->timings,
                   entry->timing_count * sizeof(double));
        }
    }

    results->entry_count++;
    return 0;
}

bench_results_t *bench_results_load(const char *filename)
{
    if (!filename)
        return NULL;

    FILE *f = fopen(filename, "r");
    if (!f)
        return NULL;

    bench_results_t *results = bench_results_create();
    if (!results)
    {
        fclose(f);
        return NULL;
    }

    /* Simple CSV parsing for baseline comparison */
    char line[1024];
    bool header = true;

    while (fgets(line, sizeof(line), f))
    {
        if (header)
        {
            header = false;
            continue;
        }

        bench_result_entry_t entry;
        memset(&entry, 0, sizeof(entry));

        /* Parse CSV line */
        char *tok = strtok(line, ",");
        if (tok)
            strncpy(entry.algorithm, tok, sizeof(entry.algorithm) - 1);

        tok = strtok(NULL, ",");
        if (tok)
            strncpy(entry.operation, tok, sizeof(entry.operation) - 1);

        tok = strtok(NULL, ",");
        if (tok)
            entry.iterations = atoi(tok);

        tok = strtok(NULL, ",");
        if (tok)
            entry.total_time_us = atof(tok);

        tok = strtok(NULL, ",");
        if (tok)
            entry.throughput_ops = atof(tok);

        tok = strtok(NULL, ",");
        if (tok)
            entry.latency.min_us = atof(tok);

        tok = strtok(NULL, ",");
        if (tok)
            entry.latency.max_us = atof(tok);

        tok = strtok(NULL, ",");
        if (tok)
            entry.latency.mean_us = atof(tok);

        tok = strtok(NULL, ",");
        if (tok)
            entry.latency.median_us = atof(tok);

        tok = strtok(NULL, ",");
        if (tok)
            entry.latency.p95_us = atof(tok);

        tok = strtok(NULL, ",\n");
        if (tok)
            entry.latency.p99_us = atof(tok);

        bench_results_add(results, &entry);
    }

    fclose(f);
    return results;
}

int bench_results_save(const bench_results_t *results, const char *filename)
{
    if (!results || !filename)
        return -1;

    FILE *f = fopen(filename, "w");
    if (!f)
        return -1;

    /* CSV header */
    fprintf(f, "algorithm,operation,iterations,total_time_us,throughput_ops,"
               "lat_min_us,lat_max_us,lat_mean_us,lat_median_us,lat_p95_us,lat_p99_us\n");

    for (int i = 0; i < results->entry_count; i++)
    {
        const bench_result_entry_t *e = &results->entries[i];
        fprintf(f, "%s,%s,%d,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f\n",
                e->algorithm,
                e->operation,
                e->iterations,
                e->total_time_us,
                e->throughput_ops,
                e->latency.min_us,
                e->latency.max_us,
                e->latency.mean_us,
                e->latency.median_us,
                e->latency.p95_us,
                e->latency.p99_us);
    }

    fclose(f);
    return 0;
}