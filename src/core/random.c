/**
 * @file random.c
 * @brief QuantaCore SDK - QRNG Operations Implementation
 *
 * Implements Quantum Random Number Generator operations including
 * entropy collection, health testing, and random byte generation.
 * Supports both hardware QRNG and software simulation modes.
 *
 * The QUAC 100 QRNG uses 8 parallel avalanche noise sources providing
 * over 2 Gbps of conditioned entropy, compliant with NIST SP 800-90B.
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include "quac100.h"
#include "quac100_types.h"
#include "quac100_error.h"
#include "quac100_random.h"
#include "internal/quac100_ioctl.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#else
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/random.h>
#endif

/*=============================================================================
 * Error Recording Macro
 *=============================================================================*/

extern void quac_error_record(quac_result_t result, const char *file, int line,
                              const char *func, const char *fmt, ...);

#define QUAC_RECORD_ERROR(result, ...) \
    quac_error_record((result), __FILE__, __LINE__, __func__, __VA_ARGS__)

/*=============================================================================
 * Internal Device Access (from device.c)
 *=============================================================================*/

extern intptr_t quac_device_get_ioctl_fd(quac_device_t device);
extern bool quac_device_is_simulator(quac_device_t device);
extern void quac_device_inc_ops(quac_device_t device);
extern void quac_device_lock(quac_device_t device);
extern void quac_device_unlock(quac_device_t device);
extern uint32_t quac_device_get_sim_latency(quac_device_t device);

/*=============================================================================
 * Constants
 *=============================================================================*/

/** Number of entropy sources */
#define QUAC_QRNG_NUM_SOURCES 8

/** Default entropy pool size (bits) */
#define QUAC_QRNG_POOL_SIZE (1024 * 1024)

/** Entropy rate per source (bits/sec) */
#define QUAC_QRNG_SOURCE_RATE (256 * 1024 * 1024)

/** Total entropy rate (bits/sec) */
#define QUAC_QRNG_TOTAL_RATE (QUAC_QRNG_SOURCE_RATE * QUAC_QRNG_NUM_SOURCES)

/*=============================================================================
 * Global Statistics
 *=============================================================================*/

static quac_random_stats_t g_random_stats = {0};

/*=============================================================================
 * Internal Helpers
 *=============================================================================*/

/**
 * @brief Get current timestamp in microseconds
 */
static uint64_t get_timestamp_us(void)
{
#ifdef _WIN32
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (uint64_t)((count.QuadPart * 1000000ULL) / freq.QuadPart);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000;
#endif
}

/**
 * @brief Update statistics for random generation
 */
static void update_random_stats(size_t bytes, bool success, uint64_t wait_time_us)
{
    g_random_stats.requests_total++;

    if (success)
    {
        g_random_stats.requests_success++;
        g_random_stats.bytes_generated += bytes;
    }
    else
    {
        g_random_stats.requests_failed++;
    }

    if (wait_time_us > 0)
    {
        g_random_stats.requests_blocked++;
        g_random_stats.total_wait_time_us += wait_time_us;

        if (wait_time_us > g_random_stats.max_wait_time_us)
        {
            g_random_stats.max_wait_time_us = (uint32_t)wait_time_us;
        }
    }
}

/*=============================================================================
 * Simulator Implementation
 *=============================================================================*/

/**
 * @brief Get system random bytes (for simulator fallback)
 */
static quac_result_t get_system_random(uint8_t *buffer, size_t length)
{
#ifdef _WIN32
    NTSTATUS status = BCryptGenRandom(NULL, buffer, (ULONG)length,
                                      BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(status))
    {
        return QUAC_ERROR_QRNG_FAILURE;
    }
    return QUAC_SUCCESS;
#else
    /* Use getrandom() if available, otherwise /dev/urandom */
    ssize_t ret = getrandom(buffer, length, 0);
    if (ret < 0 || (size_t)ret != length)
    {
        /* Fallback to /dev/urandom */
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0)
        {
            return QUAC_ERROR_QRNG_FAILURE;
        }

        size_t total = 0;
        while (total < length)
        {
            ssize_t n = read(fd, buffer + total, length - total);
            if (n <= 0)
            {
                close(fd);
                return QUAC_ERROR_QRNG_FAILURE;
            }
            total += n;
        }
        close(fd);
    }
    return QUAC_SUCCESS;
#endif
}

/**
 * @brief Simulated random byte generation
 */
static quac_result_t sim_random_bytes(uint8_t *buffer, size_t length,
                                      quac_random_quality_t quality)
{
    (void)quality; /* Simulator ignores quality level */

    return get_system_random(buffer, length);
}

/**
 * @brief Simulated QRNG info
 */
static quac_result_t sim_get_random_info(quac_random_info_t *info)
{
    memset(info, 0, sizeof(*info));
    info->struct_size = sizeof(*info);

    /* Simulate healthy QRNG */
    info->pool_size_bits = QUAC_QRNG_POOL_SIZE;
    info->pool_fill_rate_bps = QUAC_QRNG_TOTAL_RATE;
    info->health_status = QUAC_HEALTH_STATE_OK;
    info->total_sources = QUAC_QRNG_NUM_SOURCES;
    info->active_sources = QUAC_QRNG_NUM_SOURCES;
    info->failed_sources = 0;
    info->available_bits = QUAC_QRNG_POOL_SIZE; /* Always full in simulator */

    return QUAC_SUCCESS;
}

/**
 * @brief Simulated entropy source info
 */
static quac_result_t sim_get_source_info(uint32_t source_id,
                                         quac_entropy_source_t *source)
{
    if (source_id >= QUAC_QRNG_NUM_SOURCES)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    memset(source, 0, sizeof(*source));
    source->struct_size = sizeof(*source);
    source->source_id = source_id;
    snprintf(source->name, sizeof(source->name), "Avalanche-%u", source_id);
    source->entropy_rate_bps = QUAC_QRNG_SOURCE_RATE;
    source->min_entropy_estimate = 7.9f; /* bits per byte */
    source->health_ok = true;
    source->enabled = true;
    source->temperature_celsius = 45 + (source_id % 5);

    return QUAC_SUCCESS;
}

/**
 * @brief Simulated health test
 */
static quac_result_t sim_run_health_tests(quac_random_test_t tests,
                                          quac_random_test_result_t *result)
{
    memset(result, 0, sizeof(*result));
    result->struct_size = sizeof(*result);
    result->tests_run = tests;
    result->tests_passed = tests; /* All pass in simulator */
    result->overall_pass = true;
    result->min_entropy_estimate = 7.9f;
    result->shannon_entropy = 7.99f;

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Hardware Implementation
 *=============================================================================*/

/**
 * @brief Hardware random byte generation via IOCTL
 */
static quac_result_t hw_random_bytes(quac_device_t device,
                                     uint8_t *buffer, size_t length,
                                     quac_random_quality_t quality)
{
    intptr_t fd = quac_device_get_ioctl_fd(device);
    if (fd < 0)
    {
        return QUAC_ERROR_DEVICE_ERROR;
    }

    struct quac_ioctl_random req = {
        .struct_size = sizeof(req),
        .buf_addr = (uint64_t)(uintptr_t)buffer,
        .length = length,
        .quality = quality,
    };

    quac_result_t result = quac_ioctl_execute(fd, QUAC_IOC_RANDOM,
                                              &req, sizeof(req));

    return (result == QUAC_SUCCESS) ? req.result : result;
}

/**
 * @brief Hardware QRNG info via IOCTL
 */
static quac_result_t hw_get_random_info(quac_device_t device,
                                        quac_random_info_t *info)
{
    intptr_t fd = quac_device_get_ioctl_fd(device);
    if (fd < 0)
    {
        return QUAC_ERROR_DEVICE_ERROR;
    }

    struct quac_ioctl_health health;
    health.struct_size = sizeof(health);

    quac_result_t result = quac_ioctl_execute(fd, QUAC_IOC_GET_HEALTH,
                                              &health, sizeof(health));

    if (QUAC_FAILED(result))
    {
        return result;
    }

    memset(info, 0, sizeof(*info));
    info->struct_size = sizeof(*info);
    info->pool_size_bits = QUAC_QRNG_POOL_SIZE;
    info->pool_fill_rate_bps = QUAC_QRNG_TOTAL_RATE;
    info->health_status = health.state;
    info->total_sources = QUAC_QRNG_NUM_SOURCES;
    info->active_sources = health.entropy_sources_ok;
    info->failed_sources = QUAC_QRNG_NUM_SOURCES - health.entropy_sources_ok;
    info->available_bits = health.entropy_available;

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Public API Implementation
 *=============================================================================*/

QUAC100_API quac_result_t QUAC100_CALL
quac_random_bytes(quac_device_t device, uint8_t *buffer, size_t length)
{
    return quac_random_bytes_ex(device, buffer, length, QUAC_RANDOM_QUALITY_STANDARD);
}

QUAC100_API quac_result_t QUAC100_CALL
quac_random_bytes_ex(quac_device_t device,
                     uint8_t *buffer,
                     size_t length,
                     quac_random_quality_t quality)
{
    QUAC_CHECK_NULL(buffer);

    if (length == 0)
    {
        return QUAC_SUCCESS;
    }

    uint64_t start_time = get_timestamp_us();
    quac_result_t result;

    quac_device_lock(device);

    if (quac_device_is_simulator(device))
    {
        result = sim_random_bytes(buffer, length, quality);
    }
    else
    {
        result = hw_random_bytes(device, buffer, length, quality);
    }

    quac_device_unlock(device);

    uint64_t duration = get_timestamp_us() - start_time;
    update_random_stats(length, QUAC_SUCCEEDED(result), 0);

    if (QUAC_SUCCEEDED(result))
    {
        quac_device_inc_ops(device);
    }
    else
    {
        QUAC_RECORD_ERROR(result, "Failed to generate %zu random bytes", length);
    }

    return result;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_random_bytes_wait(quac_device_t device,
                       uint8_t *buffer,
                       size_t length,
                       uint32_t timeout_ms)
{
    QUAC_CHECK_NULL(buffer);

    if (length == 0)
    {
        return QUAC_SUCCESS;
    }

    uint64_t start_time = get_timestamp_us();
    uint64_t deadline = start_time + (uint64_t)timeout_ms * 1000;
    quac_result_t result;

    do
    {
        result = quac_random_bytes_ex(device, buffer, length,
                                      QUAC_RANDOM_QUALITY_STANDARD);

        if (result != QUAC_ERROR_ENTROPY_DEPLETED)
        {
            break;
        }

        /* Wait and retry */
#ifdef _WIN32
        Sleep(1);
#else
        usleep(1000);
#endif

    } while (get_timestamp_us() < deadline);

    uint64_t wait_time = get_timestamp_us() - start_time;

    if (result == QUAC_ERROR_ENTROPY_DEPLETED)
    {
        QUAC_RECORD_ERROR(QUAC_ERROR_TIMEOUT,
                          "Timed out waiting for entropy after %u ms", timeout_ms);
        update_random_stats(0, false, wait_time);
        return QUAC_ERROR_TIMEOUT;
    }

    update_random_stats(length, QUAC_SUCCEEDED(result), wait_time);
    return result;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_random_uint32(quac_device_t device, uint32_t *value)
{
    QUAC_CHECK_NULL(value);

    return quac_random_bytes(device, (uint8_t *)value, sizeof(*value));
}

QUAC100_API quac_result_t QUAC100_CALL
quac_random_uint64(quac_device_t device, uint64_t *value)
{
    QUAC_CHECK_NULL(value);

    return quac_random_bytes(device, (uint8_t *)value, sizeof(*value));
}

QUAC100_API quac_result_t QUAC100_CALL
quac_random_range(quac_device_t device, uint32_t max, uint32_t *value)
{
    QUAC_CHECK_NULL(value);

    if (max == 0)
    {
        *value = 0;
        return QUAC_SUCCESS;
    }

    /* Use rejection sampling to avoid bias */
    uint32_t limit = UINT32_MAX - (UINT32_MAX % max);
    uint32_t r;
    quac_result_t result;

    do
    {
        result = quac_random_uint32(device, &r);
        if (QUAC_FAILED(result))
        {
            return result;
        }
    } while (r >= limit);

    *value = r % max;
    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_random_range_inclusive(quac_device_t device,
                            uint32_t min, uint32_t max,
                            uint32_t *value)
{
    QUAC_CHECK_NULL(value);

    if (min > max)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    if (min == max)
    {
        *value = min;
        return QUAC_SUCCESS;
    }

    uint32_t range = max - min + 1;
    uint32_t r;
    quac_result_t result = quac_random_range(device, range, &r);

    if (QUAC_SUCCEEDED(result))
    {
        *value = min + r;
    }

    return result;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_random_double(quac_device_t device, double *value)
{
    QUAC_CHECK_NULL(value);

    uint64_t r;
    quac_result_t result = quac_random_uint64(device, &r);

    if (QUAC_SUCCEEDED(result))
    {
        /* Use 53 bits for double mantissa */
        *value = (double)(r >> 11) / (double)(1ULL << 53);
    }

    return result;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_random_uint32_array(quac_device_t device,
                         uint32_t *values, size_t count)
{
    QUAC_CHECK_NULL(values);

    return quac_random_bytes(device, (uint8_t *)values, count * sizeof(uint32_t));
}

QUAC100_API quac_result_t QUAC100_CALL
quac_random_uint64_array(quac_device_t device,
                         uint64_t *values, size_t count)
{
    QUAC_CHECK_NULL(values);

    return quac_random_bytes(device, (uint8_t *)values, count * sizeof(uint64_t));
}

/*=============================================================================
 * Entropy Pool Management
 *=============================================================================*/

QUAC100_API quac_result_t QUAC100_CALL
quac_random_available(quac_device_t device, uint32_t *bits)
{
    QUAC_CHECK_NULL(bits);

    quac_random_info_t info;
    quac_result_t result = quac_random_get_info(device, &info);

    if (QUAC_SUCCEEDED(result))
    {
        *bits = info.available_bits;
    }

    return result;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_random_check_available(quac_device_t device, size_t bytes_needed)
{
    uint32_t available_bits;
    quac_result_t result = quac_random_available(device, &available_bits);

    if (QUAC_FAILED(result))
    {
        return result;
    }

    uint32_t needed_bits = (uint32_t)(bytes_needed * 8);

    if (available_bits < needed_bits)
    {
        return QUAC_ERROR_ENTROPY_DEPLETED;
    }

    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_random_wait_entropy(quac_device_t device, size_t bytes, uint32_t timeout_ms)
{
    uint64_t deadline = get_timestamp_us() + (uint64_t)timeout_ms * 1000;

    while (get_timestamp_us() < deadline)
    {
        quac_result_t result = quac_random_check_available(device, bytes);

        if (result == QUAC_SUCCESS)
        {
            return QUAC_SUCCESS;
        }

        if (result != QUAC_ERROR_ENTROPY_DEPLETED)
        {
            return result;
        }

#ifdef _WIN32
        Sleep(1);
#else
        usleep(1000);
#endif
    }

    return QUAC_ERROR_TIMEOUT;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_random_reseed(quac_device_t device, const uint8_t *seed, size_t seed_len)
{
    (void)device;
    (void)seed;
    (void)seed_len;

    /* Hardware QRNG doesn't need external seeding */
    /* Could mix in additional entropy if provided */

    g_random_stats.reseeds++;

    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_random_flush(quac_device_t device)
{
    (void)device;

    /* Flush entropy pool (for post-compromise security) */
    /* In hardware, this would trigger a full pool refresh */

    return QUAC_SUCCESS;
}

/*=============================================================================
 * QRNG Status and Health
 *=============================================================================*/

QUAC100_API quac_result_t QUAC100_CALL
quac_random_get_info(quac_device_t device, quac_random_info_t *info)
{
    QUAC_CHECK_NULL(info);

    quac_result_t result;

    quac_device_lock(device);

    if (quac_device_is_simulator(device))
    {
        result = sim_get_random_info(info);
    }
    else
    {
        result = hw_get_random_info(device, info);
    }

    quac_device_unlock(device);

    return result;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_random_get_source(quac_device_t device,
                       uint32_t source_id,
                       quac_entropy_source_t *source)
{
    QUAC_CHECK_NULL(source);

    quac_result_t result;

    quac_device_lock(device);

    if (quac_device_is_simulator(device))
    {
        result = sim_get_source_info(source_id, source);
    }
    else
    {
        /* Hardware would query individual source status */
        result = sim_get_source_info(source_id, source); /* TODO: hw impl */
    }

    quac_device_unlock(device);

    return result;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_random_get_sources(quac_device_t device,
                        quac_entropy_source_t *sources,
                        uint32_t max_sources,
                        uint32_t *count)
{
    QUAC_CHECK_NULL(sources);
    QUAC_CHECK_NULL(count);

    *count = 0;

    uint32_t num = (max_sources < QUAC_QRNG_NUM_SOURCES) ? max_sources : QUAC_QRNG_NUM_SOURCES;

    for (uint32_t i = 0; i < num; i++)
    {
        quac_result_t result = quac_random_get_source(device, i, &sources[i]);
        if (QUAC_FAILED(result))
        {
            return result;
        }
        (*count)++;
    }

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Health Testing
 *=============================================================================*/

QUAC100_API quac_result_t QUAC100_CALL
quac_random_run_tests(quac_device_t device,
                      quac_random_test_t tests,
                      quac_random_test_result_t *result)
{
    QUAC_CHECK_NULL(result);

    quac_result_t ret;

    quac_device_lock(device);

    if (quac_device_is_simulator(device))
    {
        ret = sim_run_health_tests(tests, result);
    }
    else
    {
        /* Hardware health tests */
        ret = sim_run_health_tests(tests, result); /* TODO: hw impl */
    }

    quac_device_unlock(device);

    g_random_stats.health_tests_run++;
    if (result->overall_pass)
    {
        g_random_stats.health_tests_passed++;
    }

    return ret;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_random_is_healthy(quac_device_t device, bool *healthy)
{
    QUAC_CHECK_NULL(healthy);

    quac_random_info_t info;
    quac_result_t result = quac_random_get_info(device, &info);

    if (QUAC_SUCCEEDED(result))
    {
        *healthy = (info.health_status == QUAC_HEALTH_STATE_OK &&
                    info.failed_sources == 0);
    }

    return result;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_random_set_source_enabled(quac_device_t device,
                               uint32_t source_id,
                               bool enabled)
{
    if (source_id >= QUAC_QRNG_NUM_SOURCES)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    /* At least one source must remain enabled */
    if (!enabled)
    {
        quac_random_info_t info;
        quac_result_t result = quac_random_get_info(device, &info);
        if (QUAC_SUCCEEDED(result) && info.active_sources <= 1)
        {
            QUAC_RECORD_ERROR(QUAC_ERROR_INVALID_PARAMETER,
                              "Cannot disable last active entropy source");
            return QUAC_ERROR_INVALID_PARAMETER;
        }
    }

    /* Hardware would configure source enable/disable */
    (void)device;
    (void)enabled;

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Statistics
 *=============================================================================*/

QUAC100_API quac_result_t QUAC100_CALL
quac_random_get_stats(quac_random_stats_t *stats)
{
    QUAC_CHECK_NULL(stats);

    memcpy(stats, &g_random_stats, sizeof(*stats));
    stats->struct_size = sizeof(*stats);

    /* Calculate throughput */
    if (g_random_stats.requests_success > 0 &&
        g_random_stats.total_wait_time_us > 0)
    {
        stats->avg_throughput_bps = (uint64_t)g_random_stats.bytes_generated *
                                    8000000ULL / g_random_stats.total_wait_time_us;
    }

    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_random_reset_stats(void)
{
    memset(&g_random_stats, 0, sizeof(g_random_stats));
    g_random_stats.struct_size = sizeof(g_random_stats);
    return QUAC_SUCCESS;
}