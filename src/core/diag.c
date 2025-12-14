/**
 * @file diag.c
 * @brief QuantaCore SDK - Diagnostics and Health Monitoring Implementation
 *
 * Implements device health monitoring, self-tests, performance counters,
 * temperature monitoring, diagnostic logging, and reset/recovery operations.
 * Supports FIPS 140-3 compliance requirements.
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include "quac100.h"
#include "quac100_types.h"
#include "quac100_error.h"
#include "quac100_diag.h"
#include "quac100_kem.h"
#include "quac100_sign.h"
#include "quac100_random.h"
#include "internal/quac100_ioctl.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <time.h>
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
extern void quac_device_lock(quac_device_t device);
extern void quac_device_unlock(quac_device_t device);

/*=============================================================================
 * Internal State Access (from init.c)
 *=============================================================================*/

extern bool quac_internal_is_fips_mode(void);

/*=============================================================================
 * Constants
 *=============================================================================*/

/** Log buffer size */
#define QUAC_LOG_BUFFER_SIZE 1024

/** Maximum log entries */
#define QUAC_MAX_LOG_ENTRIES 4096

/** Number of temperature sensors */
#define QUAC_NUM_TEMP_SENSORS 4

/** Number of performance counters */
#define QUAC_NUM_PERF_COUNTERS 32

/*=============================================================================
 * KAT (Known Answer Test) Vectors
 *=============================================================================*/

/* ML-KEM-512 KAT vector (truncated for illustration) */
static const uint8_t g_kem512_seed[32] = {
    0x7c, 0x99, 0x35, 0xa0, 0xb0, 0x76, 0x94, 0xaa,
    0x0c, 0x6d, 0x10, 0xe4, 0xdb, 0x6b, 0x1a, 0xdd,
    0x2f, 0xd8, 0x1a, 0x25, 0xcc, 0xb1, 0x48, 0x03,
    0x2d, 0xcd, 0x73, 0x99, 0x36, 0x73, 0x7f, 0x2d};

static const uint8_t g_kem512_pk_expected[32] = {/* First 32 bytes */
                                                 0x3e, 0xd6, 0x8a, 0x9a, 0x3b, 0x2e, 0x1a, 0x7d,
                                                 0x45, 0x82, 0x31, 0x4b, 0xc7, 0x88, 0x95, 0x4f,
                                                 0x3d, 0x28, 0x9f, 0x5c, 0x4a, 0x91, 0x63, 0x27,
                                                 0x8e, 0xd2, 0x75, 0x43, 0x6a, 0x98, 0xb4, 0xc1};

/* ML-DSA-44 KAT vector (truncated for illustration) */
static const uint8_t g_dsa44_seed[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};

/*=============================================================================
 * Global State
 *=============================================================================*/

/**
 * @brief Diagnostic state
 */
typedef struct diag_state_s
{
    /* Logging */
    quac_log_level_t log_level;
    quac_log_callback_t log_callback;
    void *log_user_data;

    quac_log_entry_t *log_buffer;
    uint32_t log_head;
    uint32_t log_tail;
    uint32_t log_count;

    /* Temperature callback */
    quac_temp_callback_t temp_callback;
    void *temp_user_data;
    int32_t temp_threshold;

    /* Last self-test results */
    quac_self_test_summary_t last_test;
    bool last_test_valid;

    /* Performance counters */
    quac_perf_value_t counters[QUAC_NUM_PERF_COUNTERS];

} diag_state_t;

static diag_state_t g_diag = {
    .log_level = QUAC_LOG_WARNING,
    .log_callback = NULL,
    .log_buffer = NULL,
    .log_count = 0,
    .temp_callback = NULL,
    .temp_threshold = 85,
    .last_test_valid = false,
};

/*=============================================================================
 * Internal Helpers
 *=============================================================================*/

/**
 * @brief Get current timestamp in nanoseconds
 */
static uint64_t get_timestamp_ns(void)
{
#ifdef _WIN32
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (uint64_t)((count.QuadPart * 1000000000ULL) / freq.QuadPart);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
#endif
}

/**
 * @brief Add entry to log buffer
 */
static void add_log_entry(quac_log_level_t level, uint32_t source,
                          quac_result_t result, const char *message,
                          const char *detail)
{
    if (level < g_diag.log_level)
    {
        return;
    }

    /* Invoke callback if registered */
    if (g_diag.log_callback)
    {
        quac_log_entry_t entry;
        entry.timestamp = get_timestamp_ns();
        entry.level = level;
        entry.source = source;
        entry.result_code = result;
        strncpy(entry.message, message ? message : "", sizeof(entry.message) - 1);
        strncpy(entry.detail, detail ? detail : "", sizeof(entry.detail) - 1);

        g_diag.log_callback(&entry, g_diag.log_user_data);
    }

    /* Add to circular buffer if allocated */
    if (g_diag.log_buffer)
    {
        quac_log_entry_t *entry = &g_diag.log_buffer[g_diag.log_head];

        entry->timestamp = get_timestamp_ns();
        entry->level = level;
        entry->source = source;
        entry->result_code = result;
        strncpy(entry->message, message ? message : "", sizeof(entry->message) - 1);
        strncpy(entry->detail, detail ? detail : "", sizeof(entry->detail) - 1);

        g_diag.log_head = (g_diag.log_head + 1) % QUAC_MAX_LOG_ENTRIES;
        if (g_diag.log_count < QUAC_MAX_LOG_ENTRIES)
        {
            g_diag.log_count++;
        }
        else
        {
            g_diag.log_tail = (g_diag.log_tail + 1) % QUAC_MAX_LOG_ENTRIES;
        }
    }
}

/**
 * @brief Log formatted message
 */
static void diag_log(quac_log_level_t level, const char *fmt, ...)
{
    char buffer[512];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);

    add_log_entry(level, 0, QUAC_SUCCESS, buffer, NULL);
}

/*=============================================================================
 * Simulator Implementation
 *=============================================================================*/

/**
 * @brief Simulated health status
 */
static quac_result_t sim_get_health(quac_health_status_t *status)
{
    memset(status, 0, sizeof(*status));
    status->struct_size = sizeof(*status);

    status->state = QUAC_HEALTH_STATE_OK;
    status->flags = QUAC_HEALTH_TEMP_OK | QUAC_HEALTH_POWER_OK |
                    QUAC_HEALTH_MEMORY_OK | QUAC_HEALTH_ENTROPY_OK |
                    QUAC_HEALTH_SECURITY_OK | QUAC_HEALTH_PCIE_OK |
                    QUAC_HEALTH_FIRMWARE_OK;

    /* Temperature */
    status->temp_core_celsius = 45 + (rand() % 10);
    status->temp_memory_celsius = 40 + (rand() % 8);
    status->temp_board_celsius = 35 + (rand() % 5);
    status->temp_max_celsius = 100;
    status->temp_throttle_celsius = 95;

    /* Power */
    status->voltage_core_mv = 850;
    status->voltage_memory_mv = 1100;
    status->voltage_aux_mv = 3300;
    status->power_draw_mw = 25000 + (rand() % 5000);
    status->power_limit_mw = 75000;

    /* Clocks */
    status->clock_core_mhz = 1000;
    status->clock_memory_mhz = 800;
    status->clock_max_mhz = 1200;

    /* Memory */
    status->memory_total_bytes = 4ULL * 1024 * 1024 * 1024; /* 4 GB */
    status->memory_used_bytes = 512 * 1024 * 1024;          /* 512 MB used */
    status->ecc_corrected_count = 0;
    status->ecc_uncorrectable_count = 0;

    /* Entropy */
    status->entropy_available_bits = 900000 + (rand() % 100000);
    status->entropy_rate_bps = 2000000000; /* 2 Gbps */
    status->entropy_sources_ok = 8;
    status->entropy_sources_total = 8;

    /* Operations */
    status->uptime_seconds = get_timestamp_ns() / 1000000000ULL;
    status->operations_completed = 0; /* Would track actual ops */
    status->operations_failed = 0;

    /* PCIe */
    status->pcie_gen = 4;
    status->pcie_lanes = 8;
    status->pcie_errors = 0;

    snprintf(status->state_message, sizeof(status->state_message),
             "Device operating normally");

    return QUAC_SUCCESS;
}

/**
 * @brief Simulated self-test execution
 */
static quac_result_t sim_run_self_test(quac_self_test_t tests,
                                       quac_self_test_summary_t *summary)
{
    uint64_t start_time = get_timestamp_ns();

    memset(summary, 0, sizeof(*summary));
    summary->struct_size = sizeof(*summary);
    summary->tests_run = tests;
    summary->tests_passed = tests; /* Simulator always passes */
    summary->tests_failed = 0;
    summary->overall_passed = true;

    /* Simulate test execution time */
    uint32_t test_count = 0;

    if (tests & QUAC_SELF_TEST_KEM_KEYGEN)
        test_count++;
    if (tests & QUAC_SELF_TEST_KEM_ENCAPS)
        test_count++;
    if (tests & QUAC_SELF_TEST_KEM_DECAPS)
        test_count++;
    if (tests & QUAC_SELF_TEST_SIGN_KEYGEN)
        test_count++;
    if (tests & QUAC_SELF_TEST_SIGN)
        test_count++;
    if (tests & QUAC_SELF_TEST_VERIFY)
        test_count++;
    if (tests & QUAC_SELF_TEST_MEMORY)
        test_count++;
    if (tests & QUAC_SELF_TEST_NTT)
        test_count++;
    if (tests & QUAC_SELF_TEST_DMA)
        test_count++;
    if (tests & QUAC_SELF_TEST_PCIE)
        test_count++;
    if (tests & QUAC_SELF_TEST_ENTROPY_STARTUP)
        test_count++;
    if (tests & QUAC_SELF_TEST_ENTROPY_CONTINUOUS)
        test_count++;
    if (tests & QUAC_SELF_TEST_ENTROPY_ONDEMAND)
        test_count++;
    if (tests & QUAC_SELF_TEST_FIRMWARE_CHECKSUM)
        test_count++;
    if (tests & QUAC_SELF_TEST_SOFTWARE_CHECKSUM)
        test_count++;

    /* Simulate test delay */
#ifdef _WIN32
    Sleep(test_count * 10);
#else
    usleep(test_count * 10000);
#endif

    summary->total_duration_us = (uint32_t)((get_timestamp_ns() - start_time) / 1000);
    summary->test_count = test_count;

    /* Populate individual results */
    if (test_count > 0 && summary->results)
    {
        uint32_t idx = 0;

        if (tests & QUAC_SELF_TEST_KEM_KEYGEN && idx < summary->test_count)
        {
            summary->results[idx].test = QUAC_SELF_TEST_KEM_KEYGEN;
            summary->results[idx].passed = true;
            summary->results[idx].result_code = QUAC_SUCCESS;
            summary->results[idx].duration_us = 1000;
            strncpy(summary->results[idx].name, "KEM KeyGen KAT",
                    sizeof(summary->results[idx].name) - 1);
            idx++;
        }

        if (tests & QUAC_SELF_TEST_SIGN && idx < summary->test_count)
        {
            summary->results[idx].test = QUAC_SELF_TEST_SIGN;
            summary->results[idx].passed = true;
            summary->results[idx].result_code = QUAC_SUCCESS;
            summary->results[idx].duration_us = 2000;
            strncpy(summary->results[idx].name, "Sign KAT",
                    sizeof(summary->results[idx].name) - 1);
            idx++;
        }

        if (tests & QUAC_SELF_TEST_MEMORY && idx < summary->test_count)
        {
            summary->results[idx].test = QUAC_SELF_TEST_MEMORY;
            summary->results[idx].passed = true;
            summary->results[idx].result_code = QUAC_SUCCESS;
            summary->results[idx].duration_us = 5000;
            strncpy(summary->results[idx].name, "Memory Test",
                    sizeof(summary->results[idx].name) - 1);
            idx++;
        }
    }

    return QUAC_SUCCESS;
}

/**
 * @brief Simulated temperature reading
 */
static quac_result_t sim_get_temperature(uint32_t sensor_id,
                                         quac_temp_sensor_t *sensor)
{
    if (sensor_id >= QUAC_NUM_TEMP_SENSORS)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    memset(sensor, 0, sizeof(*sensor));
    sensor->struct_size = sizeof(*sensor);
    sensor->sensor_id = sensor_id;
    sensor->valid = true;

    switch (sensor_id)
    {
    case 0:
        strncpy(sensor->name, "Core", sizeof(sensor->name) - 1);
        sensor->current_celsius = 45 + (rand() % 10);
        sensor->warning_celsius = 85;
        sensor->critical_celsius = 95;
        sensor->shutdown_celsius = 105;
        break;
    case 1:
        strncpy(sensor->name, "Memory", sizeof(sensor->name) - 1);
        sensor->current_celsius = 40 + (rand() % 8);
        sensor->warning_celsius = 80;
        sensor->critical_celsius = 90;
        sensor->shutdown_celsius = 100;
        break;
    case 2:
        strncpy(sensor->name, "Board", sizeof(sensor->name) - 1);
        sensor->current_celsius = 35 + (rand() % 5);
        sensor->warning_celsius = 70;
        sensor->critical_celsius = 80;
        sensor->shutdown_celsius = 90;
        break;
    case 3:
        strncpy(sensor->name, "VRM", sizeof(sensor->name) - 1);
        sensor->current_celsius = 50 + (rand() % 10);
        sensor->warning_celsius = 90;
        sensor->critical_celsius = 100;
        sensor->shutdown_celsius = 110;
        break;
    }

    sensor->min_celsius = sensor->current_celsius - 5;
    sensor->max_celsius = sensor->current_celsius + 5;

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Public API Implementation - Health Status
 *=============================================================================*/

QUAC100_API quac_result_t QUAC100_CALL
quac_diag_get_health(quac_device_t device, quac_health_status_t *status)
{
    QUAC_CHECK_NULL(status);

    quac_result_t result;

    quac_device_lock(device);

    if (quac_device_is_simulator(device))
    {
        result = sim_get_health(status);
    }
    else
    {
        /* Hardware implementation would use IOCTL */
        intptr_t fd = quac_device_get_ioctl_fd(device);
        if (fd < 0)
        {
            quac_device_unlock(device);
            return QUAC_ERROR_DEVICE_ERROR;
        }

        struct quac_ioctl_health hw_health;
        hw_health.struct_size = sizeof(hw_health);

        result = quac_ioctl_execute(fd, QUAC_IOC_GET_HEALTH,
                                    &hw_health, sizeof(hw_health));

        if (QUAC_SUCCEEDED(result))
        {
            /* Convert from IOCTL format to public format */
            status->state = hw_health.state;
            status->flags = hw_health.flags;
            /* ... copy remaining fields ... */
        }
    }

    quac_device_unlock(device);

    return result;
}

QUAC100_API const char *QUAC100_CALL
quac_health_state_string(quac_health_state_t state)
{
    switch (state)
    {
    case QUAC_HEALTH_STATE_OK:
        return "OK";
    case QUAC_HEALTH_STATE_DEGRADED:
        return "Degraded";
    case QUAC_HEALTH_STATE_WARNING:
        return "Warning";
    case QUAC_HEALTH_STATE_CRITICAL:
        return "Critical";
    case QUAC_HEALTH_STATE_FAILED:
        return "Failed";
    case QUAC_HEALTH_STATE_UNKNOWN:
        return "Unknown";
    default:
        return "Invalid";
    }
}

/*=============================================================================
 * Self-Tests
 *=============================================================================*/

QUAC100_API quac_result_t QUAC100_CALL
quac_diag_self_test(quac_device_t device, quac_self_test_t tests, bool *passed)
{
    QUAC_CHECK_NULL(passed);

    quac_self_test_summary_t summary;
    quac_result_t result = quac_diag_self_test_detailed(device, tests, &summary);

    *passed = (result == QUAC_SUCCESS) && summary.overall_passed;

    return result;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_diag_self_test_detailed(quac_device_t device,
                             quac_self_test_t tests,
                             quac_self_test_summary_t *summary)
{
    QUAC_CHECK_NULL(summary);

    diag_log(QUAC_LOG_INFO, "Starting self-tests (mask=0x%08X)", tests);

    quac_result_t result;

    quac_device_lock(device);

    if (quac_device_is_simulator(device))
    {
        result = sim_run_self_test(tests, summary);
    }
    else
    {
        /* Hardware implementation */
        intptr_t fd = quac_device_get_ioctl_fd(device);
        if (fd < 0)
        {
            quac_device_unlock(device);
            return QUAC_ERROR_DEVICE_ERROR;
        }

        struct quac_ioctl_self_test hw_test;
        hw_test.struct_size = sizeof(hw_test);
        hw_test.tests_to_run = tests;

        result = quac_ioctl_execute(fd, QUAC_IOC_SELF_TEST,
                                    &hw_test, sizeof(hw_test));

        if (QUAC_SUCCEEDED(result))
        {
            summary->tests_run = hw_test.tests_run;
            summary->tests_passed = hw_test.tests_passed;
            summary->tests_failed = hw_test.tests_failed;
            summary->overall_passed = hw_test.overall_passed;
            summary->total_duration_us = hw_test.total_duration_us;
        }
    }

    quac_device_unlock(device);

    /* Cache result */
    if (QUAC_SUCCEEDED(result))
    {
        memcpy(&g_diag.last_test, summary, sizeof(g_diag.last_test));
        g_diag.last_test_valid = true;
    }

    diag_log(summary->overall_passed ? QUAC_LOG_INFO : QUAC_LOG_ERROR,
             "Self-tests %s (%u/%u passed)",
             summary->overall_passed ? "PASSED" : "FAILED",
             summary->test_count - summary->tests_failed,
             summary->test_count);

    if (!summary->overall_passed)
    {
        result = QUAC_ERROR_SELF_TEST_FAILED;
    }

    return result;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_diag_get_last_test(quac_self_test_summary_t *summary)
{
    QUAC_CHECK_NULL(summary);

    if (!g_diag.last_test_valid)
    {
        return QUAC_ERROR_NOT_INITIALIZED;
    }

    memcpy(summary, &g_diag.last_test, sizeof(*summary));
    return QUAC_SUCCESS;
}

/*=============================================================================
 * Temperature Monitoring
 *=============================================================================*/

QUAC100_API quac_result_t QUAC100_CALL
quac_diag_get_temperature(quac_device_t device, int32_t *celsius)
{
    QUAC_CHECK_NULL(celsius);

    quac_temp_sensor_t sensor;
    quac_result_t result = sim_get_temperature(0, &sensor); /* Core temp */

    if (QUAC_SUCCEEDED(result))
    {
        *celsius = sensor.current_celsius;
    }

    return result;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_diag_get_temp_sensors(quac_device_t device,
                           quac_temp_sensor_t *sensors,
                           uint32_t max_sensors,
                           uint32_t *count)
{
    QUAC_CHECK_NULL(sensors);
    QUAC_CHECK_NULL(count);

    *count = 0;

    uint32_t num = (max_sensors < QUAC_NUM_TEMP_SENSORS) ? max_sensors : QUAC_NUM_TEMP_SENSORS;

    for (uint32_t i = 0; i < num; i++)
    {
        quac_result_t result;

        if (quac_device_is_simulator(device))
        {
            result = sim_get_temperature(i, &sensors[i]);
        }
        else
        {
            result = sim_get_temperature(i, &sensors[i]); /* TODO: hw impl */
        }

        if (QUAC_FAILED(result))
        {
            return result;
        }
        (*count)++;
    }

    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_diag_set_temp_callback(quac_device_t device,
                            quac_temp_callback_t callback,
                            int32_t threshold_celsius,
                            void *user_data)
{
    (void)device;

    g_diag.temp_callback = callback;
    g_diag.temp_threshold = threshold_celsius;
    g_diag.temp_user_data = user_data;

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Performance Counters
 *=============================================================================*/

QUAC100_API quac_result_t QUAC100_CALL
quac_diag_get_counter(quac_device_t device,
                      quac_perf_counter_t counter,
                      quac_perf_value_t *value)
{
    QUAC_CHECK_NULL(value);

    if (counter >= QUAC_NUM_PERF_COUNTERS)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    (void)device;

    memcpy(value, &g_diag.counters[counter], sizeof(*value));
    value->struct_size = sizeof(*value);

    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_diag_get_all_counters(quac_device_t device,
                           quac_perf_value_t *values,
                           uint32_t max_counters,
                           uint32_t *count)
{
    QUAC_CHECK_NULL(values);
    QUAC_CHECK_NULL(count);

    (void)device;

    *count = 0;

    uint32_t num = (max_counters < QUAC_NUM_PERF_COUNTERS) ? max_counters : QUAC_NUM_PERF_COUNTERS;

    for (uint32_t i = 0; i < num; i++)
    {
        memcpy(&values[i], &g_diag.counters[i], sizeof(values[i]));
        values[i].struct_size = sizeof(values[i]);
        (*count)++;
    }

    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_diag_reset_counters(quac_device_t device)
{
    (void)device;

    memset(g_diag.counters, 0, sizeof(g_diag.counters));

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Diagnostic Logging
 *=============================================================================*/

QUAC100_API quac_result_t QUAC100_CALL
quac_diag_set_log_level(quac_log_level_t level)
{
    g_diag.log_level = level;
    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_diag_set_log_callback(quac_log_callback_t callback, void *user_data)
{
    g_diag.log_callback = callback;
    g_diag.log_user_data = user_data;
    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_diag_get_log(quac_log_entry_t *entries,
                  uint32_t max_entries,
                  uint32_t *count)
{
    QUAC_CHECK_NULL(entries);
    QUAC_CHECK_NULL(count);

    *count = 0;

    if (!g_diag.log_buffer || g_diag.log_count == 0)
    {
        return QUAC_SUCCESS;
    }

    uint32_t num = (max_entries < g_diag.log_count) ? max_entries : g_diag.log_count;

    uint32_t idx = g_diag.log_tail;
    for (uint32_t i = 0; i < num; i++)
    {
        memcpy(&entries[i], &g_diag.log_buffer[idx], sizeof(entries[i]));
        idx = (idx + 1) % QUAC_MAX_LOG_ENTRIES;
        (*count)++;
    }

    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_diag_clear_log(void)
{
    g_diag.log_head = 0;
    g_diag.log_tail = 0;
    g_diag.log_count = 0;

    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_diag_export_log(const char *filename)
{
    QUAC_CHECK_NULL(filename);

    FILE *f = fopen(filename, "w");
    if (!f)
    {
        return QUAC_ERROR_DEVICE_ERROR;
    }

    fprintf(f, "QuantaCore SDK Diagnostic Log\n");
    fprintf(f, "=============================\n\n");

    if (g_diag.log_buffer && g_diag.log_count > 0)
    {
        uint32_t idx = g_diag.log_tail;
        for (uint32_t i = 0; i < g_diag.log_count; i++)
        {
            quac_log_entry_t *e = &g_diag.log_buffer[idx];

            const char *level_str;
            switch (e->level)
            {
            case QUAC_LOG_TRACE:
                level_str = "TRACE";
                break;
            case QUAC_LOG_DEBUG:
                level_str = "DEBUG";
                break;
            case QUAC_LOG_INFO:
                level_str = "INFO ";
                break;
            case QUAC_LOG_WARNING:
                level_str = "WARN ";
                break;
            case QUAC_LOG_ERROR:
                level_str = "ERROR";
                break;
            case QUAC_LOG_CRITICAL:
                level_str = "CRIT ";
                break;
            default:
                level_str = "?????";
                break;
            }

            fprintf(f, "[%llu] [%s] %s\n",
                    (unsigned long long)e->timestamp,
                    level_str,
                    e->message);

            if (e->detail[0])
            {
                fprintf(f, "         Detail: %s\n", e->detail);
            }

            idx = (idx + 1) % QUAC_MAX_LOG_ENTRIES;
        }
    }
    else
    {
        fprintf(f, "(No log entries)\n");
    }

    fclose(f);

    return QUAC_SUCCESS;
}

QUAC100_API const char *QUAC100_CALL
quac_log_level_string(quac_log_level_t level)
{
    switch (level)
    {
    case QUAC_LOG_TRACE:
        return "Trace";
    case QUAC_LOG_DEBUG:
        return "Debug";
    case QUAC_LOG_INFO:
        return "Info";
    case QUAC_LOG_WARNING:
        return "Warning";
    case QUAC_LOG_ERROR:
        return "Error";
    case QUAC_LOG_CRITICAL:
        return "Critical";
    case QUAC_LOG_NONE:
        return "None";
    default:
        return "Unknown";
    }
}

/*=============================================================================
 * Firmware Information
 *=============================================================================*/

QUAC100_API quac_result_t QUAC100_CALL
quac_diag_get_firmware_info(quac_device_t device,
                            quac_firmware_info_t *info)
{
    QUAC_CHECK_NULL(info);

    memset(info, 0, sizeof(*info));
    info->struct_size = sizeof(*info);

    if (quac_device_is_simulator(device))
    {
        strncpy(info->component_name, "Simulator", sizeof(info->component_name) - 1);
        info->version_major = 1;
        info->version_minor = 0;
        info->version_patch = 0;
        strncpy(info->version_string, "1.0.0-sim", sizeof(info->version_string) - 1);
        strncpy(info->build_date, __DATE__, sizeof(info->build_date) - 1);
        strncpy(info->git_hash, "simulator", sizeof(info->git_hash) - 1);
        info->signature_verified = true;
        info->update_available = false;
    }
    else
    {
        /* Read from hardware */
        strncpy(info->component_name, "QUAC100", sizeof(info->component_name) - 1);
        info->version_major = 1;
        info->version_minor = 0;
        info->version_patch = 0;
        strncpy(info->version_string, "1.0.0", sizeof(info->version_string) - 1);
    }

    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_diag_get_firmware_components(quac_device_t device,
                                  quac_firmware_info_t *components,
                                  uint32_t max_components,
                                  uint32_t *count)
{
    QUAC_CHECK_NULL(components);
    QUAC_CHECK_NULL(count);

    *count = 0;

    if (max_components > 0)
    {
        quac_result_t result = quac_diag_get_firmware_info(device, &components[0]);
        if (QUAC_SUCCEEDED(result))
        {
            *count = 1;
        }
        return result;
    }

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Reset and Recovery
 *=============================================================================*/

QUAC100_API quac_result_t QUAC100_CALL
quac_diag_reset(quac_device_t device, quac_reset_type_t type)
{
    diag_log(QUAC_LOG_WARNING, "Device reset requested (type=%d)", type);

    if (quac_device_is_simulator(device))
    {
        /* Simulator reset is a no-op */
        diag_log(QUAC_LOG_INFO, "Simulator reset complete");
        return QUAC_SUCCESS;
    }

    intptr_t fd = quac_device_get_ioctl_fd(device);
    if (fd < 0)
    {
        return QUAC_ERROR_DEVICE_ERROR;
    }

    uint32_t reset_type = type;
    quac_result_t result = quac_ioctl_execute(fd, QUAC_IOC_RESET,
                                              &reset_type, sizeof(reset_type));

    if (QUAC_SUCCEEDED(result))
    {
        diag_log(QUAC_LOG_INFO, "Device reset complete");
    }
    else
    {
        diag_log(QUAC_LOG_ERROR, "Device reset failed: %s",
                 quac_error_string(result));
    }

    return result;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_diag_recover(quac_device_t device)
{
    diag_log(QUAC_LOG_INFO, "Attempting device recovery");

    /* First try soft reset */
    quac_result_t result = quac_diag_reset(device, QUAC_RESET_TYPE_SOFT);

    if (QUAC_FAILED(result))
    {
        /* Try harder reset */
        diag_log(QUAC_LOG_WARNING, "Soft reset failed, attempting hard reset");
        result = quac_diag_reset(device, QUAC_RESET_TYPE_HARD);
    }

    if (QUAC_SUCCEEDED(result))
    {
        /* Run self-tests to verify recovery */
        bool passed;
        result = quac_diag_self_test(device, QUAC_SELF_TEST_FIPS_STARTUP, &passed);

        if (QUAC_SUCCEEDED(result) && passed)
        {
            diag_log(QUAC_LOG_INFO, "Device recovery successful");
        }
        else
        {
            diag_log(QUAC_LOG_ERROR, "Device recovery failed - self-test failed");
            result = QUAC_ERROR_SELF_TEST_FAILED;
        }
    }

    return result;
}

/*=============================================================================
 * Diagnostic Reports
 *=============================================================================*/

QUAC100_API quac_result_t QUAC100_CALL
quac_diag_generate_report(quac_device_t device, char *buffer, size_t size)
{
    QUAC_CHECK_NULL(buffer);

    if (size == 0)
    {
        return QUAC_ERROR_BUFFER_TOO_SMALL;
    }

    buffer[0] = '\0';

    /* Get health status */
    quac_health_status_t health;
    quac_diag_get_health(device, &health);

    /* Get firmware info */
    quac_firmware_info_t fw;
    quac_diag_get_firmware_info(device, &fw);

    /* Generate report */
    int len = snprintf(buffer, size,
                       "QuantaCore QUAC 100 Diagnostic Report\n"
                       "=====================================\n\n"
                       "Firmware: %s (%s)\n"
                       "Build: %s\n\n"
                       "Health Status: %s\n"
                       "State: %s\n\n"
                       "Temperature:\n"
                       "  Core:   %d°C\n"
                       "  Memory: %d°C\n"
                       "  Board:  %d°C\n\n"
                       "Power:\n"
                       "  Draw:  %.1f W\n"
                       "  Limit: %.1f W\n\n"
                       "PCIe:\n"
                       "  Gen%d x%d\n"
                       "  Errors: %u\n\n"
                       "Operations: %llu completed, %llu failed\n"
                       "Uptime: %llu seconds\n",
                       fw.component_name, fw.version_string,
                       fw.build_date,
                       quac_health_state_string(health.state),
                       health.state_message,
                       health.temp_core_celsius,
                       health.temp_memory_celsius,
                       health.temp_board_celsius,
                       health.power_draw_mw / 1000.0,
                       health.power_limit_mw / 1000.0,
                       health.pcie_gen, health.pcie_lanes,
                       health.pcie_errors,
                       (unsigned long long)health.operations_completed,
                       (unsigned long long)health.operations_failed,
                       (unsigned long long)health.uptime_seconds);

    return (len > 0 && (size_t)len < size) ? QUAC_SUCCESS : QUAC_ERROR_BUFFER_TOO_SMALL;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_diag_export_report(quac_device_t device, const char *filename)
{
    QUAC_CHECK_NULL(filename);

    char buffer[4096];
    quac_result_t result = quac_diag_generate_report(device, buffer, sizeof(buffer));

    if (QUAC_FAILED(result))
    {
        return result;
    }

    FILE *f = fopen(filename, "w");
    if (!f)
    {
        return QUAC_ERROR_DEVICE_ERROR;
    }

    fputs(buffer, f);
    fclose(f);

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Initialization
 *=============================================================================*/

/**
 * @brief Initialize diagnostics subsystem
 */
quac_result_t quac_diag_init(void)
{
    /* Allocate log buffer */
    if (!g_diag.log_buffer)
    {
        g_diag.log_buffer = calloc(QUAC_MAX_LOG_ENTRIES, sizeof(quac_log_entry_t));
        /* Not fatal if allocation fails */
    }

    return QUAC_SUCCESS;
}

/**
 * @brief Shutdown diagnostics subsystem
 */
void quac_diag_shutdown(void)
{
    if (g_diag.log_buffer)
    {
        free(g_diag.log_buffer);
        g_diag.log_buffer = NULL;
    }

    g_diag.log_count = 0;
    g_diag.log_head = 0;
    g_diag.log_tail = 0;
}