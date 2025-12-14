/**
 * @file error.c
 * @brief QuantaCore SDK - Error Handling Implementation
 *
 * Implements error reporting, error strings, extended error information,
 * error callbacks, and error statistics tracking.
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include "quac100.h"
#include "quac100_types.h"
#include "quac100_error.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#ifdef _WIN32
#include <windows.h>
#define QUAC_TLS __declspec(thread)
#else
#include <pthread.h>
#include <errno.h>
#define QUAC_TLS __thread
#endif

/*=============================================================================
 * Error Table
 *=============================================================================*/

/**
 * @brief Error definition entry
 */
static const quac_error_entry_t g_error_table[] = {
    /* Success */
    {QUAC_SUCCESS, "QUAC_SUCCESS", "Success", QUAC_SEVERITY_SUCCESS, true},

    /* General errors (0x0001-0x00FF) */
    {QUAC_ERROR_UNKNOWN, "QUAC_ERROR_UNKNOWN", "Unknown error", QUAC_SEVERITY_ERROR, false},
    {QUAC_ERROR_NOT_INITIALIZED, "QUAC_ERROR_NOT_INITIALIZED", "SDK not initialized", QUAC_SEVERITY_ERROR, true},
    {QUAC_ERROR_ALREADY_INITIALIZED, "QUAC_ERROR_ALREADY_INITIALIZED", "SDK already initialized", QUAC_SEVERITY_WARNING, true},
    {QUAC_ERROR_INVALID_PARAMETER, "QUAC_ERROR_INVALID_PARAMETER", "Invalid parameter", QUAC_SEVERITY_ERROR, true},
    {QUAC_ERROR_NULL_POINTER, "QUAC_ERROR_NULL_POINTER", "Null pointer", QUAC_SEVERITY_ERROR, true},
    {QUAC_ERROR_BUFFER_TOO_SMALL, "QUAC_ERROR_BUFFER_TOO_SMALL", "Buffer too small", QUAC_SEVERITY_ERROR, true},
    {QUAC_ERROR_OUT_OF_MEMORY, "QUAC_ERROR_OUT_OF_MEMORY", "Out of memory", QUAC_SEVERITY_ERROR, true},
    {QUAC_ERROR_NOT_SUPPORTED, "QUAC_ERROR_NOT_SUPPORTED", "Operation not supported", QUAC_SEVERITY_ERROR, false},
    {QUAC_ERROR_TIMEOUT, "QUAC_ERROR_TIMEOUT", "Operation timed out", QUAC_SEVERITY_ERROR, true},
    {QUAC_ERROR_CANCELLED, "QUAC_ERROR_CANCELLED", "Operation cancelled", QUAC_SEVERITY_WARNING, true},
    {QUAC_ERROR_BUSY, "QUAC_ERROR_BUSY", "Resource busy", QUAC_SEVERITY_ERROR, true},
    {QUAC_ERROR_OVERFLOW, "QUAC_ERROR_OVERFLOW", "Overflow error", QUAC_SEVERITY_ERROR, false},

    /* Device errors (0x0100-0x01FF) */
    {QUAC_ERROR_NO_DEVICE, "QUAC_ERROR_NO_DEVICE", "No device available", QUAC_SEVERITY_ERROR, false},
    {QUAC_ERROR_DEVICE_NOT_FOUND, "QUAC_ERROR_DEVICE_NOT_FOUND", "Device not found", QUAC_SEVERITY_ERROR, true},
    {QUAC_ERROR_DEVICE_OPEN_FAILED, "QUAC_ERROR_DEVICE_OPEN_FAILED", "Failed to open device", QUAC_SEVERITY_ERROR, true},
    {QUAC_ERROR_DEVICE_CLOSED, "QUAC_ERROR_DEVICE_CLOSED", "Device is closed", QUAC_SEVERITY_ERROR, true},
    {QUAC_ERROR_DEVICE_ERROR, "QUAC_ERROR_DEVICE_ERROR", "Device error", QUAC_SEVERITY_ERROR, true},
    {QUAC_ERROR_DEVICE_BUSY, "QUAC_ERROR_DEVICE_BUSY", "Device is busy", QUAC_SEVERITY_ERROR, true},
    {QUAC_ERROR_DEVICE_NOT_READY, "QUAC_ERROR_DEVICE_NOT_READY", "Device not ready", QUAC_SEVERITY_ERROR, true},
    {QUAC_ERROR_DEVICE_RESET, "QUAC_ERROR_DEVICE_RESET", "Device was reset", QUAC_SEVERITY_WARNING, true},
    {QUAC_ERROR_DEVICE_REMOVED, "QUAC_ERROR_DEVICE_REMOVED", "Device was removed", QUAC_SEVERITY_CRITICAL, false},
    {QUAC_ERROR_DRIVER_ERROR, "QUAC_ERROR_DRIVER_ERROR", "Driver error", QUAC_SEVERITY_ERROR, true},
    {QUAC_ERROR_FIRMWARE_ERROR, "QUAC_ERROR_FIRMWARE_ERROR", "Firmware error", QUAC_SEVERITY_ERROR, true},
    {QUAC_ERROR_HARDWARE_ERROR, "QUAC_ERROR_HARDWARE_ERROR", "Hardware error", QUAC_SEVERITY_CRITICAL, false},

    /* Cryptographic errors (0x0200-0x02FF) */
    {QUAC_ERROR_INVALID_ALGORITHM, "QUAC_ERROR_INVALID_ALGORITHM", "Invalid algorithm", QUAC_SEVERITY_ERROR, true},
    {QUAC_ERROR_INVALID_KEY, "QUAC_ERROR_INVALID_KEY", "Invalid key", QUAC_SEVERITY_ERROR, true},
    {QUAC_ERROR_INVALID_KEY_SIZE, "QUAC_ERROR_INVALID_KEY_SIZE", "Invalid key size", QUAC_SEVERITY_ERROR, true},
    {QUAC_ERROR_INVALID_CIPHERTEXT, "QUAC_ERROR_INVALID_CIPHERTEXT", "Invalid ciphertext", QUAC_SEVERITY_ERROR, true},
    {QUAC_ERROR_INVALID_SIGNATURE, "QUAC_ERROR_INVALID_SIGNATURE", "Invalid signature", QUAC_SEVERITY_ERROR, true},
    {QUAC_ERROR_DECAPSULATION_FAILED, "QUAC_ERROR_DECAPSULATION_FAILED", "Decapsulation failed", QUAC_SEVERITY_ERROR, true},
    {QUAC_ERROR_VERIFICATION_FAILED, "QUAC_ERROR_VERIFICATION_FAILED", "Signature verification failed", QUAC_SEVERITY_ERROR, true},
    {QUAC_ERROR_KEY_GENERATION_FAILED, "QUAC_ERROR_KEY_GENERATION_FAILED", "Key generation failed", QUAC_SEVERITY_ERROR, true},
    {QUAC_ERROR_SIGNING_FAILED, "QUAC_ERROR_SIGNING_FAILED", "Signing failed", QUAC_SEVERITY_ERROR, true},
    {QUAC_ERROR_ENCAPSULATION_FAILED, "QUAC_ERROR_ENCAPSULATION_FAILED", "Encapsulation failed", QUAC_SEVERITY_ERROR, true},

    /* Key management errors (0x0300-0x03FF) */
    {QUAC_ERROR_KEY_NOT_FOUND, "QUAC_ERROR_KEY_NOT_FOUND", "Key not found", QUAC_SEVERITY_ERROR, true},
    {QUAC_ERROR_KEY_EXISTS, "QUAC_ERROR_KEY_EXISTS", "Key already exists", QUAC_SEVERITY_ERROR, true},
    {QUAC_ERROR_KEY_SLOT_FULL, "QUAC_ERROR_KEY_SLOT_FULL", "Key storage full", QUAC_SEVERITY_ERROR, true},
    {QUAC_ERROR_KEY_LOCKED, "QUAC_ERROR_KEY_LOCKED", "Key is locked", QUAC_SEVERITY_ERROR, false},
    {QUAC_ERROR_KEY_EXPIRED, "QUAC_ERROR_KEY_EXPIRED", "Key has expired", QUAC_SEVERITY_ERROR, false},
    {QUAC_ERROR_KEY_USAGE_DENIED, "QUAC_ERROR_KEY_USAGE_DENIED", "Key usage denied", QUAC_SEVERITY_ERROR, false},
    {QUAC_ERROR_KEY_IMPORT_FAILED, "QUAC_ERROR_KEY_IMPORT_FAILED", "Key import failed", QUAC_SEVERITY_ERROR, true},
    {QUAC_ERROR_KEY_EXPORT_DENIED, "QUAC_ERROR_KEY_EXPORT_DENIED", "Key export denied", QUAC_SEVERITY_ERROR, false},

    /* QRNG errors (0x0400-0x04FF) */
    {QUAC_ERROR_ENTROPY_DEPLETED, "QUAC_ERROR_ENTROPY_DEPLETED", "Entropy pool depleted", QUAC_SEVERITY_ERROR, true},
    {QUAC_ERROR_ENTROPY_QUALITY, "QUAC_ERROR_ENTROPY_QUALITY", "Entropy quality insufficient", QUAC_SEVERITY_ERROR, true},
    {QUAC_ERROR_QRNG_FAILURE, "QUAC_ERROR_QRNG_FAILURE", "QRNG failure", QUAC_SEVERITY_CRITICAL, false},
    {QUAC_ERROR_HEALTH_TEST_FAILED, "QUAC_ERROR_HEALTH_TEST_FAILED", "Health test failed", QUAC_SEVERITY_CRITICAL, false},

    /* Async/batch errors (0x0500-0x05FF) */
    {QUAC_ERROR_INVALID_JOB_ID, "QUAC_ERROR_INVALID_JOB_ID", "Invalid job ID", QUAC_SEVERITY_ERROR, true},
    {QUAC_ERROR_JOB_NOT_FOUND, "QUAC_ERROR_JOB_NOT_FOUND", "Job not found", QUAC_SEVERITY_ERROR, true},
    {QUAC_ERROR_JOB_PENDING, "QUAC_ERROR_JOB_PENDING", "Job still pending", QUAC_SEVERITY_WARNING, true},
    {QUAC_ERROR_JOB_FAILED, "QUAC_ERROR_JOB_FAILED", "Job failed", QUAC_SEVERITY_ERROR, true},
    {QUAC_ERROR_QUEUE_FULL, "QUAC_ERROR_QUEUE_FULL", "Queue is full", QUAC_SEVERITY_ERROR, true},
    {QUAC_ERROR_BATCH_PARTIAL, "QUAC_ERROR_BATCH_PARTIAL", "Batch partially completed", QUAC_SEVERITY_WARNING, true},

    /* Security errors (0x0600-0x06FF) */
    {QUAC_ERROR_AUTHENTICATION, "QUAC_ERROR_AUTHENTICATION", "Authentication failed", QUAC_SEVERITY_ERROR, false},
    {QUAC_ERROR_AUTHORIZATION, "QUAC_ERROR_AUTHORIZATION", "Authorization denied", QUAC_SEVERITY_ERROR, false},
    {QUAC_ERROR_TAMPER_DETECTED, "QUAC_ERROR_TAMPER_DETECTED", "Tamper detected", QUAC_SEVERITY_FATAL, false},
    {QUAC_ERROR_SECURITY_VIOLATION, "QUAC_ERROR_SECURITY_VIOLATION", "Security violation", QUAC_SEVERITY_FATAL, false},
    {QUAC_ERROR_FIPS_MODE_REQUIRED, "QUAC_ERROR_FIPS_MODE_REQUIRED", "FIPS mode required", QUAC_SEVERITY_ERROR, false},
    {QUAC_ERROR_SELF_TEST_FAILED, "QUAC_ERROR_SELF_TEST_FAILED", "Self-test failed", QUAC_SEVERITY_FATAL, false},

    /* Simulator errors (0x0700-0x07FF) */
    {QUAC_ERROR_SIMULATOR_ONLY, "QUAC_ERROR_SIMULATOR_ONLY", "Simulator-only feature", QUAC_SEVERITY_WARNING, true},
    {QUAC_ERROR_HARDWARE_REQUIRED, "QUAC_ERROR_HARDWARE_REQUIRED", "Hardware required", QUAC_SEVERITY_ERROR, false},
};

#define QUAC_ERROR_TABLE_SIZE (sizeof(g_error_table) / sizeof(g_error_table[0]))

/*=============================================================================
 * Thread-Local Error State
 *=============================================================================*/

/**
 * @brief Thread-local error information
 */
static QUAC_TLS quac_error_info_t tls_error_info = {0};
static QUAC_TLS bool tls_error_valid = false;

/*=============================================================================
 * Global Error State
 *=============================================================================*/

/**
 * @brief Global error callback
 */
static quac_error_callback_t g_error_callback = NULL;
static void *g_error_callback_data = NULL;
static quac_error_filter_t g_error_filter = QUAC_ERROR_FILTER_ALL;

/**
 * @brief Global error statistics
 */
static quac_error_stats_t g_error_stats = {0};

/*=============================================================================
 * Internal Helpers
 *=============================================================================*/

/**
 * @brief Find error entry by result code
 */
static const quac_error_entry_t *find_error_entry(quac_result_t result)
{
    for (size_t i = 0; i < QUAC_ERROR_TABLE_SIZE; i++)
    {
        if (g_error_table[i].result == result)
        {
            return &g_error_table[i];
        }
    }
    return NULL;
}

/**
 * @brief Update error statistics
 */
static void update_error_stats(quac_result_t result, quac_error_severity_t severity)
{
    if (result == QUAC_SUCCESS)
    {
        return;
    }

    g_error_stats.total_errors++;

    switch (severity)
    {
    case QUAC_SEVERITY_WARNING:
        g_error_stats.warnings++;
        break;
    case QUAC_SEVERITY_ERROR:
        g_error_stats.errors++;
        break;
    case QUAC_SEVERITY_CRITICAL:
        g_error_stats.critical++;
        break;
    case QUAC_SEVERITY_FATAL:
        g_error_stats.fatal++;
        break;
    default:
        break;
    }

    /* Track by category */
    quac_error_category_t cat = QUAC_ERROR_CATEGORY(result);
    if (cat < 16)
    {
        g_error_stats.by_category[cat]++;
    }

    g_error_stats.last_error = result;
}

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

/*=============================================================================
 * Internal Error Recording (used by other modules)
 *=============================================================================*/

/**
 * @brief Record an error (internal use)
 */
void quac_error_record(quac_result_t result, const char *file, int line,
                       const char *func, const char *fmt, ...)
{
    if (result == QUAC_SUCCESS)
    {
        return;
    }

    const quac_error_entry_t *entry = find_error_entry(result);
    quac_error_severity_t severity = entry ? entry->severity : QUAC_SEVERITY_ERROR;

    /* Update thread-local error info */
    tls_error_info.struct_size = sizeof(quac_error_info_t);
    tls_error_info.result = result;
    tls_error_info.category = QUAC_ERROR_CATEGORY(result);
    tls_error_info.severity = severity;
    tls_error_info.timestamp = get_timestamp_ns();
    tls_error_info.line = line;
    tls_error_info.file = file;
    tls_error_info.function = func;

#ifdef _WIN32
    tls_error_info.os_error = GetLastError();
#else
    tls_error_info.os_error = errno;
#endif

    /* Format message */
    if (entry)
    {
        strncpy(tls_error_info.message, entry->message, sizeof(tls_error_info.message) - 1);
    }
    else
    {
        snprintf(tls_error_info.message, sizeof(tls_error_info.message),
                 "Error 0x%04X", result);
    }
    tls_error_info.message[sizeof(tls_error_info.message) - 1] = '\0';

    /* Format detail */
    if (fmt)
    {
        va_list args;
        va_start(args, fmt);
        vsnprintf(tls_error_info.detail, sizeof(tls_error_info.detail), fmt, args);
        va_end(args);
    }
    else
    {
        tls_error_info.detail[0] = '\0';
    }

    tls_error_valid = true;

    /* Update statistics */
    update_error_stats(result, severity);

    /* Invoke callback if registered */
    if (g_error_callback)
    {
        bool should_report = false;
        switch (severity)
        {
        case QUAC_SEVERITY_WARNING:
            should_report = (g_error_filter & QUAC_ERROR_FILTER_WARNINGS) != 0;
            break;
        case QUAC_SEVERITY_ERROR:
            should_report = (g_error_filter & QUAC_ERROR_FILTER_ERRORS) != 0;
            break;
        case QUAC_SEVERITY_CRITICAL:
            should_report = (g_error_filter & QUAC_ERROR_FILTER_CRITICAL) != 0;
            break;
        case QUAC_SEVERITY_FATAL:
            should_report = (g_error_filter & QUAC_ERROR_FILTER_FATAL) != 0;
            break;
        default:
            break;
        }

        if (should_report)
        {
            g_error_callback(&tls_error_info, g_error_callback_data);
        }
    }
}

/*=============================================================================
 * Public API Implementation
 *=============================================================================*/

QUAC100_API const char *QUAC100_CALL
quac_error_string(quac_result_t result)
{
    if (result == QUAC_SUCCESS)
    {
        return "Success";
    }

    const quac_error_entry_t *entry = find_error_entry(result);
    if (entry)
    {
        return entry->message;
    }

    return "Unknown error";
}

QUAC100_API const char *QUAC100_CALL
quac_error_name(quac_result_t result)
{
    const quac_error_entry_t *entry = find_error_entry(result);
    if (entry)
    {
        return entry->name;
    }

    return "QUAC_ERROR_UNKNOWN";
}

QUAC100_API quac_result_t QUAC100_CALL
quac_get_last_error(void)
{
    if (tls_error_valid)
    {
        return tls_error_info.result;
    }
    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_get_last_error_detail(char *buffer, size_t size)
{
    QUAC_CHECK_NULL(buffer);

    if (!tls_error_valid)
    {
        if (size > 0)
        {
            buffer[0] = '\0';
        }
        return QUAC_SUCCESS;
    }

    snprintf(buffer, size, "%s: %s",
             tls_error_info.message,
             tls_error_info.detail[0] ? tls_error_info.detail : "(no detail)");

    return QUAC_SUCCESS;
}

QUAC100_API quac_error_severity_t QUAC100_CALL
quac_error_severity(quac_result_t result)
{
    if (result == QUAC_SUCCESS)
    {
        return QUAC_SEVERITY_SUCCESS;
    }

    const quac_error_entry_t *entry = find_error_entry(result);
    if (entry)
    {
        return entry->severity;
    }

    return QUAC_SEVERITY_ERROR;
}

QUAC100_API bool QUAC100_CALL
quac_error_is_recoverable(quac_result_t result)
{
    if (result == QUAC_SUCCESS)
    {
        return true;
    }

    const quac_error_entry_t *entry = find_error_entry(result);
    if (entry)
    {
        return entry->recoverable;
    }

    return false;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_error_get_info(quac_error_info_t *info)
{
    QUAC_CHECK_NULL(info);

    if (!tls_error_valid)
    {
        memset(info, 0, sizeof(*info));
        info->struct_size = sizeof(*info);
        return QUAC_SUCCESS;
    }

    memcpy(info, &tls_error_info, sizeof(*info));
    return QUAC_SUCCESS;
}

QUAC100_API void QUAC100_CALL
quac_error_clear(void)
{
    tls_error_valid = false;
    memset(&tls_error_info, 0, sizeof(tls_error_info));
}

QUAC100_API const char *QUAC100_CALL
quac_error_category_name(quac_error_category_t category)
{
    switch (category)
    {
    case QUAC_ERROR_CAT_SUCCESS:
        return "Success";
    case QUAC_ERROR_CAT_DEVICE:
        return "Device";
    case QUAC_ERROR_CAT_CRYPTO:
        return "Cryptographic";
    case QUAC_ERROR_CAT_KEY:
        return "Key Management";
    case QUAC_ERROR_CAT_QRNG:
        return "QRNG";
    case QUAC_ERROR_CAT_ASYNC:
        return "Async/Batch";
    case QUAC_ERROR_CAT_SECURITY:
        return "Security";
    case QUAC_ERROR_CAT_SIMULATOR:
        return "Simulator";
    default:
        return "Unknown";
    }
}

QUAC100_API const char *QUAC100_CALL
quac_error_severity_name(quac_error_severity_t severity)
{
    switch (severity)
    {
    case QUAC_SEVERITY_SUCCESS:
        return "Success";
    case QUAC_SEVERITY_WARNING:
        return "Warning";
    case QUAC_SEVERITY_ERROR:
        return "Error";
    case QUAC_SEVERITY_CRITICAL:
        return "Critical";
    case QUAC_SEVERITY_FATAL:
        return "Fatal";
    default:
        return "Unknown";
    }
}

QUAC100_API size_t QUAC100_CALL
quac_error_format(quac_result_t result, char *buffer, size_t size)
{
    if (!buffer || size == 0)
    {
        return 0;
    }

    const quac_error_entry_t *entry = find_error_entry(result);
    quac_error_category_t cat = QUAC_ERROR_CATEGORY(result);
    quac_error_severity_t sev = entry ? entry->severity : QUAC_SEVERITY_ERROR;

    int len = snprintf(buffer, size, "[%s] %s (0x%04X): %s",
                       quac_error_severity_name(sev),
                       quac_error_category_name(cat),
                       result,
                       entry ? entry->message : "Unknown error");

    return (len > 0) ? (size_t)len : 0;
}

QUAC100_API size_t QUAC100_CALL
quac_error_format_info(const quac_error_info_t *info, char *buffer, size_t size)
{
    if (!buffer || size == 0 || !info)
    {
        return 0;
    }

    int len = snprintf(buffer, size,
                       "[%s] %s (0x%04X): %s\n"
                       "  File: %s:%d\n"
                       "  Function: %s\n"
                       "  OS Error: %u\n"
                       "  Detail: %s",
                       quac_error_severity_name(info->severity),
                       quac_error_category_name(info->category),
                       info->result,
                       info->message,
                       info->file ? info->file : "unknown",
                       info->line,
                       info->function ? info->function : "unknown",
                       info->os_error,
                       info->detail[0] ? info->detail : "(none)");

    return (len > 0) ? (size_t)len : 0;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_error_set_callback(quac_error_callback_t callback, void *user_data)
{
    g_error_callback = callback;
    g_error_callback_data = user_data;
    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_error_set_filter(quac_error_filter_t filter)
{
    g_error_filter = filter;
    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_error_get_stats(quac_error_stats_t *stats)
{
    QUAC_CHECK_NULL(stats);

    memcpy(stats, &g_error_stats, sizeof(*stats));
    stats->struct_size = sizeof(*stats);

    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_error_reset_stats(void)
{
    memset(&g_error_stats, 0, sizeof(g_error_stats));
    g_error_stats.struct_size = sizeof(g_error_stats);
    return QUAC_SUCCESS;
}

QUAC100_API const quac_error_entry_t *QUAC100_CALL
quac_error_lookup(quac_result_t result)
{
    return find_error_entry(result);
}

QUAC100_API const quac_error_entry_t *QUAC100_CALL
quac_error_enumerate(size_t index)
{
    if (index >= QUAC_ERROR_TABLE_SIZE)
    {
        return NULL;
    }
    return &g_error_table[index];
}

QUAC100_API size_t QUAC100_CALL
quac_error_count(void)
{
    return QUAC_ERROR_TABLE_SIZE;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_error_assert_impl(bool condition, quac_result_t result,
                       const char *file, int line, const char *func)
{
    if (condition)
    {
        return QUAC_SUCCESS;
    }

    quac_error_record(result, file, line, func, "Assertion failed");
    return result;
}