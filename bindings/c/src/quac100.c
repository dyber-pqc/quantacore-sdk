/**
 * @file quac100.c
 * @brief QUAC 100 SDK - Main Library Implementation
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 */

#include "quac100/quac100.h"
#include "internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

/*============================================================================
 * Version Information
 *============================================================================*/

#define QUAC_VERSION_MAJOR 1
#define QUAC_VERSION_MINOR 0
#define QUAC_VERSION_PATCH 0
#define QUAC_VERSION_STRING "1.0.0"

#ifndef QUAC_BUILD_DATE
#define QUAC_BUILD_DATE __DATE__
#endif

#ifndef QUAC_BUILD_TIME
#define QUAC_BUILD_TIME __TIME__
#endif

/*============================================================================
 * Global State
 *============================================================================*/

static struct
{
    bool initialized;
    uint32_t flags;
    quac_log_level_t log_level;
    quac_log_callback_t log_callback;
    void *log_user_data;
    quac_status_t last_error;
    char error_details[256];

#ifdef QUAC_PLATFORM_WINDOWS
    CRITICAL_SECTION init_lock;
#else
    pthread_mutex_t init_lock;
#endif
} g_quac_state = {
    .initialized = false,
    .flags = 0,
    .log_level = QUAC_LOG_WARNING,
    .log_callback = NULL,
    .log_user_data = NULL,
    .last_error = QUAC_SUCCESS,
};

static bool g_lock_initialized = false;

/*============================================================================
 * Internal Functions
 *============================================================================*/

static void init_global_lock(void)
{
    if (g_lock_initialized)
        return;

#ifdef QUAC_PLATFORM_WINDOWS
    InitializeCriticalSection(&g_quac_state.init_lock);
#else
    pthread_mutex_init(&g_quac_state.init_lock, NULL);
#endif
    g_lock_initialized = true;
}

static void lock_global(void)
{
    init_global_lock();
#ifdef QUAC_PLATFORM_WINDOWS
    EnterCriticalSection(&g_quac_state.init_lock);
#else
    pthread_mutex_lock(&g_quac_state.init_lock);
#endif
}

static void unlock_global(void)
{
#ifdef QUAC_PLATFORM_WINDOWS
    LeaveCriticalSection(&g_quac_state.init_lock);
#else
    pthread_mutex_unlock(&g_quac_state.init_lock);
#endif
}

void quac_internal_log(quac_log_level_t level, const char *format, ...)
{
    if (level > g_quac_state.log_level)
        return;

    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    if (g_quac_state.log_callback)
    {
        g_quac_state.log_callback(level, buffer, g_quac_state.log_user_data);
    }
    else
    {
        const char *level_str;
        switch (level)
        {
        case QUAC_LOG_ERROR:
            level_str = "ERROR";
            break;
        case QUAC_LOG_WARNING:
            level_str = "WARN";
            break;
        case QUAC_LOG_INFO:
            level_str = "INFO";
            break;
        case QUAC_LOG_DEBUG:
            level_str = "DEBUG";
            break;
        case QUAC_LOG_TRACE:
            level_str = "TRACE";
            break;
        default:
            level_str = "???";
            break;
        }
        fprintf(stderr, "[QUAC100] [%s] %s\n", level_str, buffer);
    }
}

void quac_internal_set_error(quac_status_t status, const char *details)
{
    g_quac_state.last_error = status;
    if (details)
    {
        strncpy(g_quac_state.error_details, details, sizeof(g_quac_state.error_details) - 1);
        g_quac_state.error_details[sizeof(g_quac_state.error_details) - 1] = '\0';
    }
    else
    {
        g_quac_state.error_details[0] = '\0';
    }
}

/*============================================================================
 * Library Management
 *============================================================================*/

QUAC_API quac_status_t quac_init(uint32_t flags)
{
    lock_global();

    if (g_quac_state.initialized)
    {
        unlock_global();
        return QUAC_SUCCESS;
    }

    QUAC_LOG_INFO("Initializing QUAC 100 SDK v%s", QUAC_VERSION_STRING);
    QUAC_LOG_DEBUG("Flags: 0x%08X", flags);

    /* Initialize hardware abstraction layer */
    quac_status_t status = quac_hal_init(flags);
    if (status != QUAC_SUCCESS)
    {
        QUAC_LOG_ERROR("HAL initialization failed: %s", quac_error_string(status));
        unlock_global();
        return status;
    }

    /* Discover devices */
    status = quac_hal_discover_devices();
    if (status != QUAC_SUCCESS && status != QUAC_ERROR_DEVICE_NOT_FOUND)
    {
        QUAC_LOG_ERROR("Device discovery failed: %s", quac_error_string(status));
        quac_hal_cleanup();
        unlock_global();
        return status;
    }

    g_quac_state.flags = flags;
    g_quac_state.initialized = true;

    QUAC_LOG_INFO("QUAC 100 SDK initialized successfully");

    unlock_global();
    return QUAC_SUCCESS;
}

QUAC_API quac_status_t quac_cleanup(void)
{
    lock_global();

    if (!g_quac_state.initialized)
    {
        unlock_global();
        return QUAC_SUCCESS;
    }

    QUAC_LOG_INFO("Cleaning up QUAC 100 SDK");

    /* Cleanup hardware abstraction layer */
    quac_status_t status = quac_hal_cleanup();

    g_quac_state.initialized = false;
    g_quac_state.flags = 0;

    unlock_global();
    return status;
}

QUAC_API int quac_is_initialized(void)
{
    return g_quac_state.initialized ? 1 : 0;
}

QUAC_API const char *quac_version(void)
{
    return QUAC_VERSION_STRING;
}

QUAC_API quac_status_t quac_version_info(int *major, int *minor, int *patch)
{
    if (!major || !minor || !patch)
    {
        return QUAC_ERROR_INVALID_PARAM;
    }

    *major = QUAC_VERSION_MAJOR;
    *minor = QUAC_VERSION_MINOR;
    *patch = QUAC_VERSION_PATCH;

    return QUAC_SUCCESS;
}

QUAC_API const char *quac_build_info(void)
{
    static char build_info[256] = {0};

    if (build_info[0] == '\0')
    {
        snprintf(build_info, sizeof(build_info),
                 "QUAC 100 SDK v%s\n"
                 "Built: %s %s\n"
#ifdef __clang__
                 "Compiler: Clang %d.%d.%d\n"
#elif defined(__GNUC__)
                 "Compiler: GCC %d.%d.%d\n"
#elif defined(_MSC_VER)
                 "Compiler: MSVC %d\n"
#else
                 "Compiler: Unknown\n"
#endif
                 "Platform: "
#ifdef QUAC_PLATFORM_WINDOWS
                 "Windows"
#elif defined(QUAC_PLATFORM_MACOS)
                 "macOS"
#elif defined(QUAC_PLATFORM_LINUX)
                 "Linux"
#else
                 "Unknown"
#endif
                 "\n",
                 QUAC_VERSION_STRING,
                 QUAC_BUILD_DATE, QUAC_BUILD_TIME
#ifdef __clang__
                 ,
                 __clang_major__, __clang_minor__, __clang_patchlevel__
#elif defined(__GNUC__)
                 ,
                 __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__
#elif defined(_MSC_VER)
                 ,
                 _MSC_VER
#endif
        );
    }

    return build_info;
}

/*============================================================================
 * Error Handling
 *============================================================================*/

QUAC_API const char *quac_error_string(quac_status_t status)
{
    switch (status)
    {
    case QUAC_SUCCESS:
        return "Success";
    case QUAC_ERROR:
        return "Generic error";
    case QUAC_ERROR_INVALID_PARAM:
        return "Invalid parameter";
    case QUAC_ERROR_BUFFER_SMALL:
        return "Buffer too small";
    case QUAC_ERROR_DEVICE_NOT_FOUND:
        return "Device not found";
    case QUAC_ERROR_DEVICE_BUSY:
        return "Device busy";
    case QUAC_ERROR_DEVICE:
        return "Device error";
    case QUAC_ERROR_OUT_OF_MEMORY:
        return "Out of memory";
    case QUAC_ERROR_NOT_SUPPORTED:
        return "Not supported";
    case QUAC_ERROR_AUTH_REQUIRED:
        return "Authentication required";
    case QUAC_ERROR_AUTH_FAILED:
        return "Authentication failed";
    case QUAC_ERROR_KEY_NOT_FOUND:
        return "Key not found";
    case QUAC_ERROR_INVALID_KEY:
        return "Invalid key";
    case QUAC_ERROR_VERIFY_FAILED:
        return "Verification failed";
    case QUAC_ERROR_DECAPS_FAILED:
        return "Decapsulation failed";
    case QUAC_ERROR_HARDWARE_UNAVAIL:
        return "Hardware unavailable";
    case QUAC_ERROR_TIMEOUT:
        return "Timeout";
    case QUAC_ERROR_NOT_INITIALIZED:
        return "Not initialized";
    case QUAC_ERROR_ALREADY_INIT:
        return "Already initialized";
    case QUAC_ERROR_INVALID_HANDLE:
        return "Invalid handle";
    case QUAC_ERROR_CANCELLED:
        return "Cancelled";
    case QUAC_ERROR_ENTROPY_DEPLETED:
        return "Entropy depleted";
    case QUAC_ERROR_SELF_TEST_FAILED:
        return "Self-test failed";
    case QUAC_ERROR_TAMPER_DETECTED:
        return "Tamper detected";
    case QUAC_ERROR_TEMPERATURE:
        return "Temperature error";
    case QUAC_ERROR_POWER:
        return "Power error";
    case QUAC_ERROR_INTERNAL:
        return "Internal error";
    default:
        return "Unknown error";
    }
}

QUAC_API quac_status_t quac_get_error_details(
    quac_device_t device,
    char *buffer,
    size_t buffer_size)
{
    if (!buffer || buffer_size == 0)
    {
        return QUAC_ERROR_INVALID_PARAM;
    }

    /* TODO: Get device-specific error details if device is provided */

    strncpy(buffer, g_quac_state.error_details, buffer_size - 1);
    buffer[buffer_size - 1] = '\0';

    return QUAC_SUCCESS;
}

QUAC_API void quac_clear_error(quac_device_t device)
{
    g_quac_state.last_error = QUAC_SUCCESS;
    g_quac_state.error_details[0] = '\0';

    /* TODO: Clear device-specific error if device is provided */
}

/*============================================================================
 * Logging
 *============================================================================*/

QUAC_API void quac_set_log_level(quac_log_level_t level)
{
    g_quac_state.log_level = level;
}

QUAC_API quac_log_level_t quac_get_log_level(void)
{
    return g_quac_state.log_level;
}

QUAC_API void quac_set_log_callback(
    quac_log_callback_t callback,
    void *user_data)
{
    g_quac_state.log_callback = callback;
    g_quac_state.log_user_data = user_data;
}

QUAC_API void quac_log(quac_log_level_t level, const char *format, ...)
{
    if (level > g_quac_state.log_level)
        return;

    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    quac_internal_log(level, "%s", buffer);
}

/*============================================================================
 * Algorithm Information
 *============================================================================*/

QUAC_API const char *quac_algorithm_name(int algorithm)
{
    /* KEM algorithms */
    switch ((quac_kem_algorithm_t)algorithm)
    {
    case QUAC_KEM_ML_KEM_512:
        return "ML-KEM-512";
    case QUAC_KEM_ML_KEM_768:
        return "ML-KEM-768";
    case QUAC_KEM_ML_KEM_1024:
        return "ML-KEM-1024";
    default:
        break;
    }

    /* Signature algorithms */
    switch ((quac_sign_algorithm_t)algorithm)
    {
    case QUAC_SIGN_ML_DSA_44:
        return "ML-DSA-44";
    case QUAC_SIGN_ML_DSA_65:
        return "ML-DSA-65";
    case QUAC_SIGN_ML_DSA_87:
        return "ML-DSA-87";
    case QUAC_SIGN_SLH_DSA_SHA2_128S:
        return "SLH-DSA-SHA2-128s";
    case QUAC_SIGN_SLH_DSA_SHA2_128F:
        return "SLH-DSA-SHA2-128f";
    case QUAC_SIGN_SLH_DSA_SHA2_192S:
        return "SLH-DSA-SHA2-192s";
    case QUAC_SIGN_SLH_DSA_SHA2_192F:
        return "SLH-DSA-SHA2-192f";
    case QUAC_SIGN_SLH_DSA_SHA2_256S:
        return "SLH-DSA-SHA2-256s";
    case QUAC_SIGN_SLH_DSA_SHA2_256F:
        return "SLH-DSA-SHA2-256f";
    default:
        break;
    }

    return "Unknown";
}

QUAC_API int quac_is_kem_algorithm(int algorithm)
{
    return algorithm >= QUAC_KEM_ML_KEM_512 && algorithm <= QUAC_KEM_ML_KEM_1024;
}

QUAC_API int quac_is_sign_algorithm(int algorithm)
{
    return algorithm >= QUAC_SIGN_ML_DSA_44 && algorithm <= QUAC_SIGN_SLH_DSA_SHAKE_256F;
}

QUAC_API int quac_algorithm_security_level(int algorithm)
{
    /* KEM algorithms */
    switch ((quac_kem_algorithm_t)algorithm)
    {
    case QUAC_KEM_ML_KEM_512:
        return 1;
    case QUAC_KEM_ML_KEM_768:
        return 3;
    case QUAC_KEM_ML_KEM_1024:
        return 5;
    default:
        break;
    }

    /* Signature algorithms */
    switch ((quac_sign_algorithm_t)algorithm)
    {
    case QUAC_SIGN_ML_DSA_44:
        return 2;
    case QUAC_SIGN_ML_DSA_65:
        return 3;
    case QUAC_SIGN_ML_DSA_87:
        return 5;
    case QUAC_SIGN_SLH_DSA_SHA2_128S:
    case QUAC_SIGN_SLH_DSA_SHA2_128F:
        return 1;
    case QUAC_SIGN_SLH_DSA_SHA2_192S:
    case QUAC_SIGN_SLH_DSA_SHA2_192F:
        return 3;
    case QUAC_SIGN_SLH_DSA_SHA2_256S:
    case QUAC_SIGN_SLH_DSA_SHA2_256F:
        return 5;
    default:
        break;
    }

    return 0;
}

/*============================================================================
 * Time Functions
 *============================================================================*/

QUAC_API uint64_t quac_timestamp_ns(void)
{
#ifdef QUAC_PLATFORM_WINDOWS
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (uint64_t)(count.QuadPart * 1000000000ULL / freq.QuadPart);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
#endif
}

QUAC_API uint64_t quac_timestamp_us(void)
{
    return quac_timestamp_ns() / 1000;
}

QUAC_API uint64_t quac_timestamp_ms(void)
{
    return quac_timestamp_ns() / 1000000;
}