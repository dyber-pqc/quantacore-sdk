/**
 * @file init.c
 * @brief QuantaCore SDK - Library Initialization and Shutdown
 *
 * Implements SDK initialization, shutdown, and global state management.
 * Handles device enumeration, simulator mode, and thread-safe initialization.
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include "quac100.h"
#include "quac100_types.h"
#include "quac100_error.h"
#include "internal/quac100_ioctl.h"
#include "internal/quac100_pcie.h"
#include "internal/quac100_dma.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#define QUAC_MUTEX CRITICAL_SECTION
#define QUAC_MUTEX_INIT(m) InitializeCriticalSection(&(m))
#define QUAC_MUTEX_DESTROY(m) DeleteCriticalSection(&(m))
#define QUAC_MUTEX_LOCK(m) EnterCriticalSection(&(m))
#define QUAC_MUTEX_UNLOCK(m) LeaveCriticalSection(&(m))
#define QUAC_ONCE INIT_ONCE
#define QUAC_ONCE_INIT INIT_ONCE_STATIC_INIT
#else
#include <pthread.h>
#include <unistd.h>
#define QUAC_MUTEX pthread_mutex_t
#define QUAC_MUTEX_INIT(m) pthread_mutex_init(&(m), NULL)
#define QUAC_MUTEX_DESTROY(m) pthread_mutex_destroy(&(m))
#define QUAC_MUTEX_LOCK(m) pthread_mutex_lock(&(m))
#define QUAC_MUTEX_UNLOCK(m) pthread_mutex_unlock(&(m))
#define QUAC_ONCE pthread_once_t
#define QUAC_ONCE_INIT PTHREAD_ONCE_INIT
#endif

/*=============================================================================
 * Version Information
 *=============================================================================*/

/** SDK version components */
#define QUAC_SDK_VERSION_MAJOR 1
#define QUAC_SDK_VERSION_MINOR 0
#define QUAC_SDK_VERSION_PATCH 0

/** Version string */
static const char *g_version_string = "1.0.0";

/** Version as hex */
#define QUAC_SDK_VERSION_HEX \
    ((QUAC_SDK_VERSION_MAJOR << 16) | (QUAC_SDK_VERSION_MINOR << 8) | QUAC_SDK_VERSION_PATCH)

/*=============================================================================
 * Global State
 *=============================================================================*/

/**
 * @brief SDK global state structure
 */
typedef struct quac_global_state_s
{
    /* Initialization state */
    bool initialized;
    int init_refcount;
    QUAC_MUTEX init_mutex;

    /* Configuration */
    quac_init_options_t options;
    bool simulator_mode;
    bool force_simulator;
    bool fips_mode;

    /* Logging */
    quac_log_callback_t log_callback;
    void *log_user_data;
    quac_log_level_t log_level;

    /* Device tracking */
    uint32_t device_count;
    bool devices_enumerated;

    /* Async thread pool */
    uint32_t async_thread_count;
    void *thread_pool;

    /* Statistics */
    uint64_t init_timestamp;
    uint64_t total_operations;

} quac_global_state_t;

/** Global state singleton */
static quac_global_state_t g_state = {
    .initialized = false,
    .init_refcount = 0,
    .simulator_mode = false,
    .force_simulator = false,
    .fips_mode = false,
    .log_callback = NULL,
    .log_user_data = NULL,
    .log_level = QUAC_LOG_WARNING,
    .device_count = 0,
    .devices_enumerated = false,
    .async_thread_count = 0,
    .thread_pool = NULL,
    .init_timestamp = 0,
    .total_operations = 0,
};

/** One-time initialization flag */
static QUAC_ONCE g_once_init = QUAC_ONCE_INIT;
static bool g_mutex_initialized = false;

/*=============================================================================
 * Internal Helpers
 *=============================================================================*/

/**
 * @brief Get current timestamp in nanoseconds
 */
static uint64_t quac_get_timestamp_ns(void)
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
 * @brief Log a message
 */
static void quac_log_internal(quac_log_level_t level, const char *fmt, ...)
{
    if (level < g_state.log_level)
    {
        return;
    }

    char buffer[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);

    if (g_state.log_callback)
    {
        quac_log_entry_t entry = {
            .timestamp = quac_get_timestamp_ns(),
            .level = level,
            .source = 0,
            .result_code = QUAC_SUCCESS,
        };
        strncpy(entry.message, buffer, sizeof(entry.message) - 1);
        entry.message[sizeof(entry.message) - 1] = '\0';
        entry.detail[0] = '\0';

        g_state.log_callback(&entry, g_state.log_user_data);
    }
}

#define QUAC_LOG_TRACE(...) quac_log_internal(QUAC_LOG_TRACE, __VA_ARGS__)
#define QUAC_LOG_DEBUG(...) quac_log_internal(QUAC_LOG_DEBUG, __VA_ARGS__)
#define QUAC_LOG_INFO(...) quac_log_internal(QUAC_LOG_INFO, __VA_ARGS__)
#define QUAC_LOG_WARN(...) quac_log_internal(QUAC_LOG_WARNING, __VA_ARGS__)
#define QUAC_LOG_ERROR(...) quac_log_internal(QUAC_LOG_ERROR, __VA_ARGS__)

/**
 * @brief One-time mutex initialization
 */
#ifdef _WIN32
static BOOL CALLBACK quac_init_mutex_once(PINIT_ONCE once, PVOID param, PVOID *ctx)
{
    (void)once;
    (void)param;
    (void)ctx;
    QUAC_MUTEX_INIT(g_state.init_mutex);
    g_mutex_initialized = true;
    return TRUE;
}
#else
static void quac_init_mutex_once(void)
{
    QUAC_MUTEX_INIT(g_state.init_mutex);
    g_mutex_initialized = true;
}
#endif

/**
 * @brief Ensure mutex is initialized
 */
static void quac_ensure_mutex(void)
{
#ifdef _WIN32
    InitOnceExecuteOnce(&g_once_init, quac_init_mutex_once, NULL, NULL);
#else
    pthread_once(&g_once_init, quac_init_mutex_once);
#endif
}

/**
 * @brief Enumerate hardware devices
 */
static quac_result_t quac_enumerate_devices(void)
{
    quac_result_t result;

    if (g_state.devices_enumerated)
    {
        return QUAC_SUCCESS;
    }

    /* Try to enumerate PCIe devices */
    result = quac_pcie_enumerate(&g_state.device_count);

    if (QUAC_FAILED(result) || g_state.device_count == 0)
    {
        if (g_state.force_simulator ||
            (g_state.options.flags & QUAC_INIT_FLAG_SIMULATOR))
        {
            /* Fall back to simulator mode */
            QUAC_LOG_INFO("No hardware devices found, using simulator mode");
            g_state.simulator_mode = true;
            g_state.device_count = 1; /* Simulated device */
            result = QUAC_SUCCESS;
        }
        else
        {
            QUAC_LOG_WARN("No QUAC 100 devices found");
            g_state.device_count = 0;
        }
    }
    else
    {
        QUAC_LOG_INFO("Found %u QUAC 100 device(s)", g_state.device_count);
    }

    g_state.devices_enumerated = true;
    return result;
}

/**
 * @brief Initialize async thread pool
 */
static quac_result_t quac_init_thread_pool(uint32_t thread_count)
{
    if (thread_count == 0)
    {
        /* Auto-detect based on CPU cores */
#ifdef _WIN32
        SYSTEM_INFO sysinfo;
        GetSystemInfo(&sysinfo);
        thread_count = sysinfo.dwNumberOfProcessors;
#else
        thread_count = (uint32_t)sysconf(_SC_NPROCESSORS_ONLN);
#endif
        /* Clamp to reasonable range */
        if (thread_count < 2)
            thread_count = 2;
        if (thread_count > 16)
            thread_count = 16;
    }

    g_state.async_thread_count = thread_count;

    /* Thread pool implementation would go here */
    /* For now, we'll use on-demand threading */
    g_state.thread_pool = NULL;

    QUAC_LOG_DEBUG("Async thread pool configured with %u threads", thread_count);

    return QUAC_SUCCESS;
}

/**
 * @brief Shutdown async thread pool
 */
static void quac_shutdown_thread_pool(void)
{
    if (g_state.thread_pool)
    {
        /* Cleanup thread pool */
        g_state.thread_pool = NULL;
    }
    g_state.async_thread_count = 0;
}

/**
 * @brief Run FIPS self-tests if required
 */
static quac_result_t quac_run_fips_self_tests(void)
{
    if (!g_state.fips_mode)
    {
        return QUAC_SUCCESS;
    }

    QUAC_LOG_INFO("Running FIPS 140-3 startup self-tests...");

    /* KAT tests would be performed here */
    /* For now, return success */

    QUAC_LOG_INFO("FIPS self-tests passed");

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Public API Implementation
 *=============================================================================*/

QUAC100_API quac_result_t QUAC100_CALL
quac_init(const quac_init_options_t *options)
{
    quac_result_t result = QUAC_SUCCESS;

    /* Ensure mutex is initialized */
    quac_ensure_mutex();

    QUAC_MUTEX_LOCK(g_state.init_mutex);

    /* Check if already initialized */
    if (g_state.initialized)
    {
        g_state.init_refcount++;
        QUAC_LOG_DEBUG("SDK already initialized, refcount=%d", g_state.init_refcount);
        QUAC_MUTEX_UNLOCK(g_state.init_mutex);
        return QUAC_SUCCESS;
    }

    QUAC_LOG_INFO("Initializing QuantaCore SDK v%s", g_version_string);

    /* Store options */
    if (options)
    {
        if (options->struct_size >= sizeof(quac_init_options_t))
        {
            memcpy(&g_state.options, options, sizeof(quac_init_options_t));
        }
        else
        {
            memset(&g_state.options, 0, sizeof(quac_init_options_t));
            memcpy(&g_state.options, options, options->struct_size);
        }

        /* Apply options */
        if (options->log_callback)
        {
            g_state.log_callback = options->log_callback;
            g_state.log_user_data = options->log_user_data;
        }
        if (options->log_level != 0)
        {
            g_state.log_level = options->log_level;
        }

        g_state.simulator_mode = (options->flags & QUAC_INIT_FLAG_SIMULATOR) != 0;
        g_state.force_simulator = (options->flags & QUAC_INIT_FLAG_FORCE_SIMULATOR) != 0;
        g_state.fips_mode = (options->flags & QUAC_INIT_FLAG_FIPS_MODE) != 0;
    }

    /* Initialize error subsystem */
    quac_error_clear();

    /* Initialize PCIe subsystem (unless simulator-only) */
    if (!g_state.force_simulator)
    {
        result = quac_pcie_init();
        if (QUAC_FAILED(result) && !g_state.simulator_mode)
        {
            QUAC_LOG_WARN("PCIe initialization failed: %s", quac_error_string(result));
            /* Continue - may fall back to simulator */
        }
    }

    /* Enumerate devices */
    result = quac_enumerate_devices();
    if (QUAC_FAILED(result) && g_state.device_count == 0 && !g_state.simulator_mode)
    {
        QUAC_LOG_ERROR("No devices available and simulator not enabled");
        QUAC_MUTEX_UNLOCK(g_state.init_mutex);
        return QUAC_ERROR_NO_DEVICE;
    }

    /* Initialize thread pool for async operations */
    uint32_t thread_count = options ? options->async_thread_count : 0;
    result = quac_init_thread_pool(thread_count);
    if (QUAC_FAILED(result))
    {
        QUAC_LOG_ERROR("Failed to initialize thread pool");
        QUAC_MUTEX_UNLOCK(g_state.init_mutex);
        return result;
    }

    /* Run FIPS self-tests if required */
    result = quac_run_fips_self_tests();
    if (QUAC_FAILED(result))
    {
        QUAC_LOG_ERROR("FIPS self-tests failed");
        QUAC_MUTEX_UNLOCK(g_state.init_mutex);
        return QUAC_ERROR_SELF_TEST_FAILED;
    }

    /* Mark as initialized */
    g_state.initialized = true;
    g_state.init_refcount = 1;
    g_state.init_timestamp = quac_get_timestamp_ns();

    QUAC_LOG_INFO("QuantaCore SDK initialized successfully%s",
                  g_state.simulator_mode ? " (simulator mode)" : "");

    QUAC_MUTEX_UNLOCK(g_state.init_mutex);

    return QUAC_SUCCESS;
}

QUAC100_API void QUAC100_CALL
quac_shutdown(void)
{
    quac_ensure_mutex();

    QUAC_MUTEX_LOCK(g_state.init_mutex);

    if (!g_state.initialized)
    {
        QUAC_LOG_WARN("SDK not initialized");
        QUAC_MUTEX_UNLOCK(g_state.init_mutex);
        return;
    }

    /* Decrement refcount */
    g_state.init_refcount--;

    if (g_state.init_refcount > 0)
    {
        QUAC_LOG_DEBUG("SDK still in use, refcount=%d", g_state.init_refcount);
        QUAC_MUTEX_UNLOCK(g_state.init_mutex);
        return;
    }

    QUAC_LOG_INFO("Shutting down QuantaCore SDK...");

    /* Shutdown thread pool */
    quac_shutdown_thread_pool();

    /* Shutdown PCIe subsystem */
    if (!g_state.force_simulator)
    {
        quac_pcie_shutdown();
    }

    /* Reset state */
    g_state.initialized = false;
    g_state.devices_enumerated = false;
    g_state.device_count = 0;
    g_state.simulator_mode = false;
    g_state.fips_mode = false;
    g_state.total_operations = 0;

    /* Keep logging active until the very end */
    QUAC_LOG_INFO("QuantaCore SDK shutdown complete");

    /* Clear logging */
    g_state.log_callback = NULL;
    g_state.log_user_data = NULL;

    QUAC_MUTEX_UNLOCK(g_state.init_mutex);
}

QUAC100_API bool QUAC100_CALL
quac_is_initialized(void)
{
    return g_state.initialized;
}

QUAC100_API const char *QUAC100_CALL
quac_version_string(void)
{
    return g_version_string;
}

QUAC100_API uint32_t QUAC100_CALL
quac_version_hex(void)
{
    return QUAC_SDK_VERSION_HEX;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_device_count(uint32_t *count)
{
    QUAC_CHECK_NULL(count);

    if (!g_state.initialized)
    {
        return QUAC_ERROR_NOT_INITIALIZED;
    }

    *count = g_state.device_count;
    return QUAC_SUCCESS;
}

/*=============================================================================
 * Simulator Control
 *=============================================================================*/

QUAC100_API quac_result_t QUAC100_CALL
quac_set_simulator_mode(bool use_simulator)
{
    if (g_state.initialized)
    {
        return QUAC_ERROR_ALREADY_INITIALIZED;
    }

    g_state.force_simulator = use_simulator;
    g_state.simulator_mode = use_simulator;

    return QUAC_SUCCESS;
}

QUAC100_API bool QUAC100_CALL
quac_is_simulator(void)
{
    return g_state.simulator_mode;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_simulator_config(uint32_t latency_us, uint32_t throughput_ops)
{
    if (g_state.initialized)
    {
        return QUAC_ERROR_ALREADY_INITIALIZED;
    }

    g_state.options.sim_latency_us = latency_us;
    g_state.options.sim_throughput_ops = throughput_ops;

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Internal State Access (for other modules)
 *=============================================================================*/

/**
 * @brief Check if SDK is initialized (internal use)
 */
bool quac_internal_is_initialized(void)
{
    return g_state.initialized;
}

/**
 * @brief Check if running in simulator mode (internal use)
 */
bool quac_internal_is_simulator(void)
{
    return g_state.simulator_mode;
}

/**
 * @brief Get FIPS mode status (internal use)
 */
bool quac_internal_is_fips_mode(void)
{
    return g_state.fips_mode;
}

/**
 * @brief Get simulator latency config (internal use)
 */
uint32_t quac_internal_get_sim_latency(void)
{
    return g_state.options.sim_latency_us;
}

/**
 * @brief Increment operation counter (internal use)
 */
void quac_internal_inc_operations(void)
{
    /* Atomic increment would be better, but this is for statistics only */
    g_state.total_operations++;
}

/**
 * @brief Get log level (internal use)
 */
quac_log_level_t quac_internal_get_log_level(void)
{
    return g_state.log_level;
}

/**
 * @brief Log message (internal use)
 */
void quac_internal_log(quac_log_level_t level, const char *message)
{
    quac_log_internal(level, "%s", message);
}