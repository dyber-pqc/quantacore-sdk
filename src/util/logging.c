/**
 * @file logging.c
 * @brief QuantaCore SDK - Logging Subsystem Implementation
 *
 * Provides a comprehensive logging facility with multiple output targets,
 * log levels, filtering, rotation, and thread-safe operation.
 *
 * Features:
 * - Multiple log levels (TRACE, DEBUG, INFO, WARN, ERROR, FATAL)
 * - Multiple output targets (console, file, callback, syslog)
 * - Log file rotation by size and count
 * - Colored console output (optional)
 * - Thread-safe logging with minimal contention
 * - Performance timestamps with microsecond resolution
 * - Module-based filtering
 * - Rate limiting for high-frequency messages
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <errno.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <io.h>
#define isatty _isatty
#define fileno _fileno
#else
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <syslog.h>
#endif

#include "quac100.h"
#include "quac100_types.h"

/*=============================================================================
 * Constants
 *=============================================================================*/

/** Maximum log message length */
#define QUAC_LOG_MAX_MESSAGE 4096

/** Maximum log file path length */
#define QUAC_LOG_MAX_PATH 512

/** Maximum module name length */
#define QUAC_LOG_MAX_MODULE 64

/** Maximum number of log filters */
#define QUAC_LOG_MAX_FILTERS 32

/** Default log file rotation size (10 MB) */
#define QUAC_LOG_DEFAULT_ROTATE_SIZE (10 * 1024 * 1024)

/** Default number of rotated files to keep */
#define QUAC_LOG_DEFAULT_ROTATE_COUNT 5

/** Rate limit window (milliseconds) */
#define QUAC_LOG_RATE_LIMIT_WINDOW 1000

/** Rate limit max messages per window */
#define QUAC_LOG_RATE_LIMIT_MAX 100

/*=============================================================================
 * Types
 *=============================================================================*/

/** Log levels */
typedef enum quac_log_level_e
{
    QUAC_LOG_TRACE = 0,
    QUAC_LOG_DEBUG = 1,
    QUAC_LOG_INFO = 2,
    QUAC_LOG_WARN = 3,
    QUAC_LOG_ERROR = 4,
    QUAC_LOG_FATAL = 5,
    QUAC_LOG_NONE = 6
} quac_log_level_t;

/** Log output targets */
typedef enum quac_log_target_e
{
    QUAC_LOG_TARGET_NONE = 0,
    QUAC_LOG_TARGET_CONSOLE = (1 << 0),
    QUAC_LOG_TARGET_FILE = (1 << 1),
    QUAC_LOG_TARGET_CALLBACK = (1 << 2),
    QUAC_LOG_TARGET_SYSLOG = (1 << 3),
    QUAC_LOG_TARGET_ALL = 0x0F
} quac_log_target_t;

/** Log callback function type */
typedef void (*quac_log_callback_t)(quac_log_level_t level,
                                    const char *module,
                                    const char *message,
                                    void *user_data);

/** Log filter entry */
typedef struct quac_log_filter_s
{
    char module[QUAC_LOG_MAX_MODULE];
    quac_log_level_t level;
    bool enabled;
} quac_log_filter_t;

/** Rate limiter entry */
typedef struct quac_log_rate_limit_s
{
    uint64_t window_start;
    uint32_t message_count;
    uint32_t dropped_count;
} quac_log_rate_limit_t;

/** Logger state */
typedef struct quac_logger_s
{
    /* Configuration */
    quac_log_level_t level;
    uint32_t targets;
    bool colors_enabled;
    bool timestamps_enabled;
    bool module_enabled;
    bool rate_limit_enabled;

    /* File output */
    char file_path[QUAC_LOG_MAX_PATH];
    FILE *file_handle;
    size_t file_size;
    size_t rotate_size;
    uint32_t rotate_count;

    /* Callback output */
    quac_log_callback_t callback;
    void *callback_data;

    /* Filters */
    quac_log_filter_t filters[QUAC_LOG_MAX_FILTERS];
    uint32_t filter_count;

    /* Rate limiting */
    quac_log_rate_limit_t rate_limiter;

    /* Statistics */
    uint64_t messages_logged;
    uint64_t messages_dropped;
    uint64_t bytes_written;

    /* Thread safety */
#ifdef _WIN32
    CRITICAL_SECTION lock;
#else
    pthread_mutex_t lock;
#endif
    bool initialized;

} quac_logger_t;

/*=============================================================================
 * Global State
 *=============================================================================*/

static quac_logger_t g_logger = {0};

/*=============================================================================
 * Level Names and Colors
 *=============================================================================*/

static const char *g_level_names[] = {
    "TRACE", "DEBUG", "INFO ", "WARN ", "ERROR", "FATAL"};

static const char *g_level_colors[] = {
    "\x1b[90m", /* TRACE: gray */
    "\x1b[36m", /* DEBUG: cyan */
    "\x1b[32m", /* INFO:  green */
    "\x1b[33m", /* WARN:  yellow */
    "\x1b[31m", /* ERROR: red */
    "\x1b[35m"  /* FATAL: magenta */
};

static const char *g_color_reset = "\x1b[0m";

/*=============================================================================
 * Platform Helpers
 *=============================================================================*/

/**
 * @brief Get current time in microseconds
 */
static uint64_t get_time_us(void)
{
#ifdef _WIN32
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (uint64_t)(count.QuadPart * 1000000 / freq.QuadPart);
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
#endif
}

/**
 * @brief Get current time in milliseconds
 */
static uint64_t get_time_ms(void)
{
    return get_time_us() / 1000;
}

/**
 * @brief Format timestamp
 */
static void format_timestamp(char *buffer, size_t size)
{
    time_t now = time(NULL);
    struct tm *tm_info;

#ifdef _WIN32
    struct tm tm_buf;
    localtime_s(&tm_buf, &now);
    tm_info = &tm_buf;
#else
    struct tm tm_buf;
    tm_info = localtime_r(&now, &tm_buf);
#endif

    uint64_t us = get_time_us() % 1000000;

    strftime(buffer, size - 8, "%Y-%m-%d %H:%M:%S", tm_info);
    snprintf(buffer + strlen(buffer), 8, ".%06u", (unsigned)(us));
}

/**
 * @brief Check if output is a terminal
 */
static bool is_terminal(FILE *f)
{
    return isatty(fileno(f)) != 0;
}

/**
 * @brief Initialize lock
 */
static void init_lock(void)
{
#ifdef _WIN32
    InitializeCriticalSection(&g_logger.lock);
#else
    pthread_mutex_init(&g_logger.lock, NULL);
#endif
}

/**
 * @brief Destroy lock
 */
static void destroy_lock(void)
{
#ifdef _WIN32
    DeleteCriticalSection(&g_logger.lock);
#else
    pthread_mutex_destroy(&g_logger.lock);
#endif
}

/**
 * @brief Acquire lock
 */
static void acquire_lock(void)
{
#ifdef _WIN32
    EnterCriticalSection(&g_logger.lock);
#else
    pthread_mutex_lock(&g_logger.lock);
#endif
}

/**
 * @brief Release lock
 */
static void release_lock(void)
{
#ifdef _WIN32
    LeaveCriticalSection(&g_logger.lock);
#else
    pthread_mutex_unlock(&g_logger.lock);
#endif
}

/*=============================================================================
 * Internal Functions
 *=============================================================================*/

/**
 * @brief Check if message should be rate limited
 */
static bool check_rate_limit(void)
{
    if (!g_logger.rate_limit_enabled)
    {
        return false;
    }

    uint64_t now = get_time_ms();
    quac_log_rate_limit_t *rl = &g_logger.rate_limiter;

    /* Check if we're in a new window */
    if (now - rl->window_start >= QUAC_LOG_RATE_LIMIT_WINDOW)
    {
        if (rl->dropped_count > 0)
        {
            /* Log dropped message count */
            fprintf(stderr, "[LOG] Dropped %u messages due to rate limiting\n",
                    rl->dropped_count);
        }
        rl->window_start = now;
        rl->message_count = 0;
        rl->dropped_count = 0;
    }

    /* Check limit */
    if (rl->message_count >= QUAC_LOG_RATE_LIMIT_MAX)
    {
        rl->dropped_count++;
        g_logger.messages_dropped++;
        return true;
    }

    rl->message_count++;
    return false;
}

/**
 * @brief Check module filter
 */
static bool check_filter(const char *module, quac_log_level_t level)
{
    if (!module || g_logger.filter_count == 0)
    {
        return level >= g_logger.level;
    }

    for (uint32_t i = 0; i < g_logger.filter_count; i++)
    {
        quac_log_filter_t *f = &g_logger.filters[i];

        if (!f->enabled)
            continue;

        /* Check for wildcard or exact match */
        if (f->module[0] == '*' || strcmp(f->module, module) == 0)
        {
            return level >= f->level;
        }

        /* Check for prefix match (e.g., "crypto.*") */
        size_t len = strlen(f->module);
        if (len > 2 && f->module[len - 1] == '*' && f->module[len - 2] == '.')
        {
            if (strncmp(f->module, module, len - 1) == 0)
            {
                return level >= f->level;
            }
        }
    }

    return level >= g_logger.level;
}

/**
 * @brief Rotate log file
 */
static void rotate_log_file(void)
{
    if (!g_logger.file_handle || g_logger.file_path[0] == '\0')
    {
        return;
    }

    fclose(g_logger.file_handle);
    g_logger.file_handle = NULL;

    /* Rotate existing files */
    char old_path[QUAC_LOG_MAX_PATH];
    char new_path[QUAC_LOG_MAX_PATH];

    for (int i = (int)g_logger.rotate_count - 1; i >= 0; i--)
    {
        if (i == 0)
        {
            snprintf(old_path, sizeof(old_path), "%s", g_logger.file_path);
        }
        else
        {
            snprintf(old_path, sizeof(old_path), "%s.%d", g_logger.file_path, i);
        }

        snprintf(new_path, sizeof(new_path), "%s.%d", g_logger.file_path, i + 1);

        /* Delete oldest if at max */
        if (i == (int)g_logger.rotate_count - 1)
        {
            remove(new_path);
        }

        rename(old_path, new_path);
    }

    /* Reopen file */
#ifdef _WIN32
    fopen_s(&g_logger.file_handle, g_logger.file_path, "a");
#else
    g_logger.file_handle = fopen(g_logger.file_path, "a");
#endif

    g_logger.file_size = 0;
}

/**
 * @brief Write to file target
 */
static void write_to_file(const char *message, size_t len)
{
    if (!g_logger.file_handle)
    {
        return;
    }

    fwrite(message, 1, len, g_logger.file_handle);
    fflush(g_logger.file_handle);

    g_logger.file_size += len;
    g_logger.bytes_written += len;

    /* Check for rotation */
    if (g_logger.rotate_size > 0 && g_logger.file_size >= g_logger.rotate_size)
    {
        rotate_log_file();
    }
}

/**
 * @brief Write to console target
 */
static void write_to_console(quac_log_level_t level, const char *message)
{
    FILE *out = (level >= QUAC_LOG_WARN) ? stderr : stdout;

    if (g_logger.colors_enabled && is_terminal(out))
    {
        fprintf(out, "%s%s%s\n", g_level_colors[level], message, g_color_reset);
    }
    else
    {
        fprintf(out, "%s\n", message);
    }

    fflush(out);
}

/**
 * @brief Write to syslog target
 */
#ifndef _WIN32
static void write_to_syslog(quac_log_level_t level, const char *message)
{
    int priority;

    switch (level)
    {
    case QUAC_LOG_TRACE:
    case QUAC_LOG_DEBUG:
        priority = LOG_DEBUG;
        break;
    case QUAC_LOG_INFO:
        priority = LOG_INFO;
        break;
    case QUAC_LOG_WARN:
        priority = LOG_WARNING;
        break;
    case QUAC_LOG_ERROR:
        priority = LOG_ERR;
        break;
    case QUAC_LOG_FATAL:
        priority = LOG_CRIT;
        break;
    default:
        priority = LOG_INFO;
    }

    syslog(priority, "%s", message);
}
#endif

/*=============================================================================
 * Public API - Initialization
 *=============================================================================*/

/**
 * @brief Initialize logging subsystem
 */
quac_result_t quac_log_init(void)
{
    if (g_logger.initialized)
    {
        return QUAC_SUCCESS;
    }

    memset(&g_logger, 0, sizeof(g_logger));

    init_lock();

    g_logger.level = QUAC_LOG_INFO;
    g_logger.targets = QUAC_LOG_TARGET_CONSOLE;
    g_logger.colors_enabled = true;
    g_logger.timestamps_enabled = true;
    g_logger.module_enabled = true;
    g_logger.rate_limit_enabled = false;
    g_logger.rotate_size = QUAC_LOG_DEFAULT_ROTATE_SIZE;
    g_logger.rotate_count = QUAC_LOG_DEFAULT_ROTATE_COUNT;

    g_logger.initialized = true;

#ifndef _WIN32
    openlog("quac", LOG_PID | LOG_NDELAY, LOG_USER);
#endif

    return QUAC_SUCCESS;
}

/**
 * @brief Shutdown logging subsystem
 */
void quac_log_shutdown(void)
{
    if (!g_logger.initialized)
    {
        return;
    }

    acquire_lock();

    if (g_logger.file_handle)
    {
        fclose(g_logger.file_handle);
        g_logger.file_handle = NULL;
    }

#ifndef _WIN32
    closelog();
#endif

    g_logger.initialized = false;

    release_lock();
    destroy_lock();
}

/*=============================================================================
 * Public API - Configuration
 *=============================================================================*/

/**
 * @brief Set global log level
 */
quac_result_t quac_log_set_level(quac_log_level_t level)
{
    if (level > QUAC_LOG_NONE)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    acquire_lock();
    g_logger.level = level;
    release_lock();

    return QUAC_SUCCESS;
}

/**
 * @brief Get current log level
 */
quac_log_level_t quac_log_get_level(void)
{
    return g_logger.level;
}

/**
 * @brief Set log targets
 */
quac_result_t quac_log_set_targets(uint32_t targets)
{
    acquire_lock();
    g_logger.targets = targets;
    release_lock();

    return QUAC_SUCCESS;
}

/**
 * @brief Enable/disable colored output
 */
quac_result_t quac_log_set_colors(bool enabled)
{
    g_logger.colors_enabled = enabled;
    return QUAC_SUCCESS;
}

/**
 * @brief Enable/disable timestamps
 */
quac_result_t quac_log_set_timestamps(bool enabled)
{
    g_logger.timestamps_enabled = enabled;
    return QUAC_SUCCESS;
}

/**
 * @brief Enable/disable rate limiting
 */
quac_result_t quac_log_set_rate_limit(bool enabled)
{
    g_logger.rate_limit_enabled = enabled;
    return QUAC_SUCCESS;
}

/**
 * @brief Set log file path
 */
quac_result_t quac_log_set_file(const char *path)
{
    if (!path)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    acquire_lock();

    /* Close existing file */
    if (g_logger.file_handle)
    {
        fclose(g_logger.file_handle);
        g_logger.file_handle = NULL;
    }

    strncpy(g_logger.file_path, path, QUAC_LOG_MAX_PATH - 1);
    g_logger.file_path[QUAC_LOG_MAX_PATH - 1] = '\0';

    /* Open new file */
#ifdef _WIN32
    fopen_s(&g_logger.file_handle, g_logger.file_path, "a");
#else
    g_logger.file_handle = fopen(g_logger.file_path, "a");
#endif

    if (!g_logger.file_handle)
    {
        release_lock();
        return QUAC_ERROR_FILE_OPEN_FAILED;
    }

    /* Get current file size */
    fseek(g_logger.file_handle, 0, SEEK_END);
    g_logger.file_size = (size_t)ftell(g_logger.file_handle);

    g_logger.targets |= QUAC_LOG_TARGET_FILE;

    release_lock();

    return QUAC_SUCCESS;
}

/**
 * @brief Set log file rotation parameters
 */
quac_result_t quac_log_set_rotation(size_t max_size, uint32_t max_files)
{
    acquire_lock();
    g_logger.rotate_size = max_size;
    g_logger.rotate_count = max_files;
    release_lock();

    return QUAC_SUCCESS;
}

/**
 * @brief Set log callback
 */
quac_result_t quac_log_set_callback(quac_log_callback_t callback, void *user_data)
{
    acquire_lock();
    g_logger.callback = callback;
    g_logger.callback_data = user_data;

    if (callback)
    {
        g_logger.targets |= QUAC_LOG_TARGET_CALLBACK;
    }
    else
    {
        g_logger.targets &= ~QUAC_LOG_TARGET_CALLBACK;
    }

    release_lock();

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Public API - Filtering
 *=============================================================================*/

/**
 * @brief Add module filter
 */
quac_result_t quac_log_add_filter(const char *module, quac_log_level_t level)
{
    if (!module)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    acquire_lock();

    if (g_logger.filter_count >= QUAC_LOG_MAX_FILTERS)
    {
        release_lock();
        return QUAC_ERROR_LIMIT_EXCEEDED;
    }

    quac_log_filter_t *f = &g_logger.filters[g_logger.filter_count];
    strncpy(f->module, module, QUAC_LOG_MAX_MODULE - 1);
    f->module[QUAC_LOG_MAX_MODULE - 1] = '\0';
    f->level = level;
    f->enabled = true;

    g_logger.filter_count++;

    release_lock();

    return QUAC_SUCCESS;
}

/**
 * @brief Remove module filter
 */
quac_result_t quac_log_remove_filter(const char *module)
{
    if (!module)
    {
        return QUAC_ERROR_NULL_POINTER;
    }

    acquire_lock();

    for (uint32_t i = 0; i < g_logger.filter_count; i++)
    {
        if (strcmp(g_logger.filters[i].module, module) == 0)
        {
            /* Shift remaining filters */
            memmove(&g_logger.filters[i], &g_logger.filters[i + 1],
                    (g_logger.filter_count - i - 1) * sizeof(quac_log_filter_t));
            g_logger.filter_count--;
            release_lock();
            return QUAC_SUCCESS;
        }
    }

    release_lock();
    return QUAC_ERROR_NOT_FOUND;
}

/**
 * @brief Clear all filters
 */
quac_result_t quac_log_clear_filters(void)
{
    acquire_lock();
    g_logger.filter_count = 0;
    release_lock();

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Public API - Logging Functions
 *=============================================================================*/

/**
 * @brief Core logging function
 */
void quac_log_write(quac_log_level_t level, const char *module,
                    const char *file, int line, const char *fmt, ...)
{
    if (!g_logger.initialized || level < g_logger.level)
    {
        return;
    }

    if (!check_filter(module, level))
    {
        return;
    }

    acquire_lock();

    /* Check rate limit */
    if (check_rate_limit())
    {
        release_lock();
        return;
    }

    /* Format message */
    char message[QUAC_LOG_MAX_MESSAGE];
    char *ptr = message;
    size_t remaining = sizeof(message);
    int written;

    /* Timestamp */
    if (g_logger.timestamps_enabled)
    {
        char timestamp[32];
        format_timestamp(timestamp, sizeof(timestamp));
        written = snprintf(ptr, remaining, "[%s] ", timestamp);
        ptr += written;
        remaining -= written;
    }

    /* Level */
    written = snprintf(ptr, remaining, "[%s] ", g_level_names[level]);
    ptr += written;
    remaining -= written;

    /* Module */
    if (g_logger.module_enabled && module)
    {
        written = snprintf(ptr, remaining, "[%s] ", module);
        ptr += written;
        remaining -= written;
    }

    /* User message */
    va_list args;
    va_start(args, fmt);
    written = vsnprintf(ptr, remaining, fmt, args);
    va_end(args);

    if (written > 0)
    {
        ptr += (written < (int)remaining) ? written : (remaining - 1);
    }

    /* Optional file/line */
    if (file && level >= QUAC_LOG_WARN)
    {
        /* Extract filename from path */
        const char *filename = strrchr(file, '/');
        if (!filename)
            filename = strrchr(file, '\\');
        filename = filename ? filename + 1 : file;

        remaining = sizeof(message) - (ptr - message);
        snprintf(ptr, remaining, " (%s:%d)", filename, line);
    }

    size_t len = strlen(message);

    /* Write to targets */
    if (g_logger.targets & QUAC_LOG_TARGET_CONSOLE)
    {
        write_to_console(level, message);
    }

    if (g_logger.targets & QUAC_LOG_TARGET_FILE)
    {
        /* Add newline for file */
        message[len] = '\n';
        write_to_file(message, len + 1);
        message[len] = '\0';
    }

    if (g_logger.targets & QUAC_LOG_TARGET_CALLBACK && g_logger.callback)
    {
        g_logger.callback(level, module, message, g_logger.callback_data);
    }

#ifndef _WIN32
    if (g_logger.targets & QUAC_LOG_TARGET_SYSLOG)
    {
        write_to_syslog(level, message);
    }
#endif

    g_logger.messages_logged++;

    release_lock();

    /* Fatal messages terminate */
    if (level == QUAC_LOG_FATAL)
    {
        abort();
    }
}

/**
 * @brief Log binary data as hex dump
 */
void quac_log_hexdump(quac_log_level_t level, const char *module,
                      const char *label, const void *data, size_t size)
{
    if (!g_logger.initialized || level < g_logger.level || !data)
    {
        return;
    }

    if (!check_filter(module, level))
    {
        return;
    }

    const uint8_t *bytes = (const uint8_t *)data;
    char line[128];
    char hex[64];
    char ascii[32];

    quac_log_write(level, module, NULL, 0, "%s (%zu bytes):", label ? label : "Data", size);

    for (size_t i = 0; i < size; i += 16)
    {
        char *hptr = hex;
        char *aptr = ascii;

        for (size_t j = 0; j < 16; j++)
        {
            if (i + j < size)
            {
                hptr += sprintf(hptr, "%02X ", bytes[i + j]);
                *aptr++ = (bytes[i + j] >= 32 && bytes[i + j] < 127) ? bytes[i + j] : '.';
            }
            else
            {
                hptr += sprintf(hptr, "   ");
                *aptr++ = ' ';
            }

            if (j == 7)
            {
                *hptr++ = ' ';
            }
        }

        *aptr = '\0';

        snprintf(line, sizeof(line), "  %04zX: %s |%s|", i, hex, ascii);
        quac_log_write(level, module, NULL, 0, "%s", line);
    }
}

/*=============================================================================
 * Public API - Statistics
 *=============================================================================*/

/**
 * @brief Get logging statistics
 */
quac_result_t quac_log_get_stats(uint64_t *messages_logged,
                                 uint64_t *messages_dropped,
                                 uint64_t *bytes_written)
{
    acquire_lock();

    if (messages_logged)
        *messages_logged = g_logger.messages_logged;
    if (messages_dropped)
        *messages_dropped = g_logger.messages_dropped;
    if (bytes_written)
        *bytes_written = g_logger.bytes_written;

    release_lock();

    return QUAC_SUCCESS;
}

/**
 * @brief Reset statistics
 */
quac_result_t quac_log_reset_stats(void)
{
    acquire_lock();

    g_logger.messages_logged = 0;
    g_logger.messages_dropped = 0;
    g_logger.bytes_written = 0;

    release_lock();

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Convenience Macros (typically in header)
 *=============================================================================*/

/*
 * These would typically be in quac100_log.h:
 *
 * #define QUAC_LOG_TRACE(module, ...) \
 *     quac_log_write(QUAC_LOG_TRACE, module, __FILE__, __LINE__, __VA_ARGS__)
 * #define QUAC_LOG_DEBUG(module, ...) \
 *     quac_log_write(QUAC_LOG_DEBUG, module, __FILE__, __LINE__, __VA_ARGS__)
 * #define QUAC_LOG_INFO(module, ...) \
 *     quac_log_write(QUAC_LOG_INFO, module, __FILE__, __LINE__, __VA_ARGS__)
 * #define QUAC_LOG_WARN(module, ...) \
 *     quac_log_write(QUAC_LOG_WARN, module, __FILE__, __LINE__, __VA_ARGS__)
 * #define QUAC_LOG_ERROR(module, ...) \
 *     quac_log_write(QUAC_LOG_ERROR, module, __FILE__, __LINE__, __VA_ARGS__)
 * #define QUAC_LOG_FATAL(module, ...) \
 *     quac_log_write(QUAC_LOG_FATAL, module, __FILE__, __LINE__, __VA_ARGS__)
 */