/**
 * @file quac100_error.h
 * @brief QuantaCore SDK - Error Handling and Diagnostics
 *
 * Extended error handling facilities including error categories, detailed
 * error information, and diagnostic utilities.
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 * @doc QUAC100-SDK-DEV-001
 */

#ifndef QUAC100_ERROR_H
#define QUAC100_ERROR_H

#include "quac100_types.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /*=============================================================================
     * Error Category Extraction
     *=============================================================================*/

    /**
     * @brief Error category identifiers
     */
    typedef enum quac_error_category_e
    {
        QUAC_ERROR_CAT_SUCCESS = 0x00,   /**< Success (no error) */
        QUAC_ERROR_CAT_GENERAL = 0x00,   /**< General errors */
        QUAC_ERROR_CAT_DEVICE = 0x01,    /**< Device errors */
        QUAC_ERROR_CAT_CRYPTO = 0x02,    /**< Cryptographic errors */
        QUAC_ERROR_CAT_KEY = 0x03,       /**< Key management errors */
        QUAC_ERROR_CAT_QRNG = 0x04,      /**< QRNG errors */
        QUAC_ERROR_CAT_ASYNC = 0x05,     /**< Async/batch errors */
        QUAC_ERROR_CAT_SECURITY = 0x06,  /**< Security errors */
        QUAC_ERROR_CAT_SIMULATOR = 0x07, /**< Simulator errors */
    } quac_error_category_t;

/**
 * @brief Extract error category from result code
 *
 * @param result    Result code
 * @return Error category
 */
#define QUAC_ERROR_CATEGORY(result) \
    ((quac_error_category_t)(((result) >> 8) & 0xFF))

/**
 * @brief Extract error code within category
 *
 * @param result    Result code
 * @return Error code (0-255)
 */
#define QUAC_ERROR_CODE(result) \
    ((uint8_t)((result) & 0xFF))

/**
 * @brief Build result code from category and code
 *
 * @param category  Error category
 * @param code      Error code within category
 * @return Result code
 */
#define QUAC_MAKE_ERROR(category, code) \
    ((quac_result_t)(((category) << 8) | (code)))

    /*=============================================================================
     * Error Severity
     *=============================================================================*/

    /**
     * @brief Error severity levels
     */
    typedef enum quac_error_severity_e
    {
        QUAC_SEVERITY_SUCCESS = 0,  /**< No error */
        QUAC_SEVERITY_WARNING = 1,  /**< Warning - operation succeeded with issues */
        QUAC_SEVERITY_ERROR = 2,    /**< Error - operation failed, recoverable */
        QUAC_SEVERITY_CRITICAL = 3, /**< Critical - device may need reset */
        QUAC_SEVERITY_FATAL = 4,    /**< Fatal - device unusable */
    } quac_error_severity_t;

    /**
     * @brief Get severity level for a result code
     *
     * @param result    Result code
     * @return Severity level
     */
    QUAC100_API quac_error_severity_t QUAC100_CALL
    quac_error_severity(quac_result_t result);

    /**
     * @brief Check if error is recoverable
     *
     * @param result    Result code
     * @return true if recoverable (retry may succeed)
     */
    QUAC100_API bool QUAC100_CALL
    quac_error_is_recoverable(quac_result_t result);

    /*=============================================================================
     * Extended Error Information
     *=============================================================================*/

    /**
     * @brief Extended error information structure
     */
    typedef struct quac_error_info_s
    {
        uint32_t struct_size;           /**< Size of this structure */
        quac_result_t result;           /**< Result code */
        quac_error_category_t category; /**< Error category */
        quac_error_severity_t severity; /**< Error severity */
        uint32_t os_error;              /**< OS-specific error code (errno/GetLastError) */
        uint32_t driver_error;          /**< Driver-specific error code */
        uint32_t firmware_error;        /**< Firmware error code */
        uint32_t line;                  /**< Source line (debug builds) */
        const char *file;               /**< Source file (debug builds) */
        const char *function;           /**< Function name (debug builds) */
        char message[256];              /**< Human-readable message */
        char detail[512];               /**< Extended detail/context */
        uint64_t timestamp;             /**< Error timestamp (nanoseconds) */
        uint32_t device_index;          /**< Device index (if applicable) */
        quac_algorithm_t algorithm;     /**< Algorithm (if applicable) */
    } quac_error_info_t;

    /**
     * @brief Get extended error information for last error
     *
     * @param[out] info     Pointer to receive error information
     *
     * @return QUAC_SUCCESS if info available
     * @return QUAC_ERROR_NULL_POINTER if info is NULL
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_error_get_info(quac_error_info_t *info);

    /**
     * @brief Clear last error information
     */
    QUAC100_API void QUAC100_CALL
    quac_error_clear(void);

    /*=============================================================================
     * Error Strings
     *=============================================================================*/

    /**
     * @brief Get short error name
     *
     * @param result    Result code
     * @return Error name (e.g., "QUAC_ERROR_DEVICE_NOT_FOUND")
     */
    QUAC100_API const char *QUAC100_CALL
    quac_error_name(quac_result_t result);

    /**
     * @brief Get error category name
     *
     * @param category  Error category
     * @return Category name (e.g., "Device")
     */
    QUAC100_API const char *QUAC100_CALL
    quac_error_category_name(quac_error_category_t category);

    /**
     * @brief Get severity name
     *
     * @param severity  Severity level
     * @return Severity name (e.g., "Critical")
     */
    QUAC100_API const char *QUAC100_CALL
    quac_error_severity_name(quac_error_severity_t severity);

    /**
     * @brief Format error for logging
     *
     * Produces a formatted string suitable for logging, including result code,
     * category, severity, and message.
     *
     * @param[in]  result   Result code
     * @param[out] buffer   Buffer for formatted string
     * @param[in]  size     Buffer size
     *
     * @return Number of characters written (excluding null terminator)
     */
    QUAC100_API size_t QUAC100_CALL
    quac_error_format(quac_result_t result, char *buffer, size_t size);

    /**
     * @brief Format extended error info for logging
     *
     * @param[in]  info     Error information
     * @param[out] buffer   Buffer for formatted string
     * @param[in]  size     Buffer size
     *
     * @return Number of characters written
     */
    QUAC100_API size_t QUAC100_CALL
    quac_error_format_info(const quac_error_info_t *info, char *buffer, size_t size);

    /*=============================================================================
     * Error Callback Registration
     *=============================================================================*/

    /**
     * @brief Error callback function type
     *
     * @param info      Error information
     * @param user_data User-provided context
     */
    typedef void(QUAC100_CALL *quac_error_callback_t)(
        const quac_error_info_t *info,
        void *user_data);

    /**
     * @brief Register global error callback
     *
     * The callback is invoked for all errors. Useful for centralized logging.
     *
     * @param callback  Error callback (NULL to unregister)
     * @param user_data User context passed to callback
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_error_set_callback(quac_error_callback_t callback, void *user_data);

    /**
     * @brief Error filter for callback
     */
    typedef enum quac_error_filter_e
    {
        QUAC_ERROR_FILTER_NONE = 0x00,     /**< No filtering (all errors) */
        QUAC_ERROR_FILTER_WARNINGS = 0x01, /**< Include warnings */
        QUAC_ERROR_FILTER_ERRORS = 0x02,   /**< Include errors */
        QUAC_ERROR_FILTER_CRITICAL = 0x04, /**< Include critical */
        QUAC_ERROR_FILTER_FATAL = 0x08,    /**< Include fatal */
        QUAC_ERROR_FILTER_ALL = 0x0F,      /**< All severities */
    } quac_error_filter_t;

    /**
     * @brief Set error callback filter
     *
     * @param filter    Bitmask of severities to report
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_error_set_filter(quac_error_filter_t filter);

    /*=============================================================================
     * Error Statistics
     *=============================================================================*/

    /**
     * @brief Error statistics structure
     */
    typedef struct quac_error_stats_s
    {
        uint32_t struct_size;         /**< Size of this structure */
        uint64_t total_errors;        /**< Total errors since init */
        uint64_t warnings;            /**< Warning count */
        uint64_t errors;              /**< Error count */
        uint64_t critical;            /**< Critical error count */
        uint64_t fatal;               /**< Fatal error count */
        uint64_t by_category[16];     /**< Errors by category */
        quac_result_t last_error;     /**< Most recent error */
        quac_result_t most_frequent;  /**< Most frequent error */
        uint64_t most_frequent_count; /**< Count of most frequent */
    } quac_error_stats_t;

    /**
     * @brief Get error statistics
     *
     * @param[out] stats    Pointer to receive statistics
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_error_get_stats(quac_error_stats_t *stats);

    /**
     * @brief Reset error statistics
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_error_reset_stats(void);

    /*=============================================================================
     * Debug Helpers
     *=============================================================================*/

    /**
     * @brief Assert and record error (debug builds)
     *
     * @param condition Condition to check
     * @param result    Result to return if condition false
     * @param file      Source file
     * @param line      Source line
     * @param func      Function name
     *
     * @return QUAC_SUCCESS if condition true, result otherwise
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_error_assert_impl(bool condition, quac_result_t result,
                           const char *file, int line, const char *func);

#ifdef QUAC_DEBUG
#define QUAC_ASSERT(cond, result) \
    quac_error_assert_impl((cond), (result), __FILE__, __LINE__, __func__)

#define QUAC_RETURN_IF_FAILED(expr)                                          \
    do                                                                       \
    {                                                                        \
        quac_result_t _r = (expr);                                           \
        if (QUAC_FAILED(_r))                                                 \
        {                                                                    \
            quac_error_assert_impl(false, _r, __FILE__, __LINE__, __func__); \
            return _r;                                                       \
        }                                                                    \
    } while (0)
#else
#define QUAC_ASSERT(cond, result) \
    ((cond) ? QUAC_SUCCESS : (result))

#define QUAC_RETURN_IF_FAILED(expr) \
    do                              \
    {                               \
        quac_result_t _r = (expr);  \
        if (QUAC_FAILED(_r))        \
            return _r;              \
    } while (0)
#endif

/**
 * @brief Check parameter and return error if NULL
 */
#define QUAC_CHECK_NULL(ptr)                \
    do                                      \
    {                                       \
        if ((ptr) == NULL)                  \
        {                                   \
            return QUAC_ERROR_NULL_POINTER; \
        }                                   \
    } while (0)

/**
 * @brief Check device handle and return error if invalid
 */
#define QUAC_CHECK_DEVICE(dev)                   \
    do                                           \
    {                                            \
        if ((dev) == QUAC_INVALID_DEVICE)        \
        {                                        \
            return QUAC_ERROR_INVALID_PARAMETER; \
        }                                        \
    } while (0)

/**
 * @brief Check buffer size and return error if too small
 */
#define QUAC_CHECK_SIZE(actual, required)       \
    do                                          \
    {                                           \
        if ((actual) < (required))              \
        {                                       \
            return QUAC_ERROR_BUFFER_TOO_SMALL; \
        }                                       \
    } while (0)

    /*=============================================================================
     * Error Result Lookup Tables
     *=============================================================================*/

    /**
     * @brief Error information entry for lookup
     */
    typedef struct quac_error_entry_s
    {
        quac_result_t result;           /**< Result code */
        const char *name;               /**< Error name */
        const char *message;            /**< Error message */
        quac_error_severity_t severity; /**< Error severity */
        bool recoverable;               /**< Is recoverable */
    } quac_error_entry_t;

    /**
     * @brief Get error table entry
     *
     * @param result    Result code
     * @return Pointer to entry, or NULL if not found
     */
    QUAC100_API const quac_error_entry_t *QUAC100_CALL
    quac_error_lookup(quac_result_t result);

    /**
     * @brief Iterate all error entries
     *
     * @param index     Entry index (0-based)
     * @return Pointer to entry, or NULL if index out of range
     */
    QUAC100_API const quac_error_entry_t *QUAC100_CALL
    quac_error_enumerate(size_t index);

    /**
     * @brief Get total number of defined error codes
     *
     * @return Number of error codes
     */
    QUAC100_API size_t QUAC100_CALL
    quac_error_count(void);

#ifdef __cplusplus
}
#endif

#endif /* QUAC100_ERROR_H */
