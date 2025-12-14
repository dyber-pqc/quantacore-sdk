/**
 * @file utils.h
 * @brief QUAC 100 SDK - Utility Functions
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_UTILS_H
#define QUAC100_UTILS_H

#include "types.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * @defgroup Utils Utility Functions
     * @brief Helper and utility functions
     * @{
     */

    /*============================================================================
     * Error Handling
     *============================================================================*/

    /**
     * @brief Get error message for status code
     *
     * @param[in] status Status code
     * @return Human-readable error message
     */
    QUAC_API const char *quac_error_string(quac_status_t status);

    /**
     * @brief Get detailed error information
     *
     * @param[in] device Device handle (or NULL for library-level errors)
     * @param[out] buffer Buffer for error details
     * @param[in] buffer_size Buffer size
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_get_error_details(
        quac_device_t device,
        char *buffer,
        size_t buffer_size);

    /**
     * @brief Clear last error
     *
     * @param[in] device Device handle (or NULL for library-level)
     */
    QUAC_API void quac_clear_error(quac_device_t device);

    /*============================================================================
     * Memory Functions
     *============================================================================*/

    /**
     * @brief Securely zero memory
     *
     * Guaranteed not to be optimized away by the compiler.
     *
     * @param[out] buffer Buffer to zero
     * @param[in] length Buffer length
     */
    QUAC_API void quac_secure_zero(void *buffer, size_t length);

    /**
     * @brief Constant-time memory comparison
     *
     * @param[in] a First buffer
     * @param[in] b Second buffer
     * @param[in] length Buffer length
     * @return 0 if equal, non-zero if different
     */
    QUAC_API int quac_secure_compare(
        const void *a,
        const void *b,
        size_t length);

    /**
     * @brief Allocate secure memory
     *
     * Allocates memory that will be automatically zeroized when freed.
     *
     * @param[in] size Size to allocate
     * @return Pointer to allocated memory, or NULL on failure
     */
    QUAC_API void *quac_secure_alloc(size_t size);

    /**
     * @brief Free secure memory
     *
     * Zeroizes and frees memory allocated with quac_secure_alloc.
     *
     * @param[in] ptr Pointer to free
     * @param[in] size Size of allocation
     */
    QUAC_API void quac_secure_free(void *ptr, size_t size);

    /**
     * @brief Reallocate secure memory
     *
     * @param[in] ptr Current pointer
     * @param[in] old_size Current size
     * @param[in] new_size New size
     * @return Pointer to reallocated memory, or NULL on failure
     */
    QUAC_API void *quac_secure_realloc(void *ptr, size_t old_size, size_t new_size);

    /*============================================================================
     * Encoding Functions
     *============================================================================*/

    /**
     * @brief Encode bytes to hexadecimal string
     *
     * @param[in] data Data to encode
     * @param[in] data_len Data length
     * @param[out] hex_str Output buffer (must be 2*data_len + 1)
     * @param[in] buffer_size Output buffer size
     * @param[in] uppercase Use uppercase letters
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_hex_encode(
        const uint8_t *data,
        size_t data_len,
        char *hex_str,
        size_t buffer_size,
        bool uppercase);

    /**
     * @brief Decode hexadecimal string to bytes
     *
     * @param[in] hex_str Hex string to decode
     * @param[out] data Output buffer
     * @param[in,out] data_len Output buffer size / actual size
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_hex_decode(
        const char *hex_str,
        uint8_t *data,
        size_t *data_len);

    /**
     * @brief Encode bytes to Base64 string
     *
     * @param[in] data Data to encode
     * @param[in] data_len Data length
     * @param[out] b64_str Output buffer
     * @param[in] buffer_size Output buffer size
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_base64_encode(
        const uint8_t *data,
        size_t data_len,
        char *b64_str,
        size_t buffer_size);

    /**
     * @brief Decode Base64 string to bytes
     *
     * @param[in] b64_str Base64 string to decode
     * @param[out] data Output buffer
     * @param[in,out] data_len Output buffer size / actual size
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_base64_decode(
        const char *b64_str,
        uint8_t *data,
        size_t *data_len);

    /*============================================================================
     * Logging Functions
     *============================================================================*/

    /**
     * @brief Log level enumeration
     */
    typedef enum quac_log_level
    {
        QUAC_LOG_NONE = 0,
        QUAC_LOG_ERROR = 1,
        QUAC_LOG_WARNING = 2,
        QUAC_LOG_INFO = 3,
        QUAC_LOG_DEBUG = 4,
        QUAC_LOG_TRACE = 5
    } quac_log_level_t;

    /**
     * @brief Set log level
     *
     * @param[in] level Log level
     */
    QUAC_API void quac_set_log_level(quac_log_level_t level);

    /**
     * @brief Get current log level
     *
     * @return Current log level
     */
    QUAC_API quac_log_level_t quac_get_log_level(void);

    /**
     * @brief Set custom log callback
     *
     * @param[in] callback Log callback function
     * @param[in] user_data User data passed to callback
     */
    QUAC_API void quac_set_log_callback(
        quac_log_callback_t callback,
        void *user_data);

    /**
     * @brief Log a message
     *
     * @param[in] level Log level
     * @param[in] format Printf-style format string
     * @param[in] ... Format arguments
     */
    QUAC_API void quac_log(quac_log_level_t level, const char *format, ...);

    /*============================================================================
     * Async Operations
     *============================================================================*/

    /**
     * @brief Wait for async operation to complete
     *
     * @param[in] handle Async operation handle
     * @param[in] timeout_ms Timeout in milliseconds (0 for infinite)
     * @return QUAC_SUCCESS on success, QUAC_ERROR_TIMEOUT on timeout
     */
    QUAC_API quac_status_t quac_async_wait(
        quac_async_t handle,
        uint32_t timeout_ms);

    /**
     * @brief Cancel an async operation
     *
     * @param[in] handle Async operation handle
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_async_cancel(quac_async_t handle);

    /**
     * @brief Check if async operation is complete
     *
     * @param[in] handle Async operation handle
     * @return Non-zero if complete, zero if still pending
     */
    QUAC_API int quac_async_is_complete(quac_async_t handle);

    /**
     * @brief Get result of async operation
     *
     * @param[in] handle Async operation handle
     * @return Status of the completed operation
     */
    QUAC_API quac_status_t quac_async_get_result(quac_async_t handle);

    /**
     * @brief Free async operation handle
     *
     * @param[in] handle Async operation handle
     */
    QUAC_API void quac_async_free(quac_async_t handle);

    /*============================================================================
     * Algorithm Information
     *============================================================================*/

    /**
     * @brief Get algorithm name string
     *
     * @param[in] algorithm Algorithm ID (KEM or signature)
     * @return Algorithm name string
     */
    QUAC_API const char *quac_algorithm_name(int algorithm);

    /**
     * @brief Check if algorithm is a KEM algorithm
     *
     * @param[in] algorithm Algorithm ID
     * @return Non-zero if KEM, zero otherwise
     */
    QUAC_API int quac_is_kem_algorithm(int algorithm);

    /**
     * @brief Check if algorithm is a signature algorithm
     *
     * @param[in] algorithm Algorithm ID
     * @return Non-zero if signature, zero otherwise
     */
    QUAC_API int quac_is_sign_algorithm(int algorithm);

    /**
     * @brief Get security level for algorithm
     *
     * @param[in] algorithm Algorithm ID
     * @return NIST security level (1-5) or 0 if unknown
     */
    QUAC_API int quac_algorithm_security_level(int algorithm);

    /*============================================================================
     * Time Functions
     *============================================================================*/

    /**
     * @brief Get high-resolution timestamp
     *
     * @return Timestamp in nanoseconds
     */
    QUAC_API uint64_t quac_timestamp_ns(void);

    /**
     * @brief Get timestamp in microseconds
     *
     * @return Timestamp in microseconds
     */
    QUAC_API uint64_t quac_timestamp_us(void);

    /**
     * @brief Get timestamp in milliseconds
     *
     * @return Timestamp in milliseconds
     */
    QUAC_API uint64_t quac_timestamp_ms(void);

    /*============================================================================
     * Thread Safety
     *============================================================================*/

    /**
     * @brief Acquire device lock
     *
     * For operations requiring exclusive device access.
     *
     * @param[in] device Device handle
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_device_lock(quac_device_t device);

    /**
     * @brief Release device lock
     *
     * @param[in] device Device handle
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_device_unlock(quac_device_t device);

    /**
     * @brief Try to acquire device lock
     *
     * Non-blocking version of quac_device_lock.
     *
     * @param[in] device Device handle
     * @return QUAC_SUCCESS if acquired, QUAC_ERROR_DEVICE_BUSY if not
     */
    QUAC_API quac_status_t quac_device_trylock(quac_device_t device);

    /** @} */ /* end of Utils group */

#ifdef __cplusplus
}
#endif

#endif /* QUAC100_UTILS_H */