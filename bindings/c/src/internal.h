/**
 * @file internal.h
 * @brief QUAC 100 SDK - Internal Definitions
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 * @internal
 */

#ifndef QUAC100_INTERNAL_H
#define QUAC100_INTERNAL_H

#include "quac100/quac100.h"

#ifdef QUAC_PLATFORM_WINDOWS
#include <windows.h>
#else
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#endif

#ifdef __cplusplus
extern "C"
{
#endif

    /*============================================================================
     * Internal Macros
     *============================================================================*/

#define QUAC_LOG_ERROR(...) quac_internal_log(QUAC_LOG_ERROR, __VA_ARGS__)
#define QUAC_LOG_WARNING(...) quac_internal_log(QUAC_LOG_WARNING, __VA_ARGS__)
#define QUAC_LOG_INFO(...) quac_internal_log(QUAC_LOG_INFO, __VA_ARGS__)
#define QUAC_LOG_DEBUG(...) quac_internal_log(QUAC_LOG_DEBUG, __VA_ARGS__)
#define QUAC_LOG_TRACE(...) quac_internal_log(QUAC_LOG_TRACE, __VA_ARGS__)

#define QUAC_CHECK_INIT()                      \
    do                                         \
    {                                          \
        if (!quac_is_initialized())            \
        {                                      \
            return QUAC_ERROR_NOT_INITIALIZED; \
        }                                      \
    } while (0)

#define QUAC_CHECK_DEVICE(dev)                \
    do                                        \
    {                                         \
        if (!quac_device_is_valid(dev))       \
        {                                     \
            return QUAC_ERROR_INVALID_HANDLE; \
        }                                     \
    } while (0)

#define QUAC_CHECK_PARAM(cond)               \
    do                                       \
    {                                        \
        if (!(cond))                         \
        {                                    \
            return QUAC_ERROR_INVALID_PARAM; \
        }                                    \
    } while (0)

    /*============================================================================
     * Internal Structures
     *============================================================================*/

    /**
     * @brief Internal device structure
     */
    typedef struct quac_device_handle
    {
        int device_index;
        uint32_t flags;
        bool is_open;

        quac_device_info_t info;
        quac_device_status_t status;

        /* Platform-specific handle */
#ifdef QUAC_PLATFORM_WINDOWS
        HANDLE native_handle;
        CRITICAL_SECTION lock;
#else
    int native_handle;
    pthread_mutex_t lock;
#endif

        /* Performance tracking */
        uint64_t total_ops;
        uint64_t total_errors;
        uint64_t last_op_time_ns;

        /* Error state */
        quac_status_t last_error;
        char error_details[256];
    } quac_device_handle_impl;

    /**
     * @brief Internal hash context structure
     */
    typedef struct quac_hash_context
    {
        quac_device_t device;
        quac_hash_algorithm_t algorithm;
        bool finalized;

        /* State buffer for incremental hashing */
        uint8_t state[256];
        size_t state_size;

        /* Pending data buffer */
        uint8_t buffer[256];
        size_t buffer_len;
    } quac_hash_context_impl;

    /**
     * @brief Internal async operation structure
     */
    typedef struct quac_async_op
    {
        quac_device_t device;
        quac_status_t status;
        bool complete;
        bool cancelled;

        quac_async_callback_t callback;
        void *user_data;
        void *result;

#ifdef QUAC_PLATFORM_WINDOWS
        HANDLE thread;
        HANDLE event;
#else
    pthread_t thread;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
#endif
    } quac_async_op_impl;

    /*============================================================================
     * Hardware Abstraction Layer (HAL) Functions
     *============================================================================*/

    /**
     * @brief Initialize HAL
     */
    quac_status_t quac_hal_init(uint32_t flags);

    /**
     * @brief Cleanup HAL
     */
    quac_status_t quac_hal_cleanup(void);

    /**
     * @brief Discover devices
     */
    quac_status_t quac_hal_discover_devices(void);

    /**
     * @brief Get device count
     */
    int quac_hal_device_count(void);

    /**
     * @brief Get device info
     */
    quac_status_t quac_hal_get_device_info(int index, quac_device_info_t *info);

    /**
     * @brief Open device
     */
    quac_status_t quac_hal_open_device(int index, uint32_t flags, quac_device_handle_impl **handle);

    /**
     * @brief Close device
     */
    quac_status_t quac_hal_close_device(quac_device_handle_impl *handle);

    /**
     * @brief Send command to device
     */
    quac_status_t quac_hal_send_command(
        quac_device_handle_impl *handle,
        uint32_t command,
        const void *input,
        size_t input_len,
        void *output,
        size_t *output_len);

    /**
     * @brief DMA transfer to device
     */
    quac_status_t quac_hal_dma_write(
        quac_device_handle_impl *handle,
        const void *data,
        size_t len,
        uint64_t device_addr);

    /**
     * @brief DMA transfer from device
     */
    quac_status_t quac_hal_dma_read(
        quac_device_handle_impl *handle,
        void *data,
        size_t len,
        uint64_t device_addr);

    /*============================================================================
     * Internal Helper Functions
     *============================================================================*/

    /**
     * @brief Log message
     */
    void quac_internal_log(quac_log_level_t level, const char *format, ...);

    /**
     * @brief Set error state
     */
    void quac_internal_set_error(quac_status_t status, const char *details);

    /**
     * @brief Check if device handle is valid
     */
    int quac_device_is_valid(quac_device_t device);

    /**
     * @brief Lock device
     */
    void quac_device_lock_internal(quac_device_handle_impl *handle);

    /**
     * @brief Unlock device
     */
    void quac_device_unlock_internal(quac_device_handle_impl *handle);

    /*============================================================================
     * Cryptographic Core Functions
     *============================================================================*/

    /**
     * @brief Execute KEM keygen on hardware
     */
    quac_status_t quac_core_kem_keygen(
        quac_device_handle_impl *handle,
        quac_kem_algorithm_t algorithm,
        uint8_t *public_key,
        size_t *public_key_len,
        uint8_t *secret_key,
        size_t *secret_key_len);

    /**
     * @brief Execute KEM encaps on hardware
     */
    quac_status_t quac_core_kem_encaps(
        quac_device_handle_impl *handle,
        quac_kem_algorithm_t algorithm,
        const uint8_t *public_key,
        size_t public_key_len,
        uint8_t *ciphertext,
        size_t *ciphertext_len,
        uint8_t *shared_secret,
        size_t *shared_secret_len);

    /**
     * @brief Execute KEM decaps on hardware
     */
    quac_status_t quac_core_kem_decaps(
        quac_device_handle_impl *handle,
        quac_kem_algorithm_t algorithm,
        const uint8_t *secret_key,
        size_t secret_key_len,
        const uint8_t *ciphertext,
        size_t ciphertext_len,
        uint8_t *shared_secret,
        size_t *shared_secret_len);

    /**
     * @brief Execute signature keygen on hardware
     */
    quac_status_t quac_core_sign_keygen(
        quac_device_handle_impl *handle,
        quac_sign_algorithm_t algorithm,
        uint8_t *public_key,
        size_t *public_key_len,
        uint8_t *secret_key,
        size_t *secret_key_len);

    /**
     * @brief Execute sign on hardware
     */
    quac_status_t quac_core_sign(
        quac_device_handle_impl *handle,
        quac_sign_algorithm_t algorithm,
        const uint8_t *secret_key,
        size_t secret_key_len,
        const uint8_t *message,
        size_t message_len,
        uint8_t *signature,
        size_t *signature_len);

    /**
     * @brief Execute verify on hardware
     */
    quac_status_t quac_core_verify(
        quac_device_handle_impl *handle,
        quac_sign_algorithm_t algorithm,
        const uint8_t *public_key,
        size_t public_key_len,
        const uint8_t *message,
        size_t message_len,
        const uint8_t *signature,
        size_t signature_len);

    /**
     * @brief Generate random bytes from hardware
     */
    quac_status_t quac_core_random_bytes(
        quac_device_handle_impl *handle,
        uint8_t *buffer,
        size_t length,
        quac_entropy_source_t source);

    /**
     * @brief Compute hash on hardware
     */
    quac_status_t quac_core_hash(
        quac_device_handle_impl *handle,
        quac_hash_algorithm_t algorithm,
        const uint8_t *data,
        size_t data_len,
        uint8_t *hash,
        size_t *hash_len);

#ifdef __cplusplus
}
#endif

#endif /* QUAC100_INTERNAL_H */