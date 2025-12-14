/**
 * @file random.h
 * @brief QUAC 100 SDK - Quantum Random Number Generation API
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_RANDOM_H
#define QUAC100_RANDOM_H

#include "types.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * @defgroup Random Random Number Generation
     * @brief Quantum random number generation operations
     * @{
     */

    /**
     * @brief Generate random bytes
     *
     * Uses the hardware quantum random number generator.
     *
     * @param[in] device Device handle
     * @param[out] buffer Buffer to fill with random bytes
     * @param[in] length Number of bytes to generate
     * @return QUAC_SUCCESS on success, error code on failure
     *
     * @code
     * uint8_t buffer[32];
     * quac_status_t status = quac_random_bytes(device, buffer, sizeof(buffer));
     * @endcode
     */
    QUAC_API quac_status_t quac_random_bytes(
        quac_device_t device,
        uint8_t *buffer,
        size_t length);

    /**
     * @brief Generate random bytes with specific entropy source
     *
     * @param[in] device Device handle
     * @param[out] buffer Buffer to fill with random bytes
     * @param[in] length Number of bytes to generate
     * @param[in] source Entropy source to use
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_random_bytes_ex(
        quac_device_t device,
        uint8_t *buffer,
        size_t length,
        quac_entropy_source_t source);

    /**
     * @brief Generate non-zero random bytes
     *
     * @param[in] device Device handle
     * @param[out] buffer Buffer to fill with random bytes
     * @param[in] length Number of bytes to generate
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_random_bytes_nonzero(
        quac_device_t device,
        uint8_t *buffer,
        size_t length);

    /**
     * @brief Generate a random 32-bit unsigned integer
     *
     * @param[in] device Device handle
     * @param[out] value Random value
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_random_uint32(
        quac_device_t device,
        uint32_t *value);

    /**
     * @brief Generate a random 64-bit unsigned integer
     *
     * @param[in] device Device handle
     * @param[out] value Random value
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_random_uint64(
        quac_device_t device,
        uint64_t *value);

    /**
     * @brief Generate a random integer in range [0, max)
     *
     * Uses rejection sampling for unbiased results.
     *
     * @param[in] device Device handle
     * @param[in] max Exclusive upper bound (must be > 0)
     * @param[out] value Random value in [0, max)
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_random_range(
        quac_device_t device,
        uint32_t max,
        uint32_t *value);

    /**
     * @brief Generate a random integer in range [min, max)
     *
     * @param[in] device Device handle
     * @param[in] min Inclusive lower bound
     * @param[in] max Exclusive upper bound (must be > min)
     * @param[out] value Random value in [min, max)
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_random_range_ex(
        quac_device_t device,
        int64_t min,
        int64_t max,
        int64_t *value);

    /**
     * @brief Generate a random double in [0.0, 1.0)
     *
     * Uses full mantissa precision (53 bits).
     *
     * @param[in] device Device handle
     * @param[out] value Random value
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_random_double(
        quac_device_t device,
        double *value);

    /**
     * @brief Generate a random float in [0.0, 1.0)
     *
     * Uses full mantissa precision (24 bits).
     *
     * @param[in] device Device handle
     * @param[out] value Random value
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_random_float(
        quac_device_t device,
        float *value);

    /**
     * @brief Get entropy pool status
     *
     * @param[in] device Device handle
     * @param[out] status Entropy status
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_entropy_status(
        quac_device_t device,
        quac_entropy_status_t *status);

    /**
     * @brief Get entropy level (0-100)
     *
     * Convenience function to get just the entropy level.
     *
     * @param[in] device Device handle
     * @param[out] level Entropy level (0-100)
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_entropy_level(
        quac_device_t device,
        int *level);

    /**
     * @brief Seed the random number generator
     *
     * Adds additional entropy to the pool.
     *
     * @param[in] device Device handle
     * @param[in] seed Seed data
     * @param[in] seed_len Seed length
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_random_seed(
        quac_device_t device,
        const uint8_t *seed,
        size_t seed_len);

    /**
     * @brief Reseed from hardware entropy
     *
     * Forces a reseed from the hardware entropy source.
     *
     * @param[in] device Device handle
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_random_reseed(quac_device_t device);

    /**
     * @brief Shuffle an array using Fisher-Yates algorithm
     *
     * @param[in] device Device handle
     * @param[in,out] array Array to shuffle
     * @param[in] count Number of elements
     * @param[in] element_size Size of each element in bytes
     * @return QUAC_SUCCESS on success, error code on failure
     *
     * @code
     * int values[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
     * quac_random_shuffle(device, values, 10, sizeof(int));
     * @endcode
     */
    QUAC_API quac_status_t quac_random_shuffle(
        quac_device_t device,
        void *array,
        size_t count,
        size_t element_size);

    /**
     * @brief Select random elements from an array
     *
     * @param[in] device Device handle
     * @param[in] array Source array
     * @param[in] count Number of elements in source
     * @param[in] element_size Size of each element
     * @param[in] select_count Number of elements to select
     * @param[out] selected Buffer for selected elements
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_random_select(
        quac_device_t device,
        const void *array,
        size_t count,
        size_t element_size,
        size_t select_count,
        void *selected);

    /**
     * @brief Generate a random UUID v4
     *
     * @param[in] device Device handle
     * @param[out] uuid Buffer for UUID (16 bytes)
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_random_uuid(
        quac_device_t device,
        uint8_t uuid[16]);

    /**
     * @brief Generate a random UUID v4 as string
     *
     * @param[in] device Device handle
     * @param[out] uuid_str Buffer for UUID string (37 bytes minimum)
     * @param[in] buffer_size Buffer size
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_random_uuid_string(
        quac_device_t device,
        char *uuid_str,
        size_t buffer_size);

    /**
     * @brief Estimate Shannon entropy of random bytes
     *
     * @param[in] device Device handle
     * @param[in] sample_size Number of bytes to sample
     * @param[out] entropy Estimated entropy (bits per byte, max 8.0)
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_random_estimate_entropy(
        quac_device_t device,
        size_t sample_size,
        double *entropy);

    /**
     * @brief Run NIST SP 800-90B health tests
     *
     * @param[in] device Device handle
     * @param[out] passed Non-zero if tests pass
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_random_health_test(
        quac_device_t device,
        int *passed);

    /**
     * @brief Benchmark random generation throughput
     *
     * @param[in] device Device handle
     * @param[in] total_bytes Total bytes to generate for test
     * @param[out] mbps Throughput in MB/s
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_random_benchmark(
        quac_device_t device,
        size_t total_bytes,
        double *mbps);

    /* Async version */

    /**
     * @brief Asynchronous random byte generation
     */
    QUAC_API quac_status_t quac_random_bytes_async(
        quac_device_t device,
        uint8_t *buffer,
        size_t length,
        quac_async_callback_t callback,
        void *user_data,
        quac_async_t *async_handle);

    /** @} */ /* end of Random group */

#ifdef __cplusplus
}
#endif

#endif /* QUAC100_RANDOM_H */