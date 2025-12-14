/**
 * @file hash.h
 * @brief QUAC 100 SDK - Hash Operations API
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_HASH_H
#define QUAC100_HASH_H

#include "types.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * @defgroup Hash Hash Operations
     * @brief Hardware-accelerated hash functions
     * @{
     */

    /**
     * @brief Get hash output size
     *
     * @param[in] algorithm Hash algorithm
     * @param[out] size Hash output size in bytes
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_hash_size(
        quac_hash_algorithm_t algorithm,
        size_t *size);

    /**
     * @brief Compute hash of data (one-shot)
     *
     * @param[in] device Device handle
     * @param[in] algorithm Hash algorithm
     * @param[in] data Data to hash
     * @param[in] data_len Data length
     * @param[out] hash Buffer for hash output
     * @param[in,out] hash_len Hash buffer size / actual size
     * @return QUAC_SUCCESS on success, error code on failure
     *
     * @code
     * uint8_t hash[QUAC_SHA256_SIZE];
     * size_t hash_len = sizeof(hash);
     * quac_hash(device, QUAC_HASH_SHA256, data, data_len, hash, &hash_len);
     * @endcode
     */
    QUAC_API quac_status_t quac_hash(
        quac_device_t device,
        quac_hash_algorithm_t algorithm,
        const uint8_t *data,
        size_t data_len,
        uint8_t *hash,
        size_t *hash_len);

    /**
     * @brief Initialize incremental hash context
     *
     * @param[in] device Device handle
     * @param[in] algorithm Hash algorithm
     * @param[out] ctx Hash context handle
     * @return QUAC_SUCCESS on success, error code on failure
     *
     * @code
     * quac_hash_ctx_t ctx;
     * quac_hash_init(device, QUAC_HASH_SHA256, &ctx);
     * quac_hash_update(ctx, data1, len1);
     * quac_hash_update(ctx, data2, len2);
     * quac_hash_final(ctx, hash, &hash_len);
     * quac_hash_free(ctx);
     * @endcode
     */
    QUAC_API quac_status_t quac_hash_init(
        quac_device_t device,
        quac_hash_algorithm_t algorithm,
        quac_hash_ctx_t *ctx);

    /**
     * @brief Update hash context with data
     *
     * @param[in] ctx Hash context
     * @param[in] data Data to hash
     * @param[in] data_len Data length
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_hash_update(
        quac_hash_ctx_t ctx,
        const uint8_t *data,
        size_t data_len);

    /**
     * @brief Finalize hash and get result
     *
     * @param[in] ctx Hash context
     * @param[out] hash Buffer for hash output
     * @param[in,out] hash_len Hash buffer size / actual size
     * @return QUAC_SUCCESS on success, error code on failure
     *
     * @note The context is invalidated after this call
     */
    QUAC_API quac_status_t quac_hash_final(
        quac_hash_ctx_t ctx,
        uint8_t *hash,
        size_t *hash_len);

    /**
     * @brief Free hash context
     *
     * @param[in] ctx Hash context
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_hash_free(quac_hash_ctx_t ctx);

    /**
     * @brief Clone hash context
     *
     * Creates a copy of the hash context for computing multiple
     * hashes with a shared prefix.
     *
     * @param[in] src Source context
     * @param[out] dst Destination context
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_hash_clone(
        quac_hash_ctx_t src,
        quac_hash_ctx_t *dst);

    /**
     * @brief Reset hash context for reuse
     *
     * @param[in] ctx Hash context
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_hash_reset(quac_hash_ctx_t ctx);

    /* Convenience functions */

    /**
     * @brief Compute SHA-256 hash
     */
    QUAC_API quac_status_t quac_sha256(
        quac_device_t device,
        const uint8_t *data,
        size_t data_len,
        uint8_t hash[QUAC_SHA256_SIZE]);

    /**
     * @brief Compute SHA-384 hash
     */
    QUAC_API quac_status_t quac_sha384(
        quac_device_t device,
        const uint8_t *data,
        size_t data_len,
        uint8_t hash[QUAC_SHA384_SIZE]);

    /**
     * @brief Compute SHA-512 hash
     */
    QUAC_API quac_status_t quac_sha512(
        quac_device_t device,
        const uint8_t *data,
        size_t data_len,
        uint8_t hash[QUAC_SHA512_SIZE]);

    /**
     * @brief Compute SHA3-256 hash
     */
    QUAC_API quac_status_t quac_sha3_256(
        quac_device_t device,
        const uint8_t *data,
        size_t data_len,
        uint8_t hash[QUAC_SHA3_256_SIZE]);

    /**
     * @brief Compute SHA3-512 hash
     */
    QUAC_API quac_status_t quac_sha3_512(
        quac_device_t device,
        const uint8_t *data,
        size_t data_len,
        uint8_t hash[QUAC_SHA3_512_SIZE]);

    /**
     * @brief Compute SHAKE128 extendable output
     *
     * @param[in] device Device handle
     * @param[in] data Input data
     * @param[in] data_len Input length
     * @param[out] output Output buffer
     * @param[in] output_len Desired output length
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_shake128(
        quac_device_t device,
        const uint8_t *data,
        size_t data_len,
        uint8_t *output,
        size_t output_len);

    /**
     * @brief Compute SHAKE256 extendable output
     */
    QUAC_API quac_status_t quac_shake256(
        quac_device_t device,
        const uint8_t *data,
        size_t data_len,
        uint8_t *output,
        size_t output_len);

    /**
     * @brief Compute HMAC
     *
     * @param[in] device Device handle
     * @param[in] algorithm Underlying hash algorithm
     * @param[in] key HMAC key
     * @param[in] key_len Key length
     * @param[in] data Data to authenticate
     * @param[in] data_len Data length
     * @param[out] mac MAC output buffer
     * @param[in,out] mac_len MAC buffer size / actual size
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_hmac(
        quac_device_t device,
        quac_hash_algorithm_t algorithm,
        const uint8_t *key,
        size_t key_len,
        const uint8_t *data,
        size_t data_len,
        uint8_t *mac,
        size_t *mac_len);

    /**
     * @brief HKDF key derivation
     *
     * @param[in] device Device handle
     * @param[in] algorithm Underlying hash algorithm
     * @param[in] salt Salt (optional, can be NULL)
     * @param[in] salt_len Salt length
     * @param[in] ikm Input key material
     * @param[in] ikm_len IKM length
     * @param[in] info Context info (optional, can be NULL)
     * @param[in] info_len Info length
     * @param[out] okm Output key material
     * @param[in] okm_len Desired output length
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_hkdf(
        quac_device_t device,
        quac_hash_algorithm_t algorithm,
        const uint8_t *salt,
        size_t salt_len,
        const uint8_t *ikm,
        size_t ikm_len,
        const uint8_t *info,
        size_t info_len,
        uint8_t *okm,
        size_t okm_len);

    /**
     * @brief Hash file contents
     *
     * @param[in] device Device handle
     * @param[in] algorithm Hash algorithm
     * @param[in] filename Path to file
     * @param[out] hash Buffer for hash output
     * @param[in,out] hash_len Hash buffer size / actual size
     * @param[in] progress Optional progress callback
     * @param[in] user_data User data for callback
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_hash_file(
        quac_device_t device,
        quac_hash_algorithm_t algorithm,
        const char *filename,
        uint8_t *hash,
        size_t *hash_len,
        quac_progress_callback_t progress,
        void *user_data);

    /** @} */ /* end of Hash group */

#ifdef __cplusplus
}
#endif

#endif /* QUAC100_HASH_H */