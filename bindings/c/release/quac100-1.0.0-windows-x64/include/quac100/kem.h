/**
 * @file kem.h
 * @brief QUAC 100 SDK - Key Encapsulation Mechanism (ML-KEM/Kyber) API
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_KEM_H
#define QUAC100_KEM_H

#include "types.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * @defgroup KEM Key Encapsulation Mechanism
     * @brief ML-KEM (Kyber) key encapsulation operations
     * @{
     */

    /**
     * @brief Get ML-KEM algorithm parameters
     *
     * @param[in] algorithm Algorithm identifier
     * @param[out] params Algorithm parameters
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_kem_get_params(
        quac_kem_algorithm_t algorithm,
        quac_kem_params_t *params);

    /**
     * @brief Get key sizes for an ML-KEM algorithm
     *
     * @param[in] algorithm Algorithm identifier
     * @param[out] public_key_len Public key size in bytes
     * @param[out] secret_key_len Secret key size in bytes
     * @param[out] ciphertext_len Ciphertext size in bytes
     * @param[out] shared_secret_len Shared secret size in bytes
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_kem_get_sizes(
        quac_kem_algorithm_t algorithm,
        size_t *public_key_len,
        size_t *secret_key_len,
        size_t *ciphertext_len,
        size_t *shared_secret_len);

    /**
     * @brief Generate an ML-KEM key pair
     *
     * @param[in] device Device handle
     * @param[in] algorithm Algorithm identifier
     * @param[out] public_key Buffer for public key
     * @param[in,out] public_key_len Public key buffer size / actual size
     * @param[out] secret_key Buffer for secret key
     * @param[in,out] secret_key_len Secret key buffer size / actual size
     * @return QUAC_SUCCESS on success, error code on failure
     *
     * @code
     * uint8_t pk[QUAC_ML_KEM_768_PUBLIC_KEY_SIZE];
     * uint8_t sk[QUAC_ML_KEM_768_SECRET_KEY_SIZE];
     * size_t pk_len = sizeof(pk);
     * size_t sk_len = sizeof(sk);
     *
     * quac_status_t status = quac_kem_keygen(device, QUAC_KEM_ML_KEM_768,
     *                                         pk, &pk_len, sk, &sk_len);
     * @endcode
     */
    QUAC_API quac_status_t quac_kem_keygen(
        quac_device_t device,
        quac_kem_algorithm_t algorithm,
        uint8_t *public_key,
        size_t *public_key_len,
        uint8_t *secret_key,
        size_t *secret_key_len);

    /**
     * @brief Encapsulate a shared secret
     *
     * Generates a shared secret and encapsulates it under the given public key.
     *
     * @param[in] device Device handle
     * @param[in] algorithm Algorithm identifier
     * @param[in] public_key Public key
     * @param[in] public_key_len Public key length
     * @param[out] ciphertext Buffer for ciphertext
     * @param[in,out] ciphertext_len Ciphertext buffer size / actual size
     * @param[out] shared_secret Buffer for shared secret
     * @param[in,out] shared_secret_len Shared secret buffer size / actual size
     * @return QUAC_SUCCESS on success, error code on failure
     *
     * @code
     * uint8_t ct[QUAC_ML_KEM_768_CIPHERTEXT_SIZE];
     * uint8_t ss[QUAC_ML_KEM_SHARED_SECRET_SIZE];
     * size_t ct_len = sizeof(ct);
     * size_t ss_len = sizeof(ss);
     *
     * quac_status_t status = quac_kem_encaps(device, QUAC_KEM_ML_KEM_768,
     *                                         pk, pk_len, ct, &ct_len, ss, &ss_len);
     * @endcode
     */
    QUAC_API quac_status_t quac_kem_encaps(
        quac_device_t device,
        quac_kem_algorithm_t algorithm,
        const uint8_t *public_key,
        size_t public_key_len,
        uint8_t *ciphertext,
        size_t *ciphertext_len,
        uint8_t *shared_secret,
        size_t *shared_secret_len);

    /**
     * @brief Decapsulate a shared secret
     *
     * Recovers the shared secret from a ciphertext using the secret key.
     *
     * @param[in] device Device handle
     * @param[in] algorithm Algorithm identifier
     * @param[in] secret_key Secret key
     * @param[in] secret_key_len Secret key length
     * @param[in] ciphertext Ciphertext
     * @param[in] ciphertext_len Ciphertext length
     * @param[out] shared_secret Buffer for shared secret
     * @param[in,out] shared_secret_len Shared secret buffer size / actual size
     * @return QUAC_SUCCESS on success, error code on failure
     *
     * @code
     * uint8_t ss[QUAC_ML_KEM_SHARED_SECRET_SIZE];
     * size_t ss_len = sizeof(ss);
     *
     * quac_status_t status = quac_kem_decaps(device, QUAC_KEM_ML_KEM_768,
     *                                         sk, sk_len, ct, ct_len, ss, &ss_len);
     * @endcode
     */
    QUAC_API quac_status_t quac_kem_decaps(
        quac_device_t device,
        quac_kem_algorithm_t algorithm,
        const uint8_t *secret_key,
        size_t secret_key_len,
        const uint8_t *ciphertext,
        size_t ciphertext_len,
        uint8_t *shared_secret,
        size_t *shared_secret_len);

    /**
     * @brief Batch key generation
     *
     * Generates multiple key pairs in a single call for improved throughput.
     *
     * @param[in] device Device handle
     * @param[in] algorithm Algorithm identifier
     * @param[in] count Number of key pairs to generate
     * @param[out] public_keys Array of public key buffers
     * @param[out] secret_keys Array of secret key buffers
     * @param[out] status_codes Array of status codes for each operation
     * @return QUAC_SUCCESS if all operations succeed
     */
    QUAC_API quac_status_t quac_kem_keygen_batch(
        quac_device_t device,
        quac_kem_algorithm_t algorithm,
        size_t count,
        uint8_t **public_keys,
        uint8_t **secret_keys,
        quac_status_t *status_codes);

    /**
     * @brief Batch encapsulation
     *
     * @param[in] device Device handle
     * @param[in] algorithm Algorithm identifier
     * @param[in] count Number of encapsulations
     * @param[in] public_keys Array of public keys
     * @param[in] public_key_lens Array of public key lengths
     * @param[out] ciphertexts Array of ciphertext buffers
     * @param[out] shared_secrets Array of shared secret buffers
     * @param[out] status_codes Array of status codes
     * @return QUAC_SUCCESS if all operations succeed
     */
    QUAC_API quac_status_t quac_kem_encaps_batch(
        quac_device_t device,
        quac_kem_algorithm_t algorithm,
        size_t count,
        const uint8_t **public_keys,
        const size_t *public_key_lens,
        uint8_t **ciphertexts,
        uint8_t **shared_secrets,
        quac_status_t *status_codes);

    /**
     * @brief Batch decapsulation
     *
     * @param[in] device Device handle
     * @param[in] algorithm Algorithm identifier
     * @param[in] count Number of decapsulations
     * @param[in] secret_keys Array of secret keys
     * @param[in] secret_key_lens Array of secret key lengths
     * @param[in] ciphertexts Array of ciphertexts
     * @param[in] ciphertext_lens Array of ciphertext lengths
     * @param[out] shared_secrets Array of shared secret buffers
     * @param[out] status_codes Array of status codes
     * @return QUAC_SUCCESS if all operations succeed
     */
    QUAC_API quac_status_t quac_kem_decaps_batch(
        quac_device_t device,
        quac_kem_algorithm_t algorithm,
        size_t count,
        const uint8_t **secret_keys,
        const size_t *secret_key_lens,
        const uint8_t **ciphertexts,
        const size_t *ciphertext_lens,
        uint8_t **shared_secrets,
        quac_status_t *status_codes);

    /* Async versions */

    /**
     * @brief Asynchronous key generation
     */
    QUAC_API quac_status_t quac_kem_keygen_async(
        quac_device_t device,
        quac_kem_algorithm_t algorithm,
        uint8_t *public_key,
        size_t *public_key_len,
        uint8_t *secret_key,
        size_t *secret_key_len,
        quac_async_callback_t callback,
        void *user_data,
        quac_async_t *async_handle);

    /**
     * @brief Asynchronous encapsulation
     */
    QUAC_API quac_status_t quac_kem_encaps_async(
        quac_device_t device,
        quac_kem_algorithm_t algorithm,
        const uint8_t *public_key,
        size_t public_key_len,
        uint8_t *ciphertext,
        size_t *ciphertext_len,
        uint8_t *shared_secret,
        size_t *shared_secret_len,
        quac_async_callback_t callback,
        void *user_data,
        quac_async_t *async_handle);

    /**
     * @brief Asynchronous decapsulation
     */
    QUAC_API quac_status_t quac_kem_decaps_async(
        quac_device_t device,
        quac_kem_algorithm_t algorithm,
        const uint8_t *secret_key,
        size_t secret_key_len,
        const uint8_t *ciphertext,
        size_t ciphertext_len,
        uint8_t *shared_secret,
        size_t *shared_secret_len,
        quac_async_callback_t callback,
        void *user_data,
        quac_async_t *async_handle);

    /** @} */ /* end of KEM group */

#ifdef __cplusplus
}
#endif

#endif /* QUAC100_KEM_H */