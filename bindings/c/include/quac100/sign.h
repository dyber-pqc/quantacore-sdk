/**
 * @file sign.h
 * @brief QUAC 100 SDK - Digital Signature API (ML-DSA, SLH-DSA)
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_SIGN_H
#define QUAC100_SIGN_H

#include "types.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * @defgroup Signature Digital Signatures
     * @brief ML-DSA (Dilithium) and SLH-DSA (SPHINCS+) signature operations
     * @{
     */

    /**
     * @brief Get signature algorithm parameters
     *
     * @param[in] algorithm Algorithm identifier
     * @param[out] params Algorithm parameters
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_sign_get_params(
        quac_sign_algorithm_t algorithm,
        quac_sign_params_t *params);

    /**
     * @brief Get key/signature sizes for a signature algorithm
     *
     * @param[in] algorithm Algorithm identifier
     * @param[out] public_key_len Public key size in bytes
     * @param[out] secret_key_len Secret key size in bytes
     * @param[out] signature_len Maximum signature size in bytes
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_sign_get_sizes(
        quac_sign_algorithm_t algorithm,
        size_t *public_key_len,
        size_t *secret_key_len,
        size_t *signature_len);

    /**
     * @brief Generate a signature key pair
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
     * uint8_t pk[QUAC_ML_DSA_65_PUBLIC_KEY_SIZE];
     * uint8_t sk[QUAC_ML_DSA_65_SECRET_KEY_SIZE];
     * size_t pk_len = sizeof(pk);
     * size_t sk_len = sizeof(sk);
     *
     * quac_status_t status = quac_sign_keygen(device, QUAC_SIGN_ML_DSA_65,
     *                                          pk, &pk_len, sk, &sk_len);
     * @endcode
     */
    QUAC_API quac_status_t quac_sign_keygen(
        quac_device_t device,
        quac_sign_algorithm_t algorithm,
        uint8_t *public_key,
        size_t *public_key_len,
        uint8_t *secret_key,
        size_t *secret_key_len);

    /**
     * @brief Sign a message
     *
     * @param[in] device Device handle
     * @param[in] algorithm Algorithm identifier
     * @param[in] secret_key Secret key
     * @param[in] secret_key_len Secret key length
     * @param[in] message Message to sign
     * @param[in] message_len Message length
     * @param[out] signature Buffer for signature
     * @param[in,out] signature_len Signature buffer size / actual size
     * @return QUAC_SUCCESS on success, error code on failure
     *
     * @code
     * uint8_t sig[QUAC_ML_DSA_65_SIGNATURE_SIZE];
     * size_t sig_len = sizeof(sig);
     * const char* msg = "Hello, World!";
     *
     * quac_status_t status = quac_sign(device, QUAC_SIGN_ML_DSA_65,
     *                                   sk, sk_len,
     *                                   (uint8_t*)msg, strlen(msg),
     *                                   sig, &sig_len);
     * @endcode
     */
    QUAC_API quac_status_t quac_sign(
        quac_device_t device,
        quac_sign_algorithm_t algorithm,
        const uint8_t *secret_key,
        size_t secret_key_len,
        const uint8_t *message,
        size_t message_len,
        uint8_t *signature,
        size_t *signature_len);

    /**
     * @brief Verify a signature
     *
     * @param[in] device Device handle
     * @param[in] algorithm Algorithm identifier
     * @param[in] public_key Public key
     * @param[in] public_key_len Public key length
     * @param[in] message Message that was signed
     * @param[in] message_len Message length
     * @param[in] signature Signature to verify
     * @param[in] signature_len Signature length
     * @return QUAC_SUCCESS if valid, QUAC_ERROR_VERIFY_FAILED if invalid
     *
     * @code
     * quac_status_t status = quac_verify(device, QUAC_SIGN_ML_DSA_65,
     *                                     pk, pk_len,
     *                                     (uint8_t*)msg, strlen(msg),
     *                                     sig, sig_len);
     * if (status == QUAC_SUCCESS) {
     *     printf("Signature valid\n");
     * } else if (status == QUAC_ERROR_VERIFY_FAILED) {
     *     printf("Signature invalid\n");
     * }
     * @endcode
     */
    QUAC_API quac_status_t quac_verify(
        quac_device_t device,
        quac_sign_algorithm_t algorithm,
        const uint8_t *public_key,
        size_t public_key_len,
        const uint8_t *message,
        size_t message_len,
        const uint8_t *signature,
        size_t signature_len);

    /**
     * @brief Sign a pre-hashed message
     *
     * For large messages, pre-hash with a secure hash function first.
     *
     * @param[in] device Device handle
     * @param[in] algorithm Algorithm identifier
     * @param[in] secret_key Secret key
     * @param[in] secret_key_len Secret key length
     * @param[in] hash Pre-computed hash of message
     * @param[in] hash_len Hash length
     * @param[in] hash_alg Hash algorithm used
     * @param[out] signature Buffer for signature
     * @param[in,out] signature_len Signature buffer size / actual size
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_sign_prehash(
        quac_device_t device,
        quac_sign_algorithm_t algorithm,
        const uint8_t *secret_key,
        size_t secret_key_len,
        const uint8_t *hash,
        size_t hash_len,
        quac_hash_algorithm_t hash_alg,
        uint8_t *signature,
        size_t *signature_len);

    /**
     * @brief Verify a signature on a pre-hashed message
     *
     * @param[in] device Device handle
     * @param[in] algorithm Algorithm identifier
     * @param[in] public_key Public key
     * @param[in] public_key_len Public key length
     * @param[in] hash Pre-computed hash of message
     * @param[in] hash_len Hash length
     * @param[in] hash_alg Hash algorithm used
     * @param[in] signature Signature to verify
     * @param[in] signature_len Signature length
     * @return QUAC_SUCCESS if valid, QUAC_ERROR_VERIFY_FAILED if invalid
     */
    QUAC_API quac_status_t quac_verify_prehash(
        quac_device_t device,
        quac_sign_algorithm_t algorithm,
        const uint8_t *public_key,
        size_t public_key_len,
        const uint8_t *hash,
        size_t hash_len,
        quac_hash_algorithm_t hash_alg,
        const uint8_t *signature,
        size_t signature_len);

    /**
     * @brief Batch key generation
     *
     * @param[in] device Device handle
     * @param[in] algorithm Algorithm identifier
     * @param[in] count Number of key pairs to generate
     * @param[out] public_keys Array of public key buffers
     * @param[out] secret_keys Array of secret key buffers
     * @param[out] status_codes Array of status codes
     * @return QUAC_SUCCESS if all operations succeed
     */
    QUAC_API quac_status_t quac_sign_keygen_batch(
        quac_device_t device,
        quac_sign_algorithm_t algorithm,
        size_t count,
        uint8_t **public_keys,
        uint8_t **secret_keys,
        quac_status_t *status_codes);

    /**
     * @brief Batch signing
     *
     * @param[in] device Device handle
     * @param[in] algorithm Algorithm identifier
     * @param[in] secret_key Secret key (same for all messages)
     * @param[in] secret_key_len Secret key length
     * @param[in] count Number of messages to sign
     * @param[in] messages Array of messages
     * @param[in] message_lens Array of message lengths
     * @param[out] signatures Array of signature buffers
     * @param[out] signature_lens Array of signature lengths
     * @param[out] status_codes Array of status codes
     * @return QUAC_SUCCESS if all operations succeed
     */
    QUAC_API quac_status_t quac_sign_batch(
        quac_device_t device,
        quac_sign_algorithm_t algorithm,
        const uint8_t *secret_key,
        size_t secret_key_len,
        size_t count,
        const uint8_t **messages,
        const size_t *message_lens,
        uint8_t **signatures,
        size_t *signature_lens,
        quac_status_t *status_codes);

    /**
     * @brief Batch verification
     *
     * @param[in] device Device handle
     * @param[in] algorithm Algorithm identifier
     * @param[in] public_key Public key (same for all messages)
     * @param[in] public_key_len Public key length
     * @param[in] count Number of signatures to verify
     * @param[in] messages Array of messages
     * @param[in] message_lens Array of message lengths
     * @param[in] signatures Array of signatures
     * @param[in] signature_lens Array of signature lengths
     * @param[out] results Array of verification results (1=valid, 0=invalid)
     * @param[out] status_codes Array of status codes
     * @return QUAC_SUCCESS if all operations complete
     */
    QUAC_API quac_status_t quac_verify_batch(
        quac_device_t device,
        quac_sign_algorithm_t algorithm,
        const uint8_t *public_key,
        size_t public_key_len,
        size_t count,
        const uint8_t **messages,
        const size_t *message_lens,
        const uint8_t **signatures,
        const size_t *signature_lens,
        int *results,
        quac_status_t *status_codes);

    /* Async versions */

    /**
     * @brief Asynchronous key generation
     */
    QUAC_API quac_status_t quac_sign_keygen_async(
        quac_device_t device,
        quac_sign_algorithm_t algorithm,
        uint8_t *public_key,
        size_t *public_key_len,
        uint8_t *secret_key,
        size_t *secret_key_len,
        quac_async_callback_t callback,
        void *user_data,
        quac_async_t *async_handle);

    /**
     * @brief Asynchronous signing
     */
    QUAC_API quac_status_t quac_sign_async(
        quac_device_t device,
        quac_sign_algorithm_t algorithm,
        const uint8_t *secret_key,
        size_t secret_key_len,
        const uint8_t *message,
        size_t message_len,
        uint8_t *signature,
        size_t *signature_len,
        quac_async_callback_t callback,
        void *user_data,
        quac_async_t *async_handle);

    /**
     * @brief Asynchronous verification
     */
    QUAC_API quac_status_t quac_verify_async(
        quac_device_t device,
        quac_sign_algorithm_t algorithm,
        const uint8_t *public_key,
        size_t public_key_len,
        const uint8_t *message,
        size_t message_len,
        const uint8_t *signature,
        size_t signature_len,
        quac_async_callback_t callback,
        void *user_data,
        quac_async_t *async_handle);

    /** @} */ /* end of Signature group */

#ifdef __cplusplus
}
#endif

#endif /* QUAC100_SIGN_H */