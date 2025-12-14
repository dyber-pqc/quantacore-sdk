/**
 * @file quac100_kem.h
 * @brief QuantaCore SDK - Key Encapsulation Mechanism (KEM) Operations
 *
 * Extended KEM interface for ML-KEM (Kyber) operations including deterministic
 * key generation, stored key operations, and batch processing.
 *
 * This header provides additional KEM functionality beyond the core API
 * defined in quac100.h.
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 * @doc QUAC100-SDK-DEV-001
 *
 * @par Supported Algorithms
 * - ML-KEM-512 (Kyber512) - NIST Security Level 1
 * - ML-KEM-768 (Kyber768) - NIST Security Level 3
 * - ML-KEM-1024 (Kyber1024) - NIST Security Level 5
 */

#ifndef QUAC100_KEM_H
#define QUAC100_KEM_H

#include "quac100_types.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /*=============================================================================
     * KEM Algorithm Information
     *=============================================================================*/

    /**
     * @brief KEM algorithm parameters
     */
    typedef struct quac_kem_params_s
    {
        uint32_t struct_size;       /**< Size of this structure */
        quac_algorithm_t algorithm; /**< Algorithm identifier */
        const char *name;           /**< Algorithm name */
        const char *nist_name;      /**< NIST standard name (e.g., "ML-KEM-768") */
        uint32_t security_level;    /**< NIST security level (1, 3, or 5) */
        size_t public_key_size;     /**< Public key size in bytes */
        size_t secret_key_size;     /**< Secret key size in bytes */
        size_t ciphertext_size;     /**< Ciphertext size in bytes */
        size_t shared_secret_size;  /**< Shared secret size in bytes */
        uint32_t n;                 /**< Polynomial ring dimension */
        uint32_t k;                 /**< Module rank */
        uint32_t q;                 /**< Modulus */
        uint32_t eta1;              /**< Noise parameter η₁ */
        uint32_t eta2;              /**< Noise parameter η₂ */
        uint32_t du;                /**< Compression parameter d_u */
        uint32_t dv;                /**< Compression parameter d_v */
    } quac_kem_params_t;

    /**
     * @brief Get KEM algorithm parameters
     *
     * @param[in]  algorithm    KEM algorithm
     * @param[out] params       Pointer to receive parameters
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_INVALID_ALGORITHM if not a KEM algorithm
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_kem_get_params(quac_algorithm_t algorithm, quac_kem_params_t *params);

    /**
     * @brief Enumerate supported KEM algorithms
     *
     * @param[in]  index        Algorithm index (0-based)
     * @param[out] algorithm    Pointer to receive algorithm
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_INVALID_PARAMETER if index out of range
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_kem_enumerate(uint32_t index, quac_algorithm_t *algorithm);

    /**
     * @brief Get number of supported KEM algorithms
     *
     * @return Number of supported KEM algorithms
     */
    QUAC100_API uint32_t QUAC100_CALL
    quac_kem_count(void);

    /*=============================================================================
     * Key Pair Structure
     *=============================================================================*/

    /**
     * @brief KEM key pair container
     *
     * Holds both public and secret keys with associated metadata.
     */
    typedef struct quac_kem_keypair_s
    {
        uint32_t struct_size;       /**< Size of this structure */
        quac_algorithm_t algorithm; /**< Key algorithm */
        uint8_t *public_key;        /**< Public key data */
        size_t public_key_size;     /**< Public key size */
        uint8_t *secret_key;        /**< Secret key data */
        size_t secret_key_size;     /**< Secret key size */
        bool owns_memory;           /**< True if struct owns key memory */
        uint8_t fingerprint[32];    /**< Key fingerprint (SHA-256 of public key) */
    } quac_kem_keypair_t;

    /**
     * @brief Allocate a key pair structure
     *
     * Allocates memory for keys based on algorithm requirements.
     *
     * @param[in]  algorithm    KEM algorithm
     * @param[out] keypair      Pointer to receive allocated keypair
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_OUT_OF_MEMORY on allocation failure
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_kem_keypair_alloc(quac_algorithm_t algorithm, quac_kem_keypair_t **keypair);

    /**
     * @brief Free a key pair structure
     *
     * Securely zeroizes key material before freeing memory.
     *
     * @param keypair   Key pair to free
     */
    QUAC100_API void QUAC100_CALL
    quac_kem_keypair_free(quac_kem_keypair_t *keypair);

    /**
     * @brief Initialize key pair with existing buffers
     *
     * @param[out] keypair      Key pair structure to initialize
     * @param[in]  algorithm    KEM algorithm
     * @param[in]  public_key   Public key buffer
     * @param[in]  pk_size      Public key size
     * @param[in]  secret_key   Secret key buffer (may be NULL for public-only)
     * @param[in]  sk_size      Secret key size
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_kem_keypair_init(quac_kem_keypair_t *keypair,
                          quac_algorithm_t algorithm,
                          uint8_t *public_key, size_t pk_size,
                          uint8_t *secret_key, size_t sk_size);

    /**
     * @brief Compute key fingerprint
     *
     * Computes SHA-256 hash of public key for identification.
     *
     * @param keypair   Key pair (fingerprint field updated)
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_kem_keypair_fingerprint(quac_kem_keypair_t *keypair);

    /*=============================================================================
     * Extended Key Generation
     *=============================================================================*/

    /**
     * @brief Generate KEM key pair into structure
     *
     * @param[in]  device       Device handle
     * @param[in]  algorithm    KEM algorithm
     * @param[out] keypair      Pre-allocated key pair structure
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_KEY_GENERATION_FAILED on failure
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_kem_keygen_ex(quac_device_t device,
                       quac_algorithm_t algorithm,
                       quac_kem_keypair_t *keypair);

    /**
     * @brief Generate deterministic KEM key pair from seed
     *
     * Generates a key pair deterministically from a 64-byte seed.
     * WARNING: Seed must be kept secret and never reused.
     *
     * @param[in]  device       Device handle
     * @param[in]  algorithm    KEM algorithm
     * @param[in]  seed         64-byte seed value
     * @param[out] public_key   Buffer for public key
     * @param[in]  pk_size      Public key buffer size
     * @param[out] secret_key   Buffer for secret key
     * @param[in]  sk_size      Secret key buffer size
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_KEY_GENERATION_FAILED on failure
     *
     * @note This function is primarily for testing and key recovery scenarios.
     *       For normal use, prefer quac_kem_keygen() with hardware RNG.
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_kem_keygen_deterministic(quac_device_t device,
                                  quac_algorithm_t algorithm,
                                  const uint8_t seed[64],
                                  uint8_t *public_key, size_t pk_size,
                                  uint8_t *secret_key, size_t sk_size);

    /*=============================================================================
     * Stored Key Operations
     *=============================================================================*/

    /**
     * @brief Generate and store KEM key pair on device
     *
     * @param[in]  device       Device handle
     * @param[in]  algorithm    KEM algorithm
     * @param[in]  label        Optional key label (may be NULL)
     * @param[in]  persistent   True to persist across reboots
     * @param[out] handle       Handle to stored key
     * @param[out] public_key   Buffer for public key (may be NULL)
     * @param[in]  pk_size      Public key buffer size
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_KEY_SLOT_FULL if no storage available
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_kem_keygen_stored(quac_device_t device,
                           quac_algorithm_t algorithm,
                           const char *label,
                           bool persistent,
                           quac_key_handle_t *handle,
                           uint8_t *public_key, size_t pk_size);

    /**
     * @brief Encapsulate using stored public key
     *
     * @param[in]  device       Device handle
     * @param[in]  key_handle   Handle to stored key (public key portion)
     * @param[out] ciphertext   Buffer for ciphertext
     * @param[in]  ct_size      Ciphertext buffer size
     * @param[out] shared_secret Buffer for shared secret
     * @param[in]  ss_size      Shared secret buffer size
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_kem_encaps_stored(quac_device_t device,
                           quac_key_handle_t key_handle,
                           uint8_t *ciphertext, size_t ct_size,
                           uint8_t *shared_secret, size_t ss_size);

    /**
     * @brief Decapsulate using stored secret key
     *
     * The shared secret is computed on-device; the secret key never leaves
     * the hardware security boundary.
     *
     * @param[in]  device       Device handle
     * @param[in]  key_handle   Handle to stored key (must include secret key)
     * @param[in]  ciphertext   Ciphertext
     * @param[in]  ct_size      Ciphertext size
     * @param[out] shared_secret Buffer for shared secret
     * @param[in]  ss_size      Shared secret buffer size
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_KEY_NOT_FOUND if key not found
     * @return QUAC_ERROR_KEY_USAGE_DENIED if key cannot decapsulate
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_kem_decaps_stored(quac_device_t device,
                           quac_key_handle_t key_handle,
                           const uint8_t *ciphertext, size_t ct_size,
                           uint8_t *shared_secret, size_t ss_size);

    /*=============================================================================
     * Batch KEM Operations
     *=============================================================================*/

    /**
     * @brief KEM operation type for batch processing
     */
    typedef enum quac_kem_op_e
    {
        QUAC_KEM_OP_KEYGEN = 0, /**< Key generation */
        QUAC_KEM_OP_ENCAPS = 1, /**< Encapsulation */
        QUAC_KEM_OP_DECAPS = 2, /**< Decapsulation */
    } quac_kem_op_t;

    /**
     * @brief Batch KEM operation item
     */
    typedef struct quac_kem_batch_item_s
    {
        quac_kem_op_t operation;    /**< Operation type */
        quac_algorithm_t algorithm; /**< Algorithm */

        /* Input data (depends on operation) */
        const uint8_t *public_key;    /**< Public key (encaps) */
        size_t pk_size;               /**< Public key size */
        const uint8_t *secret_key;    /**< Secret key (decaps) */
        size_t sk_size;               /**< Secret key size */
        const uint8_t *ciphertext_in; /**< Ciphertext input (decaps) */
        size_t ct_in_size;            /**< Ciphertext input size */

        /* Output data */
        uint8_t *public_key_out; /**< Public key output (keygen) */
        size_t pk_out_size;      /**< Public key output buffer size */
        uint8_t *secret_key_out; /**< Secret key output (keygen) */
        size_t sk_out_size;      /**< Secret key output buffer size */
        uint8_t *ciphertext_out; /**< Ciphertext output (encaps) */
        size_t ct_out_size;      /**< Ciphertext output buffer size */
        uint8_t *shared_secret;  /**< Shared secret output */
        size_t ss_size;          /**< Shared secret buffer size */

        /* Result */
        quac_result_t result; /**< Operation result */
        void *user_data;      /**< User context */
    } quac_kem_batch_item_t;

    /**
     * @brief Execute batch KEM operations
     *
     * Processes multiple KEM operations in parallel for maximum throughput.
     *
     * @param[in]     device    Device handle
     * @param[in,out] items     Array of batch items
     * @param[in]     count     Number of items
     *
     * @return QUAC_SUCCESS if all operations succeeded
     * @return QUAC_ERROR_BATCH_PARTIAL if some operations failed
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_kem_batch(quac_device_t device, quac_kem_batch_item_t *items, size_t count);

    /**
     * @brief Batch key generation
     *
     * Generate multiple key pairs in a single call.
     *
     * @param[in]  device       Device handle
     * @param[in]  algorithm    KEM algorithm (same for all)
     * @param[out] keypairs     Array of keypair structures
     * @param[in]  count        Number of keypairs to generate
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_kem_batch_keygen(quac_device_t device,
                          quac_algorithm_t algorithm,
                          quac_kem_keypair_t *keypairs,
                          size_t count);

    /*=============================================================================
     * Async KEM Operations
     *=============================================================================*/

    /**
     * @brief Submit async encapsulation
     *
     * @param[in]  device       Device handle
     * @param[in]  algorithm    KEM algorithm
     * @param[in]  public_key   Public key
     * @param[in]  pk_size      Public key size
     * @param[out] ciphertext   Buffer for ciphertext
     * @param[in]  ct_size      Ciphertext buffer size
     * @param[out] shared_secret Buffer for shared secret
     * @param[in]  ss_size      Shared secret buffer size
     * @param[in]  callback     Completion callback (may be NULL)
     * @param[in]  user_data    User context
     * @param[out] job_id       Job identifier
     *
     * @return QUAC_SUCCESS on successful submission
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_kem_async_encaps(quac_device_t device,
                          quac_algorithm_t algorithm,
                          const uint8_t *public_key, size_t pk_size,
                          uint8_t *ciphertext, size_t ct_size,
                          uint8_t *shared_secret, size_t ss_size,
                          quac_async_callback_t callback,
                          void *user_data,
                          quac_job_id_t *job_id);

    /**
     * @brief Submit async decapsulation
     *
     * @param[in]  device       Device handle
     * @param[in]  algorithm    KEM algorithm
     * @param[in]  ciphertext   Ciphertext
     * @param[in]  ct_size      Ciphertext size
     * @param[in]  secret_key   Secret key
     * @param[in]  sk_size      Secret key size
     * @param[out] shared_secret Buffer for shared secret
     * @param[in]  ss_size      Shared secret buffer size
     * @param[in]  callback     Completion callback
     * @param[in]  user_data    User context
     * @param[out] job_id       Job identifier
     *
     * @return QUAC_SUCCESS on successful submission
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_kem_async_decaps(quac_device_t device,
                          quac_algorithm_t algorithm,
                          const uint8_t *ciphertext, size_t ct_size,
                          const uint8_t *secret_key, size_t sk_size,
                          uint8_t *shared_secret, size_t ss_size,
                          quac_async_callback_t callback,
                          void *user_data,
                          quac_job_id_t *job_id);

    /*=============================================================================
     * Key Validation
     *=============================================================================*/

    /**
     * @brief Validate public key format
     *
     * Checks that the public key is properly formatted for the algorithm.
     * Does not verify the key was generated correctly.
     *
     * @param[in] algorithm     KEM algorithm
     * @param[in] public_key    Public key to validate
     * @param[in] pk_size       Public key size
     *
     * @return QUAC_SUCCESS if valid
     * @return QUAC_ERROR_INVALID_KEY if malformed
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_kem_validate_public_key(quac_algorithm_t algorithm,
                                 const uint8_t *public_key, size_t pk_size);

    /**
     * @brief Validate secret key format
     *
     * @param[in] algorithm     KEM algorithm
     * @param[in] secret_key    Secret key to validate
     * @param[in] sk_size       Secret key size
     *
     * @return QUAC_SUCCESS if valid
     * @return QUAC_ERROR_INVALID_KEY if malformed
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_kem_validate_secret_key(quac_algorithm_t algorithm,
                                 const uint8_t *secret_key, size_t sk_size);

    /**
     * @brief Validate ciphertext format
     *
     * @param[in] algorithm     KEM algorithm
     * @param[in] ciphertext    Ciphertext to validate
     * @param[in] ct_size       Ciphertext size
     *
     * @return QUAC_SUCCESS if valid
     * @return QUAC_ERROR_INVALID_CIPHERTEXT if malformed
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_kem_validate_ciphertext(quac_algorithm_t algorithm,
                                 const uint8_t *ciphertext, size_t ct_size);

    /**
     * @brief Check if public and secret keys match
     *
     * Verifies that the secret key corresponds to the public key.
     *
     * @param[in] algorithm     KEM algorithm
     * @param[in] public_key    Public key
     * @param[in] pk_size       Public key size
     * @param[in] secret_key    Secret key
     * @param[in] sk_size       Secret key size
     *
     * @return QUAC_SUCCESS if keys match
     * @return QUAC_ERROR_INVALID_KEY if keys don't match
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_kem_check_keypair(quac_algorithm_t algorithm,
                           const uint8_t *public_key, size_t pk_size,
                           const uint8_t *secret_key, size_t sk_size);

    /*=============================================================================
     * Performance Statistics
     *=============================================================================*/

    /**
     * @brief KEM performance statistics
     */
    typedef struct quac_kem_stats_s
    {
        uint32_t struct_size;     /**< Size of this structure */
        uint64_t keygen_count;    /**< Key generations performed */
        uint64_t encaps_count;    /**< Encapsulations performed */
        uint64_t decaps_count;    /**< Decapsulations performed */
        uint64_t keygen_failures; /**< Key generation failures */
        uint64_t encaps_failures; /**< Encapsulation failures */
        uint64_t decaps_failures; /**< Decapsulation failures */
        uint64_t keygen_total_ns; /**< Total keygen time (ns) */
        uint64_t encaps_total_ns; /**< Total encaps time (ns) */
        uint64_t decaps_total_ns; /**< Total decaps time (ns) */
        uint32_t keygen_avg_us;   /**< Average keygen time (μs) */
        uint32_t encaps_avg_us;   /**< Average encaps time (μs) */
        uint32_t decaps_avg_us;   /**< Average decaps time (μs) */
        uint32_t keygen_min_us;   /**< Minimum keygen time (μs) */
        uint32_t encaps_min_us;   /**< Minimum encaps time (μs) */
        uint32_t decaps_min_us;   /**< Minimum decaps time (μs) */
        uint32_t keygen_max_us;   /**< Maximum keygen time (μs) */
        uint32_t encaps_max_us;   /**< Maximum encaps time (μs) */
        uint32_t decaps_max_us;   /**< Maximum decaps time (μs) */
    } quac_kem_stats_t;

    /**
     * @brief Get KEM performance statistics
     *
     * @param[in]  device       Device handle
     * @param[in]  algorithm    Algorithm (or QUAC_ALGORITHM_NONE for all)
     * @param[out] stats        Pointer to receive statistics
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_kem_get_stats(quac_device_t device,
                       quac_algorithm_t algorithm,
                       quac_kem_stats_t *stats);

    /**
     * @brief Reset KEM performance statistics
     *
     * @param[in] device        Device handle
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_kem_reset_stats(quac_device_t device);

#ifdef __cplusplus
}
#endif

#endif /* QUAC100_KEM_H */
