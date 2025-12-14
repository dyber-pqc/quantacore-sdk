/**
 * @file quac100_sign.h
 * @brief QuantaCore SDK - Digital Signature Operations
 *
 * Extended digital signature interface for ML-DSA (Dilithium) and SLH-DSA
 * (SPHINCS+) operations including deterministic signing, stored key operations,
 * context strings, and batch processing.
 *
 * This header provides additional signature functionality beyond the core API
 * defined in quac100.h.
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 * @doc QUAC100-SDK-DEV-001
 *
 * @par Supported Algorithms
 *
 * ML-DSA (Dilithium) - NIST FIPS 204:
 * - ML-DSA-44 (Dilithium2) - NIST Security Level 2
 * - ML-DSA-65 (Dilithium3) - NIST Security Level 3
 * - ML-DSA-87 (Dilithium5) - NIST Security Level 5
 *
 * SLH-DSA (SPHINCS+) - NIST FIPS 205:
 * - SLH-DSA-SHA2-128s/f - NIST Security Level 1
 * - SLH-DSA-SHA2-192s/f - NIST Security Level 3
 * - SLH-DSA-SHA2-256s/f - NIST Security Level 5
 */

#ifndef QUAC100_SIGN_H
#define QUAC100_SIGN_H

#include "quac100_types.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /*=============================================================================
     * Signature Algorithm Information
     *=============================================================================*/

    /**
     * @brief Signature algorithm family
     */
    typedef enum quac_sign_family_e
    {
        QUAC_SIGN_FAMILY_DILITHIUM = 0, /**< ML-DSA (Dilithium) */
        QUAC_SIGN_FAMILY_SPHINCS = 1,   /**< SLH-DSA (SPHINCS+) */
    } quac_sign_family_t;

    /**
     * @brief SPHINCS+ variant type
     */
    typedef enum quac_sphincs_variant_e
    {
        QUAC_SPHINCS_SMALL = 0, /**< Small signatures ('s' variant) */
        QUAC_SPHINCS_FAST = 1,  /**< Fast signing ('f' variant) */
    } quac_sphincs_variant_t;

    /**
     * @brief Signature algorithm parameters
     */
    typedef struct quac_sign_params_s
    {
        uint32_t struct_size;       /**< Size of this structure */
        quac_algorithm_t algorithm; /**< Algorithm identifier */
        quac_sign_family_t family;  /**< Algorithm family */
        const char *name;           /**< Algorithm name */
        const char *nist_name;      /**< NIST standard name */
        uint32_t security_level;    /**< NIST security level (1-5) */
        size_t public_key_size;     /**< Public key size in bytes */
        size_t secret_key_size;     /**< Secret key size in bytes */
        size_t signature_size;      /**< Maximum signature size in bytes */
        bool deterministic;         /**< True if signatures are deterministic */

        /* ML-DSA (Dilithium) specific parameters */
        struct
        {
            uint32_t n;      /**< Polynomial ring dimension (256) */
            uint32_t k;      /**< Rows in matrix A */
            uint32_t l;      /**< Columns in matrix A */
            uint32_t q;      /**< Modulus */
            uint32_t eta;    /**< Secret key coefficient range */
            uint32_t tau;    /**< Number of ±1s in challenge */
            uint32_t beta;   /**< Rejection bound */
            uint32_t gamma1; /**< y coefficient range */
            uint32_t gamma2; /**< Low-order rounding range */
            uint32_t omega;  /**< Max hint ones */
        } dilithium;

        /* SLH-DSA (SPHINCS+) specific parameters */
        struct
        {
            quac_sphincs_variant_t variant; /**< Small or fast variant */
            uint32_t n;                     /**< Security parameter */
            uint32_t h;                     /**< Hypertree height */
            uint32_t d;                     /**< Hypertree layers */
            uint32_t a;                     /**< FORS trees */
            uint32_t k;                     /**< FORS leaves */
            uint32_t w;                     /**< Winternitz parameter */
        } sphincs;
    } quac_sign_params_t;

    /**
     * @brief Get signature algorithm parameters
     *
     * @param[in]  algorithm    Signature algorithm
     * @param[out] params       Pointer to receive parameters
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_INVALID_ALGORITHM if not a signature algorithm
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_sign_get_params(quac_algorithm_t algorithm, quac_sign_params_t *params);

    /**
     * @brief Enumerate supported signature algorithms
     *
     * @param[in]  index        Algorithm index (0-based)
     * @param[out] algorithm    Pointer to receive algorithm
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_INVALID_PARAMETER if index out of range
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_sign_enumerate(uint32_t index, quac_algorithm_t *algorithm);

    /**
     * @brief Get number of supported signature algorithms
     *
     * @return Number of supported signature algorithms
     */
    QUAC100_API uint32_t QUAC100_CALL
    quac_sign_count(void);

/**
 * @brief Check if algorithm is ML-DSA (Dilithium)
 */
#define QUAC_IS_DILITHIUM(alg) \
    ((alg) >= QUAC_ALGORITHM_DILITHIUM2 && (alg) <= QUAC_ALGORITHM_DILITHIUM5)

/**
 * @brief Check if algorithm is SLH-DSA (SPHINCS+)
 */
#define QUAC_IS_SPHINCS(alg) \
    ((alg) >= QUAC_ALGORITHM_SPHINCS_SHA2_128S && (alg) <= QUAC_ALGORITHM_SPHINCS_SHAKE_256F)

    /*=============================================================================
     * Key Pair Structure
     *=============================================================================*/

    /**
     * @brief Signature key pair container
     */
    typedef struct quac_sign_keypair_s
    {
        uint32_t struct_size;       /**< Size of this structure */
        quac_algorithm_t algorithm; /**< Key algorithm */
        uint8_t *public_key;        /**< Public key data */
        size_t public_key_size;     /**< Public key size */
        uint8_t *secret_key;        /**< Secret key data */
        size_t secret_key_size;     /**< Secret key size */
        bool owns_memory;           /**< True if struct owns key memory */
        uint8_t fingerprint[32];    /**< Key fingerprint (SHA-256 of public key) */
    } quac_sign_keypair_t;

    /**
     * @brief Allocate a signature key pair structure
     *
     * @param[in]  algorithm    Signature algorithm
     * @param[out] keypair      Pointer to receive allocated keypair
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_OUT_OF_MEMORY on allocation failure
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_sign_keypair_alloc(quac_algorithm_t algorithm, quac_sign_keypair_t **keypair);

    /**
     * @brief Free a signature key pair structure
     *
     * Securely zeroizes key material before freeing memory.
     *
     * @param keypair   Key pair to free
     */
    QUAC100_API void QUAC100_CALL
    quac_sign_keypair_free(quac_sign_keypair_t *keypair);

    /**
     * @brief Initialize key pair with existing buffers
     *
     * @param[out] keypair      Key pair structure to initialize
     * @param[in]  algorithm    Signature algorithm
     * @param[in]  public_key   Public key buffer
     * @param[in]  pk_size      Public key size
     * @param[in]  secret_key   Secret key buffer (may be NULL for public-only)
     * @param[in]  sk_size      Secret key size
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_sign_keypair_init(quac_sign_keypair_t *keypair,
                           quac_algorithm_t algorithm,
                           uint8_t *public_key, size_t pk_size,
                           uint8_t *secret_key, size_t sk_size);

    /*=============================================================================
     * Extended Key Generation
     *=============================================================================*/

    /**
     * @brief Generate signature key pair into structure
     *
     * @param[in]  device       Device handle
     * @param[in]  algorithm    Signature algorithm
     * @param[out] keypair      Pre-allocated key pair structure
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_sign_keygen_ex(quac_device_t device,
                        quac_algorithm_t algorithm,
                        quac_sign_keypair_t *keypair);

    /**
     * @brief Generate deterministic signature key pair from seed
     *
     * Generates a key pair deterministically from a seed.
     * WARNING: Seed must be kept secret and never reused.
     *
     * @param[in]  device       Device handle
     * @param[in]  algorithm    Signature algorithm
     * @param[in]  seed         Seed value (32 bytes for Dilithium, varies for SPHINCS+)
     * @param[in]  seed_len     Seed length
     * @param[out] public_key   Buffer for public key
     * @param[in]  pk_size      Public key buffer size
     * @param[out] secret_key   Buffer for secret key
     * @param[in]  sk_size      Secret key buffer size
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_sign_keygen_deterministic(quac_device_t device,
                                   quac_algorithm_t algorithm,
                                   const uint8_t *seed, size_t seed_len,
                                   uint8_t *public_key, size_t pk_size,
                                   uint8_t *secret_key, size_t sk_size);

    /*=============================================================================
     * Extended Signing Operations
     *=============================================================================*/

    /**
     * @brief Signing options
     */
    typedef struct quac_sign_options_s
    {
        uint32_t struct_size;             /**< Size of this structure */
        const uint8_t *context;           /**< Context string (FIPS 204/205) */
        size_t context_len;               /**< Context string length (max 255) */
        bool prehashed;                   /**< Message is pre-hashed (HashML-DSA) */
        quac_algorithm_t hash_algorithm;  /**< Hash algorithm if prehashed */
        bool deterministic;               /**< Force deterministic signing */
        const uint8_t *additional_random; /**< Additional randomness (hedged signing) */
        size_t random_len;                /**< Additional randomness length */
    } quac_sign_options_t;

    /**
     * @brief Sign with options
     *
     * Extended signing function supporting context strings, pre-hashing,
     * and hedged signing modes.
     *
     * @param[in]  device       Device handle
     * @param[in]  algorithm    Signature algorithm
     * @param[in]  secret_key   Secret key
     * @param[in]  sk_size      Secret key size
     * @param[in]  message      Message to sign
     * @param[in]  msg_size     Message size
     * @param[in]  options      Signing options (NULL for defaults)
     * @param[out] signature    Buffer for signature
     * @param[in]  sig_size     Signature buffer size
     * @param[out] sig_len      Actual signature length
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_sign_ex(quac_device_t device,
                 quac_algorithm_t algorithm,
                 const uint8_t *secret_key, size_t sk_size,
                 const uint8_t *message, size_t msg_size,
                 const quac_sign_options_t *options,
                 uint8_t *signature, size_t sig_size,
                 size_t *sig_len);

    /**
     * @brief Verify with options
     *
     * Extended verification supporting context strings and pre-hashing.
     *
     * @param[in] device        Device handle
     * @param[in] algorithm     Signature algorithm
     * @param[in] public_key    Public key
     * @param[in] pk_size       Public key size
     * @param[in] message       Original message
     * @param[in] msg_size      Message size
     * @param[in] options       Verification options (NULL for defaults)
     * @param[in] signature     Signature to verify
     * @param[in] sig_size      Signature size
     *
     * @return QUAC_SUCCESS if signature is valid
     * @return QUAC_ERROR_VERIFICATION_FAILED if invalid
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_verify_ex(quac_device_t device,
                   quac_algorithm_t algorithm,
                   const uint8_t *public_key, size_t pk_size,
                   const uint8_t *message, size_t msg_size,
                   const quac_sign_options_t *options,
                   const uint8_t *signature, size_t sig_size);

    /**
     * @brief Sign a pre-hashed message (HashML-DSA / HashSLH-DSA)
     *
     * Signs a message that has already been hashed. The hash OID is included
     * in the signature for domain separation.
     *
     * @param[in]  device       Device handle
     * @param[in]  algorithm    Signature algorithm
     * @param[in]  secret_key   Secret key
     * @param[in]  sk_size      Secret key size
     * @param[in]  hash         Hash of message
     * @param[in]  hash_size    Hash size
     * @param[in]  hash_alg     Hash algorithm used (e.g., SHA-256, SHA-512, SHAKE256)
     * @param[in]  context      Context string (may be NULL)
     * @param[in]  ctx_len      Context string length
     * @param[out] signature    Buffer for signature
     * @param[in]  sig_size     Signature buffer size
     * @param[out] sig_len      Actual signature length
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_sign_prehashed(quac_device_t device,
                        quac_algorithm_t algorithm,
                        const uint8_t *secret_key, size_t sk_size,
                        const uint8_t *hash, size_t hash_size,
                        quac_algorithm_t hash_alg,
                        const uint8_t *context, size_t ctx_len,
                        uint8_t *signature, size_t sig_size,
                        size_t *sig_len);

    /**
     * @brief Verify a pre-hashed message signature
     *
     * @param[in] device        Device handle
     * @param[in] algorithm     Signature algorithm
     * @param[in] public_key    Public key
     * @param[in] pk_size       Public key size
     * @param[in] hash          Hash of original message
     * @param[in] hash_size     Hash size
     * @param[in] hash_alg      Hash algorithm used
     * @param[in] context       Context string (may be NULL)
     * @param[in] ctx_len       Context string length
     * @param[in] signature     Signature to verify
     * @param[in] sig_size      Signature size
     *
     * @return QUAC_SUCCESS if signature is valid
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_verify_prehashed(quac_device_t device,
                          quac_algorithm_t algorithm,
                          const uint8_t *public_key, size_t pk_size,
                          const uint8_t *hash, size_t hash_size,
                          quac_algorithm_t hash_alg,
                          const uint8_t *context, size_t ctx_len,
                          const uint8_t *signature, size_t sig_size);

    /*=============================================================================
     * Stored Key Operations
     *=============================================================================*/

    /**
     * @brief Generate and store signature key pair on device
     *
     * @param[in]  device       Device handle
     * @param[in]  algorithm    Signature algorithm
     * @param[in]  label        Optional key label
     * @param[in]  persistent   True to persist across reboots
     * @param[out] handle       Handle to stored key
     * @param[out] public_key   Buffer for public key (may be NULL)
     * @param[in]  pk_size      Public key buffer size
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_sign_keygen_stored(quac_device_t device,
                            quac_algorithm_t algorithm,
                            const char *label,
                            bool persistent,
                            quac_key_handle_t *handle,
                            uint8_t *public_key, size_t pk_size);

    /**
     * @brief Sign using stored secret key
     *
     * The secret key never leaves the hardware security boundary.
     *
     * @param[in]  device       Device handle
     * @param[in]  key_handle   Handle to stored key
     * @param[in]  message      Message to sign
     * @param[in]  msg_size     Message size
     * @param[in]  options      Signing options (may be NULL)
     * @param[out] signature    Buffer for signature
     * @param[in]  sig_size     Signature buffer size
     * @param[out] sig_len      Actual signature length
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_sign_stored(quac_device_t device,
                     quac_key_handle_t key_handle,
                     const uint8_t *message, size_t msg_size,
                     const quac_sign_options_t *options,
                     uint8_t *signature, size_t sig_size,
                     size_t *sig_len);

    /**
     * @brief Verify using stored public key
     *
     * @param[in] device        Device handle
     * @param[in] key_handle    Handle to stored key
     * @param[in] message       Original message
     * @param[in] msg_size      Message size
     * @param[in] options       Verification options (may be NULL)
     * @param[in] signature     Signature to verify
     * @param[in] sig_size      Signature size
     *
     * @return QUAC_SUCCESS if signature is valid
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_verify_stored(quac_device_t device,
                       quac_key_handle_t key_handle,
                       const uint8_t *message, size_t msg_size,
                       const quac_sign_options_t *options,
                       const uint8_t *signature, size_t sig_size);

    /*=============================================================================
     * Batch Signature Operations
     *=============================================================================*/

    /**
     * @brief Signature operation type for batch processing
     */
    typedef enum quac_sign_op_e
    {
        QUAC_SIGN_OP_KEYGEN = 0, /**< Key generation */
        QUAC_SIGN_OP_SIGN = 1,   /**< Signing */
        QUAC_SIGN_OP_VERIFY = 2, /**< Verification */
    } quac_sign_op_t;

    /**
     * @brief Batch signature operation item
     */
    typedef struct quac_sign_batch_item_s
    {
        quac_sign_op_t operation;   /**< Operation type */
        quac_algorithm_t algorithm; /**< Algorithm */

        /* Input data */
        const uint8_t *public_key;          /**< Public key (verify) */
        size_t pk_size;                     /**< Public key size */
        const uint8_t *secret_key;          /**< Secret key (sign) */
        size_t sk_size;                     /**< Secret key size */
        const uint8_t *message;             /**< Message */
        size_t msg_size;                    /**< Message size */
        const uint8_t *signature_in;        /**< Signature input (verify) */
        size_t sig_in_size;                 /**< Signature input size */
        const quac_sign_options_t *options; /**< Signing/verify options */

        /* Output data */
        uint8_t *public_key_out; /**< Public key output (keygen) */
        size_t pk_out_size;      /**< Public key output buffer size */
        uint8_t *secret_key_out; /**< Secret key output (keygen) */
        size_t sk_out_size;      /**< Secret key output buffer size */
        uint8_t *signature_out;  /**< Signature output (sign) */
        size_t sig_out_size;     /**< Signature output buffer size */
        size_t sig_actual_len;   /**< Actual signature length */

        /* Result */
        quac_result_t result; /**< Operation result */
        void *user_data;      /**< User context */
    } quac_sign_batch_item_t;

    /**
     * @brief Execute batch signature operations
     *
     * @param[in]     device    Device handle
     * @param[in,out] items     Array of batch items
     * @param[in]     count     Number of items
     *
     * @return QUAC_SUCCESS if all operations succeeded
     * @return QUAC_ERROR_BATCH_PARTIAL if some operations failed
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_sign_batch(quac_device_t device, quac_sign_batch_item_t *items, size_t count);

    /**
     * @brief Batch signature verification
     *
     * Verify multiple signatures in a single call. Optimized for bulk verification.
     *
     * @param[in]  device       Device handle
     * @param[in]  algorithm    Signature algorithm (same for all)
     * @param[in]  public_key   Public key (same for all signatures)
     * @param[in]  pk_size      Public key size
     * @param[in]  messages     Array of message pointers
     * @param[in]  msg_sizes    Array of message sizes
     * @param[in]  signatures   Array of signature pointers
     * @param[in]  sig_sizes    Array of signature sizes
     * @param[out] results      Array to receive individual results
     * @param[in]  count        Number of signatures to verify
     *
     * @return QUAC_SUCCESS if all signatures valid
     * @return QUAC_ERROR_BATCH_PARTIAL if some verifications failed
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_verify_batch(quac_device_t device,
                      quac_algorithm_t algorithm,
                      const uint8_t *public_key, size_t pk_size,
                      const uint8_t **messages, const size_t *msg_sizes,
                      const uint8_t **signatures, const size_t *sig_sizes,
                      quac_result_t *results,
                      size_t count);

    /*=============================================================================
     * Async Signature Operations
     *=============================================================================*/

    /**
     * @brief Submit async key generation
     *
     * @param[in]  device       Device handle
     * @param[in]  algorithm    Signature algorithm
     * @param[out] public_key   Buffer for public key
     * @param[in]  pk_size      Public key buffer size
     * @param[out] secret_key   Buffer for secret key
     * @param[in]  sk_size      Secret key buffer size
     * @param[in]  callback     Completion callback
     * @param[in]  user_data    User context
     * @param[out] job_id       Job identifier
     *
     * @return QUAC_SUCCESS on successful submission
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_sign_async_keygen(quac_device_t device,
                           quac_algorithm_t algorithm,
                           uint8_t *public_key, size_t pk_size,
                           uint8_t *secret_key, size_t sk_size,
                           quac_async_callback_t callback,
                           void *user_data,
                           quac_job_id_t *job_id);

    /**
     * @brief Submit async signing
     *
     * @param[in]  device       Device handle
     * @param[in]  algorithm    Signature algorithm
     * @param[in]  secret_key   Secret key
     * @param[in]  sk_size      Secret key size
     * @param[in]  message      Message to sign
     * @param[in]  msg_size     Message size
     * @param[in]  options      Signing options
     * @param[out] signature    Buffer for signature
     * @param[in]  sig_size     Signature buffer size
     * @param[out] sig_len      Pointer to receive actual signature length
     * @param[in]  callback     Completion callback
     * @param[in]  user_data    User context
     * @param[out] job_id       Job identifier
     *
     * @return QUAC_SUCCESS on successful submission
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_sign_async(quac_device_t device,
                    quac_algorithm_t algorithm,
                    const uint8_t *secret_key, size_t sk_size,
                    const uint8_t *message, size_t msg_size,
                    const quac_sign_options_t *options,
                    uint8_t *signature, size_t sig_size,
                    size_t *sig_len,
                    quac_async_callback_t callback,
                    void *user_data,
                    quac_job_id_t *job_id);

    /**
     * @brief Submit async verification
     *
     * @param[in]  device       Device handle
     * @param[in]  algorithm    Signature algorithm
     * @param[in]  public_key   Public key
     * @param[in]  pk_size      Public key size
     * @param[in]  message      Original message
     * @param[in]  msg_size     Message size
     * @param[in]  options      Verification options
     * @param[in]  signature    Signature to verify
     * @param[in]  sig_size     Signature size
     * @param[in]  callback     Completion callback
     * @param[in]  user_data    User context
     * @param[out] job_id       Job identifier
     *
     * @return QUAC_SUCCESS on successful submission
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_verify_async(quac_device_t device,
                      quac_algorithm_t algorithm,
                      const uint8_t *public_key, size_t pk_size,
                      const uint8_t *message, size_t msg_size,
                      const quac_sign_options_t *options,
                      const uint8_t *signature, size_t sig_size,
                      quac_async_callback_t callback,
                      void *user_data,
                      quac_job_id_t *job_id);

    /*=============================================================================
     * Key Validation
     *=============================================================================*/

    /**
     * @brief Validate public key format
     *
     * @param[in] algorithm     Signature algorithm
     * @param[in] public_key    Public key to validate
     * @param[in] pk_size       Public key size
     *
     * @return QUAC_SUCCESS if valid
     * @return QUAC_ERROR_INVALID_KEY if malformed
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_sign_validate_public_key(quac_algorithm_t algorithm,
                                  const uint8_t *public_key, size_t pk_size);

    /**
     * @brief Validate secret key format
     *
     * @param[in] algorithm     Signature algorithm
     * @param[in] secret_key    Secret key to validate
     * @param[in] sk_size       Secret key size
     *
     * @return QUAC_SUCCESS if valid
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_sign_validate_secret_key(quac_algorithm_t algorithm,
                                  const uint8_t *secret_key, size_t sk_size);

    /**
     * @brief Validate signature format
     *
     * Checks structural validity without verification.
     *
     * @param[in] algorithm     Signature algorithm
     * @param[in] signature     Signature to validate
     * @param[in] sig_size      Signature size
     *
     * @return QUAC_SUCCESS if structurally valid
     * @return QUAC_ERROR_INVALID_SIGNATURE if malformed
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_sign_validate_signature(quac_algorithm_t algorithm,
                                 const uint8_t *signature, size_t sig_size);

    /**
     * @brief Check if public and secret keys match
     *
     * @param[in] algorithm     Signature algorithm
     * @param[in] public_key    Public key
     * @param[in] pk_size       Public key size
     * @param[in] secret_key    Secret key
     * @param[in] sk_size       Secret key size
     *
     * @return QUAC_SUCCESS if keys match
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_sign_check_keypair(quac_algorithm_t algorithm,
                            const uint8_t *public_key, size_t pk_size,
                            const uint8_t *secret_key, size_t sk_size);

    /*=============================================================================
     * Performance Statistics
     *=============================================================================*/

    /**
     * @brief Signature performance statistics
     */
    typedef struct quac_sign_stats_s
    {
        uint32_t struct_size;     /**< Size of this structure */
        uint64_t keygen_count;    /**< Key generations performed */
        uint64_t sign_count;      /**< Signatures generated */
        uint64_t verify_count;    /**< Verifications performed */
        uint64_t keygen_failures; /**< Key generation failures */
        uint64_t sign_failures;   /**< Signing failures */
        uint64_t verify_failures; /**< Verification failures (invalid sigs) */
        uint64_t keygen_total_ns; /**< Total keygen time (ns) */
        uint64_t sign_total_ns;   /**< Total sign time (ns) */
        uint64_t verify_total_ns; /**< Total verify time (ns) */
        uint32_t keygen_avg_us;   /**< Average keygen time (μs) */
        uint32_t sign_avg_us;     /**< Average sign time (μs) */
        uint32_t verify_avg_us;   /**< Average verify time (μs) */
        uint32_t keygen_min_us;   /**< Minimum keygen time (μs) */
        uint32_t sign_min_us;     /**< Minimum sign time (μs) */
        uint32_t verify_min_us;   /**< Minimum verify time (μs) */
        uint32_t keygen_max_us;   /**< Maximum keygen time (μs) */
        uint32_t sign_max_us;     /**< Maximum sign time (μs) */
        uint32_t verify_max_us;   /**< Maximum verify time (μs) */
    } quac_sign_stats_t;

    /**
     * @brief Get signature performance statistics
     *
     * @param[in]  device       Device handle
     * @param[in]  algorithm    Algorithm (or QUAC_ALGORITHM_NONE for all)
     * @param[out] stats        Pointer to receive statistics
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_sign_get_stats(quac_device_t device,
                        quac_algorithm_t algorithm,
                        quac_sign_stats_t *stats);

    /**
     * @brief Reset signature performance statistics
     *
     * @param[in] device        Device handle
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_sign_reset_stats(quac_device_t device);

#ifdef __cplusplus
}
#endif

#endif /* QUAC100_SIGN_H */
