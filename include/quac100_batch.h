/**
 * @file quac100_batch.h
 * @brief QuantaCore SDK - Batch Operations
 *
 * High-throughput batch processing interface for executing multiple
 * cryptographic operations in a single call. Batch operations maximize
 * hardware utilization by processing operations in parallel across
 * multiple cryptographic engines.
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 * @doc QUAC100-SDK-DEV-001
 *
 * @par Performance Characteristics
 * The QUAC 100 achieves maximum throughput when processing batches of
 * operations. Single operations incur per-call overhead; batching amortizes
 * this overhead across many operations.
 *
 * | Batch Size | Relative Throughput |
 * |------------|---------------------|
 * | 1          | 1.0x (baseline)     |
 * | 16         | 8-10x               |
 * | 64         | 12-15x              |
 * | 256        | 15-18x              |
 * | 1024       | 18-20x              |
 *
 * @par Usage Patterns
 * - TLS handshake offload: batch key exchanges for multiple connections
 * - Certificate verification: batch signature verifications
 * - Key generation: pre-generate key pools
 * - Session ticket encryption: batch encrypt/decrypt operations
 */

#ifndef QUAC100_BATCH_H
#define QUAC100_BATCH_H

#include "quac100_types.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*=============================================================================
 * Batch Constants
 *=============================================================================*/

/** Maximum items per batch */
#define QUAC_BATCH_MAX_ITEMS 1024

/** Recommended batch size for optimal throughput */
#define QUAC_BATCH_OPTIMAL_SIZE 256

/** Minimum batch size to benefit from batching */
#define QUAC_BATCH_MIN_EFFECTIVE 8

    /*=============================================================================
     * Batch Operation Types
     *=============================================================================*/

    /**
     * @brief Batch operation type
     */
    typedef enum quac_batch_op_e
    {
        /* KEM Operations */
        QUAC_BATCH_OP_KEM_KEYGEN = 0x0100, /**< KEM key generation */
        QUAC_BATCH_OP_KEM_ENCAPS = 0x0101, /**< KEM encapsulation */
        QUAC_BATCH_OP_KEM_DECAPS = 0x0102, /**< KEM decapsulation */

        /* Signature Operations */
        QUAC_BATCH_OP_SIGN_KEYGEN = 0x0200, /**< Signature key generation */
        QUAC_BATCH_OP_SIGN = 0x0201,        /**< Signing */
        QUAC_BATCH_OP_VERIFY = 0x0202,      /**< Verification */

        /* Random Operations */
        QUAC_BATCH_OP_RANDOM = 0x0300, /**< Random generation */

        /* Mixed (heterogeneous batch) */
        QUAC_BATCH_OP_MIXED = 0x1000, /**< Mixed operation types */
    } quac_batch_op_t;

    /*=============================================================================
     * Batch Item Structures
     *=============================================================================*/

    /**
     * @brief Generic batch item
     *
     * Base structure for all batch operations. Cast to specific types
     * for type-safe access.
     */
    typedef enum quac_batch_item_flags_e
    {
        QUAC_BATCH_ITEM_FLAG_NONE = 0x0000,
        QUAC_BATCH_ITEM_FLAG_SKIP = 0x0001,      /**< Skip this item */
        QUAC_BATCH_ITEM_FLAG_CRITICAL = 0x0002,  /**< Abort batch on failure */
        QUAC_BATCH_ITEM_FLAG_COMPLETED = 0x0100, /**< (Output) Item completed */
        QUAC_BATCH_ITEM_FLAG_FAILED = 0x0200,    /**< (Output) Item failed */
    } quac_batch_item_flags_t;

    /**
     * @brief KEM keygen batch item
     */
    typedef struct quac_batch_kem_keygen_s
    {
        quac_batch_op_t operation;  /**< Must be QUAC_BATCH_OP_KEM_KEYGEN */
        quac_algorithm_t algorithm; /**< KEM algorithm */
        quac_result_t result;       /**< Result code */
        void *user_data;            /**< User context */
        uint32_t flags;             /**< Item flags */
        uint8_t reserved[12];       /**< Reserved */

        /* Output */
        uint8_t *public_key; /**< Public key buffer */
        size_t pk_size;      /**< Public key buffer size */
        uint8_t *secret_key; /**< Secret key buffer */
        size_t sk_size;      /**< Secret key buffer size */
    } quac_batch_kem_keygen_t;

    /**
     * @brief KEM encapsulation batch item
     */
    typedef struct quac_batch_kem_encaps_s
    {
        quac_batch_op_t operation;  /**< Must be QUAC_BATCH_OP_KEM_ENCAPS */
        quac_algorithm_t algorithm; /**< KEM algorithm */
        quac_result_t result;       /**< Result code */
        void *user_data;            /**< User context */
        uint32_t flags;             /**< Item flags */
        uint8_t reserved[12];       /**< Reserved */

        /* Input */
        const uint8_t *public_key; /**< Public key */
        size_t pk_size;            /**< Public key size */

        /* Output */
        uint8_t *ciphertext;    /**< Ciphertext buffer */
        size_t ct_size;         /**< Ciphertext buffer size */
        uint8_t *shared_secret; /**< Shared secret buffer */
        size_t ss_size;         /**< Shared secret buffer size */
    } quac_batch_kem_encaps_t;

    /**
     * @brief KEM decapsulation batch item
     */
    typedef struct quac_batch_kem_decaps_s
    {
        quac_batch_op_t operation;  /**< Must be QUAC_BATCH_OP_KEM_DECAPS */
        quac_algorithm_t algorithm; /**< KEM algorithm */
        quac_result_t result;       /**< Result code */
        void *user_data;            /**< User context */
        uint32_t flags;             /**< Item flags */
        uint8_t reserved[12];       /**< Reserved */

        /* Input */
        const uint8_t *ciphertext; /**< Ciphertext */
        size_t ct_size;            /**< Ciphertext size */
        const uint8_t *secret_key; /**< Secret key */
        size_t sk_size;            /**< Secret key size */

        /* Output */
        uint8_t *shared_secret; /**< Shared secret buffer */
        size_t ss_size;         /**< Shared secret buffer size */
    } quac_batch_kem_decaps_t;

    /**
     * @brief Signature keygen batch item
     */
    typedef struct quac_batch_sign_keygen_s
    {
        quac_batch_op_t operation;  /**< Must be QUAC_BATCH_OP_SIGN_KEYGEN */
        quac_algorithm_t algorithm; /**< Signature algorithm */
        quac_result_t result;       /**< Result code */
        void *user_data;            /**< User context */
        uint32_t flags;             /**< Item flags */
        uint8_t reserved[12];       /**< Reserved */

        /* Output */
        uint8_t *public_key; /**< Public key buffer */
        size_t pk_size;      /**< Public key buffer size */
        uint8_t *secret_key; /**< Secret key buffer */
        size_t sk_size;      /**< Secret key buffer size */
    } quac_batch_sign_keygen_t;

    /**
     * @brief Signing batch item
     */
    typedef struct quac_batch_sign_s
    {
        quac_batch_op_t operation;  /**< Must be QUAC_BATCH_OP_SIGN */
        quac_algorithm_t algorithm; /**< Signature algorithm */
        quac_result_t result;       /**< Result code */
        void *user_data;            /**< User context */
        uint32_t flags;             /**< Item flags */
        uint8_t reserved[12];       /**< Reserved */

        /* Input */
        const uint8_t *secret_key; /**< Secret key */
        size_t sk_size;            /**< Secret key size */
        const uint8_t *message;    /**< Message to sign */
        size_t msg_size;           /**< Message size */

        /* Output */
        uint8_t *signature; /**< Signature buffer */
        size_t sig_size;    /**< Signature buffer size */
        size_t sig_actual;  /**< Actual signature length */
    } quac_batch_sign_t;

    /**
     * @brief Verification batch item
     */
    typedef struct quac_batch_verify_s
    {
        quac_batch_op_t operation;  /**< Must be QUAC_BATCH_OP_VERIFY */
        quac_algorithm_t algorithm; /**< Signature algorithm */
        quac_result_t result;       /**< Result code */
        void *user_data;            /**< User context */
        uint32_t flags;             /**< Item flags */
        uint8_t reserved[12];       /**< Reserved */

        /* Input */
        const uint8_t *public_key; /**< Public key */
        size_t pk_size;            /**< Public key size */
        const uint8_t *message;    /**< Original message */
        size_t msg_size;           /**< Message size */
        const uint8_t *signature;  /**< Signature to verify */
        size_t sig_size;           /**< Signature size */

        /* Output */
        bool valid; /**< true if signature valid */
    } quac_batch_verify_t;

    /**
     * @brief Random generation batch item
     */
    typedef struct quac_batch_random_s
    {
        quac_batch_op_t operation;  /**< Must be QUAC_BATCH_OP_RANDOM */
        quac_algorithm_t algorithm; /**< QUAC_ALGORITHM_NONE */
        quac_result_t result;       /**< Result code */
        void *user_data;            /**< User context */
        uint32_t flags;             /**< Item flags */
        uint8_t reserved[12];       /**< Reserved */

        /* Output */
        uint8_t *buffer; /**< Random data buffer */
        size_t length;   /**< Number of bytes to generate */
    } quac_batch_random_t;

    /*=============================================================================
     * Batch Execution Options
     *=============================================================================*/

    /**
     * @brief Batch execution options
     */
    typedef struct quac_batch_options_s
    {
        uint32_t struct_size;           /**< Size of this structure */
        uint32_t flags;                 /**< Execution flags */
        uint32_t timeout_ms;            /**< Execution timeout (0 = none) */
        uint32_t max_parallel;          /**< Max parallel operations (0 = auto) */
        quac_async_callback_t callback; /**< Completion callback */
        void *callback_data;            /**< Callback context */
    } quac_batch_options_t;

    /**
     * @brief Batch execution flags
     */
    typedef enum quac_batch_flags_e
    {
        QUAC_BATCH_FLAG_NONE = 0x0000,
        QUAC_BATCH_FLAG_STOP_ON_ERROR = 0x0001, /**< Stop at first error */
        QUAC_BATCH_FLAG_ORDERED = 0x0002,       /**< Execute in order */
        QUAC_BATCH_FLAG_ASYNC = 0x0004,         /**< Return immediately */
        QUAC_BATCH_FLAG_NO_VALIDATE = 0x0008,   /**< Skip input validation */
        QUAC_BATCH_FLAG_HIGH_PRIORITY = 0x0010, /**< High priority processing */
    } quac_batch_flags_t;

    /*=============================================================================
     * Batch Results
     *=============================================================================*/

    /**
     * @brief Batch execution results
     */
    typedef struct quac_batch_result_s
    {
        uint32_t struct_size;         /**< Size of this structure */
        uint32_t total_items;         /**< Total items in batch */
        uint32_t completed;           /**< Successfully completed */
        uint32_t failed;              /**< Failed items */
        uint32_t skipped;             /**< Skipped items */
        quac_result_t overall_result; /**< Overall batch result */
        uint64_t total_time_us;       /**< Total execution time (μs) */
        uint64_t queue_time_us;       /**< Time in queue (μs) */
        uint64_t exec_time_us;        /**< Actual execution time (μs) */
        uint32_t throughput_ops;      /**< Operations per second */
        quac_job_id_t job_id;         /**< Job ID if async */
    } quac_batch_result_t;

    /*=============================================================================
     * Batch Execution - Generic
     *=============================================================================*/

    /**
     * @brief Execute a batch of operations
     *
     * Processes multiple cryptographic operations in a single call.
     * Operations may execute in parallel for maximum throughput.
     *
     * @param[in]     device    Device handle
     * @param[in,out] items     Array of batch items (results written back)
     * @param[in]     count     Number of items
     * @param[in]     options   Execution options (NULL for defaults)
     * @param[out]    result    Batch result summary (may be NULL)
     *
     * @return QUAC_SUCCESS if all operations succeeded
     * @return QUAC_ERROR_BATCH_PARTIAL if some operations failed
     *
     * @par Example
     * @code
     * quac_batch_kem_keygen_t items[100];
     *
     * // Setup items
     * for (int i = 0; i < 100; i++) {
     *     items[i].operation = QUAC_BATCH_OP_KEM_KEYGEN;
     *     items[i].algorithm = QUAC_ALGORITHM_KYBER768;
     *     items[i].public_key = pk_buffers[i];
     *     items[i].pk_size = sizeof(pk_buffers[i]);
     *     items[i].secret_key = sk_buffers[i];
     *     items[i].sk_size = sizeof(sk_buffers[i]);
     * }
     *
     * // Execute batch
     * result = quac_batch_execute(device, (quac_batch_item_t*)items, 100, NULL, NULL);
     *
     * // Check individual results
     * for (int i = 0; i < 100; i++) {
     *     if (QUAC_FAILED(items[i].result)) {
     *         // Handle failure
     *     }
     * }
     * @endcode
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_batch_execute(quac_device_t device,
                       quac_batch_item_t *items, size_t count,
                       const quac_batch_options_t *options,
                       quac_batch_result_t *result);

    /**
     * @brief Execute async batch
     *
     * Submits batch for async execution. Returns immediately.
     *
     * @param[in]     device    Device handle
     * @param[in,out] items     Array of batch items
     * @param[in]     count     Number of items
     * @param[in]     options   Execution options (callback recommended)
     * @param[out]    job_id    Job identifier for tracking
     *
     * @return QUAC_SUCCESS on successful submission
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_batch_execute_async(quac_device_t device,
                             quac_batch_item_t *items, size_t count,
                             const quac_batch_options_t *options,
                             quac_job_id_t *job_id);

    /**
     * @brief Wait for async batch completion
     *
     * @param[in]  device       Device handle
     * @param[in]  job_id       Batch job identifier
     * @param[in]  timeout_ms   Timeout in milliseconds
     * @param[out] result       Batch result summary (may be NULL)
     *
     * @return QUAC_SUCCESS on completion
     * @return QUAC_ERROR_TIMEOUT if timeout elapsed
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_batch_wait(quac_device_t device,
                    quac_job_id_t job_id,
                    uint32_t timeout_ms,
                    quac_batch_result_t *result);

    /*=============================================================================
     * Homogeneous Batch Operations
     *=============================================================================*/

    /**
     * @brief Batch KEM key generation
     *
     * Generate multiple key pairs of the same algorithm.
     *
     * @param[in]  device       Device handle
     * @param[in]  algorithm    KEM algorithm (same for all)
     * @param[out] public_keys  Array of public key buffers
     * @param[in]  pk_size      Size of each public key buffer
     * @param[out] secret_keys  Array of secret key buffers
     * @param[in]  sk_size      Size of each secret key buffer
     * @param[out] results      Array for individual results (may be NULL)
     * @param[in]  count        Number of key pairs to generate
     *
     * @return QUAC_SUCCESS if all succeeded
     * @return QUAC_ERROR_BATCH_PARTIAL if some failed
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_batch_kem_keygen(quac_device_t device,
                          quac_algorithm_t algorithm,
                          uint8_t **public_keys, size_t pk_size,
                          uint8_t **secret_keys, size_t sk_size,
                          quac_result_t *results,
                          size_t count);

    /**
     * @brief Batch KEM encapsulation
     *
     * Encapsulate to multiple public keys.
     *
     * @param[in]  device       Device handle
     * @param[in]  algorithm    KEM algorithm
     * @param[in]  public_keys  Array of public key pointers
     * @param[in]  pk_size      Size of each public key
     * @param[out] ciphertexts  Array of ciphertext buffers
     * @param[in]  ct_size      Size of each ciphertext buffer
     * @param[out] secrets      Array of shared secret buffers
     * @param[in]  ss_size      Size of each shared secret buffer
     * @param[out] results      Array for individual results
     * @param[in]  count        Number of encapsulations
     *
     * @return QUAC_SUCCESS if all succeeded
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_batch_kem_encaps(quac_device_t device,
                          quac_algorithm_t algorithm,
                          const uint8_t **public_keys, size_t pk_size,
                          uint8_t **ciphertexts, size_t ct_size,
                          uint8_t **secrets, size_t ss_size,
                          quac_result_t *results,
                          size_t count);

    /**
     * @brief Batch KEM decapsulation
     *
     * Decapsulate multiple ciphertexts with the same secret key.
     *
     * @param[in]  device       Device handle
     * @param[in]  algorithm    KEM algorithm
     * @param[in]  ciphertexts  Array of ciphertext pointers
     * @param[in]  ct_size      Size of each ciphertext
     * @param[in]  secret_key   Secret key (same for all)
     * @param[in]  sk_size      Secret key size
     * @param[out] secrets      Array of shared secret buffers
     * @param[in]  ss_size      Size of each shared secret buffer
     * @param[out] results      Array for individual results
     * @param[in]  count        Number of decapsulations
     *
     * @return QUAC_SUCCESS if all succeeded
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_batch_kem_decaps(quac_device_t device,
                          quac_algorithm_t algorithm,
                          const uint8_t **ciphertexts, size_t ct_size,
                          const uint8_t *secret_key, size_t sk_size,
                          uint8_t **secrets, size_t ss_size,
                          quac_result_t *results,
                          size_t count);

    /**
     * @brief Batch signature generation
     *
     * Sign multiple messages with the same secret key.
     *
     * @param[in]  device       Device handle
     * @param[in]  algorithm    Signature algorithm
     * @param[in]  secret_key   Secret key (same for all)
     * @param[in]  sk_size      Secret key size
     * @param[in]  messages     Array of message pointers
     * @param[in]  msg_sizes    Array of message sizes
     * @param[out] signatures   Array of signature buffers
     * @param[in]  sig_size     Size of each signature buffer
     * @param[out] sig_lens     Array to receive actual signature lengths
     * @param[out] results      Array for individual results
     * @param[in]  count        Number of signatures
     *
     * @return QUAC_SUCCESS if all succeeded
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_batch_sign(quac_device_t device,
                    quac_algorithm_t algorithm,
                    const uint8_t *secret_key, size_t sk_size,
                    const uint8_t **messages, const size_t *msg_sizes,
                    uint8_t **signatures, size_t sig_size,
                    size_t *sig_lens,
                    quac_result_t *results,
                    size_t count);

    /**
     * @brief Batch signature verification
     *
     * Verify multiple signatures with the same public key.
     *
     * @param[in]  device       Device handle
     * @param[in]  algorithm    Signature algorithm
     * @param[in]  public_key   Public key (same for all)
     * @param[in]  pk_size      Public key size
     * @param[in]  messages     Array of message pointers
     * @param[in]  msg_sizes    Array of message sizes
     * @param[in]  signatures   Array of signature pointers
     * @param[in]  sig_sizes    Array of signature sizes
     * @param[out] results      Array for individual results
     * @param[in]  count        Number of verifications
     *
     * @return QUAC_SUCCESS if all valid
     * @return QUAC_ERROR_BATCH_PARTIAL if some invalid
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_batch_verify(quac_device_t device,
                      quac_algorithm_t algorithm,
                      const uint8_t *public_key, size_t pk_size,
                      const uint8_t **messages, const size_t *msg_sizes,
                      const uint8_t **signatures, const size_t *sig_sizes,
                      quac_result_t *results,
                      size_t count);

    /*=============================================================================
     * Batch Builder API
     *=============================================================================*/

    /**
     * @brief Opaque batch builder handle
     */
    typedef struct quac_batch_builder_s *quac_batch_builder_t;

    /**
     * @brief Create a batch builder
     *
     * Batch builder provides a convenient way to construct heterogeneous
     * batches with mixed operation types.
     *
     * @param[in]  device       Device handle
     * @param[in]  initial_capacity Initial item capacity (0 = default)
     * @param[out] builder      Pointer to receive builder handle
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_batch_builder_create(quac_device_t device,
                              size_t initial_capacity,
                              quac_batch_builder_t *builder);

    /**
     * @brief Destroy a batch builder
     *
     * @param builder   Builder handle
     */
    QUAC100_API void QUAC100_CALL
    quac_batch_builder_destroy(quac_batch_builder_t builder);

    /**
     * @brief Reset batch builder for reuse
     *
     * @param builder   Builder handle
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_batch_builder_reset(quac_batch_builder_t builder);

    /**
     * @brief Add KEM keygen to batch
     *
     * @param[in]  builder      Builder handle
     * @param[in]  algorithm    KEM algorithm
     * @param[out] public_key   Public key buffer
     * @param[in]  pk_size      Public key buffer size
     * @param[out] secret_key   Secret key buffer
     * @param[in]  sk_size      Secret key buffer size
     * @param[in]  user_data    User context
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_batch_builder_add_kem_keygen(quac_batch_builder_t builder,
                                      quac_algorithm_t algorithm,
                                      uint8_t *public_key, size_t pk_size,
                                      uint8_t *secret_key, size_t sk_size,
                                      void *user_data);

    /**
     * @brief Add KEM encaps to batch
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_batch_builder_add_kem_encaps(quac_batch_builder_t builder,
                                      quac_algorithm_t algorithm,
                                      const uint8_t *public_key, size_t pk_size,
                                      uint8_t *ciphertext, size_t ct_size,
                                      uint8_t *shared_secret, size_t ss_size,
                                      void *user_data);

    /**
     * @brief Add KEM decaps to batch
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_batch_builder_add_kem_decaps(quac_batch_builder_t builder,
                                      quac_algorithm_t algorithm,
                                      const uint8_t *ciphertext, size_t ct_size,
                                      const uint8_t *secret_key, size_t sk_size,
                                      uint8_t *shared_secret, size_t ss_size,
                                      void *user_data);

    /**
     * @brief Add signing to batch
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_batch_builder_add_sign(quac_batch_builder_t builder,
                                quac_algorithm_t algorithm,
                                const uint8_t *secret_key, size_t sk_size,
                                const uint8_t *message, size_t msg_size,
                                uint8_t *signature, size_t sig_size,
                                size_t *sig_len,
                                void *user_data);

    /**
     * @brief Add verification to batch
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_batch_builder_add_verify(quac_batch_builder_t builder,
                                  quac_algorithm_t algorithm,
                                  const uint8_t *public_key, size_t pk_size,
                                  const uint8_t *message, size_t msg_size,
                                  const uint8_t *signature, size_t sig_size,
                                  void *user_data);

    /**
     * @brief Add random generation to batch
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_batch_builder_add_random(quac_batch_builder_t builder,
                                  uint8_t *buffer, size_t length,
                                  void *user_data);

    /**
     * @brief Get current batch size
     *
     * @param[in]  builder      Builder handle
     * @param[out] count        Number of items in batch
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_batch_builder_count(quac_batch_builder_t builder, size_t *count);

    /**
     * @brief Execute the batch
     *
     * @param[in]  builder      Builder handle
     * @param[in]  options      Execution options
     * @param[out] result       Batch result summary
     *
     * @return QUAC_SUCCESS if all operations succeeded
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_batch_builder_execute(quac_batch_builder_t builder,
                               const quac_batch_options_t *options,
                               quac_batch_result_t *result);

    /**
     * @brief Iterate batch results
     *
     * @param[in] builder       Builder handle
     * @param[in] index         Item index
     * @param[out] result       Item result code
     * @param[out] user_data    Item user data
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_INVALID_PARAMETER if index out of range
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_batch_builder_get_result(quac_batch_builder_t builder,
                                  size_t index,
                                  quac_result_t *result,
                                  void **user_data);

    /*=============================================================================
     * Statistics
     *=============================================================================*/

    /**
     * @brief Batch performance statistics
     */
    typedef struct quac_batch_stats_s
    {
        uint32_t struct_size;      /**< Size of this structure */
        uint64_t batches_executed; /**< Total batches executed */
        uint64_t items_total;      /**< Total items processed */
        uint64_t items_success;    /**< Successful items */
        uint64_t items_failed;     /**< Failed items */
        uint64_t total_time_ns;    /**< Total execution time (ns) */
        uint32_t avg_batch_size;   /**< Average batch size */
        uint32_t max_batch_size;   /**< Maximum batch size */
        uint32_t avg_throughput;   /**< Average ops/second */
        uint32_t peak_throughput;  /**< Peak ops/second */
        uint32_t avg_latency_us;   /**< Average per-item latency (μs) */
    } quac_batch_stats_t;

    /**
     * @brief Get batch statistics
     *
     * @param[in]  device       Device handle
     * @param[out] stats        Pointer to receive statistics
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_batch_get_stats(quac_device_t device, quac_batch_stats_t *stats);

    /**
     * @brief Reset batch statistics
     *
     * @param[in] device        Device handle
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_batch_reset_stats(quac_device_t device);

#ifdef __cplusplus
}
#endif

#endif /* QUAC100_BATCH_H */
