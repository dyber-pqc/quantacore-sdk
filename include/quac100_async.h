/**
 * @file quac100_async.h
 * @brief QuantaCore SDK - Asynchronous Operations
 *
 * Asynchronous operation interface for non-blocking cryptographic operations.
 * Enables high-throughput processing by allowing multiple operations to be
 * queued and processed concurrently.
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 * @doc QUAC100-SDK-DEV-001
 *
 * @par Threading Model
 * The async interface is thread-safe. Multiple threads may submit jobs
 * concurrently. Callbacks are invoked from a dedicated completion thread
 * pool managed by the SDK.
 *
 * @par Job Lifecycle
 * 1. Submit job via quac_async_*() function → returns job_id
 * 2. Job enters PENDING state in queue
 * 3. Job transitions to RUNNING when hardware begins processing
 * 4. Job completes → COMPLETED or FAILED state
 * 5. Callback invoked (if provided)
 * 6. Application retrieves results or calls quac_async_wait()
 * 7. Job resources released after result retrieval or explicit release
 */

#ifndef QUAC100_ASYNC_H
#define QUAC100_ASYNC_H

#include "quac100_types.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*=============================================================================
 * Async Constants
 *=============================================================================*/

/** Maximum pending jobs per device */
#define QUAC_ASYNC_MAX_PENDING 4096

/** Default async thread pool size (0 = auto-detect based on CPU cores) */
#define QUAC_ASYNC_DEFAULT_THREADS 0

/** Infinite timeout for wait operations */
#define QUAC_ASYNC_WAIT_INFINITE 0xFFFFFFFF

/** Poll timeout (return immediately) */
#define QUAC_ASYNC_NO_WAIT 0

    /*=============================================================================
     * Job Status and Information
     *=============================================================================*/

    /**
     * @brief Async job status
     */
    typedef enum quac_job_status_e
    {
        QUAC_JOB_STATUS_PENDING = 0,   /**< Job is queued, waiting to execute */
        QUAC_JOB_STATUS_RUNNING = 1,   /**< Job is currently executing */
        QUAC_JOB_STATUS_COMPLETED = 2, /**< Job completed successfully */
        QUAC_JOB_STATUS_FAILED = 3,    /**< Job failed with error */
        QUAC_JOB_STATUS_CANCELLED = 4, /**< Job was cancelled */
        QUAC_JOB_STATUS_TIMEOUT = 5,   /**< Job timed out */
    } quac_job_status_t;

    /**
     * @brief Async operation type
     */
    typedef enum quac_async_op_e
    {
        QUAC_ASYNC_OP_KEM_KEYGEN = 0x0100,  /**< KEM key generation */
        QUAC_ASYNC_OP_KEM_ENCAPS = 0x0101,  /**< KEM encapsulation */
        QUAC_ASYNC_OP_KEM_DECAPS = 0x0102,  /**< KEM decapsulation */
        QUAC_ASYNC_OP_SIGN_KEYGEN = 0x0200, /**< Signature key generation */
        QUAC_ASYNC_OP_SIGN = 0x0201,        /**< Signing */
        QUAC_ASYNC_OP_VERIFY = 0x0202,      /**< Verification */
        QUAC_ASYNC_OP_RANDOM = 0x0300,      /**< Random generation */
        QUAC_ASYNC_OP_BATCH = 0x0400,       /**< Batch operation */
        QUAC_ASYNC_OP_CUSTOM = 0x1000,      /**< Custom/extension operation */
    } quac_async_op_t;

    /**
     * @brief Job priority levels
     */
    typedef enum quac_job_priority_e
    {
        QUAC_PRIORITY_LOW = 0,      /**< Low priority (background) */
        QUAC_PRIORITY_NORMAL = 1,   /**< Normal priority (default) */
        QUAC_PRIORITY_HIGH = 2,     /**< High priority */
        QUAC_PRIORITY_CRITICAL = 3, /**< Critical priority (preemptive) */
    } quac_job_priority_t;

    /**
     * @brief Detailed job information
     */
    typedef struct quac_job_info_s
    {
        uint32_t struct_size;         /**< Size of this structure */
        quac_job_id_t job_id;         /**< Job identifier */
        quac_job_status_t status;     /**< Current status */
        quac_async_op_t operation;    /**< Operation type */
        quac_algorithm_t algorithm;   /**< Algorithm (if applicable) */
        quac_job_priority_t priority; /**< Job priority */
        quac_result_t result;         /**< Result code (if completed) */

        /* Timing information (nanoseconds since epoch) */
        uint64_t submit_time;   /**< When job was submitted */
        uint64_t start_time;    /**< When execution started (0 if pending) */
        uint64_t complete_time; /**< When job completed (0 if not done) */

        /* Derived timing (microseconds) */
        uint32_t queue_time_us; /**< Time spent in queue */
        uint32_t exec_time_us;  /**< Execution time */
        uint32_t total_time_us; /**< Total time from submit to complete */

        /* Progress (for long-running operations) */
        uint32_t progress_percent; /**< Progress 0-100 (if supported) */
        uint64_t bytes_processed;  /**< Bytes processed so far */
        uint64_t bytes_total;      /**< Total bytes to process */

        /* User context */
        void *user_data; /**< User-provided context */

        /* Error detail */
        char error_detail[128]; /**< Error message if failed */
    } quac_job_info_t;

    /*=============================================================================
     * Callback Types
     *=============================================================================*/

    /**
     * @brief Async completion callback
     *
     * Called when an async operation completes (success or failure).
     * Callback is invoked from a completion thread, not the submitting thread.
     *
     * @param device    Device handle
     * @param job_id    Job identifier
     * @param result    Operation result
     * @param user_data User-provided context from submission
     *
     * @note Callbacks should be lightweight. For heavy processing, signal
     *       another thread rather than blocking in the callback.
     */
    typedef void(QUAC100_CALL *quac_async_callback_t)(
        quac_device_t device,
        quac_job_id_t job_id,
        quac_result_t result,
        void *user_data);

    /**
     * @brief Progress callback for long-running operations
     *
     * @param device        Device handle
     * @param job_id        Job identifier
     * @param progress      Progress percentage (0-100)
     * @param bytes_done    Bytes processed so far
     * @param bytes_total   Total bytes to process
     * @param user_data     User-provided context
     *
     * @return true to continue, false to cancel
     */
    typedef bool(QUAC100_CALL *quac_progress_callback_t)(
        quac_device_t device,
        quac_job_id_t job_id,
        uint32_t progress,
        uint64_t bytes_done,
        uint64_t bytes_total,
        void *user_data);

    /*=============================================================================
     * Async Job Submission Options
     *=============================================================================*/

    /**
     * @brief Async submission options
     */
    typedef struct quac_async_options_s
    {
        uint32_t struct_size;                 /**< Size of this structure */
        quac_job_priority_t priority;         /**< Job priority */
        uint32_t timeout_ms;                  /**< Execution timeout (0 = none) */
        quac_async_callback_t callback;       /**< Completion callback (may be NULL) */
        quac_progress_callback_t progress_cb; /**< Progress callback (may be NULL) */
        void *user_data;                      /**< User context for callbacks */
        uint32_t flags;                       /**< Option flags (see below) */
    } quac_async_options_t;

    /**
     * @brief Async option flags
     */
    typedef enum quac_async_flags_e
    {
        QUAC_ASYNC_FLAG_NONE = 0x0000,
        QUAC_ASYNC_FLAG_NO_CALLBACK = 0x0001,   /**< Suppress callback */
        QUAC_ASYNC_FLAG_AUTO_RELEASE = 0x0002,  /**< Auto-release after callback */
        QUAC_ASYNC_FLAG_HIGH_PRIORITY = 0x0004, /**< Same as QUAC_PRIORITY_HIGH */
        QUAC_ASYNC_FLAG_PREEMPTIVE = 0x0008,    /**< Allow preempting lower priority */
    } quac_async_flags_t;

    /*=============================================================================
     * Job Submission - Generic
     *=============================================================================*/

    /**
     * @brief Submit a generic async job
     *
     * Low-level submission function for custom or advanced use cases.
     *
     * @param[in]  device       Device handle
     * @param[in]  operation    Operation type
     * @param[in]  algorithm    Algorithm (QUAC_ALGORITHM_NONE if N/A)
     * @param[in]  input        Input data
     * @param[in]  input_len    Input data length
     * @param[out] output       Output buffer
     * @param[in]  output_len   Output buffer size
     * @param[in]  options      Async options (NULL for defaults)
     * @param[out] job_id       Pointer to receive job identifier
     *
     * @return QUAC_SUCCESS on successful submission
     * @return QUAC_ERROR_QUEUE_FULL if job queue is full
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_async_submit(quac_device_t device,
                      quac_async_op_t operation,
                      quac_algorithm_t algorithm,
                      const void *input, size_t input_len,
                      void *output, size_t output_len,
                      const quac_async_options_t *options,
                      quac_job_id_t *job_id);

    /*=============================================================================
     * Job Submission - KEM Operations
     *=============================================================================*/

    /**
     * @brief Submit async KEM key generation
     *
     * @param[in]  device       Device handle
     * @param[in]  algorithm    KEM algorithm
     * @param[out] public_key   Buffer for public key
     * @param[in]  pk_size      Public key buffer size
     * @param[out] secret_key   Buffer for secret key
     * @param[in]  sk_size      Secret key buffer size
     * @param[in]  options      Async options (NULL for defaults)
     * @param[out] job_id       Job identifier
     *
     * @return QUAC_SUCCESS on successful submission
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_async_kem_keygen(quac_device_t device,
                          quac_algorithm_t algorithm,
                          uint8_t *public_key, size_t pk_size,
                          uint8_t *secret_key, size_t sk_size,
                          const quac_async_options_t *options,
                          quac_job_id_t *job_id);

    /**
     * @brief Submit async KEM encapsulation
     *
     * @param[in]  device       Device handle
     * @param[in]  algorithm    KEM algorithm
     * @param[in]  public_key   Public key
     * @param[in]  pk_size      Public key size
     * @param[out] ciphertext   Buffer for ciphertext
     * @param[in]  ct_size      Ciphertext buffer size
     * @param[out] shared_secret Buffer for shared secret
     * @param[in]  ss_size      Shared secret buffer size
     * @param[in]  options      Async options
     * @param[out] job_id       Job identifier
     *
     * @return QUAC_SUCCESS on successful submission
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_async_kem_encaps(quac_device_t device,
                          quac_algorithm_t algorithm,
                          const uint8_t *public_key, size_t pk_size,
                          uint8_t *ciphertext, size_t ct_size,
                          uint8_t *shared_secret, size_t ss_size,
                          const quac_async_options_t *options,
                          quac_job_id_t *job_id);

    /**
     * @brief Submit async KEM decapsulation
     *
     * @param[in]  device       Device handle
     * @param[in]  algorithm    KEM algorithm
     * @param[in]  ciphertext   Ciphertext
     * @param[in]  ct_size      Ciphertext size
     * @param[in]  secret_key   Secret key
     * @param[in]  sk_size      Secret key size
     * @param[out] shared_secret Buffer for shared secret
     * @param[in]  ss_size      Shared secret buffer size
     * @param[in]  options      Async options
     * @param[out] job_id       Job identifier
     *
     * @return QUAC_SUCCESS on successful submission
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_async_kem_decaps(quac_device_t device,
                          quac_algorithm_t algorithm,
                          const uint8_t *ciphertext, size_t ct_size,
                          const uint8_t *secret_key, size_t sk_size,
                          uint8_t *shared_secret, size_t ss_size,
                          const quac_async_options_t *options,
                          quac_job_id_t *job_id);

    /*=============================================================================
     * Job Submission - Signature Operations
     *=============================================================================*/

    /**
     * @brief Submit async signature key generation
     *
     * @param[in]  device       Device handle
     * @param[in]  algorithm    Signature algorithm
     * @param[out] public_key   Buffer for public key
     * @param[in]  pk_size      Public key buffer size
     * @param[out] secret_key   Buffer for secret key
     * @param[in]  sk_size      Secret key buffer size
     * @param[in]  options      Async options
     * @param[out] job_id       Job identifier
     *
     * @return QUAC_SUCCESS on successful submission
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_async_sign_keygen(quac_device_t device,
                           quac_algorithm_t algorithm,
                           uint8_t *public_key, size_t pk_size,
                           uint8_t *secret_key, size_t sk_size,
                           const quac_async_options_t *options,
                           quac_job_id_t *job_id);

    /**
     * @brief Submit async signing operation
     *
     * @param[in]  device       Device handle
     * @param[in]  algorithm    Signature algorithm
     * @param[in]  secret_key   Secret key
     * @param[in]  sk_size      Secret key size
     * @param[in]  message      Message to sign
     * @param[in]  msg_size     Message size
     * @param[out] signature    Buffer for signature
     * @param[in]  sig_size     Signature buffer size
     * @param[out] sig_len      Pointer to receive actual signature length
     * @param[in]  options      Async options
     * @param[out] job_id       Job identifier
     *
     * @return QUAC_SUCCESS on successful submission
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_async_sign(quac_device_t device,
                    quac_algorithm_t algorithm,
                    const uint8_t *secret_key, size_t sk_size,
                    const uint8_t *message, size_t msg_size,
                    uint8_t *signature, size_t sig_size,
                    size_t *sig_len,
                    const quac_async_options_t *options,
                    quac_job_id_t *job_id);

    /**
     * @brief Submit async verification operation
     *
     * @param[in]  device       Device handle
     * @param[in]  algorithm    Signature algorithm
     * @param[in]  public_key   Public key
     * @param[in]  pk_size      Public key size
     * @param[in]  message      Original message
     * @param[in]  msg_size     Message size
     * @param[in]  signature    Signature to verify
     * @param[in]  sig_size     Signature size
     * @param[in]  options      Async options
     * @param[out] job_id       Job identifier
     *
     * @return QUAC_SUCCESS on successful submission
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_async_verify(quac_device_t device,
                      quac_algorithm_t algorithm,
                      const uint8_t *public_key, size_t pk_size,
                      const uint8_t *message, size_t msg_size,
                      const uint8_t *signature, size_t sig_size,
                      const quac_async_options_t *options,
                      quac_job_id_t *job_id);

    /*=============================================================================
     * Job Submission - Random Generation
     *=============================================================================*/

    /**
     * @brief Submit async random generation
     *
     * @param[in]  device       Device handle
     * @param[out] buffer       Buffer to receive random bytes
     * @param[in]  length       Number of bytes to generate
     * @param[in]  options      Async options
     * @param[out] job_id       Job identifier
     *
     * @return QUAC_SUCCESS on successful submission
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_async_random(quac_device_t device,
                      uint8_t *buffer, size_t length,
                      const quac_async_options_t *options,
                      quac_job_id_t *job_id);

    /*=============================================================================
     * Job Control
     *=============================================================================*/

    /**
     * @brief Wait for job completion
     *
     * Blocks until the specified job completes or timeout expires.
     *
     * @param[in] device        Device handle
     * @param[in] job_id        Job identifier
     * @param[in] timeout_ms    Timeout in milliseconds (QUAC_ASYNC_WAIT_INFINITE for infinite)
     *
     * @return QUAC_SUCCESS if job completed successfully
     * @return QUAC_ERROR_TIMEOUT if timeout elapsed
     * @return Job's result code if job failed
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_async_wait(quac_device_t device,
                    quac_job_id_t job_id,
                    uint32_t timeout_ms);

    /**
     * @brief Wait for any of multiple jobs
     *
     * Blocks until at least one of the specified jobs completes.
     *
     * @param[in]  device       Device handle
     * @param[in]  job_ids      Array of job identifiers
     * @param[in]  count        Number of jobs to wait on
     * @param[in]  timeout_ms   Timeout in milliseconds
     * @param[out] completed_id Pointer to receive ID of completed job
     *
     * @return QUAC_SUCCESS when a job completes
     * @return QUAC_ERROR_TIMEOUT if timeout elapsed
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_async_wait_any(quac_device_t device,
                        const quac_job_id_t *job_ids, size_t count,
                        uint32_t timeout_ms,
                        quac_job_id_t *completed_id);

    /**
     * @brief Wait for all jobs to complete
     *
     * @param[in]  device       Device handle
     * @param[in]  job_ids      Array of job identifiers
     * @param[in]  count        Number of jobs to wait on
     * @param[in]  timeout_ms   Timeout in milliseconds
     * @param[out] results      Array to receive individual results (may be NULL)
     *
     * @return QUAC_SUCCESS if all jobs completed successfully
     * @return QUAC_ERROR_TIMEOUT if timeout elapsed
     * @return QUAC_ERROR_BATCH_PARTIAL if some jobs failed
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_async_wait_all(quac_device_t device,
                        const quac_job_id_t *job_ids, size_t count,
                        uint32_t timeout_ms,
                        quac_result_t *results);

    /**
     * @brief Poll job completion status
     *
     * Non-blocking check of job status.
     *
     * @param[in]  device       Device handle
     * @param[in]  job_id       Job identifier
     * @param[out] completed    Set to true if job is complete
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_INVALID_JOB_ID if job not found
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_async_poll(quac_device_t device,
                    quac_job_id_t job_id,
                    bool *completed);

    /**
     * @brief Cancel a pending job
     *
     * Attempts to cancel a job. Jobs that are already executing may not
     * be cancellable.
     *
     * @param[in] device        Device handle
     * @param[in] job_id        Job identifier
     *
     * @return QUAC_SUCCESS if cancelled
     * @return QUAC_ERROR_JOB_NOT_FOUND if job not found or already complete
     * @return QUAC_ERROR_NOT_SUPPORTED if job cannot be cancelled
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_async_cancel(quac_device_t device, quac_job_id_t job_id);

    /**
     * @brief Cancel all pending jobs
     *
     * @param[in] device        Device handle
     * @param[out] cancelled    Number of jobs cancelled (may be NULL)
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_async_cancel_all(quac_device_t device, uint32_t *cancelled);

    /**
     * @brief Release job resources
     *
     * Frees resources associated with a completed job. Called automatically
     * if QUAC_ASYNC_FLAG_AUTO_RELEASE is set.
     *
     * @param[in] device        Device handle
     * @param[in] job_id        Job identifier
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_async_release(quac_device_t device, quac_job_id_t job_id);

    /*=============================================================================
     * Job Information
     *=============================================================================*/

    /**
     * @brief Get job information
     *
     * @param[in]  device       Device handle
     * @param[in]  job_id       Job identifier
     * @param[out] info         Pointer to receive job information
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_INVALID_JOB_ID if job not found
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_async_get_info(quac_device_t device,
                        quac_job_id_t job_id,
                        quac_job_info_t *info);

    /**
     * @brief Get job result
     *
     * Returns the result code of a completed job.
     *
     * @param[in]  device       Device handle
     * @param[in]  job_id       Job identifier
     * @param[out] result       Pointer to receive result code
     *
     * @return QUAC_SUCCESS if job is complete
     * @return QUAC_ERROR_JOB_PENDING if job still running
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_async_get_result(quac_device_t device,
                          quac_job_id_t job_id,
                          quac_result_t *result);

    /**
     * @brief Get job status string
     *
     * @param[in] status        Job status
     *
     * @return Status string (e.g., "COMPLETED")
     */
    QUAC100_API const char *QUAC100_CALL
    quac_job_status_string(quac_job_status_t status);

    /*=============================================================================
     * Queue Management
     *=============================================================================*/

    /**
     * @brief Async queue information
     */
    typedef struct quac_async_queue_info_s
    {
        uint32_t struct_size;      /**< Size of this structure */
        uint32_t max_pending;      /**< Maximum pending jobs */
        uint32_t current_pending;  /**< Current pending jobs */
        uint32_t current_running;  /**< Currently executing jobs */
        uint32_t total_submitted;  /**< Total jobs submitted */
        uint32_t total_completed;  /**< Total jobs completed */
        uint32_t total_failed;     /**< Total jobs failed */
        uint32_t total_cancelled;  /**< Total jobs cancelled */
        uint32_t thread_pool_size; /**< Completion thread pool size */
        uint32_t threads_active;   /**< Currently active threads */
    } quac_async_queue_info_t;

    /**
     * @brief Get async queue information
     *
     * @param[in]  device       Device handle
     * @param[out] info         Pointer to receive queue information
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_async_get_queue_info(quac_device_t device, quac_async_queue_info_t *info);

    /**
     * @brief Set thread pool size
     *
     * @param[in] device        Device handle
     * @param[in] threads       Number of threads (0 = auto)
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_async_set_thread_pool(quac_device_t device, uint32_t threads);

    /**
     * @brief Drain async queue
     *
     * Waits for all pending and running jobs to complete.
     *
     * @param[in] device        Device handle
     * @param[in] timeout_ms    Timeout in milliseconds
     *
     * @return QUAC_SUCCESS if queue drained
     * @return QUAC_ERROR_TIMEOUT if timeout elapsed
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_async_drain(quac_device_t device, uint32_t timeout_ms);

    /*=============================================================================
     * Enumeration
     *=============================================================================*/

    /**
     * @brief Job enumeration callback
     *
     * @param device    Device handle
     * @param info      Job information
     * @param user_data User context
     *
     * @return true to continue enumeration, false to stop
     */
    typedef bool(QUAC100_CALL *quac_job_enum_callback_t)(
        quac_device_t device,
        const quac_job_info_t *info,
        void *user_data);

    /**
     * @brief Enumerate all jobs
     *
     * @param[in] device        Device handle
     * @param[in] status_filter Status filter (0 = all statuses)
     * @param[in] callback      Enumeration callback
     * @param[in] user_data     User context
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_async_enumerate_jobs(quac_device_t device,
                              quac_job_status_t status_filter,
                              quac_job_enum_callback_t callback,
                              void *user_data);

    /**
     * @brief Get list of pending job IDs
     *
     * @param[in]  device       Device handle
     * @param[out] job_ids      Array to receive job IDs
     * @param[in]  max_jobs     Maximum jobs to return
     * @param[out] count        Actual number of jobs
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_async_get_pending(quac_device_t device,
                           quac_job_id_t *job_ids, size_t max_jobs,
                           size_t *count);

    /*=============================================================================
     * Statistics
     *=============================================================================*/

    /**
     * @brief Async performance statistics
     */
    typedef struct quac_async_stats_s
    {
        uint32_t struct_size;         /**< Size of this structure */
        uint64_t jobs_submitted;      /**< Total jobs submitted */
        uint64_t jobs_completed;      /**< Jobs completed successfully */
        uint64_t jobs_failed;         /**< Jobs that failed */
        uint64_t jobs_cancelled;      /**< Jobs that were cancelled */
        uint64_t jobs_timeout;        /**< Jobs that timed out */
        uint64_t total_queue_time_ns; /**< Total time in queue (ns) */
        uint64_t total_exec_time_ns;  /**< Total execution time (ns) */
        uint32_t avg_queue_time_us;   /**< Average queue time (μs) */
        uint32_t avg_exec_time_us;    /**< Average execution time (μs) */
        uint32_t max_queue_time_us;   /**< Maximum queue time (μs) */
        uint32_t max_exec_time_us;    /**< Maximum execution time (μs) */
        uint32_t peak_pending;        /**< Peak pending jobs */
        uint32_t peak_running;        /**< Peak concurrent running */
    } quac_async_stats_t;

    /**
     * @brief Get async statistics
     *
     * @param[in]  device       Device handle
     * @param[out] stats        Pointer to receive statistics
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_async_get_stats(quac_device_t device, quac_async_stats_t *stats);

    /**
     * @brief Reset async statistics
     *
     * @param[in] device        Device handle
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_async_reset_stats(quac_device_t device);

#ifdef __cplusplus
}
#endif

#endif /* QUAC100_ASYNC_H */
