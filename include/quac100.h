/**
 * @file quac100.h
 * @brief QuantaCore SDK - QUAC 100 Post-Quantum Cryptographic Accelerator API
 *
 * Main header file for the QuantaCore SDK. This file includes all public API
 * declarations for the QUAC 100 Post-Quantum Cryptographic Accelerator.
 *
 * Include this header to access all SDK functionality:
 * @code
 * #include <quac100.h>
 * @endcode
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 * @doc QUAC100-SDK-DEV-001
 *
 * @par Supported Algorithms
 * - ML-KEM (Kyber): 512, 768, 1024
 * - ML-DSA (Dilithium): 2, 3, 5
 * - SLH-DSA (SPHINCS+): 128s/f, 192s/f, 256s/f
 * - QRNG: Hardware quantum random number generation
 *
 * @par Example Usage
 * @code
 * #include <quac100.h>
 *
 * int main(void) {
 *     quac_result_t result;
 *     quac_device_t device;
 *
 *     // Initialize SDK
 *     result = quac_init(NULL);
 *     if (QUAC_FAILED(result)) {
 *         return 1;
 *     }
 *
 *     // Open device
 *     result = quac_open(0, &device);
 *     if (QUAC_FAILED(result)) {
 *         quac_shutdown();
 *         return 1;
 *     }
 *
 *     // Generate Kyber-768 key pair
 *     uint8_t public_key[QUAC_KYBER768_PUBLIC_KEY_SIZE];
 *     uint8_t secret_key[QUAC_KYBER768_SECRET_KEY_SIZE];
 *
 *     result = quac_kem_keygen(device, QUAC_ALGORITHM_KYBER768,
 *                              public_key, sizeof(public_key),
 *                              secret_key, sizeof(secret_key));
 *
 *     // Cleanup
 *     quac_close(device);
 *     quac_shutdown();
 *     return 0;
 * }
 * @endcode
 */

#ifndef QUAC100_H
#define QUAC100_H

#include "quac100_types.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /*=============================================================================
     * Library Initialization and Shutdown
     *=============================================================================*/

    /**
     * @brief Initialize the QuantaCore SDK
     *
     * Must be called before any other SDK function. Safe to call multiple times;
     * subsequent calls have no effect.
     *
     * @param[in] options   Initialization options (NULL for defaults)
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_ALREADY_INITIALIZED if already initialized
     * @return QUAC_ERROR_OUT_OF_MEMORY on memory allocation failure
     * @return QUAC_ERROR_NO_DEVICE if no device found and simulator disabled
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_init(const quac_init_options_t *options);

    /**
     * @brief Shutdown the QuantaCore SDK
     *
     * Releases all resources. All device handles become invalid after this call.
     * Safe to call multiple times; subsequent calls have no effect.
     */
    QUAC100_API void QUAC100_CALL
    quac_shutdown(void);

    /**
     * @brief Check if SDK is initialized
     *
     * @return true if initialized, false otherwise
     */
    QUAC100_API bool QUAC100_CALL
    quac_is_initialized(void);

    /**
     * @brief Get SDK version string
     *
     * @return Version string (e.g., "1.0.0")
     */
    QUAC100_API const char *QUAC100_CALL
    quac_version_string(void);

    /**
     * @brief Get SDK version as integer
     *
     * @return Version as hex (e.g., 0x010000 for 1.0.0)
     */
    QUAC100_API uint32_t QUAC100_CALL
    quac_version_hex(void);

    /*=============================================================================
     * Device Management
     *=============================================================================*/

    /**
     * @brief Get number of available devices
     *
     * @param[out] count    Pointer to receive device count
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_NOT_INITIALIZED if SDK not initialized
     * @return QUAC_ERROR_NULL_POINTER if count is NULL
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_device_count(uint32_t *count);

    /**
     * @brief Open a device by index
     *
     * @param[in]  index    Device index (0 to count-1)
     * @param[out] device   Pointer to receive device handle
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_NOT_INITIALIZED if SDK not initialized
     * @return QUAC_ERROR_DEVICE_NOT_FOUND if index invalid
     * @return QUAC_ERROR_DEVICE_OPEN_FAILED on open failure
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_open(uint32_t index, quac_device_t *device);

    /**
     * @brief Open a device by serial number
     *
     * @param[in]  serial   Device serial number string
     * @param[out] device   Pointer to receive device handle
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_DEVICE_NOT_FOUND if serial not found
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_open_by_serial(const char *serial, quac_device_t *device);

    /**
     * @brief Close a device
     *
     * @param[in] device    Device handle to close
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_INVALID_PARAMETER if device is invalid
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_close(quac_device_t device);

    /**
     * @brief Get device information
     *
     * @param[in]  device   Device handle
     * @param[out] info     Pointer to receive device information
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_INVALID_PARAMETER if device invalid
     * @return QUAC_ERROR_NULL_POINTER if info is NULL
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_get_info(quac_device_t device, quac_device_info_t *info);

    /**
     * @brief Reset a device
     *
     * Performs a soft reset of the device. All pending operations are cancelled.
     *
     * @param[in] device    Device handle
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_DEVICE_ERROR on reset failure
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_reset(quac_device_t device);

    /*=============================================================================
     * ML-KEM (Kyber) Key Encapsulation Operations
     *=============================================================================*/

    /**
     * @brief Generate a KEM key pair
     *
     * Generates a public/secret key pair for the specified KEM algorithm.
     *
     * @param[in]  device       Device handle
     * @param[in]  algorithm    KEM algorithm (QUAC_ALGORITHM_KYBER*)
     * @param[out] public_key   Buffer for public key
     * @param[in]  pk_size      Size of public key buffer
     * @param[out] secret_key   Buffer for secret key
     * @param[in]  sk_size      Size of secret key buffer
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_INVALID_ALGORITHM if not a KEM algorithm
     * @return QUAC_ERROR_BUFFER_TOO_SMALL if buffers too small
     * @return QUAC_ERROR_KEY_GENERATION_FAILED on generation failure
     *
     * @par Example
     * @code
     * uint8_t pk[QUAC_KYBER768_PUBLIC_KEY_SIZE];
     * uint8_t sk[QUAC_KYBER768_SECRET_KEY_SIZE];
     *
     * result = quac_kem_keygen(device, QUAC_ALGORITHM_KYBER768,
     *                          pk, sizeof(pk), sk, sizeof(sk));
     * @endcode
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_kem_keygen(quac_device_t device,
                    quac_algorithm_t algorithm,
                    uint8_t *public_key, size_t pk_size,
                    uint8_t *secret_key, size_t sk_size);

    /**
     * @brief Encapsulate a shared secret
     *
     * Given a public key, generates a ciphertext and shared secret.
     *
     * @param[in]  device       Device handle
     * @param[in]  algorithm    KEM algorithm
     * @param[in]  public_key   Public key
     * @param[in]  pk_size      Public key size
     * @param[out] ciphertext   Buffer for ciphertext
     * @param[in]  ct_size      Size of ciphertext buffer
     * @param[out] shared_secret Buffer for shared secret
     * @param[in]  ss_size      Size of shared secret buffer
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_INVALID_KEY if public key invalid
     * @return QUAC_ERROR_ENCAPSULATION_FAILED on failure
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_kem_encaps(quac_device_t device,
                    quac_algorithm_t algorithm,
                    const uint8_t *public_key, size_t pk_size,
                    uint8_t *ciphertext, size_t ct_size,
                    uint8_t *shared_secret, size_t ss_size);

    /**
     * @brief Decapsulate a shared secret
     *
     * Given a ciphertext and secret key, recovers the shared secret.
     *
     * @param[in]  device       Device handle
     * @param[in]  algorithm    KEM algorithm
     * @param[in]  ciphertext   Ciphertext
     * @param[in]  ct_size      Ciphertext size
     * @param[in]  secret_key   Secret key
     * @param[in]  sk_size      Secret key size
     * @param[out] shared_secret Buffer for shared secret
     * @param[in]  ss_size      Size of shared secret buffer
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_INVALID_CIPHERTEXT if ciphertext invalid
     * @return QUAC_ERROR_DECAPSULATION_FAILED on failure
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_kem_decaps(quac_device_t device,
                    quac_algorithm_t algorithm,
                    const uint8_t *ciphertext, size_t ct_size,
                    const uint8_t *secret_key, size_t sk_size,
                    uint8_t *shared_secret, size_t ss_size);

    /**
     * @brief Get KEM algorithm key and ciphertext sizes
     *
     * @param[in]  algorithm    KEM algorithm
     * @param[out] pk_size      Public key size (may be NULL)
     * @param[out] sk_size      Secret key size (may be NULL)
     * @param[out] ct_size      Ciphertext size (may be NULL)
     * @param[out] ss_size      Shared secret size (may be NULL)
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_INVALID_ALGORITHM if not a KEM algorithm
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_kem_sizes(quac_algorithm_t algorithm,
                   size_t *pk_size, size_t *sk_size,
                   size_t *ct_size, size_t *ss_size);

    /*=============================================================================
     * ML-DSA (Dilithium) / SLH-DSA (SPHINCS+) Digital Signature Operations
     *=============================================================================*/

    /**
     * @brief Generate a signature key pair
     *
     * @param[in]  device       Device handle
     * @param[in]  algorithm    Signature algorithm (QUAC_ALGORITHM_DILITHIUM* or SPHINCS*)
     * @param[out] public_key   Buffer for public key
     * @param[in]  pk_size      Size of public key buffer
     * @param[out] secret_key   Buffer for secret key
     * @param[in]  sk_size      Size of secret key buffer
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_INVALID_ALGORITHM if not a signature algorithm
     * @return QUAC_ERROR_KEY_GENERATION_FAILED on failure
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_sign_keygen(quac_device_t device,
                     quac_algorithm_t algorithm,
                     uint8_t *public_key, size_t pk_size,
                     uint8_t *secret_key, size_t sk_size);

    /**
     * @brief Sign a message
     *
     * @param[in]  device       Device handle
     * @param[in]  algorithm    Signature algorithm
     * @param[in]  secret_key   Secret key
     * @param[in]  sk_size      Secret key size
     * @param[in]  message      Message to sign
     * @param[in]  msg_size     Message size
     * @param[out] signature    Buffer for signature
     * @param[in]  sig_size     Size of signature buffer
     * @param[out] sig_len      Actual signature length (may be NULL)
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_SIGNING_FAILED on failure
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_sign(quac_device_t device,
              quac_algorithm_t algorithm,
              const uint8_t *secret_key, size_t sk_size,
              const uint8_t *message, size_t msg_size,
              uint8_t *signature, size_t sig_size,
              size_t *sig_len);

    /**
     * @brief Verify a signature
     *
     * @param[in] device        Device handle
     * @param[in] algorithm     Signature algorithm
     * @param[in] public_key    Public key
     * @param[in] pk_size       Public key size
     * @param[in] message       Original message
     * @param[in] msg_size      Message size
     * @param[in] signature     Signature to verify
     * @param[in] sig_size      Signature size
     *
     * @return QUAC_SUCCESS if signature is valid
     * @return QUAC_ERROR_VERIFICATION_FAILED if signature invalid
     * @return QUAC_ERROR_INVALID_SIGNATURE if signature malformed
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_verify(quac_device_t device,
                quac_algorithm_t algorithm,
                const uint8_t *public_key, size_t pk_size,
                const uint8_t *message, size_t msg_size,
                const uint8_t *signature, size_t sig_size);

    /**
     * @brief Get signature algorithm key and signature sizes
     *
     * @param[in]  algorithm    Signature algorithm
     * @param[out] pk_size      Public key size (may be NULL)
     * @param[out] sk_size      Secret key size (may be NULL)
     * @param[out] sig_size     Maximum signature size (may be NULL)
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_INVALID_ALGORITHM if not a signature algorithm
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_sign_sizes(quac_algorithm_t algorithm,
                    size_t *pk_size, size_t *sk_size, size_t *sig_size);

    /*=============================================================================
     * Quantum Random Number Generation (QRNG)
     *=============================================================================*/

    /**
     * @brief Generate random bytes from hardware QRNG
     *
     * Generates cryptographically secure random bytes from the hardware
     * quantum random number generator.
     *
     * @param[in]  device       Device handle
     * @param[out] buffer       Buffer to receive random bytes
     * @param[in]  length       Number of bytes to generate
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_ENTROPY_DEPLETED if entropy pool depleted
     * @return QUAC_ERROR_QRNG_FAILURE on hardware failure
     *
     * @par Example
     * @code
     * uint8_t nonce[32];
     * result = quac_random_bytes(device, nonce, sizeof(nonce));
     * @endcode
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_random_bytes(quac_device_t device, uint8_t *buffer, size_t length);

    /**
     * @brief Get available entropy
     *
     * @param[in]  device       Device handle
     * @param[out] bits         Available entropy in bits
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_random_available(quac_device_t device, uint32_t *bits);

    /**
     * @brief Reseed the QRNG (if supported)
     *
     * @param[in] device        Device handle
     * @param[in] seed          Optional additional seed data (may be NULL)
     * @param[in] seed_len      Length of seed data
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_NOT_SUPPORTED if reseeding not supported
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_random_reseed(quac_device_t device, const uint8_t *seed, size_t seed_len);

    /*=============================================================================
     * Key Management
     *=============================================================================*/

    /**
     * @brief Generate and store a key pair on device
     *
     * @param[in]  device       Device handle
     * @param[in]  attr         Key attributes
     * @param[out] handle       Key handle for stored key
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_KEY_SLOT_FULL if no storage available
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_key_generate(quac_device_t device,
                      const quac_key_attr_t *attr,
                      quac_key_handle_t *handle);

    /**
     * @brief Import a key to device storage
     *
     * @param[in]  device       Device handle
     * @param[in]  attr         Key attributes
     * @param[in]  key_data     Key data to import
     * @param[in]  key_len      Key data length
     * @param[out] handle       Key handle for stored key
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_KEY_IMPORT_FAILED on failure
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_key_import(quac_device_t device,
                    const quac_key_attr_t *attr,
                    const uint8_t *key_data, size_t key_len,
                    quac_key_handle_t *handle);

    /**
     * @brief Export a key from device storage
     *
     * @param[in]  device       Device handle
     * @param[in]  handle       Key handle
     * @param[out] key_data     Buffer for key data
     * @param[in]  key_len      Buffer size
     * @param[out] actual_len   Actual key length
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_KEY_EXPORT_DENIED if key not extractable
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_key_export(quac_device_t device,
                    quac_key_handle_t handle,
                    uint8_t *key_data, size_t key_len,
                    size_t *actual_len);

    /**
     * @brief Delete a key from device storage
     *
     * @param[in] device        Device handle
     * @param[in] handle        Key handle
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_KEY_NOT_FOUND if key not found
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_key_destroy(quac_device_t device, quac_key_handle_t handle);

    /**
     * @brief Get key attributes
     *
     * @param[in]  device       Device handle
     * @param[in]  handle       Key handle
     * @param[out] attr         Key attributes
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_key_get_attr(quac_device_t device,
                      quac_key_handle_t handle,
                      quac_key_attr_t *attr);

    /*=============================================================================
     * Asynchronous Operations
     *=============================================================================*/

    /**
     * @brief Submit an async KEM keygen operation
     *
     * @param[in]  device       Device handle
     * @param[in]  algorithm    KEM algorithm
     * @param[out] public_key   Buffer for public key
     * @param[in]  pk_size      Public key buffer size
     * @param[out] secret_key   Buffer for secret key
     * @param[in]  sk_size      Secret key buffer size
     * @param[in]  callback     Completion callback (may be NULL)
     * @param[in]  user_data    User context for callback
     * @param[out] job_id       Job identifier
     *
     * @return QUAC_SUCCESS on successful submission
     * @return QUAC_ERROR_QUEUE_FULL if job queue full
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_async_kem_keygen(quac_device_t device,
                          quac_algorithm_t algorithm,
                          uint8_t *public_key, size_t pk_size,
                          uint8_t *secret_key, size_t sk_size,
                          quac_async_callback_t callback,
                          void *user_data,
                          quac_job_id_t *job_id);

    /**
     * @brief Wait for an async job to complete
     *
     * @param[in] device        Device handle
     * @param[in] job_id        Job identifier
     * @param[in] timeout_ms    Timeout in milliseconds (0 = infinite)
     *
     * @return QUAC_SUCCESS if job completed successfully
     * @return QUAC_ERROR_TIMEOUT if timeout elapsed
     * @return QUAC_ERROR_JOB_FAILED if job failed
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_async_wait(quac_device_t device, quac_job_id_t job_id, uint32_t timeout_ms);

    /**
     * @brief Poll job completion status
     *
     * @param[in]  device       Device handle
     * @param[in]  job_id       Job identifier
     * @param[out] completed    Set to true if job complete
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_INVALID_JOB_ID if job not found
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_async_poll(quac_device_t device, quac_job_id_t job_id, bool *completed);

    /**
     * @brief Cancel a pending async job
     *
     * @param[in] device        Device handle
     * @param[in] job_id        Job identifier
     *
     * @return QUAC_SUCCESS if cancelled
     * @return QUAC_ERROR_JOB_NOT_FOUND if job not found or already complete
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_async_cancel(quac_device_t device, quac_job_id_t job_id);

    /**
     * @brief Get async job information
     *
     * @param[in]  device       Device handle
     * @param[in]  job_id       Job identifier
     * @param[out] info         Job information
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_async_get_info(quac_device_t device, quac_job_id_t job_id, quac_job_info_t *info);

    /*=============================================================================
     * Batch Operations
     *=============================================================================*/

    /**
     * @brief Submit a batch of operations
     *
     * Executes multiple cryptographic operations in a single call for maximum
     * throughput. Operations are processed in parallel where possible.
     *
     * @param[in]     device    Device handle
     * @param[in,out] items     Array of batch items
     * @param[in]     count     Number of items in array
     *
     * @return QUAC_SUCCESS if all operations succeeded
     * @return QUAC_ERROR_BATCH_PARTIAL if some operations failed (check individual results)
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_batch_submit(quac_device_t device, quac_batch_item_t *items, size_t count);

    /**
     * @brief Wait for batch completion
     *
     * @param[in] device        Device handle
     * @param[in] timeout_ms    Timeout in milliseconds
     *
     * @return QUAC_SUCCESS on completion
     * @return QUAC_ERROR_TIMEOUT if timeout elapsed
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_batch_wait(quac_device_t device, uint32_t timeout_ms);

    /*=============================================================================
     * Diagnostics and Health
     *=============================================================================*/

    /**
     * @brief Run device self-test
     *
     * Executes FIPS-required cryptographic self-tests.
     *
     * @param[in] device        Device handle
     *
     * @return QUAC_SUCCESS if all tests pass
     * @return QUAC_ERROR_SELF_TEST_FAILED if any test fails
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_self_test(quac_device_t device);

    /**
     * @brief Get device health status
     *
     * @param[in]  device       Device handle
     * @param[out] status       Device status flags
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_get_health(quac_device_t device, quac_device_status_t *status);

    /**
     * @brief Get device temperature
     *
     * @param[in]  device       Device handle
     * @param[out] celsius      Temperature in degrees Celsius
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_get_temperature(quac_device_t device, int32_t *celsius);

    /*=============================================================================
     * Error Handling
     *=============================================================================*/

    /**
     * @brief Get human-readable error message
     *
     * @param[in] result        Result code
     *
     * @return Error message string (never NULL)
     */
    QUAC100_API const char *QUAC100_CALL
    quac_error_string(quac_result_t result);

    /**
     * @brief Get last error for current thread
     *
     * @return Last error code
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_get_last_error(void);

    /**
     * @brief Get extended error information
     *
     * @param[out] buffer       Buffer for extended error message
     * @param[in]  size         Buffer size
     *
     * @return QUAC_SUCCESS if extended info available
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_get_last_error_detail(char *buffer, size_t size);

    /*=============================================================================
     * Simulator Control (Debug/Development)
     *=============================================================================*/

    /**
     * @brief Enable or disable simulator mode
     *
     * When enabled, the SDK uses a software simulator instead of real hardware.
     * Must be called before quac_init().
     *
     * @param[in] use_simulator true to use simulator
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_ALREADY_INITIALIZED if SDK already initialized
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_set_simulator_mode(bool use_simulator);

    /**
     * @brief Check if running in simulator mode
     *
     * @return true if using simulator
     */
    QUAC100_API bool QUAC100_CALL
    quac_is_simulator(void);

    /**
     * @brief Configure simulator parameters
     *
     * @param[in] latency_us    Simulated operation latency (microseconds)
     * @param[in] throughput_ops Simulated throughput (operations/second)
     *
     * @return QUAC_SUCCESS on success
     */
    QUAC100_API quac_result_t QUAC100_CALL
    quac_simulator_config(uint32_t latency_us, uint32_t throughput_ops);

    /*=============================================================================
     * Algorithm Queries
     *=============================================================================*/

    /**
     * @brief Check if algorithm is supported
     *
     * @param[in] device        Device handle (NULL to check SDK support)
     * @param[in] algorithm     Algorithm to check
     *
     * @return true if supported
     */
    QUAC100_API bool QUAC100_CALL
    quac_is_algorithm_supported(quac_device_t device, quac_algorithm_t algorithm);

    /**
     * @brief Get algorithm name string
     *
     * @param[in] algorithm     Algorithm identifier
     *
     * @return Algorithm name (e.g., "ML-KEM-768") or "Unknown"
     */
    QUAC100_API const char *QUAC100_CALL
    quac_algorithm_name(quac_algorithm_t algorithm);

#ifdef __cplusplus
}
#endif

#endif /* QUAC100_H */
