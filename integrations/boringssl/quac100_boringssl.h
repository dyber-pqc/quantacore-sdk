/**
 * @file quac100_boringssl.h
 * @brief QUAC 100 BoringSSL Integration - Public Header
 *
 * Provides post-quantum cryptographic acceleration for BoringSSL:
 * - ML-KEM (FIPS 203) key encapsulation
 * - ML-DSA (FIPS 204) digital signatures
 * - QRNG hardware random number generation
 * - TLS 1.3 hybrid key exchange
 *
 * Unlike OpenSSL 3.x, BoringSSL doesn't use a provider model.
 * This integration provides direct function calls and EVP method
 * registration for transparent acceleration.
 *
 * Usage:
 *   #include "quac100_boringssl.h"
 *
 *   // Initialize once at startup
 *   QUAC_init();
 *
 *   // Use ML-KEM
 *   QUAC_KEM_keypair(QUAC_KEM_ML_KEM_768, pk, sk);
 *   QUAC_KEM_encaps(QUAC_KEM_ML_KEM_768, ct, ss, pk);
 *   QUAC_KEM_decaps(QUAC_KEM_ML_KEM_768, ss, ct, sk);
 *
 *   // Use ML-DSA
 *   QUAC_sign(QUAC_SIG_ML_DSA_65, sig, &sig_len, msg, msg_len, sk);
 *   QUAC_verify(QUAC_SIG_ML_DSA_65, sig, sig_len, msg, msg_len, pk);
 *
 *   // Cleanup
 *   QUAC_cleanup();
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_BORINGSSL_H
#define QUAC100_BORINGSSL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /* ==========================================================================
     * Version Information
     * ========================================================================== */

#define QUAC_BORINGSSL_VERSION_MAJOR 1
#define QUAC_BORINGSSL_VERSION_MINOR 0
#define QUAC_BORINGSSL_VERSION_PATCH 0
#define QUAC_BORINGSSL_VERSION_STRING "1.0.0"

    /* ==========================================================================
     * Algorithm Identifiers
     * ========================================================================== */

    /**
     * @brief KEM algorithm identifiers
     */
    typedef enum
    {
        QUAC_KEM_NONE = 0,
        QUAC_KEM_ML_KEM_512 = 1,
        QUAC_KEM_ML_KEM_768 = 2,
        QUAC_KEM_ML_KEM_1024 = 3,
    } quac_kem_algorithm_t;

    /**
     * @brief Signature algorithm identifiers
     */
    typedef enum
    {
        QUAC_SIG_NONE = 0,
        QUAC_SIG_ML_DSA_44 = 1,
        QUAC_SIG_ML_DSA_65 = 2,
        QUAC_SIG_ML_DSA_87 = 3,
    } quac_sig_algorithm_t;

    /**
     * @brief TLS hybrid group identifiers
     */
    typedef enum
    {
        QUAC_GROUP_NONE = 0,
        QUAC_GROUP_X25519_ML_KEM_768 = 0x6399,
        QUAC_GROUP_SECP384R1_ML_KEM_1024 = 0x639A,
        QUAC_GROUP_X25519_ML_KEM_512 = 0x639B,
    } quac_tls_group_t;

/* ==========================================================================
 * Key Sizes (bytes)
 * ========================================================================== */

/* ML-KEM-512 */
#define QUAC_ML_KEM_512_PUBLIC_KEY_BYTES 800
#define QUAC_ML_KEM_512_SECRET_KEY_BYTES 1632
#define QUAC_ML_KEM_512_CIPHERTEXT_BYTES 768
#define QUAC_ML_KEM_512_SHARED_SECRET_BYTES 32

/* ML-KEM-768 */
#define QUAC_ML_KEM_768_PUBLIC_KEY_BYTES 1184
#define QUAC_ML_KEM_768_SECRET_KEY_BYTES 2400
#define QUAC_ML_KEM_768_CIPHERTEXT_BYTES 1088
#define QUAC_ML_KEM_768_SHARED_SECRET_BYTES 32

/* ML-KEM-1024 */
#define QUAC_ML_KEM_1024_PUBLIC_KEY_BYTES 1568
#define QUAC_ML_KEM_1024_SECRET_KEY_BYTES 3168
#define QUAC_ML_KEM_1024_CIPHERTEXT_BYTES 1568
#define QUAC_ML_KEM_1024_SHARED_SECRET_BYTES 32

/* ML-DSA-44 */
#define QUAC_ML_DSA_44_PUBLIC_KEY_BYTES 1312
#define QUAC_ML_DSA_44_SECRET_KEY_BYTES 2560
#define QUAC_ML_DSA_44_SIGNATURE_BYTES 2420

/* ML-DSA-65 */
#define QUAC_ML_DSA_65_PUBLIC_KEY_BYTES 1952
#define QUAC_ML_DSA_65_SECRET_KEY_BYTES 4032
#define QUAC_ML_DSA_65_SIGNATURE_BYTES 3309

/* ML-DSA-87 */
#define QUAC_ML_DSA_87_PUBLIC_KEY_BYTES 2592
#define QUAC_ML_DSA_87_SECRET_KEY_BYTES 4896
#define QUAC_ML_DSA_87_SIGNATURE_BYTES 4627

/* Maximum sizes (for buffer allocation) */
#define QUAC_KEM_MAX_PUBLIC_KEY_BYTES 1568
#define QUAC_KEM_MAX_SECRET_KEY_BYTES 3168
#define QUAC_KEM_MAX_CIPHERTEXT_BYTES 1568
#define QUAC_KEM_MAX_SHARED_SECRET_BYTES 32

#define QUAC_SIG_MAX_PUBLIC_KEY_BYTES 2592
#define QUAC_SIG_MAX_SECRET_KEY_BYTES 4896
#define QUAC_SIG_MAX_SIGNATURE_BYTES 4627

    /* ==========================================================================
     * Error Codes
     * ========================================================================== */

    typedef enum
    {
        QUAC_SUCCESS = 0,
        QUAC_ERROR_INVALID_ALGORITHM = -1,
        QUAC_ERROR_INVALID_KEY = -2,
        QUAC_ERROR_INVALID_SIGNATURE = -3,
        QUAC_ERROR_INVALID_CIPHERTEXT = -4,
        QUAC_ERROR_BUFFER_TOO_SMALL = -5,
        QUAC_ERROR_HARDWARE_UNAVAILABLE = -6,
        QUAC_ERROR_INTERNAL = -7,
        QUAC_ERROR_NOT_INITIALIZED = -8,
        QUAC_ERROR_MEMORY_ALLOCATION = -9,
        QUAC_ERROR_VERIFICATION_FAILED = -10,
    } quac_error_t;

    /* ==========================================================================
     * Initialization and Cleanup
     * ========================================================================== */

    /**
     * @brief Initialize QUAC 100 integration
     *
     * Must be called before using any other QUAC functions.
     * Attempts to connect to hardware; falls back to software if unavailable.
     *
     * @return QUAC_SUCCESS on success, error code on failure
     */
    int QUAC_init(void);

    /**
     * @brief Initialize with specific options
     *
     * @param use_hardware  1 to require hardware, 0 to allow software fallback
     * @param device_index  Hardware device index (0 for first device)
     * @return QUAC_SUCCESS on success, error code on failure
     */
    int QUAC_init_ex(int use_hardware, int device_index);

    /**
     * @brief Clean up QUAC 100 resources
     */
    void QUAC_cleanup(void);

    /**
     * @brief Check if hardware acceleration is available
     *
     * @return 1 if hardware is being used, 0 if software fallback
     */
    int QUAC_is_hardware_available(void);

    /**
     * @brief Get version string
     *
     * @return Version string (e.g., "1.0.0")
     */
    const char *QUAC_version_string(void);

    /**
     * @brief Get last error message
     *
     * @return Human-readable error message
     */
    const char *QUAC_get_error_string(int error_code);

    /* ==========================================================================
     * ML-KEM (Key Encapsulation Mechanism)
     * ========================================================================== */

    /**
     * @brief Get public key size for algorithm
     */
    size_t QUAC_KEM_public_key_bytes(quac_kem_algorithm_t alg);

    /**
     * @brief Get secret key size for algorithm
     */
    size_t QUAC_KEM_secret_key_bytes(quac_kem_algorithm_t alg);

    /**
     * @brief Get ciphertext size for algorithm
     */
    size_t QUAC_KEM_ciphertext_bytes(quac_kem_algorithm_t alg);

    /**
     * @brief Get shared secret size for algorithm
     */
    size_t QUAC_KEM_shared_secret_bytes(quac_kem_algorithm_t alg);

    /**
     * @brief Generate ML-KEM keypair
     *
     * @param alg       Algorithm (ML_KEM_512, ML_KEM_768, ML_KEM_1024)
     * @param pk        Output public key buffer
     * @param sk        Output secret key buffer
     * @return QUAC_SUCCESS on success
     */
    int QUAC_KEM_keypair(quac_kem_algorithm_t alg,
                         uint8_t *pk,
                         uint8_t *sk);

    /**
     * @brief Encapsulate shared secret
     *
     * @param alg       Algorithm
     * @param ct        Output ciphertext buffer
     * @param ss        Output shared secret buffer (32 bytes)
     * @param pk        Public key
     * @return QUAC_SUCCESS on success
     */
    int QUAC_KEM_encaps(quac_kem_algorithm_t alg,
                        uint8_t *ct,
                        uint8_t *ss,
                        const uint8_t *pk);

    /**
     * @brief Decapsulate shared secret
     *
     * @param alg       Algorithm
     * @param ss        Output shared secret buffer (32 bytes)
     * @param ct        Ciphertext
     * @param sk        Secret key
     * @return QUAC_SUCCESS on success
     */
    int QUAC_KEM_decaps(quac_kem_algorithm_t alg,
                        uint8_t *ss,
                        const uint8_t *ct,
                        const uint8_t *sk);

    /* ==========================================================================
     * ML-DSA (Digital Signature Algorithm)
     * ========================================================================== */

    /**
     * @brief Get public key size for algorithm
     */
    size_t QUAC_SIG_public_key_bytes(quac_sig_algorithm_t alg);

    /**
     * @brief Get secret key size for algorithm
     */
    size_t QUAC_SIG_secret_key_bytes(quac_sig_algorithm_t alg);

    /**
     * @brief Get maximum signature size for algorithm
     */
    size_t QUAC_SIG_signature_bytes(quac_sig_algorithm_t alg);

    /**
     * @brief Generate ML-DSA keypair
     *
     * @param alg       Algorithm (ML_DSA_44, ML_DSA_65, ML_DSA_87)
     * @param pk        Output public key buffer
     * @param sk        Output secret key buffer
     * @return QUAC_SUCCESS on success
     */
    int QUAC_SIG_keypair(quac_sig_algorithm_t alg,
                         uint8_t *pk,
                         uint8_t *sk);

    /**
     * @brief Sign message
     *
     * @param alg       Algorithm
     * @param sig       Output signature buffer
     * @param sig_len   Output signature length
     * @param msg       Message to sign
     * @param msg_len   Message length
     * @param sk        Secret key
     * @return QUAC_SUCCESS on success
     */
    int QUAC_sign(quac_sig_algorithm_t alg,
                  uint8_t *sig,
                  size_t *sig_len,
                  const uint8_t *msg,
                  size_t msg_len,
                  const uint8_t *sk);

    /**
     * @brief Verify signature
     *
     * @param alg       Algorithm
     * @param sig       Signature
     * @param sig_len   Signature length
     * @param msg       Message
     * @param msg_len   Message length
     * @param pk        Public key
     * @return QUAC_SUCCESS if valid, QUAC_ERROR_VERIFICATION_FAILED if invalid
     */
    int QUAC_verify(quac_sig_algorithm_t alg,
                    const uint8_t *sig,
                    size_t sig_len,
                    const uint8_t *msg,
                    size_t msg_len,
                    const uint8_t *pk);

    /* ==========================================================================
     * QRNG (Quantum Random Number Generator)
     * ========================================================================== */

    /**
     * @brief Generate random bytes using QRNG
     *
     * Uses hardware QRNG when available, falls back to BoringSSL's RAND.
     *
     * @param buf       Output buffer
     * @param len       Number of bytes to generate
     * @return QUAC_SUCCESS on success
     */
    int QUAC_random_bytes(uint8_t *buf, size_t len);

    /**
     * @brief Add entropy to the RNG
     *
     * @param seed      Seed data
     * @param seed_len  Seed length
     * @return QUAC_SUCCESS on success
     */
    int QUAC_random_seed(const uint8_t *seed, size_t seed_len);

    /**
     * @brief Check QRNG health status
     *
     * @return 1 if healthy, 0 if degraded
     */
    int QUAC_random_health_check(void);

    /* ==========================================================================
     * Key Serialization (ASN.1/DER)
     * ========================================================================== */

    /**
     * @brief Encode public key to DER format
     *
     * @param alg       Algorithm (KEM or SIG)
     * @param pk        Public key
     * @param pk_len    Public key length
     * @param der       Output DER buffer (NULL to query size)
     * @param der_len   Input: buffer size, Output: DER length
     * @return QUAC_SUCCESS on success
     */
    int QUAC_encode_public_key_der(int alg,
                                   const uint8_t *pk,
                                   size_t pk_len,
                                   uint8_t *der,
                                   size_t *der_len);

    /**
     * @brief Decode public key from DER format
     *
     * @param der       DER-encoded key
     * @param der_len   DER length
     * @param alg       Output algorithm identifier
     * @param pk        Output public key buffer
     * @param pk_len    Input: buffer size, Output: key length
     * @return QUAC_SUCCESS on success
     */
    int QUAC_decode_public_key_der(const uint8_t *der,
                                   size_t der_len,
                                   int *alg,
                                   uint8_t *pk,
                                   size_t *pk_len);

    /**
     * @brief Encode private key to DER format (PKCS#8)
     */
    int QUAC_encode_private_key_der(int alg,
                                    const uint8_t *sk,
                                    size_t sk_len,
                                    uint8_t *der,
                                    size_t *der_len);

    /**
     * @brief Decode private key from DER format (PKCS#8)
     */
    int QUAC_decode_private_key_der(const uint8_t *der,
                                    size_t der_len,
                                    int *alg,
                                    uint8_t *sk,
                                    size_t *sk_len);

    /* ==========================================================================
     * EVP Integration (BoringSSL EVP API)
     * ========================================================================== */

    /* Forward declarations for BoringSSL types */
    struct evp_pkey_st;
    struct evp_pkey_ctx_st;
    struct evp_md_ctx_st;

    typedef struct evp_pkey_st EVP_PKEY;
    typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
    typedef struct evp_md_ctx_st EVP_MD_CTX;

    /**
     * @brief Register QUAC algorithms with BoringSSL EVP
     *
     * Call after QUAC_init() to enable EVP_PKEY-based usage.
     *
     * @return QUAC_SUCCESS on success
     */
    int QUAC_EVP_register(void);

    /**
     * @brief Create EVP_PKEY from raw ML-KEM keys
     *
     * @param alg       KEM algorithm
     * @param pk        Public key (may be NULL)
     * @param sk        Secret key (may be NULL)
     * @return New EVP_PKEY or NULL on error
     */
    EVP_PKEY *QUAC_EVP_PKEY_new_kem(quac_kem_algorithm_t alg,
                                    const uint8_t *pk,
                                    const uint8_t *sk);

    /**
     * @brief Create EVP_PKEY from raw ML-DSA keys
     *
     * @param alg       Signature algorithm
     * @param pk        Public key (may be NULL)
     * @param sk        Secret key (may be NULL)
     * @return New EVP_PKEY or NULL on error
     */
    EVP_PKEY *QUAC_EVP_PKEY_new_sig(quac_sig_algorithm_t alg,
                                    const uint8_t *pk,
                                    const uint8_t *sk);

    /**
     * @brief Extract raw keys from EVP_PKEY
     *
     * @param pkey      EVP_PKEY
     * @param pk        Output public key (may be NULL)
     * @param pk_len    Output public key length
     * @param sk        Output secret key (may be NULL)
     * @param sk_len    Output secret key length
     * @return QUAC_SUCCESS on success
     */
    int QUAC_EVP_PKEY_get_raw_keys(const EVP_PKEY *pkey,
                                   uint8_t *pk, size_t *pk_len,
                                   uint8_t *sk, size_t *sk_len);

    /* ==========================================================================
     * TLS Integration
     * ========================================================================== */

    /**
     * @brief Register hybrid key exchange groups for TLS
     *
     * Enables X25519_ML-KEM-768 and other hybrid groups for TLS 1.3.
     *
     * @return QUAC_SUCCESS on success
     */
    int QUAC_TLS_register_groups(void);

    /**
     * @brief Get supported TLS groups
     *
     * @param groups    Output array of group IDs
     * @param count     Input: array size, Output: number of groups
     * @return QUAC_SUCCESS on success
     */
    int QUAC_TLS_get_groups(quac_tls_group_t *groups, size_t *count);

    /**
     * @brief Check if a TLS group is supported
     *
     * @param group     Group ID
     * @return 1 if supported, 0 otherwise
     */
    int QUAC_TLS_group_is_supported(quac_tls_group_t group);

    /* ==========================================================================
     * Self-Test (for FIPS compliance)
     * ========================================================================== */

    /**
     * @brief Run FIPS self-tests
     *
     * Executes Known Answer Tests (KAT) for all algorithms.
     *
     * @return QUAC_SUCCESS if all tests pass
     */
    int QUAC_self_test(void);

    /**
     * @brief Check module integrity
     *
     * @return QUAC_SUCCESS if integrity check passes
     */
    int QUAC_integrity_check(void);

    /* ==========================================================================
     * Benchmark/Performance
     * ========================================================================== */

    /**
     * @brief Benchmark results structure
     */
    typedef struct
    {
        const char *algorithm;
        const char *operation;
        uint64_t iterations;
        double total_seconds;
        double ops_per_second;
        double microseconds_per_op;
    } quac_benchmark_result_t;

    /**
     * @brief Run benchmarks for an algorithm
     *
     * @param alg           Algorithm (KEM or SIG)
     * @param duration_sec  Test duration in seconds
     * @param results       Output results array
     * @param result_count  Number of result entries
     * @return QUAC_SUCCESS on success
     */
    int QUAC_benchmark(int alg, int duration_sec,
                       quac_benchmark_result_t *results,
                       size_t *result_count);

#ifdef __cplusplus
}
#endif

#endif /* QUAC100_BORINGSSL_H */