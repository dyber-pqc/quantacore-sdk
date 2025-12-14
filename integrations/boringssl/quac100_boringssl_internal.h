/**
 * @file D:\quantacore-sdk\integrations\boringssl\quac100_boringssl_internal.h
 * @brief QUAC 100 BoringSSL Integration - Internal Definitions
 *
 * Internal structures and functions for the QUAC 100 BoringSSL provider.
 * This file is not part of the public API.
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_BORINGSSL_INTERNAL_H
#define QUAC100_BORINGSSL_INTERNAL_H

#include "quac100_boringssl.h"
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /* ==========================================================================
     * Version and Build Info
     * ========================================================================== */

#define QUAC100_BORINGSSL_VERSION_MAJOR 1
#define QUAC100_BORINGSSL_VERSION_MINOR 0
#define QUAC100_BORINGSSL_VERSION_PATCH 0
#define QUAC100_BORINGSSL_VERSION_STRING "1.0.0"

    /* ==========================================================================
     * Compile-time Configuration
     * ========================================================================== */

#ifndef QUAC100_MAX_CONTEXTS
#define QUAC100_MAX_CONTEXTS 256
#endif

#ifndef QUAC100_MAX_CONNECTIONS
#define QUAC100_MAX_CONNECTIONS 4096
#endif

#ifndef QUAC100_ENTROPY_POOL_SIZE
#define QUAC100_ENTROPY_POOL_SIZE 4096
#endif

/* ==========================================================================
 * Algorithm OIDs
 * ========================================================================== */

/* ML-KEM OIDs (NIST) */
#define QUAC100_OID_ML_KEM_512 "1.3.6.1.4.1.22554.5.6.1"
#define QUAC100_OID_ML_KEM_768 "1.3.6.1.4.1.22554.5.6.2"
#define QUAC100_OID_ML_KEM_1024 "1.3.6.1.4.1.22554.5.6.3"

/* ML-DSA OIDs (NIST) */
#define QUAC100_OID_ML_DSA_44 "1.3.6.1.4.1.22554.5.7.1"
#define QUAC100_OID_ML_DSA_65 "1.3.6.1.4.1.22554.5.7.2"
#define QUAC100_OID_ML_DSA_87 "1.3.6.1.4.1.22554.5.7.3"

/* Hybrid KEX OIDs */
#define QUAC100_OID_X25519_ML_KEM_768 "1.3.6.1.4.1.22554.5.8.1"
#define QUAC100_OID_P256_ML_KEM_768 "1.3.6.1.4.1.22554.5.8.2"
#define QUAC100_OID_P384_ML_KEM_1024 "1.3.6.1.4.1.22554.5.8.3"

/* ==========================================================================
 * Algorithm Parameters
 * ========================================================================== */

/* ML-KEM-512 */
#define MLKEM512_PUBLIC_KEY_BYTES 800
#define MLKEM512_SECRET_KEY_BYTES 1632
#define MLKEM512_CIPHERTEXT_BYTES 768
#define MLKEM512_SHARED_SECRET_BYTES 32

/* ML-KEM-768 */
#define MLKEM768_PUBLIC_KEY_BYTES 1184
#define MLKEM768_SECRET_KEY_BYTES 2400
#define MLKEM768_CIPHERTEXT_BYTES 1088
#define MLKEM768_SHARED_SECRET_BYTES 32

/* ML-KEM-1024 */
#define MLKEM1024_PUBLIC_KEY_BYTES 1568
#define MLKEM1024_SECRET_KEY_BYTES 3168
#define MLKEM1024_CIPHERTEXT_BYTES 1568
#define MLKEM1024_SHARED_SECRET_BYTES 32

/* ML-DSA-44 */
#define MLDSA44_PUBLIC_KEY_BYTES 1312
#define MLDSA44_SECRET_KEY_BYTES 2560
#define MLDSA44_SIGNATURE_BYTES 2420

/* ML-DSA-65 */
#define MLDSA65_PUBLIC_KEY_BYTES 1952
#define MLDSA65_SECRET_KEY_BYTES 4032
#define MLDSA65_SIGNATURE_BYTES 3309

/* ML-DSA-87 */
#define MLDSA87_PUBLIC_KEY_BYTES 2592
#define MLDSA87_SECRET_KEY_BYTES 4896
#define MLDSA87_SIGNATURE_BYTES 4627

    /* ==========================================================================
     * Internal Structures
     * ========================================================================== */

    /**
     * @brief Hardware device context
     */
    typedef struct quac100_hw_ctx_st
    {
        int device_id;
        int slot;
        int is_open;
        void *hw_handle;
        pthread_mutex_t lock;
    } QUAC100_HW_CTX;

    /**
     * @brief ML-KEM key pair structure
     */
    typedef struct quac100_mlkem_key_st
    {
        int level; /* 512, 768, or 1024 */
        uint8_t *public_key;
        size_t public_key_len;
        uint8_t *secret_key;
        size_t secret_key_len;
        int has_private;
        QUAC100_HW_CTX *hw_ctx; /* NULL for software */
    } QUAC100_MLKEM_KEY;

    /**
     * @brief ML-DSA key pair structure
     */
    typedef struct quac100_mldsa_key_st
    {
        int level; /* 44, 65, or 87 */
        uint8_t *public_key;
        size_t public_key_len;
        uint8_t *secret_key;
        size_t secret_key_len;
        int has_private;
        QUAC100_HW_CTX *hw_ctx; /* NULL for software */
    } QUAC100_MLDSA_KEY;

    /**
     * @brief Hybrid KEX context
     */
    typedef struct quac100_hybrid_kex_st
    {
        int classical_nid; /* NID_X25519, NID_X9_62_prime256v1, etc. */
        int pqc_level;     /* ML-KEM level */
        EVP_PKEY *classical_key;
        QUAC100_MLKEM_KEY *pqc_key;
        uint8_t *combined_secret;
        size_t combined_secret_len;
    } QUAC100_HYBRID_KEX;

    /**
     * @brief Statistics tracking
     */
    typedef struct quac100_stats_st
    {
        uint64_t mlkem_keygen_count;
        uint64_t mlkem_encaps_count;
        uint64_t mlkem_decaps_count;
        uint64_t mldsa_keygen_count;
        uint64_t mldsa_sign_count;
        uint64_t mldsa_verify_count;
        uint64_t hw_operations;
        uint64_t sw_fallback_count;
        uint64_t bytes_encrypted;
        uint64_t bytes_decrypted;
        uint64_t handshakes_completed;
        uint64_t handshakes_failed;
        pthread_mutex_t lock;
    } QUAC100_STATS;

    /**
     * @brief Global library state
     */
    typedef struct quac100_global_st
    {
        int initialized;
        int hw_available;
        QUAC100_HW_CTX *hw_ctx;
        QUAC100_STATS stats;
        pthread_mutex_t init_lock;

        /* Registered NIDs */
        int nid_mlkem512;
        int nid_mlkem768;
        int nid_mlkem1024;
        int nid_mldsa44;
        int nid_mldsa65;
        int nid_mldsa87;
        int nid_x25519_mlkem768;
        int nid_p256_mlkem768;
        int nid_p384_mlkem1024;

        /* EVP methods */
        EVP_PKEY_METHOD *mlkem_pmeth;
        EVP_PKEY_METHOD *mldsa_pmeth;
        EVP_PKEY_ASN1_METHOD *mlkem_ameth;
        EVP_PKEY_ASN1_METHOD *mldsa_ameth;
    } QUAC100_GLOBAL;

    /* Global state (defined in quac100_boringssl.c) */
    extern QUAC100_GLOBAL g_quac100;

    /* ==========================================================================
     * Internal Functions - Hardware
     * ========================================================================== */

    int quac100_hw_init(QUAC100_HW_CTX *ctx, int device_id, int slot);
    void quac100_hw_cleanup(QUAC100_HW_CTX *ctx);
    int quac100_hw_available(void);

    int quac100_hw_mlkem_keygen(QUAC100_HW_CTX *ctx, int level,
                                uint8_t *pk, size_t *pk_len,
                                uint8_t *sk, size_t *sk_len);
    int quac100_hw_mlkem_encaps(QUAC100_HW_CTX *ctx, int level,
                                const uint8_t *pk, size_t pk_len,
                                uint8_t *ct, size_t *ct_len,
                                uint8_t *ss, size_t *ss_len);
    int quac100_hw_mlkem_decaps(QUAC100_HW_CTX *ctx, int level,
                                const uint8_t *sk, size_t sk_len,
                                const uint8_t *ct, size_t ct_len,
                                uint8_t *ss, size_t *ss_len);

    int quac100_hw_mldsa_keygen(QUAC100_HW_CTX *ctx, int level,
                                uint8_t *pk, size_t *pk_len,
                                uint8_t *sk, size_t *sk_len);
    int quac100_hw_mldsa_sign(QUAC100_HW_CTX *ctx, int level,
                              const uint8_t *sk, size_t sk_len,
                              const uint8_t *msg, size_t msg_len,
                              uint8_t *sig, size_t *sig_len);
    int quac100_hw_mldsa_verify(QUAC100_HW_CTX *ctx, int level,
                                const uint8_t *pk, size_t pk_len,
                                const uint8_t *msg, size_t msg_len,
                                const uint8_t *sig, size_t sig_len);

    /* ==========================================================================
     * Internal Functions - Software Fallback
     * ========================================================================== */

    int quac100_sw_mlkem_keygen(int level,
                                uint8_t *pk, size_t *pk_len,
                                uint8_t *sk, size_t *sk_len);
    int quac100_sw_mlkem_encaps(int level,
                                const uint8_t *pk, size_t pk_len,
                                uint8_t *ct, size_t *ct_len,
                                uint8_t *ss, size_t *ss_len);
    int quac100_sw_mlkem_decaps(int level,
                                const uint8_t *sk, size_t sk_len,
                                const uint8_t *ct, size_t ct_len,
                                uint8_t *ss, size_t *ss_len);

    int quac100_sw_mldsa_keygen(int level,
                                uint8_t *pk, size_t *pk_len,
                                uint8_t *sk, size_t *sk_len);
    int quac100_sw_mldsa_sign(int level,
                              const uint8_t *sk, size_t sk_len,
                              const uint8_t *msg, size_t msg_len,
                              uint8_t *sig, size_t *sig_len);
    int quac100_sw_mldsa_verify(int level,
                                const uint8_t *pk, size_t pk_len,
                                const uint8_t *msg, size_t msg_len,
                                const uint8_t *sig, size_t sig_len);

    /* ==========================================================================
     * Internal Functions - EVP Integration
     * ========================================================================== */

    int quac100_register_nids(void);
    int quac100_register_mlkem_pmeth(void);
    int quac100_register_mldsa_pmeth(void);
    int quac100_register_asn1_meths(void);

    /* EVP_PKEY data getters */
    QUAC100_MLKEM_KEY *quac100_evp_pkey_get_mlkem(EVP_PKEY *pkey);
    QUAC100_MLDSA_KEY *quac100_evp_pkey_get_mldsa(EVP_PKEY *pkey);

    /* EVP_PKEY data setters */
    int quac100_evp_pkey_set_mlkem(EVP_PKEY *pkey, QUAC100_MLKEM_KEY *key);
    int quac100_evp_pkey_set_mldsa(EVP_PKEY *pkey, QUAC100_MLDSA_KEY *key);

    /* ==========================================================================
     * Internal Functions - TLS Integration
     * ========================================================================== */

    int quac100_tls_register_kex_groups(SSL_CTX *ctx);
    int quac100_tls_register_sigalgs(SSL_CTX *ctx);
    int quac100_tls_kex_generate(SSL *ssl, int group_id,
                                 uint8_t **out_public_key, size_t *out_public_key_len);
    int quac100_tls_kex_encap(SSL *ssl, int group_id,
                              const uint8_t *peer_public_key, size_t peer_public_key_len,
                              uint8_t **out_ciphertext, size_t *out_ciphertext_len,
                              uint8_t **out_secret, size_t *out_secret_len);
    int quac100_tls_kex_decap(SSL *ssl, int group_id,
                              const uint8_t *ciphertext, size_t ciphertext_len,
                              uint8_t **out_secret, size_t *out_secret_len);

    /* ==========================================================================
     * Internal Functions - Utilities
     * ========================================================================== */

    void quac100_stats_increment(uint64_t *counter);
    void quac100_secure_zero(void *ptr, size_t len);
    int quac100_constant_time_compare(const uint8_t *a, const uint8_t *b, size_t len);
    void quac100_log(int level, const char *fmt, ...);

    /* Key size helpers */
    size_t quac100_mlkem_pk_size(int level);
    size_t quac100_mlkem_sk_size(int level);
    size_t quac100_mlkem_ct_size(int level);
    size_t quac100_mldsa_pk_size(int level);
    size_t quac100_mldsa_sk_size(int level);
    size_t quac100_mldsa_sig_size(int level);

    /* ==========================================================================
     * Memory Management
     * ========================================================================== */

    QUAC100_MLKEM_KEY *quac100_mlkem_key_new(int level);
    void quac100_mlkem_key_free(QUAC100_MLKEM_KEY *key);
    QUAC100_MLKEM_KEY *quac100_mlkem_key_dup(const QUAC100_MLKEM_KEY *key);

    QUAC100_MLDSA_KEY *quac100_mldsa_key_new(int level);
    void quac100_mldsa_key_free(QUAC100_MLDSA_KEY *key);
    QUAC100_MLDSA_KEY *quac100_mldsa_key_dup(const QUAC100_MLDSA_KEY *key);

    QUAC100_HYBRID_KEX *quac100_hybrid_kex_new(int classical_nid, int pqc_level);
    void quac100_hybrid_kex_free(QUAC100_HYBRID_KEX *kex);

#ifdef __cplusplus
}
#endif

#endif /* QUAC100_BORINGSSL_INTERNAL_H */