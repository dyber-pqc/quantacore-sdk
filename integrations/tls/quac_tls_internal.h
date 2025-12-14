/**
 * @file quac_tls_internal.h
 * @brief QUAC 100 TLS Integration - Internal Definitions
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC_TLS_INTERNAL_H
#define QUAC_TLS_INTERNAL_H

#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "quac_tls.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /* ==========================================================================
     * Internal Structure Definitions
     * ========================================================================== */

    /**
     * @brief TLS Context internal structure
     */
    struct quac_tls_ctx_st
    {
        SSL_CTX *ssl_ctx;
        int is_server;
        quac_tls_config_t config;

        /* ML-DSA configuration */
        int mldsa_level;

        /* Callbacks */
        quac_tls_verify_cb verify_cb;
        void *verify_cb_data;
        quac_tls_sni_cb sni_cb;
        void *sni_cb_data;
        quac_tls_alpn_cb alpn_cb;
        void *alpn_cb_data;
        quac_tls_ticket_cb ticket_cb;
        void *ticket_cb_data;

        /* Statistics */
        quac_tls_stats_t stats;
        pthread_mutex_t stats_lock;
    };

    /**
     * @brief TLS Connection internal structure
     */
    struct quac_tls_conn_st
    {
        SSL *ssl;
        quac_tls_ctx_t *ctx;
        int fd;

        /* State */
        int handshake_complete;

        /* SNI */
        char *server_name;

        /* ALPN */
        char *alpn_selected;

        /* Peer certificate */
        X509 *peer_cert;

        /* User data */
        void *user_data;
    };

    /**
     * @brief Certificate internal structure
     */
    struct quac_tls_cert_st
    {
        X509 *x509;
    };

    /**
     * @brief Private key internal structure
     */
    struct quac_tls_key_st
    {
        EVP_PKEY *pkey;
    };

    /**
     * @brief Session internal structure
     */
    struct quac_tls_session_st
    {
        SSL_SESSION *session;
    };

    /* ==========================================================================
     * PQC Algorithm Registration
     * ========================================================================== */

    /**
     * @brief Register PQC algorithms with OpenSSL
     */
    void quac_tls_register_pqc_algorithms(void);

    /**
     * @brief Configure cipher suites
     */
    void quac_tls_configure_ciphers(quac_tls_ctx_t *ctx, const quac_tls_config_t *config);

    /**
     * @brief Configure key exchange groups (including PQC hybrids)
     */
    void quac_tls_configure_groups(quac_tls_ctx_t *ctx, const quac_tls_config_t *config);

    /**
     * @brief Configure signature algorithms
     */
    void quac_tls_configure_sigalgs(quac_tls_ctx_t *ctx, const quac_tls_config_t *config);

    /**
     * @brief Configure ALPN protocols
     */
    void quac_tls_configure_alpn(quac_tls_ctx_t *ctx, const char *protocols);

    /* ==========================================================================
     * Hardware Acceleration
     * ========================================================================== */

#ifdef QUAC_HAS_HARDWARE

    /**
     * @brief ML-KEM encapsulation using hardware
     */
    int quac_tls_hw_mlkem_encaps(int level, const uint8_t *pk, size_t pk_len,
                                 uint8_t *ct, size_t *ct_len,
                                 uint8_t *ss, size_t *ss_len);

    /**
     * @brief ML-KEM decapsulation using hardware
     */
    int quac_tls_hw_mlkem_decaps(int level, const uint8_t *sk, size_t sk_len,
                                 const uint8_t *ct, size_t ct_len,
                                 uint8_t *ss, size_t *ss_len);

    /**
     * @brief ML-DSA signing using hardware
     */
    int quac_tls_hw_mldsa_sign(int level, const uint8_t *sk, size_t sk_len,
                               const uint8_t *msg, size_t msg_len,
                               uint8_t *sig, size_t *sig_len);

    /**
     * @brief ML-DSA verification using hardware
     */
    int quac_tls_hw_mldsa_verify(int level, const uint8_t *pk, size_t pk_len,
                                 const uint8_t *msg, size_t msg_len,
                                 const uint8_t *sig, size_t sig_len);

#endif /* QUAC_HAS_HARDWARE */

/* ==========================================================================
 * OID Definitions for PQC
 * ========================================================================== */

/* ML-KEM OIDs (NIST) */
#define QUAC_OID_ML_KEM_512 "1.3.6.1.4.1.22554.5.6.1"
#define QUAC_OID_ML_KEM_768 "1.3.6.1.4.1.22554.5.6.2"
#define QUAC_OID_ML_KEM_1024 "1.3.6.1.4.1.22554.5.6.3"

/* ML-DSA OIDs (NIST) */
#define QUAC_OID_ML_DSA_44 "1.3.6.1.4.1.22554.5.7.1"
#define QUAC_OID_ML_DSA_65 "1.3.6.1.4.1.22554.5.7.2"
#define QUAC_OID_ML_DSA_87 "1.3.6.1.4.1.22554.5.7.3"

/* Hybrid KEX Group IDs (draft-ietf-tls-hybrid-design) */
#define QUAC_GROUP_X25519_ML_KEM_768 0x4588
#define QUAC_GROUP_P256_ML_KEM_768 0x4589
#define QUAC_GROUP_P384_ML_KEM_1024 0x458A

/* Signature Algorithm IDs */
#define QUAC_SIGALG_ML_DSA_44 0x0901
#define QUAC_SIGALG_ML_DSA_65 0x0902
#define QUAC_SIGALG_ML_DSA_87 0x0903

/* ==========================================================================
 * Key Sizes
 * ========================================================================== */

/* ML-KEM key sizes */
#define ML_KEM_512_PUBLIC_KEY_LEN 800
#define ML_KEM_512_SECRET_KEY_LEN 1632
#define ML_KEM_512_CIPHERTEXT_LEN 768
#define ML_KEM_768_PUBLIC_KEY_LEN 1184
#define ML_KEM_768_SECRET_KEY_LEN 2400
#define ML_KEM_768_CIPHERTEXT_LEN 1088
#define ML_KEM_1024_PUBLIC_KEY_LEN 1568
#define ML_KEM_1024_SECRET_KEY_LEN 3168
#define ML_KEM_1024_CIPHERTEXT_LEN 1568
#define ML_KEM_SHARED_SECRET_LEN 32

/* ML-DSA key sizes */
#define ML_DSA_44_PUBLIC_KEY_LEN 1312
#define ML_DSA_44_SECRET_KEY_LEN 2560
#define ML_DSA_44_SIGNATURE_LEN 2420
#define ML_DSA_65_PUBLIC_KEY_LEN 1952
#define ML_DSA_65_SECRET_KEY_LEN 4032
#define ML_DSA_65_SIGNATURE_LEN 3309
#define ML_DSA_87_PUBLIC_KEY_LEN 2592
#define ML_DSA_87_SECRET_KEY_LEN 4896
#define ML_DSA_87_SIGNATURE_LEN 4627

#ifdef __cplusplus
}
#endif

#endif /* QUAC_TLS_INTERNAL_H */