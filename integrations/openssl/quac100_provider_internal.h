/**
 * @file D:\quantacore-sdk\integrations\openssl\quac100_provider_internal.h
 * @brief QUAC 100 OpenSSL Provider - Internal Definitions
 *
 * Internal structures, OIDs, and function prototypes for the QUAC 100
 * OpenSSL 3.x provider. Not part of the public API.
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_PROVIDER_INTERNAL_H
#define QUAC100_PROVIDER_INTERNAL_H

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /* ==========================================================================
     * Version Information
     * ========================================================================== */

#define QUAC100_PROVIDER_VERSION_MAJOR 1
#define QUAC100_PROVIDER_VERSION_MINOR 0
#define QUAC100_PROVIDER_VERSION_PATCH 0
#define QUAC100_PROVIDER_VERSION_STR "1.0.0"
#define QUAC100_PROVIDER_FULL_VERSION "QUAC100 OpenSSL Provider 1.0.0"
#define QUAC100_PROVIDER_NAME "quac100"

/* ==========================================================================
 * Algorithm OIDs (NIST PQC)
 * ========================================================================== */

/* ML-KEM OIDs */
#define QUAC100_OID_ML_KEM_512 "1.3.6.1.4.1.22554.5.6.1"
#define QUAC100_OID_ML_KEM_768 "1.3.6.1.4.1.22554.5.6.2"
#define QUAC100_OID_ML_KEM_1024 "1.3.6.1.4.1.22554.5.6.3"

/* ML-DSA OIDs */
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
#define MLKEM512_PK_BYTES 800
#define MLKEM512_SK_BYTES 1632
#define MLKEM512_CT_BYTES 768
#define MLKEM512_SS_BYTES 32
#define MLKEM512_SEED_BYTES 64

/* ML-KEM-768 */
#define MLKEM768_PK_BYTES 1184
#define MLKEM768_SK_BYTES 2400
#define MLKEM768_CT_BYTES 1088
#define MLKEM768_SS_BYTES 32
#define MLKEM768_SEED_BYTES 64

/* ML-KEM-1024 */
#define MLKEM1024_PK_BYTES 1568
#define MLKEM1024_SK_BYTES 3168
#define MLKEM1024_CT_BYTES 1568
#define MLKEM1024_SS_BYTES 32
#define MLKEM1024_SEED_BYTES 64

/* ML-DSA-44 */
#define MLDSA44_PK_BYTES 1312
#define MLDSA44_SK_BYTES 2560
#define MLDSA44_SIG_BYTES 2420

/* ML-DSA-65 */
#define MLDSA65_PK_BYTES 1952
#define MLDSA65_SK_BYTES 4032
#define MLDSA65_SIG_BYTES 3309

/* ML-DSA-87 */
#define MLDSA87_PK_BYTES 2592
#define MLDSA87_SK_BYTES 4896
#define MLDSA87_SIG_BYTES 4627

    /* ==========================================================================
     * Provider Context
     * ========================================================================== */

    /**
     * @brief Main provider context
     */
    typedef struct quac100_prov_ctx_st
    {
        const OSSL_CORE_HANDLE *handle;
        OSSL_LIB_CTX *libctx;

        /* Core functions */
        OSSL_FUNC_core_gettable_params_fn *core_gettable_params;
        OSSL_FUNC_core_get_params_fn *core_get_params;
        OSSL_FUNC_core_new_error_fn *core_new_error;
        OSSL_FUNC_core_set_error_debug_fn *core_set_error_debug;
        OSSL_FUNC_core_vset_error_fn *core_vset_error;

        /* BIO functions */
        OSSL_FUNC_BIO_new_file_fn *bio_new_file;
        OSSL_FUNC_BIO_new_membuf_fn *bio_new_membuf;
        OSSL_FUNC_BIO_read_ex_fn *bio_read_ex;
        OSSL_FUNC_BIO_write_ex_fn *bio_write_ex;
        OSSL_FUNC_BIO_free_fn *bio_free;
        OSSL_FUNC_BIO_vprintf_fn *bio_vprintf;

        /* Hardware state */
        int hw_available;
        void *hw_handle;
        pthread_mutex_t hw_lock;

        /* Statistics */
        struct
        {
            uint64_t keygen_ops;
            uint64_t encaps_ops;
            uint64_t decaps_ops;
            uint64_t sign_ops;
            uint64_t verify_ops;
            uint64_t hw_ops;
            uint64_t sw_fallback;
            pthread_mutex_t lock;
        } stats;

        /* Configuration */
        int prefer_hardware;
        int fips_mode;
        char *config_file;
    } QUAC100_PROV_CTX;

    /* ==========================================================================
     * Key Structures
     * ========================================================================== */

    /**
     * @brief ML-KEM key structure
     */
    typedef struct quac100_mlkem_key_st
    {
        QUAC100_PROV_CTX *provctx;
        int level; /* 512, 768, 1024 */
        int has_private;

        /* Key material */
        unsigned char *public_key;
        size_t public_key_len;
        unsigned char *secret_key;
        size_t secret_key_len;

        /* For key generation */
        unsigned char seed[64];
        int has_seed;

        /* Reference counting */
        int refcnt;
        pthread_mutex_t lock;
    } QUAC100_MLKEM_KEY;

    /**
     * @brief ML-DSA key structure
     */
    typedef struct quac100_mldsa_key_st
    {
        QUAC100_PROV_CTX *provctx;
        int level; /* 44, 65, 87 */
        int has_private;

        /* Key material */
        unsigned char *public_key;
        size_t public_key_len;
        unsigned char *secret_key;
        size_t secret_key_len;

        /* Reference counting */
        int refcnt;
        pthread_mutex_t lock;
    } QUAC100_MLDSA_KEY;

    /* ==========================================================================
     * Operation Contexts
     * ========================================================================== */

    /**
     * @brief KEM operation context
     */
    typedef struct quac100_kem_ctx_st
    {
        QUAC100_PROV_CTX *provctx;
        QUAC100_MLKEM_KEY *key;
        int operation; /* EVP_PKEY_OP_ENCAPSULATE / DECAPSULATE */
    } QUAC100_KEM_CTX;

    /**
     * @brief Signature operation context
     */
    typedef struct quac100_sig_ctx_st
    {
        QUAC100_PROV_CTX *provctx;
        QUAC100_MLDSA_KEY *key;
        int operation; /* EVP_PKEY_OP_SIGN / VERIFY */

        /* Message accumulator for streaming */
        unsigned char *msg_buf;
        size_t msg_len;
        size_t msg_alloc;

        /* Context string (optional) */
        unsigned char *ctx_str;
        size_t ctx_str_len;
    } QUAC100_SIG_CTX;

    /**
     * @brief Key exchange context (for hybrid)
     */
    typedef struct quac100_kex_ctx_st
    {
        QUAC100_PROV_CTX *provctx;
        QUAC100_MLKEM_KEY *key;
        QUAC100_MLKEM_KEY *peer_key;

        /* Classical key (for hybrid) */
        EVP_PKEY *classical_key;
        EVP_PKEY *classical_peer;
        int classical_nid;

        /* Shared secret */
        unsigned char *secret;
        size_t secret_len;
    } QUAC100_KEX_CTX;

    /* ==========================================================================
     * Encoder/Decoder Contexts
     * ========================================================================== */

    typedef struct quac100_encoder_ctx_st
    {
        QUAC100_PROV_CTX *provctx;
        int format;      /* OSSL_KEYMGMT_SELECT_* */
        int output_type; /* DER, PEM, TEXT */
        int key_type;    /* NID */
    } QUAC100_ENCODER_CTX;

    typedef struct quac100_decoder_ctx_st
    {
        QUAC100_PROV_CTX *provctx;
        int input_type; /* DER, PEM */
        int key_type;   /* NID or 0 for auto */
    } QUAC100_DECODER_CTX;

    /* ==========================================================================
     * Internal Function Prototypes - Provider
     * ========================================================================== */

    QUAC100_PROV_CTX *quac100_prov_ctx_new(const OSSL_CORE_HANDLE *handle,
                                           const OSSL_DISPATCH *in);
    void quac100_prov_ctx_free(QUAC100_PROV_CTX *ctx);

    /* ==========================================================================
     * Internal Function Prototypes - ML-KEM
     * ========================================================================== */

    QUAC100_MLKEM_KEY *quac100_mlkem_key_new(QUAC100_PROV_CTX *provctx, int level);
    void quac100_mlkem_key_free(QUAC100_MLKEM_KEY *key);
    QUAC100_MLKEM_KEY *quac100_mlkem_key_dup(const QUAC100_MLKEM_KEY *key);
    int quac100_mlkem_key_up_ref(QUAC100_MLKEM_KEY *key);

    int quac100_mlkem_keygen(QUAC100_MLKEM_KEY *key);
    int quac100_mlkem_keygen_from_seed(QUAC100_MLKEM_KEY *key,
                                       const unsigned char *seed, size_t seed_len);
    int quac100_mlkem_encaps(QUAC100_MLKEM_KEY *key,
                             unsigned char *ct, size_t *ct_len,
                             unsigned char *ss, size_t *ss_len);
    int quac100_mlkem_decaps(QUAC100_MLKEM_KEY *key,
                             const unsigned char *ct, size_t ct_len,
                             unsigned char *ss, size_t *ss_len);

    size_t quac100_mlkem_pk_size(int level);
    size_t quac100_mlkem_sk_size(int level);
    size_t quac100_mlkem_ct_size(int level);
    size_t quac100_mlkem_ss_size(int level);

    /* ==========================================================================
     * Internal Function Prototypes - ML-DSA
     * ========================================================================== */

    QUAC100_MLDSA_KEY *quac100_mldsa_key_new(QUAC100_PROV_CTX *provctx, int level);
    void quac100_mldsa_key_free(QUAC100_MLDSA_KEY *key);
    QUAC100_MLDSA_KEY *quac100_mldsa_key_dup(const QUAC100_MLDSA_KEY *key);
    int quac100_mldsa_key_up_ref(QUAC100_MLDSA_KEY *key);

    int quac100_mldsa_keygen(QUAC100_MLDSA_KEY *key);
    int quac100_mldsa_sign(QUAC100_MLDSA_KEY *key,
                           unsigned char *sig, size_t *sig_len,
                           const unsigned char *msg, size_t msg_len,
                           const unsigned char *ctx, size_t ctx_len);
    int quac100_mldsa_verify(QUAC100_MLDSA_KEY *key,
                             const unsigned char *sig, size_t sig_len,
                             const unsigned char *msg, size_t msg_len,
                             const unsigned char *ctx, size_t ctx_len);

    size_t quac100_mldsa_pk_size(int level);
    size_t quac100_mldsa_sk_size(int level);
    size_t quac100_mldsa_sig_size(int level);

    /* ==========================================================================
     * Internal Function Prototypes - Hardware
     * ========================================================================== */

    int quac100_hw_init(QUAC100_PROV_CTX *ctx);
    void quac100_hw_cleanup(QUAC100_PROV_CTX *ctx);
    int quac100_hw_available(QUAC100_PROV_CTX *ctx);

    int quac100_hw_mlkem_keygen(QUAC100_PROV_CTX *ctx, int level,
                                unsigned char *pk, unsigned char *sk);
    int quac100_hw_mlkem_encaps(QUAC100_PROV_CTX *ctx, int level,
                                const unsigned char *pk,
                                unsigned char *ct, unsigned char *ss);
    int quac100_hw_mlkem_decaps(QUAC100_PROV_CTX *ctx, int level,
                                const unsigned char *sk,
                                const unsigned char *ct, unsigned char *ss);

    int quac100_hw_mldsa_keygen(QUAC100_PROV_CTX *ctx, int level,
                                unsigned char *pk, unsigned char *sk);
    int quac100_hw_mldsa_sign(QUAC100_PROV_CTX *ctx, int level,
                              const unsigned char *sk,
                              const unsigned char *msg, size_t msg_len,
                              unsigned char *sig, size_t *sig_len);
    int quac100_hw_mldsa_verify(QUAC100_PROV_CTX *ctx, int level,
                                const unsigned char *pk,
                                const unsigned char *msg, size_t msg_len,
                                const unsigned char *sig, size_t sig_len);

    /* ==========================================================================
     * Internal Function Prototypes - RAND
     * ========================================================================== */

    int quac100_rand_bytes(QUAC100_PROV_CTX *ctx, unsigned char *buf, size_t len);
    int quac100_rand_seed(QUAC100_PROV_CTX *ctx,
                          const unsigned char *seed, size_t seed_len);

    /* ==========================================================================
     * Internal Function Prototypes - Utilities
     * ========================================================================== */

    void quac100_secure_clear(void *ptr, size_t len);
    int quac100_constant_time_compare(const unsigned char *a,
                                      const unsigned char *b, size_t len);
    void quac100_stats_inc(QUAC100_PROV_CTX *ctx, uint64_t *counter);

    /* Error reporting */
    void quac100_raise_error(QUAC100_PROV_CTX *ctx, int reason,
                             const char *file, int line, const char *func,
                             const char *fmt, ...);

#define QUAC100_RAISE_ERROR(ctx, reason, ...) \
    quac100_raise_error((ctx), (reason), __FILE__, __LINE__, __func__, __VA_ARGS__)

    /* ==========================================================================
     * Dispatch Tables (declared in respective .c files)
     * ========================================================================== */

    extern const OSSL_DISPATCH quac100_mlkem512_keymgmt_functions[];
    extern const OSSL_DISPATCH quac100_mlkem768_keymgmt_functions[];
    extern const OSSL_DISPATCH quac100_mlkem1024_keymgmt_functions[];

    extern const OSSL_DISPATCH quac100_mldsa44_keymgmt_functions[];
    extern const OSSL_DISPATCH quac100_mldsa65_keymgmt_functions[];
    extern const OSSL_DISPATCH quac100_mldsa87_keymgmt_functions[];

    extern const OSSL_DISPATCH quac100_mlkem_kem_functions[];
    extern const OSSL_DISPATCH quac100_mldsa_signature_functions[];
    extern const OSSL_DISPATCH quac100_keyexch_functions[];

    extern const OSSL_DISPATCH quac100_encoder_functions[];
    extern const OSSL_DISPATCH quac100_decoder_functions[];

    extern const OSSL_DISPATCH quac100_rand_functions[];
    extern const OSSL_DISPATCH quac100_store_functions[];

    /* ==========================================================================
     * Algorithm Names
     * ========================================================================== */

#define QUAC100_ALG_MLKEM512 "ML-KEM-512"
#define QUAC100_ALG_MLKEM768 "ML-KEM-768"
#define QUAC100_ALG_MLKEM1024 "ML-KEM-1024"
#define QUAC100_ALG_MLDSA44 "ML-DSA-44"
#define QUAC100_ALG_MLDSA65 "ML-DSA-65"
#define QUAC100_ALG_MLDSA87 "ML-DSA-87"

/* Aliases for compatibility */
#define QUAC100_ALG_KYBER512 "Kyber512"
#define QUAC100_ALG_KYBER768 "Kyber768"
#define QUAC100_ALG_KYBER1024 "Kyber1024"
#define QUAC100_ALG_DILITHIUM2 "Dilithium2"
#define QUAC100_ALG_DILITHIUM3 "Dilithium3"
#define QUAC100_ALG_DILITHIUM5 "Dilithium5"

#ifdef __cplusplus
}
#endif

#endif /* QUAC100_PROVIDER_INTERNAL_H */