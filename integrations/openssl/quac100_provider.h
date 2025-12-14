/**
 * @file quac100_provider.h
 * @brief QUAC 100 OpenSSL Provider - Internal Header
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_PROVIDER_H
#define QUAC100_PROVIDER_H

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/types.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /* ==========================================================================
     * Provider Context
     * ========================================================================== */

    typedef struct quac_prov_ctx QUAC_PROV_CTX;

    /* Provider context access */
    QUAC_PROV_CTX *quac_prov_get_ctx(void);
    void *quac_prov_get_device(QUAC_PROV_CTX *ctx);
    int quac_prov_is_simulator(QUAC_PROV_CTX *ctx);
    const OSSL_CORE_HANDLE *quac_prov_get_handle(QUAC_PROV_CTX *ctx);
    OSSL_LIB_CTX *quac_prov_get_libctx(QUAC_PROV_CTX *ctx);

    /* Error handling */
    void quac_prov_raise_error(QUAC_PROV_CTX *ctx, int reason, const char *fmt, ...);

/* ==========================================================================
 * Algorithm Identifiers
 * ========================================================================== */

/* ML-KEM (FIPS 203) - Key Encapsulation */
#define QUAC_ALG_ML_KEM_512 "ML-KEM-512"
#define QUAC_ALG_ML_KEM_768 "ML-KEM-768"
#define QUAC_ALG_ML_KEM_1024 "ML-KEM-1024"

/* ML-DSA (FIPS 204) - Digital Signatures */
#define QUAC_ALG_ML_DSA_44 "ML-DSA-44"
#define QUAC_ALG_ML_DSA_65 "ML-DSA-65"
#define QUAC_ALG_ML_DSA_87 "ML-DSA-87"

/* SLH-DSA (FIPS 205) - Stateless Hash-Based Signatures */
#define QUAC_ALG_SLH_DSA_SHA2_128S "SLH-DSA-SHA2-128s"
#define QUAC_ALG_SLH_DSA_SHA2_128F "SLH-DSA-SHA2-128f"
#define QUAC_ALG_SLH_DSA_SHA2_192S "SLH-DSA-SHA2-192s"
#define QUAC_ALG_SLH_DSA_SHA2_192F "SLH-DSA-SHA2-192f"
#define QUAC_ALG_SLH_DSA_SHA2_256S "SLH-DSA-SHA2-256s"
#define QUAC_ALG_SLH_DSA_SHA2_256F "SLH-DSA-SHA2-256f"

/* QRNG */
#define QUAC_ALG_QRNG "QRNG"

/* ==========================================================================
 * Key Sizes (bytes)
 * ========================================================================== */

/* ML-KEM-512 */
#define QUAC_ML_KEM_512_PK_SIZE 800
#define QUAC_ML_KEM_512_SK_SIZE 1632
#define QUAC_ML_KEM_512_CT_SIZE 768
#define QUAC_ML_KEM_512_SS_SIZE 32

/* ML-KEM-768 */
#define QUAC_ML_KEM_768_PK_SIZE 1184
#define QUAC_ML_KEM_768_SK_SIZE 2400
#define QUAC_ML_KEM_768_CT_SIZE 1088
#define QUAC_ML_KEM_768_SS_SIZE 32

/* ML-KEM-1024 */
#define QUAC_ML_KEM_1024_PK_SIZE 1568
#define QUAC_ML_KEM_1024_SK_SIZE 3168
#define QUAC_ML_KEM_1024_CT_SIZE 1568
#define QUAC_ML_KEM_1024_SS_SIZE 32

/* ML-DSA-44 */
#define QUAC_ML_DSA_44_PK_SIZE 1312
#define QUAC_ML_DSA_44_SK_SIZE 2560
#define QUAC_ML_DSA_44_SIG_SIZE 2420

/* ML-DSA-65 */
#define QUAC_ML_DSA_65_PK_SIZE 1952
#define QUAC_ML_DSA_65_SK_SIZE 4032
#define QUAC_ML_DSA_65_SIG_SIZE 3309

/* ML-DSA-87 */
#define QUAC_ML_DSA_87_PK_SIZE 2592
#define QUAC_ML_DSA_87_SK_SIZE 4896
#define QUAC_ML_DSA_87_SIG_SIZE 4627

    /* ==========================================================================
     * Key Types
     * ========================================================================== */

    typedef enum
    {
        QUAC_KEY_TYPE_UNKNOWN = 0,
        QUAC_KEY_TYPE_ML_KEM_512,
        QUAC_KEY_TYPE_ML_KEM_768,
        QUAC_KEY_TYPE_ML_KEM_1024,
        QUAC_KEY_TYPE_ML_DSA_44,
        QUAC_KEY_TYPE_ML_DSA_65,
        QUAC_KEY_TYPE_ML_DSA_87,
        QUAC_KEY_TYPE_SLH_DSA_SHA2_128S,
        QUAC_KEY_TYPE_SLH_DSA_SHA2_128F,
        QUAC_KEY_TYPE_SLH_DSA_SHA2_192S,
        QUAC_KEY_TYPE_SLH_DSA_SHA2_192F,
        QUAC_KEY_TYPE_SLH_DSA_SHA2_256S,
        QUAC_KEY_TYPE_SLH_DSA_SHA2_256F,
    } quac_key_type_t;

    /* ==========================================================================
     * Key Structure
     * ========================================================================== */

    typedef struct quac_key
    {
        QUAC_PROV_CTX *provctx;
        quac_key_type_t type;

        /* Key material */
        unsigned char *pubkey;
        size_t pubkey_len;
        unsigned char *privkey;
        size_t privkey_len;

        /* Key properties */
        int has_public;
        int has_private;

        /* Reference count */
        int refcnt;
    } QUAC_KEY;

    /* Key management */
    QUAC_KEY *quac_key_new(QUAC_PROV_CTX *provctx, quac_key_type_t type);
    void quac_key_free(QUAC_KEY *key);
    int quac_key_up_ref(QUAC_KEY *key);
    QUAC_KEY *quac_key_dup(const QUAC_KEY *key);

    /* Key operations */
    int quac_key_generate(QUAC_KEY *key);
    int quac_key_set_public(QUAC_KEY *key, const unsigned char *pub, size_t len);
    int quac_key_set_private(QUAC_KEY *key, const unsigned char *priv, size_t len);
    int quac_key_get_public(const QUAC_KEY *key, unsigned char **pub, size_t *len);
    int quac_key_get_private(const QUAC_KEY *key, unsigned char **priv, size_t *len);

    /* Key type helpers */
    const char *quac_key_type_name(quac_key_type_t type);
    quac_key_type_t quac_key_type_from_name(const char *name);
    int quac_key_type_is_kem(quac_key_type_t type);
    int quac_key_type_is_sig(quac_key_type_t type);
    size_t quac_key_type_pk_size(quac_key_type_t type);
    size_t quac_key_type_sk_size(quac_key_type_t type);

    /* ==========================================================================
     * Utility Functions
     * ========================================================================== */

    /* Secure memory operations */
    void quac_cleanse(void *ptr, size_t len);
    void *quac_secure_alloc(size_t size);
    void quac_secure_free(void *ptr, size_t size);

    /* Hex encoding/decoding */
    char *quac_bin2hex(const unsigned char *bin, size_t len);
    int quac_hex2bin(const char *hex, unsigned char *bin, size_t *len);

#ifdef __cplusplus
}
#endif

#endif /* QUAC100_PROVIDER_H */