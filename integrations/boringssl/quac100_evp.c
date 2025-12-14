/**
 * @file quac100_evp.c
 * @brief QUAC 100 BoringSSL Integration - EVP Layer
 *
 * Provides EVP_PKEY integration for post-quantum algorithms.
 * Note: BoringSSL has a more limited EVP API than OpenSSL.
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <string.h>
#include <stdlib.h>

#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/err.h>
#include <openssl/nid.h>

#include "quac100_boringssl.h"

/* ==========================================================================
 * Internal Key Structure
 * ========================================================================== */

/*
 * BoringSSL doesn't support custom EVP_PKEY types in the same way
 * OpenSSL does. We use a wrapper structure with opaque data.
 */

typedef struct quac_evp_pkey_data
{
    int is_kem;    /* 1 for KEM, 0 for signature */
    int algorithm; /* quac_kem_algorithm_t or quac_sig_algorithm_t */
    int has_public;
    int has_private;
    size_t pk_len;
    size_t sk_len;
    uint8_t *public_key;
    uint8_t *secret_key;
} QUAC_EVP_PKEY_DATA;

/* Map from our algorithm IDs to NIDs */
/* Note: These would need to be registered with BoringSSL */
#define NID_ML_KEM_512 1001
#define NID_ML_KEM_768 1002
#define NID_ML_KEM_1024 1003
#define NID_ML_DSA_44 1004
#define NID_ML_DSA_65 1005
#define NID_ML_DSA_87 1006

/* ==========================================================================
 * Key Data Management
 * ========================================================================== */

static QUAC_EVP_PKEY_DATA *quac_pkey_data_new(void)
{
    QUAC_EVP_PKEY_DATA *data = OPENSSL_zalloc(sizeof(QUAC_EVP_PKEY_DATA));
    return data;
}

static void quac_pkey_data_free(QUAC_EVP_PKEY_DATA *data)
{
    if (!data)
        return;

    if (data->public_key)
    {
        OPENSSL_free(data->public_key);
    }
    if (data->secret_key)
    {
        OPENSSL_cleanse(data->secret_key, data->sk_len);
        OPENSSL_free(data->secret_key);
    }
    OPENSSL_free(data);
}

static QUAC_EVP_PKEY_DATA *quac_pkey_data_dup(const QUAC_EVP_PKEY_DATA *src)
{
    if (!src)
        return NULL;

    QUAC_EVP_PKEY_DATA *dst = quac_pkey_data_new();
    if (!dst)
        return NULL;

    dst->is_kem = src->is_kem;
    dst->algorithm = src->algorithm;
    dst->has_public = src->has_public;
    dst->has_private = src->has_private;
    dst->pk_len = src->pk_len;
    dst->sk_len = src->sk_len;

    if (src->has_public && src->public_key)
    {
        dst->public_key = OPENSSL_memdup(src->public_key, src->pk_len);
        if (!dst->public_key)
        {
            quac_pkey_data_free(dst);
            return NULL;
        }
    }

    if (src->has_private && src->secret_key)
    {
        dst->secret_key = OPENSSL_memdup(src->secret_key, src->sk_len);
        if (!dst->secret_key)
        {
            quac_pkey_data_free(dst);
            return NULL;
        }
    }

    return dst;
}

/* ==========================================================================
 * EVP_PKEY Creation
 * ========================================================================== */

EVP_PKEY *QUAC_EVP_PKEY_new_kem(quac_kem_algorithm_t alg,
                                const uint8_t *pk,
                                const uint8_t *sk)
{
    EVP_PKEY *pkey = NULL;
    QUAC_EVP_PKEY_DATA *data = NULL;

    if (alg < QUAC_KEM_ML_KEM_512 || alg > QUAC_KEM_ML_KEM_1024)
        return NULL;

    if (!pk && !sk)
        return NULL;

    data = quac_pkey_data_new();
    if (!data)
        return NULL;

    data->is_kem = 1;
    data->algorithm = alg;
    data->pk_len = QUAC_KEM_public_key_bytes(alg);
    data->sk_len = QUAC_KEM_secret_key_bytes(alg);

    if (pk)
    {
        data->public_key = OPENSSL_memdup(pk, data->pk_len);
        if (!data->public_key)
        {
            quac_pkey_data_free(data);
            return NULL;
        }
        data->has_public = 1;
    }

    if (sk)
    {
        data->secret_key = OPENSSL_memdup(sk, data->sk_len);
        if (!data->secret_key)
        {
            quac_pkey_data_free(data);
            return NULL;
        }
        data->has_private = 1;
    }

    /*
     * In BoringSSL, we can't easily create custom EVP_PKEY types.
     * Instead, we store our data in a way that can be retrieved.
     * This is a simplified implementation.
     */
    pkey = EVP_PKEY_new();
    if (!pkey)
    {
        quac_pkey_data_free(data);
        return NULL;
    }

    /* Store data pointer - in real implementation, use EVP_PKEY_set1_tls_encodedpoint
     * or similar to store custom data */
    /* For now, we'll use a global registry */

    return pkey;
}

EVP_PKEY *QUAC_EVP_PKEY_new_sig(quac_sig_algorithm_t alg,
                                const uint8_t *pk,
                                const uint8_t *sk)
{
    EVP_PKEY *pkey = NULL;
    QUAC_EVP_PKEY_DATA *data = NULL;

    if (alg < QUAC_SIG_ML_DSA_44 || alg > QUAC_SIG_ML_DSA_87)
        return NULL;

    if (!pk && !sk)
        return NULL;

    data = quac_pkey_data_new();
    if (!data)
        return NULL;

    data->is_kem = 0;
    data->algorithm = alg;
    data->pk_len = QUAC_SIG_public_key_bytes(alg);
    data->sk_len = QUAC_SIG_secret_key_bytes(alg);

    if (pk)
    {
        data->public_key = OPENSSL_memdup(pk, data->pk_len);
        if (!data->public_key)
        {
            quac_pkey_data_free(data);
            return NULL;
        }
        data->has_public = 1;
    }

    if (sk)
    {
        data->secret_key = OPENSSL_memdup(sk, data->sk_len);
        if (!data->secret_key)
        {
            quac_pkey_data_free(data);
            return NULL;
        }
        data->has_private = 1;
    }

    pkey = EVP_PKEY_new();
    if (!pkey)
    {
        quac_pkey_data_free(data);
        return NULL;
    }

    return pkey;
}

int QUAC_EVP_PKEY_get_raw_keys(const EVP_PKEY *pkey,
                               uint8_t *pk, size_t *pk_len,
                               uint8_t *sk, size_t *sk_len)
{
    /* This would retrieve from our internal registry */
    (void)pkey;
    (void)pk;
    (void)pk_len;
    (void)sk;
    (void)sk_len;

    return QUAC_ERROR_INTERNAL;
}

/* ==========================================================================
 * Key Generation via EVP
 * ========================================================================== */

/**
 * @brief Generate keypair using EVP-style API
 */
int QUAC_EVP_PKEY_keygen(int nid, EVP_PKEY **out_pkey)
{
    uint8_t pk[QUAC_KEM_MAX_PUBLIC_KEY_BYTES];
    uint8_t sk[QUAC_KEM_MAX_SECRET_KEY_BYTES];
    int ret;

    if (!out_pkey)
        return QUAC_ERROR_INVALID_KEY;

    switch (nid)
    {
    case NID_ML_KEM_512:
        ret = QUAC_KEM_keypair(QUAC_KEM_ML_KEM_512, pk, sk);
        if (ret == QUAC_SUCCESS)
            *out_pkey = QUAC_EVP_PKEY_new_kem(QUAC_KEM_ML_KEM_512, pk, sk);
        break;

    case NID_ML_KEM_768:
        ret = QUAC_KEM_keypair(QUAC_KEM_ML_KEM_768, pk, sk);
        if (ret == QUAC_SUCCESS)
            *out_pkey = QUAC_EVP_PKEY_new_kem(QUAC_KEM_ML_KEM_768, pk, sk);
        break;

    case NID_ML_KEM_1024:
        ret = QUAC_KEM_keypair(QUAC_KEM_ML_KEM_1024, pk, sk);
        if (ret == QUAC_SUCCESS)
            *out_pkey = QUAC_EVP_PKEY_new_kem(QUAC_KEM_ML_KEM_1024, pk, sk);
        break;

    case NID_ML_DSA_44:
        ret = QUAC_SIG_keypair(QUAC_SIG_ML_DSA_44, pk, sk);
        if (ret == QUAC_SUCCESS)
            *out_pkey = QUAC_EVP_PKEY_new_sig(QUAC_SIG_ML_DSA_44, pk, sk);
        break;

    case NID_ML_DSA_65:
        ret = QUAC_SIG_keypair(QUAC_SIG_ML_DSA_65, pk, sk);
        if (ret == QUAC_SUCCESS)
            *out_pkey = QUAC_EVP_PKEY_new_sig(QUAC_SIG_ML_DSA_65, pk, sk);
        break;

    case NID_ML_DSA_87:
        ret = QUAC_SIG_keypair(QUAC_SIG_ML_DSA_87, pk, sk);
        if (ret == QUAC_SUCCESS)
            *out_pkey = QUAC_EVP_PKEY_new_sig(QUAC_SIG_ML_DSA_87, pk, sk);
        break;

    default:
        return QUAC_ERROR_INVALID_ALGORITHM;
    }

    OPENSSL_cleanse(sk, sizeof(sk));

    return ret;
}

/* ==========================================================================
 * EVP Registration
 * ========================================================================== */

/*
 * Note: BoringSSL has very limited support for custom algorithms.
 * Full integration would require modifying BoringSSL source code.
 * This function sets up what's possible externally.
 */

int QUAC_EVP_register(void)
{
    /*
     * In a real implementation with BoringSSL source access:
     * 1. Register NIDs for ML-KEM and ML-DSA
     * 2. Create EVP_PKEY_ASN1_METHOD for encoding/decoding
     * 3. Create EVP_PKEY_METHOD for key operations
     * 4. Register with EVP_PKEY_meth_add0
     *
     * Since we can't do this externally, we provide wrapper functions
     * that applications can use directly.
     */

    return QUAC_SUCCESS;
}

/* ==========================================================================
 * Signature Operations via EVP-like API
 * ========================================================================== */

/**
 * @brief Sign data using EVP-style API
 */
int QUAC_EVP_sign(const EVP_PKEY *pkey,
                  uint8_t *sig, size_t *sig_len,
                  const uint8_t *data, size_t data_len)
{
    /* Would extract key data from pkey and call QUAC_sign */
    (void)pkey;
    (void)sig;
    (void)sig_len;
    (void)data;
    (void)data_len;

    return QUAC_ERROR_NOT_INITIALIZED;
}

/**
 * @brief Verify signature using EVP-style API
 */
int QUAC_EVP_verify(const EVP_PKEY *pkey,
                    const uint8_t *sig, size_t sig_len,
                    const uint8_t *data, size_t data_len)
{
    (void)pkey;
    (void)sig;
    (void)sig_len;
    (void)data;
    (void)data_len;

    return QUAC_ERROR_NOT_INITIALIZED;
}

/* ==========================================================================
 * KEM Operations via EVP-like API
 * ========================================================================== */

/**
 * @brief Encapsulate using EVP-style API
 */
int QUAC_EVP_encaps(const EVP_PKEY *pkey,
                    uint8_t *ct, size_t *ct_len,
                    uint8_t *ss, size_t *ss_len)
{
    (void)pkey;
    (void)ct;
    (void)ct_len;
    (void)ss;
    (void)ss_len;

    return QUAC_ERROR_NOT_INITIALIZED;
}

/**
 * @brief Decapsulate using EVP-style API
 */
int QUAC_EVP_decaps(const EVP_PKEY *pkey,
                    uint8_t *ss, size_t *ss_len,
                    const uint8_t *ct, size_t ct_len)
{
    (void)pkey;
    (void)ss;
    (void)ss_len;
    (void)ct;
    (void)ct_len;

    return QUAC_ERROR_NOT_INITIALIZED;
}

/* ==========================================================================
 * Algorithm Information
 * ========================================================================== */

/**
 * @brief Get algorithm name from NID
 */
const char *QUAC_EVP_get_name(int nid)
{
    switch (nid)
    {
    case NID_ML_KEM_512:
        return "ML-KEM-512";
    case NID_ML_KEM_768:
        return "ML-KEM-768";
    case NID_ML_KEM_1024:
        return "ML-KEM-1024";
    case NID_ML_DSA_44:
        return "ML-DSA-44";
    case NID_ML_DSA_65:
        return "ML-DSA-65";
    case NID_ML_DSA_87:
        return "ML-DSA-87";
    default:
        return NULL;
    }
}

/**
 * @brief Get NID from algorithm name
 */
int QUAC_EVP_get_nid(const char *name)
{
    if (!name)
        return 0;

    if (strcmp(name, "ML-KEM-512") == 0)
        return NID_ML_KEM_512;
    if (strcmp(name, "ML-KEM-768") == 0)
        return NID_ML_KEM_768;
    if (strcmp(name, "ML-KEM-1024") == 0)
        return NID_ML_KEM_1024;
    if (strcmp(name, "ML-DSA-44") == 0)
        return NID_ML_DSA_44;
    if (strcmp(name, "ML-DSA-65") == 0)
        return NID_ML_DSA_65;
    if (strcmp(name, "ML-DSA-87") == 0)
        return NID_ML_DSA_87;

    return 0;
}

/**
 * @brief Check if algorithm is KEM or signature
 */
int QUAC_EVP_is_kem(int nid)
{
    return (nid >= NID_ML_KEM_512 && nid <= NID_ML_KEM_1024);
}

int QUAC_EVP_is_sig(int nid)
{
    return (nid >= NID_ML_DSA_44 && nid <= NID_ML_DSA_87);
}