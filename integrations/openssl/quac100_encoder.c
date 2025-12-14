/**
 * @file quac100_encoder.c
 * @brief QUAC 100 OpenSSL Provider - Key Encoder/Decoder
 *
 * Implements ASN.1 encoding/decoding for post-quantum keys:
 * - PEM format (Base64-encoded with headers)
 * - DER format (raw binary ASN.1)
 * - SubjectPublicKeyInfo (SPKI) structure
 * - PKCS#8 PrivateKeyInfo structure
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <string.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "quac100_provider.h"

/* ==========================================================================
 * OID Definitions for PQC Algorithms
 * ========================================================================== */

/*
 * OIDs from NIST PQC standards (draft)
 * These follow the NIST OID arc: 2.16.840.1.101.3.4.4.x
 */

/* ML-KEM OIDs (FIPS 203) */
#define QUAC_OID_ML_KEM_512 "2.16.840.1.101.3.4.4.1"
#define QUAC_OID_ML_KEM_768 "2.16.840.1.101.3.4.4.2"
#define QUAC_OID_ML_KEM_1024 "2.16.840.1.101.3.4.4.3"

/* ML-DSA OIDs (FIPS 204) */
#define QUAC_OID_ML_DSA_44 "2.16.840.1.101.3.4.3.17"
#define QUAC_OID_ML_DSA_65 "2.16.840.1.101.3.4.3.18"
#define QUAC_OID_ML_DSA_87 "2.16.840.1.101.3.4.3.19"

/* ==========================================================================
 * Encoder Context
 * ========================================================================== */

typedef struct quac_encoder_ctx
{
    QUAC_PROV_CTX *provctx;
    int output_type; /* OSSL_KEYMGMT_SELECT_* */
    const char *output_struct;
    const char *format; /* "PEM" or "DER" */
} QUAC_ENCODER_CTX;

/* ==========================================================================
 * OID Lookup
 * ========================================================================== */

static const char *quac_key_type_to_oid(quac_key_type_t type)
{
    switch (type)
    {
    case QUAC_KEY_TYPE_ML_KEM_512:
        return QUAC_OID_ML_KEM_512;
    case QUAC_KEY_TYPE_ML_KEM_768:
        return QUAC_OID_ML_KEM_768;
    case QUAC_KEY_TYPE_ML_KEM_1024:
        return QUAC_OID_ML_KEM_1024;
    case QUAC_KEY_TYPE_ML_DSA_44:
        return QUAC_OID_ML_DSA_44;
    case QUAC_KEY_TYPE_ML_DSA_65:
        return QUAC_OID_ML_DSA_65;
    case QUAC_KEY_TYPE_ML_DSA_87:
        return QUAC_OID_ML_DSA_87;
    default:
        return NULL;
    }
}

static const char *quac_key_type_to_pem_label(quac_key_type_t type, int is_private)
{
    if (is_private)
    {
        switch (type)
        {
        case QUAC_KEY_TYPE_ML_KEM_512:
        case QUAC_KEY_TYPE_ML_KEM_768:
        case QUAC_KEY_TYPE_ML_KEM_1024:
            return "ML-KEM PRIVATE KEY";
        case QUAC_KEY_TYPE_ML_DSA_44:
        case QUAC_KEY_TYPE_ML_DSA_65:
        case QUAC_KEY_TYPE_ML_DSA_87:
            return "ML-DSA PRIVATE KEY";
        default:
            return "PRIVATE KEY";
        }
    }
    else
    {
        switch (type)
        {
        case QUAC_KEY_TYPE_ML_KEM_512:
        case QUAC_KEY_TYPE_ML_KEM_768:
        case QUAC_KEY_TYPE_ML_KEM_1024:
            return "ML-KEM PUBLIC KEY";
        case QUAC_KEY_TYPE_ML_DSA_44:
        case QUAC_KEY_TYPE_ML_DSA_65:
        case QUAC_KEY_TYPE_ML_DSA_87:
            return "ML-DSA PUBLIC KEY";
        default:
            return "PUBLIC KEY";
        }
    }
}

/* ==========================================================================
 * ASN.1 Encoding Helpers
 * ========================================================================== */

/*
 * SubjectPublicKeyInfo ::= SEQUENCE {
 *   algorithm   AlgorithmIdentifier,
 *   publicKey   BIT STRING
 * }
 *
 * AlgorithmIdentifier ::= SEQUENCE {
 *   algorithm   OBJECT IDENTIFIER,
 *   parameters  ANY DEFINED BY algorithm OPTIONAL
 * }
 */

static int quac_encode_spki(const QUAC_KEY *key, unsigned char **out, size_t *out_len)
{
    const char *oid_str;
    ASN1_OBJECT *oid = NULL;
    X509_PUBKEY *pubkey = NULL;
    unsigned char *der = NULL;
    int der_len;
    int ret = 0;

    if (!key || !key->has_public || !out || !out_len)
        return 0;

    oid_str = quac_key_type_to_oid(key->type);
    if (!oid_str)
        return 0;

    oid = OBJ_txt2obj(oid_str, 1);
    if (!oid)
        return 0;

    pubkey = X509_PUBKEY_new();
    if (!pubkey)
        goto cleanup;

    /* Set algorithm identifier (no parameters for PQC) */
    if (!X509_PUBKEY_set0_param(pubkey, oid, V_ASN1_UNDEF, NULL,
                                (unsigned char *)key->pubkey, key->pubkey_len))
    {
        goto cleanup;
    }
    oid = NULL; /* Ownership transferred */

    /* Encode to DER */
    der_len = i2d_X509_PUBKEY(pubkey, &der);
    if (der_len <= 0)
        goto cleanup;

    *out = der;
    *out_len = der_len;
    der = NULL;
    ret = 1;

cleanup:
    ASN1_OBJECT_free(oid);
    X509_PUBKEY_free(pubkey);
    OPENSSL_free(der);
    return ret;
}

/*
 * OneAsymmetricKey (PKCS#8 v2) ::= SEQUENCE {
 *   version                   INTEGER,
 *   privateKeyAlgorithm       AlgorithmIdentifier,
 *   privateKey                OCTET STRING,
 *   attributes            [0] Attributes OPTIONAL,
 *   publicKey             [1] BIT STRING OPTIONAL
 * }
 */

static int quac_encode_pkcs8(const QUAC_KEY *key, unsigned char **out, size_t *out_len)
{
    const char *oid_str;
    ASN1_OBJECT *oid = NULL;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    unsigned char *der = NULL;
    int der_len;
    int ret = 0;

    if (!key || !key->has_private || !out || !out_len)
        return 0;

    oid_str = quac_key_type_to_oid(key->type);
    if (!oid_str)
        return 0;

    oid = OBJ_txt2obj(oid_str, 1);
    if (!oid)
        return 0;

    p8 = PKCS8_PRIV_KEY_INFO_new();
    if (!p8)
        goto cleanup;

    /* Set algorithm and private key */
    if (!PKCS8_pkey_set0(p8, oid, V_ASN1_UNDEF, NULL,
                         (unsigned char *)key->privkey, key->privkey_len))
    {
        goto cleanup;
    }
    oid = NULL; /* Ownership transferred */

    /* Encode to DER */
    der_len = i2d_PKCS8_PRIV_KEY_INFO(p8, &der);
    if (der_len <= 0)
        goto cleanup;

    *out = der;
    *out_len = der_len;
    der = NULL;
    ret = 1;

cleanup:
    ASN1_OBJECT_free(oid);
    PKCS8_PRIV_KEY_INFO_free(p8);
    OPENSSL_free(der);
    return ret;
}

/* ==========================================================================
 * PEM Encoding
 * ========================================================================== */

static int quac_encode_pem(const unsigned char *der, size_t der_len,
                           const char *label, BIO *out)
{
    return PEM_write_bio(out, label, "", der, der_len);
}

/* ==========================================================================
 * Encoder Dispatch Functions
 * ========================================================================== */

static void *quac_encoder_newctx(void *provctx)
{
    QUAC_ENCODER_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx)
        ctx->provctx = provctx;
    return ctx;
}

static void quac_encoder_freectx(void *vctx)
{
    OPENSSL_free(vctx);
}

static int quac_encoder_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    QUAC_ENCODER_CTX *ctx = vctx;
    const OSSL_PARAM *p;

    if (!ctx)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_ENCODER_PARAM_OUTPUT_TYPE);
    if (p)
    {
        const char *output_type = NULL;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &output_type))
            return 0;
        /* Store output type preference */
    }

    return 1;
}

static const OSSL_PARAM *quac_encoder_settable_ctx_params(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_ENCODER_PARAM_OUTPUT_TYPE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_ENCODER_PARAM_OUTPUT_STRUCTURE, NULL, 0),
        OSSL_PARAM_END};
    (void)provctx;
    return params;
}

static int quac_encoder_does_selection(void *provctx, int selection)
{
    (void)provctx;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        return 1;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        return 1;
    if ((selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0)
        return 1;

    return 0;
}

/* DER encoder for public keys (SPKI) */
static int quac_encoder_encode_der_pubkey(void *vctx, OSSL_CORE_BIO *cout,
                                          const void *key_obj,
                                          const OSSL_PARAM key_abstract[],
                                          int selection,
                                          OSSL_PASSPHRASE_CALLBACK *cb,
                                          void *cbarg)
{
    const QUAC_KEY *key = key_obj;
    unsigned char *der = NULL;
    size_t der_len = 0;
    BIO *out = NULL;
    int ret = 0;

    (void)vctx;
    (void)key_abstract;
    (void)selection;
    (void)cb;
    (void)cbarg;

    if (!key || !key->has_public)
        return 0;

    if (!quac_encode_spki(key, &der, &der_len))
        return 0;

    out = BIO_new_from_core_bio(NULL, cout);
    if (!out)
        goto cleanup;

    if (BIO_write(out, der, der_len) == (int)der_len)
        ret = 1;

cleanup:
    BIO_free(out);
    OPENSSL_free(der);
    return ret;
}

/* PEM encoder for public keys */
static int quac_encoder_encode_pem_pubkey(void *vctx, OSSL_CORE_BIO *cout,
                                          const void *key_obj,
                                          const OSSL_PARAM key_abstract[],
                                          int selection,
                                          OSSL_PASSPHRASE_CALLBACK *cb,
                                          void *cbarg)
{
    const QUAC_KEY *key = key_obj;
    unsigned char *der = NULL;
    size_t der_len = 0;
    BIO *out = NULL;
    const char *label;
    int ret = 0;

    (void)vctx;
    (void)key_abstract;
    (void)selection;
    (void)cb;
    (void)cbarg;

    if (!key || !key->has_public)
        return 0;

    if (!quac_encode_spki(key, &der, &der_len))
        return 0;

    out = BIO_new_from_core_bio(NULL, cout);
    if (!out)
        goto cleanup;

    label = quac_key_type_to_pem_label(key->type, 0);
    if (quac_encode_pem(der, der_len, label, out))
        ret = 1;

cleanup:
    BIO_free(out);
    OPENSSL_free(der);
    return ret;
}

/* DER encoder for private keys (PKCS#8) */
static int quac_encoder_encode_der_privkey(void *vctx, OSSL_CORE_BIO *cout,
                                           const void *key_obj,
                                           const OSSL_PARAM key_abstract[],
                                           int selection,
                                           OSSL_PASSPHRASE_CALLBACK *cb,
                                           void *cbarg)
{
    const QUAC_KEY *key = key_obj;
    unsigned char *der = NULL;
    size_t der_len = 0;
    BIO *out = NULL;
    int ret = 0;

    (void)vctx;
    (void)key_abstract;
    (void)selection;
    (void)cb;
    (void)cbarg;

    if (!key || !key->has_private)
        return 0;

    if (!quac_encode_pkcs8(key, &der, &der_len))
        return 0;

    out = BIO_new_from_core_bio(NULL, cout);
    if (!out)
        goto cleanup;

    if (BIO_write(out, der, der_len) == (int)der_len)
        ret = 1;

cleanup:
    BIO_free(out);
    OPENSSL_secure_clear_free(der, der_len);
    return ret;
}

/* PEM encoder for private keys */
static int quac_encoder_encode_pem_privkey(void *vctx, OSSL_CORE_BIO *cout,
                                           const void *key_obj,
                                           const OSSL_PARAM key_abstract[],
                                           int selection,
                                           OSSL_PASSPHRASE_CALLBACK *cb,
                                           void *cbarg)
{
    const QUAC_KEY *key = key_obj;
    unsigned char *der = NULL;
    size_t der_len = 0;
    BIO *out = NULL;
    const char *label;
    int ret = 0;

    (void)vctx;
    (void)key_abstract;
    (void)selection;
    (void)cb;
    (void)cbarg;

    if (!key || !key->has_private)
        return 0;

    if (!quac_encode_pkcs8(key, &der, &der_len))
        return 0;

    out = BIO_new_from_core_bio(NULL, cout);
    if (!out)
        goto cleanup;

    label = quac_key_type_to_pem_label(key->type, 1);
    if (quac_encode_pem(der, der_len, label, out))
        ret = 1;

cleanup:
    BIO_free(out);
    OPENSSL_secure_clear_free(der, der_len);
    return ret;
}

/* ==========================================================================
 * Decoder Functions
 * ========================================================================== */

typedef struct quac_decoder_ctx
{
    QUAC_PROV_CTX *provctx;
    quac_key_type_t expected_type;
} QUAC_DECODER_CTX;

static void *quac_decoder_newctx(void *provctx)
{
    QUAC_DECODER_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx)
        ctx->provctx = provctx;
    return ctx;
}

static void quac_decoder_freectx(void *vctx)
{
    OPENSSL_free(vctx);
}

static int quac_decoder_does_selection(void *provctx, int selection)
{
    (void)provctx;
    return (selection & (OSSL_KEYMGMT_SELECT_PUBLIC_KEY |
                         OSSL_KEYMGMT_SELECT_PRIVATE_KEY)) != 0;
}

static quac_key_type_t quac_oid_to_key_type(const ASN1_OBJECT *oid)
{
    char oid_str[80];

    if (OBJ_obj2txt(oid_str, sizeof(oid_str), oid, 1) <= 0)
        return QUAC_KEY_TYPE_UNKNOWN;

    if (strcmp(oid_str, QUAC_OID_ML_KEM_512) == 0)
        return QUAC_KEY_TYPE_ML_KEM_512;
    if (strcmp(oid_str, QUAC_OID_ML_KEM_768) == 0)
        return QUAC_KEY_TYPE_ML_KEM_768;
    if (strcmp(oid_str, QUAC_OID_ML_KEM_1024) == 0)
        return QUAC_KEY_TYPE_ML_KEM_1024;
    if (strcmp(oid_str, QUAC_OID_ML_DSA_44) == 0)
        return QUAC_KEY_TYPE_ML_DSA_44;
    if (strcmp(oid_str, QUAC_OID_ML_DSA_65) == 0)
        return QUAC_KEY_TYPE_ML_DSA_65;
    if (strcmp(oid_str, QUAC_OID_ML_DSA_87) == 0)
        return QUAC_KEY_TYPE_ML_DSA_87;

    return QUAC_KEY_TYPE_UNKNOWN;
}

static int quac_decoder_decode_der_pubkey(void *vctx, OSSL_CORE_BIO *cin,
                                          int selection,
                                          OSSL_CALLBACK *data_cb,
                                          void *data_cbarg,
                                          OSSL_PASSPHRASE_CALLBACK *pw_cb,
                                          void *pw_cbarg)
{
    QUAC_DECODER_CTX *ctx = vctx;
    BIO *in = NULL;
    X509_PUBKEY *pubkey = NULL;
    const ASN1_OBJECT *oid = NULL;
    const unsigned char *pk_data = NULL;
    int pk_len = 0;
    quac_key_type_t type;
    QUAC_KEY *key = NULL;
    OSSL_PARAM params[4];
    int ret = 0;

    (void)selection;
    (void)pw_cb;
    (void)pw_cbarg;

    in = BIO_new_from_core_bio(NULL, cin);
    if (!in)
        return 0;

    pubkey = d2i_X509_PUBKEY_bio(in, NULL);
    if (!pubkey)
        goto cleanup;

    if (!X509_PUBKEY_get0_param((ASN1_OBJECT **)&oid, &pk_data, &pk_len, NULL, pubkey))
        goto cleanup;

    type = quac_oid_to_key_type(oid);
    if (type == QUAC_KEY_TYPE_UNKNOWN)
        goto cleanup;

    key = quac_key_new(ctx->provctx, type);
    if (!key)
        goto cleanup;

    key->pubkey = OPENSSL_memdup(pk_data, pk_len);
    if (!key->pubkey)
        goto cleanup;
    key->pubkey_len = pk_len;
    key->has_public = 1;

    /* Callback with decoded key */
    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE,
                                         &(int){OSSL_OBJECT_PKEY});
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                                 (char *)quac_key_type_name(type), 0);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                                                  &key, sizeof(key));
    params[3] = OSSL_PARAM_construct_end();

    ret = data_cb(params, data_cbarg);
    if (ret)
        key = NULL; /* Ownership transferred */

cleanup:
    BIO_free(in);
    X509_PUBKEY_free(pubkey);
    quac_key_free(key);
    return ret;
}

static int quac_decoder_decode_der_privkey(void *vctx, OSSL_CORE_BIO *cin,
                                           int selection,
                                           OSSL_CALLBACK *data_cb,
                                           void *data_cbarg,
                                           OSSL_PASSPHRASE_CALLBACK *pw_cb,
                                           void *pw_cbarg)
{
    QUAC_DECODER_CTX *ctx = vctx;
    BIO *in = NULL;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    const ASN1_OBJECT *oid = NULL;
    const unsigned char *pk_data = NULL;
    int pk_len = 0;
    quac_key_type_t type;
    QUAC_KEY *key = NULL;
    OSSL_PARAM params[4];
    int ret = 0;

    (void)selection;
    (void)pw_cb;
    (void)pw_cbarg;

    in = BIO_new_from_core_bio(NULL, cin);
    if (!in)
        return 0;

    p8 = d2i_PKCS8_PRIV_KEY_INFO_bio(in, NULL);
    if (!p8)
        goto cleanup;

    if (!PKCS8_pkey_get0(&oid, &pk_data, &pk_len, NULL, p8))
        goto cleanup;

    type = quac_oid_to_key_type(oid);
    if (type == QUAC_KEY_TYPE_UNKNOWN)
        goto cleanup;

    key = quac_key_new(ctx->provctx, type);
    if (!key)
        goto cleanup;

    key->privkey = OPENSSL_secure_malloc(pk_len);
    if (!key->privkey)
        goto cleanup;
    memcpy(key->privkey, pk_data, pk_len);
    key->privkey_len = pk_len;
    key->has_private = 1;

    /* Callback with decoded key */
    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE,
                                         &(int){OSSL_OBJECT_PKEY});
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                                 (char *)quac_key_type_name(type), 0);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                                                  &key, sizeof(key));
    params[3] = OSSL_PARAM_construct_end();

    ret = data_cb(params, data_cbarg);
    if (ret)
        key = NULL;

cleanup:
    BIO_free(in);
    PKCS8_PRIV_KEY_INFO_free(p8);
    quac_key_free(key);
    return ret;
}

/* ==========================================================================
 * Encoder Dispatch Tables
 * ========================================================================== */

static const OSSL_DISPATCH quac_encoder_der_pubkey_functions[] = {
    {OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))quac_encoder_newctx},
    {OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))quac_encoder_freectx},
    {OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (void (*)(void))quac_encoder_set_ctx_params},
    {OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS, (void (*)(void))quac_encoder_settable_ctx_params},
    {OSSL_FUNC_ENCODER_DOES_SELECTION, (void (*)(void))quac_encoder_does_selection},
    {OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))quac_encoder_encode_der_pubkey},
    {0, NULL}};

static const OSSL_DISPATCH quac_encoder_pem_pubkey_functions[] = {
    {OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))quac_encoder_newctx},
    {OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))quac_encoder_freectx},
    {OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (void (*)(void))quac_encoder_set_ctx_params},
    {OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS, (void (*)(void))quac_encoder_settable_ctx_params},
    {OSSL_FUNC_ENCODER_DOES_SELECTION, (void (*)(void))quac_encoder_does_selection},
    {OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))quac_encoder_encode_pem_pubkey},
    {0, NULL}};

static const OSSL_DISPATCH quac_encoder_der_privkey_functions[] = {
    {OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))quac_encoder_newctx},
    {OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))quac_encoder_freectx},
    {OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (void (*)(void))quac_encoder_set_ctx_params},
    {OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS, (void (*)(void))quac_encoder_settable_ctx_params},
    {OSSL_FUNC_ENCODER_DOES_SELECTION, (void (*)(void))quac_encoder_does_selection},
    {OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))quac_encoder_encode_der_privkey},
    {0, NULL}};

static const OSSL_DISPATCH quac_encoder_pem_privkey_functions[] = {
    {OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))quac_encoder_newctx},
    {OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))quac_encoder_freectx},
    {OSSL_FUNC_ENCODER_SET_CTX_PARAMS, (void (*)(void))quac_encoder_set_ctx_params},
    {OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS, (void (*)(void))quac_encoder_settable_ctx_params},
    {OSSL_FUNC_ENCODER_DOES_SELECTION, (void (*)(void))quac_encoder_does_selection},
    {OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))quac_encoder_encode_pem_privkey},
    {0, NULL}};

/* ==========================================================================
 * Decoder Dispatch Tables
 * ========================================================================== */

static const OSSL_DISPATCH quac_decoder_der_pubkey_functions[] = {
    {OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))quac_decoder_newctx},
    {OSSL_FUNC_DECODER_FREECTX, (void (*)(void))quac_decoder_freectx},
    {OSSL_FUNC_DECODER_DOES_SELECTION, (void (*)(void))quac_decoder_does_selection},
    {OSSL_FUNC_DECODER_DECODE, (void (*)(void))quac_decoder_decode_der_pubkey},
    {0, NULL}};

static const OSSL_DISPATCH quac_decoder_der_privkey_functions[] = {
    {OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))quac_decoder_newctx},
    {OSSL_FUNC_DECODER_FREECTX, (void (*)(void))quac_decoder_freectx},
    {OSSL_FUNC_DECODER_DOES_SELECTION, (void (*)(void))quac_decoder_does_selection},
    {OSSL_FUNC_DECODER_DECODE, (void (*)(void))quac_decoder_decode_der_privkey},
    {0, NULL}};

/* ==========================================================================
 * Algorithm Registration
 * ========================================================================== */

const OSSL_ALGORITHM quac_encoder_algorithms[] = {
    /* DER encoders */
    {"ML-KEM-512:ML-KEM-768:ML-KEM-1024:ML-DSA-44:ML-DSA-65:ML-DSA-87",
     "provider=quac100,output=der,structure=SubjectPublicKeyInfo",
     quac_encoder_der_pubkey_functions, "QUAC DER Public Key Encoder"},
    {"ML-KEM-512:ML-KEM-768:ML-KEM-1024:ML-DSA-44:ML-DSA-65:ML-DSA-87",
     "provider=quac100,output=der,structure=PrivateKeyInfo",
     quac_encoder_der_privkey_functions, "QUAC DER Private Key Encoder"},

    /* PEM encoders */
    {"ML-KEM-512:ML-KEM-768:ML-KEM-1024:ML-DSA-44:ML-DSA-65:ML-DSA-87",
     "provider=quac100,output=pem,structure=SubjectPublicKeyInfo",
     quac_encoder_pem_pubkey_functions, "QUAC PEM Public Key Encoder"},
    {"ML-KEM-512:ML-KEM-768:ML-KEM-1024:ML-DSA-44:ML-DSA-65:ML-DSA-87",
     "provider=quac100,output=pem,structure=PrivateKeyInfo",
     quac_encoder_pem_privkey_functions, "QUAC PEM Private Key Encoder"},

    {NULL, NULL, NULL, NULL}};

const OSSL_ALGORITHM quac_decoder_algorithms[] = {
    /* DER decoders */
    {"ML-KEM-512:ML-KEM-768:ML-KEM-1024:ML-DSA-44:ML-DSA-65:ML-DSA-87",
     "provider=quac100,input=der,structure=SubjectPublicKeyInfo",
     quac_decoder_der_pubkey_functions, "QUAC DER Public Key Decoder"},
    {"ML-KEM-512:ML-KEM-768:ML-KEM-1024:ML-DSA-44:ML-DSA-65:ML-DSA-87",
     "provider=quac100,input=der,structure=PrivateKeyInfo",
     quac_decoder_der_privkey_functions, "QUAC DER Private Key Decoder"},

    {NULL, NULL, NULL, NULL}};