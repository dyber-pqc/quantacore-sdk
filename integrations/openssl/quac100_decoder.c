/**
 * @file D:\quantacore-sdk\integrations\openssl\quac100_decoder.c
 * @brief QUAC 100 OpenSSL Provider - ASN.1 Key Decoder
 *
 * Decodes ML-KEM and ML-DSA keys from DER/PEM formats.
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <string.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>

#include "quac100_provider.h"
#include "quac100_provider_internal.h"

/* ==========================================================================
 * ASN.1 Structures
 * ========================================================================== */

/*
 * SubjectPublicKeyInfo ::= SEQUENCE {
 *   algorithm         AlgorithmIdentifier,
 *   subjectPublicKey  BIT STRING
 * }
 *
 * PrivateKeyInfo ::= SEQUENCE {
 *   version           INTEGER,
 *   privateKeyAlgorithm AlgorithmIdentifier,
 *   privateKey        OCTET STRING
 * }
 */

/* ==========================================================================
 * Decoder Context
 * ========================================================================== */

typedef struct
{
    QUAC100_PROV_CTX *provctx;
    int input_type; /* OSSL_KEYMGMT_SELECT_* */
    int format;     /* DER or PEM */
    const char *keytype;
    int selection;
} DECODER_CTX;

/* ==========================================================================
 * Decoder Implementation
 * ========================================================================== */

static OSSL_FUNC_decoder_newctx_fn decoder_newctx;
static OSSL_FUNC_decoder_freectx_fn decoder_freectx;
static OSSL_FUNC_decoder_decode_fn decoder_decode;
static OSSL_FUNC_decoder_gettable_params_fn decoder_gettable_params;
static OSSL_FUNC_decoder_get_params_fn decoder_get_params;
static OSSL_FUNC_decoder_settable_ctx_params_fn decoder_settable_ctx_params;
static OSSL_FUNC_decoder_set_ctx_params_fn decoder_set_ctx_params;

static void *decoder_newctx(void *provctx)
{
    DECODER_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;

    ctx->provctx = provctx;
    ctx->format = 0; /* Auto-detect */
    ctx->selection = OSSL_KEYMGMT_SELECT_ALL;
    return ctx;
}

static void decoder_freectx(void *vctx)
{
    DECODER_CTX *ctx = vctx;
    if (ctx)
        OPENSSL_free(ctx);
}

static const OSSL_PARAM *decoder_gettable_params(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_ptr(OSSL_DECODER_PARAM_INPUT_TYPE, NULL, 0),
        OSSL_PARAM_utf8_ptr(OSSL_DECODER_PARAM_INPUT_STRUCTURE, NULL, 0),
        OSSL_PARAM_END};
    (void)provctx;
    return params;
}

static int decoder_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_DECODER_PARAM_INPUT_TYPE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "DER"))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DECODER_PARAM_INPUT_STRUCTURE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "SubjectPublicKeyInfo"))
        return 0;

    return 1;
}

static const OSSL_PARAM *decoder_settable_ctx_params(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_int(OSSL_DECODER_PARAM_SELECTION, NULL),
        OSSL_PARAM_END};
    (void)provctx;
    return params;
}

static int decoder_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    DECODER_CTX *ctx = vctx;
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, OSSL_DECODER_PARAM_SELECTION);
    if (p != NULL && !OSSL_PARAM_get_int(p, &ctx->selection))
        return 0;

    return 1;
}

/* Parse OID and determine key type */
static int parse_algorithm_oid(const unsigned char *oid, size_t oid_len,
                               int *key_type, int *level)
{
    /* ML-KEM OIDs */
    static const unsigned char oid_mlkem512[] = {
        0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xB0, 0x7A, 0x05, 0x06, 0x01};
    static const unsigned char oid_mlkem768[] = {
        0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xB0, 0x7A, 0x05, 0x06, 0x02};
    static const unsigned char oid_mlkem1024[] = {
        0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xB0, 0x7A, 0x05, 0x06, 0x03};

    /* ML-DSA OIDs */
    static const unsigned char oid_mldsa44[] = {
        0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xB0, 0x7A, 0x05, 0x07, 0x01};
    static const unsigned char oid_mldsa65[] = {
        0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xB0, 0x7A, 0x05, 0x07, 0x02};
    static const unsigned char oid_mldsa87[] = {
        0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xB0, 0x7A, 0x05, 0x07, 0x03};

    if (oid_len >= sizeof(oid_mlkem512) &&
        memcmp(oid, oid_mlkem512, sizeof(oid_mlkem512)) == 0)
    {
        *key_type = 1; /* ML-KEM */
        *level = 512;
        return 1;
    }
    if (oid_len >= sizeof(oid_mlkem768) &&
        memcmp(oid, oid_mlkem768, sizeof(oid_mlkem768)) == 0)
    {
        *key_type = 1;
        *level = 768;
        return 1;
    }
    if (oid_len >= sizeof(oid_mlkem1024) &&
        memcmp(oid, oid_mlkem1024, sizeof(oid_mlkem1024)) == 0)
    {
        *key_type = 1;
        *level = 1024;
        return 1;
    }
    if (oid_len >= sizeof(oid_mldsa44) &&
        memcmp(oid, oid_mldsa44, sizeof(oid_mldsa44)) == 0)
    {
        *key_type = 2; /* ML-DSA */
        *level = 44;
        return 1;
    }
    if (oid_len >= sizeof(oid_mldsa65) &&
        memcmp(oid, oid_mldsa65, sizeof(oid_mldsa65)) == 0)
    {
        *key_type = 2;
        *level = 65;
        return 1;
    }
    if (oid_len >= sizeof(oid_mldsa87) &&
        memcmp(oid, oid_mldsa87, sizeof(oid_mldsa87)) == 0)
    {
        *key_type = 2;
        *level = 87;
        return 1;
    }

    return 0;
}

/* Decode SubjectPublicKeyInfo */
static int decode_spki(DECODER_CTX *ctx, const unsigned char *data, size_t len,
                       OSSL_CALLBACK *data_cb, void *data_cbarg)
{
    const unsigned char *p = data;
    long seq_len, algo_len, pk_len;
    int key_type = 0, level = 0;
    int tag, xclass;
    void *key = NULL;
    OSSL_PARAM params[4];
    int ret = 0;

    /* SEQUENCE */
    if (ASN1_get_object(&p, &seq_len, &tag, &xclass, len) != 0 || tag != V_ASN1_SEQUENCE)
        return 0;

    /* AlgorithmIdentifier SEQUENCE */
    const unsigned char *algo_start = p;
    if (ASN1_get_object(&p, &algo_len, &tag, &xclass, seq_len) != 0 || tag != V_ASN1_SEQUENCE)
        return 0;

    /* Parse OID */
    if (!parse_algorithm_oid(p, algo_len, &key_type, &level))
        return 0;

    p = algo_start + algo_len + 2; /* Skip AlgorithmIdentifier */

    /* BIT STRING (public key) */
    if (ASN1_get_object(&p, &pk_len, &tag, &xclass, seq_len - (p - data)) != 0 ||
        tag != V_ASN1_BIT_STRING)
        return 0;

    /* Skip unused bits byte */
    p++;
    pk_len--;

    /* Create key object */
    if (key_type == 1)
    {
        /* ML-KEM */
        QUAC100_MLKEM_KEY *mlkem = quac100_mlkem_key_new(ctx->provctx, level);
        if (!mlkem)
            return 0;

        size_t expected_len = quac100_mlkem_pk_size(level);
        if ((size_t)pk_len != expected_len)
        {
            quac100_mlkem_key_free(mlkem);
            return 0;
        }

        mlkem->public_key = OPENSSL_memdup(p, pk_len);
        mlkem->public_key_len = pk_len;
        mlkem->has_private = 0;

        key = mlkem;

        params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &(int){OSSL_OBJECT_PKEY});
        params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                                     (char *)(level == 512 ? QUAC100_ALG_MLKEM512 : level == 768 ? QUAC100_ALG_MLKEM768
                                                                                                                 : QUAC100_ALG_MLKEM1024),
                                                     0);
        params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                                                      &key, sizeof(key));
        params[3] = OSSL_PARAM_construct_end();
    }
    else if (key_type == 2)
    {
        /* ML-DSA */
        QUAC100_MLDSA_KEY *mldsa = quac100_mldsa_key_new(ctx->provctx, level);
        if (!mldsa)
            return 0;

        size_t expected_len = quac100_mldsa_pk_size(level);
        if ((size_t)pk_len != expected_len)
        {
            quac100_mldsa_key_free(mldsa);
            return 0;
        }

        mldsa->public_key = OPENSSL_memdup(p, pk_len);
        mldsa->public_key_len = pk_len;
        mldsa->has_private = 0;

        key = mldsa;

        params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &(int){OSSL_OBJECT_PKEY});
        params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                                     (char *)(level == 44 ? QUAC100_ALG_MLDSA44 : level == 65 ? QUAC100_ALG_MLDSA65
                                                                                                              : QUAC100_ALG_MLDSA87),
                                                     0);
        params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                                                      &key, sizeof(key));
        params[3] = OSSL_PARAM_construct_end();
    }

    if (key)
    {
        ret = data_cb(params, data_cbarg);
    }

    return ret;
}

/* Decode PrivateKeyInfo */
static int decode_pkcs8(DECODER_CTX *ctx, const unsigned char *data, size_t len,
                        OSSL_CALLBACK *data_cb, void *data_cbarg)
{
    const unsigned char *p = data;
    long seq_len, ver_len, algo_len, sk_len;
    int key_type = 0, level = 0;
    int tag, xclass;
    void *key = NULL;
    OSSL_PARAM params[4];
    int ret = 0;

    /* SEQUENCE */
    if (ASN1_get_object(&p, &seq_len, &tag, &xclass, len) != 0 || tag != V_ASN1_SEQUENCE)
        return 0;

    /* INTEGER (version) */
    if (ASN1_get_object(&p, &ver_len, &tag, &xclass, seq_len) != 0 || tag != V_ASN1_INTEGER)
        return 0;
    p += ver_len;

    /* AlgorithmIdentifier SEQUENCE */
    const unsigned char *algo_start = p;
    if (ASN1_get_object(&p, &algo_len, &tag, &xclass, seq_len - (p - data)) != 0 ||
        tag != V_ASN1_SEQUENCE)
        return 0;

    /* Parse OID */
    if (!parse_algorithm_oid(p, algo_len, &key_type, &level))
        return 0;

    p = algo_start + algo_len + 2;

    /* OCTET STRING (private key) */
    if (ASN1_get_object(&p, &sk_len, &tag, &xclass, seq_len - (p - data)) != 0 ||
        tag != V_ASN1_OCTET_STRING)
        return 0;

    /* Create key object with private key */
    if (key_type == 1)
    {
        /* ML-KEM */
        QUAC100_MLKEM_KEY *mlkem = quac100_mlkem_key_new(ctx->provctx, level);
        if (!mlkem)
            return 0;

        size_t expected_len = quac100_mlkem_sk_size(level);
        if ((size_t)sk_len != expected_len)
        {
            quac100_mlkem_key_free(mlkem);
            return 0;
        }

        mlkem->secret_key = OPENSSL_secure_malloc(sk_len);
        if (!mlkem->secret_key)
        {
            quac100_mlkem_key_free(mlkem);
            return 0;
        }
        memcpy(mlkem->secret_key, p, sk_len);
        mlkem->secret_key_len = sk_len;
        mlkem->has_private = 1;

        /* Extract public key from secret key (it's embedded) */
        size_t pk_len = quac100_mlkem_pk_size(level);
        mlkem->public_key = OPENSSL_memdup(mlkem->secret_key + mlkem->secret_key_len - pk_len, pk_len);
        mlkem->public_key_len = pk_len;

        key = mlkem;

        params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &(int){OSSL_OBJECT_PKEY});
        params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                                     (char *)(level == 512 ? QUAC100_ALG_MLKEM512 : level == 768 ? QUAC100_ALG_MLKEM768
                                                                                                                 : QUAC100_ALG_MLKEM1024),
                                                     0);
        params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                                                      &key, sizeof(key));
        params[3] = OSSL_PARAM_construct_end();
    }
    else if (key_type == 2)
    {
        /* ML-DSA */
        QUAC100_MLDSA_KEY *mldsa = quac100_mldsa_key_new(ctx->provctx, level);
        if (!mldsa)
            return 0;

        size_t expected_len = quac100_mldsa_sk_size(level);
        if ((size_t)sk_len != expected_len)
        {
            quac100_mldsa_key_free(mldsa);
            return 0;
        }

        mldsa->secret_key = OPENSSL_secure_malloc(sk_len);
        if (!mldsa->secret_key)
        {
            quac100_mldsa_key_free(mldsa);
            return 0;
        }
        memcpy(mldsa->secret_key, p, sk_len);
        mldsa->secret_key_len = sk_len;
        mldsa->has_private = 1;

        /* Extract public key from secret key */
        size_t pk_len = quac100_mldsa_pk_size(level);
        mldsa->public_key = OPENSSL_memdup(mldsa->secret_key + 32, pk_len); /* Offset varies */
        mldsa->public_key_len = pk_len;

        key = mldsa;

        params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &(int){OSSL_OBJECT_PKEY});
        params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                                     (char *)(level == 44 ? QUAC100_ALG_MLDSA44 : level == 65 ? QUAC100_ALG_MLDSA65
                                                                                                              : QUAC100_ALG_MLDSA87),
                                                     0);
        params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                                                      &key, sizeof(key));
        params[3] = OSSL_PARAM_construct_end();
    }

    if (key)
    {
        ret = data_cb(params, data_cbarg);
    }

    return ret;
}

static int decoder_decode(void *vctx, OSSL_CORE_BIO *cin, int selection,
                          OSSL_CALLBACK *data_cb, void *data_cbarg,
                          OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    DECODER_CTX *ctx = vctx;
    unsigned char *data = NULL;
    size_t data_len = 0;
    size_t allocated = 4096;
    int ret = 0;

    (void)pw_cb;
    (void)pw_cbarg;
    (void)selection;

    /* Read all data from BIO */
    data = OPENSSL_malloc(allocated);
    if (!data)
        return 0;

    while (1)
    {
        size_t read = 0;
        if (!ctx->provctx->bio_read_ex(cin, data + data_len,
                                       allocated - data_len, &read))
        {
            if (data_len == 0)
                goto cleanup;
            break;
        }
        if (read == 0)
            break;

        data_len += read;
        if (data_len >= allocated)
        {
            allocated *= 2;
            unsigned char *new_data = OPENSSL_realloc(data, allocated);
            if (!new_data)
                goto cleanup;
            data = new_data;
        }
    }

    /* Try to decode as PEM first */
    if (data_len > 10 && memcmp(data, "-----BEGIN", 10) == 0)
    {
        BIO *mem = BIO_new_mem_buf(data, data_len);
        if (mem)
        {
            char *name = NULL, *header = NULL;
            unsigned char *der = NULL;
            long der_len;

            if (PEM_read_bio(mem, &name, &header, &der, &der_len))
            {
                if (strstr(name, "PUBLIC KEY"))
                {
                    ret = decode_spki(ctx, der, der_len, data_cb, data_cbarg);
                }
                else if (strstr(name, "PRIVATE KEY"))
                {
                    ret = decode_pkcs8(ctx, der, der_len, data_cb, data_cbarg);
                }
                OPENSSL_free(name);
                OPENSSL_free(header);
                OPENSSL_free(der);
            }
            BIO_free(mem);
        }
    }
    else
    {
        /* Try DER decoding */
        /* First try SubjectPublicKeyInfo */
        ret = decode_spki(ctx, data, data_len, data_cb, data_cbarg);
        if (!ret)
        {
            /* Try PrivateKeyInfo */
            ret = decode_pkcs8(ctx, data, data_len, data_cb, data_cbarg);
        }
    }

cleanup:
    OPENSSL_free(data);
    return ret;
}

/* ==========================================================================
 * Dispatch Tables
 * ========================================================================== */

const OSSL_DISPATCH quac100_decoder_spki_der_functions[] = {
    {OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))decoder_newctx},
    {OSSL_FUNC_DECODER_FREECTX, (void (*)(void))decoder_freectx},
    {OSSL_FUNC_DECODER_GETTABLE_PARAMS, (void (*)(void))decoder_gettable_params},
    {OSSL_FUNC_DECODER_GET_PARAMS, (void (*)(void))decoder_get_params},
    {OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS, (void (*)(void))decoder_settable_ctx_params},
    {OSSL_FUNC_DECODER_SET_CTX_PARAMS, (void (*)(void))decoder_set_ctx_params},
    {OSSL_FUNC_DECODER_DECODE, (void (*)(void))decoder_decode},
    {0, NULL}};

const OSSL_DISPATCH quac100_decoder_pkcs8_der_functions[] = {
    {OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))decoder_newctx},
    {OSSL_FUNC_DECODER_FREECTX, (void (*)(void))decoder_freectx},
    {OSSL_FUNC_DECODER_GETTABLE_PARAMS, (void (*)(void))decoder_gettable_params},
    {OSSL_FUNC_DECODER_GET_PARAMS, (void (*)(void))decoder_get_params},
    {OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS, (void (*)(void))decoder_settable_ctx_params},
    {OSSL_FUNC_DECODER_SET_CTX_PARAMS, (void (*)(void))decoder_set_ctx_params},
    {OSSL_FUNC_DECODER_DECODE, (void (*)(void))decoder_decode},
    {0, NULL}};

const OSSL_DISPATCH quac100_decoder_pem_functions[] = {
    {OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))decoder_newctx},
    {OSSL_FUNC_DECODER_FREECTX, (void (*)(void))decoder_freectx},
    {OSSL_FUNC_DECODER_GETTABLE_PARAMS, (void (*)(void))decoder_gettable_params},
    {OSSL_FUNC_DECODER_GET_PARAMS, (void (*)(void))decoder_get_params},
    {OSSL_FUNC_DECODER_SETTABLE_CTX_PARAMS, (void (*)(void))decoder_settable_ctx_params},
    {OSSL_FUNC_DECODER_SET_CTX_PARAMS, (void (*)(void))decoder_set_ctx_params},
    {OSSL_FUNC_DECODER_DECODE, (void (*)(void))decoder_decode},
    {0, NULL}};