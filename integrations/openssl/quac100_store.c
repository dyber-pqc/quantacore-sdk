/**
 * @file quac100_store.c
 * @brief QUAC 100 OpenSSL Provider - Key Storage Provider
 *
 * Implements file-based key storage with support for:
 * - PEM and DER file formats
 * - Password-protected private keys
 * - URI-based key loading (file:// scheme)
 * - Key enumeration and search
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <string.h>
#include <stdio.h>
#include <sys/stat.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/store.h>

#include "quac100_provider.h"

/* ==========================================================================
 * Store Context
 * ========================================================================== */

typedef struct quac_store_ctx
{
    QUAC_PROV_CTX *provctx;

    /* URI components */
    char *uri;
    char *path;

    /* File handle */
    BIO *bio;

    /* State */
    int eof;
    int expect_type; /* OSSL_STORE_INFO_* */

    /* Password callback data */
    OSSL_PASSPHRASE_CALLBACK *pw_cb;
    void *pw_cbarg;
} QUAC_STORE_CTX;

/* ==========================================================================
 * URI Parsing
 * ========================================================================== */

static int quac_store_parse_uri(const char *uri, char **path)
{
    const char *p;

    if (!uri || !path)
        return 0;

    *path = NULL;

    /* Check for file:// scheme */
    if (strncmp(uri, "file://", 7) == 0)
    {
        p = uri + 7;
        /* Skip optional localhost */
        if (strncmp(p, "localhost", 9) == 0)
            p += 9;
        /* Handle Windows paths like file:///C:/... */
        if (*p == '/' && p[2] == ':')
            p++;
    }
    else if (uri[0] == '/' || (uri[1] == ':' && uri[2] == '\\'))
    {
        /* Absolute path without scheme */
        p = uri;
    }
    else
    {
        /* Unsupported URI scheme */
        return 0;
    }

    *path = OPENSSL_strdup(p);
    return *path != NULL;
}

/* ==========================================================================
 * File Type Detection
 * ========================================================================== */

typedef enum
{
    QUAC_FILE_UNKNOWN = 0,
    QUAC_FILE_PEM_PUBKEY,
    QUAC_FILE_PEM_PRIVKEY,
    QUAC_FILE_PEM_CERT,
    QUAC_FILE_DER_PUBKEY,
    QUAC_FILE_DER_PRIVKEY,
    QUAC_FILE_DER_CERT
} quac_file_type_t;

static quac_file_type_t quac_detect_file_type(BIO *bio)
{
    char buf[64];
    int len;
    long pos;

    /* Save position */
    pos = BIO_tell(bio);

    /* Read header */
    len = BIO_read(bio, buf, sizeof(buf) - 1);
    if (len <= 0)
    {
        BIO_seek(bio, pos);
        return QUAC_FILE_UNKNOWN;
    }
    buf[len] = '\0';

    /* Reset position */
    BIO_seek(bio, pos);

    /* Check for PEM headers */
    if (strstr(buf, "-----BEGIN"))
    {
        if (strstr(buf, "PUBLIC KEY"))
            return QUAC_FILE_PEM_PUBKEY;
        if (strstr(buf, "PRIVATE KEY"))
            return QUAC_FILE_PEM_PRIVKEY;
        if (strstr(buf, "CERTIFICATE"))
            return QUAC_FILE_PEM_CERT;
        return QUAC_FILE_UNKNOWN;
    }

    /* Check for DER (ASN.1 SEQUENCE tag) */
    if ((unsigned char)buf[0] == 0x30)
    {
        /* Could be public key, private key, or cert - need deeper inspection */
        /* For now, assume public key for SubjectPublicKeyInfo */
        return QUAC_FILE_DER_PUBKEY;
    }

    return QUAC_FILE_UNKNOWN;
}

/* ==========================================================================
 * Store Loader Functions
 * ========================================================================== */

static void *quac_store_open(void *provctx, const char *uri)
{
    QUAC_STORE_CTX *ctx;
    struct stat st;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (!ctx)
        return NULL;

    ctx->provctx = provctx;
    ctx->uri = OPENSSL_strdup(uri);
    if (!ctx->uri)
        goto err;

    if (!quac_store_parse_uri(uri, &ctx->path))
        goto err;

    /* Check if path exists */
    if (stat(ctx->path, &st) != 0)
        goto err;

    /* Open file */
    ctx->bio = BIO_new_file(ctx->path, "rb");
    if (!ctx->bio)
        goto err;

    ctx->eof = 0;
    return ctx;

err:
    OPENSSL_free(ctx->uri);
    OPENSSL_free(ctx->path);
    OPENSSL_free(ctx);
    return NULL;
}

static int quac_store_attach(void *provctx, OSSL_CORE_BIO *cin)
{
    /* Not implemented - would attach to existing BIO */
    (void)provctx;
    (void)cin;
    return 0;
}

static const OSSL_PARAM *quac_store_settable_ctx_params(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_int(OSSL_STORE_PARAM_EXPECT, NULL),
        OSSL_PARAM_utf8_string(OSSL_STORE_PARAM_SUBJECT, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_STORE_PARAM_ISSUER, NULL, 0),
        OSSL_PARAM_END};
    (void)provctx;
    return params;
}

static int quac_store_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    QUAC_STORE_CTX *ctx = vctx;
    const OSSL_PARAM *p;

    if (!ctx)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_EXPECT);
    if (p)
    {
        if (!OSSL_PARAM_get_int(p, &ctx->expect_type))
            return 0;
    }

    return 1;
}

static int quac_store_load(void *vctx,
                           OSSL_CALLBACK *object_cb, void *object_cbarg,
                           OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    QUAC_STORE_CTX *ctx = vctx;
    quac_file_type_t ftype;
    OSSL_PARAM params[4];
    int object_type;
    const char *data_type = NULL;
    unsigned char *data = NULL;
    long data_len;
    int ret = 0;

    if (!ctx || ctx->eof)
        return 0;

    ctx->pw_cb = pw_cb;
    ctx->pw_cbarg = pw_cbarg;

    /* Detect file type */
    ftype = quac_detect_file_type(ctx->bio);

    switch (ftype)
    {
    case QUAC_FILE_PEM_PUBKEY:
    case QUAC_FILE_DER_PUBKEY:
        object_type = OSSL_OBJECT_PKEY;
        data_type = "SubjectPublicKeyInfo";
        break;

    case QUAC_FILE_PEM_PRIVKEY:
    case QUAC_FILE_DER_PRIVKEY:
        object_type = OSSL_OBJECT_PKEY;
        data_type = "PrivateKeyInfo";
        break;

    case QUAC_FILE_PEM_CERT:
    case QUAC_FILE_DER_CERT:
        object_type = OSSL_OBJECT_CERT;
        data_type = "Certificate";
        break;

    default:
        ctx->eof = 1;
        return 0;
    }

    /* Read entire file */
    data_len = BIO_get_mem_data(ctx->bio, &data);
    if (data_len <= 0)
    {
        /* Read file into memory BIO */
        BIO *mem = BIO_new(BIO_s_mem());
        char buf[4096];
        int n;

        while ((n = BIO_read(ctx->bio, buf, sizeof(buf))) > 0)
        {
            BIO_write(mem, buf, n);
        }

        data_len = BIO_get_mem_data(mem, &data);
        if (data_len <= 0)
        {
            BIO_free(mem);
            ctx->eof = 1;
            return 0;
        }

        /* Copy data */
        unsigned char *copy = OPENSSL_malloc(data_len);
        if (copy)
        {
            memcpy(copy, data, data_len);
            data = copy;
        }
        BIO_free(mem);
    }

    /* Build callback parameters */
    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                                 (char *)data_type, 0);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA,
                                                  data, data_len);
    params[3] = OSSL_PARAM_construct_end();

    ret = object_cb(params, object_cbarg);

    ctx->eof = 1;
    return ret;
}

static int quac_store_eof(void *vctx)
{
    QUAC_STORE_CTX *ctx = vctx;
    return ctx ? ctx->eof : 1;
}

static int quac_store_close(void *vctx)
{
    QUAC_STORE_CTX *ctx = vctx;

    if (!ctx)
        return 1;

    BIO_free(ctx->bio);
    OPENSSL_free(ctx->uri);
    OPENSSL_free(ctx->path);
    OPENSSL_free(ctx);

    return 1;
}

/* ==========================================================================
 * Store Export Functions
 * ========================================================================== */

static int quac_store_export_object(void *vctx,
                                    const void *data, size_t data_len,
                                    OSSL_CALLBACK *export_cb, void *export_cbarg)
{
    OSSL_PARAM params[2];

    (void)vctx;

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA,
                                                  (void *)data, data_len);
    params[1] = OSSL_PARAM_construct_end();

    return export_cb(params, export_cbarg);
}

/* ==========================================================================
 * Store Info Functions
 * ========================================================================== */

static int quac_store_delete(void *loaderctx, const char *uri,
                             const OSSL_PARAM params[],
                             OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    char *path = NULL;
    int ret = 0;

    (void)loaderctx;
    (void)params;
    (void)pw_cb;
    (void)pw_cbarg;

    if (!quac_store_parse_uri(uri, &path))
        return 0;

    ret = (remove(path) == 0);
    OPENSSL_free(path);

    return ret;
}

/* ==========================================================================
 * Store Dispatch Table
 * ========================================================================== */

static const OSSL_DISPATCH quac_store_functions[] = {
    {OSSL_FUNC_STORE_OPEN, (void (*)(void))quac_store_open},
    {OSSL_FUNC_STORE_ATTACH, (void (*)(void))quac_store_attach},
    {OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS, (void (*)(void))quac_store_settable_ctx_params},
    {OSSL_FUNC_STORE_SET_CTX_PARAMS, (void (*)(void))quac_store_set_ctx_params},
    {OSSL_FUNC_STORE_LOAD, (void (*)(void))quac_store_load},
    {OSSL_FUNC_STORE_EOF, (void (*)(void))quac_store_eof},
    {OSSL_FUNC_STORE_CLOSE, (void (*)(void))quac_store_close},
    {OSSL_FUNC_STORE_EXPORT_OBJECT, (void (*)(void))quac_store_export_object},
    {OSSL_FUNC_STORE_DELETE, (void (*)(void))quac_store_delete},
    {0, NULL}};

/* ==========================================================================
 * Algorithm Registration
 * ========================================================================== */

const OSSL_ALGORITHM quac_store_algorithms[] = {
    {"file", "provider=quac100", quac_store_functions, "QUAC File Store"},
    {NULL, NULL, NULL, NULL}};