/**
 * @file quac100_provider.c
 * @brief QUAC 100 OpenSSL 3.x Provider - Main Implementation
 *
 * This provider enables transparent hardware acceleration for post-quantum
 * cryptographic operations through OpenSSL's provider interface.
 *
 * Supported algorithms:
 * - ML-KEM-512, ML-KEM-768, ML-KEM-1024 (FIPS 203)
 * - ML-DSA-44, ML-DSA-65, ML-DSA-87 (FIPS 204)
 * - SLH-DSA variants (FIPS 205)
 * - QRNG (hardware random number generation)
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/crypto.h>

#include "quac100_provider.h"

#ifdef QUAC_HAS_HARDWARE
#include <quac100.h>
#endif

/* ==========================================================================
 * Provider Context Structure
 * ========================================================================== */

struct quac_prov_ctx
{
    const OSSL_CORE_HANDLE *handle;
    OSSL_LIB_CTX *libctx;

    /* Core functions from OpenSSL */
    OSSL_FUNC_core_gettable_params_fn *core_gettable_params;
    OSSL_FUNC_core_get_params_fn *core_get_params;
    OSSL_FUNC_core_new_error_fn *core_new_error;
    OSSL_FUNC_core_set_error_debug_fn *core_set_error_debug;
    OSSL_FUNC_core_vset_error_fn *core_vset_error;

    /* QUAC device handle */
    void *quac_ctx;
    void *quac_device;
    int use_simulator;

    /* Provider info */
    char *name;
    char *version;
};

/* Global provider context */
static QUAC_PROV_CTX *g_provctx = NULL;

/* ==========================================================================
 * Provider Information
 * ========================================================================== */

#define QUAC_PROVIDER_NAME "quac100"
#define QUAC_PROVIDER_VERSION "1.0.0"
#define QUAC_PROVIDER_BUILDINFO "QUAC 100 PQC Accelerator Provider (Dyber, Inc.)"

/* ==========================================================================
 * Error Handling
 * ========================================================================== */

#define QUAC_R_INTERNAL_ERROR 1
#define QUAC_R_INVALID_KEY 2
#define QUAC_R_OPERATION_FAILED 3
#define QUAC_R_DEVICE_NOT_AVAILABLE 4
#define QUAC_R_UNSUPPORTED_ALGORITHM 5
#define QUAC_R_MALLOC_FAILURE 6
#define QUAC_R_INVALID_PARAM 7

static const OSSL_ITEM quac_reason_strings[] = {
    {QUAC_R_INTERNAL_ERROR, "internal error"},
    {QUAC_R_INVALID_KEY, "invalid key"},
    {QUAC_R_OPERATION_FAILED, "operation failed"},
    {QUAC_R_DEVICE_NOT_AVAILABLE, "device not available"},
    {QUAC_R_UNSUPPORTED_ALGORITHM, "unsupported algorithm"},
    {QUAC_R_MALLOC_FAILURE, "memory allocation failed"},
    {QUAC_R_INVALID_PARAM, "invalid parameter"},
    {0, NULL}};

void quac_prov_raise_error(QUAC_PROV_CTX *ctx, int reason, const char *fmt, ...)
{
    if (ctx && ctx->core_new_error && ctx->core_vset_error)
    {
        ctx->core_new_error(ctx->handle);
        if (fmt)
        {
            va_list args;
            va_start(args, fmt);
            ctx->core_vset_error(ctx->handle, reason, fmt, args);
            va_end(args);
        }
    }
}

/* ==========================================================================
 * Algorithm Dispatch Tables (external declarations)
 * ========================================================================== */

extern const OSSL_ALGORITHM quac_kem_algorithms[];
extern const OSSL_ALGORITHM quac_signature_algorithms[];
extern const OSSL_ALGORITHM quac_keymgmt_algorithms[];
extern const OSSL_ALGORITHM quac_rand_algorithms[];

/* ==========================================================================
 * Provider Parameters
 * ========================================================================== */

static const OSSL_PARAM *quac_gettable_params(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
        OSSL_PARAM_END};
    (void)provctx;
    return params;
}

static int quac_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    (void)provctx;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, QUAC_PROVIDER_NAME))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, QUAC_PROVIDER_VERSION))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, QUAC_PROVIDER_BUILDINFO))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))
        return 0;

    return 1;
}

/* ==========================================================================
 * Algorithm Query
 * ========================================================================== */

static const OSSL_ALGORITHM *quac_query(void *provctx, int operation_id,
                                        int *no_cache)
{
    (void)provctx;
    *no_cache = 0;

    switch (operation_id)
    {
    case OSSL_OP_KEM:
        return quac_kem_algorithms;

    case OSSL_OP_SIGNATURE:
        return quac_signature_algorithms;

    case OSSL_OP_KEYMGMT:
        return quac_keymgmt_algorithms;

    case OSSL_OP_RAND:
        return quac_rand_algorithms;

    default:
        return NULL;
    }
}

/* ==========================================================================
 * Provider Lifecycle
 * ========================================================================== */

static const OSSL_ITEM *quac_get_reason_strings(void *provctx)
{
    (void)provctx;
    return quac_reason_strings;
}

static int quac_self_test(void *provctx)
{
    QUAC_PROV_CTX *ctx = provctx;
    (void)ctx;
    return 1;
}

static void quac_teardown(void *provctx)
{
    QUAC_PROV_CTX *ctx = provctx;

    if (ctx == NULL)
        return;

#ifdef QUAC_HAS_HARDWARE
    if (ctx->quac_device)
    {
        quac_close_device(ctx->quac_device);
        ctx->quac_device = NULL;
    }
    if (ctx->quac_ctx)
    {
        quac_shutdown(ctx->quac_ctx);
        ctx->quac_ctx = NULL;
    }
#endif

    OPENSSL_free(ctx->name);
    OPENSSL_free(ctx->version);
    OPENSSL_free(ctx);

    g_provctx = NULL;
}

/* ==========================================================================
 * Provider Dispatch Table
 * ========================================================================== */

static const OSSL_DISPATCH quac_dispatch_table[] = {
    {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))quac_gettable_params},
    {OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))quac_get_params},
    {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))quac_query},
    {OSSL_FUNC_PROVIDER_GET_REASON_STRINGS, (void (*)(void))quac_get_reason_strings},
    {OSSL_FUNC_PROVIDER_SELF_TEST, (void (*)(void))quac_self_test},
    {OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))quac_teardown},
    {0, NULL}};

/* ==========================================================================
 * Initialization Helpers
 * ========================================================================== */

static int quac_init_core_functions(QUAC_PROV_CTX *ctx, const OSSL_DISPATCH *in)
{
    for (; in->function_id != 0; in++)
    {
        switch (in->function_id)
        {
        case OSSL_FUNC_CORE_GETTABLE_PARAMS:
            ctx->core_gettable_params = OSSL_FUNC_core_gettable_params(in);
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            ctx->core_get_params = OSSL_FUNC_core_get_params(in);
            break;
        case OSSL_FUNC_CORE_NEW_ERROR:
            ctx->core_new_error = OSSL_FUNC_core_new_error(in);
            break;
        case OSSL_FUNC_CORE_SET_ERROR_DEBUG:
            ctx->core_set_error_debug = OSSL_FUNC_core_set_error_debug(in);
            break;
        case OSSL_FUNC_CORE_VSET_ERROR:
            ctx->core_vset_error = OSSL_FUNC_core_vset_error(in);
            break;
        }
    }
    return 1;
}

static int quac_init_device(QUAC_PROV_CTX *ctx)
{
#ifdef QUAC_HAS_HARDWARE
    quac_result_t result;
    uint32_t device_count;

    result = quac_init((quac_context_t **)&ctx->quac_ctx);
    if (result != QUAC_SUCCESS)
    {
        ctx->use_simulator = 1;
        return 1;
    }

    result = quac_get_device_count(ctx->quac_ctx, &device_count);
    if (result != QUAC_SUCCESS || device_count == 0)
    {
        quac_shutdown(ctx->quac_ctx);
        ctx->quac_ctx = NULL;
        ctx->use_simulator = 1;
        return 1;
    }

    result = quac_open_device(ctx->quac_ctx, 0, (quac_device_t **)&ctx->quac_device);
    if (result != QUAC_SUCCESS)
    {
        quac_shutdown(ctx->quac_ctx);
        ctx->quac_ctx = NULL;
        ctx->use_simulator = 1;
        return 1;
    }

    ctx->use_simulator = 0;
    return 1;
#else
    ctx->use_simulator = 1;
    ctx->quac_ctx = NULL;
    ctx->quac_device = NULL;
    return 1;
#endif
}

/* ==========================================================================
 * Provider Entry Point (exported)
 * ========================================================================== */

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    QUAC_PROV_CTX *ctx;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return 0;

    ctx->handle = handle;
    ctx->libctx = NULL;
    ctx->name = OPENSSL_strdup(QUAC_PROVIDER_NAME);
    ctx->version = OPENSSL_strdup(QUAC_PROVIDER_VERSION);

    if (ctx->name == NULL || ctx->version == NULL)
    {
        quac_teardown(ctx);
        return 0;
    }

    if (!quac_init_core_functions(ctx, in))
    {
        quac_teardown(ctx);
        return 0;
    }

    if (!quac_init_device(ctx))
    {
        quac_teardown(ctx);
        return 0;
    }

    *out = quac_dispatch_table;
    *provctx = ctx;
    g_provctx = ctx;

    return 1;
}

/* ==========================================================================
 * Context Accessors
 * ========================================================================== */

QUAC_PROV_CTX *quac_prov_get_ctx(void) { return g_provctx; }
void *quac_prov_get_device(QUAC_PROV_CTX *ctx) { return ctx ? ctx->quac_device : NULL; }
int quac_prov_is_simulator(QUAC_PROV_CTX *ctx) { return ctx ? ctx->use_simulator : 1; }
const OSSL_CORE_HANDLE *quac_prov_get_handle(QUAC_PROV_CTX *ctx) { return ctx ? ctx->handle : NULL; }
OSSL_LIB_CTX *quac_prov_get_libctx(QUAC_PROV_CTX *ctx) { return ctx ? ctx->libctx : NULL; }

/* ==========================================================================
 * Key Management
 * ========================================================================== */

QUAC_KEY *quac_key_new(QUAC_PROV_CTX *provctx, quac_key_type_t type)
{
    QUAC_KEY *key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL)
        return NULL;
    key->provctx = provctx;
    key->type = type;
    key->refcnt = 1;
    return key;
}

void quac_key_free(QUAC_KEY *key)
{
    if (key == NULL)
        return;
    if (--key->refcnt > 0)
        return;
    if (key->privkey)
    {
        OPENSSL_cleanse(key->privkey, key->privkey_len);
        OPENSSL_free(key->privkey);
    }
    OPENSSL_free(key->pubkey);
    OPENSSL_free(key);
}

int quac_key_up_ref(QUAC_KEY *key)
{
    if (key)
        key->refcnt++;
    return key != NULL;
}

QUAC_KEY *quac_key_dup(const QUAC_KEY *key)
{
    QUAC_KEY *newkey;
    if (key == NULL)
        return NULL;
    newkey = quac_key_new(key->provctx, key->type);
    if (newkey == NULL)
        return NULL;
    if (key->pubkey)
    {
        newkey->pubkey = OPENSSL_memdup(key->pubkey, key->pubkey_len);
        if (newkey->pubkey == NULL)
        {
            quac_key_free(newkey);
            return NULL;
        }
        newkey->pubkey_len = key->pubkey_len;
        newkey->has_public = 1;
    }
    if (key->privkey)
    {
        newkey->privkey = OPENSSL_secure_malloc(key->privkey_len);
        if (newkey->privkey == NULL)
        {
            quac_key_free(newkey);
            return NULL;
        }
        memcpy(newkey->privkey, key->privkey, key->privkey_len);
        newkey->privkey_len = key->privkey_len;
        newkey->has_private = 1;
    }
    return newkey;
}

const char *quac_key_type_name(quac_key_type_t type)
{
    switch (type)
    {
    case QUAC_KEY_TYPE_ML_KEM_512:
        return QUAC_ALG_ML_KEM_512;
    case QUAC_KEY_TYPE_ML_KEM_768:
        return QUAC_ALG_ML_KEM_768;
    case QUAC_KEY_TYPE_ML_KEM_1024:
        return QUAC_ALG_ML_KEM_1024;
    case QUAC_KEY_TYPE_ML_DSA_44:
        return QUAC_ALG_ML_DSA_44;
    case QUAC_KEY_TYPE_ML_DSA_65:
        return QUAC_ALG_ML_DSA_65;
    case QUAC_KEY_TYPE_ML_DSA_87:
        return QUAC_ALG_ML_DSA_87;
    default:
        return "unknown";
    }
}

quac_key_type_t quac_key_type_from_name(const char *name)
{
    if (!name)
        return QUAC_KEY_TYPE_UNKNOWN;
    if (strcmp(name, QUAC_ALG_ML_KEM_512) == 0)
        return QUAC_KEY_TYPE_ML_KEM_512;
    if (strcmp(name, QUAC_ALG_ML_KEM_768) == 0)
        return QUAC_KEY_TYPE_ML_KEM_768;
    if (strcmp(name, QUAC_ALG_ML_KEM_1024) == 0)
        return QUAC_KEY_TYPE_ML_KEM_1024;
    if (strcmp(name, QUAC_ALG_ML_DSA_44) == 0)
        return QUAC_KEY_TYPE_ML_DSA_44;
    if (strcmp(name, QUAC_ALG_ML_DSA_65) == 0)
        return QUAC_KEY_TYPE_ML_DSA_65;
    if (strcmp(name, QUAC_ALG_ML_DSA_87) == 0)
        return QUAC_KEY_TYPE_ML_DSA_87;
    return QUAC_KEY_TYPE_UNKNOWN;
}

int quac_key_type_is_kem(quac_key_type_t t)
{
    return t == QUAC_KEY_TYPE_ML_KEM_512 || t == QUAC_KEY_TYPE_ML_KEM_768 || t == QUAC_KEY_TYPE_ML_KEM_1024;
}

int quac_key_type_is_sig(quac_key_type_t t)
{
    return t == QUAC_KEY_TYPE_ML_DSA_44 || t == QUAC_KEY_TYPE_ML_DSA_65 || t == QUAC_KEY_TYPE_ML_DSA_87;
}

size_t quac_key_type_pk_size(quac_key_type_t type)
{
    switch (type)
    {
    case QUAC_KEY_TYPE_ML_KEM_512:
        return QUAC_ML_KEM_512_PK_SIZE;
    case QUAC_KEY_TYPE_ML_KEM_768:
        return QUAC_ML_KEM_768_PK_SIZE;
    case QUAC_KEY_TYPE_ML_KEM_1024:
        return QUAC_ML_KEM_1024_PK_SIZE;
    case QUAC_KEY_TYPE_ML_DSA_44:
        return QUAC_ML_DSA_44_PK_SIZE;
    case QUAC_KEY_TYPE_ML_DSA_65:
        return QUAC_ML_DSA_65_PK_SIZE;
    case QUAC_KEY_TYPE_ML_DSA_87:
        return QUAC_ML_DSA_87_PK_SIZE;
    default:
        return 0;
    }
}

size_t quac_key_type_sk_size(quac_key_type_t type)
{
    switch (type)
    {
    case QUAC_KEY_TYPE_ML_KEM_512:
        return QUAC_ML_KEM_512_SK_SIZE;
    case QUAC_KEY_TYPE_ML_KEM_768:
        return QUAC_ML_KEM_768_SK_SIZE;
    case QUAC_KEY_TYPE_ML_KEM_1024:
        return QUAC_ML_KEM_1024_SK_SIZE;
    case QUAC_KEY_TYPE_ML_DSA_44:
        return QUAC_ML_DSA_44_SK_SIZE;
    case QUAC_KEY_TYPE_ML_DSA_65:
        return QUAC_ML_DSA_65_SK_SIZE;
    case QUAC_KEY_TYPE_ML_DSA_87:
        return QUAC_ML_DSA_87_SK_SIZE;
    default:
        return 0;
    }
}

void quac_cleanse(void *ptr, size_t len) { OPENSSL_cleanse(ptr, len); }
void *quac_secure_alloc(size_t size) { return OPENSSL_secure_malloc(size); }
void quac_secure_free(void *ptr, size_t size)
{
    if (ptr)
    {
        OPENSSL_cleanse(ptr, size);
        OPENSSL_secure_free(ptr);
    }
}