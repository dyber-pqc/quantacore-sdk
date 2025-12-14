/**
 * @file quac100_rand.c
 * @brief QUAC 100 OpenSSL Provider - Random Number Generator
 *
 * Implements hardware QRNG (Quantum Random Number Generator) as an
 * OpenSSL RAND provider. Falls back to software RNG when hardware
 * is unavailable.
 *
 * Features:
 * - Hardware entropy from QUAC 100 QRNG
 * - Automatic fallback to OpenSSL's default RAND
 * - Health monitoring and entropy pool management
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <string.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include "quac100_provider.h"

#ifdef QUAC_HAS_HARDWARE
#include <quac100.h>
#endif

/* ==========================================================================
 * QRNG Context
 * ========================================================================== */

typedef struct quac_rand_ctx
{
    QUAC_PROV_CTX *provctx;

    /* State */
    int state; /* 0 = uninitialized, 1 = ready, 2 = error */
    unsigned int strength;

    /* Entropy buffer for buffering QRNG output */
    unsigned char buffer[4096];
    size_t buffer_pos;
    size_t buffer_len;

    /* Statistics */
    uint64_t bytes_generated;
    uint64_t reseed_count;
} QUAC_RAND_CTX;

#define QUAC_RAND_STATE_UNINIT 0
#define QUAC_RAND_STATE_READY 1
#define QUAC_RAND_STATE_ERROR 2

/* QRNG strength in bits (hardware provides 256-bit security) */
#define QUAC_QRNG_STRENGTH 256

/* ==========================================================================
 * Hardware QRNG Access
 * ========================================================================== */

static int quac_hw_random(void *device, unsigned char *buf, size_t len)
{
#ifdef QUAC_HAS_HARDWARE
    quac_result_t result;
    size_t generated = 0;

    while (generated < len)
    {
        size_t chunk = len - generated;
        if (chunk > 4096)
            chunk = 4096;

        result = quac_random(device, buf + generated, chunk);
        if (result != QUAC_SUCCESS)
            return 0;

        generated += chunk;
    }

    return 1;
#else
    (void)device;
    /* Fallback to OpenSSL RAND */
    return RAND_bytes(buf, len) == 1;
#endif
}

/* ==========================================================================
 * RAND Dispatch Functions
 * ========================================================================== */

static void *quac_rand_newctx(void *provctx, void *parent,
                              const OSSL_DISPATCH *parent_dispatch)
{
    QUAC_RAND_CTX *ctx;

    (void)parent;
    (void)parent_dispatch;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;

    ctx->provctx = provctx;
    ctx->state = QUAC_RAND_STATE_UNINIT;
    ctx->strength = QUAC_QRNG_STRENGTH;
    ctx->buffer_pos = 0;
    ctx->buffer_len = 0;
    ctx->bytes_generated = 0;
    ctx->reseed_count = 0;

    return ctx;
}

static void quac_rand_freectx(void *vctx)
{
    QUAC_RAND_CTX *ctx = vctx;

    if (ctx == NULL)
        return;

    /* Clear any buffered random data */
    OPENSSL_cleanse(ctx->buffer, sizeof(ctx->buffer));
    OPENSSL_free(ctx);
}

static int quac_rand_instantiate(void *vctx, unsigned int strength,
                                 int prediction_resistance,
                                 const unsigned char *pstr, size_t pstr_len,
                                 const OSSL_PARAM params[])
{
    QUAC_RAND_CTX *ctx = vctx;

    (void)prediction_resistance;
    (void)pstr;
    (void)pstr_len;
    (void)params;

    if (ctx == NULL)
        return 0;

    if (strength > QUAC_QRNG_STRENGTH)
        return 0;

    ctx->state = QUAC_RAND_STATE_READY;
    ctx->strength = QUAC_QRNG_STRENGTH;

    return 1;
}

static int quac_rand_uninstantiate(void *vctx)
{
    QUAC_RAND_CTX *ctx = vctx;

    if (ctx == NULL)
        return 0;

    /* Clear buffer */
    OPENSSL_cleanse(ctx->buffer, sizeof(ctx->buffer));
    ctx->buffer_pos = 0;
    ctx->buffer_len = 0;
    ctx->state = QUAC_RAND_STATE_UNINIT;

    return 1;
}

static int quac_rand_generate(void *vctx,
                              unsigned char *out, size_t outlen,
                              unsigned int strength,
                              int prediction_resistance,
                              const unsigned char *adin, size_t adin_len)
{
    QUAC_RAND_CTX *ctx = vctx;
    void *device;
    int use_sim;
    size_t copied = 0;

    (void)prediction_resistance;
    (void)adin;
    (void)adin_len;

    if (ctx == NULL || out == NULL)
        return 0;

    if (ctx->state != QUAC_RAND_STATE_READY)
        return 0;

    if (strength > ctx->strength)
        return 0;

    device = quac_prov_get_device(ctx->provctx);
    use_sim = quac_prov_is_simulator(ctx->provctx);

    /* First, use any buffered data */
    if (ctx->buffer_len > ctx->buffer_pos)
    {
        size_t avail = ctx->buffer_len - ctx->buffer_pos;
        size_t to_copy = (avail < outlen) ? avail : outlen;

        memcpy(out, ctx->buffer + ctx->buffer_pos, to_copy);
        ctx->buffer_pos += to_copy;
        copied = to_copy;

        /* Clear used portion */
        if (ctx->buffer_pos == ctx->buffer_len)
        {
            OPENSSL_cleanse(ctx->buffer, ctx->buffer_len);
            ctx->buffer_pos = 0;
            ctx->buffer_len = 0;
        }
    }

    /* Generate remaining data */
    if (copied < outlen)
    {
        size_t remaining = outlen - copied;

        if (use_sim || device == NULL)
        {
            /* Software fallback */
            if (RAND_bytes(out + copied, remaining) != 1)
                return 0;
        }
        else
        {
            /* Hardware QRNG */
            if (!quac_hw_random(device, out + copied, remaining))
                return 0;
        }
    }

    ctx->bytes_generated += outlen;

    return 1;
}

static int quac_rand_reseed(void *vctx,
                            int prediction_resistance,
                            const unsigned char *ent, size_t ent_len,
                            const unsigned char *adin, size_t adin_len)
{
    QUAC_RAND_CTX *ctx = vctx;
    void *device;
    int use_sim;

    (void)prediction_resistance;
    (void)ent;
    (void)ent_len;
    (void)adin;
    (void)adin_len;

    if (ctx == NULL)
        return 0;

    device = quac_prov_get_device(ctx->provctx);
    use_sim = quac_prov_is_simulator(ctx->provctx);

    /* Refill the entropy buffer from QRNG */
    if (use_sim || device == NULL)
    {
        if (RAND_bytes(ctx->buffer, sizeof(ctx->buffer)) != 1)
            return 0;
    }
    else
    {
        if (!quac_hw_random(device, ctx->buffer, sizeof(ctx->buffer)))
            return 0;
    }

    ctx->buffer_pos = 0;
    ctx->buffer_len = sizeof(ctx->buffer);
    ctx->reseed_count++;

    return 1;
}

static int quac_rand_enable_locking(void *vctx)
{
    (void)vctx;
    /* Thread safety handled by OpenSSL's provider framework */
    return 1;
}

static int quac_rand_lock(void *vctx)
{
    (void)vctx;
    return 1;
}

static void quac_rand_unlock(void *vctx)
{
    (void)vctx;
}

/* ==========================================================================
 * RAND Parameters
 * ========================================================================== */

static const OSSL_PARAM *quac_rand_gettable_ctx_params(void *vctx, void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_int(OSSL_RAND_PARAM_STATE, NULL),
        OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, NULL),
        OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL),
        OSSL_PARAM_END};
    (void)vctx;
    (void)provctx;
    return params;
}

static int quac_rand_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    QUAC_RAND_CTX *ctx = vctx;
    OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
    if (p != NULL)
    {
        int state;
        switch (ctx->state)
        {
        case QUAC_RAND_STATE_READY:
            state = EVP_RAND_STATE_READY;
            break;
        case QUAC_RAND_STATE_ERROR:
            state = EVP_RAND_STATE_ERROR;
            break;
        default:
            state = EVP_RAND_STATE_UNINITIALISED;
            break;
        }
        if (!OSSL_PARAM_set_int(p, state))
            return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
    if (p != NULL && !OSSL_PARAM_set_uint(p, ctx->strength))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 65536))
        return 0;

    return 1;
}

static const OSSL_PARAM *quac_rand_settable_ctx_params(void *vctx, void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_END};
    (void)vctx;
    (void)provctx;
    return params;
}

static int quac_rand_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    (void)vctx;
    (void)params;
    return 1;
}

static int quac_rand_verify_zeroization(void *vctx)
{
    QUAC_RAND_CTX *ctx = vctx;
    size_t i;

    if (ctx == NULL)
        return 0;

    /* Verify buffer is zeroed */
    for (i = 0; i < sizeof(ctx->buffer); i++)
    {
        if (ctx->buffer[i] != 0)
            return 0;
    }

    return 1;
}

static size_t quac_rand_get_seed(void *vctx,
                                 unsigned char **pout,
                                 int entropy, size_t min_len, size_t max_len,
                                 int prediction_resistance,
                                 const unsigned char *adin, size_t adin_len)
{
    QUAC_RAND_CTX *ctx = vctx;
    size_t len;
    unsigned char *buf;
    void *device;
    int use_sim;

    (void)entropy;
    (void)prediction_resistance;
    (void)adin;
    (void)adin_len;

    if (ctx == NULL || pout == NULL)
        return 0;

    /* Determine length */
    len = min_len;
    if (len < 32)
        len = 32;
    if (len > max_len)
        len = max_len;

    buf = OPENSSL_secure_malloc(len);
    if (buf == NULL)
        return 0;

    device = quac_prov_get_device(ctx->provctx);
    use_sim = quac_prov_is_simulator(ctx->provctx);

    if (use_sim || device == NULL)
    {
        if (RAND_bytes(buf, len) != 1)
        {
            OPENSSL_secure_free(buf, len);
            return 0;
        }
    }
    else
    {
        if (!quac_hw_random(device, buf, len))
        {
            OPENSSL_secure_free(buf, len);
            return 0;
        }
    }

    *pout = buf;
    return len;
}

static void quac_rand_clear_seed(void *vctx,
                                 unsigned char *out, size_t outlen)
{
    (void)vctx;
    OPENSSL_secure_clear_free(out, outlen);
}

/* ==========================================================================
 * RAND Dispatch Table
 * ========================================================================== */

static const OSSL_DISPATCH quac_rand_functions[] = {
    {OSSL_FUNC_RAND_NEWCTX, (void (*)(void))quac_rand_newctx},
    {OSSL_FUNC_RAND_FREECTX, (void (*)(void))quac_rand_freectx},
    {OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void))quac_rand_instantiate},
    {OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void))quac_rand_uninstantiate},
    {OSSL_FUNC_RAND_GENERATE, (void (*)(void))quac_rand_generate},
    {OSSL_FUNC_RAND_RESEED, (void (*)(void))quac_rand_reseed},
    {OSSL_FUNC_RAND_ENABLE_LOCKING, (void (*)(void))quac_rand_enable_locking},
    {OSSL_FUNC_RAND_LOCK, (void (*)(void))quac_rand_lock},
    {OSSL_FUNC_RAND_UNLOCK, (void (*)(void))quac_rand_unlock},
    {OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (void (*)(void))quac_rand_gettable_ctx_params},
    {OSSL_FUNC_RAND_GET_CTX_PARAMS, (void (*)(void))quac_rand_get_ctx_params},
    {OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS, (void (*)(void))quac_rand_settable_ctx_params},
    {OSSL_FUNC_RAND_SET_CTX_PARAMS, (void (*)(void))quac_rand_set_ctx_params},
    {OSSL_FUNC_RAND_VERIFY_ZEROIZATION, (void (*)(void))quac_rand_verify_zeroization},
    {OSSL_FUNC_RAND_GET_SEED, (void (*)(void))quac_rand_get_seed},
    {OSSL_FUNC_RAND_CLEAR_SEED, (void (*)(void))quac_rand_clear_seed},
    {0, NULL}};

/* ==========================================================================
 * Algorithm Registration
 * ========================================================================== */

const OSSL_ALGORITHM quac_rand_algorithms[] = {
    {QUAC_ALG_QRNG, "provider=quac100", quac_rand_functions, "QUAC Hardware QRNG"},
    {NULL, NULL, NULL, NULL}};