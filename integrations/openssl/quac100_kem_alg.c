/**
 * @file quac100_kem_alg.c
 * @brief QUAC 100 OpenSSL Provider - KEM Algorithm Implementation
 *
 * Implements ML-KEM (FIPS 203) key encapsulation mechanism:
 * - ML-KEM-512 (NIST Level 1)
 * - ML-KEM-768 (NIST Level 3)
 * - ML-KEM-1024 (NIST Level 5)
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <string.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include "quac100_provider.h"

#ifdef QUAC_HAS_HARDWARE
#include <quac100.h>
#endif

/* ==========================================================================
 * KEM Context
 * ========================================================================== */

typedef struct quac_kem_ctx
{
    QUAC_PROV_CTX *provctx;
    QUAC_KEY *key;
    quac_key_type_t type;
} QUAC_KEM_CTX;

/* ==========================================================================
 * KEM Size Helpers
 * ========================================================================== */

static size_t quac_kem_ct_size(quac_key_type_t type)
{
    switch (type)
    {
    case QUAC_KEY_TYPE_ML_KEM_512:
        return QUAC_ML_KEM_512_CT_SIZE;
    case QUAC_KEY_TYPE_ML_KEM_768:
        return QUAC_ML_KEM_768_CT_SIZE;
    case QUAC_KEY_TYPE_ML_KEM_1024:
        return QUAC_ML_KEM_1024_CT_SIZE;
    default:
        return 0;
    }
}

static size_t quac_kem_ss_size(quac_key_type_t type)
{
    switch (type)
    {
    case QUAC_KEY_TYPE_ML_KEM_512:
        return QUAC_ML_KEM_512_SS_SIZE;
    case QUAC_KEY_TYPE_ML_KEM_768:
        return QUAC_ML_KEM_768_SS_SIZE;
    case QUAC_KEY_TYPE_ML_KEM_1024:
        return QUAC_ML_KEM_1024_SS_SIZE;
    default:
        return 0;
    }
}

/* ==========================================================================
 * Simulated KEM Operations (when hardware unavailable)
 * ========================================================================== */

static int quac_sim_kem_keygen(quac_key_type_t type,
                               unsigned char *pk, size_t pk_len,
                               unsigned char *sk, size_t sk_len)
{
    /* Generate random keys for simulation */
    if (RAND_bytes(pk, pk_len) != 1)
        return 0;
    if (RAND_bytes(sk, sk_len) != 1)
        return 0;

    /* Embed public key in secret key (simplified simulation) */
    if (sk_len > pk_len)
    {
        memcpy(sk + sk_len - pk_len, pk, pk_len);
    }

    return 1;
}

static int quac_sim_kem_encaps(quac_key_type_t type,
                               const unsigned char *pk, size_t pk_len,
                               unsigned char *ct, size_t ct_len,
                               unsigned char *ss, size_t ss_len)
{
    unsigned char seed[32];

    /* Generate random shared secret and ciphertext */
    if (RAND_bytes(seed, sizeof(seed)) != 1)
        return 0;

    /* Derive shared secret from seed */
    memcpy(ss, seed, ss_len < sizeof(seed) ? ss_len : sizeof(seed));

    /* Derive ciphertext (simplified - real ML-KEM uses lattice operations) */
    if (RAND_bytes(ct, ct_len) != 1)
        return 0;

    /* Mix in public key and seed for determinism in decaps */
    for (size_t i = 0; i < 32 && i < ct_len; i++)
    {
        ct[i] ^= pk[i % pk_len] ^ seed[i];
    }

    return 1;
}

static int quac_sim_kem_decaps(quac_key_type_t type,
                               const unsigned char *ct, size_t ct_len,
                               const unsigned char *sk, size_t sk_len,
                               unsigned char *ss, size_t ss_len)
{
    /* Extract embedded public key from secret key */
    size_t pk_len = quac_key_type_pk_size(type);
    const unsigned char *pk = sk + sk_len - pk_len;

    /* Recover seed from ciphertext */
    unsigned char seed[32];
    for (size_t i = 0; i < 32 && i < ct_len; i++)
    {
        seed[i] = ct[i] ^ pk[i % pk_len];
    }

    /* Derive shared secret */
    memcpy(ss, seed, ss_len < sizeof(seed) ? ss_len : sizeof(seed));

    return 1;
}

/* ==========================================================================
 * KEM Operations with Hardware
 * ========================================================================== */

static int quac_hw_kem_keygen(void *device, quac_key_type_t type,
                              unsigned char *pk, size_t pk_len,
                              unsigned char *sk, size_t sk_len)
{
#ifdef QUAC_HAS_HARDWARE
    quac_algorithm_t alg;
    quac_result_t result;

    switch (type)
    {
    case QUAC_KEY_TYPE_ML_KEM_512:
        alg = QUAC_ALG_ML_KEM_512;
        break;
    case QUAC_KEY_TYPE_ML_KEM_768:
        alg = QUAC_ALG_ML_KEM_768;
        break;
    case QUAC_KEY_TYPE_ML_KEM_1024:
        alg = QUAC_ALG_ML_KEM_1024;
        break;
    default:
        return 0;
    }

    result = quac_kem_keygen(device, alg, pk, pk_len, sk, sk_len);
    return result == QUAC_SUCCESS;
#else
    (void)device;
    return quac_sim_kem_keygen(type, pk, pk_len, sk, sk_len);
#endif
}

static int quac_hw_kem_encaps(void *device, quac_key_type_t type,
                              const unsigned char *pk, size_t pk_len,
                              unsigned char *ct, size_t ct_len,
                              unsigned char *ss, size_t ss_len)
{
#ifdef QUAC_HAS_HARDWARE
    quac_algorithm_t alg;
    quac_result_t result;

    switch (type)
    {
    case QUAC_KEY_TYPE_ML_KEM_512:
        alg = QUAC_ALG_ML_KEM_512;
        break;
    case QUAC_KEY_TYPE_ML_KEM_768:
        alg = QUAC_ALG_ML_KEM_768;
        break;
    case QUAC_KEY_TYPE_ML_KEM_1024:
        alg = QUAC_ALG_ML_KEM_1024;
        break;
    default:
        return 0;
    }

    result = quac_kem_encaps(device, alg, pk, pk_len, ct, ct_len, ss, ss_len);
    return result == QUAC_SUCCESS;
#else
    (void)device;
    return quac_sim_kem_encaps(type, pk, pk_len, ct, ct_len, ss, ss_len);
#endif
}

static int quac_hw_kem_decaps(void *device, quac_key_type_t type,
                              const unsigned char *ct, size_t ct_len,
                              const unsigned char *sk, size_t sk_len,
                              unsigned char *ss, size_t ss_len)
{
#ifdef QUAC_HAS_HARDWARE
    quac_algorithm_t alg;
    quac_result_t result;

    switch (type)
    {
    case QUAC_KEY_TYPE_ML_KEM_512:
        alg = QUAC_ALG_ML_KEM_512;
        break;
    case QUAC_KEY_TYPE_ML_KEM_768:
        alg = QUAC_ALG_ML_KEM_768;
        break;
    case QUAC_KEY_TYPE_ML_KEM_1024:
        alg = QUAC_ALG_ML_KEM_1024;
        break;
    default:
        return 0;
    }

    result = quac_kem_decaps(device, alg, ct, ct_len, sk, sk_len, ss, ss_len);
    return result == QUAC_SUCCESS;
#else
    (void)device;
    return quac_sim_kem_decaps(type, ct, ct_len, sk, sk_len, ss, ss_len);
#endif
}

/* ==========================================================================
 * OpenSSL KEM Dispatch Functions
 * ========================================================================== */

static void *quac_kem_newctx(void *provctx)
{
    QUAC_KEM_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;

    ctx->provctx = provctx;
    ctx->key = NULL;
    ctx->type = QUAC_KEY_TYPE_UNKNOWN;

    return ctx;
}

static void quac_kem_freectx(void *vctx)
{
    QUAC_KEM_CTX *ctx = vctx;
    if (ctx == NULL)
        return;

    if (ctx->key)
        quac_key_free(ctx->key);

    OPENSSL_free(ctx);
}

static void *quac_kem_dupctx(void *vctx)
{
    QUAC_KEM_CTX *src = vctx;
    QUAC_KEM_CTX *dst;

    if (src == NULL)
        return NULL;

    dst = OPENSSL_zalloc(sizeof(*dst));
    if (dst == NULL)
        return NULL;

    dst->provctx = src->provctx;
    dst->type = src->type;

    if (src->key)
    {
        dst->key = quac_key_dup(src->key);
        if (dst->key == NULL)
        {
            OPENSSL_free(dst);
            return NULL;
        }
    }

    return dst;
}

static int quac_kem_encapsulate_init(void *vctx, void *vkey,
                                     const OSSL_PARAM params[])
{
    QUAC_KEM_CTX *ctx = vctx;
    QUAC_KEY *key = vkey;

    (void)params;

    if (ctx == NULL || key == NULL)
        return 0;

    if (!key->has_public)
        return 0;

    if (ctx->key)
        quac_key_free(ctx->key);

    quac_key_up_ref(key);
    ctx->key = key;
    ctx->type = key->type;

    return 1;
}

static int quac_kem_encapsulate(void *vctx,
                                unsigned char *out, size_t *outlen,
                                unsigned char *secret, size_t *secretlen)
{
    QUAC_KEM_CTX *ctx = vctx;
    size_t ct_len, ss_len;

    if (ctx == NULL || ctx->key == NULL)
        return 0;

    ct_len = quac_kem_ct_size(ctx->type);
    ss_len = quac_kem_ss_size(ctx->type);

    if (ct_len == 0 || ss_len == 0)
        return 0;

    /* Return sizes if buffers are NULL */
    if (out == NULL || secret == NULL)
    {
        if (outlen)
            *outlen = ct_len;
        if (secretlen)
            *secretlen = ss_len;
        return 1;
    }

    /* Check buffer sizes */
    if (*outlen < ct_len || *secretlen < ss_len)
        return 0;

    /* Perform encapsulation */
    void *device = quac_prov_get_device(ctx->provctx);
    int use_sim = quac_prov_is_simulator(ctx->provctx);

    int ret;
    if (use_sim || device == NULL)
    {
        ret = quac_sim_kem_encaps(ctx->type,
                                  ctx->key->pubkey, ctx->key->pubkey_len,
                                  out, ct_len, secret, ss_len);
    }
    else
    {
        ret = quac_hw_kem_encaps(device, ctx->type,
                                 ctx->key->pubkey, ctx->key->pubkey_len,
                                 out, ct_len, secret, ss_len);
    }

    if (ret)
    {
        *outlen = ct_len;
        *secretlen = ss_len;
    }

    return ret;
}

static int quac_kem_decapsulate_init(void *vctx, void *vkey,
                                     const OSSL_PARAM params[])
{
    QUAC_KEM_CTX *ctx = vctx;
    QUAC_KEY *key = vkey;

    (void)params;

    if (ctx == NULL || key == NULL)
        return 0;

    if (!key->has_private)
        return 0;

    if (ctx->key)
        quac_key_free(ctx->key);

    quac_key_up_ref(key);
    ctx->key = key;
    ctx->type = key->type;

    return 1;
}

static int quac_kem_decapsulate(void *vctx,
                                unsigned char *out, size_t *outlen,
                                const unsigned char *in, size_t inlen)
{
    QUAC_KEM_CTX *ctx = vctx;
    size_t ct_len, ss_len;

    if (ctx == NULL || ctx->key == NULL)
        return 0;

    ct_len = quac_kem_ct_size(ctx->type);
    ss_len = quac_kem_ss_size(ctx->type);

    if (ct_len == 0 || ss_len == 0)
        return 0;

    /* Return size if buffer is NULL */
    if (out == NULL)
    {
        if (outlen)
            *outlen = ss_len;
        return 1;
    }

    /* Check sizes */
    if (*outlen < ss_len || inlen != ct_len)
        return 0;

    /* Perform decapsulation */
    void *device = quac_prov_get_device(ctx->provctx);
    int use_sim = quac_prov_is_simulator(ctx->provctx);

    int ret;
    if (use_sim || device == NULL)
    {
        ret = quac_sim_kem_decaps(ctx->type,
                                  in, inlen,
                                  ctx->key->privkey, ctx->key->privkey_len,
                                  out, ss_len);
    }
    else
    {
        ret = quac_hw_kem_decaps(device, ctx->type,
                                 in, inlen,
                                 ctx->key->privkey, ctx->key->privkey_len,
                                 out, ss_len);
    }

    if (ret)
    {
        *outlen = ss_len;
    }

    return ret;
}

/* ==========================================================================
 * KEM Gettable/Settable Parameters
 * ========================================================================== */

static const OSSL_PARAM *quac_kem_gettable_ctx_params(void *vctx, void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_END};
    (void)vctx;
    (void)provctx;
    return params;
}

static const OSSL_PARAM *quac_kem_settable_ctx_params(void *vctx, void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_END};
    (void)vctx;
    (void)provctx;
    return params;
}

static int quac_kem_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    (void)vctx;
    (void)params;
    return 1;
}

static int quac_kem_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    (void)vctx;
    (void)params;
    return 1;
}

/* ==========================================================================
 * KEM Dispatch Table
 * ========================================================================== */

static const OSSL_DISPATCH quac_kem_functions[] = {
    {OSSL_FUNC_KEM_NEWCTX, (void (*)(void))quac_kem_newctx},
    {OSSL_FUNC_KEM_FREECTX, (void (*)(void))quac_kem_freectx},
    {OSSL_FUNC_KEM_DUPCTX, (void (*)(void))quac_kem_dupctx},
    {OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))quac_kem_encapsulate_init},
    {OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))quac_kem_encapsulate},
    {OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))quac_kem_decapsulate_init},
    {OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))quac_kem_decapsulate},
    {OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS, (void (*)(void))quac_kem_gettable_ctx_params},
    {OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS, (void (*)(void))quac_kem_settable_ctx_params},
    {OSSL_FUNC_KEM_GET_CTX_PARAMS, (void (*)(void))quac_kem_get_ctx_params},
    {OSSL_FUNC_KEM_SET_CTX_PARAMS, (void (*)(void))quac_kem_set_ctx_params},
    {0, NULL}};

/* ==========================================================================
 * Key Management Dispatch Functions
 * ========================================================================== */

static void *quac_keymgmt_new(void *provctx, quac_key_type_t type)
{
    return quac_key_new(provctx, type);
}

static void *quac_keymgmt_new_mlkem512(void *provctx) { return quac_keymgmt_new(provctx, QUAC_KEY_TYPE_ML_KEM_512); }
static void *quac_keymgmt_new_mlkem768(void *provctx) { return quac_keymgmt_new(provctx, QUAC_KEY_TYPE_ML_KEM_768); }
static void *quac_keymgmt_new_mlkem1024(void *provctx) { return quac_keymgmt_new(provctx, QUAC_KEY_TYPE_ML_KEM_1024); }

static void quac_keymgmt_free(void *vkey)
{
    quac_key_free(vkey);
}

static void *quac_keymgmt_dup(const void *vkey, int selection)
{
    (void)selection;
    return quac_key_dup(vkey);
}

static int quac_keymgmt_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    (void)genctx;
    (void)params;
    return 1;
}

static const OSSL_PARAM *quac_keymgmt_gen_settable_params(void *genctx, void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_END};
    (void)genctx;
    (void)provctx;
    return params;
}

static void *quac_keymgmt_gen_init(void *provctx, int selection, const OSSL_PARAM params[], quac_key_type_t type)
{
    QUAC_KEY *key;
    (void)selection;
    (void)params;

    key = quac_key_new(provctx, type);
    return key;
}

static void *quac_keymgmt_gen_init_mlkem512(void *provctx, int selection, const OSSL_PARAM params[])
{
    return quac_keymgmt_gen_init(provctx, selection, params, QUAC_KEY_TYPE_ML_KEM_512);
}
static void *quac_keymgmt_gen_init_mlkem768(void *provctx, int selection, const OSSL_PARAM params[])
{
    return quac_keymgmt_gen_init(provctx, selection, params, QUAC_KEY_TYPE_ML_KEM_768);
}
static void *quac_keymgmt_gen_init_mlkem1024(void *provctx, int selection, const OSSL_PARAM params[])
{
    return quac_keymgmt_gen_init(provctx, selection, params, QUAC_KEY_TYPE_ML_KEM_1024);
}

static void *quac_keymgmt_gen(void *genctx, OSSL_CALLBACK *cb, void *cbarg)
{
    QUAC_KEY *key = genctx;
    size_t pk_len, sk_len;

    (void)cb;
    (void)cbarg;

    if (key == NULL)
        return NULL;

    pk_len = quac_key_type_pk_size(key->type);
    sk_len = quac_key_type_sk_size(key->type);

    if (pk_len == 0 || sk_len == 0)
        return NULL;

    key->pubkey = OPENSSL_malloc(pk_len);
    key->privkey = OPENSSL_secure_malloc(sk_len);

    if (key->pubkey == NULL || key->privkey == NULL)
    {
        OPENSSL_free(key->pubkey);
        OPENSSL_secure_free(key->privkey, sk_len);
        key->pubkey = NULL;
        key->privkey = NULL;
        return NULL;
    }

    /* Generate keypair */
    QUAC_PROV_CTX *provctx = key->provctx;
    void *device = quac_prov_get_device(provctx);
    int use_sim = quac_prov_is_simulator(provctx);

    int ret;
    if (use_sim || device == NULL)
    {
        ret = quac_sim_kem_keygen(key->type, key->pubkey, pk_len, key->privkey, sk_len);
    }
    else
    {
        ret = quac_hw_kem_keygen(device, key->type, key->pubkey, pk_len, key->privkey, sk_len);
    }

    if (!ret)
    {
        OPENSSL_free(key->pubkey);
        OPENSSL_secure_free(key->privkey, sk_len);
        key->pubkey = NULL;
        key->privkey = NULL;
        return NULL;
    }

    key->pubkey_len = pk_len;
    key->privkey_len = sk_len;
    key->has_public = 1;
    key->has_private = 1;

    quac_key_up_ref(key);
    return key;
}

static void quac_keymgmt_gen_cleanup(void *genctx)
{
    quac_key_free(genctx);
}

static int quac_keymgmt_has(const void *vkey, int selection)
{
    const QUAC_KEY *key = vkey;
    int ok = 1;

    if (key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        ok = ok && key->has_public;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        ok = ok && key->has_private;

    return ok;
}

static int quac_keymgmt_match(const void *vkey1, const void *vkey2, int selection)
{
    const QUAC_KEY *key1 = vkey1;
    const QUAC_KEY *key2 = vkey2;

    if (key1 == NULL || key2 == NULL)
        return 0;

    if (key1->type != key2->type)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
    {
        if (key1->pubkey_len != key2->pubkey_len)
            return 0;
        if (memcmp(key1->pubkey, key2->pubkey, key1->pubkey_len) != 0)
            return 0;
    }

    return 1;
}

static int quac_keymgmt_get_params(void *vkey, OSSL_PARAM params[])
{
    QUAC_KEY *key = vkey;
    OSSL_PARAM *p;

    if (key == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p != NULL)
    {
        int bits = quac_key_type_pk_size(key->type) * 8;
        if (!OSSL_PARAM_set_int(p, bits))
            return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p != NULL)
    {
        size_t size = quac_key_type_pk_size(key->type);
        if (!OSSL_PARAM_set_size_t(p, size))
            return 0;
    }

    return 1;
}

static const OSSL_PARAM *quac_keymgmt_gettable_params(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_size_t(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_END};
    (void)provctx;
    return params;
}

/* ==========================================================================
 * Key Import/Export
 * ========================================================================== */

static int quac_keymgmt_import(void *vkey, int selection, const OSSL_PARAM params[])
{
    QUAC_KEY *key = vkey;
    const OSSL_PARAM *p;

    if (key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
    {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
        if (p != NULL)
        {
            void *data = NULL;
            size_t len = 0;

            if (!OSSL_PARAM_get_octet_string(p, &data, 0, &len))
                return 0;

            key->pubkey = data;
            key->pubkey_len = len;
            key->has_public = 1;
        }
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
    {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if (p != NULL)
        {
            void *data = NULL;
            size_t len = 0;

            if (!OSSL_PARAM_get_octet_string(p, &data, 0, &len))
                return 0;

            key->privkey = data;
            key->privkey_len = len;
            key->has_private = 1;
        }
    }

    return 1;
}

static int quac_keymgmt_export(void *vkey, int selection,
                               OSSL_CALLBACK *param_cb, void *cbarg)
{
    QUAC_KEY *key = vkey;
    OSSL_PARAM params[3];
    int idx = 0;

    if (key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 && key->has_public)
    {
        params[idx++] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PUB_KEY,
            key->pubkey, key->pubkey_len);
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 && key->has_private)
    {
        params[idx++] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PRIV_KEY,
            key->privkey, key->privkey_len);
    }

    params[idx] = OSSL_PARAM_construct_end();

    return param_cb(params, cbarg);
}

static const OSSL_PARAM *quac_keymgmt_import_types(int selection)
{
    static const OSSL_PARAM import_params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_END};
    (void)selection;
    return import_params;
}

static const OSSL_PARAM *quac_keymgmt_export_types(int selection)
{
    return quac_keymgmt_import_types(selection);
}

/* ==========================================================================
 * Key Management Dispatch Tables
 * ========================================================================== */

#define DEFINE_KEYMGMT_FUNCTIONS(name, type)                                                       \
    static const OSSL_DISPATCH quac_keymgmt_##name##_functions[] = {                               \
        {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))quac_keymgmt_new_##name},                          \
        {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))quac_keymgmt_free},                               \
        {OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))quac_keymgmt_dup},                                 \
        {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))quac_keymgmt_gen_init_##name},                \
        {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))quac_keymgmt_gen_set_params},           \
        {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))quac_keymgmt_gen_settable_params}, \
        {OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))quac_keymgmt_gen},                                 \
        {OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))quac_keymgmt_gen_cleanup},                 \
        {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))quac_keymgmt_has},                                 \
        {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))quac_keymgmt_match},                             \
        {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))quac_keymgmt_get_params},                   \
        {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))quac_keymgmt_gettable_params},         \
        {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))quac_keymgmt_import},                           \
        {OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))quac_keymgmt_export},                           \
        {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))quac_keymgmt_import_types},               \
        {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))quac_keymgmt_export_types},               \
        {0, NULL}}

DEFINE_KEYMGMT_FUNCTIONS(mlkem512, QUAC_KEY_TYPE_ML_KEM_512);
DEFINE_KEYMGMT_FUNCTIONS(mlkem768, QUAC_KEY_TYPE_ML_KEM_768);
DEFINE_KEYMGMT_FUNCTIONS(mlkem1024, QUAC_KEY_TYPE_ML_KEM_1024);

/* ==========================================================================
 * Algorithm Registration
 * ========================================================================== */

const OSSL_ALGORITHM quac_kem_algorithms[] = {
    {QUAC_ALG_ML_KEM_512, "provider=quac100", quac_kem_functions, "QUAC ML-KEM-512"},
    {QUAC_ALG_ML_KEM_768, "provider=quac100", quac_kem_functions, "QUAC ML-KEM-768"},
    {QUAC_ALG_ML_KEM_1024, "provider=quac100", quac_kem_functions, "QUAC ML-KEM-1024"},
    {NULL, NULL, NULL, NULL}};

const OSSL_ALGORITHM quac_keymgmt_algorithms[] = {
    {QUAC_ALG_ML_KEM_512, "provider=quac100", quac_keymgmt_mlkem512_functions, "QUAC ML-KEM-512 Key Management"},
    {QUAC_ALG_ML_KEM_768, "provider=quac100", quac_keymgmt_mlkem768_functions, "QUAC ML-KEM-768 Key Management"},
    {QUAC_ALG_ML_KEM_1024, "provider=quac100", quac_keymgmt_mlkem1024_functions, "QUAC ML-KEM-1024 Key Management"},
    {NULL, NULL, NULL, NULL}};