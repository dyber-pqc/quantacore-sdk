/**
 * @file quac100_sig_alg.c
 * @brief QUAC 100 OpenSSL Provider - Signature Algorithm Implementation
 *
 * Implements ML-DSA (FIPS 204) digital signatures:
 * - ML-DSA-44 (NIST Level 2)
 * - ML-DSA-65 (NIST Level 3)
 * - ML-DSA-87 (NIST Level 5)
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <string.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#include "quac100_provider.h"

#ifdef QUAC_HAS_HARDWARE
#include <quac100.h>
#endif

/* ==========================================================================
 * Signature Context
 * ========================================================================== */

typedef struct quac_sig_ctx
{
    QUAC_PROV_CTX *provctx;
    QUAC_KEY *key;
    quac_key_type_t type;

    /* Operation state */
    int operation; /* 0 = none, 1 = sign, 2 = verify */

    /* Message digest */
    EVP_MD_CTX *mdctx;
    EVP_MD *md;

    /* Accumulated message data */
    unsigned char *msg;
    size_t msg_len;
    size_t msg_alloc;
} QUAC_SIG_CTX;

#define QUAC_SIG_OP_NONE 0
#define QUAC_SIG_OP_SIGN 1
#define QUAC_SIG_OP_VERIFY 2

/* ==========================================================================
 * Signature Size Helper
 * ========================================================================== */

static size_t quac_sig_size(quac_key_type_t type)
{
    switch (type)
    {
    case QUAC_KEY_TYPE_ML_DSA_44:
        return QUAC_ML_DSA_44_SIG_SIZE;
    case QUAC_KEY_TYPE_ML_DSA_65:
        return QUAC_ML_DSA_65_SIG_SIZE;
    case QUAC_KEY_TYPE_ML_DSA_87:
        return QUAC_ML_DSA_87_SIG_SIZE;
    default:
        return 0;
    }
}

/* ==========================================================================
 * Simulated Signature Operations
 * ========================================================================== */

static int quac_sim_sign(quac_key_type_t type,
                         const unsigned char *msg, size_t msg_len,
                         const unsigned char *sk, size_t sk_len,
                         unsigned char *sig, size_t *sig_len)
{
    size_t expected_sig_len = quac_sig_size(type);
    unsigned char hash[64];

    if (expected_sig_len == 0)
        return 0;

    /* Compute deterministic signature (simplified simulation) */
    /* Real ML-DSA uses lattice operations */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        return 0;

    if (EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, sk, sk_len > 64 ? 64 : sk_len) != 1 ||
        EVP_DigestUpdate(ctx, msg, msg_len) != 1 ||
        EVP_DigestFinal_ex(ctx, hash, NULL) != 1)
    {
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    EVP_MD_CTX_free(ctx);

    /* Fill signature with hash and deterministic expansion */
    memset(sig, 0, expected_sig_len);
    memcpy(sig, hash, 32);

    /* Expand hash to fill signature */
    for (size_t i = 32; i < expected_sig_len; i++)
    {
        sig[i] = hash[i % 32] ^ (unsigned char)(i & 0xFF);
    }

    *sig_len = expected_sig_len;
    return 1;
}

static int quac_sim_verify(quac_key_type_t type,
                           const unsigned char *msg, size_t msg_len,
                           const unsigned char *sig, size_t sig_len,
                           const unsigned char *pk, size_t pk_len)
{
    /*
     * In simulation, we can't truly verify since we don't have
     * the actual ML-DSA algorithm. Accept signatures of correct size.
     * Real verification would use lattice operations.
     */
    size_t expected_sig_len = quac_sig_size(type);

    if (sig_len != expected_sig_len)
        return 0;

    /* Verify signature has expected structure (simplified) */
    /* Check that first 32 bytes are non-zero */
    int nonzero = 0;
    for (size_t i = 0; i < 32; i++)
    {
        if (sig[i] != 0)
            nonzero = 1;
    }

    return nonzero;
}

static int quac_sim_sig_keygen(quac_key_type_t type,
                               unsigned char *pk, size_t pk_len,
                               unsigned char *sk, size_t sk_len)
{
    /* Generate random keys */
    if (RAND_bytes(pk, pk_len) != 1)
        return 0;
    if (RAND_bytes(sk, sk_len) != 1)
        return 0;

    /* Embed public key hash in secret key for verification */
    unsigned char pk_hash[32];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        return 0;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, pk, pk_len) != 1 ||
        EVP_DigestFinal_ex(ctx, pk_hash, NULL) != 1)
    {
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    EVP_MD_CTX_free(ctx);

    /* Store hash at end of secret key */
    if (sk_len >= 32)
    {
        memcpy(sk + sk_len - 32, pk_hash, 32);
    }

    return 1;
}

/* ==========================================================================
 * Hardware Signature Operations
 * ========================================================================== */

static int quac_hw_sign(void *device, quac_key_type_t type,
                        const unsigned char *msg, size_t msg_len,
                        const unsigned char *sk, size_t sk_len,
                        unsigned char *sig, size_t *sig_len)
{
#ifdef QUAC_HAS_HARDWARE
    quac_algorithm_t alg;
    quac_result_t result;

    switch (type)
    {
    case QUAC_KEY_TYPE_ML_DSA_44:
        alg = QUAC_ALG_ML_DSA_44;
        break;
    case QUAC_KEY_TYPE_ML_DSA_65:
        alg = QUAC_ALG_ML_DSA_65;
        break;
    case QUAC_KEY_TYPE_ML_DSA_87:
        alg = QUAC_ALG_ML_DSA_87;
        break;
    default:
        return 0;
    }

    result = quac_sign(device, alg, msg, msg_len, sk, sk_len, sig, sig_len);
    return result == QUAC_SUCCESS;
#else
    (void)device;
    return quac_sim_sign(type, msg, msg_len, sk, sk_len, sig, sig_len);
#endif
}

static int quac_hw_verify(void *device, quac_key_type_t type,
                          const unsigned char *msg, size_t msg_len,
                          const unsigned char *sig, size_t sig_len,
                          const unsigned char *pk, size_t pk_len)
{
#ifdef QUAC_HAS_HARDWARE
    quac_algorithm_t alg;
    quac_result_t result;

    switch (type)
    {
    case QUAC_KEY_TYPE_ML_DSA_44:
        alg = QUAC_ALG_ML_DSA_44;
        break;
    case QUAC_KEY_TYPE_ML_DSA_65:
        alg = QUAC_ALG_ML_DSA_65;
        break;
    case QUAC_KEY_TYPE_ML_DSA_87:
        alg = QUAC_ALG_ML_DSA_87;
        break;
    default:
        return 0;
    }

    result = quac_verify(device, alg, msg, msg_len, sig, sig_len, pk, pk_len);
    return result == QUAC_SUCCESS;
#else
    (void)device;
    return quac_sim_verify(type, msg, msg_len, sig, sig_len, pk, pk_len);
#endif
}

/* ==========================================================================
 * OpenSSL Signature Dispatch Functions
 * ========================================================================== */

static void *quac_sig_newctx(void *provctx, const char *propq)
{
    QUAC_SIG_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    (void)propq;

    if (ctx == NULL)
        return NULL;

    ctx->provctx = provctx;
    ctx->operation = QUAC_SIG_OP_NONE;

    return ctx;
}

static void quac_sig_freectx(void *vctx)
{
    QUAC_SIG_CTX *ctx = vctx;
    if (ctx == NULL)
        return;

    if (ctx->key)
        quac_key_free(ctx->key);
    if (ctx->mdctx)
        EVP_MD_CTX_free(ctx->mdctx);
    if (ctx->md)
        EVP_MD_free(ctx->md);
    if (ctx->msg)
    {
        OPENSSL_cleanse(ctx->msg, ctx->msg_alloc);
        OPENSSL_free(ctx->msg);
    }

    OPENSSL_free(ctx);
}

static void *quac_sig_dupctx(void *vctx)
{
    QUAC_SIG_CTX *src = vctx;
    QUAC_SIG_CTX *dst;

    if (src == NULL)
        return NULL;

    dst = OPENSSL_zalloc(sizeof(*dst));
    if (dst == NULL)
        return NULL;

    dst->provctx = src->provctx;
    dst->type = src->type;
    dst->operation = src->operation;

    if (src->key)
    {
        dst->key = quac_key_dup(src->key);
        if (dst->key == NULL)
        {
            quac_sig_freectx(dst);
            return NULL;
        }
    }

    if (src->msg && src->msg_len > 0)
    {
        dst->msg = OPENSSL_memdup(src->msg, src->msg_len);
        if (dst->msg == NULL)
        {
            quac_sig_freectx(dst);
            return NULL;
        }
        dst->msg_len = src->msg_len;
        dst->msg_alloc = src->msg_len;
    }

    return dst;
}

static int quac_sig_sign_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    QUAC_SIG_CTX *ctx = vctx;
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
    ctx->operation = QUAC_SIG_OP_SIGN;

    /* Reset message buffer */
    ctx->msg_len = 0;

    return 1;
}

static int quac_sig_sign(void *vctx,
                         unsigned char *sig, size_t *siglen, size_t sigsize,
                         const unsigned char *tbs, size_t tbslen)
{
    QUAC_SIG_CTX *ctx = vctx;
    size_t expected_sig_len;

    if (ctx == NULL || ctx->key == NULL)
        return 0;

    expected_sig_len = quac_sig_size(ctx->type);
    if (expected_sig_len == 0)
        return 0;

    /* Return size if buffer is NULL */
    if (sig == NULL)
    {
        *siglen = expected_sig_len;
        return 1;
    }

    if (sigsize < expected_sig_len)
        return 0;

    /* Perform signature */
    void *device = quac_prov_get_device(ctx->provctx);
    int use_sim = quac_prov_is_simulator(ctx->provctx);

    int ret;
    if (use_sim || device == NULL)
    {
        ret = quac_sim_sign(ctx->type, tbs, tbslen,
                            ctx->key->privkey, ctx->key->privkey_len,
                            sig, siglen);
    }
    else
    {
        ret = quac_hw_sign(device, ctx->type, tbs, tbslen,
                           ctx->key->privkey, ctx->key->privkey_len,
                           sig, siglen);
    }

    return ret;
}

static int quac_sig_verify_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    QUAC_SIG_CTX *ctx = vctx;
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
    ctx->operation = QUAC_SIG_OP_VERIFY;

    ctx->msg_len = 0;

    return 1;
}

static int quac_sig_verify(void *vctx,
                           const unsigned char *sig, size_t siglen,
                           const unsigned char *tbs, size_t tbslen)
{
    QUAC_SIG_CTX *ctx = vctx;

    if (ctx == NULL || ctx->key == NULL)
        return 0;

    /* Verify signature */
    void *device = quac_prov_get_device(ctx->provctx);
    int use_sim = quac_prov_is_simulator(ctx->provctx);

    int ret;
    if (use_sim || device == NULL)
    {
        ret = quac_sim_verify(ctx->type, tbs, tbslen,
                              sig, siglen,
                              ctx->key->pubkey, ctx->key->pubkey_len);
    }
    else
    {
        ret = quac_hw_verify(device, ctx->type, tbs, tbslen,
                             sig, siglen,
                             ctx->key->pubkey, ctx->key->pubkey_len);
    }

    return ret;
}

/* ==========================================================================
 * Digest Sign/Verify (for use with EVP_DigestSign/Verify API)
 * ========================================================================== */

static int quac_sig_digest_sign_init(void *vctx, const char *mdname,
                                     void *vkey, const OSSL_PARAM params[])
{
    (void)mdname; /* ML-DSA is a pure signature scheme */
    return quac_sig_sign_init(vctx, vkey, params);
}

static int quac_sig_digest_sign_update(void *vctx,
                                       const unsigned char *data, size_t datalen)
{
    QUAC_SIG_CTX *ctx = vctx;

    if (ctx == NULL)
        return 0;

    /* Accumulate message data */
    size_t new_len = ctx->msg_len + datalen;
    if (new_len > ctx->msg_alloc)
    {
        size_t new_alloc = new_len * 2;
        unsigned char *new_msg = OPENSSL_realloc(ctx->msg, new_alloc);
        if (new_msg == NULL)
            return 0;
        ctx->msg = new_msg;
        ctx->msg_alloc = new_alloc;
    }

    memcpy(ctx->msg + ctx->msg_len, data, datalen);
    ctx->msg_len = new_len;

    return 1;
}

static int quac_sig_digest_sign_final(void *vctx,
                                      unsigned char *sig, size_t *siglen, size_t sigsize)
{
    QUAC_SIG_CTX *ctx = vctx;

    if (ctx == NULL)
        return 0;

    return quac_sig_sign(vctx, sig, siglen, sigsize, ctx->msg, ctx->msg_len);
}

static int quac_sig_digest_verify_init(void *vctx, const char *mdname,
                                       void *vkey, const OSSL_PARAM params[])
{
    (void)mdname;
    return quac_sig_verify_init(vctx, vkey, params);
}

static int quac_sig_digest_verify_update(void *vctx,
                                         const unsigned char *data, size_t datalen)
{
    return quac_sig_digest_sign_update(vctx, data, datalen);
}

static int quac_sig_digest_verify_final(void *vctx,
                                        const unsigned char *sig, size_t siglen)
{
    QUAC_SIG_CTX *ctx = vctx;

    if (ctx == NULL)
        return 0;

    return quac_sig_verify(vctx, sig, siglen, ctx->msg, ctx->msg_len);
}

/* ==========================================================================
 * Parameters
 * ========================================================================== */

static const OSSL_PARAM *quac_sig_gettable_ctx_params(void *vctx, void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_SIGNATURE_SIZE, NULL),
        OSSL_PARAM_END};
    (void)vctx;
    (void)provctx;
    return params;
}

static int quac_sig_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    QUAC_SIG_CTX *ctx = vctx;
    OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_SIGNATURE_SIZE);
    if (p != NULL)
    {
        size_t sig_size = quac_sig_size(ctx->type);
        if (!OSSL_PARAM_set_size_t(p, sig_size))
            return 0;
    }

    return 1;
}

static const OSSL_PARAM *quac_sig_settable_ctx_params(void *vctx, void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_END};
    (void)vctx;
    (void)provctx;
    return params;
}

static int quac_sig_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    (void)vctx;
    (void)params;
    return 1;
}

/* ==========================================================================
 * Signature Dispatch Table
 * ========================================================================== */

static const OSSL_DISPATCH quac_sig_functions[] = {
    {OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))quac_sig_newctx},
    {OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))quac_sig_freectx},
    {OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))quac_sig_dupctx},
    {OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))quac_sig_sign_init},
    {OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))quac_sig_sign},
    {OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))quac_sig_verify_init},
    {OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))quac_sig_verify},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))quac_sig_digest_sign_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))quac_sig_digest_sign_update},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))quac_sig_digest_sign_final},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))quac_sig_digest_verify_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (void (*)(void))quac_sig_digest_verify_update},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (void (*)(void))quac_sig_digest_verify_final},
    {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))quac_sig_gettable_ctx_params},
    {OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))quac_sig_get_ctx_params},
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))quac_sig_settable_ctx_params},
    {OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))quac_sig_set_ctx_params},
    {0, NULL}};

/* ==========================================================================
 * Key Management for Signatures
 * ========================================================================== */

static void *quac_sig_keymgmt_new_mldsa44(void *provctx) { return quac_key_new(provctx, QUAC_KEY_TYPE_ML_DSA_44); }
static void *quac_sig_keymgmt_new_mldsa65(void *provctx) { return quac_key_new(provctx, QUAC_KEY_TYPE_ML_DSA_65); }
static void *quac_sig_keymgmt_new_mldsa87(void *provctx) { return quac_key_new(provctx, QUAC_KEY_TYPE_ML_DSA_87); }

static void *quac_sig_keymgmt_gen_init_mldsa44(void *provctx, int selection, const OSSL_PARAM params[])
{
    (void)selection;
    (void)params;
    return quac_key_new(provctx, QUAC_KEY_TYPE_ML_DSA_44);
}
static void *quac_sig_keymgmt_gen_init_mldsa65(void *provctx, int selection, const OSSL_PARAM params[])
{
    (void)selection;
    (void)params;
    return quac_key_new(provctx, QUAC_KEY_TYPE_ML_DSA_65);
}
static void *quac_sig_keymgmt_gen_init_mldsa87(void *provctx, int selection, const OSSL_PARAM params[])
{
    (void)selection;
    (void)params;
    return quac_key_new(provctx, QUAC_KEY_TYPE_ML_DSA_87);
}

static void *quac_sig_keymgmt_gen(void *genctx, OSSL_CALLBACK *cb, void *cbarg)
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

    if (!quac_sim_sig_keygen(key->type, key->pubkey, pk_len, key->privkey, sk_len))
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

/* Forward declarations from kem_alg.c */
extern void quac_keymgmt_free(void *vkey);
extern void *quac_keymgmt_dup(const void *vkey, int selection);
extern int quac_keymgmt_gen_set_params(void *genctx, const OSSL_PARAM params[]);
extern const OSSL_PARAM *quac_keymgmt_gen_settable_params(void *genctx, void *provctx);
extern void quac_keymgmt_gen_cleanup(void *genctx);
extern int quac_keymgmt_has(const void *vkey, int selection);
extern int quac_keymgmt_match(const void *vkey1, const void *vkey2, int selection);
extern int quac_keymgmt_get_params(void *vkey, OSSL_PARAM params[]);
extern const OSSL_PARAM *quac_keymgmt_gettable_params(void *provctx);
extern int quac_keymgmt_import(void *vkey, int selection, const OSSL_PARAM params[]);
extern int quac_keymgmt_export(void *vkey, int selection, OSSL_CALLBACK *param_cb, void *cbarg);
extern const OSSL_PARAM *quac_keymgmt_import_types(int selection);
extern const OSSL_PARAM *quac_keymgmt_export_types(int selection);

/* Redeclare locally to avoid extern issues */
static void quac_sig_keymgmt_free(void *vkey) { quac_key_free(vkey); }
static void *quac_sig_keymgmt_dup(const void *vkey, int sel)
{
    (void)sel;
    return quac_key_dup(vkey);
}
static int quac_sig_keymgmt_gen_set_params(void *g, const OSSL_PARAM p[])
{
    (void)g;
    (void)p;
    return 1;
}
static const OSSL_PARAM *quac_sig_keymgmt_gen_settable_params(void *g, void *p)
{
    static const OSSL_PARAM params[] = {OSSL_PARAM_END};
    (void)g;
    (void)p;
    return params;
}
static void quac_sig_keymgmt_gen_cleanup(void *g) { quac_key_free(g); }

static int quac_sig_keymgmt_has(const void *vkey, int selection)
{
    const QUAC_KEY *key = vkey;
    int ok = 1;
    if (!key)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        ok = ok && key->has_public;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        ok = ok && key->has_private;
    return ok;
}

static int quac_sig_keymgmt_match(const void *k1, const void *k2, int sel)
{
    const QUAC_KEY *key1 = k1, *key2 = k2;
    if (!key1 || !key2)
        return 0;
    if (key1->type != key2->type)
        return 0;
    if ((sel & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
    {
        if (key1->pubkey_len != key2->pubkey_len)
            return 0;
        if (memcmp(key1->pubkey, key2->pubkey, key1->pubkey_len) != 0)
            return 0;
    }
    return 1;
}

static int quac_sig_keymgmt_get_params(void *vkey, OSSL_PARAM params[])
{
    QUAC_KEY *key = vkey;
    OSSL_PARAM *p;
    if (!key)
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p != NULL)
    {
        int bits = quac_key_type_pk_size(key->type) * 8;
        if (!OSSL_PARAM_set_int(p, bits))
            return 0;
    }
    return 1;
}

static const OSSL_PARAM *quac_sig_keymgmt_gettable_params(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_END};
    (void)provctx;
    return params;
}

static int quac_sig_keymgmt_import(void *vkey, int sel, const OSSL_PARAM params[])
{
    QUAC_KEY *key = vkey;
    const OSSL_PARAM *p;
    if (!key)
        return 0;
    if ((sel & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
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
    if ((sel & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
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

static int quac_sig_keymgmt_export(void *vkey, int sel, OSSL_CALLBACK *cb, void *cbarg)
{
    QUAC_KEY *key = vkey;
    OSSL_PARAM params[3];
    int idx = 0;
    if (!key)
        return 0;
    if ((sel & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0 && key->has_public)
        params[idx++] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, key->pubkey, key->pubkey_len);
    if ((sel & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0 && key->has_private)
        params[idx++] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, key->privkey, key->privkey_len);
    params[idx] = OSSL_PARAM_construct_end();
    return cb(params, cbarg);
}

static const OSSL_PARAM *quac_sig_keymgmt_import_types(int sel)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_END};
    (void)sel;
    return params;
}

static const OSSL_PARAM *quac_sig_keymgmt_export_types(int sel)
{
    return quac_sig_keymgmt_import_types(sel);
}

/* Key management dispatch tables for signature keys */
#define DEFINE_SIG_KEYMGMT(name)                                                                       \
    static const OSSL_DISPATCH quac_sig_keymgmt_##name##_functions[] = {                               \
        {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))quac_sig_keymgmt_new_##name},                          \
        {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))quac_sig_keymgmt_free},                               \
        {OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))quac_sig_keymgmt_dup},                                 \
        {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))quac_sig_keymgmt_gen_init_##name},                \
        {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))quac_sig_keymgmt_gen_set_params},           \
        {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))quac_sig_keymgmt_gen_settable_params}, \
        {OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))quac_sig_keymgmt_gen},                                 \
        {OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))quac_sig_keymgmt_gen_cleanup},                 \
        {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))quac_sig_keymgmt_has},                                 \
        {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))quac_sig_keymgmt_match},                             \
        {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))quac_sig_keymgmt_get_params},                   \
        {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))quac_sig_keymgmt_gettable_params},         \
        {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))quac_sig_keymgmt_import},                           \
        {OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))quac_sig_keymgmt_export},                           \
        {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))quac_sig_keymgmt_import_types},               \
        {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))quac_sig_keymgmt_export_types},               \
        {0, NULL}}

DEFINE_SIG_KEYMGMT(mldsa44);
DEFINE_SIG_KEYMGMT(mldsa65);
DEFINE_SIG_KEYMGMT(mldsa87);

/* ==========================================================================
 * Algorithm Registration
 * ========================================================================== */

const OSSL_ALGORITHM quac_signature_algorithms[] = {
    {QUAC_ALG_ML_DSA_44, "provider=quac100", quac_sig_functions, "QUAC ML-DSA-44"},
    {QUAC_ALG_ML_DSA_65, "provider=quac100", quac_sig_functions, "QUAC ML-DSA-65"},
    {QUAC_ALG_ML_DSA_87, "provider=quac100", quac_sig_functions, "QUAC ML-DSA-87"},
    {NULL, NULL, NULL, NULL}};

/* Note: keymgmt_algorithms is defined in quac100_kem_alg.c,
   but we need to add signature key types. This would be combined
   in a real implementation. For now, signature keys use same keymgmt. */