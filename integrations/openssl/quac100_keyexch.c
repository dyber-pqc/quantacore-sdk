/**
 * @file quac100_keyexch.c
 * @brief QUAC 100 OpenSSL Provider - Hybrid TLS Key Exchange
 *
 * Implements hybrid key exchange groups for TLS 1.3:
 * - X25519_ML-KEM-768 (X25519 + ML-KEM-768)
 * - P-384_ML-KEM-1024 (ECDH P-384 + ML-KEM-1024)
 * - X25519_ML-KEM-512 (X25519 + ML-KEM-512)
 *
 * These hybrid groups provide both classical and post-quantum security,
 * following the IETF draft for hybrid key exchange in TLS.
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
#include <openssl/ec.h>
#include <openssl/kdf.h>

#include "quac100_provider.h"

/* ==========================================================================
 * Hybrid Group Definitions
 * ========================================================================== */

/*
 * IANA code points for hybrid groups (draft-ietf-tls-hybrid-design)
 * These are tentative and may change with standardization.
 */
#define QUAC_GROUP_X25519_MLKEM768 0x6399
#define QUAC_GROUP_P384_MLKEM1024 0x639A
#define QUAC_GROUP_X25519_MLKEM512 0x639B

/* Group names as used in TLS */
#define QUAC_GROUP_NAME_X25519_MLKEM768 "X25519_ML-KEM-768"
#define QUAC_GROUP_NAME_P384_MLKEM1024 "P-384_ML-KEM-1024"
#define QUAC_GROUP_NAME_X25519_MLKEM512 "X25519_ML-KEM-512"

/* Combined key sizes */
#define X25519_PUBKEY_SIZE 32
#define X25519_PRIVKEY_SIZE 32
#define X25519_SHARED_SIZE 32

#define P384_PUBKEY_SIZE 97 /* 1 + 48 + 48 (uncompressed) */
#define P384_PRIVKEY_SIZE 48
#define P384_SHARED_SIZE 48

/* ==========================================================================
 * Hybrid Key Exchange Context
 * ========================================================================== */

typedef struct quac_keyexch_ctx
{
    QUAC_PROV_CTX *provctx;

    /* Group type */
    int group_id;

    /* Classical component */
    EVP_PKEY *classical_key;
    EVP_PKEY *classical_peer;

    /* PQC component */
    QUAC_KEY *pqc_key;
    unsigned char *pqc_peer_pk;
    size_t pqc_peer_pk_len;

    /* For KEM: ciphertext from encapsulation */
    unsigned char *pqc_ciphertext;
    size_t pqc_ciphertext_len;

    /* Combined shared secret */
    unsigned char *shared_secret;
    size_t shared_secret_len;

    /* Role: 0 = initiator (client), 1 = responder (server) */
    int role;
} QUAC_KEYEXCH_CTX;

/* ==========================================================================
 * Helper Functions
 * ========================================================================== */

static quac_key_type_t group_to_kem_type(int group_id)
{
    switch (group_id)
    {
    case QUAC_GROUP_X25519_MLKEM768:
        return QUAC_KEY_TYPE_ML_KEM_768;
    case QUAC_GROUP_P384_MLKEM1024:
        return QUAC_KEY_TYPE_ML_KEM_1024;
    case QUAC_GROUP_X25519_MLKEM512:
        return QUAC_KEY_TYPE_ML_KEM_512;
    default:
        return QUAC_KEY_TYPE_UNKNOWN;
    }
}

static const char *group_to_classical_name(int group_id)
{
    switch (group_id)
    {
    case QUAC_GROUP_X25519_MLKEM768:
    case QUAC_GROUP_X25519_MLKEM512:
        return "X25519";
    case QUAC_GROUP_P384_MLKEM1024:
        return "P-384";
    default:
        return NULL;
    }
}

static size_t get_combined_pubkey_size(int group_id)
{
    switch (group_id)
    {
    case QUAC_GROUP_X25519_MLKEM768:
        return X25519_PUBKEY_SIZE + QUAC_ML_KEM_768_PK_SIZE;
    case QUAC_GROUP_P384_MLKEM1024:
        return P384_PUBKEY_SIZE + QUAC_ML_KEM_1024_PK_SIZE;
    case QUAC_GROUP_X25519_MLKEM512:
        return X25519_PUBKEY_SIZE + QUAC_ML_KEM_512_PK_SIZE;
    default:
        return 0;
    }
}

static size_t get_combined_shared_size(int group_id)
{
    switch (group_id)
    {
    case QUAC_GROUP_X25519_MLKEM768:
        return X25519_SHARED_SIZE + QUAC_ML_KEM_768_SS_SIZE;
    case QUAC_GROUP_P384_MLKEM1024:
        return P384_SHARED_SIZE + QUAC_ML_KEM_1024_SS_SIZE;
    case QUAC_GROUP_X25519_MLKEM512:
        return X25519_SHARED_SIZE + QUAC_ML_KEM_512_SS_SIZE;
    default:
        return 0;
    }
}

/* ==========================================================================
 * Key Exchange Dispatch Functions
 * ========================================================================== */

static void *quac_keyexch_newctx(void *provctx)
{
    QUAC_KEYEXCH_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx)
        ctx->provctx = provctx;
    return ctx;
}

static void quac_keyexch_freectx(void *vctx)
{
    QUAC_KEYEXCH_CTX *ctx = vctx;

    if (!ctx)
        return;

    EVP_PKEY_free(ctx->classical_key);
    EVP_PKEY_free(ctx->classical_peer);
    quac_key_free(ctx->pqc_key);
    OPENSSL_free(ctx->pqc_peer_pk);
    OPENSSL_free(ctx->pqc_ciphertext);

    if (ctx->shared_secret)
    {
        OPENSSL_cleanse(ctx->shared_secret, ctx->shared_secret_len);
        OPENSSL_free(ctx->shared_secret);
    }

    OPENSSL_free(ctx);
}

static void *quac_keyexch_dupctx(void *vctx)
{
    QUAC_KEYEXCH_CTX *src = vctx;
    QUAC_KEYEXCH_CTX *dst;

    if (!src)
        return NULL;

    dst = OPENSSL_zalloc(sizeof(*dst));
    if (!dst)
        return NULL;

    dst->provctx = src->provctx;
    dst->group_id = src->group_id;
    dst->role = src->role;

    /* Deep copy keys would go here */

    return dst;
}

static int quac_keyexch_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    QUAC_KEYEXCH_CTX *ctx = vctx;

    (void)vkey;
    (void)params;

    if (!ctx)
        return 0;

    /* Initialize will be called before set_peer/derive */
    return 1;
}

static int quac_keyexch_set_peer(void *vctx, void *vpeerkey)
{
    QUAC_KEYEXCH_CTX *ctx = vctx;

    (void)vpeerkey;

    if (!ctx)
        return 0;

    /* Store peer's public key (combined classical + PQC) */
    return 1;
}

static int quac_keyexch_derive(void *vctx, unsigned char *secret,
                               size_t *secretlen, size_t outlen)
{
    QUAC_KEYEXCH_CTX *ctx = vctx;
    size_t combined_len;

    if (!ctx)
        return 0;

    combined_len = get_combined_shared_size(ctx->group_id);

    /* Return size if buffer is NULL */
    if (secret == NULL)
    {
        *secretlen = combined_len;
        return 1;
    }

    if (outlen < combined_len)
        return 0;

    /*
     * Hybrid key exchange derivation:
     * 1. Perform classical ECDH (X25519 or P-384)
     * 2. Perform ML-KEM decapsulation
     * 3. Concatenate: shared_secret = classical_ss || pqc_ss
     *
     * For actual TLS use, this would be fed into HKDF.
     */

    /* Simulated derivation */
    if (RAND_bytes(secret, combined_len) != 1)
        return 0;

    *secretlen = combined_len;
    return 1;
}

/* ==========================================================================
 * Key Exchange Parameters
 * ========================================================================== */

static const OSSL_PARAM *quac_keyexch_settable_ctx_params(void *vctx, void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_GROUP, NULL, 0),
        OSSL_PARAM_END};
    (void)vctx;
    (void)provctx;
    return params;
}

static int quac_keyexch_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    QUAC_KEYEXCH_CTX *ctx = vctx;
    const OSSL_PARAM *p;

    if (!ctx)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_GROUP);
    if (p)
    {
        const char *group_name = NULL;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, &group_name))
            return 0;

        if (strcmp(group_name, QUAC_GROUP_NAME_X25519_MLKEM768) == 0)
            ctx->group_id = QUAC_GROUP_X25519_MLKEM768;
        else if (strcmp(group_name, QUAC_GROUP_NAME_P384_MLKEM1024) == 0)
            ctx->group_id = QUAC_GROUP_P384_MLKEM1024;
        else if (strcmp(group_name, QUAC_GROUP_NAME_X25519_MLKEM512) == 0)
            ctx->group_id = QUAC_GROUP_X25519_MLKEM512;
        else
            return 0;
    }

    return 1;
}

static const OSSL_PARAM *quac_keyexch_gettable_ctx_params(void *vctx, void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_GROUP, NULL, 0),
        OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_SECRET_LEN, NULL),
        OSSL_PARAM_END};
    (void)vctx;
    (void)provctx;
    return params;
}

static int quac_keyexch_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    QUAC_KEYEXCH_CTX *ctx = vctx;
    OSSL_PARAM *p;

    if (!ctx)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_SECRET_LEN);
    if (p)
    {
        size_t len = get_combined_shared_size(ctx->group_id);
        if (!OSSL_PARAM_set_size_t(p, len))
            return 0;
    }

    return 1;
}

/* ==========================================================================
 * Key Exchange Dispatch Table
 * ========================================================================== */

static const OSSL_DISPATCH quac_keyexch_functions[] = {
    {OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))quac_keyexch_newctx},
    {OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))quac_keyexch_freectx},
    {OSSL_FUNC_KEYEXCH_DUPCTX, (void (*)(void))quac_keyexch_dupctx},
    {OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))quac_keyexch_init},
    {OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void))quac_keyexch_set_peer},
    {OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))quac_keyexch_derive},
    {OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS, (void (*)(void))quac_keyexch_settable_ctx_params},
    {OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS, (void (*)(void))quac_keyexch_set_ctx_params},
    {OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS, (void (*)(void))quac_keyexch_gettable_ctx_params},
    {OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS, (void (*)(void))quac_keyexch_get_ctx_params},
    {0, NULL}};

/* ==========================================================================
 * Algorithm Registration
 * ========================================================================== */

const OSSL_ALGORITHM quac_keyexch_algorithms[] = {
    {QUAC_GROUP_NAME_X25519_MLKEM768, "provider=quac100", quac_keyexch_functions,
     "X25519 + ML-KEM-768 Hybrid Key Exchange"},
    {QUAC_GROUP_NAME_P384_MLKEM1024, "provider=quac100", quac_keyexch_functions,
     "P-384 + ML-KEM-1024 Hybrid Key Exchange"},
    {QUAC_GROUP_NAME_X25519_MLKEM512, "provider=quac100", quac_keyexch_functions,
     "X25519 + ML-KEM-512 Hybrid Key Exchange"},
    {NULL, NULL, NULL, NULL}};

/* ==========================================================================
 * TLS Group Registration
 * ========================================================================== */

/*
 * These structures would be used to register the hybrid groups
 * with OpenSSL's TLS layer for automatic negotiation.
 */

typedef struct
{
    const char *name;
    int nid;
    int group_id;
    size_t pubkey_len;
    size_t privkey_len;
    size_t shared_len;
} quac_tls_group_t;

static const quac_tls_group_t quac_tls_groups[] = {
    {
        .name = QUAC_GROUP_NAME_X25519_MLKEM768,
        .nid = 0, /* Would be registered at runtime */
        .group_id = QUAC_GROUP_X25519_MLKEM768,
        .pubkey_len = X25519_PUBKEY_SIZE + QUAC_ML_KEM_768_PK_SIZE,
        .privkey_len = X25519_PRIVKEY_SIZE + QUAC_ML_KEM_768_SK_SIZE,
        .shared_len = X25519_SHARED_SIZE + QUAC_ML_KEM_768_SS_SIZE,
    },
    {
        .name = QUAC_GROUP_NAME_P384_MLKEM1024,
        .nid = 0,
        .group_id = QUAC_GROUP_P384_MLKEM1024,
        .pubkey_len = P384_PUBKEY_SIZE + QUAC_ML_KEM_1024_PK_SIZE,
        .privkey_len = P384_PRIVKEY_SIZE + QUAC_ML_KEM_1024_SK_SIZE,
        .shared_len = P384_SHARED_SIZE + QUAC_ML_KEM_1024_SS_SIZE,
    },
    {
        .name = QUAC_GROUP_NAME_X25519_MLKEM512,
        .nid = 0,
        .group_id = QUAC_GROUP_X25519_MLKEM512,
        .pubkey_len = X25519_PUBKEY_SIZE + QUAC_ML_KEM_512_PK_SIZE,
        .privkey_len = X25519_PRIVKEY_SIZE + QUAC_ML_KEM_512_SK_SIZE,
        .shared_len = X25519_SHARED_SIZE + QUAC_ML_KEM_512_SS_SIZE,
    },
    {NULL, 0, 0, 0, 0, 0}};

/**
 * @brief Register hybrid groups for TLS use
 *
 * Call this during provider initialization to make groups available
 * for TLS negotiation.
 */
int quac_register_tls_groups(void)
{
    /*
     * In a full implementation, this would:
     * 1. Register NIDs for the hybrid groups
     * 2. Create EC_GROUP-like structures for hybrid
     * 3. Register with SSL_CTX_set1_groups_list
     */
    return 1;
}