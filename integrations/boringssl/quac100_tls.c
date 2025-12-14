/**
 * @file quac100_tls.c
 * @brief QUAC 100 BoringSSL Integration - TLS Key Exchange
 *
 * Implements hybrid key exchange for TLS 1.3:
 * - X25519_ML-KEM-768 (X25519 + ML-KEM-768)
 * - P-384_ML-KEM-1024 (ECDH P-384 + ML-KEM-1024)
 * - X25519_ML-KEM-512 (X25519 + ML-KEM-512)
 *
 * These hybrid groups provide both classical and post-quantum security
 * following draft-ietf-tls-hybrid-design.
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <string.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/curve25519.h>
#include <openssl/ec.h>
#include <openssl/mem.h>

#include "quac100_boringssl.h"

/* ==========================================================================
 * Hybrid Group Constants
 * ========================================================================== */

/* X25519 sizes */
#define X25519_PUBLIC_KEY_LEN 32
#define X25519_PRIVATE_KEY_LEN 32
#define X25519_SHARED_SECRET_LEN 32

/* P-384 sizes (uncompressed) */
#define P384_PUBLIC_KEY_LEN 97 /* 1 + 48 + 48 */
#define P384_PRIVATE_KEY_LEN 48
#define P384_SHARED_SECRET_LEN 48

/* Combined key sizes for hybrid groups */
#define HYBRID_X25519_MLKEM768_PK_LEN (X25519_PUBLIC_KEY_LEN + QUAC_ML_KEM_768_PUBLIC_KEY_BYTES)
#define HYBRID_X25519_MLKEM768_SK_LEN (X25519_PRIVATE_KEY_LEN + QUAC_ML_KEM_768_SECRET_KEY_BYTES)
#define HYBRID_X25519_MLKEM768_CT_LEN (X25519_PUBLIC_KEY_LEN + QUAC_ML_KEM_768_CIPHERTEXT_BYTES)
#define HYBRID_X25519_MLKEM768_SS_LEN (X25519_SHARED_SECRET_LEN + QUAC_ML_KEM_768_SHARED_SECRET_BYTES)

#define HYBRID_P384_MLKEM1024_PK_LEN (P384_PUBLIC_KEY_LEN + QUAC_ML_KEM_1024_PUBLIC_KEY_BYTES)
#define HYBRID_P384_MLKEM1024_SK_LEN (P384_PRIVATE_KEY_LEN + QUAC_ML_KEM_1024_SECRET_KEY_BYTES)
#define HYBRID_P384_MLKEM1024_CT_LEN (P384_PUBLIC_KEY_LEN + QUAC_ML_KEM_1024_CIPHERTEXT_BYTES)
#define HYBRID_P384_MLKEM1024_SS_LEN (P384_SHARED_SECRET_LEN + QUAC_ML_KEM_1024_SHARED_SECRET_BYTES)

/* ==========================================================================
 * Hybrid Key Exchange Context
 * ========================================================================== */

typedef struct quac_hybrid_ctx
{
    quac_tls_group_t group;

    /* Classical component (X25519 or ECDH) */
    uint8_t classical_public[P384_PUBLIC_KEY_LEN];
    uint8_t classical_private[P384_PRIVATE_KEY_LEN];
    size_t classical_pk_len;
    size_t classical_sk_len;

    /* PQC component (ML-KEM) */
    uint8_t *pqc_public;
    uint8_t *pqc_secret;
    size_t pqc_pk_len;
    size_t pqc_sk_len;

    /* Peer's public key */
    uint8_t *peer_public;
    size_t peer_pk_len;

    /* Combined shared secret */
    uint8_t shared_secret[HYBRID_P384_MLKEM1024_SS_LEN];
    size_t ss_len;

    /* State */
    int keys_generated;
    int peer_set;
    int derived;
} QUAC_HYBRID_CTX;

/* ==========================================================================
 * Context Management
 * ========================================================================== */

QUAC_HYBRID_CTX *QUAC_hybrid_ctx_new(quac_tls_group_t group)
{
    QUAC_HYBRID_CTX *ctx = OPENSSL_zalloc(sizeof(QUAC_HYBRID_CTX));
    if (!ctx)
        return NULL;

    ctx->group = group;

    switch (group)
    {
    case QUAC_GROUP_X25519_ML_KEM_768:
        ctx->classical_pk_len = X25519_PUBLIC_KEY_LEN;
        ctx->classical_sk_len = X25519_PRIVATE_KEY_LEN;
        ctx->pqc_pk_len = QUAC_ML_KEM_768_PUBLIC_KEY_BYTES;
        ctx->pqc_sk_len = QUAC_ML_KEM_768_SECRET_KEY_BYTES;
        ctx->ss_len = HYBRID_X25519_MLKEM768_SS_LEN;
        break;

    case QUAC_GROUP_SECP384R1_ML_KEM_1024:
        ctx->classical_pk_len = P384_PUBLIC_KEY_LEN;
        ctx->classical_sk_len = P384_PRIVATE_KEY_LEN;
        ctx->pqc_pk_len = QUAC_ML_KEM_1024_PUBLIC_KEY_BYTES;
        ctx->pqc_sk_len = QUAC_ML_KEM_1024_SECRET_KEY_BYTES;
        ctx->ss_len = HYBRID_P384_MLKEM1024_SS_LEN;
        break;

    case QUAC_GROUP_X25519_ML_KEM_512:
        ctx->classical_pk_len = X25519_PUBLIC_KEY_LEN;
        ctx->classical_sk_len = X25519_PRIVATE_KEY_LEN;
        ctx->pqc_pk_len = QUAC_ML_KEM_512_PUBLIC_KEY_BYTES;
        ctx->pqc_sk_len = QUAC_ML_KEM_512_SECRET_KEY_BYTES;
        ctx->ss_len = X25519_SHARED_SECRET_LEN + QUAC_ML_KEM_512_SHARED_SECRET_BYTES;
        break;

    default:
        OPENSSL_free(ctx);
        return NULL;
    }

    ctx->pqc_public = OPENSSL_malloc(ctx->pqc_pk_len);
    ctx->pqc_secret = OPENSSL_malloc(ctx->pqc_sk_len);

    if (!ctx->pqc_public || !ctx->pqc_secret)
    {
        OPENSSL_free(ctx->pqc_public);
        OPENSSL_free(ctx->pqc_secret);
        OPENSSL_free(ctx);
        return NULL;
    }

    return ctx;
}

void QUAC_hybrid_ctx_free(QUAC_HYBRID_CTX *ctx)
{
    if (!ctx)
        return;

    OPENSSL_cleanse(ctx->classical_private, sizeof(ctx->classical_private));

    if (ctx->pqc_secret)
    {
        OPENSSL_cleanse(ctx->pqc_secret, ctx->pqc_sk_len);
        OPENSSL_free(ctx->pqc_secret);
    }

    OPENSSL_free(ctx->pqc_public);
    OPENSSL_free(ctx->peer_public);

    OPENSSL_cleanse(ctx->shared_secret, sizeof(ctx->shared_secret));

    OPENSSL_free(ctx);
}

/* ==========================================================================
 * Key Generation
 * ========================================================================== */

int QUAC_hybrid_generate_keypair(QUAC_HYBRID_CTX *ctx)
{
    int ret;

    if (!ctx)
        return QUAC_ERROR_INVALID_KEY;

    /* Generate classical keypair */
    switch (ctx->group)
    {
    case QUAC_GROUP_X25519_ML_KEM_768:
    case QUAC_GROUP_X25519_ML_KEM_512:
        /* X25519 key generation */
        X25519_keypair(ctx->classical_public, ctx->classical_private);
        break;

    case QUAC_GROUP_SECP384R1_ML_KEM_1024:
        /* P-384 key generation */
        {
            EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_secp384r1);
            if (!ec_key)
                return QUAC_ERROR_INTERNAL;

            if (!EC_KEY_generate_key(ec_key))
            {
                EC_KEY_free(ec_key);
                return QUAC_ERROR_INTERNAL;
            }

            /* Extract public key */
            const EC_POINT *pub = EC_KEY_get0_public_key(ec_key);
            const EC_GROUP *grp = EC_KEY_get0_group(ec_key);

            size_t pk_len = EC_POINT_point2oct(grp, pub, POINT_CONVERSION_UNCOMPRESSED,
                                               ctx->classical_public, ctx->classical_pk_len, NULL);
            if (pk_len != ctx->classical_pk_len)
            {
                EC_KEY_free(ec_key);
                return QUAC_ERROR_INTERNAL;
            }

            /* Extract private key */
            const BIGNUM *priv = EC_KEY_get0_private_key(ec_key);
            size_t sk_len = BN_num_bytes(priv);
            memset(ctx->classical_private, 0, ctx->classical_sk_len);
            BN_bn2bin(priv, ctx->classical_private + (ctx->classical_sk_len - sk_len));

            EC_KEY_free(ec_key);
        }
        break;

    default:
        return QUAC_ERROR_INVALID_ALGORITHM;
    }

    /* Generate PQC keypair */
    quac_kem_algorithm_t kem_alg;
    switch (ctx->group)
    {
    case QUAC_GROUP_X25519_ML_KEM_768:
        kem_alg = QUAC_KEM_ML_KEM_768;
        break;
    case QUAC_GROUP_SECP384R1_ML_KEM_1024:
        kem_alg = QUAC_KEM_ML_KEM_1024;
        break;
    case QUAC_GROUP_X25519_ML_KEM_512:
        kem_alg = QUAC_KEM_ML_KEM_512;
        break;
    default:
        return QUAC_ERROR_INVALID_ALGORITHM;
    }

    ret = QUAC_KEM_keypair(kem_alg, ctx->pqc_public, ctx->pqc_secret);
    if (ret != QUAC_SUCCESS)
        return ret;

    ctx->keys_generated = 1;

    return QUAC_SUCCESS;
}

/* ==========================================================================
 * Public Key Export/Import
 * ========================================================================== */

int QUAC_hybrid_get_public_key(const QUAC_HYBRID_CTX *ctx,
                               uint8_t *pk, size_t *pk_len)
{
    size_t total_len;

    if (!ctx || !ctx->keys_generated)
        return QUAC_ERROR_INVALID_KEY;

    total_len = ctx->classical_pk_len + ctx->pqc_pk_len;

    if (pk == NULL)
    {
        *pk_len = total_len;
        return QUAC_SUCCESS;
    }

    if (*pk_len < total_len)
        return QUAC_ERROR_BUFFER_TOO_SMALL;

    /* Concatenate: classical || PQC */
    memcpy(pk, ctx->classical_public, ctx->classical_pk_len);
    memcpy(pk + ctx->classical_pk_len, ctx->pqc_public, ctx->pqc_pk_len);

    *pk_len = total_len;

    return QUAC_SUCCESS;
}

int QUAC_hybrid_set_peer_public_key(QUAC_HYBRID_CTX *ctx,
                                    const uint8_t *pk, size_t pk_len)
{
    size_t expected_len;

    if (!ctx)
        return QUAC_ERROR_INVALID_KEY;

    expected_len = ctx->classical_pk_len + ctx->pqc_pk_len;

    if (pk_len != expected_len)
        return QUAC_ERROR_INVALID_KEY;

    ctx->peer_public = OPENSSL_memdup(pk, pk_len);
    if (!ctx->peer_public)
        return QUAC_ERROR_MEMORY_ALLOCATION;

    ctx->peer_pk_len = pk_len;
    ctx->peer_set = 1;

    return QUAC_SUCCESS;
}

/* ==========================================================================
 * Shared Secret Derivation
 * ========================================================================== */

int QUAC_hybrid_derive(QUAC_HYBRID_CTX *ctx,
                       uint8_t *shared_secret, size_t *ss_len)
{
    uint8_t classical_ss[P384_SHARED_SECRET_LEN];
    uint8_t pqc_ss[QUAC_ML_KEM_768_SHARED_SECRET_BYTES];
    size_t classical_ss_len, pqc_ss_len;
    int ret;

    if (!ctx || !ctx->keys_generated || !ctx->peer_set)
        return QUAC_ERROR_INVALID_KEY;

    /* Extract peer's keys */
    const uint8_t *peer_classical = ctx->peer_public;
    const uint8_t *peer_pqc = ctx->peer_public + ctx->classical_pk_len;

    /* Classical key agreement */
    switch (ctx->group)
    {
    case QUAC_GROUP_X25519_ML_KEM_768:
    case QUAC_GROUP_X25519_ML_KEM_512:
        /* X25519 */
        if (!X25519(classical_ss, ctx->classical_private, peer_classical))
            return QUAC_ERROR_INTERNAL;
        classical_ss_len = X25519_SHARED_SECRET_LEN;
        break;

    case QUAC_GROUP_SECP384R1_ML_KEM_1024:
        /* ECDH P-384 */
        {
            EC_KEY *our_key = EC_KEY_new_by_curve_name(NID_secp384r1);
            if (!our_key)
                return QUAC_ERROR_INTERNAL;

            /* Set our private key */
            BIGNUM *priv_bn = BN_bin2bn(ctx->classical_private, ctx->classical_sk_len, NULL);
            if (!EC_KEY_set_private_key(our_key, priv_bn))
            {
                BN_free(priv_bn);
                EC_KEY_free(our_key);
                return QUAC_ERROR_INTERNAL;
            }
            BN_free(priv_bn);

            /* Decode peer's public key */
            const EC_GROUP *grp = EC_KEY_get0_group(our_key);
            EC_POINT *peer_point = EC_POINT_new(grp);

            if (!EC_POINT_oct2point(grp, peer_point, peer_classical,
                                    ctx->classical_pk_len, NULL))
            {
                EC_POINT_free(peer_point);
                EC_KEY_free(our_key);
                return QUAC_ERROR_INVALID_KEY;
            }

            /* Compute shared secret */
            int ss_size = ECDH_compute_key(classical_ss, P384_SHARED_SECRET_LEN,
                                           peer_point, our_key, NULL);

            EC_POINT_free(peer_point);
            EC_KEY_free(our_key);

            if (ss_size != P384_SHARED_SECRET_LEN)
                return QUAC_ERROR_INTERNAL;

            classical_ss_len = P384_SHARED_SECRET_LEN;
        }
        break;

    default:
        return QUAC_ERROR_INVALID_ALGORITHM;
    }

    /* PQC encapsulation/decapsulation */
    quac_kem_algorithm_t kem_alg;
    switch (ctx->group)
    {
    case QUAC_GROUP_X25519_ML_KEM_768:
        kem_alg = QUAC_KEM_ML_KEM_768;
        pqc_ss_len = QUAC_ML_KEM_768_SHARED_SECRET_BYTES;
        break;
    case QUAC_GROUP_SECP384R1_ML_KEM_1024:
        kem_alg = QUAC_KEM_ML_KEM_1024;
        pqc_ss_len = QUAC_ML_KEM_1024_SHARED_SECRET_BYTES;
        break;
    case QUAC_GROUP_X25519_ML_KEM_512:
        kem_alg = QUAC_KEM_ML_KEM_512;
        pqc_ss_len = QUAC_ML_KEM_512_SHARED_SECRET_BYTES;
        break;
    default:
        return QUAC_ERROR_INVALID_ALGORITHM;
    }

    /* For client: encapsulate to peer's PQC public key */
    /* For server: decapsulate using our PQC secret key */
    /* This simplified version always encapsulates */
    uint8_t ct[QUAC_KEM_MAX_CIPHERTEXT_BYTES];
    ret = QUAC_KEM_encaps(kem_alg, ct, pqc_ss, peer_pqc);
    if (ret != QUAC_SUCCESS)
        return ret;

    /* Combine shared secrets */
    size_t total_ss = classical_ss_len + pqc_ss_len;

    if (shared_secret == NULL)
    {
        *ss_len = total_ss;
        return QUAC_SUCCESS;
    }

    if (*ss_len < total_ss)
        return QUAC_ERROR_BUFFER_TOO_SMALL;

    /* Concatenate: classical_ss || pqc_ss */
    memcpy(shared_secret, classical_ss, classical_ss_len);
    memcpy(shared_secret + classical_ss_len, pqc_ss, pqc_ss_len);

    *ss_len = total_ss;
    ctx->derived = 1;

    /* Secure cleanup */
    OPENSSL_cleanse(classical_ss, sizeof(classical_ss));
    OPENSSL_cleanse(pqc_ss, sizeof(pqc_ss));

    return QUAC_SUCCESS;
}

/* ==========================================================================
 * TLS Group Registration
 * ========================================================================== */

/*
 * BoringSSL's SSL_CTX_set1_groups_list expects comma-separated names.
 * We provide functions to integrate with BoringSSL's TLS stack.
 */

static const struct
{
    quac_tls_group_t id;
    const char *name;
    int nid;
    size_t pk_len;
    size_t ss_len;
} quac_tls_groups[] = {
    {QUAC_GROUP_X25519_ML_KEM_768,
     "X25519_ML-KEM-768",
     0x6399,
     HYBRID_X25519_MLKEM768_PK_LEN,
     HYBRID_X25519_MLKEM768_SS_LEN},
    {QUAC_GROUP_SECP384R1_ML_KEM_1024,
     "P-384_ML-KEM-1024",
     0x639A,
     HYBRID_P384_MLKEM1024_PK_LEN,
     HYBRID_P384_MLKEM1024_SS_LEN},
    {QUAC_GROUP_X25519_ML_KEM_512,
     "X25519_ML-KEM-512",
     0x639B,
     X25519_PUBLIC_KEY_LEN + QUAC_ML_KEM_512_PUBLIC_KEY_BYTES,
     X25519_SHARED_SECRET_LEN + QUAC_ML_KEM_512_SHARED_SECRET_BYTES},
    {0, NULL, 0, 0, 0}};

int QUAC_TLS_register_groups(void)
{
    /*
     * Full TLS integration requires BoringSSL source modifications.
     * This function prepares our side; actual registration needs
     * patching SSL_GROUP definitions in ssl/internal.h
     */
    return QUAC_SUCCESS;
}

int QUAC_TLS_get_groups(quac_tls_group_t *groups, size_t *count)
{
    size_t n = 0;

    if (!count)
        return QUAC_ERROR_INVALID_KEY;

    for (int i = 0; quac_tls_groups[i].name != NULL; i++)
        n++;

    if (groups == NULL)
    {
        *count = n;
        return QUAC_SUCCESS;
    }

    if (*count < n)
        return QUAC_ERROR_BUFFER_TOO_SMALL;

    for (size_t i = 0; i < n; i++)
    {
        groups[i] = quac_tls_groups[i].id;
    }

    *count = n;
    return QUAC_SUCCESS;
}

int QUAC_TLS_group_is_supported(quac_tls_group_t group)
{
    for (int i = 0; quac_tls_groups[i].name != NULL; i++)
    {
        if (quac_tls_groups[i].id == group)
            return 1;
    }
    return 0;
}

const char *QUAC_TLS_group_name(quac_tls_group_t group)
{
    for (int i = 0; quac_tls_groups[i].name != NULL; i++)
    {
        if (quac_tls_groups[i].id == group)
            return quac_tls_groups[i].name;
    }
    return NULL;
}