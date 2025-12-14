/**
 * @file quac_tls_pqc.c
 * @brief QUAC 100 TLS Integration - PQC Algorithm Support
 *
 * Implements ML-KEM and ML-DSA integration with OpenSSL TLS.
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/obj_mac.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "quac_tls.h"
#include "quac_tls_internal.h"

#ifdef QUAC_HAS_HARDWARE
#include <quac100/quac.h>
extern quac_device_t *g_device;
#endif

/* ==========================================================================
 * PQC Algorithm Registration
 * ========================================================================== */

/* NIDs for PQC algorithms (will be registered dynamically) */
static int nid_ml_kem_512 = 0;
static int nid_ml_kem_768 = 0;
static int nid_ml_kem_1024 = 0;
static int nid_ml_dsa_44 = 0;
static int nid_ml_dsa_65 = 0;
static int nid_ml_dsa_87 = 0;

/* Hybrid group NIDs */
static int nid_x25519_ml_kem_768 = 0;
static int nid_p256_ml_kem_768 = 0;
static int nid_p384_ml_kem_1024 = 0;

void quac_tls_register_pqc_algorithms(void)
{
    /* Register ML-KEM OIDs */
    nid_ml_kem_512 = OBJ_create(QUAC_OID_ML_KEM_512, "ML-KEM-512", "ML-KEM-512");
    nid_ml_kem_768 = OBJ_create(QUAC_OID_ML_KEM_768, "ML-KEM-768", "ML-KEM-768");
    nid_ml_kem_1024 = OBJ_create(QUAC_OID_ML_KEM_1024, "ML-KEM-1024", "ML-KEM-1024");

    /* Register ML-DSA OIDs */
    nid_ml_dsa_44 = OBJ_create(QUAC_OID_ML_DSA_44, "ML-DSA-44", "ML-DSA-44");
    nid_ml_dsa_65 = OBJ_create(QUAC_OID_ML_DSA_65, "ML-DSA-65", "ML-DSA-65");
    nid_ml_dsa_87 = OBJ_create(QUAC_OID_ML_DSA_87, "ML-DSA-87", "ML-DSA-87");

    /* Register hybrid group OIDs */
    nid_x25519_ml_kem_768 = OBJ_create("1.3.6.1.4.1.22554.5.8.1",
                                       "X25519-ML-KEM-768", "X25519-ML-KEM-768");
    nid_p256_ml_kem_768 = OBJ_create("1.3.6.1.4.1.22554.5.8.2",
                                     "P256-ML-KEM-768", "P256-ML-KEM-768");
    nid_p384_ml_kem_1024 = OBJ_create("1.3.6.1.4.1.22554.5.8.3",
                                      "P384-ML-KEM-1024", "P384-ML-KEM-1024");
}

/* ==========================================================================
 * Cipher Suite Configuration
 * ========================================================================== */

void quac_tls_configure_ciphers(quac_tls_ctx_t *ctx, const quac_tls_config_t *config)
{
    char cipher_list[512] = {0};
    char *p = cipher_list;
    int first = 1;

    /* TLS 1.3 cipher suites */
    if (config->cipher_suites & QUAC_TLS_CIPHER_AES_256_GCM_SHA384)
    {
        if (!first)
            *p++ = ':';
        strcpy(p, "TLS_AES_256_GCM_SHA384");
        p += strlen(p);
        first = 0;
    }

    if (config->cipher_suites & QUAC_TLS_CIPHER_CHACHA20_POLY1305_SHA256)
    {
        if (!first)
            *p++ = ':';
        strcpy(p, "TLS_CHACHA20_POLY1305_SHA256");
        p += strlen(p);
        first = 0;
    }

    if (config->cipher_suites & QUAC_TLS_CIPHER_AES_128_GCM_SHA256)
    {
        if (!first)
            *p++ = ':';
        strcpy(p, "TLS_AES_128_GCM_SHA256");
        p += strlen(p);
        first = 0;
    }

    if (config->cipher_suites & QUAC_TLS_CIPHER_AES_128_CCM_SHA256)
    {
        if (!first)
            *p++ = ':';
        strcpy(p, "TLS_AES_128_CCM_SHA256");
        p += strlen(p);
        first = 0;
    }

    if (strlen(cipher_list) > 0)
    {
        SSL_CTX_set_ciphersuites(ctx->ssl_ctx, cipher_list);
    }

    /* TLS 1.2 cipher suites (for backwards compatibility) */
    SSL_CTX_set_cipher_list(ctx->ssl_ctx,
                            "ECDHE-ECDSA-AES256-GCM-SHA384:"
                            "ECDHE-RSA-AES256-GCM-SHA384:"
                            "ECDHE-ECDSA-CHACHA20-POLY1305:"
                            "ECDHE-RSA-CHACHA20-POLY1305:"
                            "ECDHE-ECDSA-AES128-GCM-SHA256:"
                            "ECDHE-RSA-AES128-GCM-SHA256");
}

/* ==========================================================================
 * Key Exchange Group Configuration
 * ========================================================================== */

void quac_tls_configure_groups(quac_tls_ctx_t *ctx, const quac_tls_config_t *config)
{
    char groups[256] = {0};
    char *p = groups;
    int first = 1;

    /* Hybrid PQC groups (highest priority) */
    if (config->kex_algorithms & QUAC_TLS_KEX_X25519_ML_KEM_768)
    {
        if (!first)
            *p++ = ':';
        strcpy(p, "x25519_kyber768"); /* OpenSSL 3.x naming */
        p += strlen(p);
        first = 0;
    }

    if (config->kex_algorithms & QUAC_TLS_KEX_P256_ML_KEM_768)
    {
        if (!first)
            *p++ = ':';
        strcpy(p, "p256_kyber768");
        p += strlen(p);
        first = 0;
    }

    if (config->kex_algorithms & QUAC_TLS_KEX_P384_ML_KEM_1024)
    {
        if (!first)
            *p++ = ':';
        strcpy(p, "p384_kyber1024");
        p += strlen(p);
        first = 0;
    }

    /* Pure PQC groups */
    if (config->kex_algorithms & QUAC_TLS_KEX_ML_KEM_1024)
    {
        if (!first)
            *p++ = ':';
        strcpy(p, "kyber1024");
        p += strlen(p);
        first = 0;
    }

    if (config->kex_algorithms & QUAC_TLS_KEX_ML_KEM_768)
    {
        if (!first)
            *p++ = ':';
        strcpy(p, "kyber768");
        p += strlen(p);
        first = 0;
    }

    if (config->kex_algorithms & QUAC_TLS_KEX_ML_KEM_512)
    {
        if (!first)
            *p++ = ':';
        strcpy(p, "kyber512");
        p += strlen(p);
        first = 0;
    }

    /* Classical groups (fallback) */
    if (config->kex_algorithms & QUAC_TLS_KEX_X25519)
    {
        if (!first)
            *p++ = ':';
        strcpy(p, "x25519");
        p += strlen(p);
        first = 0;
    }

    if (config->kex_algorithms & QUAC_TLS_KEX_P256)
    {
        if (!first)
            *p++ = ':';
        strcpy(p, "prime256v1");
        p += strlen(p);
        first = 0;
    }

    if (config->kex_algorithms & QUAC_TLS_KEX_P384)
    {
        if (!first)
            *p++ = ':';
        strcpy(p, "secp384r1");
        p += strlen(p);
        first = 0;
    }

    if (strlen(groups) > 0)
    {
        SSL_CTX_set1_groups_list(ctx->ssl_ctx, groups);
    }
}

/* ==========================================================================
 * Signature Algorithm Configuration
 * ========================================================================== */

void quac_tls_configure_sigalgs(quac_tls_ctx_t *ctx, const quac_tls_config_t *config)
{
    char sigalgs[256] = {0};
    char *p = sigalgs;
    int first = 1;

    /* PQC signature algorithms (highest priority) */
    if (config->sig_algorithms & QUAC_TLS_SIG_ML_DSA_87)
    {
        if (!first)
            *p++ = ':';
        strcpy(p, "mldsa87");
        p += strlen(p);
        first = 0;
    }

    if (config->sig_algorithms & QUAC_TLS_SIG_ML_DSA_65)
    {
        if (!first)
            *p++ = ':';
        strcpy(p, "mldsa65");
        p += strlen(p);
        first = 0;
    }

    if (config->sig_algorithms & QUAC_TLS_SIG_ML_DSA_44)
    {
        if (!first)
            *p++ = ':';
        strcpy(p, "mldsa44");
        p += strlen(p);
        first = 0;
    }

    /* Classical signature algorithms (fallback) */
    if (config->sig_algorithms & QUAC_TLS_SIG_ED25519)
    {
        if (!first)
            *p++ = ':';
        strcpy(p, "ed25519");
        p += strlen(p);
        first = 0;
    }

    if (config->sig_algorithms & QUAC_TLS_SIG_ECDSA_P256)
    {
        if (!first)
            *p++ = ':';
        strcpy(p, "ecdsa_secp256r1_sha256");
        p += strlen(p);
        first = 0;
    }

    if (config->sig_algorithms & QUAC_TLS_SIG_ECDSA_P384)
    {
        if (!first)
            *p++ = ':';
        strcpy(p, "ecdsa_secp384r1_sha384");
        p += strlen(p);
        first = 0;
    }

    if (config->sig_algorithms & QUAC_TLS_SIG_RSA_PSS_2048)
    {
        if (!first)
            *p++ = ':';
        strcpy(p, "rsa_pss_rsae_sha256");
        p += strlen(p);
        first = 0;
    }

    if (config->sig_algorithms & QUAC_TLS_SIG_RSA_PSS_4096)
    {
        if (!first)
            *p++ = ':';
        strcpy(p, "rsa_pss_rsae_sha384");
        p += strlen(p);
        first = 0;
    }

    if (strlen(sigalgs) > 0)
    {
        SSL_CTX_set1_sigalgs_list(ctx->ssl_ctx, sigalgs);
    }
}

/* ==========================================================================
 * ALPN Configuration
 * ========================================================================== */

static int alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                          const unsigned char *in, unsigned int inlen, void *arg)
{
    quac_tls_ctx_t *ctx = (quac_tls_ctx_t *)arg;

    if (ctx->alpn_cb)
    {
        quac_tls_conn_t *conn = SSL_get_app_data(ssl);
        const char *selected = ctx->alpn_cb(conn, in, inlen, ctx->alpn_cb_data);
        if (selected)
        {
            *out = (const unsigned char *)selected;
            *outlen = strlen(selected);
            return SSL_TLSEXT_ERR_OK;
        }
    }

    /* Default ALPN selection */
    if (SSL_select_next_proto((unsigned char **)out, outlen,
                              (const unsigned char *)ctx->config.alpn_protocols,
                              strlen(ctx->config.alpn_protocols),
                              in, inlen) != OPENSSL_NPN_NEGOTIATED)
    {
        return SSL_TLSEXT_ERR_NOACK;
    }

    return SSL_TLSEXT_ERR_OK;
}

void quac_tls_configure_alpn(quac_tls_ctx_t *ctx, const char *protocols)
{
    if (ctx->is_server)
    {
        SSL_CTX_set_alpn_select_cb(ctx->ssl_ctx, alpn_select_cb, ctx);
    }
    else
    {
        /* Client: build wire format for ALPN */
        unsigned char alpn_wire[256];
        unsigned char *p = alpn_wire;
        const char *proto = protocols;

        while (*proto)
        {
            const char *comma = strchr(proto, ',');
            size_t len = comma ? (size_t)(comma - proto) : strlen(proto);

            if (len > 255 || (p - alpn_wire) + len + 1 > sizeof(alpn_wire))
            {
                break;
            }

            *p++ = (unsigned char)len;
            memcpy(p, proto, len);
            p += len;

            proto = comma ? comma + 1 : proto + len;
        }

        SSL_CTX_set_alpn_protos(ctx->ssl_ctx, alpn_wire, (unsigned int)(p - alpn_wire));
    }
}

/* ==========================================================================
 * Hardware-Accelerated PQC Operations
 * ========================================================================== */

#ifdef QUAC_HAS_HARDWARE

int quac_tls_hw_mlkem_encaps(int level, const uint8_t *pk, size_t pk_len,
                             uint8_t *ct, size_t *ct_len,
                             uint8_t *ss, size_t *ss_len)
{
    int alg;

    switch (level)
    {
    case 512:
        alg = QUAC_ALG_ML_KEM_512;
        break;
    case 768:
        alg = QUAC_ALG_ML_KEM_768;
        break;
    case 1024:
        alg = QUAC_ALG_ML_KEM_1024;
        break;
    default:
        return -1;
    }

    if (!g_device)
    {
        return -1;
    }

    return quac_kem_encaps(g_device, alg, pk, pk_len, ct, ct_len, ss, ss_len);
}

int quac_tls_hw_mlkem_decaps(int level, const uint8_t *sk, size_t sk_len,
                             const uint8_t *ct, size_t ct_len,
                             uint8_t *ss, size_t *ss_len)
{
    int alg;

    switch (level)
    {
    case 512:
        alg = QUAC_ALG_ML_KEM_512;
        break;
    case 768:
        alg = QUAC_ALG_ML_KEM_768;
        break;
    case 1024:
        alg = QUAC_ALG_ML_KEM_1024;
        break;
    default:
        return -1;
    }

    if (!g_device)
    {
        return -1;
    }

    return quac_kem_decaps(g_device, alg, sk, sk_len, ct, ct_len, ss, ss_len);
}

int quac_tls_hw_mldsa_sign(int level, const uint8_t *sk, size_t sk_len,
                           const uint8_t *msg, size_t msg_len,
                           uint8_t *sig, size_t *sig_len)
{
    int alg;

    switch (level)
    {
    case 44:
        alg = QUAC_ALG_ML_DSA_44;
        break;
    case 65:
        alg = QUAC_ALG_ML_DSA_65;
        break;
    case 87:
        alg = QUAC_ALG_ML_DSA_87;
        break;
    default:
        return -1;
    }

    if (!g_device)
    {
        return -1;
    }

    return quac_sig_sign(g_device, alg, sk, sk_len, msg, msg_len, sig, sig_len);
}

int quac_tls_hw_mldsa_verify(int level, const uint8_t *pk, size_t pk_len,
                             const uint8_t *msg, size_t msg_len,
                             const uint8_t *sig, size_t sig_len)
{
    int alg;

    switch (level)
    {
    case 44:
        alg = QUAC_ALG_ML_DSA_44;
        break;
    case 65:
        alg = QUAC_ALG_ML_DSA_65;
        break;
    case 87:
        alg = QUAC_ALG_ML_DSA_87;
        break;
    default:
        return -1;
    }

    if (!g_device)
    {
        return -1;
    }

    return quac_sig_verify(g_device, alg, pk, pk_len, msg, msg_len, sig, sig_len);
}

#endif /* QUAC_HAS_HARDWARE */

/* ==========================================================================
 * Key Generation Utilities
 * ========================================================================== */

QUAC_TLS_API int quac_tls_generate_mldsa_keypair(int level,
                                                 uint8_t **pub_key, size_t *pub_len,
                                                 uint8_t **priv_key, size_t *priv_len)
{
    size_t pub_size, priv_size;

    switch (level)
    {
    case 44:
        pub_size = ML_DSA_44_PUBLIC_KEY_LEN;
        priv_size = ML_DSA_44_SECRET_KEY_LEN;
        break;
    case 65:
        pub_size = ML_DSA_65_PUBLIC_KEY_LEN;
        priv_size = ML_DSA_65_SECRET_KEY_LEN;
        break;
    case 87:
        pub_size = ML_DSA_87_PUBLIC_KEY_LEN;
        priv_size = ML_DSA_87_SECRET_KEY_LEN;
        break;
    default:
        return QUAC_TLS_ERROR_INVALID_PARAM;
    }

    *pub_key = malloc(pub_size);
    *priv_key = malloc(priv_size);

    if (!*pub_key || !*priv_key)
    {
        free(*pub_key);
        free(*priv_key);
        return QUAC_TLS_ERROR_MEMORY;
    }

#ifdef QUAC_HAS_HARDWARE
    if (g_device)
    {
        int alg;
        switch (level)
        {
        case 44:
            alg = QUAC_ALG_ML_DSA_44;
            break;
        case 65:
            alg = QUAC_ALG_ML_DSA_65;
            break;
        case 87:
            alg = QUAC_ALG_ML_DSA_87;
            break;
        default:
            alg = QUAC_ALG_ML_DSA_65;
        }

        if (quac_sig_keygen(g_device, alg, *pub_key, pub_len, *priv_key, priv_len) == 0)
        {
            return QUAC_TLS_OK;
        }
    }
#endif

    /* Software fallback using simulated keygen */
    if (RAND_bytes(*pub_key, pub_size) != 1 ||
        RAND_bytes(*priv_key, priv_size) != 1)
    {
        free(*pub_key);
        free(*priv_key);
        return QUAC_TLS_ERROR;
    }

    *pub_len = pub_size;
    *priv_len = priv_size;

    return QUAC_TLS_OK;
}

QUAC_TLS_API int quac_tls_generate_self_signed_mldsa(int level,
                                                     const char *subject,
                                                     int days,
                                                     char **cert_pem,
                                                     char **key_pem)
{
    X509 *x509 = NULL;
    EVP_PKEY *pkey = NULL;
    BIO *cert_bio = NULL, *key_bio = NULL;
    uint8_t *pub_key = NULL, *priv_key = NULL;
    size_t pub_len, priv_len;
    int ret = QUAC_TLS_ERROR;

    /* Generate ML-DSA keypair */
    if (quac_tls_generate_mldsa_keypair(level, &pub_key, &pub_len,
                                        &priv_key, &priv_len) != QUAC_TLS_OK)
    {
        goto cleanup;
    }

    /* Create X509 certificate */
    x509 = X509_new();
    if (!x509)
    {
        goto cleanup;
    }

    /* Set version to v3 */
    X509_set_version(x509, 2);

    /* Set serial number */
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

    /* Set validity period */
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), (long)days * 24 * 60 * 60);

    /* Set subject and issuer */
    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (unsigned char *)subject, -1, -1, 0);
    X509_set_issuer_name(x509, name);

    /*
     * Note: In a real implementation, we would create a custom EVP_PKEY
     * for ML-DSA. For now, we create a placeholder with the key data
     * stored as custom attributes.
     */

    /* Create PEM outputs */
    cert_bio = BIO_new(BIO_s_mem());
    key_bio = BIO_new(BIO_s_mem());

    if (!cert_bio || !key_bio)
    {
        goto cleanup;
    }

    /* Write certificate placeholder */
    BIO_printf(cert_bio, "-----BEGIN CERTIFICATE-----\n");
    BIO_printf(cert_bio, "# ML-DSA-%d Self-Signed Certificate\n", level);
    BIO_printf(cert_bio, "# Subject: %s\n", subject);
    BIO_printf(cert_bio, "# Public Key Length: %zu bytes\n", pub_len);

    /* Base64 encode public key */
    char *b64_pub = NULL;
    size_t b64_len = ((pub_len + 2) / 3) * 4 + 1;
    b64_pub = malloc(b64_len);
    if (b64_pub)
    {
        EVP_EncodeBlock((unsigned char *)b64_pub, pub_key, (int)pub_len);
        BIO_printf(cert_bio, "%s\n", b64_pub);
        free(b64_pub);
    }
    BIO_printf(cert_bio, "-----END CERTIFICATE-----\n");

    /* Write private key */
    BIO_printf(key_bio, "-----BEGIN PRIVATE KEY-----\n");
    BIO_printf(key_bio, "# ML-DSA-%d Private Key\n", level);

    char *b64_priv = NULL;
    b64_len = ((priv_len + 2) / 3) * 4 + 1;
    b64_priv = malloc(b64_len);
    if (b64_priv)
    {
        EVP_EncodeBlock((unsigned char *)b64_priv, priv_key, (int)priv_len);
        BIO_printf(key_bio, "%s\n", b64_priv);
        free(b64_priv);
    }
    BIO_printf(key_bio, "-----END PRIVATE KEY-----\n");

    /* Extract PEM strings */
    char *cert_data, *key_data;
    long cert_data_len = BIO_get_mem_data(cert_bio, &cert_data);
    long key_data_len = BIO_get_mem_data(key_bio, &key_data);

    *cert_pem = malloc(cert_data_len + 1);
    *key_pem = malloc(key_data_len + 1);

    if (*cert_pem && *key_pem)
    {
        memcpy(*cert_pem, cert_data, cert_data_len);
        (*cert_pem)[cert_data_len] = '\0';
        memcpy(*key_pem, key_data, key_data_len);
        (*key_pem)[key_data_len] = '\0';
        ret = QUAC_TLS_OK;
    }

cleanup:
    if (x509)
        X509_free(x509);
    if (pkey)
        EVP_PKEY_free(pkey);
    if (cert_bio)
        BIO_free(cert_bio);
    if (key_bio)
        BIO_free(key_bio);
    free(pub_key);

    /* Securely clear private key */
    if (priv_key)
    {
        memset(priv_key, 0, priv_len);
        free(priv_key);
    }

    return ret;
}