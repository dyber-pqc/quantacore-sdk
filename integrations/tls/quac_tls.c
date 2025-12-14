/**
 * @file quac_tls.c
 * @brief QUAC 100 TLS Integration - Core Implementation
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#include "quac_tls.h"
#include "quac_tls_internal.h"

#ifdef QUAC_HAS_HARDWARE
#include <quac100/quac.h>
#endif

/* ==========================================================================
 * Global State
 * ========================================================================== */

static int g_initialized = 0;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

#ifdef QUAC_HAS_HARDWARE
static quac_device_t *g_device = NULL;
#endif

/* ==========================================================================
 * Error Messages
 * ========================================================================== */

static const char *g_error_strings[] = {
    [0] = "Success",
    [1] = "General error",
    [2] = "Memory allocation failed",
    [3] = "Invalid parameter",
    [4] = "Library not initialized",
    [5] = "Library already initialized",
    [6] = "Hardware error",
    [7] = "Handshake failed",
    [8] = "Certificate error",
    [9] = "Private key error",
    [10] = "Verification failed",
    [11] = "Decryption failed",
    [12] = "Encryption failed",
    [13] = "Timeout",
    [14] = "Connection closed",
    [15] = "Want read",
    [16] = "Want write",
    [17] = "System call error",
    [18] = "SSL error",
    [19] = "Unsupported operation",
};

/* ==========================================================================
 * Library Initialization
 * ========================================================================== */

QUAC_TLS_API int quac_tls_init(void)
{
    pthread_mutex_lock(&g_lock);

    if (g_initialized)
    {
        pthread_mutex_unlock(&g_lock);
        return QUAC_TLS_ERROR_ALREADY_INIT;
    }

    /* Initialize OpenSSL */
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    /* Initialize hardware if available */
#ifdef QUAC_HAS_HARDWARE
    if (quac_init() == 0)
    {
        int num_devices = quac_device_count();
        if (num_devices > 0)
        {
            g_device = quac_device_open(0);
        }
    }
#endif

    /* Register PQC algorithms with OpenSSL */
    quac_tls_register_pqc_algorithms();

    g_initialized = 1;
    pthread_mutex_unlock(&g_lock);

    return QUAC_TLS_OK;
}

QUAC_TLS_API void quac_tls_cleanup(void)
{
    pthread_mutex_lock(&g_lock);

    if (!g_initialized)
    {
        pthread_mutex_unlock(&g_lock);
        return;
    }

#ifdef QUAC_HAS_HARDWARE
    if (g_device)
    {
        quac_device_close(g_device);
        g_device = NULL;
    }
    quac_cleanup();
#endif

    EVP_cleanup();
    ERR_free_strings();

    g_initialized = 0;
    pthread_mutex_unlock(&g_lock);
}

QUAC_TLS_API const char *quac_tls_version(void)
{
    return QUAC_TLS_VERSION_STRING;
}

QUAC_TLS_API const char *quac_tls_error_string(int error)
{
    int idx = -error;
    if (idx >= 0 && idx < (int)(sizeof(g_error_strings) / sizeof(g_error_strings[0])))
    {
        return g_error_strings[idx];
    }
    return "Unknown error";
}

/* ==========================================================================
 * Configuration
 * ========================================================================== */

QUAC_TLS_API void quac_tls_config_default(quac_tls_config_t *config)
{
    if (!config)
        return;

    memset(config, 0, sizeof(*config));

    config->min_version = QUAC_TLS_VERSION_1_2;
    config->max_version = QUAC_TLS_VERSION_1_3;

    /* Default to hybrid PQC + classical for maximum security */
    config->kex_algorithms = QUAC_TLS_KEX_X25519_ML_KEM_768 |
                             QUAC_TLS_KEX_P256_ML_KEM_768 |
                             QUAC_TLS_KEX_X25519 |
                             QUAC_TLS_KEX_P256;

    config->sig_algorithms = QUAC_TLS_SIG_ML_DSA_65 |
                             QUAC_TLS_SIG_ML_DSA_87 |
                             QUAC_TLS_SIG_ED25519 |
                             QUAC_TLS_SIG_ECDSA_P256;

    config->cipher_suites = QUAC_TLS_CIPHER_AES_256_GCM_SHA384 |
                            QUAC_TLS_CIPHER_CHACHA20_POLY1305_SHA256 |
                            QUAC_TLS_CIPHER_AES_128_GCM_SHA256;

    config->verify_mode = QUAC_TLS_VERIFY_PEER;
    config->verify_depth = 4;

    config->resume_mode = QUAC_TLS_RESUME_SESSION_TICKET;
    config->session_timeout = 300;

    config->use_hardware = 1;
    config->hardware_slot = 0;

    config->early_data = 0; /* 0-RTT disabled by default */
    config->session_cache_size = 20000;
    config->max_fragment_length = 16384;

    config->alpn_protocols = "h2,http/1.1";
    config->sni_enabled = 1;
    config->ocsp_stapling = 1;
    config->ct_enabled = 0;
}

/* ==========================================================================
 * Context Management
 * ========================================================================== */

QUAC_TLS_API quac_tls_ctx_t *quac_tls_ctx_new(int is_server)
{
    quac_tls_config_t config;
    quac_tls_config_default(&config);
    return quac_tls_ctx_new_config(is_server, &config);
}

QUAC_TLS_API quac_tls_ctx_t *quac_tls_ctx_new_config(int is_server,
                                                     const quac_tls_config_t *config)
{
    quac_tls_ctx_t *ctx;
    SSL_CTX *ssl_ctx;
    const SSL_METHOD *method;

    if (!g_initialized)
    {
        return NULL;
    }

    ctx = calloc(1, sizeof(quac_tls_ctx_t));
    if (!ctx)
    {
        return NULL;
    }

    /* Create OpenSSL context */
    if (is_server)
    {
        method = TLS_server_method();
    }
    else
    {
        method = TLS_client_method();
    }

    ssl_ctx = SSL_CTX_new(method);
    if (!ssl_ctx)
    {
        free(ctx);
        return NULL;
    }

    ctx->ssl_ctx = ssl_ctx;
    ctx->is_server = is_server;
    memcpy(&ctx->config, config, sizeof(quac_tls_config_t));

    /* Configure protocol versions */
    if (config->min_version == QUAC_TLS_VERSION_1_3)
    {
        SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
    }
    else
    {
        SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);
    }
    SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);

    /* Configure cipher suites */
    quac_tls_configure_ciphers(ctx, config);

    /* Configure key exchange groups (including PQC) */
    quac_tls_configure_groups(ctx, config);

    /* Configure signature algorithms */
    quac_tls_configure_sigalgs(ctx, config);

    /* Configure verification */
    if (config->verify_mode != QUAC_TLS_VERIFY_NONE)
    {
        int mode = SSL_VERIFY_PEER;
        if (config->verify_mode & QUAC_TLS_VERIFY_FAIL_IF_NO_PEER)
        {
            mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
        }
        if (config->verify_mode & QUAC_TLS_VERIFY_CLIENT_ONCE)
        {
            mode |= SSL_VERIFY_CLIENT_ONCE;
        }
        SSL_CTX_set_verify(ssl_ctx, mode, NULL);
        SSL_CTX_set_verify_depth(ssl_ctx, config->verify_depth);
    }

    /* Configure session resumption */
    if (config->resume_mode == QUAC_TLS_RESUME_SESSION_TICKET)
    {
        SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_BOTH);
        SSL_CTX_sess_set_cache_size(ssl_ctx, config->session_cache_size);
        SSL_CTX_set_timeout(ssl_ctx, config->session_timeout);
    }
    else if (config->resume_mode == QUAC_TLS_RESUME_NONE)
    {
        SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_OFF);
    }

    /* Configure ALPN */
    if (config->alpn_protocols && strlen(config->alpn_protocols) > 0)
    {
        quac_tls_configure_alpn(ctx, config->alpn_protocols);
    }

    /* Initialize statistics */
    memset(&ctx->stats, 0, sizeof(quac_tls_stats_t));
    pthread_mutex_init(&ctx->stats_lock, NULL);

    return ctx;
}

QUAC_TLS_API void quac_tls_ctx_free(quac_tls_ctx_t *ctx)
{
    if (!ctx)
        return;

    if (ctx->ssl_ctx)
    {
        SSL_CTX_free(ctx->ssl_ctx);
    }

    pthread_mutex_destroy(&ctx->stats_lock);
    free(ctx);
}

/* ==========================================================================
 * Certificate Management
 * ========================================================================== */

QUAC_TLS_API int quac_tls_ctx_use_certificate_file(quac_tls_ctx_t *ctx,
                                                   const char *cert_file)
{
    if (!ctx || !cert_file)
    {
        return QUAC_TLS_ERROR_INVALID_PARAM;
    }

    if (SSL_CTX_use_certificate_file(ctx->ssl_ctx, cert_file, SSL_FILETYPE_PEM) != 1)
    {
        /* Try DER format */
        if (SSL_CTX_use_certificate_file(ctx->ssl_ctx, cert_file, SSL_FILETYPE_ASN1) != 1)
        {
            return QUAC_TLS_ERROR_CERTIFICATE;
        }
    }

    return QUAC_TLS_OK;
}

QUAC_TLS_API int quac_tls_ctx_use_certificate(quac_tls_ctx_t *ctx,
                                              const uint8_t *cert_data,
                                              size_t cert_len, int format)
{
    BIO *bio;
    X509 *cert;
    int ret;

    if (!ctx || !cert_data || cert_len == 0)
    {
        return QUAC_TLS_ERROR_INVALID_PARAM;
    }

    bio = BIO_new_mem_buf(cert_data, (int)cert_len);
    if (!bio)
    {
        return QUAC_TLS_ERROR_MEMORY;
    }

    if (format == 0)
    { /* PEM */
        cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    }
    else
    { /* DER */
        cert = d2i_X509_bio(bio, NULL);
    }

    BIO_free(bio);

    if (!cert)
    {
        return QUAC_TLS_ERROR_CERTIFICATE;
    }

    ret = SSL_CTX_use_certificate(ctx->ssl_ctx, cert);
    X509_free(cert);

    return (ret == 1) ? QUAC_TLS_OK : QUAC_TLS_ERROR_CERTIFICATE;
}

QUAC_TLS_API int quac_tls_ctx_use_certificate_chain_file(quac_tls_ctx_t *ctx,
                                                         const char *chain_file)
{
    if (!ctx || !chain_file)
    {
        return QUAC_TLS_ERROR_INVALID_PARAM;
    }

    if (SSL_CTX_use_certificate_chain_file(ctx->ssl_ctx, chain_file) != 1)
    {
        return QUAC_TLS_ERROR_CERTIFICATE;
    }

    return QUAC_TLS_OK;
}

QUAC_TLS_API int quac_tls_ctx_use_private_key_file(quac_tls_ctx_t *ctx,
                                                   const char *key_file)
{
    if (!ctx || !key_file)
    {
        return QUAC_TLS_ERROR_INVALID_PARAM;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx->ssl_ctx, key_file, SSL_FILETYPE_PEM) != 1)
    {
        /* Try DER format */
        if (SSL_CTX_use_PrivateKey_file(ctx->ssl_ctx, key_file, SSL_FILETYPE_ASN1) != 1)
        {
            return QUAC_TLS_ERROR_KEY;
        }
    }

    return QUAC_TLS_OK;
}

QUAC_TLS_API int quac_tls_ctx_use_private_key(quac_tls_ctx_t *ctx,
                                              const uint8_t *key_data,
                                              size_t key_len, int format)
{
    BIO *bio;
    EVP_PKEY *pkey;
    int ret;

    if (!ctx || !key_data || key_len == 0)
    {
        return QUAC_TLS_ERROR_INVALID_PARAM;
    }

    bio = BIO_new_mem_buf(key_data, (int)key_len);
    if (!bio)
    {
        return QUAC_TLS_ERROR_MEMORY;
    }

    if (format == 0)
    { /* PEM */
        pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    }
    else
    { /* DER */
        pkey = d2i_PrivateKey_bio(bio, NULL);
    }

    BIO_free(bio);

    if (!pkey)
    {
        return QUAC_TLS_ERROR_KEY;
    }

    ret = SSL_CTX_use_PrivateKey(ctx->ssl_ctx, pkey);
    EVP_PKEY_free(pkey);

    return (ret == 1) ? QUAC_TLS_OK : QUAC_TLS_ERROR_KEY;
}

QUAC_TLS_API int quac_tls_ctx_use_mldsa(quac_tls_ctx_t *ctx,
                                        const char *cert_file,
                                        const char *key_file,
                                        int level)
{
    int ret;

    if (!ctx || !cert_file || !key_file)
    {
        return QUAC_TLS_ERROR_INVALID_PARAM;
    }

    if (level != 44 && level != 65 && level != 87)
    {
        return QUAC_TLS_ERROR_INVALID_PARAM;
    }

    /* Load ML-DSA certificate */
    ret = quac_tls_ctx_use_certificate_file(ctx, cert_file);
    if (ret != QUAC_TLS_OK)
    {
        return ret;
    }

    /* Load ML-DSA private key */
    ret = quac_tls_ctx_use_private_key_file(ctx, key_file);
    if (ret != QUAC_TLS_OK)
    {
        return ret;
    }

    /* Verify key matches certificate */
    ret = quac_tls_ctx_check_private_key(ctx);
    if (ret != QUAC_TLS_OK)
    {
        return ret;
    }

    ctx->mldsa_level = level;

    return QUAC_TLS_OK;
}

QUAC_TLS_API int quac_tls_ctx_check_private_key(quac_tls_ctx_t *ctx)
{
    if (!ctx)
    {
        return QUAC_TLS_ERROR_INVALID_PARAM;
    }

    if (SSL_CTX_check_private_key(ctx->ssl_ctx) != 1)
    {
        return QUAC_TLS_ERROR_KEY;
    }

    return QUAC_TLS_OK;
}

QUAC_TLS_API int quac_tls_ctx_load_verify_locations(quac_tls_ctx_t *ctx,
                                                    const char *ca_file,
                                                    const char *ca_path)
{
    if (!ctx)
    {
        return QUAC_TLS_ERROR_INVALID_PARAM;
    }

    if (!ca_file && !ca_path)
    {
        /* Use system defaults */
        if (SSL_CTX_set_default_verify_paths(ctx->ssl_ctx) != 1)
        {
            return QUAC_TLS_ERROR_CERTIFICATE;
        }
    }
    else
    {
        if (SSL_CTX_load_verify_locations(ctx->ssl_ctx, ca_file, ca_path) != 1)
        {
            return QUAC_TLS_ERROR_CERTIFICATE;
        }
    }

    return QUAC_TLS_OK;
}

/* ==========================================================================
 * Connection Management
 * ========================================================================== */

QUAC_TLS_API quac_tls_conn_t *quac_tls_conn_new(quac_tls_ctx_t *ctx)
{
    quac_tls_conn_t *conn;
    SSL *ssl;

    if (!ctx)
    {
        return NULL;
    }

    conn = calloc(1, sizeof(quac_tls_conn_t));
    if (!conn)
    {
        return NULL;
    }

    ssl = SSL_new(ctx->ssl_ctx);
    if (!ssl)
    {
        free(conn);
        return NULL;
    }

    conn->ssl = ssl;
    conn->ctx = ctx;
    conn->fd = -1;

    /* Store connection in SSL for callbacks */
    SSL_set_app_data(ssl, conn);

    return conn;
}

QUAC_TLS_API void quac_tls_conn_free(quac_tls_conn_t *conn)
{
    if (!conn)
        return;

    if (conn->ssl)
    {
        SSL_free(conn->ssl);
    }

    if (conn->peer_cert)
    {
        X509_free(conn->peer_cert);
    }

    free(conn->server_name);
    free(conn);
}

QUAC_TLS_API int quac_tls_conn_set_fd(quac_tls_conn_t *conn, int fd)
{
    if (!conn || fd < 0)
    {
        return QUAC_TLS_ERROR_INVALID_PARAM;
    }

    if (SSL_set_fd(conn->ssl, fd) != 1)
    {
        return QUAC_TLS_ERROR_SSL;
    }

    conn->fd = fd;
    return QUAC_TLS_OK;
}

QUAC_TLS_API int quac_tls_conn_set_server_name(quac_tls_conn_t *conn,
                                               const char *server_name)
{
    if (!conn || !server_name)
    {
        return QUAC_TLS_ERROR_INVALID_PARAM;
    }

    free(conn->server_name);
    conn->server_name = strdup(server_name);

    if (SSL_set_tlsext_host_name(conn->ssl, server_name) != 1)
    {
        return QUAC_TLS_ERROR_SSL;
    }

    return QUAC_TLS_OK;
}

static int translate_ssl_error(SSL *ssl, int ret)
{
    int err = SSL_get_error(ssl, ret);

    switch (err)
    {
    case SSL_ERROR_NONE:
        return QUAC_TLS_OK;
    case SSL_ERROR_WANT_READ:
        return QUAC_TLS_ERROR_WANT_READ;
    case SSL_ERROR_WANT_WRITE:
        return QUAC_TLS_ERROR_WANT_WRITE;
    case SSL_ERROR_ZERO_RETURN:
        return QUAC_TLS_ERROR_CLOSED;
    case SSL_ERROR_SYSCALL:
        return QUAC_TLS_ERROR_SYSCALL;
    case SSL_ERROR_SSL:
        return QUAC_TLS_ERROR_SSL;
    default:
        return QUAC_TLS_ERROR;
    }
}

QUAC_TLS_API int quac_tls_handshake(quac_tls_conn_t *conn)
{
    int ret;
    struct timespec start, end;

    if (!conn)
    {
        return QUAC_TLS_ERROR_INVALID_PARAM;
    }

    clock_gettime(CLOCK_MONOTONIC, &start);

    ret = SSL_do_handshake(conn->ssl);

    if (ret == 1)
    {
        clock_gettime(CLOCK_MONOTONIC, &end);

        /* Update statistics */
        double elapsed = (end.tv_sec - start.tv_sec) * 1000.0 +
                         (end.tv_nsec - start.tv_nsec) / 1000000.0;

        pthread_mutex_lock(&conn->ctx->stats_lock);
        conn->ctx->stats.handshakes_total++;
        if (SSL_session_reused(conn->ssl))
        {
            conn->ctx->stats.handshakes_resumed++;
        }

        /* Update timing stats */
        if (conn->ctx->stats.handshake_time_min_ms == 0 ||
            elapsed < conn->ctx->stats.handshake_time_min_ms)
        {
            conn->ctx->stats.handshake_time_min_ms = elapsed;
        }
        if (elapsed > conn->ctx->stats.handshake_time_max_ms)
        {
            conn->ctx->stats.handshake_time_max_ms = elapsed;
        }

        /* Running average */
        uint64_t n = conn->ctx->stats.handshakes_total;
        conn->ctx->stats.handshake_time_avg_ms =
            (conn->ctx->stats.handshake_time_avg_ms * (n - 1) + elapsed) / n;

        pthread_mutex_unlock(&conn->ctx->stats_lock);

        conn->handshake_complete = 1;
        return QUAC_TLS_OK;
    }

    int error = translate_ssl_error(conn->ssl, ret);

    if (error == QUAC_TLS_ERROR_SSL || error == QUAC_TLS_ERROR_SYSCALL)
    {
        pthread_mutex_lock(&conn->ctx->stats_lock);
        conn->ctx->stats.handshakes_failed++;
        pthread_mutex_unlock(&conn->ctx->stats_lock);
    }

    return error;
}

QUAC_TLS_API int quac_tls_accept(quac_tls_conn_t *conn)
{
    if (!conn)
    {
        return QUAC_TLS_ERROR_INVALID_PARAM;
    }

    SSL_set_accept_state(conn->ssl);
    return quac_tls_handshake(conn);
}

QUAC_TLS_API int quac_tls_connect(quac_tls_conn_t *conn)
{
    if (!conn)
    {
        return QUAC_TLS_ERROR_INVALID_PARAM;
    }

    SSL_set_connect_state(conn->ssl);
    return quac_tls_handshake(conn);
}

QUAC_TLS_API int quac_tls_shutdown(quac_tls_conn_t *conn)
{
    int ret;

    if (!conn)
    {
        return QUAC_TLS_ERROR_INVALID_PARAM;
    }

    ret = SSL_shutdown(conn->ssl);

    if (ret == 0)
    {
        /* Need to call again for bidirectional shutdown */
        ret = SSL_shutdown(conn->ssl);
    }

    if (ret < 0)
    {
        return translate_ssl_error(conn->ssl, ret);
    }

    return QUAC_TLS_OK;
}

/* ==========================================================================
 * Data Transfer
 * ========================================================================== */

QUAC_TLS_API int quac_tls_read(quac_tls_conn_t *conn, void *buf, size_t len)
{
    int ret;

    if (!conn || !buf || len == 0)
    {
        return QUAC_TLS_ERROR_INVALID_PARAM;
    }

    ret = SSL_read(conn->ssl, buf, (int)len);

    if (ret > 0)
    {
        pthread_mutex_lock(&conn->ctx->stats_lock);
        conn->ctx->stats.bytes_received += ret;
        conn->ctx->stats.records_received++;
        pthread_mutex_unlock(&conn->ctx->stats_lock);
        return ret;
    }

    return translate_ssl_error(conn->ssl, ret);
}

QUAC_TLS_API int quac_tls_write(quac_tls_conn_t *conn, const void *buf, size_t len)
{
    int ret;

    if (!conn || !buf || len == 0)
    {
        return QUAC_TLS_ERROR_INVALID_PARAM;
    }

    ret = SSL_write(conn->ssl, buf, (int)len);

    if (ret > 0)
    {
        pthread_mutex_lock(&conn->ctx->stats_lock);
        conn->ctx->stats.bytes_sent += ret;
        conn->ctx->stats.records_sent++;
        pthread_mutex_unlock(&conn->ctx->stats_lock);
        return ret;
    }

    return translate_ssl_error(conn->ssl, ret);
}

QUAC_TLS_API int quac_tls_pending(quac_tls_conn_t *conn)
{
    if (!conn)
    {
        return 0;
    }

    return SSL_pending(conn->ssl);
}

/* ==========================================================================
 * Connection Information
 * ========================================================================== */

QUAC_TLS_API const char *quac_tls_get_cipher(quac_tls_conn_t *conn)
{
    if (!conn)
    {
        return NULL;
    }

    return SSL_get_cipher_name(conn->ssl);
}

QUAC_TLS_API const char *quac_tls_get_version(quac_tls_conn_t *conn)
{
    if (!conn)
    {
        return NULL;
    }

    return SSL_get_version(conn->ssl);
}

QUAC_TLS_API const char *quac_tls_get_kex(quac_tls_conn_t *conn)
{
    if (!conn)
    {
        return NULL;
    }

    /* Get the key exchange algorithm name */
    const char *kex = SSL_get_cipher_kx(conn->ssl);
    if (kex)
    {
        return kex;
    }

    /* For TLS 1.3, check the group used */
    int nid = SSL_get_negotiated_group(conn->ssl);
    if (nid > 0)
    {
        return OBJ_nid2sn(nid);
    }

    return "Unknown";
}

QUAC_TLS_API quac_tls_cert_t *quac_tls_get_peer_certificate(quac_tls_conn_t *conn)
{
    X509 *cert;
    quac_tls_cert_t *result;

    if (!conn)
    {
        return NULL;
    }

    cert = SSL_get_peer_certificate(conn->ssl);
    if (!cert)
    {
        return NULL;
    }

    result = calloc(1, sizeof(quac_tls_cert_t));
    if (!result)
    {
        X509_free(cert);
        return NULL;
    }

    result->x509 = cert;
    return result;
}

QUAC_TLS_API int quac_tls_get_verify_result(quac_tls_conn_t *conn)
{
    if (!conn)
    {
        return -1;
    }

    return (int)SSL_get_verify_result(conn->ssl);
}

QUAC_TLS_API const char *quac_tls_get_alpn(quac_tls_conn_t *conn)
{
    const unsigned char *data;
    unsigned int len;

    if (!conn)
    {
        return NULL;
    }

    SSL_get0_alpn_selected(conn->ssl, &data, &len);

    if (data && len > 0)
    {
        /* Store in connection for lifetime management */
        free(conn->alpn_selected);
        conn->alpn_selected = malloc(len + 1);
        if (conn->alpn_selected)
        {
            memcpy(conn->alpn_selected, data, len);
            conn->alpn_selected[len] = '\0';
            return conn->alpn_selected;
        }
    }

    return NULL;
}

QUAC_TLS_API int quac_tls_session_reused(quac_tls_conn_t *conn)
{
    if (!conn)
    {
        return 0;
    }

    return SSL_session_reused(conn->ssl);
}

/* ==========================================================================
 * Statistics
 * ========================================================================== */

QUAC_TLS_API void quac_tls_get_stats(quac_tls_conn_t *conn,
                                     quac_tls_stats_t *stats)
{
    if (!conn || !stats)
    {
        return;
    }

    quac_tls_ctx_get_stats(conn->ctx, stats);
}

QUAC_TLS_API void quac_tls_ctx_get_stats(quac_tls_ctx_t *ctx,
                                         quac_tls_stats_t *stats)
{
    if (!ctx || !stats)
    {
        return;
    }

    pthread_mutex_lock(&ctx->stats_lock);
    memcpy(stats, &ctx->stats, sizeof(quac_tls_stats_t));
    pthread_mutex_unlock(&ctx->stats_lock);
}

QUAC_TLS_API void quac_tls_ctx_reset_stats(quac_tls_ctx_t *ctx)
{
    if (!ctx)
    {
        return;
    }

    pthread_mutex_lock(&ctx->stats_lock);
    memset(&ctx->stats, 0, sizeof(quac_tls_stats_t));
    pthread_mutex_unlock(&ctx->stats_lock);
}

/* ==========================================================================
 * Certificate Utilities
 * ========================================================================== */

QUAC_TLS_API int quac_tls_cert_get_subject(quac_tls_cert_t *cert,
                                           char *buf, size_t len)
{
    if (!cert || !cert->x509)
    {
        return -1;
    }

    X509_NAME *name = X509_get_subject_name(cert->x509);
    if (!name)
    {
        return -1;
    }

    if (!buf)
    {
        return X509_NAME_get_text_by_NID(name, NID_commonName, NULL, 0) + 1;
    }

    char *result = X509_NAME_oneline(name, buf, (int)len);
    if (!result)
    {
        return -1;
    }

    return (int)strlen(buf);
}

QUAC_TLS_API int quac_tls_cert_get_issuer(quac_tls_cert_t *cert,
                                          char *buf, size_t len)
{
    if (!cert || !cert->x509)
    {
        return -1;
    }

    X509_NAME *name = X509_get_issuer_name(cert->x509);
    if (!name)
    {
        return -1;
    }

    if (!buf)
    {
        return X509_NAME_get_text_by_NID(name, NID_commonName, NULL, 0) + 1;
    }

    char *result = X509_NAME_oneline(name, buf, (int)len);
    if (!result)
    {
        return -1;
    }

    return (int)strlen(buf);
}

QUAC_TLS_API void quac_tls_cert_free(quac_tls_cert_t *cert)
{
    if (!cert)
        return;

    if (cert->x509)
    {
        X509_free(cert->x509);
    }

    free(cert);
}