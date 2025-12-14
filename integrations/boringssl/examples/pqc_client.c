/**
 * @file D:\quantacore-sdk\integrations\boringssl\examples\pqc_client.c
 * @brief QUAC 100 BoringSSL - PQC TLS Client Example
 *
 * Demonstrates post-quantum TLS client using QUAC 100 hardware acceleration.
 * Supports ML-KEM key exchange and ML-DSA certificate verification.
 *
 * Usage:
 *   ./pqc_client -h <host> -p <port> [-k]
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include "quac100_boringssl.h"

/* ==========================================================================
 * Configuration
 * ========================================================================== */

static const char *g_host = "localhost";
static int g_port = 8443;
static const char *g_path = "/";
static int g_insecure = 0;
static int g_verbose = 0;
static const char *g_ca_file = NULL;

/* ==========================================================================
 * Utilities
 * ========================================================================== */

static void print_error(const char *msg)
{
    fprintf(stderr, "ERROR: %s\n", msg);
    ERR_print_errors_fp(stderr);
}

static int connect_tcp(const char *host, int port)
{
    struct hostent *he = gethostbyname(host);
    if (!he)
    {
        fprintf(stderr, "Cannot resolve hostname: %s\n", host);
        return -1;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        perror("socket");
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("connect");
        close(fd);
        return -1;
    }

    return fd;
}

static void print_certificate_info(X509 *cert)
{
    if (!cert)
        return;

    char subject[256], issuer[256];
    X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject));
    X509_NAME_oneline(X509_get_issuer_name(cert), issuer, sizeof(issuer));

    printf("  Subject: %s\n", subject);
    printf("  Issuer:  %s\n", issuer);

    /* Check if PQC certificate */
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    if (pkey)
    {
        int type = EVP_PKEY_id(pkey);
        printf("  Key Type: ");
        if (quac100_is_pqc_nid(type))
        {
            printf("Post-Quantum (%s)\n", OBJ_nid2sn(type));
        }
        else
        {
            printf("%s\n", OBJ_nid2sn(type));
        }
        EVP_PKEY_free(pkey);
    }
}

static void print_connection_info(SSL *ssl)
{
    printf("\nConnection Information:\n");
    printf("  TLS Version:  %s\n", SSL_get_version(ssl));
    printf("  Cipher:       %s\n", SSL_get_cipher_name(ssl));

    /* Get key exchange info */
    const char *kex = quac100_ssl_get_kex_name(ssl);
    if (kex)
    {
        printf("  Key Exchange: %s\n", kex);
    }

    /* Check session resumption */
    if (SSL_session_reused(ssl))
    {
        printf("  Session:      Resumed\n");
    }
    else
    {
        printf("  Session:      New\n");
    }

    /* ALPN */
    const unsigned char *alpn;
    unsigned int alpn_len;
    SSL_get0_alpn_selected(ssl, &alpn, &alpn_len);
    if (alpn && alpn_len > 0)
    {
        printf("  ALPN:         %.*s\n", alpn_len, alpn);
    }

    /* Server certificate */
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert)
    {
        printf("\nServer Certificate:\n");
        print_certificate_info(cert);
        X509_free(cert);
    }
}

/* ==========================================================================
 * Main
 * ========================================================================== */

static void usage(const char *prog)
{
    printf("QUAC 100 PQC TLS Client Example\n\n");
    printf("Usage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -h, --host <host>    Server hostname (default: localhost)\n");
    printf("  -p, --port <port>    Server port (default: 8443)\n");
    printf("  -u, --path <path>    Request path (default: /)\n");
    printf("  -c, --ca <file>      CA certificate file\n");
    printf("  -k, --insecure       Skip certificate verification\n");
    printf("  -v, --verbose        Verbose output\n");
    printf("  --help               Show this help\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -h example.com -p 443\n", prog);
    printf("  %s -h localhost -p 8443 -k\n", prog);
}

int main(int argc, char *argv[])
{
    int opt;
    static struct option long_opts[] = {
        {"host", required_argument, 0, 'h'},
        {"port", required_argument, 0, 'p'},
        {"path", required_argument, 0, 'u'},
        {"ca", required_argument, 0, 'c'},
        {"insecure", no_argument, 0, 'k'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'H'},
        {0, 0, 0, 0}};

    while ((opt = getopt_long(argc, argv, "h:p:u:c:kvH", long_opts, NULL)) != -1)
    {
        switch (opt)
        {
        case 'h':
            g_host = optarg;
            break;
        case 'p':
            g_port = atoi(optarg);
            break;
        case 'u':
            g_path = optarg;
            break;
        case 'c':
            g_ca_file = optarg;
            break;
        case 'k':
            g_insecure = 1;
            break;
        case 'v':
            g_verbose = 1;
            break;
        case 'H':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    printf("QUAC 100 PQC TLS Client v%s\n", quac100_version_string());
    printf("Connecting to %s:%d%s\n\n", g_host, g_port, g_path);

    /* Initialize QUAC 100 */
    if (quac100_init() != QUAC100_OK)
    {
        print_error("Failed to initialize QUAC 100");
        return 1;
    }

    if (quac100_hw_available())
    {
        printf("Hardware acceleration: ENABLED\n");
    }
    else
    {
        printf("Hardware acceleration: DISABLED (software fallback)\n");
    }

    /* Create SSL context */
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
    {
        print_error("Failed to create SSL context");
        quac100_cleanup();
        return 1;
    }

    /* Configure TLS 1.3 */
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    /* Enable PQC key exchange */
    if (quac100_ssl_ctx_enable_pqc(ctx) != QUAC100_OK)
    {
        print_error("Failed to enable PQC");
        SSL_CTX_free(ctx);
        quac100_cleanup();
        return 1;
    }

    /* Set preferred groups (hybrid first, then pure PQC, then classical) */
    if (SSL_CTX_set1_groups_list(ctx,
                                 "X25519_MLKEM768:P256_MLKEM768:MLKEM768:X25519:P-256") != 1)
    {
        fprintf(stderr, "Warning: Could not set preferred groups\n");
    }

    /* Certificate verification */
    if (g_insecure)
    {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }
    else
    {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        if (g_ca_file)
        {
            if (SSL_CTX_load_verify_locations(ctx, g_ca_file, NULL) != 1)
            {
                print_error("Failed to load CA file");
            }
        }
        else
        {
            SSL_CTX_set_default_verify_paths(ctx);
        }
    }

    /* ALPN */
    unsigned char alpn[] = "\x02h2\x08http/1.1";
    SSL_CTX_set_alpn_protos(ctx, alpn, sizeof(alpn) - 1);

    /* Connect TCP */
    printf("Connecting to %s:%d...\n", g_host, g_port);
    int fd = connect_tcp(g_host, g_port);
    if (fd < 0)
    {
        SSL_CTX_free(ctx);
        quac100_cleanup();
        return 1;
    }
    printf("TCP connected.\n");

    /* Create SSL connection */
    SSL *ssl = SSL_new(ctx);
    if (!ssl)
    {
        print_error("Failed to create SSL object");
        close(fd);
        SSL_CTX_free(ctx);
        quac100_cleanup();
        return 1;
    }

    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, g_host);

    /* TLS handshake */
    printf("Performing TLS handshake...\n");
    int ret = SSL_connect(ssl);
    if (ret != 1)
    {
        int err = SSL_get_error(ssl, ret);
        fprintf(stderr, "Handshake failed: error %d\n", err);
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(fd);
        SSL_CTX_free(ctx);
        quac100_cleanup();
        return 1;
    }

    print_connection_info(ssl);

    /* Send HTTP request */
    char request[512];
    snprintf(request, sizeof(request),
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Connection: close\r\n"
             "User-Agent: QUAC100-PQC-Client/1.0\r\n"
             "\r\n",
             g_path, g_host);

    printf("\nSending request...\n");
    if (SSL_write(ssl, request, strlen(request)) <= 0)
    {
        print_error("Failed to send request");
    }
    else
    {
        /* Read response */
        char response[8192];
        printf("\nResponse:\n");
        printf("----------------------------------------\n");

        int n;
        while ((n = SSL_read(ssl, response, sizeof(response) - 1)) > 0)
        {
            response[n] = '\0';
            printf("%s", response);
        }

        printf("\n----------------------------------------\n");
    }

    /* Print stats */
    if (g_verbose)
    {
        quac100_stats_t stats;
        quac100_get_stats(&stats);
        printf("\nQUAC 100 Statistics:\n");
        printf("  ML-KEM operations: %llu\n",
               (unsigned long long)(stats.mlkem_encaps_count + stats.mlkem_decaps_count));
        printf("  Hardware ops:      %llu\n", (unsigned long long)stats.hw_operations);
        printf("  SW fallbacks:      %llu\n", (unsigned long long)stats.sw_fallback_count);
    }

    /* Cleanup */
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(fd);
    SSL_CTX_free(ctx);
    quac100_cleanup();

    printf("\nConnection closed.\n");
    return 0;
}