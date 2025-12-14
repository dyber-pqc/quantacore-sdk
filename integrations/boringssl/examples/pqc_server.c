/**
 * @file D:\quantacore-sdk\integrations\boringssl\examples\pqc_server.c
 * @brief QUAC 100 BoringSSL - PQC TLS Server Example
 *
 * Demonstrates post-quantum TLS server using QUAC 100 hardware acceleration.
 * Supports ML-KEM key exchange and ML-DSA certificates.
 *
 * Usage:
 *   ./pqc_server -p <port> -c <cert> -k <key>
 *   ./pqc_server -p <port> -g  # Generate self-signed cert
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "quac100_boringssl.h"

/* ==========================================================================
 * Configuration
 * ========================================================================== */

static int g_port = 8443;
static const char *g_cert_file = NULL;
static const char *g_key_file = NULL;
static int g_generate = 0;
static int g_mldsa_level = 65;
static int g_verbose = 0;
static volatile int g_running = 1;

/* ==========================================================================
 * HTML Response
 * ========================================================================== */

static const char *html_template =
    "<!DOCTYPE html>\n"
    "<html>\n"
    "<head><title>QUAC 100 PQC Server</title></head>\n"
    "<body>\n"
    "<h1>Post-Quantum TLS Connection</h1>\n"
    "<table border=\"1\">\n"
    "<tr><td>TLS Version</td><td>%s</td></tr>\n"
    "<tr><td>Cipher Suite</td><td>%s</td></tr>\n"
    "<tr><td>Key Exchange</td><td>%s</td></tr>\n"
    "<tr><td>Certificate</td><td>%s</td></tr>\n"
    "<tr><td>Hardware Accel</td><td>%s</td></tr>\n"
    "</table>\n"
    "<p>Powered by QUAC 100 Quantum-Resistant Accelerator</p>\n"
    "</body>\n"
    "</html>\n";

static const char *http_response =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html\r\n"
    "X-PQC-KEX: %s\r\n"
    "X-PQC-Cipher: %s\r\n"
    "Connection: close\r\n"
    "Content-Length: %zu\r\n"
    "\r\n"
    "%s";

/* ==========================================================================
 * Utilities
 * ========================================================================== */

static void signal_handler(int sig)
{
    (void)sig;
    g_running = 0;
}

static void print_error(const char *msg)
{
    fprintf(stderr, "ERROR: %s\n", msg);
    ERR_print_errors_fp(stderr);
}

static int create_listen_socket(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        perror("socket");
        return -1;
    }

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind");
        close(fd);
        return -1;
    }

    if (listen(fd, 10) < 0)
    {
        perror("listen");
        close(fd);
        return -1;
    }

    return fd;
}

static void handle_client(SSL_CTX *ctx, int client_fd, struct sockaddr_in *addr)
{
    SSL *ssl = SSL_new(ctx);
    if (!ssl)
    {
        print_error("Failed to create SSL object");
        close(client_fd);
        return;
    }

    SSL_set_fd(ssl, client_fd);

    /* TLS handshake */
    int ret = SSL_accept(ssl);
    if (ret != 1)
    {
        int err = SSL_get_error(ssl, ret);
        if (g_verbose)
        {
            fprintf(stderr, "Handshake failed from %s: error %d\n",
                    inet_ntoa(addr->sin_addr), err);
        }
        SSL_free(ssl);
        close(client_fd);
        return;
    }

    /* Get connection info */
    const char *version = SSL_get_version(ssl);
    const char *cipher = SSL_get_cipher_name(ssl);
    const char *kex = quac100_ssl_get_kex_name(ssl);
    if (!kex)
        kex = "Classical";

    printf("  Connected: %s %s KEX=%s\n", version, cipher, kex);

    /* Read request */
    char request[4096];
    ret = SSL_read(ssl, request, sizeof(request) - 1);
    if (ret <= 0)
    {
        SSL_free(ssl);
        close(client_fd);
        return;
    }
    request[ret] = '\0';

    /* Check for HTTP GET */
    if (strstr(request, "GET "))
    {
        /* Build HTML response */
        char html[2048];
        snprintf(html, sizeof(html), html_template,
                 version,
                 cipher,
                 kex,
                 g_generate ? "ML-DSA (self-signed)" : "From file",
                 quac100_hw_available() ? "ENABLED" : "DISABLED");

        /* Build HTTP response */
        char response[4096];
        snprintf(response, sizeof(response), http_response,
                 kex, cipher, strlen(html), html);

        SSL_write(ssl, response, strlen(response));
    }

    /* Shutdown */
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_fd);
}

/* ==========================================================================
 * Certificate Generation
 * ========================================================================== */

static int generate_mldsa_cert(SSL_CTX *ctx, int level)
{
    printf("Generating ML-DSA-%d certificate...\n", level);

    /* Generate key pair */
    EVP_PKEY *pkey = NULL;
    if (quac100_mldsa_keygen(&pkey, level) != QUAC100_OK)
    {
        fprintf(stderr, "Failed to generate ML-DSA key\n");
        return -1;
    }

    /* Create self-signed certificate */
    X509 *cert = X509_new();
    if (!cert)
    {
        EVP_PKEY_free(pkey);
        return -1;
    }

    /* Set version (X509v3) */
    X509_set_version(cert, 2);

    /* Set serial number */
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);

    /* Set validity */
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 365 * 24 * 60 * 60);

    /* Set subject and issuer */
    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char *)"QUAC100 PQC Server", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                               (const unsigned char *)"Dyber Inc", -1, -1, 0);
    X509_set_issuer_name(cert, name);

    /* Set public key */
    X509_set_pubkey(cert, pkey);

    /* Sign certificate */
    if (quac100_x509_sign(cert, pkey, level) != QUAC100_OK)
    {
        fprintf(stderr, "Failed to sign certificate\n");
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return -1;
    }

    /* Apply to SSL context */
    if (SSL_CTX_use_certificate(ctx, cert) != 1)
    {
        print_error("Failed to use certificate");
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return -1;
    }

    if (SSL_CTX_use_PrivateKey(ctx, pkey) != 1)
    {
        print_error("Failed to use private key");
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return -1;
    }

    printf("Certificate generated successfully.\n");

    X509_free(cert);
    EVP_PKEY_free(pkey);
    return 0;
}

/* ==========================================================================
 * Main
 * ========================================================================== */

static void usage(const char *prog)
{
    printf("QUAC 100 PQC TLS Server Example\n\n");
    printf("Usage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -p, --port <port>    Listen port (default: 8443)\n");
    printf("  -c, --cert <file>    Certificate file\n");
    printf("  -k, --key <file>     Private key file\n");
    printf("  -g, --generate       Generate self-signed ML-DSA cert\n");
    printf("  -l, --level <lvl>    ML-DSA level: 44, 65, 87 (default: 65)\n");
    printf("  -v, --verbose        Verbose output\n");
    printf("  -h, --help           Show this help\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -g -p 8443                    # Auto-generate cert\n", prog);
    printf("  %s -c cert.pem -k key.pem        # Use existing cert\n", prog);
}

int main(int argc, char *argv[])
{
    int opt;
    static struct option long_opts[] = {
        {"port", required_argument, 0, 'p'},
        {"cert", required_argument, 0, 'c'},
        {"key", required_argument, 0, 'k'},
        {"generate", no_argument, 0, 'g'},
        {"level", required_argument, 0, 'l'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}};

    while ((opt = getopt_long(argc, argv, "p:c:k:gl:vh", long_opts, NULL)) != -1)
    {
        switch (opt)
        {
        case 'p':
            g_port = atoi(optarg);
            break;
        case 'c':
            g_cert_file = optarg;
            break;
        case 'k':
            g_key_file = optarg;
            break;
        case 'g':
            g_generate = 1;
            break;
        case 'l':
            g_mldsa_level = atoi(optarg);
            break;
        case 'v':
            g_verbose = 1;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (!g_generate && (!g_cert_file || !g_key_file))
    {
        fprintf(stderr, "Error: Specify -g or provide -c and -k\n\n");
        usage(argv[0]);
        return 1;
    }

    printf("QUAC 100 PQC TLS Server v%s\n", quac100_version_string());

    /* Initialize QUAC 100 */
    if (quac100_init() != QUAC100_OK)
    {
        print_error("Failed to initialize QUAC 100");
        return 1;
    }

    printf("Hardware acceleration: %s\n",
           quac100_hw_available() ? "ENABLED" : "DISABLED");

    /* Create SSL context */
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx)
    {
        print_error("Failed to create SSL context");
        quac100_cleanup();
        return 1;
    }

    /* Configure TLS 1.3 */
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);

    /* Enable PQC */
    if (quac100_ssl_ctx_enable_pqc(ctx) != QUAC100_OK)
    {
        print_error("Failed to enable PQC");
        SSL_CTX_free(ctx);
        quac100_cleanup();
        return 1;
    }

    /* Set preferred groups */
    SSL_CTX_set1_groups_list(ctx,
                             "X25519_MLKEM768:P256_MLKEM768:MLKEM768:X25519:P-256");

    /* Load or generate certificate */
    if (g_generate)
    {
        if (generate_mldsa_cert(ctx, g_mldsa_level) != 0)
        {
            SSL_CTX_free(ctx);
            quac100_cleanup();
            return 1;
        }
    }
    else
    {
        if (SSL_CTX_use_certificate_file(ctx, g_cert_file, SSL_FILETYPE_PEM) != 1)
        {
            print_error("Failed to load certificate");
            SSL_CTX_free(ctx);
            quac100_cleanup();
            return 1;
        }
        if (SSL_CTX_use_PrivateKey_file(ctx, g_key_file, SSL_FILETYPE_PEM) != 1)
        {
            print_error("Failed to load private key");
            SSL_CTX_free(ctx);
            quac100_cleanup();
            return 1;
        }
    }

    /* Check key/cert match */
    if (SSL_CTX_check_private_key(ctx) != 1)
    {
        print_error("Certificate and key don't match");
        SSL_CTX_free(ctx);
        quac100_cleanup();
        return 1;
    }

    /* Create listen socket */
    int server_fd = create_listen_socket(g_port);
    if (server_fd < 0)
    {
        SSL_CTX_free(ctx);
        quac100_cleanup();
        return 1;
    }

    printf("\nListening on port %d\n", g_port);
    printf("Test: curl -k https://localhost:%d\n", g_port);
    printf("Press Ctrl+C to stop\n\n");

    /* Signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Accept loop */
    while (g_running)
    {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0)
        {
            if (errno == EINTR)
                continue;
            break;
        }

        printf("Connection from %s:%d\n",
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        handle_client(ctx, client_fd, &client_addr);
    }

    /* Print final stats */
    if (g_verbose)
    {
        quac100_stats_t stats;
        quac100_get_stats(&stats);
        printf("\nSession Statistics:\n");
        printf("  Handshakes completed: %llu\n", (unsigned long long)stats.handshakes_completed);
        printf("  Handshakes failed:    %llu\n", (unsigned long long)stats.handshakes_failed);
        printf("  Hardware operations:  %llu\n", (unsigned long long)stats.hw_operations);
    }

    /* Cleanup */
    close(server_fd);
    SSL_CTX_free(ctx);
    quac100_cleanup();

    printf("\nServer stopped.\n");
    return 0;
}