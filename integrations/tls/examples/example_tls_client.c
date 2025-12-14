/**
 * @file example_tls_client.c
 * @brief QUAC 100 TLS - Example Client
 *
 * Simple TLS client demonstrating post-quantum connection.
 *
 * Usage:
 *   ./example_tls_client -h localhost -p 8443
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <getopt.h>

#include "quac_tls.h"

static const char *g_host = "localhost";
static int g_port = 8443;
static const char *g_path = "/";
static int g_insecure = 0;

static int connect_tcp(const char *host, int port)
{
    struct hostent *he = gethostbyname(host);
    if (!he)
    {
        fprintf(stderr, "Cannot resolve: %s\n", host);
        return -1;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        perror("socket");
        return -1;
    }

    struct sockaddr_in addr = {0};
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

static void usage(const char *prog)
{
    printf("QUAC TLS Example Client\n\n");
    printf("Usage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -h <host>   Hostname (default: localhost)\n");
    printf("  -p <port>   Port (default: 8443)\n");
    printf("  -u <path>   URL path (default: /)\n");
    printf("  -k          Skip certificate verification\n");
    printf("  --help      Show help\n");
}

int main(int argc, char *argv[])
{
    int opt;
    static struct option long_opts[] = {
        {"help", no_argument, 0, 'H'},
        {0, 0, 0, 0}};

    while ((opt = getopt_long(argc, argv, "h:p:u:k", long_opts, NULL)) != -1)
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
        case 'k':
            g_insecure = 1;
            break;
        case 'H':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (quac_tls_init() != QUAC_TLS_OK)
    {
        fprintf(stderr, "Failed to init library\n");
        return 1;
    }

    printf("QUAC TLS Client v%s\n", quac_tls_version());
    printf("Connecting to %s:%d%s\n\n", g_host, g_port, g_path);

    /* Configure client */
    quac_tls_config_t config;
    quac_tls_config_default(&config);
    config.kex_algorithms = QUAC_TLS_KEX_X25519_ML_KEM_768 |
                            QUAC_TLS_KEX_ML_KEM_768 |
                            QUAC_TLS_KEX_X25519;
    config.sig_algorithms = QUAC_TLS_SIG_ML_DSA_65 |
                            QUAC_TLS_SIG_ECDSA_P256;

    if (g_insecure)
    {
        config.verify_mode = QUAC_TLS_VERIFY_NONE;
    }

    quac_tls_ctx_t *ctx = quac_tls_ctx_new_config(0, &config);
    if (!ctx)
    {
        fprintf(stderr, "Failed to create context\n");
        quac_tls_cleanup();
        return 1;
    }

    /* Connect TCP */
    int fd = connect_tcp(g_host, g_port);
    if (fd < 0)
    {
        quac_tls_ctx_free(ctx);
        quac_tls_cleanup();
        return 1;
    }

    /* Create TLS connection */
    quac_tls_conn_t *conn = quac_tls_conn_new(ctx);
    if (!conn)
    {
        close(fd);
        quac_tls_ctx_free(ctx);
        quac_tls_cleanup();
        return 1;
    }

    quac_tls_conn_set_fd(conn, fd);
    quac_tls_conn_set_server_name(conn, g_host);

    /* TLS handshake */
    printf("Performing TLS handshake...\n");
    int ret = quac_tls_connect(conn);
    if (ret != QUAC_TLS_OK)
    {
        fprintf(stderr, "Handshake failed: %s\n", quac_tls_error_string(ret));
        quac_tls_conn_free(conn);
        close(fd);
        quac_tls_ctx_free(ctx);
        quac_tls_cleanup();
        return 1;
    }

    /* Print connection info */
    printf("\nConnection established:\n");
    printf("  TLS Version:   %s\n", quac_tls_get_version(conn));
    printf("  Key Exchange:  %s\n", quac_tls_get_kex(conn));
    printf("  Cipher:        %s\n", quac_tls_get_cipher(conn));
    printf("  ALPN:          %s\n", quac_tls_get_alpn(conn) ?: "none");
    printf("  Resumed:       %s\n", quac_tls_session_reused(conn) ? "yes" : "no");

    /* Send HTTP request */
    char request[512];
    snprintf(request, sizeof(request),
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Connection: close\r\n"
             "User-Agent: QUAC-TLS-Client/1.0\r\n"
             "\r\n",
             g_path, g_host);

    printf("\nSending request...\n");
    ret = quac_tls_write(conn, request, strlen(request));
    if (ret < 0)
    {
        fprintf(stderr, "Write failed: %s\n", quac_tls_error_string(ret));
    }
    else
    {
        /* Read response */
        char response[8192];
        printf("\nResponse:\n");
        printf("----------------------------------------\n");

        while ((ret = quac_tls_read(conn, response, sizeof(response) - 1)) > 0)
        {
            response[ret] = '\0';
            printf("%s", response);
        }

        printf("\n----------------------------------------\n");
    }

    /* Cleanup */
    quac_tls_shutdown(conn);
    quac_tls_conn_free(conn);
    close(fd);
    quac_tls_ctx_free(ctx);
    quac_tls_cleanup();

    printf("\nConnection closed.\n");
    return 0;
}