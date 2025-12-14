/**
 * @file quac_tls_keygen.c
 * @brief QUAC 100 TLS - Certificate Generator Tool
 *
 * Generates ML-DSA certificates for post-quantum TLS.
 *
 * Usage:
 *   quac-tls-keygen --algorithm mldsa65 --subject "CN=example.com" \
 *                   --days 365 --cert cert.pem --key key.pem
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "quac_tls.h"

static void usage(const char *prog)
{
    printf("QUAC TLS Certificate Generator\n\n");
    printf("Usage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -a, --algorithm <alg>   Algorithm: mldsa44, mldsa65, mldsa87 (default: mldsa65)\n");
    printf("  -s, --subject <subj>    Certificate subject (default: CN=localhost)\n");
    printf("  -d, --days <days>       Validity in days (default: 365)\n");
    printf("  -c, --cert <file>       Output certificate file (default: cert.pem)\n");
    printf("  -k, --key <file>        Output private key file (default: key.pem)\n");
    printf("  -p, --print             Print generated PEM to stdout\n");
    printf("  -h, --help              Show this help\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -a mldsa65 -s \"CN=example.com\" -d 365\n", prog);
    printf("  %s --algorithm mldsa87 --subject \"CN=secure.org,O=MyOrg\"\n", prog);
    printf("\n");
    printf("Algorithms:\n");
    printf("  mldsa44  ML-DSA Level 2 (NIST Level 2, 1312 B pubkey, 2420 B sig)\n");
    printf("  mldsa65  ML-DSA Level 3 (NIST Level 3, 1952 B pubkey, 3309 B sig)\n");
    printf("  mldsa87  ML-DSA Level 5 (NIST Level 5, 2592 B pubkey, 4627 B sig)\n");
}

static int parse_algorithm(const char *alg)
{
    if (strcmp(alg, "mldsa44") == 0 || strcmp(alg, "ML-DSA-44") == 0)
        return 44;
    if (strcmp(alg, "mldsa65") == 0 || strcmp(alg, "ML-DSA-65") == 0)
        return 65;
    if (strcmp(alg, "mldsa87") == 0 || strcmp(alg, "ML-DSA-87") == 0)
        return 87;
    return -1;
}

static int write_file(const char *path, const char *data)
{
    FILE *f = fopen(path, "w");
    if (!f)
    {
        perror(path);
        return -1;
    }
    fputs(data, f);
    fclose(f);
    return 0;
}

int main(int argc, char *argv[])
{
    const char *algorithm = "mldsa65";
    const char *subject = "CN=localhost";
    int days = 365;
    const char *cert_file = "cert.pem";
    const char *key_file = "key.pem";
    int print_output = 0;

    static struct option long_opts[] = {
        {"algorithm", required_argument, 0, 'a'},
        {"subject", required_argument, 0, 's'},
        {"days", required_argument, 0, 'd'},
        {"cert", required_argument, 0, 'c'},
        {"key", required_argument, 0, 'k'},
        {"print", no_argument, 0, 'p'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}};

    int opt;
    while ((opt = getopt_long(argc, argv, "a:s:d:c:k:ph", long_opts, NULL)) != -1)
    {
        switch (opt)
        {
        case 'a':
            algorithm = optarg;
            break;
        case 's':
            subject = optarg;
            break;
        case 'd':
            days = atoi(optarg);
            break;
        case 'c':
            cert_file = optarg;
            break;
        case 'k':
            key_file = optarg;
            break;
        case 'p':
            print_output = 1;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    /* Parse algorithm */
    int level = parse_algorithm(algorithm);
    if (level < 0)
    {
        fprintf(stderr, "Error: Unknown algorithm '%s'\n", algorithm);
        fprintf(stderr, "Use: mldsa44, mldsa65, or mldsa87\n");
        return 1;
    }

    if (days < 1)
    {
        fprintf(stderr, "Error: Days must be positive\n");
        return 1;
    }

    /* Initialize library */
    if (quac_tls_init() != QUAC_TLS_OK)
    {
        fprintf(stderr, "Error: Failed to initialize QUAC TLS library\n");
        return 1;
    }

    printf("QUAC TLS Certificate Generator v%s\n\n", quac_tls_version());
    printf("Algorithm:   ML-DSA-%d\n", level);
    printf("Subject:     %s\n", subject);
    printf("Validity:    %d days\n", days);
    printf("Certificate: %s\n", cert_file);
    printf("Private Key: %s\n", key_file);
    printf("\n");

    /* Generate certificate */
    printf("Generating ML-DSA-%d keypair...\n", level);

    char *cert_pem = NULL, *key_pem = NULL;
    int ret = quac_tls_generate_self_signed_mldsa(level, subject, days,
                                                  &cert_pem, &key_pem);
    if (ret != QUAC_TLS_OK)
    {
        fprintf(stderr, "Error: Failed to generate certificate: %s\n",
                quac_tls_error_string(ret));
        quac_tls_cleanup();
        return 1;
    }

    printf("Writing certificate to %s...\n", cert_file);
    if (write_file(cert_file, cert_pem) < 0)
    {
        free(cert_pem);
        free(key_pem);
        quac_tls_cleanup();
        return 1;
    }

    printf("Writing private key to %s...\n", key_file);
    if (write_file(key_file, key_pem) < 0)
    {
        free(cert_pem);
        free(key_pem);
        quac_tls_cleanup();
        return 1;
    }

    printf("\nCertificate generated successfully!\n");
    printf("  Certificate: %zu bytes\n", strlen(cert_pem));
    printf("  Private Key: %zu bytes\n", strlen(key_pem));

    if (print_output)
    {
        printf("\n--- Certificate ---\n%s", cert_pem);
        printf("\n--- Private Key ---\n%s", key_pem);
    }

    /* Cleanup */
    free(cert_pem);
    free(key_pem);
    quac_tls_cleanup();

    return 0;
}