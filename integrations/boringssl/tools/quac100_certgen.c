/**
 * @file D:\quantacore-sdk\integrations\boringssl\tools\quac100_certgen.c
 * @brief QUAC 100 BoringSSL - PQC Certificate Generation Tool
 *
 * Generates X.509 certificates with ML-DSA signatures.
 *
 * Usage:
 *   quac100_certgen --algorithm mldsa65 --subject "CN=example.com" \
 *                   --days 365 --cert cert.pem --key key.pem
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <getopt.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "quac100_boringssl.h"

/* ==========================================================================
 * Configuration
 * ========================================================================== */

static int g_mldsa_level = 65;
static const char *g_subject = "CN=localhost";
static int g_days = 365;
static const char *g_cert_file = "cert.pem";
static const char *g_key_file = "key.pem";
static const char *g_ca_cert_file = NULL;
static const char *g_ca_key_file = NULL;
static int g_is_ca = 0;
static const char *g_san = NULL; /* Subject Alternative Names */
static int g_verbose = 0;

/* ==========================================================================
 * Utilities
 * ========================================================================== */

static int add_extension(X509 *cert, int nid, const char *value)
{
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);

    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, (char *)value);
    if (!ext)
    {
        return -1;
    }

    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
    return 0;
}

static int parse_subject(X509_NAME *name, const char *subject)
{
    char *copy = strdup(subject);
    if (!copy)
        return -1;

    char *saveptr;
    char *token = strtok_r(copy, ",/", &saveptr);

    while (token)
    {
        /* Skip leading whitespace */
        while (*token == ' ')
            token++;

        char *eq = strchr(token, '=');
        if (eq)
        {
            *eq = '\0';
            const char *field = token;
            const char *value = eq + 1;

            /* Map common field names */
            int nid = OBJ_txt2nid(field);
            if (nid == NID_undef)
            {
                fprintf(stderr, "Warning: Unknown field '%s'\n", field);
            }
            else
            {
                X509_NAME_add_entry_by_NID(name, nid, MBSTRING_UTF8,
                                           (const unsigned char *)value, -1, -1, 0);
            }
        }

        token = strtok_r(NULL, ",/", &saveptr);
    }

    free(copy);
    return 0;
}

static int generate_serial(ASN1_INTEGER *serial)
{
    unsigned char buf[16];
    if (RAND_bytes(buf, sizeof(buf)) != 1)
    {
        return -1;
    }
    buf[0] &= 0x7f; /* Ensure positive */

    BIGNUM *bn = BN_bin2bn(buf, sizeof(buf), NULL);
    if (!bn)
        return -1;

    BN_to_ASN1_INTEGER(bn, serial);
    BN_free(bn);
    return 0;
}

/* ==========================================================================
 * Certificate Generation
 * ========================================================================== */

static int generate_certificate(void)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *ca_pkey = NULL;
    X509 *cert = NULL;
    X509 *ca_cert = NULL;
    FILE *f = NULL;
    int ret = -1;

    printf("Generating ML-DSA-%d key pair...\n", g_mldsa_level);

    /* Generate ML-DSA key pair */
    if (quac100_mldsa_keygen(&pkey, g_mldsa_level) != QUAC100_OK)
    {
        fprintf(stderr, "Failed to generate key pair\n");
        goto cleanup;
    }

    /* Load CA if specified */
    if (g_ca_cert_file && g_ca_key_file)
    {
        printf("Loading CA certificate...\n");

        f = fopen(g_ca_cert_file, "r");
        if (!f)
        {
            perror(g_ca_cert_file);
            goto cleanup;
        }
        ca_cert = PEM_read_X509(f, NULL, NULL, NULL);
        fclose(f);
        f = NULL;
        if (!ca_cert)
        {
            fprintf(stderr, "Failed to read CA certificate\n");
            goto cleanup;
        }

        f = fopen(g_ca_key_file, "r");
        if (!f)
        {
            perror(g_ca_key_file);
            goto cleanup;
        }
        ca_pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
        fclose(f);
        f = NULL;
        if (!ca_pkey)
        {
            fprintf(stderr, "Failed to read CA key\n");
            goto cleanup;
        }
    }

    printf("Creating certificate...\n");

    /* Create certificate */
    cert = X509_new();
    if (!cert)
    {
        fprintf(stderr, "Failed to create certificate\n");
        goto cleanup;
    }

    /* Set version (X509v3) */
    X509_set_version(cert, 2);

    /* Set serial number */
    if (generate_serial(X509_get_serialNumber(cert)) != 0)
    {
        fprintf(stderr, "Failed to generate serial number\n");
        goto cleanup;
    }

    /* Set validity period */
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), (long)g_days * 24 * 60 * 60);

    /* Set subject */
    X509_NAME *subject_name = X509_get_subject_name(cert);
    if (parse_subject(subject_name, g_subject) != 0)
    {
        fprintf(stderr, "Failed to parse subject\n");
        goto cleanup;
    }

    /* Set issuer */
    if (ca_cert)
    {
        X509_set_issuer_name(cert, X509_get_subject_name(ca_cert));
    }
    else
    {
        X509_set_issuer_name(cert, subject_name);
    }

    /* Set public key */
    X509_set_pubkey(cert, pkey);

    /* Add extensions */
    if (g_is_ca)
    {
        add_extension(cert, NID_basic_constraints, "critical,CA:TRUE");
        add_extension(cert, NID_key_usage,
                      "critical,keyCertSign,cRLSign,digitalSignature");
    }
    else
    {
        add_extension(cert, NID_basic_constraints, "critical,CA:FALSE");
        add_extension(cert, NID_key_usage,
                      "critical,digitalSignature,keyEncipherment");
        add_extension(cert, NID_ext_key_usage, "serverAuth,clientAuth");
    }

    /* Add Subject Alternative Names */
    if (g_san)
    {
        char san_value[1024];
        snprintf(san_value, sizeof(san_value), "%s", g_san);
        add_extension(cert, NID_subject_alt_name, san_value);
    }

    /* Sign certificate */
    printf("Signing certificate with ML-DSA-%d...\n", g_mldsa_level);

    EVP_PKEY *signing_key = ca_pkey ? ca_pkey : pkey;

    /* Get the ML-DSA level from the signing key */
    int sign_level = g_mldsa_level;
    if (ca_pkey)
    {
        /* If using CA key, get its level */
        sign_level = quac100_evp_pkey_get_mldsa_level(ca_pkey);
        if (sign_level <= 0)
        {
            fprintf(stderr, "CA key is not ML-DSA\n");
            goto cleanup;
        }
    }

    if (quac100_x509_sign(cert, signing_key, sign_level) != QUAC100_OK)
    {
        fprintf(stderr, "Failed to sign certificate\n");
        goto cleanup;
    }

    /* Write certificate */
    printf("Writing certificate to %s...\n", g_cert_file);
    f = fopen(g_cert_file, "w");
    if (!f)
    {
        perror(g_cert_file);
        goto cleanup;
    }
    if (PEM_write_X509(f, cert) != 1)
    {
        fprintf(stderr, "Failed to write certificate\n");
        fclose(f);
        goto cleanup;
    }
    fclose(f);
    f = NULL;

    /* Write private key */
    printf("Writing private key to %s...\n", g_key_file);
    f = fopen(g_key_file, "w");
    if (!f)
    {
        perror(g_key_file);
        goto cleanup;
    }
    if (PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL) != 1)
    {
        fprintf(stderr, "Failed to write private key\n");
        fclose(f);
        goto cleanup;
    }
    fclose(f);
    f = NULL;

    printf("\nCertificate generated successfully!\n");
    ret = 0;

    /* Print certificate info */
    if (g_verbose)
    {
        printf("\nCertificate Information:\n");

        char *subject_str = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
        char *issuer_str = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);

        printf("  Subject:    %s\n", subject_str);
        printf("  Issuer:     %s\n", issuer_str);
        printf("  Valid for:  %d days\n", g_days);
        printf("  Algorithm:  ML-DSA-%d\n", g_mldsa_level);
        printf("  Type:       %s\n", g_is_ca ? "CA Certificate" : "End Entity");

        OPENSSL_free(subject_str);
        OPENSSL_free(issuer_str);

        /* Key sizes */
        size_t pk_size, sk_size, sig_size;
        switch (g_mldsa_level)
        {
        case 44:
            pk_size = 1312;
            sk_size = 2560;
            sig_size = 2420;
            break;
        case 65:
            pk_size = 1952;
            sk_size = 4032;
            sig_size = 3309;
            break;
        case 87:
            pk_size = 2592;
            sk_size = 4896;
            sig_size = 4627;
            break;
        default:
            pk_size = sk_size = sig_size = 0;
        }
        printf("\nKey Sizes:\n");
        printf("  Public key:  %zu bytes\n", pk_size);
        printf("  Private key: %zu bytes\n", sk_size);
        printf("  Signature:   %zu bytes\n", sig_size);
    }

cleanup:
    if (f)
        fclose(f);
    if (cert)
        X509_free(cert);
    if (ca_cert)
        X509_free(ca_cert);
    if (pkey)
        EVP_PKEY_free(pkey);
    if (ca_pkey)
        EVP_PKEY_free(ca_pkey);
    return ret;
}

/* ==========================================================================
 * Main
 * ========================================================================== */

static void usage(const char *prog)
{
    printf("QUAC 100 PQC Certificate Generator\n\n");
    printf("Usage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -a, --algorithm <lvl>    ML-DSA level: 44, 65, 87 (default: 65)\n");
    printf("  -s, --subject <subj>     Certificate subject (default: CN=localhost)\n");
    printf("  -d, --days <days>        Validity in days (default: 365)\n");
    printf("  -c, --cert <file>        Output certificate file (default: cert.pem)\n");
    printf("  -k, --key <file>         Output private key file (default: key.pem)\n");
    printf("  --ca-cert <file>         CA certificate for signing\n");
    printf("  --ca-key <file>          CA private key for signing\n");
    printf("  --ca                     Generate CA certificate\n");
    printf("  --san <names>            Subject Alternative Names\n");
    printf("  -v, --verbose            Verbose output\n");
    printf("  -h, --help               Show this help\n");
    printf("\n");
    printf("Subject Format:\n");
    printf("  CN=CommonName,O=Organization,C=Country\n");
    printf("  Fields: CN, O, OU, C, ST, L, emailAddress\n");
    printf("\n");
    printf("SAN Format:\n");
    printf("  DNS:example.com,DNS:*.example.com,IP:192.168.1.1\n");
    printf("\n");
    printf("Examples:\n");
    printf("  # Self-signed server certificate\n");
    printf("  %s -s \"CN=example.com\" -d 365 --san \"DNS:example.com\"\n\n", prog);
    printf("  # CA certificate\n");
    printf("  %s -a 87 -s \"CN=My CA,O=MyOrg\" --ca -d 3650\n\n", prog);
    printf("  # Certificate signed by CA\n");
    printf("  %s -s \"CN=server\" --ca-cert ca.pem --ca-key ca-key.pem\n", prog);
}

int main(int argc, char *argv[])
{
    int opt;
    static struct option long_opts[] = {
        {"algorithm", required_argument, 0, 'a'},
        {"subject", required_argument, 0, 's'},
        {"days", required_argument, 0, 'd'},
        {"cert", required_argument, 0, 'c'},
        {"key", required_argument, 0, 'k'},
        {"ca-cert", required_argument, 0, 'C'},
        {"ca-key", required_argument, 0, 'K'},
        {"ca", no_argument, 0, 'A'},
        {"san", required_argument, 0, 'S'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}};

    while ((opt = getopt_long(argc, argv, "a:s:d:c:k:vh", long_opts, NULL)) != -1)
    {
        switch (opt)
        {
        case 'a':
            g_mldsa_level = atoi(optarg);
            break;
        case 's':
            g_subject = optarg;
            break;
        case 'd':
            g_days = atoi(optarg);
            break;
        case 'c':
            g_cert_file = optarg;
            break;
        case 'k':
            g_key_file = optarg;
            break;
        case 'C':
            g_ca_cert_file = optarg;
            break;
        case 'K':
            g_ca_key_file = optarg;
            break;
        case 'A':
            g_is_ca = 1;
            break;
        case 'S':
            g_san = optarg;
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

    /* Validate ML-DSA level */
    if (g_mldsa_level != 44 && g_mldsa_level != 65 && g_mldsa_level != 87)
    {
        fprintf(stderr, "Error: ML-DSA level must be 44, 65, or 87\n");
        return 1;
    }

    /* Check CA options */
    if ((g_ca_cert_file && !g_ca_key_file) || (!g_ca_cert_file && g_ca_key_file))
    {
        fprintf(stderr, "Error: Both --ca-cert and --ca-key required\n");
        return 1;
    }

    printf("QUAC 100 Certificate Generator v%s\n\n", quac100_version_string());

    /* Initialize QUAC 100 */
    if (quac100_init() != QUAC100_OK)
    {
        fprintf(stderr, "Failed to initialize QUAC 100\n");
        return 1;
    }

    printf("Hardware acceleration: %s\n\n",
           quac100_hw_available() ? "ENABLED" : "DISABLED");

    /* Generate certificate */
    int ret = generate_certificate();

    /* Cleanup */
    quac100_cleanup();

    return ret == 0 ? 0 : 1;
}