/**
 * @file D:\quantacore-sdk\integrations\boringssl\tools\quac100_keygen.c
 * @brief QUAC 100 BoringSSL - PQC Key Generation Tool
 *
 * Generates ML-KEM and ML-DSA key pairs in PEM format.
 *
 * Usage:
 *   quac100_keygen --algorithm mldsa65 --output key.pem
 *   quac100_keygen --algorithm mlkem768 --public pub.pem --private priv.pem
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include <openssl/pem.h>
#include <openssl/err.h>

#include "quac100_boringssl.h"

/* ==========================================================================
 * Configuration
 * ========================================================================== */

typedef enum
{
    ALG_UNKNOWN = 0,
    ALG_MLKEM_512,
    ALG_MLKEM_768,
    ALG_MLKEM_1024,
    ALG_MLDSA_44,
    ALG_MLDSA_65,
    ALG_MLDSA_87
} algorithm_t;

static algorithm_t g_algorithm = ALG_UNKNOWN;
static const char *g_output_file = NULL;
static const char *g_public_file = NULL;
static const char *g_private_file = NULL;
static int g_verbose = 0;
static int g_use_hardware = 1;

/* ==========================================================================
 * Utilities
 * ========================================================================== */

static algorithm_t parse_algorithm(const char *name)
{
    if (strcasecmp(name, "mlkem512") == 0 || strcasecmp(name, "ml-kem-512") == 0)
        return ALG_MLKEM_512;
    if (strcasecmp(name, "mlkem768") == 0 || strcasecmp(name, "ml-kem-768") == 0)
        return ALG_MLKEM_768;
    if (strcasecmp(name, "mlkem1024") == 0 || strcasecmp(name, "ml-kem-1024") == 0)
        return ALG_MLKEM_1024;
    if (strcasecmp(name, "mldsa44") == 0 || strcasecmp(name, "ml-dsa-44") == 0)
        return ALG_MLDSA_44;
    if (strcasecmp(name, "mldsa65") == 0 || strcasecmp(name, "ml-dsa-65") == 0)
        return ALG_MLDSA_65;
    if (strcasecmp(name, "mldsa87") == 0 || strcasecmp(name, "ml-dsa-87") == 0)
        return ALG_MLDSA_87;
    return ALG_UNKNOWN;
}

static const char *algorithm_name(algorithm_t alg)
{
    switch (alg)
    {
    case ALG_MLKEM_512:
        return "ML-KEM-512";
    case ALG_MLKEM_768:
        return "ML-KEM-768";
    case ALG_MLKEM_1024:
        return "ML-KEM-1024";
    case ALG_MLDSA_44:
        return "ML-DSA-44";
    case ALG_MLDSA_65:
        return "ML-DSA-65";
    case ALG_MLDSA_87:
        return "ML-DSA-87";
    default:
        return "Unknown";
    }
}

static int is_kem(algorithm_t alg)
{
    return alg == ALG_MLKEM_512 || alg == ALG_MLKEM_768 || alg == ALG_MLKEM_1024;
}

static int get_level(algorithm_t alg)
{
    switch (alg)
    {
    case ALG_MLKEM_512:
        return 512;
    case ALG_MLKEM_768:
        return 768;
    case ALG_MLKEM_1024:
        return 1024;
    case ALG_MLDSA_44:
        return 44;
    case ALG_MLDSA_65:
        return 65;
    case ALG_MLDSA_87:
        return 87;
    default:
        return 0;
    }
}

static int write_pem_file(const char *path, EVP_PKEY *pkey, int private_key)
{
    FILE *f = fopen(path, "w");
    if (!f)
    {
        perror(path);
        return -1;
    }

    int ret;
    if (private_key)
    {
        ret = PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL);
    }
    else
    {
        ret = PEM_write_PUBKEY(f, pkey);
    }

    fclose(f);

    if (ret != 1)
    {
        fprintf(stderr, "Failed to write PEM to %s\n", path);
        ERR_print_errors_fp(stderr);
        return -1;
    }

    return 0;
}

/* ==========================================================================
 * Main
 * ========================================================================== */

static void usage(const char *prog)
{
    printf("QUAC 100 PQC Key Generation Tool\n\n");
    printf("Usage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -a, --algorithm <alg>    Algorithm (required)\n");
    printf("  -o, --output <file>      Output file (private key, includes public)\n");
    printf("  -p, --public <file>      Public key output file\n");
    printf("  -k, --private <file>     Private key output file\n");
    printf("  -s, --software           Force software implementation\n");
    printf("  -v, --verbose            Verbose output\n");
    printf("  -h, --help               Show this help\n");
    printf("\n");
    printf("Algorithms:\n");
    printf("  ML-KEM:  mlkem512, mlkem768, mlkem1024\n");
    printf("  ML-DSA:  mldsa44, mldsa65, mldsa87\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -a mldsa65 -o key.pem\n", prog);
    printf("  %s -a mlkem768 -p pub.pem -k priv.pem\n", prog);
    printf("  %s -a mldsa87 -o server.key -v\n", prog);
}

int main(int argc, char *argv[])
{
    int opt;
    static struct option long_opts[] = {
        {"algorithm", required_argument, 0, 'a'},
        {"output", required_argument, 0, 'o'},
        {"public", required_argument, 0, 'p'},
        {"private", required_argument, 0, 'k'},
        {"software", no_argument, 0, 's'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}};

    while ((opt = getopt_long(argc, argv, "a:o:p:k:svh", long_opts, NULL)) != -1)
    {
        switch (opt)
        {
        case 'a':
            g_algorithm = parse_algorithm(optarg);
            break;
        case 'o':
            g_output_file = optarg;
            break;
        case 'p':
            g_public_file = optarg;
            break;
        case 'k':
            g_private_file = optarg;
            break;
        case 's':
            g_use_hardware = 0;
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

    if (g_algorithm == ALG_UNKNOWN)
    {
        fprintf(stderr, "Error: Algorithm required (-a)\n\n");
        usage(argv[0]);
        return 1;
    }

    if (!g_output_file && !g_public_file && !g_private_file)
    {
        fprintf(stderr, "Error: Output file required (-o, -p, or -k)\n\n");
        usage(argv[0]);
        return 1;
    }

    printf("QUAC 100 PQC Key Generator v%s\n\n", quac100_version_string());

    /* Initialize */
    if (quac100_init() != QUAC100_OK)
    {
        fprintf(stderr, "Failed to initialize QUAC 100\n");
        return 1;
    }

    if (g_verbose)
    {
        printf("Algorithm:     %s\n", algorithm_name(g_algorithm));
        printf("Hardware:      %s\n",
               (g_use_hardware && quac100_hw_available()) ? "ENABLED" : "DISABLED");
    }

    /* Generate key pair */
    EVP_PKEY *pkey = NULL;
    int level = get_level(g_algorithm);
    int ret;

    printf("Generating %s key pair...\n", algorithm_name(g_algorithm));

    if (is_kem(g_algorithm))
    {
        ret = quac100_mlkem_keygen(&pkey, level);
    }
    else
    {
        ret = quac100_mldsa_keygen(&pkey, level);
    }

    if (ret != QUAC100_OK)
    {
        fprintf(stderr, "Key generation failed: %s\n", quac100_error_string(ret));
        quac100_cleanup();
        return 1;
    }

    printf("Key generated successfully.\n\n");

    /* Write output files */
    if (g_output_file)
    {
        printf("Writing private key to %s...\n", g_output_file);
        if (write_pem_file(g_output_file, pkey, 1) != 0)
        {
            EVP_PKEY_free(pkey);
            quac100_cleanup();
            return 1;
        }
    }

    if (g_private_file)
    {
        printf("Writing private key to %s...\n", g_private_file);
        if (write_pem_file(g_private_file, pkey, 1) != 0)
        {
            EVP_PKEY_free(pkey);
            quac100_cleanup();
            return 1;
        }
    }

    if (g_public_file)
    {
        printf("Writing public key to %s...\n", g_public_file);
        if (write_pem_file(g_public_file, pkey, 0) != 0)
        {
            EVP_PKEY_free(pkey);
            quac100_cleanup();
            return 1;
        }
    }

    /* Print key info */
    if (g_verbose)
    {
        printf("\nKey Information:\n");
        if (is_kem(g_algorithm))
        {
            size_t pk_size, sk_size, ct_size;
            switch (level)
            {
            case 512:
                pk_size = 800;
                sk_size = 1632;
                ct_size = 768;
                break;
            case 768:
                pk_size = 1184;
                sk_size = 2400;
                ct_size = 1088;
                break;
            case 1024:
                pk_size = 1568;
                sk_size = 3168;
                ct_size = 1568;
                break;
            default:
                pk_size = sk_size = ct_size = 0;
            }
            printf("  Public key size:   %zu bytes\n", pk_size);
            printf("  Secret key size:   %zu bytes\n", sk_size);
            printf("  Ciphertext size:   %zu bytes\n", ct_size);
            printf("  Shared secret:     32 bytes\n");
        }
        else
        {
            size_t pk_size, sk_size, sig_size;
            switch (level)
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
            printf("  Public key size:   %zu bytes\n", pk_size);
            printf("  Secret key size:   %zu bytes\n", sk_size);
            printf("  Signature size:    %zu bytes\n", sig_size);
        }
    }

    /* Cleanup */
    EVP_PKEY_free(pkey);
    quac100_cleanup();

    printf("\nDone.\n");
    return 0;
}