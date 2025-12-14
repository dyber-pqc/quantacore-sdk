/**
 * @file D:\quantacore-sdk\integrations\openssl\examples\pqc_kem.c
 * @brief QUAC 100 OpenSSL Provider - ML-KEM Example
 *
 * Demonstrates key encapsulation with ML-KEM through OpenSSL provider.
 *
 * Usage:
 *   ./pqc_kem -g -k key.pem                     # Generate key pair
 *   ./pqc_kem -e -k pub.pem -o enc.bin          # Encapsulate
 *   ./pqc_kem -d -k priv.pem -i enc.bin         # Decapsulate
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

/* ==========================================================================
 * Configuration
 * ========================================================================== */

typedef enum
{
    MODE_NONE = 0,
    MODE_KEYGEN,
    MODE_ENCAPS,
    MODE_DECAPS,
    MODE_DEMO
} mode_t;

static mode_t g_mode = MODE_NONE;
static const char *g_algorithm = "ML-KEM-768";
static const char *g_key_file = "key.pem";
static const char *g_pub_file = NULL;
static const char *g_input_file = NULL;
static const char *g_output_file = "ciphertext.bin";
static int g_verbose = 0;

/* ==========================================================================
 * Utilities
 * ========================================================================== */

static void print_hex(const char *label, const unsigned char *data, size_t len)
{
    printf("%s (%zu bytes):\n", label, len);
    for (size_t i = 0; i < len && i < 64; i++)
    {
        printf("%02x", data[i]);
        if ((i + 1) % 32 == 0)
            printf("\n");
    }
    if (len > 64)
        printf("...\n");
    else if (len % 32 != 0)
        printf("\n");
}

/* ==========================================================================
 * Key Generation
 * ========================================================================== */

static int generate_key(void)
{
    printf("Generating %s key pair...\n", g_algorithm);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, g_algorithm, "provider=quac100");
    if (!ctx)
    {
        fprintf(stderr, "Failed to create key context for %s\n", g_algorithm);
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        fprintf(stderr, "Failed to initialize key generation\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    EVP_PKEY *key = NULL;
    if (EVP_PKEY_generate(ctx, &key) <= 0)
    {
        fprintf(stderr, "Key generation failed\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    EVP_PKEY_CTX_free(ctx);

    /* Write private key */
    FILE *f = fopen(g_key_file, "w");
    if (!f)
    {
        perror(g_key_file);
        EVP_PKEY_free(key);
        return -1;
    }

    if (PEM_write_PrivateKey(f, key, NULL, NULL, 0, NULL, NULL) != 1)
    {
        fprintf(stderr, "Failed to write private key\n");
        fclose(f);
        EVP_PKEY_free(key);
        return -1;
    }
    fclose(f);
    printf("Private key written to %s\n", g_key_file);

    /* Write public key if requested */
    if (g_pub_file)
    {
        f = fopen(g_pub_file, "w");
        if (!f)
        {
            perror(g_pub_file);
            EVP_PKEY_free(key);
            return -1;
        }

        if (PEM_write_PUBKEY(f, key) != 1)
        {
            fprintf(stderr, "Failed to write public key\n");
            fclose(f);
            EVP_PKEY_free(key);
            return -1;
        }
        fclose(f);
        printf("Public key written to %s\n", g_pub_file);
    }

    EVP_PKEY_free(key);
    return 0;
}

/* ==========================================================================
 * Encapsulation
 * ========================================================================== */

static int encapsulate(void)
{
    printf("Encapsulating with %s...\n", g_algorithm);

    /* Load public key */
    FILE *kf = fopen(g_key_file, "r");
    if (!kf)
    {
        perror(g_key_file);
        return -1;
    }

    EVP_PKEY *key = PEM_read_PUBKEY(kf, NULL, NULL, NULL);
    if (!key)
    {
        rewind(kf);
        key = PEM_read_PrivateKey(kf, NULL, NULL, NULL);
    }
    fclose(kf);

    if (!key)
    {
        fprintf(stderr, "Failed to read key\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    /* Encapsulate */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=quac100");
    if (!ctx)
    {
        fprintf(stderr, "Failed to create encapsulation context\n");
        EVP_PKEY_free(key);
        return -1;
    }

    if (EVP_PKEY_encapsulate_init(ctx, NULL) <= 0)
    {
        fprintf(stderr, "Failed to initialize encapsulation\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(key);
        return -1;
    }

    /* Get sizes */
    size_t ct_len = 0, ss_len = 0;
    if (EVP_PKEY_encapsulate(ctx, NULL, &ct_len, NULL, &ss_len) <= 0)
    {
        fprintf(stderr, "Failed to get sizes\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(key);
        return -1;
    }

    unsigned char *ct = malloc(ct_len);
    unsigned char *ss = malloc(ss_len);
    if (!ct || !ss)
    {
        fprintf(stderr, "Memory allocation failed\n");
        free(ct);
        free(ss);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(key);
        return -1;
    }

    /* Perform encapsulation */
    if (EVP_PKEY_encapsulate(ctx, ct, &ct_len, ss, &ss_len) <= 0)
    {
        fprintf(stderr, "Encapsulation failed\n");
        ERR_print_errors_fp(stderr);
        free(ct);
        free(ss);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(key);
        return -1;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);

    if (g_verbose)
    {
        print_hex("Ciphertext", ct, ct_len);
        print_hex("Shared Secret", ss, ss_len);
    }

    /* Write ciphertext */
    FILE *of = fopen(g_output_file, "wb");
    if (!of)
    {
        perror(g_output_file);
        free(ct);
        free(ss);
        return -1;
    }

    if (fwrite(ct, 1, ct_len, of) != ct_len)
    {
        fprintf(stderr, "Failed to write ciphertext\n");
        fclose(of);
        free(ct);
        free(ss);
        return -1;
    }
    fclose(of);

    printf("Ciphertext written to %s (%zu bytes)\n", g_output_file, ct_len);

    /* Print shared secret (in practice, would be used for encryption) */
    printf("\nShared Secret (%zu bytes): ", ss_len);
    for (size_t i = 0; i < ss_len; i++)
    {
        printf("%02x", ss[i]);
    }
    printf("\n");

    free(ct);
    free(ss);
    return 0;
}

/* ==========================================================================
 * Decapsulation
 * ========================================================================== */

static int decapsulate(void)
{
    if (!g_input_file)
    {
        fprintf(stderr, "Ciphertext file required (-i)\n");
        return -1;
    }

    printf("Decapsulating with %s...\n", g_algorithm);

    /* Load private key */
    FILE *kf = fopen(g_key_file, "r");
    if (!kf)
    {
        perror(g_key_file);
        return -1;
    }

    EVP_PKEY *key = PEM_read_PrivateKey(kf, NULL, NULL, NULL);
    fclose(kf);

    if (!key)
    {
        fprintf(stderr, "Failed to read private key\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    /* Read ciphertext */
    FILE *inf = fopen(g_input_file, "rb");
    if (!inf)
    {
        perror(g_input_file);
        EVP_PKEY_free(key);
        return -1;
    }

    fseek(inf, 0, SEEK_END);
    long ct_len = ftell(inf);
    fseek(inf, 0, SEEK_SET);

    unsigned char *ct = malloc(ct_len);
    if (!ct || fread(ct, 1, ct_len, inf) != (size_t)ct_len)
    {
        fprintf(stderr, "Failed to read ciphertext\n");
        fclose(inf);
        EVP_PKEY_free(key);
        free(ct);
        return -1;
    }
    fclose(inf);

    if (g_verbose)
    {
        print_hex("Ciphertext", ct, ct_len);
    }

    /* Decapsulate */
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=quac100");
    if (!ctx)
    {
        fprintf(stderr, "Failed to create decapsulation context\n");
        EVP_PKEY_free(key);
        free(ct);
        return -1;
    }

    if (EVP_PKEY_decapsulate_init(ctx, NULL) <= 0)
    {
        fprintf(stderr, "Failed to initialize decapsulation\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(key);
        free(ct);
        return -1;
    }

    /* Get shared secret size */
    size_t ss_len = 32; /* ML-KEM always produces 32-byte secrets */
    unsigned char *ss = malloc(ss_len);
    if (!ss)
    {
        fprintf(stderr, "Memory allocation failed\n");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(key);
        free(ct);
        return -1;
    }

    /* Perform decapsulation */
    if (EVP_PKEY_decapsulate(ctx, ss, &ss_len, ct, ct_len) <= 0)
    {
        fprintf(stderr, "Decapsulation failed\n");
        ERR_print_errors_fp(stderr);
        free(ss);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(key);
        free(ct);
        return -1;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    free(ct);

    /* Print shared secret */
    printf("\nShared Secret (%zu bytes): ", ss_len);
    for (size_t i = 0; i < ss_len; i++)
    {
        printf("%02x", ss[i]);
    }
    printf("\n");

    free(ss);
    return 0;
}

/* ==========================================================================
 * Demo Mode - Full Round Trip
 * ========================================================================== */

static int demo(void)
{
    printf("=== ML-KEM Round-Trip Demo ===\n\n");
    printf("Algorithm: %s\n\n", g_algorithm);

    /* Generate key */
    printf("1. Generating key pair...\n");
    EVP_PKEY_CTX *gen_ctx = EVP_PKEY_CTX_new_from_name(NULL, g_algorithm, "provider=quac100");
    EVP_PKEY_keygen_init(gen_ctx);
    EVP_PKEY *key = NULL;
    EVP_PKEY_generate(gen_ctx, &key);
    EVP_PKEY_CTX_free(gen_ctx);

    if (!key)
    {
        fprintf(stderr, "Key generation failed\n");
        return -1;
    }
    printf("   Key generated successfully\n\n");

    /* Encapsulate */
    printf("2. Encapsulating...\n");
    EVP_PKEY_CTX *enc_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=quac100");
    EVP_PKEY_encapsulate_init(enc_ctx, NULL);

    size_t ct_len = 0, ss_len = 0;
    EVP_PKEY_encapsulate(enc_ctx, NULL, &ct_len, NULL, &ss_len);

    unsigned char *ct = malloc(ct_len);
    unsigned char *ss_enc = malloc(ss_len);
    EVP_PKEY_encapsulate(enc_ctx, ct, &ct_len, ss_enc, &ss_len);
    EVP_PKEY_CTX_free(enc_ctx);

    printf("   Ciphertext: %zu bytes\n", ct_len);
    printf("   Shared secret (encaps): ");
    for (size_t i = 0; i < ss_len; i++)
        printf("%02x", ss_enc[i]);
    printf("\n\n");

    /* Decapsulate */
    printf("3. Decapsulating...\n");
    EVP_PKEY_CTX *dec_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=quac100");
    EVP_PKEY_decapsulate_init(dec_ctx, NULL);

    unsigned char *ss_dec = malloc(ss_len);
    size_t ss_dec_len = ss_len;
    EVP_PKEY_decapsulate(dec_ctx, ss_dec, &ss_dec_len, ct, ct_len);
    EVP_PKEY_CTX_free(dec_ctx);

    printf("   Shared secret (decaps): ");
    for (size_t i = 0; i < ss_dec_len; i++)
        printf("%02x", ss_dec[i]);
    printf("\n\n");

    /* Verify */
    printf("4. Verifying...\n");
    int match = (ss_len == ss_dec_len && memcmp(ss_enc, ss_dec, ss_len) == 0);
    printf("   Secrets match: %s\n", match ? "YES ✓" : "NO ✗");

    free(ct);
    free(ss_enc);
    free(ss_dec);
    EVP_PKEY_free(key);

    return match ? 0 : 1;
}

/* ==========================================================================
 * Main
 * ========================================================================== */

static void usage(const char *prog)
{
    printf("QUAC 100 ML-KEM Example\n\n");
    printf("Usage: %s <mode> [options]\n\n", prog);
    printf("Modes:\n");
    printf("  -g, --generate      Generate key pair\n");
    printf("  -e, --encapsulate   Encapsulate (generate shared secret)\n");
    printf("  -d, --decapsulate   Decapsulate (recover shared secret)\n");
    printf("  -D, --demo          Full round-trip demo\n");
    printf("\n");
    printf("Options:\n");
    printf("  -a, --algorithm <alg>  Algorithm: ML-KEM-512, ML-KEM-768, ML-KEM-1024 (default: ML-KEM-768)\n");
    printf("  -k, --key <file>       Key file (default: key.pem)\n");
    printf("  -p, --pub <file>       Public key output file (for -g)\n");
    printf("  -i, --input <file>     Ciphertext input file (for -d)\n");
    printf("  -o, --output <file>    Ciphertext output file (default: ciphertext.bin)\n");
    printf("  -v, --verbose          Verbose output\n");
    printf("  -h, --help             Show this help\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -g -k priv.pem -p pub.pem        # Generate key pair\n", prog);
    printf("  %s -e -k pub.pem -o ct.bin          # Encapsulate\n", prog);
    printf("  %s -d -k priv.pem -i ct.bin         # Decapsulate\n", prog);
    printf("  %s -D                               # Full demo\n", prog);
}

int main(int argc, char *argv[])
{
    int opt;
    static struct option long_opts[] = {
        {"generate", no_argument, 0, 'g'},
        {"encapsulate", no_argument, 0, 'e'},
        {"decapsulate", no_argument, 0, 'd'},
        {"demo", no_argument, 0, 'D'},
        {"algorithm", required_argument, 0, 'a'},
        {"key", required_argument, 0, 'k'},
        {"pub", required_argument, 0, 'p'},
        {"input", required_argument, 0, 'i'},
        {"output", required_argument, 0, 'o'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}};

    while ((opt = getopt_long(argc, argv, "gedDa:k:p:i:o:vh", long_opts, NULL)) != -1)
    {
        switch (opt)
        {
        case 'g':
            g_mode = MODE_KEYGEN;
            break;
        case 'e':
            g_mode = MODE_ENCAPS;
            break;
        case 'd':
            g_mode = MODE_DECAPS;
            break;
        case 'D':
            g_mode = MODE_DEMO;
            break;
        case 'a':
            g_algorithm = optarg;
            break;
        case 'k':
            g_key_file = optarg;
            break;
        case 'p':
            g_pub_file = optarg;
            break;
        case 'i':
            g_input_file = optarg;
            break;
        case 'o':
            g_output_file = optarg;
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

    if (g_mode == MODE_NONE)
    {
        fprintf(stderr, "Error: Mode required (-g, -e, -d, or -D)\n\n");
        usage(argv[0]);
        return 1;
    }

    /* Load provider */
    OSSL_PROVIDER *prov = OSSL_PROVIDER_load(NULL, "quac100");
    if (!prov)
    {
        fprintf(stderr, "Failed to load QUAC 100 provider\n");
        fprintf(stderr, "Set OPENSSL_MODULES to provider location\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    int ret;
    switch (g_mode)
    {
    case MODE_KEYGEN:
        ret = generate_key();
        break;
    case MODE_ENCAPS:
        ret = encapsulate();
        break;
    case MODE_DECAPS:
        ret = decapsulate();
        break;
    case MODE_DEMO:
        ret = demo();
        break;
    default:
        ret = -1;
    }

    OSSL_PROVIDER_unload(prov);
    return ret == 0 ? 0 : 1;
}