/**
 * @file D:\quantacore-sdk\integrations\openssl\examples\pqc_sign.c
 * @brief QUAC 100 OpenSSL Provider - ML-DSA Signing Example
 *
 * Demonstrates signing and verifying with ML-DSA through OpenSSL provider.
 *
 * Usage:
 *   ./pqc_sign -g -k key.pem                 # Generate key
 *   ./pqc_sign -s -k key.pem -i file.txt     # Sign file
 *   ./pqc_sign -v -k key.pem -i file.txt -S file.sig  # Verify
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
    MODE_SIGN,
    MODE_VERIFY
} mode_t;

static mode_t g_mode = MODE_NONE;
static const char *g_algorithm = "ML-DSA-65";
static const char *g_key_file = "key.pem";
static const char *g_input_file = NULL;
static const char *g_sig_file = NULL;
static const char *g_output_sig = "signature.bin";
static int g_verbose = 0;

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

    /* Write key to file */
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
        ERR_print_errors_fp(stderr);
        fclose(f);
        EVP_PKEY_free(key);
        return -1;
    }

    fclose(f);
    EVP_PKEY_free(key);

    printf("Key written to %s\n", g_key_file);
    return 0;
}

/* ==========================================================================
 * Signing
 * ========================================================================== */

static int sign_file(void)
{
    if (!g_input_file)
    {
        fprintf(stderr, "Input file required for signing (-i)\n");
        return -1;
    }

    printf("Signing %s with %s...\n", g_input_file, g_algorithm);

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

    /* Read input file */
    FILE *inf = fopen(g_input_file, "rb");
    if (!inf)
    {
        perror(g_input_file);
        EVP_PKEY_free(key);
        return -1;
    }

    fseek(inf, 0, SEEK_END);
    long msg_len = ftell(inf);
    fseek(inf, 0, SEEK_SET);

    unsigned char *msg = malloc(msg_len);
    if (!msg || fread(msg, 1, msg_len, inf) != (size_t)msg_len)
    {
        fprintf(stderr, "Failed to read input file\n");
        fclose(inf);
        EVP_PKEY_free(key);
        free(msg);
        return -1;
    }
    fclose(inf);

    if (g_verbose)
    {
        printf("Input: %ld bytes\n", msg_len);
    }

    /* Sign */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        fprintf(stderr, "Failed to create signing context\n");
        EVP_PKEY_free(key);
        free(msg);
        return -1;
    }

    if (EVP_DigestSignInit_ex(ctx, NULL, NULL, NULL, "provider=quac100", key, NULL) <= 0)
    {
        fprintf(stderr, "Failed to initialize signing\n");
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(key);
        free(msg);
        return -1;
    }

    /* Get signature size */
    size_t sig_len = 0;
    if (EVP_DigestSign(ctx, NULL, &sig_len, msg, msg_len) <= 0)
    {
        fprintf(stderr, "Failed to get signature size\n");
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(key);
        free(msg);
        return -1;
    }

    unsigned char *sig = malloc(sig_len);
    if (!sig)
    {
        fprintf(stderr, "Memory allocation failed\n");
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(key);
        free(msg);
        return -1;
    }

    /* Actually sign */
    if (EVP_DigestSign(ctx, sig, &sig_len, msg, msg_len) <= 0)
    {
        fprintf(stderr, "Signing failed\n");
        ERR_print_errors_fp(stderr);
        free(sig);
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(key);
        free(msg);
        return -1;
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    free(msg);

    if (g_verbose)
    {
        printf("Signature: %zu bytes\n", sig_len);
    }

    /* Write signature */
    FILE *sf = fopen(g_output_sig, "wb");
    if (!sf)
    {
        perror(g_output_sig);
        free(sig);
        return -1;
    }

    if (fwrite(sig, 1, sig_len, sf) != sig_len)
    {
        fprintf(stderr, "Failed to write signature\n");
        fclose(sf);
        free(sig);
        return -1;
    }

    fclose(sf);
    free(sig);

    printf("Signature written to %s (%zu bytes)\n", g_output_sig, sig_len);
    return 0;
}

/* ==========================================================================
 * Verification
 * ========================================================================== */

static int verify_signature(void)
{
    if (!g_input_file)
    {
        fprintf(stderr, "Input file required for verification (-i)\n");
        return -1;
    }
    if (!g_sig_file)
    {
        fprintf(stderr, "Signature file required for verification (-S)\n");
        return -1;
    }

    printf("Verifying %s with signature %s...\n", g_input_file, g_sig_file);

    /* Load public key (or private key - we only use public part) */
    FILE *kf = fopen(g_key_file, "r");
    if (!kf)
    {
        perror(g_key_file);
        return -1;
    }

    EVP_PKEY *key = PEM_read_PrivateKey(kf, NULL, NULL, NULL);
    if (!key)
    {
        rewind(kf);
        key = PEM_read_PUBKEY(kf, NULL, NULL, NULL);
    }
    fclose(kf);

    if (!key)
    {
        fprintf(stderr, "Failed to read key\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    /* Read input file */
    FILE *inf = fopen(g_input_file, "rb");
    if (!inf)
    {
        perror(g_input_file);
        EVP_PKEY_free(key);
        return -1;
    }

    fseek(inf, 0, SEEK_END);
    long msg_len = ftell(inf);
    fseek(inf, 0, SEEK_SET);

    unsigned char *msg = malloc(msg_len);
    if (!msg || fread(msg, 1, msg_len, inf) != (size_t)msg_len)
    {
        fprintf(stderr, "Failed to read input file\n");
        fclose(inf);
        EVP_PKEY_free(key);
        free(msg);
        return -1;
    }
    fclose(inf);

    /* Read signature */
    FILE *sf = fopen(g_sig_file, "rb");
    if (!sf)
    {
        perror(g_sig_file);
        EVP_PKEY_free(key);
        free(msg);
        return -1;
    }

    fseek(sf, 0, SEEK_END);
    long sig_len = ftell(sf);
    fseek(sf, 0, SEEK_SET);

    unsigned char *sig = malloc(sig_len);
    if (!sig || fread(sig, 1, sig_len, sf) != (size_t)sig_len)
    {
        fprintf(stderr, "Failed to read signature\n");
        fclose(sf);
        EVP_PKEY_free(key);
        free(msg);
        free(sig);
        return -1;
    }
    fclose(sf);

    if (g_verbose)
    {
        printf("Message: %ld bytes\n", msg_len);
        printf("Signature: %ld bytes\n", sig_len);
    }

    /* Verify */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        fprintf(stderr, "Failed to create verify context\n");
        EVP_PKEY_free(key);
        free(msg);
        free(sig);
        return -1;
    }

    if (EVP_DigestVerifyInit_ex(ctx, NULL, NULL, NULL, "provider=quac100", key, NULL) <= 0)
    {
        fprintf(stderr, "Failed to initialize verification\n");
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(key);
        free(msg);
        free(sig);
        return -1;
    }

    int result = EVP_DigestVerify(ctx, sig, sig_len, msg, msg_len);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    free(msg);
    free(sig);

    if (result == 1)
    {
        printf("Signature VALID\n");
        return 0;
    }
    else if (result == 0)
    {
        printf("Signature INVALID\n");
        return 1;
    }
    else
    {
        fprintf(stderr, "Verification error\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
}

/* ==========================================================================
 * Main
 * ========================================================================== */

static void usage(const char *prog)
{
    printf("QUAC 100 ML-DSA Signing Example\n\n");
    printf("Usage: %s <mode> [options]\n\n", prog);
    printf("Modes:\n");
    printf("  -g, --generate      Generate key pair\n");
    printf("  -s, --sign          Sign a file\n");
    printf("  -v, --verify        Verify a signature\n");
    printf("\n");
    printf("Options:\n");
    printf("  -a, --algorithm <alg>  Algorithm: ML-DSA-44, ML-DSA-65, ML-DSA-87 (default: ML-DSA-65)\n");
    printf("  -k, --key <file>       Key file (default: key.pem)\n");
    printf("  -i, --input <file>     Input file to sign/verify\n");
    printf("  -o, --output <file>    Output signature file (default: signature.bin)\n");
    printf("  -S, --signature <file> Signature file for verification\n");
    printf("  -V, --verbose          Verbose output\n");
    printf("  -h, --help             Show this help\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -g -k mldsa65.key                          # Generate key\n", prog);
    printf("  %s -s -k mldsa65.key -i document.pdf          # Sign document\n", prog);
    printf("  %s -v -k mldsa65.key -i document.pdf -S signature.bin  # Verify\n", prog);
}

int main(int argc, char *argv[])
{
    int opt;
    static struct option long_opts[] = {
        {"generate", no_argument, 0, 'g'},
        {"sign", no_argument, 0, 's'},
        {"verify", no_argument, 0, 'v'},
        {"algorithm", required_argument, 0, 'a'},
        {"key", required_argument, 0, 'k'},
        {"input", required_argument, 0, 'i'},
        {"output", required_argument, 0, 'o'},
        {"signature", required_argument, 0, 'S'},
        {"verbose", no_argument, 0, 'V'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}};

    while ((opt = getopt_long(argc, argv, "gsva:k:i:o:S:Vh", long_opts, NULL)) != -1)
    {
        switch (opt)
        {
        case 'g':
            g_mode = MODE_KEYGEN;
            break;
        case 's':
            g_mode = MODE_SIGN;
            break;
        case 'v':
            g_mode = MODE_VERIFY;
            break;
        case 'a':
            g_algorithm = optarg;
            break;
        case 'k':
            g_key_file = optarg;
            break;
        case 'i':
            g_input_file = optarg;
            break;
        case 'o':
            g_output_sig = optarg;
            break;
        case 'S':
            g_sig_file = optarg;
            break;
        case 'V':
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
        fprintf(stderr, "Error: Mode required (-g, -s, or -v)\n\n");
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
    case MODE_SIGN:
        ret = sign_file();
        break;
    case MODE_VERIFY:
        ret = verify_signature();
        break;
    default:
        ret = -1;
    }

    OSSL_PROVIDER_unload(prov);
    return ret == 0 ? 0 : 1;
}