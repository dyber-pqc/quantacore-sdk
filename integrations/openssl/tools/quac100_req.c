/**
 * @file D:\quantacore-sdk\integrations\openssl\tools\quac100_req.c
 * @brief QUAC 100 OpenSSL Provider - Certificate Request Tool
 *
 * Generates certificate signing requests (CSRs) with ML-DSA.
 *
 * Usage:
 *   quac100_req -new -key key.pem -out req.pem -subj "CN=example.com"
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
#include <openssl/x509.h>
#include <openssl/err.h>

/* ==========================================================================
 * Configuration
 * ========================================================================== */

static const char *g_algorithm = "ML-DSA-65";
static const char *g_key_file = NULL;
static const char *g_output_file = "request.pem";
static const char *g_subject = "CN=localhost";
static int g_newkey = 0;
static const char *g_newkey_file = "key.pem";
static int g_verbose = 0;
static const char *g_san = NULL;

/* ==========================================================================
 * Subject Parsing
 * ========================================================================== */

static int parse_subject(X509_NAME *name, const char *subject)
{
    char *copy = strdup(subject);
    if (!copy)
        return -1;

    char *saveptr;
    char *token = strtok_r(copy, ",/", &saveptr);

    while (token)
    {
        while (*token == ' ')
            token++;

        char *eq = strchr(token, '=');
        if (eq)
        {
            *eq = '\0';
            const char *field = token;
            const char *value = eq + 1;

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

/* ==========================================================================
 * CSR Generation
 * ========================================================================== */

static int generate_csr(void)
{
    EVP_PKEY *key = NULL;
    X509_REQ *req = NULL;
    int ret = -1;

    /* Generate or load key */
    if (g_newkey)
    {
        printf("Generating %s key...\n", g_algorithm);

        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, g_algorithm, "provider=quac100");
        if (!ctx)
        {
            fprintf(stderr, "Failed to create key context\n");
            ERR_print_errors_fp(stderr);
            return -1;
        }

        EVP_PKEY_keygen_init(ctx);
        EVP_PKEY_generate(ctx, &key);
        EVP_PKEY_CTX_free(ctx);

        if (!key)
        {
            fprintf(stderr, "Key generation failed\n");
            return -1;
        }

        /* Save key */
        FILE *kf = fopen(g_newkey_file, "w");
        if (!kf)
        {
            perror(g_newkey_file);
            EVP_PKEY_free(key);
            return -1;
        }

        if (PEM_write_PrivateKey(kf, key, NULL, NULL, 0, NULL, NULL) != 1)
        {
            fprintf(stderr, "Failed to write key\n");
            fclose(kf);
            EVP_PKEY_free(key);
            return -1;
        }
        fclose(kf);
        printf("Key written to %s\n", g_newkey_file);
    }
    else if (g_key_file)
    {
        FILE *kf = fopen(g_key_file, "r");
        if (!kf)
        {
            perror(g_key_file);
            return -1;
        }

        key = PEM_read_PrivateKey(kf, NULL, NULL, NULL);
        fclose(kf);

        if (!key)
        {
            fprintf(stderr, "Failed to read key\n");
            ERR_print_errors_fp(stderr);
            return -1;
        }
    }
    else
    {
        fprintf(stderr, "Key file required (-key or -newkey)\n");
        return -1;
    }

    /* Create CSR */
    printf("Creating certificate request...\n");

    req = X509_REQ_new();
    if (!req)
    {
        fprintf(stderr, "Failed to create request\n");
        EVP_PKEY_free(key);
        return -1;
    }

    /* Set version */
    X509_REQ_set_version(req, 0); /* Version 1 */

    /* Set subject */
    X509_NAME *name = X509_REQ_get_subject_name(req);
    if (parse_subject(name, g_subject) != 0)
    {
        fprintf(stderr, "Failed to parse subject\n");
        goto cleanup;
    }

    /* Set public key */
    if (X509_REQ_set_pubkey(req, key) != 1)
    {
        fprintf(stderr, "Failed to set public key\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    /* Add extensions (if SAN specified) */
    if (g_san)
    {
        STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();
        if (exts)
        {
            X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, NULL,
                                                      NID_subject_alt_name, (char *)g_san);
            if (ext)
            {
                sk_X509_EXTENSION_push(exts, ext);
                X509_REQ_add_extensions(req, exts);
            }
            sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
        }
    }

    /* Sign CSR */
    printf("Signing request with %s...\n", g_algorithm);

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx)
    {
        fprintf(stderr, "Failed to create signing context\n");
        goto cleanup;
    }

    if (EVP_DigestSignInit_ex(md_ctx, NULL, NULL, NULL, "provider=quac100", key, NULL) <= 0)
    {
        fprintf(stderr, "Failed to initialize signing\n");
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(md_ctx);
        goto cleanup;
    }

    /* Get the data to sign */
    unsigned char *tbs = NULL;
    int tbs_len = i2d_re_X509_REQ_tbs(req, &tbs);
    if (tbs_len <= 0)
    {
        fprintf(stderr, "Failed to encode TBS\n");
        EVP_MD_CTX_free(md_ctx);
        goto cleanup;
    }

    /* Sign */
    size_t sig_len = 0;
    if (EVP_DigestSign(md_ctx, NULL, &sig_len, tbs, tbs_len) <= 0)
    {
        fprintf(stderr, "Failed to get signature size\n");
        OPENSSL_free(tbs);
        EVP_MD_CTX_free(md_ctx);
        goto cleanup;
    }

    unsigned char *sig = OPENSSL_malloc(sig_len);
    if (!sig)
    {
        OPENSSL_free(tbs);
        EVP_MD_CTX_free(md_ctx);
        goto cleanup;
    }

    if (EVP_DigestSign(md_ctx, sig, &sig_len, tbs, tbs_len) <= 0)
    {
        fprintf(stderr, "Signing failed\n");
        ERR_print_errors_fp(stderr);
        OPENSSL_free(sig);
        OPENSSL_free(tbs);
        EVP_MD_CTX_free(md_ctx);
        goto cleanup;
    }

    OPENSSL_free(tbs);
    EVP_MD_CTX_free(md_ctx);

    /* Set signature in request */
    ASN1_BIT_STRING *sig_asn1 = X509_REQ_get0_signature(req);
    ASN1_BIT_STRING_set(sig_asn1, sig, sig_len);
    sig_asn1->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);

    OPENSSL_free(sig);

    /* Write CSR */
    FILE *of = fopen(g_output_file, "w");
    if (!of)
    {
        perror(g_output_file);
        goto cleanup;
    }

    if (PEM_write_X509_REQ(of, req) != 1)
    {
        fprintf(stderr, "Failed to write CSR\n");
        ERR_print_errors_fp(stderr);
        fclose(of);
        goto cleanup;
    }
    fclose(of);

    printf("CSR written to %s\n", g_output_file);

    /* Print info */
    if (g_verbose)
    {
        printf("\nRequest Details:\n");
        char *subject_str = X509_NAME_oneline(X509_REQ_get_subject_name(req), NULL, 0);
        printf("  Subject: %s\n", subject_str);
        OPENSSL_free(subject_str);
        printf("  Algorithm: %s\n", g_algorithm);
    }

    ret = 0;

cleanup:
    X509_REQ_free(req);
    EVP_PKEY_free(key);
    return ret;
}

/* ==========================================================================
 * Main
 * ========================================================================== */

static void usage(const char *prog)
{
    printf("QUAC 100 Certificate Request Tool\n\n");
    printf("Usage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -new                   Create new CSR\n");
    printf("  -newkey                Generate new key (implies -new)\n");
    printf("  -key <file>            Private key file\n");
    printf("  -keyout <file>         Key output file (default: key.pem)\n");
    printf("  -out <file>            CSR output file (default: request.pem)\n");
    printf("  -subj <subject>        Subject DN (e.g., \"CN=example.com,O=MyOrg\")\n");
    printf("  -addext <san>          Subject Alternative Names\n");
    printf("  -a, --algorithm <alg>  Algorithm: ML-DSA-44, ML-DSA-65, ML-DSA-87 (default: ML-DSA-65)\n");
    printf("  -v, --verbose          Verbose output\n");
    printf("  -h, --help             Show this help\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -newkey -out req.pem -subj \"CN=server.example.com\"\n", prog);
    printf("  %s -new -key existing.pem -out req.pem -subj \"CN=client\"\n", prog);
    printf("  %s -newkey -subj \"CN=www\" -addext \"DNS:www.example.com,DNS:example.com\"\n", prog);
}

int main(int argc, char *argv[])
{
    int opt;
    int new_csr = 0;

    static struct option long_opts[] = {
        {"new", no_argument, 0, 'n'},
        {"newkey", no_argument, 0, 'N'},
        {"key", required_argument, 0, 'k'},
        {"keyout", required_argument, 0, 'K'},
        {"out", required_argument, 0, 'o'},
        {"subj", required_argument, 0, 's'},
        {"addext", required_argument, 0, 'e'},
        {"algorithm", required_argument, 0, 'a'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}};

    while ((opt = getopt_long(argc, argv, "nNk:K:o:s:e:a:vh", long_opts, NULL)) != -1)
    {
        switch (opt)
        {
        case 'n':
            new_csr = 1;
            break;
        case 'N':
            g_newkey = 1;
            new_csr = 1;
            break;
        case 'k':
            g_key_file = optarg;
            break;
        case 'K':
            g_newkey_file = optarg;
            break;
        case 'o':
            g_output_file = optarg;
            break;
        case 's':
            g_subject = optarg;
            break;
        case 'e':
            g_san = optarg;
            break;
        case 'a':
            g_algorithm = optarg;
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

    if (!new_csr && !g_newkey)
    {
        fprintf(stderr, "Error: -new or -newkey required\n\n");
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

    int ret = generate_csr();

    OSSL_PROVIDER_unload(prov);
    return ret == 0 ? 0 : 1;
}