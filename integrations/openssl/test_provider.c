/**
 * @file test_provider.c
 * @brief QUAC 100 OpenSSL Provider Test Program
 *
 * Comprehensive tests for the QUAC 100 OpenSSL provider including:
 * - Provider loading
 * - ML-KEM key generation, encapsulation, decapsulation
 * - ML-DSA key generation, signing, verification
 * - QRNG random number generation
 *
 * Compile: gcc -o test_provider test_provider.c -lssl -lcrypto
 * Run: ./test_provider [provider_path]
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/core_names.h>

/* Test result tracking */
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_PASS(name)           \
    do                            \
    {                             \
        printf("  ✓ %s\n", name); \
        tests_passed++;           \
    } while (0)

#define TEST_FAIL(name, reason)               \
    do                                        \
    {                                         \
        printf("  ✗ %s: %s\n", name, reason); \
        tests_failed++;                       \
    } while (0)

/* Print OpenSSL errors */
static void print_errors(void)
{
    unsigned long err;
    while ((err = ERR_get_error()) != 0)
    {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        fprintf(stderr, "    OpenSSL error: %s\n", buf);
    }
}

/* ==========================================================================
 * Provider Loading Test
 * ========================================================================== */

static OSSL_PROVIDER *test_provider_load(const char *provider_path)
{
    OSSL_PROVIDER *prov;

    printf("\n[Provider Loading]\n");

    /* Set module path if provided */
    if (provider_path)
    {
        OSSL_PROVIDER_set_default_search_path(NULL, provider_path);
    }

    /* Load the provider */
    prov = OSSL_PROVIDER_load(NULL, "quac100");
    if (prov == NULL)
    {
        TEST_FAIL("Load provider", "OSSL_PROVIDER_load failed");
        print_errors();
        return NULL;
    }
    TEST_PASS("Load provider");

    /* Verify provider is available */
    if (!OSSL_PROVIDER_available(NULL, "quac100"))
    {
        TEST_FAIL("Provider available", "Provider not available after load");
        OSSL_PROVIDER_unload(prov);
        return NULL;
    }
    TEST_PASS("Provider available");

    return prov;
}

/* ==========================================================================
 * ML-KEM Tests
 * ========================================================================== */

static int test_mlkem(const char *alg_name)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned char *ct = NULL, *ss1 = NULL, *ss2 = NULL;
    size_t ct_len = 0, ss1_len = 0, ss2_len = 0;
    int ret = 0;
    char test_name[64];

    printf("\n[%s Tests]\n", alg_name);

    /* Key generation */
    ctx = EVP_PKEY_CTX_new_from_name(NULL, alg_name, "provider=quac100");
    if (ctx == NULL)
    {
        snprintf(test_name, sizeof(test_name), "%s CTX create", alg_name);
        TEST_FAIL(test_name, "EVP_PKEY_CTX_new_from_name failed");
        print_errors();
        goto cleanup;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        snprintf(test_name, sizeof(test_name), "%s keygen init", alg_name);
        TEST_FAIL(test_name, "EVP_PKEY_keygen_init failed");
        print_errors();
        goto cleanup;
    }

    if (EVP_PKEY_generate(ctx, &pkey) <= 0)
    {
        snprintf(test_name, sizeof(test_name), "%s keygen", alg_name);
        TEST_FAIL(test_name, "EVP_PKEY_generate failed");
        print_errors();
        goto cleanup;
    }
    snprintf(test_name, sizeof(test_name), "%s keygen", alg_name);
    TEST_PASS(test_name);

    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    /* Encapsulation */
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, "provider=quac100");
    if (ctx == NULL)
    {
        snprintf(test_name, sizeof(test_name), "%s encaps CTX", alg_name);
        TEST_FAIL(test_name, "EVP_PKEY_CTX_new_from_pkey failed");
        goto cleanup;
    }

    if (EVP_PKEY_encapsulate_init(ctx, NULL) <= 0)
    {
        snprintf(test_name, sizeof(test_name), "%s encaps init", alg_name);
        TEST_FAIL(test_name, "EVP_PKEY_encapsulate_init failed");
        print_errors();
        goto cleanup;
    }

    /* Get sizes */
    if (EVP_PKEY_encapsulate(ctx, NULL, &ct_len, NULL, &ss1_len) <= 0)
    {
        snprintf(test_name, sizeof(test_name), "%s encaps size", alg_name);
        TEST_FAIL(test_name, "EVP_PKEY_encapsulate (size) failed");
        print_errors();
        goto cleanup;
    }

    ct = OPENSSL_malloc(ct_len);
    ss1 = OPENSSL_malloc(ss1_len);
    if (ct == NULL || ss1 == NULL)
    {
        TEST_FAIL("Memory allocation", "malloc failed");
        goto cleanup;
    }

    if (EVP_PKEY_encapsulate(ctx, ct, &ct_len, ss1, &ss1_len) <= 0)
    {
        snprintf(test_name, sizeof(test_name), "%s encaps", alg_name);
        TEST_FAIL(test_name, "EVP_PKEY_encapsulate failed");
        print_errors();
        goto cleanup;
    }
    snprintf(test_name, sizeof(test_name), "%s encaps (ct=%zu, ss=%zu)", alg_name, ct_len, ss1_len);
    TEST_PASS(test_name);

    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    /* Decapsulation */
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, "provider=quac100");
    if (ctx == NULL)
    {
        snprintf(test_name, sizeof(test_name), "%s decaps CTX", alg_name);
        TEST_FAIL(test_name, "EVP_PKEY_CTX_new_from_pkey failed");
        goto cleanup;
    }

    if (EVP_PKEY_decapsulate_init(ctx, NULL) <= 0)
    {
        snprintf(test_name, sizeof(test_name), "%s decaps init", alg_name);
        TEST_FAIL(test_name, "EVP_PKEY_decapsulate_init failed");
        print_errors();
        goto cleanup;
    }

    /* Get size */
    if (EVP_PKEY_decapsulate(ctx, NULL, &ss2_len, ct, ct_len) <= 0)
    {
        snprintf(test_name, sizeof(test_name), "%s decaps size", alg_name);
        TEST_FAIL(test_name, "EVP_PKEY_decapsulate (size) failed");
        print_errors();
        goto cleanup;
    }

    ss2 = OPENSSL_malloc(ss2_len);
    if (ss2 == NULL)
    {
        TEST_FAIL("Memory allocation", "malloc failed");
        goto cleanup;
    }

    if (EVP_PKEY_decapsulate(ctx, ss2, &ss2_len, ct, ct_len) <= 0)
    {
        snprintf(test_name, sizeof(test_name), "%s decaps", alg_name);
        TEST_FAIL(test_name, "EVP_PKEY_decapsulate failed");
        print_errors();
        goto cleanup;
    }
    snprintf(test_name, sizeof(test_name), "%s decaps", alg_name);
    TEST_PASS(test_name);

    /* Verify shared secrets match */
    if (ss1_len != ss2_len || memcmp(ss1, ss2, ss1_len) != 0)
    {
        snprintf(test_name, sizeof(test_name), "%s shared secret match", alg_name);
        TEST_FAIL(test_name, "Shared secrets don't match");
        goto cleanup;
    }
    snprintf(test_name, sizeof(test_name), "%s shared secret match", alg_name);
    TEST_PASS(test_name);

    ret = 1;

cleanup:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    OPENSSL_free(ct);
    OPENSSL_free(ss1);
    OPENSSL_free(ss2);
    return ret;
}

/* ==========================================================================
 * ML-DSA Tests
 * ========================================================================== */

static int test_mldsa(const char *alg_name)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    unsigned char *sig = NULL;
    size_t sig_len = 0;
    const unsigned char msg[] = "Test message for ML-DSA signature verification";
    size_t msg_len = sizeof(msg) - 1;
    int ret = 0;
    char test_name[64];

    printf("\n[%s Tests]\n", alg_name);

    /* Key generation */
    ctx = EVP_PKEY_CTX_new_from_name(NULL, alg_name, "provider=quac100");
    if (ctx == NULL)
    {
        snprintf(test_name, sizeof(test_name), "%s CTX create", alg_name);
        TEST_FAIL(test_name, "EVP_PKEY_CTX_new_from_name failed");
        print_errors();
        goto cleanup;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        snprintf(test_name, sizeof(test_name), "%s keygen init", alg_name);
        TEST_FAIL(test_name, "EVP_PKEY_keygen_init failed");
        print_errors();
        goto cleanup;
    }

    if (EVP_PKEY_generate(ctx, &pkey) <= 0)
    {
        snprintf(test_name, sizeof(test_name), "%s keygen", alg_name);
        TEST_FAIL(test_name, "EVP_PKEY_generate failed");
        print_errors();
        goto cleanup;
    }
    snprintf(test_name, sizeof(test_name), "%s keygen", alg_name);
    TEST_PASS(test_name);

    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    /* Signing */
    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
    {
        TEST_FAIL("MD CTX create", "EVP_MD_CTX_new failed");
        goto cleanup;
    }

    if (EVP_DigestSignInit_ex(mdctx, NULL, NULL, NULL, "provider=quac100", pkey, NULL) <= 0)
    {
        snprintf(test_name, sizeof(test_name), "%s sign init", alg_name);
        TEST_FAIL(test_name, "EVP_DigestSignInit_ex failed");
        print_errors();
        goto cleanup;
    }

    /* Get signature size */
    if (EVP_DigestSign(mdctx, NULL, &sig_len, msg, msg_len) <= 0)
    {
        snprintf(test_name, sizeof(test_name), "%s sign size", alg_name);
        TEST_FAIL(test_name, "EVP_DigestSign (size) failed");
        print_errors();
        goto cleanup;
    }

    sig = OPENSSL_malloc(sig_len);
    if (sig == NULL)
    {
        TEST_FAIL("Memory allocation", "malloc failed");
        goto cleanup;
    }

    if (EVP_DigestSign(mdctx, sig, &sig_len, msg, msg_len) <= 0)
    {
        snprintf(test_name, sizeof(test_name), "%s sign", alg_name);
        TEST_FAIL(test_name, "EVP_DigestSign failed");
        print_errors();
        goto cleanup;
    }
    snprintf(test_name, sizeof(test_name), "%s sign (sig=%zu bytes)", alg_name, sig_len);
    TEST_PASS(test_name);

    EVP_MD_CTX_free(mdctx);
    mdctx = NULL;

    /* Verification */
    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL)
    {
        TEST_FAIL("MD CTX create", "EVP_MD_CTX_new failed");
        goto cleanup;
    }

    if (EVP_DigestVerifyInit_ex(mdctx, NULL, NULL, NULL, "provider=quac100", pkey, NULL) <= 0)
    {
        snprintf(test_name, sizeof(test_name), "%s verify init", alg_name);
        TEST_FAIL(test_name, "EVP_DigestVerifyInit_ex failed");
        print_errors();
        goto cleanup;
    }

    if (EVP_DigestVerify(mdctx, sig, sig_len, msg, msg_len) <= 0)
    {
        snprintf(test_name, sizeof(test_name), "%s verify", alg_name);
        TEST_FAIL(test_name, "EVP_DigestVerify failed");
        print_errors();
        goto cleanup;
    }
    snprintf(test_name, sizeof(test_name), "%s verify", alg_name);
    TEST_PASS(test_name);

    /* Test tampering detection */
    unsigned char tampered_msg[] = "Tampered message for ML-DSA signature verification";
    EVP_MD_CTX_free(mdctx);
    mdctx = EVP_MD_CTX_new();

    if (EVP_DigestVerifyInit_ex(mdctx, NULL, NULL, NULL, "provider=quac100", pkey, NULL) <= 0)
    {
        TEST_FAIL("Tamper verify init", "EVP_DigestVerifyInit_ex failed");
        goto cleanup;
    }

    if (EVP_DigestVerify(mdctx, sig, sig_len, tampered_msg, sizeof(tampered_msg) - 1) > 0)
    {
        snprintf(test_name, sizeof(test_name), "%s tamper detection", alg_name);
        TEST_FAIL(test_name, "Tampered message verified (should fail)");
        goto cleanup;
    }
    snprintf(test_name, sizeof(test_name), "%s tamper detection", alg_name);
    TEST_PASS(test_name);

    ret = 1;

cleanup:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(mdctx);
    OPENSSL_free(sig);
    return ret;
}

/* ==========================================================================
 * QRNG Tests
 * ========================================================================== */

static int test_qrng(void)
{
    unsigned char buf1[32], buf2[32], buf3[1024];
    int ret = 0;

    printf("\n[QRNG Tests]\n");

    /* Generate random bytes */
    if (RAND_bytes(buf1, sizeof(buf1)) != 1)
    {
        TEST_FAIL("RAND_bytes 32", "Generation failed");
        print_errors();
        goto cleanup;
    }
    TEST_PASS("RAND_bytes 32 bytes");

    /* Generate again - should be different */
    if (RAND_bytes(buf2, sizeof(buf2)) != 1)
    {
        TEST_FAIL("RAND_bytes 32 (2)", "Generation failed");
        goto cleanup;
    }

    if (memcmp(buf1, buf2, sizeof(buf1)) == 0)
    {
        TEST_FAIL("Randomness check", "Two random blocks identical");
        goto cleanup;
    }
    TEST_PASS("Randomness check (blocks differ)");

    /* Generate larger block */
    if (RAND_bytes(buf3, sizeof(buf3)) != 1)
    {
        TEST_FAIL("RAND_bytes 1024", "Generation failed");
        goto cleanup;
    }
    TEST_PASS("RAND_bytes 1024 bytes");

    /* Basic entropy check - not all zeros or all ones */
    int zeros = 0, ones = 0;
    for (size_t i = 0; i < sizeof(buf3); i++)
    {
        if (buf3[i] == 0x00)
            zeros++;
        if (buf3[i] == 0xFF)
            ones++;
    }

    if (zeros > sizeof(buf3) / 4 || ones > sizeof(buf3) / 4)
    {
        TEST_FAIL("Entropy check", "Too many zeros or ones");
        goto cleanup;
    }
    TEST_PASS("Basic entropy check");

    ret = 1;

cleanup:
    OPENSSL_cleanse(buf1, sizeof(buf1));
    OPENSSL_cleanse(buf2, sizeof(buf2));
    OPENSSL_cleanse(buf3, sizeof(buf3));
    return ret;
}

/* ==========================================================================
 * Main
 * ========================================================================== */

int main(int argc, char *argv[])
{
    OSSL_PROVIDER *prov = NULL;
    OSSL_PROVIDER *dflt = NULL;
    const char *provider_path = NULL;
    int exit_code = 1;

    printf("=================================================\n");
    printf("QUAC 100 OpenSSL Provider Test Suite\n");
    printf("=================================================\n");

    /* Parse arguments */
    if (argc > 1)
    {
        provider_path = argv[1];
        printf("Provider path: %s\n", provider_path);
    }

    /* Load default provider (for fallback operations) */
    dflt = OSSL_PROVIDER_load(NULL, "default");
    if (dflt == NULL)
    {
        fprintf(stderr, "Warning: Failed to load default provider\n");
    }

    /* Load QUAC 100 provider */
    prov = test_provider_load(provider_path);
    if (prov == NULL)
    {
        fprintf(stderr, "Failed to load QUAC 100 provider\n");
        goto cleanup;
    }

    /* Run ML-KEM tests */
    test_mlkem("ML-KEM-512");
    test_mlkem("ML-KEM-768");
    test_mlkem("ML-KEM-1024");

    /* Run ML-DSA tests */
    test_mldsa("ML-DSA-44");
    test_mldsa("ML-DSA-65");
    test_mldsa("ML-DSA-87");

    /* Run QRNG tests */
    test_qrng();

    /* Summary */
    printf("\n=================================================\n");
    printf("Test Summary\n");
    printf("=================================================\n");
    printf("  Passed: %d\n", tests_passed);
    printf("  Failed: %d\n", tests_failed);
    printf("  Total:  %d\n", tests_passed + tests_failed);
    printf("=================================================\n");

    exit_code = (tests_failed == 0) ? 0 : 1;

cleanup:
    if (prov)
        OSSL_PROVIDER_unload(prov);
    if (dflt)
        OSSL_PROVIDER_unload(dflt);

    return exit_code;
}