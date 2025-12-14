/**
 * @file test_quac100_boringssl.c
 * @brief QUAC 100 BoringSSL Integration - Test Suite
 *
 * Comprehensive tests for all QUAC 100 functionality.
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "quac100_boringssl.h"

/* ==========================================================================
 * Test Framework
 * ========================================================================== */

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_ASSERT(cond, msg)                               \
    do                                                       \
    {                                                        \
        if (!(cond))                                         \
        {                                                    \
            printf("  FAIL: %s (line %d)\n", msg, __LINE__); \
            return 0;                                        \
        }                                                    \
    } while (0)

#define RUN_TEST(test_func)                  \
    do                                       \
    {                                        \
        printf("Running: %s\n", #test_func); \
        tests_run++;                         \
        if (test_func())                     \
        {                                    \
            tests_passed++;                  \
            printf("  PASS\n");              \
        }                                    \
        else                                 \
        {                                    \
            tests_failed++;                  \
        }                                    \
    } while (0)

/* ==========================================================================
 * Initialization Tests
 * ========================================================================== */

static int test_init(void)
{
    int ret;

    /* Test basic init */
    ret = QUAC_init();
    TEST_ASSERT(ret == QUAC_SUCCESS, "QUAC_init failed");

    /* Test double init (should succeed) */
    ret = QUAC_init();
    TEST_ASSERT(ret == QUAC_SUCCESS, "Double init failed");

    /* Cleanup */
    QUAC_cleanup();

    /* Re-init after cleanup */
    ret = QUAC_init();
    TEST_ASSERT(ret == QUAC_SUCCESS, "Re-init after cleanup failed");

    return 1;
}

static int test_version(void)
{
    const char *version = QUAC_version_string();

    TEST_ASSERT(version != NULL, "Version string is NULL");
    TEST_ASSERT(strlen(version) > 0, "Version string is empty");
    TEST_ASSERT(strstr(version, ".") != NULL, "Version missing dot separator");

    printf("  Version: %s\n", version);

    return 1;
}

/* ==========================================================================
 * ML-KEM Tests
 * ========================================================================== */

static int test_mlkem_sizes(void)
{
    /* ML-KEM-512 */
    TEST_ASSERT(QUAC_KEM_public_key_bytes(QUAC_KEM_ML_KEM_512) == 800,
                "ML-KEM-512 public key size wrong");
    TEST_ASSERT(QUAC_KEM_secret_key_bytes(QUAC_KEM_ML_KEM_512) == 1632,
                "ML-KEM-512 secret key size wrong");
    TEST_ASSERT(QUAC_KEM_ciphertext_bytes(QUAC_KEM_ML_KEM_512) == 768,
                "ML-KEM-512 ciphertext size wrong");
    TEST_ASSERT(QUAC_KEM_shared_secret_bytes(QUAC_KEM_ML_KEM_512) == 32,
                "ML-KEM-512 shared secret size wrong");

    /* ML-KEM-768 */
    TEST_ASSERT(QUAC_KEM_public_key_bytes(QUAC_KEM_ML_KEM_768) == 1184,
                "ML-KEM-768 public key size wrong");
    TEST_ASSERT(QUAC_KEM_secret_key_bytes(QUAC_KEM_ML_KEM_768) == 2400,
                "ML-KEM-768 secret key size wrong");
    TEST_ASSERT(QUAC_KEM_ciphertext_bytes(QUAC_KEM_ML_KEM_768) == 1088,
                "ML-KEM-768 ciphertext size wrong");

    /* ML-KEM-1024 */
    TEST_ASSERT(QUAC_KEM_public_key_bytes(QUAC_KEM_ML_KEM_1024) == 1568,
                "ML-KEM-1024 public key size wrong");
    TEST_ASSERT(QUAC_KEM_secret_key_bytes(QUAC_KEM_ML_KEM_1024) == 3168,
                "ML-KEM-1024 secret key size wrong");
    TEST_ASSERT(QUAC_KEM_ciphertext_bytes(QUAC_KEM_ML_KEM_1024) == 1568,
                "ML-KEM-1024 ciphertext size wrong");

    return 1;
}

static int test_mlkem_keypair(void)
{
    uint8_t pk[QUAC_ML_KEM_768_PUBLIC_KEY_BYTES];
    uint8_t sk[QUAC_ML_KEM_768_SECRET_KEY_BYTES];
    int ret;

    ret = QUAC_KEM_keypair(QUAC_KEM_ML_KEM_768, pk, sk);
    TEST_ASSERT(ret == QUAC_SUCCESS, "ML-KEM-768 keypair generation failed");

    /* Verify keys are not all zeros */
    int pk_nonzero = 0, sk_nonzero = 0;
    for (size_t i = 0; i < sizeof(pk); i++)
    {
        if (pk[i] != 0)
            pk_nonzero = 1;
    }
    for (size_t i = 0; i < sizeof(sk); i++)
    {
        if (sk[i] != 0)
            sk_nonzero = 1;
    }

    TEST_ASSERT(pk_nonzero, "Public key is all zeros");
    TEST_ASSERT(sk_nonzero, "Secret key is all zeros");

    return 1;
}

static int test_mlkem_roundtrip(void)
{
    uint8_t pk[QUAC_ML_KEM_768_PUBLIC_KEY_BYTES];
    uint8_t sk[QUAC_ML_KEM_768_SECRET_KEY_BYTES];
    uint8_t ct[QUAC_ML_KEM_768_CIPHERTEXT_BYTES];
    uint8_t ss1[QUAC_ML_KEM_768_SHARED_SECRET_BYTES];
    uint8_t ss2[QUAC_ML_KEM_768_SHARED_SECRET_BYTES];
    int ret;

    /* Generate keypair */
    ret = QUAC_KEM_keypair(QUAC_KEM_ML_KEM_768, pk, sk);
    TEST_ASSERT(ret == QUAC_SUCCESS, "Keypair generation failed");

    /* Encapsulate */
    ret = QUAC_KEM_encaps(QUAC_KEM_ML_KEM_768, ct, ss1, pk);
    TEST_ASSERT(ret == QUAC_SUCCESS, "Encapsulation failed");

    /* Decapsulate */
    ret = QUAC_KEM_decaps(QUAC_KEM_ML_KEM_768, ss2, ct, sk);
    TEST_ASSERT(ret == QUAC_SUCCESS, "Decapsulation failed");

    /* Shared secrets should match */
    TEST_ASSERT(memcmp(ss1, ss2, sizeof(ss1)) == 0,
                "Shared secrets don't match");

    return 1;
}

static int test_mlkem_all_variants(void)
{
    quac_kem_algorithm_t algs[] = {
        QUAC_KEM_ML_KEM_512,
        QUAC_KEM_ML_KEM_768,
        QUAC_KEM_ML_KEM_1024};
    const char *names[] = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"};

    for (int i = 0; i < 3; i++)
    {
        size_t pk_len = QUAC_KEM_public_key_bytes(algs[i]);
        size_t sk_len = QUAC_KEM_secret_key_bytes(algs[i]);
        size_t ct_len = QUAC_KEM_ciphertext_bytes(algs[i]);

        uint8_t *pk = malloc(pk_len);
        uint8_t *sk = malloc(sk_len);
        uint8_t *ct = malloc(ct_len);
        uint8_t ss1[32], ss2[32];

        int ret = QUAC_KEM_keypair(algs[i], pk, sk);
        if (ret != QUAC_SUCCESS)
        {
            printf("  %s keypair failed\n", names[i]);
            free(pk);
            free(sk);
            free(ct);
            return 0;
        }

        ret = QUAC_KEM_encaps(algs[i], ct, ss1, pk);
        if (ret != QUAC_SUCCESS)
        {
            printf("  %s encaps failed\n", names[i]);
            free(pk);
            free(sk);
            free(ct);
            return 0;
        }

        ret = QUAC_KEM_decaps(algs[i], ss2, ct, sk);
        if (ret != QUAC_SUCCESS)
        {
            printf("  %s decaps failed\n", names[i]);
            free(pk);
            free(sk);
            free(ct);
            return 0;
        }

        if (memcmp(ss1, ss2, 32) != 0)
        {
            printf("  %s shared secret mismatch\n", names[i]);
            free(pk);
            free(sk);
            free(ct);
            return 0;
        }

        printf("  %s: OK\n", names[i]);

        free(pk);
        free(sk);
        free(ct);
    }

    return 1;
}

/* ==========================================================================
 * ML-DSA Tests
 * ========================================================================== */

static int test_mldsa_sizes(void)
{
    /* ML-DSA-44 */
    TEST_ASSERT(QUAC_SIG_public_key_bytes(QUAC_SIG_ML_DSA_44) == 1312,
                "ML-DSA-44 public key size wrong");
    TEST_ASSERT(QUAC_SIG_secret_key_bytes(QUAC_SIG_ML_DSA_44) == 2560,
                "ML-DSA-44 secret key size wrong");
    TEST_ASSERT(QUAC_SIG_signature_bytes(QUAC_SIG_ML_DSA_44) == 2420,
                "ML-DSA-44 signature size wrong");

    /* ML-DSA-65 */
    TEST_ASSERT(QUAC_SIG_public_key_bytes(QUAC_SIG_ML_DSA_65) == 1952,
                "ML-DSA-65 public key size wrong");
    TEST_ASSERT(QUAC_SIG_secret_key_bytes(QUAC_SIG_ML_DSA_65) == 4032,
                "ML-DSA-65 secret key size wrong");
    TEST_ASSERT(QUAC_SIG_signature_bytes(QUAC_SIG_ML_DSA_65) == 3309,
                "ML-DSA-65 signature size wrong");

    /* ML-DSA-87 */
    TEST_ASSERT(QUAC_SIG_public_key_bytes(QUAC_SIG_ML_DSA_87) == 2592,
                "ML-DSA-87 public key size wrong");
    TEST_ASSERT(QUAC_SIG_secret_key_bytes(QUAC_SIG_ML_DSA_87) == 4896,
                "ML-DSA-87 secret key size wrong");
    TEST_ASSERT(QUAC_SIG_signature_bytes(QUAC_SIG_ML_DSA_87) == 4627,
                "ML-DSA-87 signature size wrong");

    return 1;
}

static int test_mldsa_keypair(void)
{
    uint8_t pk[QUAC_ML_DSA_65_PUBLIC_KEY_BYTES];
    uint8_t sk[QUAC_ML_DSA_65_SECRET_KEY_BYTES];
    int ret;

    ret = QUAC_SIG_keypair(QUAC_SIG_ML_DSA_65, pk, sk);
    TEST_ASSERT(ret == QUAC_SUCCESS, "ML-DSA-65 keypair generation failed");

    return 1;
}

static int test_mldsa_sign_verify(void)
{
    uint8_t pk[QUAC_ML_DSA_65_PUBLIC_KEY_BYTES];
    uint8_t sk[QUAC_ML_DSA_65_SECRET_KEY_BYTES];
    uint8_t sig[QUAC_ML_DSA_65_SIGNATURE_BYTES];
    size_t sig_len;
    int ret;

    const uint8_t msg[] = "Test message for ML-DSA signature";

    /* Generate keypair */
    ret = QUAC_SIG_keypair(QUAC_SIG_ML_DSA_65, pk, sk);
    TEST_ASSERT(ret == QUAC_SUCCESS, "Keypair generation failed");

    /* Sign */
    ret = QUAC_sign(QUAC_SIG_ML_DSA_65, sig, &sig_len, msg, sizeof(msg) - 1, sk);
    TEST_ASSERT(ret == QUAC_SUCCESS, "Signing failed");
    TEST_ASSERT(sig_len > 0, "Signature length is 0");

    /* Verify */
    ret = QUAC_verify(QUAC_SIG_ML_DSA_65, sig, sig_len, msg, sizeof(msg) - 1, pk);
    TEST_ASSERT(ret == QUAC_SUCCESS, "Verification failed");

    return 1;
}

static int test_mldsa_tamper_detection(void)
{
    uint8_t pk[QUAC_ML_DSA_65_PUBLIC_KEY_BYTES];
    uint8_t sk[QUAC_ML_DSA_65_SECRET_KEY_BYTES];
    uint8_t sig[QUAC_ML_DSA_65_SIGNATURE_BYTES];
    size_t sig_len;
    int ret;

    uint8_t msg[] = "Original message";

    /* Generate, sign, verify */
    QUAC_SIG_keypair(QUAC_SIG_ML_DSA_65, pk, sk);
    QUAC_sign(QUAC_SIG_ML_DSA_65, sig, &sig_len, msg, sizeof(msg) - 1, sk);

    /* Tamper with message */
    msg[0] ^= 0xFF;

    /* Verify should fail */
    ret = QUAC_verify(QUAC_SIG_ML_DSA_65, sig, sig_len, msg, sizeof(msg) - 1, pk);
    TEST_ASSERT(ret == QUAC_ERROR_VERIFICATION_FAILED,
                "Tampered message should fail verification");

    return 1;
}

static int test_mldsa_all_variants(void)
{
    quac_sig_algorithm_t algs[] = {
        QUAC_SIG_ML_DSA_44,
        QUAC_SIG_ML_DSA_65,
        QUAC_SIG_ML_DSA_87};
    const char *names[] = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"};

    const uint8_t msg[] = "Test message for all variants";

    for (int i = 0; i < 3; i++)
    {
        size_t pk_len = QUAC_SIG_public_key_bytes(algs[i]);
        size_t sk_len = QUAC_SIG_secret_key_bytes(algs[i]);
        size_t max_sig_len = QUAC_SIG_signature_bytes(algs[i]);

        uint8_t *pk = malloc(pk_len);
        uint8_t *sk = malloc(sk_len);
        uint8_t *sig = malloc(max_sig_len);
        size_t sig_len;

        int ret = QUAC_SIG_keypair(algs[i], pk, sk);
        if (ret != QUAC_SUCCESS)
        {
            printf("  %s keypair failed\n", names[i]);
            free(pk);
            free(sk);
            free(sig);
            return 0;
        }

        ret = QUAC_sign(algs[i], sig, &sig_len, msg, sizeof(msg) - 1, sk);
        if (ret != QUAC_SUCCESS)
        {
            printf("  %s sign failed\n", names[i]);
            free(pk);
            free(sk);
            free(sig);
            return 0;
        }

        ret = QUAC_verify(algs[i], sig, sig_len, msg, sizeof(msg) - 1, pk);
        if (ret != QUAC_SUCCESS)
        {
            printf("  %s verify failed\n", names[i]);
            free(pk);
            free(sk);
            free(sig);
            return 0;
        }

        printf("  %s: OK (sig_len=%zu)\n", names[i], sig_len);

        free(pk);
        free(sk);
        free(sig);
    }

    return 1;
}

/* ==========================================================================
 * QRNG Tests
 * ========================================================================== */

static int test_qrng_basic(void)
{
    uint8_t buf[64];
    int ret;

    memset(buf, 0, sizeof(buf));

    ret = QUAC_random_bytes(buf, sizeof(buf));
    TEST_ASSERT(ret == QUAC_SUCCESS, "QUAC_random_bytes failed");

    /* Check that buffer was modified */
    int nonzero = 0;
    for (size_t i = 0; i < sizeof(buf); i++)
    {
        if (buf[i] != 0)
            nonzero = 1;
    }
    TEST_ASSERT(nonzero, "Random buffer is all zeros");

    return 1;
}

static int test_qrng_uniqueness(void)
{
    uint8_t buf1[32], buf2[32];

    QUAC_random_bytes(buf1, sizeof(buf1));
    QUAC_random_bytes(buf2, sizeof(buf2));

    TEST_ASSERT(memcmp(buf1, buf2, sizeof(buf1)) != 0,
                "Two random generations produced identical results");

    return 1;
}

static int test_qrng_health(void)
{
    int healthy = QUAC_random_health_check();
    TEST_ASSERT(healthy == 0 || healthy == 1, "Invalid health status");

    printf("  Health status: %s\n", healthy ? "OK" : "DEGRADED");

    return 1;
}

/* ==========================================================================
 * Self-Test
 * ========================================================================== */

static int test_self_test(void)
{
    int ret = QUAC_self_test();
    TEST_ASSERT(ret == QUAC_SUCCESS, "Self-test failed");

    return 1;
}

/* ==========================================================================
 * Error Handling Tests
 * ========================================================================== */

static int test_error_strings(void)
{
    const char *err;

    err = QUAC_get_error_string(QUAC_SUCCESS);
    TEST_ASSERT(err != NULL && strlen(err) > 0, "SUCCESS error string missing");

    err = QUAC_get_error_string(QUAC_ERROR_INVALID_ALGORITHM);
    TEST_ASSERT(err != NULL && strlen(err) > 0, "Error string missing");

    err = QUAC_get_error_string(-999); /* Unknown error */
    TEST_ASSERT(err != NULL, "Unknown error returns NULL");

    return 1;
}

static int test_invalid_params(void)
{
    int ret;

    /* NULL parameters */
    ret = QUAC_KEM_keypair(QUAC_KEM_ML_KEM_768, NULL, NULL);
    TEST_ASSERT(ret != QUAC_SUCCESS, "NULL params should fail");

    /* Invalid algorithm */
    uint8_t pk[2592], sk[4896];
    ret = QUAC_KEM_keypair((quac_kem_algorithm_t)99, pk, sk);
    TEST_ASSERT(ret == QUAC_ERROR_INVALID_ALGORITHM, "Invalid alg should fail");

    return 1;
}

/* ==========================================================================
 * Main
 * ========================================================================== */

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    printf("=== QUAC 100 BoringSSL Integration Test Suite ===\n");
    printf("Version: %s\n", QUAC_BORINGSSL_VERSION_STRING);
    printf("Hardware: %s\n\n", QUAC_is_hardware_available() ? "Yes" : "No (simulator)");

    /* Initialize */
    int ret = QUAC_init();
    if (ret != QUAC_SUCCESS)
    {
        printf("FATAL: QUAC_init failed: %s\n", QUAC_get_error_string(ret));
        return 1;
    }

    /* Run tests */
    printf("\n--- Initialization Tests ---\n");
    RUN_TEST(test_init);
    RUN_TEST(test_version);

    /* Re-init for remaining tests */
    QUAC_init();

    printf("\n--- ML-KEM Tests ---\n");
    RUN_TEST(test_mlkem_sizes);
    RUN_TEST(test_mlkem_keypair);
    RUN_TEST(test_mlkem_roundtrip);
    RUN_TEST(test_mlkem_all_variants);

    printf("\n--- ML-DSA Tests ---\n");
    RUN_TEST(test_mldsa_sizes);
    RUN_TEST(test_mldsa_keypair);
    RUN_TEST(test_mldsa_sign_verify);
    RUN_TEST(test_mldsa_tamper_detection);
    RUN_TEST(test_mldsa_all_variants);

    printf("\n--- QRNG Tests ---\n");
    RUN_TEST(test_qrng_basic);
    RUN_TEST(test_qrng_uniqueness);
    RUN_TEST(test_qrng_health);

    printf("\n--- Self-Test ---\n");
    RUN_TEST(test_self_test);

    printf("\n--- Error Handling Tests ---\n");
    RUN_TEST(test_error_strings);
    RUN_TEST(test_invalid_params);

    /* Summary */
    printf("\n=== Test Summary ===\n");
    printf("Total:  %d\n", tests_run);
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);

    QUAC_cleanup();

    return (tests_failed == 0) ? 0 : 1;
}