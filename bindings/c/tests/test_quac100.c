/**
 * @file test_quac100.c
 * @brief QUAC 100 SDK - Comprehensive Test Suite
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 */

#include <quac100/quac100.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*============================================================================
 * Test Framework
 *============================================================================*/

static int g_tests_run = 0;
static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define TEST_ASSERT(expr)                                      \
    do                                                         \
    {                                                          \
        if (!(expr))                                           \
        {                                                      \
            printf("  FAIL: %s (line %d)\n", #expr, __LINE__); \
            return 0;                                          \
        }                                                      \
    } while (0)

#define TEST_ASSERT_EQ(a, b)                                            \
    do                                                                  \
    {                                                                   \
        if ((a) != (b))                                                 \
        {                                                               \
            printf("  FAIL: %s == %s (got %d, expected %d, line %d)\n", \
                   #a, #b, (int)(a), (int)(b), __LINE__);               \
            return 0;                                                   \
        }                                                               \
    } while (0)

#define TEST_ASSERT_STATUS(status)                                \
    do                                                            \
    {                                                             \
        if ((status) != QUAC_SUCCESS)                             \
        {                                                         \
            printf("  FAIL: %s returned %s (line %d)\n",          \
                   #status, quac_error_string(status), __LINE__); \
            return 0;                                             \
        }                                                         \
    } while (0)

#define RUN_TEST(test_func)                    \
    do                                         \
    {                                          \
        printf("Running %s...\n", #test_func); \
        g_tests_run++;                         \
        if (test_func())                       \
        {                                      \
            g_tests_passed++;                  \
            printf("  PASS\n");                \
        }                                      \
        else                                   \
        {                                      \
            g_tests_failed++;                  \
        }                                      \
    } while (0)

/*============================================================================
 * Global Device Handle
 *============================================================================*/

static quac_device_t g_device = NULL;

/*============================================================================
 * Library Tests
 *============================================================================*/

int test_version(void)
{
    const char *ver = quac_version();
    TEST_ASSERT(ver != NULL);
    TEST_ASSERT(strlen(ver) > 0);
    printf("  Version: %s\n", ver);

    int major, minor, patch;
    quac_status_t status = quac_version_info(&major, &minor, &patch);
    TEST_ASSERT_STATUS(status);
    TEST_ASSERT(major >= 0);
    TEST_ASSERT(minor >= 0);
    TEST_ASSERT(patch >= 0);
    printf("  Version info: %d.%d.%d\n", major, minor, patch);

    const char *build = quac_build_info();
    TEST_ASSERT(build != NULL);
    printf("  Build info:\n%s", build);

    return 1;
}

int test_init_cleanup(void)
{
    TEST_ASSERT(quac_is_initialized());
    return 1;
}

int test_error_strings(void)
{
    const char *msg;

    msg = quac_error_string(QUAC_SUCCESS);
    TEST_ASSERT(msg != NULL);
    TEST_ASSERT(strcmp(msg, "Success") == 0);

    msg = quac_error_string(QUAC_ERROR_DEVICE_NOT_FOUND);
    TEST_ASSERT(msg != NULL);
    TEST_ASSERT(strstr(msg, "not found") != NULL);

    msg = quac_error_string(QUAC_ERROR_VERIFY_FAILED);
    TEST_ASSERT(msg != NULL);
    TEST_ASSERT(strstr(msg, "erif") != NULL); /* Verify or verification */

    return 1;
}

/*============================================================================
 * Device Tests
 *============================================================================*/

int test_enumerate_devices(void)
{
    quac_device_info_t devices[QUAC_MAX_DEVICES];
    int count;

    quac_status_t status = quac_enumerate_devices(devices, QUAC_MAX_DEVICES, &count);
    TEST_ASSERT_STATUS(status);
    TEST_ASSERT(count >= 0);

    printf("  Found %d device(s)\n", count);

    if (count > 0)
    {
        printf("  Device 0: %s (S/N: %s)\n",
               devices[0].model_name, devices[0].serial_number);
    }

    return 1;
}

int test_device_open_close(void)
{
    TEST_ASSERT(g_device != NULL);
    TEST_ASSERT(quac_device_is_open(g_device));

    int idx = quac_get_device_index(g_device);
    TEST_ASSERT(idx >= 0);

    return 1;
}

int test_device_info(void)
{
    quac_device_info_t info;
    quac_status_t status = quac_get_device_info(g_device, &info);
    TEST_ASSERT_STATUS(status);

    printf("  Model: %s\n", info.model_name);
    printf("  Serial: %s\n", info.serial_number);
    printf("  Firmware: %s\n", info.firmware_version);
    printf("  Key slots: %d\n", info.key_slots);

    return 1;
}

int test_device_status(void)
{
    quac_device_status_t status_info;
    quac_status_t status = quac_get_device_status(g_device, &status_info);
    TEST_ASSERT_STATUS(status);

    printf("  Temperature: %.1f C\n", status_info.temperature);
    printf("  Entropy level: %d%%\n", status_info.entropy_level);
    printf("  Total ops: %llu\n", (unsigned long long)status_info.total_operations);

    return 1;
}

int test_self_test(void)
{
    quac_status_t status = quac_self_test(g_device);
    TEST_ASSERT_STATUS(status);
    return 1;
}

/*============================================================================
 * KEM Tests
 *============================================================================*/

int test_kem_params(void)
{
    quac_kem_params_t params;

    /* ML-KEM-512 */
    quac_status_t status = quac_kem_get_params(QUAC_KEM_ML_KEM_512, &params);
    TEST_ASSERT_STATUS(status);
    TEST_ASSERT_EQ(params.public_key_size, QUAC_ML_KEM_512_PUBLIC_KEY_SIZE);
    TEST_ASSERT_EQ(params.secret_key_size, QUAC_ML_KEM_512_SECRET_KEY_SIZE);
    TEST_ASSERT_EQ(params.security_level, 1);

    /* ML-KEM-768 */
    status = quac_kem_get_params(QUAC_KEM_ML_KEM_768, &params);
    TEST_ASSERT_STATUS(status);
    TEST_ASSERT_EQ(params.public_key_size, QUAC_ML_KEM_768_PUBLIC_KEY_SIZE);
    TEST_ASSERT_EQ(params.secret_key_size, QUAC_ML_KEM_768_SECRET_KEY_SIZE);
    TEST_ASSERT_EQ(params.security_level, 3);

    /* ML-KEM-1024 */
    status = quac_kem_get_params(QUAC_KEM_ML_KEM_1024, &params);
    TEST_ASSERT_STATUS(status);
    TEST_ASSERT_EQ(params.public_key_size, QUAC_ML_KEM_1024_PUBLIC_KEY_SIZE);
    TEST_ASSERT_EQ(params.secret_key_size, QUAC_ML_KEM_1024_SECRET_KEY_SIZE);
    TEST_ASSERT_EQ(params.security_level, 5);

    return 1;
}

int test_kem_keygen(void)
{
    uint8_t pk[QUAC_ML_KEM_768_PUBLIC_KEY_SIZE];
    uint8_t sk[QUAC_ML_KEM_768_SECRET_KEY_SIZE];
    size_t pk_len = sizeof(pk);
    size_t sk_len = sizeof(sk);

    quac_status_t status = quac_kem_keygen(g_device, QUAC_KEM_ML_KEM_768,
                                           pk, &pk_len, sk, &sk_len);
    TEST_ASSERT_STATUS(status);
    TEST_ASSERT_EQ(pk_len, QUAC_ML_KEM_768_PUBLIC_KEY_SIZE);
    TEST_ASSERT_EQ(sk_len, QUAC_ML_KEM_768_SECRET_KEY_SIZE);

    /* Keys should not be all zeros */
    int pk_nonzero = 0, sk_nonzero = 0;
    for (size_t i = 0; i < pk_len; i++)
        if (pk[i] != 0)
            pk_nonzero = 1;
    for (size_t i = 0; i < sk_len; i++)
        if (sk[i] != 0)
            sk_nonzero = 1;
    TEST_ASSERT(pk_nonzero);
    TEST_ASSERT(sk_nonzero);

    return 1;
}

int test_kem_encaps_decaps(void)
{
    /* Generate key pair */
    uint8_t pk[QUAC_ML_KEM_768_PUBLIC_KEY_SIZE];
    uint8_t sk[QUAC_ML_KEM_768_SECRET_KEY_SIZE];
    size_t pk_len = sizeof(pk);
    size_t sk_len = sizeof(sk);

    quac_status_t status = quac_kem_keygen(g_device, QUAC_KEM_ML_KEM_768,
                                           pk, &pk_len, sk, &sk_len);
    TEST_ASSERT_STATUS(status);

    /* Encapsulate */
    uint8_t ct[QUAC_ML_KEM_768_CIPHERTEXT_SIZE];
    uint8_t ss1[QUAC_ML_KEM_SHARED_SECRET_SIZE];
    size_t ct_len = sizeof(ct);
    size_t ss1_len = sizeof(ss1);

    status = quac_kem_encaps(g_device, QUAC_KEM_ML_KEM_768,
                             pk, pk_len, ct, &ct_len, ss1, &ss1_len);
    TEST_ASSERT_STATUS(status);
    TEST_ASSERT_EQ(ct_len, QUAC_ML_KEM_768_CIPHERTEXT_SIZE);
    TEST_ASSERT_EQ(ss1_len, QUAC_ML_KEM_SHARED_SECRET_SIZE);

    /* Decapsulate */
    uint8_t ss2[QUAC_ML_KEM_SHARED_SECRET_SIZE];
    size_t ss2_len = sizeof(ss2);

    status = quac_kem_decaps(g_device, QUAC_KEM_ML_KEM_768,
                             sk, sk_len, ct, ct_len, ss2, &ss2_len);
    TEST_ASSERT_STATUS(status);
    TEST_ASSERT_EQ(ss2_len, QUAC_ML_KEM_SHARED_SECRET_SIZE);

    /* Shared secrets must match */
    TEST_ASSERT(memcmp(ss1, ss2, QUAC_ML_KEM_SHARED_SECRET_SIZE) == 0);

    printf("  Shared secrets match!\n");
    return 1;
}

/*============================================================================
 * Signature Tests
 *============================================================================*/

int test_sign_params(void)
{
    quac_sign_params_t params;

    /* ML-DSA-44 */
    quac_status_t status = quac_sign_get_params(QUAC_SIGN_ML_DSA_44, &params);
    TEST_ASSERT_STATUS(status);
    TEST_ASSERT_EQ(params.public_key_size, QUAC_ML_DSA_44_PUBLIC_KEY_SIZE);
    TEST_ASSERT_EQ(params.secret_key_size, QUAC_ML_DSA_44_SECRET_KEY_SIZE);

    /* ML-DSA-65 */
    status = quac_sign_get_params(QUAC_SIGN_ML_DSA_65, &params);
    TEST_ASSERT_STATUS(status);
    TEST_ASSERT_EQ(params.public_key_size, QUAC_ML_DSA_65_PUBLIC_KEY_SIZE);
    TEST_ASSERT_EQ(params.secret_key_size, QUAC_ML_DSA_65_SECRET_KEY_SIZE);

    /* ML-DSA-87 */
    status = quac_sign_get_params(QUAC_SIGN_ML_DSA_87, &params);
    TEST_ASSERT_STATUS(status);
    TEST_ASSERT_EQ(params.public_key_size, QUAC_ML_DSA_87_PUBLIC_KEY_SIZE);
    TEST_ASSERT_EQ(params.secret_key_size, QUAC_ML_DSA_87_SECRET_KEY_SIZE);

    return 1;
}

int test_sign_keygen(void)
{
    uint8_t pk[QUAC_ML_DSA_65_PUBLIC_KEY_SIZE];
    uint8_t sk[QUAC_ML_DSA_65_SECRET_KEY_SIZE];
    size_t pk_len = sizeof(pk);
    size_t sk_len = sizeof(sk);

    quac_status_t status = quac_sign_keygen(g_device, QUAC_SIGN_ML_DSA_65,
                                            pk, &pk_len, sk, &sk_len);
    TEST_ASSERT_STATUS(status);
    TEST_ASSERT_EQ(pk_len, QUAC_ML_DSA_65_PUBLIC_KEY_SIZE);
    TEST_ASSERT_EQ(sk_len, QUAC_ML_DSA_65_SECRET_KEY_SIZE);

    return 1;
}

int test_sign_verify(void)
{
    /* Generate key pair */
    uint8_t pk[QUAC_ML_DSA_65_PUBLIC_KEY_SIZE];
    uint8_t sk[QUAC_ML_DSA_65_SECRET_KEY_SIZE];
    size_t pk_len = sizeof(pk);
    size_t sk_len = sizeof(sk);

    quac_status_t status = quac_sign_keygen(g_device, QUAC_SIGN_ML_DSA_65,
                                            pk, &pk_len, sk, &sk_len);
    TEST_ASSERT_STATUS(status);

    /* Sign message */
    const char *message = "Hello, QUAC 100!";
    uint8_t sig[QUAC_ML_DSA_65_SIGNATURE_SIZE];
    size_t sig_len = sizeof(sig);

    status = quac_sign(g_device, QUAC_SIGN_ML_DSA_65,
                       sk, sk_len,
                       (const uint8_t *)message, strlen(message),
                       sig, &sig_len);
    TEST_ASSERT_STATUS(status);
    TEST_ASSERT(sig_len > 0);

    /* Verify signature */
    status = quac_verify(g_device, QUAC_SIGN_ML_DSA_65,
                         pk, pk_len,
                         (const uint8_t *)message, strlen(message),
                         sig, sig_len);
    TEST_ASSERT_STATUS(status);

    printf("  Signature verified!\n");

    /* Tamper with message - should fail */
    const char *tampered = "Hello, QUAC 100?";
    status = quac_verify(g_device, QUAC_SIGN_ML_DSA_65,
                         pk, pk_len,
                         (const uint8_t *)tampered, strlen(tampered),
                         sig, sig_len);
    TEST_ASSERT_EQ(status, QUAC_ERROR_VERIFY_FAILED);

    printf("  Tamper detection works!\n");
    return 1;
}

/*============================================================================
 * Random Tests
 *============================================================================*/

int test_random_bytes(void)
{
    uint8_t buf1[32], buf2[32];

    quac_status_t status = quac_random_bytes(g_device, buf1, sizeof(buf1));
    TEST_ASSERT_STATUS(status);

    status = quac_random_bytes(g_device, buf2, sizeof(buf2));
    TEST_ASSERT_STATUS(status);

    /* Two random buffers should be different */
    TEST_ASSERT(memcmp(buf1, buf2, sizeof(buf1)) != 0);

    return 1;
}

int test_random_range(void)
{
    uint32_t value;

    for (int i = 0; i < 100; i++)
    {
        quac_status_t status = quac_random_range(g_device, 100, &value);
        TEST_ASSERT_STATUS(status);
        TEST_ASSERT(value < 100);
    }

    return 1;
}

int test_random_double(void)
{
    double value;

    for (int i = 0; i < 100; i++)
    {
        quac_status_t status = quac_random_double(g_device, &value);
        TEST_ASSERT_STATUS(status);
        TEST_ASSERT(value >= 0.0 && value < 1.0);
    }

    return 1;
}

int test_entropy_status(void)
{
    quac_entropy_status_t status_info;
    quac_status_t status = quac_entropy_status(g_device, &status_info);
    TEST_ASSERT_STATUS(status);

    printf("  Entropy level: %d%%\n", status_info.level);
    printf("  Health OK: %s\n", status_info.health_ok ? "yes" : "no");

    return 1;
}

/*============================================================================
 * Hash Tests
 *============================================================================*/

int test_hash_sha256(void)
{
    const char *data = "Hello, World!";
    uint8_t hash[QUAC_SHA256_SIZE];
    size_t hash_len = sizeof(hash);

    quac_status_t status = quac_hash(g_device, QUAC_HASH_SHA256,
                                     (const uint8_t *)data, strlen(data),
                                     hash, &hash_len);
    TEST_ASSERT_STATUS(status);
    TEST_ASSERT_EQ(hash_len, QUAC_SHA256_SIZE);

    /* Print hash */
    printf("  SHA-256: ");
    for (size_t i = 0; i < 8; i++)
        printf("%02x", hash[i]);
    printf("...\n");

    return 1;
}

int test_hash_convenience(void)
{
    const char *data = "Test data";
    uint8_t hash256[QUAC_SHA256_SIZE];
    uint8_t hash512[QUAC_SHA512_SIZE];

    quac_status_t status = quac_sha256(g_device, (const uint8_t *)data,
                                       strlen(data), hash256);
    TEST_ASSERT_STATUS(status);

    status = quac_sha512(g_device, (const uint8_t *)data,
                         strlen(data), hash512);
    TEST_ASSERT_STATUS(status);

    return 1;
}

/*============================================================================
 * Utility Tests
 *============================================================================*/

int test_secure_zero(void)
{
    uint8_t buf[32];
    memset(buf, 0xAA, sizeof(buf));

    quac_secure_zero(buf, sizeof(buf));

    for (size_t i = 0; i < sizeof(buf); i++)
    {
        TEST_ASSERT_EQ(buf[i], 0);
    }

    return 1;
}

int test_secure_compare(void)
{
    uint8_t a[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    uint8_t b[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    uint8_t c[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 99};

    TEST_ASSERT_EQ(quac_secure_compare(a, b, 16), 0);
    TEST_ASSERT(quac_secure_compare(a, c, 16) != 0);

    return 1;
}

int test_hex_encode(void)
{
    uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF};
    char hex[16];

    quac_status_t status = quac_hex_encode(data, sizeof(data), hex, sizeof(hex), false);
    TEST_ASSERT_STATUS(status);
    TEST_ASSERT(strcmp(hex, "deadbeef") == 0);

    status = quac_hex_encode(data, sizeof(data), hex, sizeof(hex), true);
    TEST_ASSERT_STATUS(status);
    TEST_ASSERT(strcmp(hex, "DEADBEEF") == 0);

    return 1;
}

int test_hex_decode(void)
{
    const char *hex = "deadbeef";
    uint8_t data[4];
    size_t data_len = sizeof(data);

    quac_status_t status = quac_hex_decode(hex, data, &data_len);
    TEST_ASSERT_STATUS(status);
    TEST_ASSERT_EQ(data_len, 4);
    TEST_ASSERT_EQ(data[0], 0xDE);
    TEST_ASSERT_EQ(data[1], 0xAD);
    TEST_ASSERT_EQ(data[2], 0xBE);
    TEST_ASSERT_EQ(data[3], 0xEF);

    return 1;
}

/*============================================================================
 * Benchmark Tests
 *============================================================================*/

int test_benchmark_kem(void)
{
    const int iterations = 100;
    clock_t start, end;

    uint8_t pk[QUAC_ML_KEM_768_PUBLIC_KEY_SIZE];
    uint8_t sk[QUAC_ML_KEM_768_SECRET_KEY_SIZE];
    uint8_t ct[QUAC_ML_KEM_768_CIPHERTEXT_SIZE];
    uint8_t ss[QUAC_ML_KEM_SHARED_SECRET_SIZE];
    size_t pk_len, sk_len, ct_len, ss_len;

    /* Benchmark keygen */
    start = clock();
    for (int i = 0; i < iterations; i++)
    {
        pk_len = sizeof(pk);
        sk_len = sizeof(sk);
        quac_kem_keygen(g_device, QUAC_KEM_ML_KEM_768, pk, &pk_len, sk, &sk_len);
    }
    end = clock();
    double keygen_time = (double)(end - start) / CLOCKS_PER_SEC / iterations * 1000;

    /* Benchmark encaps */
    pk_len = sizeof(pk);
    sk_len = sizeof(sk);
    quac_kem_keygen(g_device, QUAC_KEM_ML_KEM_768, pk, &pk_len, sk, &sk_len);

    start = clock();
    for (int i = 0; i < iterations; i++)
    {
        ct_len = sizeof(ct);
        ss_len = sizeof(ss);
        quac_kem_encaps(g_device, QUAC_KEM_ML_KEM_768, pk, pk_len, ct, &ct_len, ss, &ss_len);
    }
    end = clock();
    double encaps_time = (double)(end - start) / CLOCKS_PER_SEC / iterations * 1000;

    /* Benchmark decaps */
    start = clock();
    for (int i = 0; i < iterations; i++)
    {
        ss_len = sizeof(ss);
        quac_kem_decaps(g_device, QUAC_KEM_ML_KEM_768, sk, sk_len, ct, ct_len, ss, &ss_len);
    }
    end = clock();
    double decaps_time = (double)(end - start) / CLOCKS_PER_SEC / iterations * 1000;

    printf("  ML-KEM-768 keygen: %.3f ms\n", keygen_time);
    printf("  ML-KEM-768 encaps: %.3f ms\n", encaps_time);
    printf("  ML-KEM-768 decaps: %.3f ms\n", decaps_time);

    return 1;
}

/*============================================================================
 * Main
 *============================================================================*/

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    printf("========================================\n");
    printf("QUAC 100 SDK Test Suite\n");
    printf("========================================\n\n");

    /* Initialize library */
    quac_status_t status = quac_init(QUAC_FLAG_DEFAULT);
    if (status != QUAC_SUCCESS)
    {
        printf("Failed to initialize library: %s\n", quac_error_string(status));
        return 1;
    }

    /* Open device */
    status = quac_open_first_device(&g_device);
    if (status != QUAC_SUCCESS)
    {
        printf("Failed to open device: %s\n", quac_error_string(status));
        printf("Running without hardware (simulation mode)\n\n");
    }

    /* Library tests */
    printf("\n--- Library Tests ---\n");
    RUN_TEST(test_version);
    RUN_TEST(test_init_cleanup);
    RUN_TEST(test_error_strings);

    /* Device tests */
    printf("\n--- Device Tests ---\n");
    RUN_TEST(test_enumerate_devices);
    if (g_device)
    {
        RUN_TEST(test_device_open_close);
        RUN_TEST(test_device_info);
        RUN_TEST(test_device_status);
        RUN_TEST(test_self_test);
    }

    /* KEM tests */
    printf("\n--- KEM Tests ---\n");
    RUN_TEST(test_kem_params);
    if (g_device)
    {
        RUN_TEST(test_kem_keygen);
        RUN_TEST(test_kem_encaps_decaps);
    }

    /* Signature tests */
    printf("\n--- Signature Tests ---\n");
    RUN_TEST(test_sign_params);
    if (g_device)
    {
        RUN_TEST(test_sign_keygen);
        RUN_TEST(test_sign_verify);
    }

    /* Random tests */
    printf("\n--- Random Tests ---\n");
    if (g_device)
    {
        RUN_TEST(test_random_bytes);
        RUN_TEST(test_random_range);
        RUN_TEST(test_random_double);
        RUN_TEST(test_entropy_status);
    }

    /* Hash tests */
    printf("\n--- Hash Tests ---\n");
    if (g_device)
    {
        RUN_TEST(test_hash_sha256);
        RUN_TEST(test_hash_convenience);
    }

    /* Utility tests */
    printf("\n--- Utility Tests ---\n");
    RUN_TEST(test_secure_zero);
    RUN_TEST(test_secure_compare);
    RUN_TEST(test_hex_encode);
    RUN_TEST(test_hex_decode);

    /* Benchmark tests */
    printf("\n--- Benchmark Tests ---\n");
    if (g_device)
    {
        RUN_TEST(test_benchmark_kem);
    }

    /* Cleanup */
    if (g_device)
    {
        quac_close_device(g_device);
    }
    quac_cleanup();

    /* Print summary */
    printf("\n========================================\n");
    printf("Test Summary\n");
    printf("========================================\n");
    printf("Total:  %d\n", g_tests_run);
    printf("Passed: %d\n", g_tests_passed);
    printf("Failed: %d\n", g_tests_failed);
    printf("========================================\n");

    return g_tests_failed > 0 ? 1 : 0;
}