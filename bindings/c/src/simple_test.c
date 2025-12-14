/**
 * @file simple_test.c
 * @brief Simple standalone test for QUAC 100 C SDK
 *
 * This test validates basic functionality without hardware.
 * Compile with: gcc -o simple_test simple_test.c quac100.c device.c kem.c sign.c random.c hash.c keys.c utils.c hal.c -DQUAC_ENABLE_SIMULATION=1
 * On Windows MSVC: cl simple_test.c quac100.c device.c kem.c sign.c random.c hash.c keys.c utils.c hal.c /DQUAC_ENABLE_SIMULATION=1
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Include the main header */
#include "quac100/quac100.h"

/*============================================================================
 * Test Utilities
 *============================================================================*/

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name)                  \
    printf("Testing %s... ", name); \
    tests_run++;

#define PASS()        \
    printf("PASS\n"); \
    tests_passed++;

#define FAIL(msg)              \
    printf("FAIL: %s\n", msg); \
    return 0;

#define ASSERT(cond, msg) \
    if (!(cond))          \
    {                     \
        FAIL(msg);        \
    }

#define ASSERT_STATUS(status)                            \
    if ((status) != QUAC_SUCCESS)                        \
    {                                                    \
        printf("FAIL: %s\n", quac_error_string(status)); \
        return 0;                                        \
    }

/*============================================================================
 * Print Helpers
 *============================================================================*/

static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("  %s: ", label);
    size_t print_len = (len > 16) ? 16 : len;
    for (size_t i = 0; i < print_len; i++)
    {
        printf("%02x", data[i]);
    }
    if (len > 16)
        printf("...");
    printf(" (%zu bytes)\n", len);
}

/*============================================================================
 * Tests
 *============================================================================*/

int test_version(void)
{
    TEST("quac_version()");

    const char *ver = quac_version();
    ASSERT(ver != NULL, "version is NULL");
    ASSERT(strlen(ver) > 0, "version is empty");

    printf("v%s ", ver);
    PASS();
    return 1;
}

int test_init_cleanup(void)
{
    TEST("quac_init/cleanup");

    /* Already initialized in main, just check */
    ASSERT(quac_is_initialized(), "not initialized");

    PASS();
    return 1;
}

int test_error_strings(void)
{
    TEST("quac_error_string()");

    const char *msg = quac_error_string(QUAC_SUCCESS);
    ASSERT(msg != NULL, "error string is NULL");
    ASSERT(strcmp(msg, "Success") == 0, "wrong success message");

    msg = quac_error_string(QUAC_ERROR_DEVICE_NOT_FOUND);
    ASSERT(msg != NULL, "error string is NULL");

    PASS();
    return 1;
}

int test_kem_params(void)
{
    TEST("quac_kem_get_params()");

    quac_kem_params_t params;
    quac_status_t status;

    /* ML-KEM-512 */
    status = quac_kem_get_params(QUAC_KEM_ML_KEM_512, &params);
    ASSERT_STATUS(status);
    ASSERT(params.public_key_size == 800, "wrong ML-KEM-512 pk size");
    ASSERT(params.secret_key_size == 1632, "wrong ML-KEM-512 sk size");

    /* ML-KEM-768 */
    status = quac_kem_get_params(QUAC_KEM_ML_KEM_768, &params);
    ASSERT_STATUS(status);
    ASSERT(params.public_key_size == 1184, "wrong ML-KEM-768 pk size");
    ASSERT(params.secret_key_size == 2400, "wrong ML-KEM-768 sk size");

    /* ML-KEM-1024 */
    status = quac_kem_get_params(QUAC_KEM_ML_KEM_1024, &params);
    ASSERT_STATUS(status);
    ASSERT(params.public_key_size == 1568, "wrong ML-KEM-1024 pk size");
    ASSERT(params.secret_key_size == 3168, "wrong ML-KEM-1024 sk size");

    PASS();
    return 1;
}

int test_sign_params(void)
{
    TEST("quac_sign_get_params()");

    quac_sign_params_t params;
    quac_status_t status;

    /* ML-DSA-44 */
    status = quac_sign_get_params(QUAC_SIGN_ML_DSA_44, &params);
    ASSERT_STATUS(status);
    ASSERT(params.public_key_size == 1312, "wrong ML-DSA-44 pk size");

    /* ML-DSA-65 */
    status = quac_sign_get_params(QUAC_SIGN_ML_DSA_65, &params);
    ASSERT_STATUS(status);
    ASSERT(params.public_key_size == 1952, "wrong ML-DSA-65 pk size");

    /* ML-DSA-87 */
    status = quac_sign_get_params(QUAC_SIGN_ML_DSA_87, &params);
    ASSERT_STATUS(status);
    ASSERT(params.public_key_size == 2592, "wrong ML-DSA-87 pk size");

    PASS();
    return 1;
}

int test_secure_zero(void)
{
    TEST("quac_secure_zero()");

    uint8_t buf[32];
    memset(buf, 0xAA, sizeof(buf));

    quac_secure_zero(buf, sizeof(buf));

    for (size_t i = 0; i < sizeof(buf); i++)
    {
        ASSERT(buf[i] == 0, "buffer not zeroed");
    }

    PASS();
    return 1;
}

int test_secure_compare(void)
{
    TEST("quac_secure_compare()");

    uint8_t a[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    uint8_t b[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    uint8_t c[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 99};

    ASSERT(quac_secure_compare(a, b, 16) == 0, "equal buffers not equal");
    ASSERT(quac_secure_compare(a, c, 16) != 0, "different buffers are equal");

    PASS();
    return 1;
}

int test_algorithm_info(void)
{
    TEST("quac_algorithm_name()");

    const char *name;

    name = quac_algorithm_name(QUAC_KEM_ML_KEM_768);
    ASSERT(name != NULL, "algorithm name is NULL");
    ASSERT(strstr(name, "768") != NULL, "wrong algorithm name");

    name = quac_algorithm_name(QUAC_SIGN_ML_DSA_65);
    ASSERT(name != NULL, "algorithm name is NULL");
    ASSERT(strstr(name, "65") != NULL, "wrong algorithm name");

    ASSERT(quac_is_kem_algorithm(QUAC_KEM_ML_KEM_768), "not detected as KEM");
    ASSERT(!quac_is_kem_algorithm(QUAC_SIGN_ML_DSA_65), "wrongly detected as KEM");
    ASSERT(quac_is_sign_algorithm(QUAC_SIGN_ML_DSA_65), "not detected as sign");

    PASS();
    return 1;
}

int test_device_enumeration(void)
{
    TEST("quac_enumerate_devices()");

    quac_device_info_t devices[16];
    int count = 0;

    quac_status_t status = quac_enumerate_devices(devices, 16, &count);
    ASSERT_STATUS(status);

    printf("found %d device(s) ", count);
    PASS();
    return 1;
}

/* Tests that require a device (simulation or real) */
int test_device_operations(quac_device_t device)
{
    TEST("device operations");

    /* Get device info */
    quac_device_info_t info;
    quac_status_t status = quac_get_device_info(device, &info);
    ASSERT_STATUS(status);
    printf("\n  Model: %s\n  ", info.model_name);

    /* Get device status */
    quac_device_status_t dev_status;
    status = quac_get_device_status(device, &dev_status);
    ASSERT_STATUS(status);

    /* Self-test */
    status = quac_self_test(device);
    ASSERT_STATUS(status);

    PASS();
    return 1;
}

int test_kem_keygen(quac_device_t device)
{
    TEST("quac_kem_keygen()");

    uint8_t pk[QUAC_ML_KEM_768_PUBLIC_KEY_SIZE];
    uint8_t sk[QUAC_ML_KEM_768_SECRET_KEY_SIZE];
    size_t pk_len = sizeof(pk);
    size_t sk_len = sizeof(sk);

    quac_status_t status = quac_kem_keygen(device, QUAC_KEM_ML_KEM_768,
                                           pk, &pk_len, sk, &sk_len);
    ASSERT_STATUS(status);
    ASSERT(pk_len == QUAC_ML_KEM_768_PUBLIC_KEY_SIZE, "wrong pk size");
    ASSERT(sk_len == QUAC_ML_KEM_768_SECRET_KEY_SIZE, "wrong sk size");

    /* Check keys are not all zeros */
    int pk_ok = 0, sk_ok = 0;
    for (size_t i = 0; i < pk_len; i++)
        if (pk[i] != 0)
            pk_ok = 1;
    for (size_t i = 0; i < sk_len; i++)
        if (sk[i] != 0)
            sk_ok = 1;
    ASSERT(pk_ok, "public key is all zeros");
    ASSERT(sk_ok, "secret key is all zeros");

    print_hex("Public key", pk, pk_len);

    /* Secure cleanup */
    quac_secure_zero(sk, sk_len);

    PASS();
    return 1;
}

int test_kem_full_cycle(quac_device_t device)
{
    TEST("KEM full cycle (keygen/encaps/decaps)");

    /* Generate key pair */
    uint8_t pk[QUAC_ML_KEM_768_PUBLIC_KEY_SIZE];
    uint8_t sk[QUAC_ML_KEM_768_SECRET_KEY_SIZE];
    size_t pk_len = sizeof(pk);
    size_t sk_len = sizeof(sk);

    quac_status_t status = quac_kem_keygen(device, QUAC_KEM_ML_KEM_768,
                                           pk, &pk_len, sk, &sk_len);
    ASSERT_STATUS(status);

    /* Encapsulate */
    uint8_t ct[QUAC_ML_KEM_768_CIPHERTEXT_SIZE];
    uint8_t ss1[QUAC_ML_KEM_SHARED_SECRET_SIZE];
    size_t ct_len = sizeof(ct);
    size_t ss1_len = sizeof(ss1);

    status = quac_kem_encaps(device, QUAC_KEM_ML_KEM_768,
                             pk, pk_len, ct, &ct_len, ss1, &ss1_len);
    ASSERT_STATUS(status);

    /* Decapsulate */
    uint8_t ss2[QUAC_ML_KEM_SHARED_SECRET_SIZE];
    size_t ss2_len = sizeof(ss2);

    status = quac_kem_decaps(device, QUAC_KEM_ML_KEM_768,
                             sk, sk_len, ct, ct_len, ss2, &ss2_len);
    ASSERT_STATUS(status);

    /* Verify shared secrets match */
    ASSERT(memcmp(ss1, ss2, QUAC_ML_KEM_SHARED_SECRET_SIZE) == 0,
           "shared secrets don't match");

    print_hex("Shared secret", ss1, ss1_len);
    printf("  Shared secrets match!\n  ");

    /* Cleanup */
    quac_secure_zero(sk, sk_len);
    quac_secure_zero(ss1, ss1_len);
    quac_secure_zero(ss2, ss2_len);

    PASS();
    return 1;
}

int test_sign_full_cycle(quac_device_t device)
{
    TEST("Sign full cycle (keygen/sign/verify)");

    /* Generate key pair */
    uint8_t pk[QUAC_ML_DSA_65_PUBLIC_KEY_SIZE];
    uint8_t sk[QUAC_ML_DSA_65_SECRET_KEY_SIZE];
    size_t pk_len = sizeof(pk);
    size_t sk_len = sizeof(sk);

    quac_status_t status = quac_sign_keygen(device, QUAC_SIGN_ML_DSA_65,
                                            pk, &pk_len, sk, &sk_len);
    ASSERT_STATUS(status);

    /* Sign message */
    const char *message = "Hello, QUAC 100!";
    uint8_t sig[QUAC_ML_DSA_65_SIGNATURE_SIZE];
    size_t sig_len = sizeof(sig);

    status = quac_sign(device, QUAC_SIGN_ML_DSA_65,
                       sk, sk_len,
                       (const uint8_t *)message, strlen(message),
                       sig, &sig_len);
    ASSERT_STATUS(status);

    print_hex("Signature", sig, sig_len);

    /* Verify signature */
    status = quac_verify(device, QUAC_SIGN_ML_DSA_65,
                         pk, pk_len,
                         (const uint8_t *)message, strlen(message),
                         sig, sig_len);
    ASSERT_STATUS(status);
    printf("  Signature valid!\n  ");

    /* Test tamper detection */
    const char *tampered = "Hello, QUAC 100?";
    status = quac_verify(device, QUAC_SIGN_ML_DSA_65,
                         pk, pk_len,
                         (const uint8_t *)tampered, strlen(tampered),
                         sig, sig_len);
    ASSERT(status == QUAC_ERROR_VERIFY_FAILED, "tamper not detected");
    printf("  Tamper detected!\n  ");

    /* Cleanup */
    quac_secure_zero(sk, sk_len);

    PASS();
    return 1;
}

int test_random_bytes(quac_device_t device)
{
    TEST("quac_random_bytes()");

    uint8_t buf1[32], buf2[32];

    quac_status_t status = quac_random_bytes(device, buf1, sizeof(buf1));
    ASSERT_STATUS(status);

    status = quac_random_bytes(device, buf2, sizeof(buf2));
    ASSERT_STATUS(status);

    /* Two random buffers should be different */
    ASSERT(memcmp(buf1, buf2, sizeof(buf1)) != 0, "random buffers identical");

    print_hex("Random bytes", buf1, sizeof(buf1));

    PASS();
    return 1;
}

int test_hash(quac_device_t device)
{
    TEST("quac_sha256()");

    const char *data = "Hello, World!";
    uint8_t hash[QUAC_SHA256_SIZE];

    quac_status_t status = quac_sha256(device, (const uint8_t *)data,
                                       strlen(data), hash);
    ASSERT_STATUS(status);

    print_hex("SHA-256", hash, sizeof(hash));

    PASS();
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
    printf("QUAC 100 C SDK - Simple Test Suite\n");
    printf("========================================\n\n");

    /* Initialize library */
    printf("Initializing library...\n");
    quac_status_t status = quac_init(QUAC_FLAG_DEFAULT);
    if (status != QUAC_SUCCESS)
    {
        printf("FATAL: Failed to initialize: %s\n", quac_error_string(status));
        return 1;
    }
    printf("Library initialized!\n\n");

    /* Run basic tests (no device needed) */
    printf("--- Basic Tests (no device required) ---\n");
    test_version();
    test_init_cleanup();
    test_error_strings();
    test_kem_params();
    test_sign_params();
    test_secure_zero();
    test_secure_compare();
    test_algorithm_info();
    test_device_enumeration();

    /* Try to open device */
    printf("\n--- Device Tests ---\n");
    quac_device_t device = NULL;
    status = quac_open_first_device(&device);

    if (status == QUAC_SUCCESS && device != NULL)
    {
        printf("Device opened successfully!\n\n");

        test_device_operations(device);
        test_kem_keygen(device);
        test_kem_full_cycle(device);
        test_sign_full_cycle(device);
        test_random_bytes(device);
        test_hash(device);

        quac_close_device(device);
    }
    else
    {
        printf("No device available (status: %s)\n", quac_error_string(status));
        printf("Skipping device-specific tests.\n");
        printf("(This is expected if running in simulation mode without hardware)\n");
    }

    /* Cleanup */
    quac_cleanup();

    /* Print summary */
    printf("\n========================================\n");
    printf("Test Summary\n");
    printf("========================================\n");
    printf("Total:  %d\n", tests_run);
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_run - tests_passed);
    printf("========================================\n");

    if (tests_passed == tests_run)
    {
        printf("\n*** ALL TESTS PASSED! ***\n\n");
        return 0;
    }
    else
    {
        printf("\n*** SOME TESTS FAILED ***\n\n");
        return 1;
    }
}