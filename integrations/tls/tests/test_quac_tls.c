/**
 * @file test_quac_tls.c
 * @brief QUAC 100 TLS Integration - Test Suite
 *
 * Comprehensive tests for the QUAC TLS library.
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "quac_tls.h"

/* ==========================================================================
 * Test Framework
 * ========================================================================== */

static int g_tests_run = 0;
static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define TEST_ASSERT(cond, msg)                                  \
    do                                                          \
    {                                                           \
        if (!(cond))                                            \
        {                                                       \
            printf("    FAIL: %s\n", msg);                      \
            printf("          at %s:%d\n", __FILE__, __LINE__); \
            return 0;                                           \
        }                                                       \
    } while (0)

#define TEST_ASSERT_EQ(a, b, msg) TEST_ASSERT((a) == (b), msg)
#define TEST_ASSERT_NE(a, b, msg) TEST_ASSERT((a) != (b), msg)
#define TEST_ASSERT_NULL(p, msg) TEST_ASSERT((p) == NULL, msg)
#define TEST_ASSERT_NOT_NULL(p, msg) TEST_ASSERT((p) != NULL, msg)
#define TEST_ASSERT_STR_NE(s, msg) TEST_ASSERT((s) != NULL && strlen(s) > 0, msg)

#define RUN_TEST(fn)             \
    do                           \
    {                            \
        printf("  %s... ", #fn); \
        fflush(stdout);          \
        g_tests_run++;           \
        if (fn())                \
        {                        \
            printf("PASS\n");    \
            g_tests_passed++;    \
        }                        \
        else                     \
        {                        \
            g_tests_failed++;    \
        }                        \
    } while (0)

/* ==========================================================================
 * Test Cases
 * ========================================================================== */

/* Test 1: Library initialization */
static int test_init_cleanup(void)
{
    int ret;

    ret = quac_tls_init();
    TEST_ASSERT_EQ(ret, QUAC_TLS_OK, "First init should succeed");

    ret = quac_tls_init();
    TEST_ASSERT_EQ(ret, QUAC_TLS_ERROR_ALREADY_INIT, "Double init should fail");

    quac_tls_cleanup();

    ret = quac_tls_init();
    TEST_ASSERT_EQ(ret, QUAC_TLS_OK, "Re-init after cleanup should succeed");

    quac_tls_cleanup();
    return 1;
}

/* Test 2: Version string */
static int test_version(void)
{
    const char *version = quac_tls_version();
    TEST_ASSERT_NOT_NULL(version, "Version should not be NULL");
    TEST_ASSERT(strlen(version) > 0, "Version should not be empty");
    TEST_ASSERT(strstr(version, ".") != NULL, "Version should contain dot");
    return 1;
}

/* Test 3: Error strings */
static int test_error_strings(void)
{
    const char *str;

    str = quac_tls_error_string(QUAC_TLS_OK);
    TEST_ASSERT_STR_NE(str, "OK error string");

    str = quac_tls_error_string(QUAC_TLS_ERROR_MEMORY);
    TEST_ASSERT_STR_NE(str, "Memory error string");

    str = quac_tls_error_string(QUAC_TLS_ERROR_HANDSHAKE);
    TEST_ASSERT_STR_NE(str, "Handshake error string");

    str = quac_tls_error_string(-999);
    TEST_ASSERT_NOT_NULL(str, "Unknown error should return string");

    return 1;
}

/* Test 4: Default configuration */
static int test_config_default(void)
{
    quac_tls_config_t config;

    quac_tls_config_default(&config);

    TEST_ASSERT_EQ(config.min_version, QUAC_TLS_VERSION_1_2, "Min version");
    TEST_ASSERT_EQ(config.max_version, QUAC_TLS_VERSION_1_3, "Max version");
    TEST_ASSERT(config.kex_algorithms != 0, "KEX should be set");
    TEST_ASSERT(config.sig_algorithms != 0, "Sig should be set");
    TEST_ASSERT_EQ(config.verify_depth, 4, "Verify depth");
    TEST_ASSERT_EQ(config.use_hardware, 1, "Hardware default");

    return 1;
}

/* Test 5: Server context creation */
static int test_ctx_server(void)
{
    quac_tls_ctx_t *ctx;
    int ret;

    ret = quac_tls_init();
    TEST_ASSERT_EQ(ret, QUAC_TLS_OK, "Init");

    ctx = quac_tls_ctx_new(1);
    TEST_ASSERT_NOT_NULL(ctx, "Server context");

    quac_tls_ctx_free(ctx);
    quac_tls_cleanup();
    return 1;
}

/* Test 6: Client context creation */
static int test_ctx_client(void)
{
    quac_tls_ctx_t *ctx;
    int ret;

    ret = quac_tls_init();
    TEST_ASSERT_EQ(ret, QUAC_TLS_OK, "Init");

    ctx = quac_tls_ctx_new(0);
    TEST_ASSERT_NOT_NULL(ctx, "Client context");

    quac_tls_ctx_free(ctx);
    quac_tls_cleanup();
    return 1;
}

/* Test 7: Context with custom config */
static int test_ctx_custom_config(void)
{
    quac_tls_ctx_t *ctx;
    quac_tls_config_t config;
    int ret;

    ret = quac_tls_init();
    TEST_ASSERT_EQ(ret, QUAC_TLS_OK, "Init");

    quac_tls_config_default(&config);
    config.min_version = QUAC_TLS_VERSION_1_3;
    config.kex_algorithms = QUAC_TLS_KEX_ML_KEM_768;
    config.sig_algorithms = QUAC_TLS_SIG_ML_DSA_65;
    config.verify_mode = QUAC_TLS_VERIFY_NONE;

    ctx = quac_tls_ctx_new_config(1, &config);
    TEST_ASSERT_NOT_NULL(ctx, "Custom config context");

    quac_tls_ctx_free(ctx);
    quac_tls_cleanup();
    return 1;
}

/* Test 8: ML-DSA-44 key generation */
static int test_mldsa44_keygen(void)
{
    int ret;
    uint8_t *pub = NULL, *priv = NULL;
    size_t pub_len, priv_len;

    ret = quac_tls_init();
    TEST_ASSERT_EQ(ret, QUAC_TLS_OK, "Init");

    ret = quac_tls_generate_mldsa_keypair(44, &pub, &pub_len, &priv, &priv_len);
    TEST_ASSERT_EQ(ret, QUAC_TLS_OK, "Keygen");
    TEST_ASSERT_NOT_NULL(pub, "Public key");
    TEST_ASSERT_NOT_NULL(priv, "Private key");
    TEST_ASSERT_EQ(pub_len, 1312, "Public key size");
    TEST_ASSERT_EQ(priv_len, 2560, "Private key size");

    free(pub);
    free(priv);
    quac_tls_cleanup();
    return 1;
}

/* Test 9: ML-DSA-65 key generation */
static int test_mldsa65_keygen(void)
{
    int ret;
    uint8_t *pub = NULL, *priv = NULL;
    size_t pub_len, priv_len;

    ret = quac_tls_init();
    TEST_ASSERT_EQ(ret, QUAC_TLS_OK, "Init");

    ret = quac_tls_generate_mldsa_keypair(65, &pub, &pub_len, &priv, &priv_len);
    TEST_ASSERT_EQ(ret, QUAC_TLS_OK, "Keygen");
    TEST_ASSERT_EQ(pub_len, 1952, "Public key size");
    TEST_ASSERT_EQ(priv_len, 4032, "Private key size");

    free(pub);
    free(priv);
    quac_tls_cleanup();
    return 1;
}

/* Test 10: ML-DSA-87 key generation */
static int test_mldsa87_keygen(void)
{
    int ret;
    uint8_t *pub = NULL, *priv = NULL;
    size_t pub_len, priv_len;

    ret = quac_tls_init();
    TEST_ASSERT_EQ(ret, QUAC_TLS_OK, "Init");

    ret = quac_tls_generate_mldsa_keypair(87, &pub, &pub_len, &priv, &priv_len);
    TEST_ASSERT_EQ(ret, QUAC_TLS_OK, "Keygen");
    TEST_ASSERT_EQ(pub_len, 2592, "Public key size");
    TEST_ASSERT_EQ(priv_len, 4896, "Private key size");

    free(pub);
    free(priv);
    quac_tls_cleanup();
    return 1;
}

/* Test 11: Invalid ML-DSA level */
static int test_mldsa_invalid_level(void)
{
    int ret;
    uint8_t *pub = NULL, *priv = NULL;
    size_t pub_len, priv_len;

    ret = quac_tls_init();
    TEST_ASSERT_EQ(ret, QUAC_TLS_OK, "Init");

    ret = quac_tls_generate_mldsa_keypair(99, &pub, &pub_len, &priv, &priv_len);
    TEST_ASSERT_EQ(ret, QUAC_TLS_ERROR_INVALID_PARAM, "Invalid level");

    quac_tls_cleanup();
    return 1;
}

/* Test 12: Self-signed certificate generation */
static int test_self_signed_cert(void)
{
    int ret;
    char *cert = NULL, *key = NULL;

    ret = quac_tls_init();
    TEST_ASSERT_EQ(ret, QUAC_TLS_OK, "Init");

    ret = quac_tls_generate_self_signed_mldsa(65, "CN=test", 365, &cert, &key);
    TEST_ASSERT_EQ(ret, QUAC_TLS_OK, "Cert gen");
    TEST_ASSERT_NOT_NULL(cert, "Certificate");
    TEST_ASSERT_NOT_NULL(key, "Key");
    TEST_ASSERT(strstr(cert, "-----BEGIN") != NULL, "Cert PEM header");
    TEST_ASSERT(strstr(key, "-----BEGIN") != NULL, "Key PEM header");

    free(cert);
    free(key);
    quac_tls_cleanup();
    return 1;
}

/* Test 13: Connection creation */
static int test_connection_create(void)
{
    quac_tls_ctx_t *ctx;
    quac_tls_conn_t *conn;
    int ret;

    ret = quac_tls_init();
    TEST_ASSERT_EQ(ret, QUAC_TLS_OK, "Init");

    ctx = quac_tls_ctx_new(0);
    TEST_ASSERT_NOT_NULL(ctx, "Context");

    conn = quac_tls_conn_new(ctx);
    TEST_ASSERT_NOT_NULL(conn, "Connection");

    ret = quac_tls_conn_set_server_name(conn, "example.com");
    TEST_ASSERT_EQ(ret, QUAC_TLS_OK, "Set server name");

    quac_tls_conn_free(conn);
    quac_tls_ctx_free(ctx);
    quac_tls_cleanup();
    return 1;
}

/* Test 14: Statistics */
static int test_statistics(void)
{
    quac_tls_ctx_t *ctx;
    quac_tls_stats_t stats;
    int ret;

    ret = quac_tls_init();
    TEST_ASSERT_EQ(ret, QUAC_TLS_OK, "Init");

    ctx = quac_tls_ctx_new(1);
    TEST_ASSERT_NOT_NULL(ctx, "Context");

    quac_tls_ctx_get_stats(ctx, &stats);
    TEST_ASSERT_EQ(stats.handshakes_total, 0, "Initial handshakes");

    quac_tls_ctx_reset_stats(ctx);
    quac_tls_ctx_get_stats(ctx, &stats);
    TEST_ASSERT_EQ(stats.bytes_sent, 0, "Reset bytes");

    quac_tls_ctx_free(ctx);
    quac_tls_cleanup();
    return 1;
}

/* Test 15: NULL parameter handling */
static int test_null_params(void)
{
    int ret;

    ret = quac_tls_init();
    TEST_ASSERT_EQ(ret, QUAC_TLS_OK, "Init");

    /* These should not crash */
    quac_tls_ctx_free(NULL);
    quac_tls_conn_free(NULL);
    quac_tls_config_default(NULL);
    quac_tls_cert_free(NULL);

    quac_tls_cleanup();
    return 1;
}

/* Test 16: Algorithm flags */
static int test_algorithm_flags(void)
{
    /* KEX flags should be distinct */
    TEST_ASSERT((QUAC_TLS_KEX_ML_KEM_512 & QUAC_TLS_KEX_ML_KEM_768) == 0, "KEX distinct");
    TEST_ASSERT((QUAC_TLS_KEX_ML_KEM_768 & QUAC_TLS_KEX_X25519) == 0, "KEX distinct 2");

    /* Sig flags should be distinct */
    TEST_ASSERT((QUAC_TLS_SIG_ML_DSA_44 & QUAC_TLS_SIG_ML_DSA_65) == 0, "Sig distinct");
    TEST_ASSERT((QUAC_TLS_SIG_ML_DSA_65 & QUAC_TLS_SIG_ED25519) == 0, "Sig distinct 2");

    /* Hybrid should differ from pure */
    TEST_ASSERT(QUAC_TLS_KEX_X25519_ML_KEM_768 != QUAC_TLS_KEX_ML_KEM_768, "Hybrid diff");

    return 1;
}

/* ==========================================================================
 * Main
 * ========================================================================== */

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    printf("================================================\n");
    printf("QUAC TLS Library Test Suite\n");
    printf("================================================\n\n");

    printf("Library Initialization:\n");
    RUN_TEST(test_init_cleanup);
    RUN_TEST(test_version);
    RUN_TEST(test_error_strings);

    printf("\nConfiguration:\n");
    RUN_TEST(test_config_default);

    printf("\nContext Management:\n");
    RUN_TEST(test_ctx_server);
    RUN_TEST(test_ctx_client);
    RUN_TEST(test_ctx_custom_config);

    printf("\nML-DSA Key Generation:\n");
    RUN_TEST(test_mldsa44_keygen);
    RUN_TEST(test_mldsa65_keygen);
    RUN_TEST(test_mldsa87_keygen);
    RUN_TEST(test_mldsa_invalid_level);

    printf("\nCertificate Generation:\n");
    RUN_TEST(test_self_signed_cert);

    printf("\nConnection Management:\n");
    RUN_TEST(test_connection_create);

    printf("\nStatistics:\n");
    RUN_TEST(test_statistics);

    printf("\nError Handling:\n");
    RUN_TEST(test_null_params);
    RUN_TEST(test_algorithm_flags);

    printf("\n================================================\n");
    printf("Results: %d/%d passed", g_tests_passed, g_tests_run);
    if (g_tests_failed > 0)
    {
        printf(" (%d FAILED)", g_tests_failed);
    }
    printf("\n================================================\n");

    return (g_tests_failed > 0) ? 1 : 0;
}