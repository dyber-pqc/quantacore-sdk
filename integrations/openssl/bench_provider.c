/**
 * @file D:\quantacore-sdk\integrations\openssl\bench_provider.c
 * @brief QUAC 100 OpenSSL Provider - Performance Benchmarks
 *
 * Benchmarks ML-KEM and ML-DSA operations through the OpenSSL provider.
 *
 * Usage:
 *   ./bench_provider [-n iterations] [-a algorithm]
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <getopt.h>

#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

/* ==========================================================================
 * Timing
 * ========================================================================== */

#ifdef _WIN32
#include <windows.h>
static double get_time_us(void)
{
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (double)count.QuadPart * 1000000.0 / (double)freq.QuadPart;
}
#else
#include <sys/time.h>
static double get_time_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000.0 + ts.tv_nsec / 1000.0;
}
#endif

/* ==========================================================================
 * Benchmark Results
 * ========================================================================== */

typedef struct
{
    const char *name;
    int iterations;
    double total_us;
    double min_us;
    double max_us;
    double avg_us;
    double ops_per_sec;
    double stddev_us;
} bench_result_t;

static void calc_stats(bench_result_t *r, double *samples, int n)
{
    r->min_us = samples[0];
    r->max_us = samples[0];
    r->total_us = 0;

    for (int i = 0; i < n; i++)
    {
        r->total_us += samples[i];
        if (samples[i] < r->min_us)
            r->min_us = samples[i];
        if (samples[i] > r->max_us)
            r->max_us = samples[i];
    }

    r->avg_us = r->total_us / n;
    r->ops_per_sec = 1000000.0 / r->avg_us;

    /* Standard deviation */
    double sum_sq = 0;
    for (int i = 0; i < n; i++)
    {
        double diff = samples[i] - r->avg_us;
        sum_sq += diff * diff;
    }
    r->stddev_us = sqrt(sum_sq / n);
}

static void print_result(bench_result_t *r)
{
    printf("%-25s %6d iter  %10.2f µs avg  %10.2f µs stddev  %10.0f ops/sec\n",
           r->name, r->iterations, r->avg_us, r->stddev_us, r->ops_per_sec);
}

/* ==========================================================================
 * ML-KEM Benchmarks
 * ========================================================================== */

static int bench_mlkem_keygen(const char *alg_name, int iterations)
{
    bench_result_t r = {.name = "Keygen", .iterations = iterations};
    double *samples = malloc(iterations * sizeof(double));
    if (!samples)
        return -1;

    for (int i = 0; i < iterations; i++)
    {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, alg_name, "provider=quac100");
        if (!ctx)
        {
            free(samples);
            return -1;
        }

        EVP_PKEY_keygen_init(ctx);

        double t0 = get_time_us();
        EVP_PKEY *key = NULL;
        EVP_PKEY_generate(ctx, &key);
        double t1 = get_time_us();

        samples[i] = t1 - t0;

        EVP_PKEY_free(key);
        EVP_PKEY_CTX_free(ctx);
    }

    calc_stats(&r, samples, iterations);
    print_result(&r);
    free(samples);
    return 0;
}

static int bench_mlkem_encaps(const char *alg_name, int iterations)
{
    bench_result_t r = {.name = "Encaps", .iterations = iterations};
    double *samples = malloc(iterations * sizeof(double));
    if (!samples)
        return -1;

    /* Generate key first */
    EVP_PKEY_CTX *gen_ctx = EVP_PKEY_CTX_new_from_name(NULL, alg_name, "provider=quac100");
    EVP_PKEY_keygen_init(gen_ctx);
    EVP_PKEY *key = NULL;
    EVP_PKEY_generate(gen_ctx, &key);
    EVP_PKEY_CTX_free(gen_ctx);

    if (!key)
    {
        free(samples);
        return -1;
    }

    for (int i = 0; i < iterations; i++)
    {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=quac100");
        EVP_PKEY_encapsulate_init(ctx, NULL);

        size_t ct_len = 0, ss_len = 0;
        EVP_PKEY_encapsulate(ctx, NULL, &ct_len, NULL, &ss_len);

        unsigned char *ct = malloc(ct_len);
        unsigned char *ss = malloc(ss_len);

        double t0 = get_time_us();
        EVP_PKEY_encapsulate(ctx, ct, &ct_len, ss, &ss_len);
        double t1 = get_time_us();

        samples[i] = t1 - t0;

        free(ct);
        free(ss);
        EVP_PKEY_CTX_free(ctx);
    }

    calc_stats(&r, samples, iterations);
    print_result(&r);

    EVP_PKEY_free(key);
    free(samples);
    return 0;
}

static int bench_mlkem_decaps(const char *alg_name, int iterations)
{
    bench_result_t r = {.name = "Decaps", .iterations = iterations};
    double *samples = malloc(iterations * sizeof(double));
    if (!samples)
        return -1;

    /* Generate key and ciphertext */
    EVP_PKEY_CTX *gen_ctx = EVP_PKEY_CTX_new_from_name(NULL, alg_name, "provider=quac100");
    EVP_PKEY_keygen_init(gen_ctx);
    EVP_PKEY *key = NULL;
    EVP_PKEY_generate(gen_ctx, &key);
    EVP_PKEY_CTX_free(gen_ctx);

    if (!key)
    {
        free(samples);
        return -1;
    }

    /* Encapsulate once */
    EVP_PKEY_CTX *enc_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=quac100");
    EVP_PKEY_encapsulate_init(enc_ctx, NULL);

    size_t ct_len = 0, ss_len = 0;
    EVP_PKEY_encapsulate(enc_ctx, NULL, &ct_len, NULL, &ss_len);

    unsigned char *ct = malloc(ct_len);
    unsigned char *ss_enc = malloc(ss_len);
    EVP_PKEY_encapsulate(enc_ctx, ct, &ct_len, ss_enc, &ss_len);
    EVP_PKEY_CTX_free(enc_ctx);

    for (int i = 0; i < iterations; i++)
    {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, "provider=quac100");
        EVP_PKEY_decapsulate_init(ctx, NULL);

        unsigned char *ss = malloc(ss_len);

        double t0 = get_time_us();
        size_t out_len = ss_len;
        EVP_PKEY_decapsulate(ctx, ss, &out_len, ct, ct_len);
        double t1 = get_time_us();

        samples[i] = t1 - t0;

        free(ss);
        EVP_PKEY_CTX_free(ctx);
    }

    calc_stats(&r, samples, iterations);
    print_result(&r);

    free(ct);
    free(ss_enc);
    EVP_PKEY_free(key);
    free(samples);
    return 0;
}

/* ==========================================================================
 * ML-DSA Benchmarks
 * ========================================================================== */

static int bench_mldsa_keygen(const char *alg_name, int iterations)
{
    bench_result_t r = {.name = "Keygen", .iterations = iterations};
    double *samples = malloc(iterations * sizeof(double));
    if (!samples)
        return -1;

    for (int i = 0; i < iterations; i++)
    {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, alg_name, "provider=quac100");
        if (!ctx)
        {
            free(samples);
            return -1;
        }

        EVP_PKEY_keygen_init(ctx);

        double t0 = get_time_us();
        EVP_PKEY *key = NULL;
        EVP_PKEY_generate(ctx, &key);
        double t1 = get_time_us();

        samples[i] = t1 - t0;

        EVP_PKEY_free(key);
        EVP_PKEY_CTX_free(ctx);
    }

    calc_stats(&r, samples, iterations);
    print_result(&r);
    free(samples);
    return 0;
}

static int bench_mldsa_sign(const char *alg_name, int iterations, size_t msg_size)
{
    char name[64];
    snprintf(name, sizeof(name), "Sign (%zu B)", msg_size);
    bench_result_t r = {.name = name, .iterations = iterations};
    double *samples = malloc(iterations * sizeof(double));
    if (!samples)
        return -1;

    /* Generate key */
    EVP_PKEY_CTX *gen_ctx = EVP_PKEY_CTX_new_from_name(NULL, alg_name, "provider=quac100");
    EVP_PKEY_keygen_init(gen_ctx);
    EVP_PKEY *key = NULL;
    EVP_PKEY_generate(gen_ctx, &key);
    EVP_PKEY_CTX_free(gen_ctx);

    if (!key)
    {
        free(samples);
        return -1;
    }

    /* Generate random message */
    unsigned char *msg = malloc(msg_size);
    RAND_bytes(msg, msg_size);

    for (int i = 0; i < iterations; i++)
    {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        EVP_DigestSignInit_ex(ctx, NULL, NULL, NULL, "provider=quac100", key, NULL);

        size_t sig_len = 0;
        EVP_DigestSign(ctx, NULL, &sig_len, msg, msg_size);

        unsigned char *sig = malloc(sig_len);

        double t0 = get_time_us();
        EVP_DigestSign(ctx, sig, &sig_len, msg, msg_size);
        double t1 = get_time_us();

        samples[i] = t1 - t0;

        free(sig);
        EVP_MD_CTX_free(ctx);
    }

    calc_stats(&r, samples, iterations);
    print_result(&r);

    free(msg);
    EVP_PKEY_free(key);
    free(samples);
    return 0;
}

static int bench_mldsa_verify(const char *alg_name, int iterations, size_t msg_size)
{
    char name[64];
    snprintf(name, sizeof(name), "Verify (%zu B)", msg_size);
    bench_result_t r = {.name = name, .iterations = iterations};
    double *samples = malloc(iterations * sizeof(double));
    if (!samples)
        return -1;

    /* Generate key */
    EVP_PKEY_CTX *gen_ctx = EVP_PKEY_CTX_new_from_name(NULL, alg_name, "provider=quac100");
    EVP_PKEY_keygen_init(gen_ctx);
    EVP_PKEY *key = NULL;
    EVP_PKEY_generate(gen_ctx, &key);
    EVP_PKEY_CTX_free(gen_ctx);

    if (!key)
    {
        free(samples);
        return -1;
    }

    /* Generate random message and sign it */
    unsigned char *msg = malloc(msg_size);
    RAND_bytes(msg, msg_size);

    EVP_MD_CTX *sign_ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit_ex(sign_ctx, NULL, NULL, NULL, "provider=quac100", key, NULL);

    size_t sig_len = 0;
    EVP_DigestSign(sign_ctx, NULL, &sig_len, msg, msg_size);
    unsigned char *sig = malloc(sig_len);
    EVP_DigestSign(sign_ctx, sig, &sig_len, msg, msg_size);
    EVP_MD_CTX_free(sign_ctx);

    for (int i = 0; i < iterations; i++)
    {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        EVP_DigestVerifyInit_ex(ctx, NULL, NULL, NULL, "provider=quac100", key, NULL);

        double t0 = get_time_us();
        int result = EVP_DigestVerify(ctx, sig, sig_len, msg, msg_size);
        double t1 = get_time_us();

        (void)result;
        samples[i] = t1 - t0;

        EVP_MD_CTX_free(ctx);
    }

    calc_stats(&r, samples, iterations);
    print_result(&r);

    free(sig);
    free(msg);
    EVP_PKEY_free(key);
    free(samples);
    return 0;
}

/* ==========================================================================
 * Main
 * ========================================================================== */

static void usage(const char *prog)
{
    printf("QUAC 100 OpenSSL Provider Benchmarks\n\n");
    printf("Usage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -n <num>    Iterations per benchmark (default: 100)\n");
    printf("  -a <alg>    Algorithm: mlkem512, mlkem768, mlkem1024,\n");
    printf("                         mldsa44, mldsa65, mldsa87, all (default: all)\n");
    printf("  -m <size>   Message size for sign/verify (default: 32)\n");
    printf("  -c          Show comparison table\n");
    printf("  -h          Show this help\n");
}

static void print_comparison(void)
{
    printf("\nExpected Performance (QUAC 100 Hardware vs Software)\n");
    printf("=====================================================\n");
    printf("| Operation          | Software   | Hardware   | Speedup |\n");
    printf("|--------------------|------------|------------|--------|\n");
    printf("| ML-KEM-768 Keygen  | 150 µs     | 0.7 µs     | 214x   |\n");
    printf("| ML-KEM-768 Encaps  | 100 µs     | 0.5 µs     | 200x   |\n");
    printf("| ML-KEM-768 Decaps  | 120 µs     | 0.5 µs     | 240x   |\n");
    printf("| ML-DSA-65 Keygen   | 500 µs     | 3.0 µs     | 167x   |\n");
    printf("| ML-DSA-65 Sign     | 450 µs     | 2.5 µs     | 180x   |\n");
    printf("| ML-DSA-65 Verify   | 150 µs     | 1.0 µs     | 150x   |\n");
    printf("\n");
}

int main(int argc, char *argv[])
{
    int iterations = 100;
    const char *algorithm = "all";
    size_t msg_size = 32;
    int show_comparison = 0;
    int opt;

    while ((opt = getopt(argc, argv, "n:a:m:ch")) != -1)
    {
        switch (opt)
        {
        case 'n':
            iterations = atoi(optarg);
            break;
        case 'a':
            algorithm = optarg;
            break;
        case 'm':
            msg_size = atoi(optarg);
            break;
        case 'c':
            show_comparison = 1;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        default:
            usage(argv[0]);
            return 1;
        }
    }

    if (show_comparison)
    {
        print_comparison();
        return 0;
    }

    printf("QUAC 100 OpenSSL Provider Benchmarks\n");
    printf("====================================\n");
    printf("Iterations: %d\n", iterations);
    printf("Message size: %zu bytes\n\n", msg_size);

    /* Load provider */
    OSSL_PROVIDER *prov = OSSL_PROVIDER_load(NULL, "quac100");
    if (!prov)
    {
        fprintf(stderr, "Failed to load QUAC 100 provider\n");
        fprintf(stderr, "Make sure OPENSSL_MODULES points to the provider location\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    printf("Provider loaded: %s\n\n", OSSL_PROVIDER_get0_name(prov));

    /* Run benchmarks */
    int run_mlkem = (strcmp(algorithm, "all") == 0 ||
                     strncmp(algorithm, "mlkem", 5) == 0);
    int run_mldsa = (strcmp(algorithm, "all") == 0 ||
                     strncmp(algorithm, "mldsa", 5) == 0);

    if (run_mlkem)
    {
        const char *levels[] = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"};
        int run_level[3] = {
            strcmp(algorithm, "all") == 0 || strcmp(algorithm, "mlkem512") == 0,
            strcmp(algorithm, "all") == 0 || strcmp(algorithm, "mlkem768") == 0,
            strcmp(algorithm, "all") == 0 || strcmp(algorithm, "mlkem1024") == 0};

        for (int i = 0; i < 3; i++)
        {
            if (!run_level[i])
                continue;

            printf("\n%s:\n", levels[i]);
            printf("----------------------------------------\n");
            bench_mlkem_keygen(levels[i], iterations);
            bench_mlkem_encaps(levels[i], iterations);
            bench_mlkem_decaps(levels[i], iterations);
        }
    }

    if (run_mldsa)
    {
        const char *levels[] = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"};
        int run_level[3] = {
            strcmp(algorithm, "all") == 0 || strcmp(algorithm, "mldsa44") == 0,
            strcmp(algorithm, "all") == 0 || strcmp(algorithm, "mldsa65") == 0,
            strcmp(algorithm, "all") == 0 || strcmp(algorithm, "mldsa87") == 0};

        for (int i = 0; i < 3; i++)
        {
            if (!run_level[i])
                continue;

            printf("\n%s:\n", levels[i]);
            printf("----------------------------------------\n");
            bench_mldsa_keygen(levels[i], iterations);
            bench_mldsa_sign(levels[i], iterations, msg_size);
            bench_mldsa_verify(levels[i], iterations, msg_size);
        }
    }

    print_comparison();

    OSSL_PROVIDER_unload(prov);
    return 0;
}