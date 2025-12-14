/**
 * @file bench_quac_tls.c
 * @brief QUAC 100 TLS Integration - Benchmarks
 *
 * Performance benchmarks for QUAC TLS operations.
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <getopt.h>

#include "quac_tls.h"

/* ==========================================================================
 * Timing
 * ========================================================================== */

static double get_time_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
}

/* ==========================================================================
 * Benchmark Results
 * ========================================================================== */

typedef struct
{
    const char *name;
    int iterations;
    double total_ms;
    double min_ms;
    double max_ms;
    double avg_ms;
    double ops_per_sec;
} bench_result_t;

static void print_result(bench_result_t *r)
{
    printf("%-35s %6d iter  %8.2f ms total  %8.3f ms/op  %10.0f ops/sec\n",
           r->name, r->iterations, r->total_ms, r->avg_ms, r->ops_per_sec);
}

/* ==========================================================================
 * Benchmarks
 * ========================================================================== */

static void bench_mldsa_keygen(int level, const char *name, int iterations)
{
    bench_result_t r = {0};
    r.name = name;
    r.iterations = iterations;
    r.min_ms = 1e9;

    uint8_t *pub, *priv;
    size_t pub_len, priv_len;

    double start = get_time_ms();

    for (int i = 0; i < iterations; i++)
    {
        double t0 = get_time_ms();
        quac_tls_generate_mldsa_keypair(level, &pub, &pub_len, &priv, &priv_len);
        double t1 = get_time_ms();

        double elapsed = t1 - t0;
        if (elapsed < r.min_ms)
            r.min_ms = elapsed;
        if (elapsed > r.max_ms)
            r.max_ms = elapsed;

        free(pub);
        free(priv);
    }

    double end = get_time_ms();
    r.total_ms = end - start;
    r.avg_ms = r.total_ms / iterations;
    r.ops_per_sec = 1000.0 / r.avg_ms;

    print_result(&r);
}

static void bench_self_signed(int level, const char *name, int iterations)
{
    bench_result_t r = {0};
    r.name = name;
    r.iterations = iterations;
    r.min_ms = 1e9;

    char *cert, *key;

    double start = get_time_ms();

    for (int i = 0; i < iterations; i++)
    {
        double t0 = get_time_ms();
        quac_tls_generate_self_signed_mldsa(level, "CN=bench", 365, &cert, &key);
        double t1 = get_time_ms();

        double elapsed = t1 - t0;
        if (elapsed < r.min_ms)
            r.min_ms = elapsed;
        if (elapsed > r.max_ms)
            r.max_ms = elapsed;

        free(cert);
        free(key);
    }

    double end = get_time_ms();
    r.total_ms = end - start;
    r.avg_ms = r.total_ms / iterations;
    r.ops_per_sec = 1000.0 / r.avg_ms;

    print_result(&r);
}

static void bench_ctx_creation(int iterations)
{
    bench_result_t r = {0};
    r.name = "Context Creation";
    r.iterations = iterations;
    r.min_ms = 1e9;

    double start = get_time_ms();

    for (int i = 0; i < iterations; i++)
    {
        double t0 = get_time_ms();
        quac_tls_ctx_t *ctx = quac_tls_ctx_new(1);
        double t1 = get_time_ms();

        double elapsed = t1 - t0;
        if (elapsed < r.min_ms)
            r.min_ms = elapsed;
        if (elapsed > r.max_ms)
            r.max_ms = elapsed;

        quac_tls_ctx_free(ctx);
    }

    double end = get_time_ms();
    r.total_ms = end - start;
    r.avg_ms = r.total_ms / iterations;
    r.ops_per_sec = 1000.0 / r.avg_ms;

    print_result(&r);
}

static void bench_conn_creation(int iterations)
{
    bench_result_t r = {0};
    r.name = "Connection Creation";
    r.iterations = iterations;
    r.min_ms = 1e9;

    quac_tls_ctx_t *ctx = quac_tls_ctx_new(1);
    if (!ctx)
        return;

    double start = get_time_ms();

    for (int i = 0; i < iterations; i++)
    {
        double t0 = get_time_ms();
        quac_tls_conn_t *conn = quac_tls_conn_new(ctx);
        double t1 = get_time_ms();

        double elapsed = t1 - t0;
        if (elapsed < r.min_ms)
            r.min_ms = elapsed;
        if (elapsed > r.max_ms)
            r.max_ms = elapsed;

        quac_tls_conn_free(conn);
    }

    double end = get_time_ms();
    r.total_ms = end - start;
    r.avg_ms = r.total_ms / iterations;
    r.ops_per_sec = 1000.0 / r.avg_ms;

    quac_tls_ctx_free(ctx);
    print_result(&r);
}

static void bench_config_default(int iterations)
{
    bench_result_t r = {0};
    r.name = "Config Default";
    r.iterations = iterations;
    r.min_ms = 1e9;

    quac_tls_config_t config;

    double start = get_time_ms();

    for (int i = 0; i < iterations; i++)
    {
        double t0 = get_time_ms();
        quac_tls_config_default(&config);
        double t1 = get_time_ms();

        double elapsed = t1 - t0;
        if (elapsed < r.min_ms)
            r.min_ms = elapsed;
        if (elapsed > r.max_ms)
            r.max_ms = elapsed;
    }

    double end = get_time_ms();
    r.total_ms = end - start;
    r.avg_ms = r.total_ms / iterations;
    r.ops_per_sec = 1000.0 / r.avg_ms;

    print_result(&r);
}

/* ==========================================================================
 * Main
 * ========================================================================== */

static void usage(const char *prog)
{
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  -n <num>   Iterations (default: 100)\n");
    printf("  -c         Show comparison table only\n");
    printf("  -h         Show help\n");
}

static void print_comparison(void)
{
    printf("\n");
    printf("Expected Performance (QUAC 100 Hardware vs Software)\n");
    printf("=====================================================\n");
    printf("| Operation           | Software  | Hardware  | Speedup |\n");
    printf("|---------------------|-----------|-----------|--------|\n");
    printf("| ML-KEM-768 Keygen   | 0.15 ms   | 0.7 µs    | 214x   |\n");
    printf("| ML-KEM-768 Encaps   | 0.10 ms   | 0.5 µs    | 200x   |\n");
    printf("| ML-KEM-768 Decaps   | 0.12 ms   | 0.5 µs    | 240x   |\n");
    printf("| ML-DSA-65 Sign      | 0.45 ms   | 2.5 µs    | 180x   |\n");
    printf("| ML-DSA-65 Verify    | 0.15 ms   | 1.0 µs    | 150x   |\n");
    printf("| TLS Handshake       | 5 ms      | 20 µs     | 250x   |\n");
    printf("\n");
}

int main(int argc, char *argv[])
{
    int iterations = 100;
    int compare_only = 0;
    int opt;

    while ((opt = getopt(argc, argv, "n:ch")) != -1)
    {
        switch (opt)
        {
        case 'n':
            iterations = atoi(optarg);
            if (iterations < 1)
                iterations = 1;
            break;
        case 'c':
            compare_only = 1;
            break;
        case 'h':
        default:
            usage(argv[0]);
            return (opt == 'h') ? 0 : 1;
        }
    }

    if (compare_only)
    {
        print_comparison();
        return 0;
    }

    printf("================================================\n");
    printf("QUAC TLS Library Benchmarks\n");
    printf("Iterations: %d\n", iterations);
    printf("================================================\n\n");

    if (quac_tls_init() != QUAC_TLS_OK)
    {
        fprintf(stderr, "Failed to initialize library\n");
        return 1;
    }

    printf("Configuration:\n");
    bench_config_default(iterations * 10);

    printf("\nContext/Connection:\n");
    bench_ctx_creation(iterations);
    bench_conn_creation(iterations);

    printf("\nML-DSA Key Generation:\n");
    bench_mldsa_keygen(44, "ML-DSA-44 Keygen", iterations);
    bench_mldsa_keygen(65, "ML-DSA-65 Keygen", iterations);
    bench_mldsa_keygen(87, "ML-DSA-87 Keygen", iterations);

    printf("\nCertificate Generation:\n");
    bench_self_signed(44, "Self-Signed ML-DSA-44", iterations / 2);
    bench_self_signed(65, "Self-Signed ML-DSA-65", iterations / 2);
    bench_self_signed(87, "Self-Signed ML-DSA-87", iterations / 2);

    quac_tls_cleanup();

    print_comparison();

    printf("================================================\n");
    printf("Benchmarks complete.\n");
    printf("================================================\n");

    return 0;
}