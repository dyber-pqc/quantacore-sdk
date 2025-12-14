/**
 * @file bench_quac100_boringssl.c
 * @brief QUAC 100 BoringSSL Integration - Performance Benchmarks
 *
 * Measures throughput for ML-KEM, ML-DSA, and QRNG operations.
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/time.h>
#endif

#include "quac100_boringssl.h"

/* ==========================================================================
 * Timing Utilities
 * ========================================================================== */

static double get_time_seconds(void)
{
#ifdef _WIN32
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (double)count.QuadPart / (double)freq.QuadPart;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0;
#endif
}

/* ==========================================================================
 * Benchmark Utilities
 * ========================================================================== */

typedef struct
{
    const char *name;
    uint64_t iterations;
    double total_time;
    double ops_per_sec;
    double us_per_op;
    double throughput_mbps; /* For QRNG */
} bench_result_t;

static void print_result(const bench_result_t *r)
{
    printf("  %-20s %8lu ops  %8.2f ops/s  %8.2f µs/op",
           r->name, (unsigned long)r->iterations, r->ops_per_sec, r->us_per_op);

    if (r->throughput_mbps > 0)
    {
        printf("  %8.2f MB/s", r->throughput_mbps);
    }
    printf("\n");
}

/* ==========================================================================
 * ML-KEM Benchmarks
 * ========================================================================== */

static void bench_mlkem(quac_kem_algorithm_t alg, const char *name, int duration_sec)
{
    size_t pk_len = QUAC_KEM_public_key_bytes(alg);
    size_t sk_len = QUAC_KEM_secret_key_bytes(alg);
    size_t ct_len = QUAC_KEM_ciphertext_bytes(alg);

    uint8_t *pk = malloc(pk_len);
    uint8_t *sk = malloc(sk_len);
    uint8_t *ct = malloc(ct_len);
    uint8_t ss[32];

    double start, end;
    uint64_t count;
    bench_result_t result;

    printf("\n%s:\n", name);

    /* Keygen benchmark */
    count = 0;
    start = get_time_seconds();
    end = start + duration_sec;
    while (get_time_seconds() < end)
    {
        QUAC_KEM_keypair(alg, pk, sk);
        count++;
    }
    end = get_time_seconds();

    result.name = "keygen";
    result.iterations = count;
    result.total_time = end - start;
    result.ops_per_sec = count / result.total_time;
    result.us_per_op = (result.total_time * 1000000.0) / count;
    result.throughput_mbps = 0;
    print_result(&result);

    /* Generate a keypair for encaps/decaps */
    QUAC_KEM_keypair(alg, pk, sk);

    /* Encaps benchmark */
    count = 0;
    start = get_time_seconds();
    end = start + duration_sec;
    while (get_time_seconds() < end)
    {
        QUAC_KEM_encaps(alg, ct, ss, pk);
        count++;
    }
    end = get_time_seconds();

    result.name = "encaps";
    result.iterations = count;
    result.total_time = end - start;
    result.ops_per_sec = count / result.total_time;
    result.us_per_op = (result.total_time * 1000000.0) / count;
    print_result(&result);

    /* Encapsulate for decaps test */
    QUAC_KEM_encaps(alg, ct, ss, pk);

    /* Decaps benchmark */
    count = 0;
    start = get_time_seconds();
    end = start + duration_sec;
    while (get_time_seconds() < end)
    {
        QUAC_KEM_decaps(alg, ss, ct, sk);
        count++;
    }
    end = get_time_seconds();

    result.name = "decaps";
    result.iterations = count;
    result.total_time = end - start;
    result.ops_per_sec = count / result.total_time;
    result.us_per_op = (result.total_time * 1000000.0) / count;
    print_result(&result);

    free(pk);
    free(sk);
    free(ct);
}

/* ==========================================================================
 * ML-DSA Benchmarks
 * ========================================================================== */

static void bench_mldsa(quac_sig_algorithm_t alg, const char *name, int duration_sec)
{
    size_t pk_len = QUAC_SIG_public_key_bytes(alg);
    size_t sk_len = QUAC_SIG_secret_key_bytes(alg);
    size_t sig_max = QUAC_SIG_signature_bytes(alg);

    uint8_t *pk = malloc(pk_len);
    uint8_t *sk = malloc(sk_len);
    uint8_t *sig = malloc(sig_max);
    size_t sig_len;

    uint8_t msg[64];
    memset(msg, 0x42, sizeof(msg));

    double start, end;
    uint64_t count;
    bench_result_t result;

    printf("\n%s:\n", name);

    /* Keygen benchmark */
    count = 0;
    start = get_time_seconds();
    end = start + duration_sec;
    while (get_time_seconds() < end)
    {
        QUAC_SIG_keypair(alg, pk, sk);
        count++;
    }
    end = get_time_seconds();

    result.name = "keygen";
    result.iterations = count;
    result.total_time = end - start;
    result.ops_per_sec = count / result.total_time;
    result.us_per_op = (result.total_time * 1000000.0) / count;
    result.throughput_mbps = 0;
    print_result(&result);

    /* Generate keypair for sign/verify */
    QUAC_SIG_keypair(alg, pk, sk);

    /* Sign benchmark */
    count = 0;
    start = get_time_seconds();
    end = start + duration_sec;
    while (get_time_seconds() < end)
    {
        QUAC_sign(alg, sig, &sig_len, msg, sizeof(msg), sk);
        count++;
    }
    end = get_time_seconds();

    result.name = "sign";
    result.iterations = count;
    result.total_time = end - start;
    result.ops_per_sec = count / result.total_time;
    result.us_per_op = (result.total_time * 1000000.0) / count;
    print_result(&result);

    /* Sign for verify test */
    QUAC_sign(alg, sig, &sig_len, msg, sizeof(msg), sk);

    /* Verify benchmark */
    count = 0;
    start = get_time_seconds();
    end = start + duration_sec;
    while (get_time_seconds() < end)
    {
        QUAC_verify(alg, sig, sig_len, msg, sizeof(msg), pk);
        count++;
    }
    end = get_time_seconds();

    result.name = "verify";
    result.iterations = count;
    result.total_time = end - start;
    result.ops_per_sec = count / result.total_time;
    result.us_per_op = (result.total_time * 1000000.0) / count;
    print_result(&result);

    free(pk);
    free(sk);
    free(sig);
}

/* ==========================================================================
 * QRNG Benchmarks
 * ========================================================================== */

static void bench_qrng(int duration_sec)
{
    size_t sizes[] = {32, 256, 1024, 4096, 16384, 65536};
    int num_sizes = sizeof(sizes) / sizeof(sizes[0]);

    printf("\nQRNG:\n");

    for (int i = 0; i < num_sizes; i++)
    {
        size_t buf_size = sizes[i];
        uint8_t *buf = malloc(buf_size);

        double start, end;
        uint64_t count = 0;
        uint64_t bytes = 0;

        start = get_time_seconds();
        end = start + duration_sec;
        while (get_time_seconds() < end)
        {
            QUAC_random_bytes(buf, buf_size);
            count++;
            bytes += buf_size;
        }
        end = get_time_seconds();

        double total_time = end - start;
        double mbps = (bytes / (1024.0 * 1024.0)) / total_time;

        char name[32];
        snprintf(name, sizeof(name), "%zu bytes", buf_size);

        bench_result_t result = {
            .name = name,
            .iterations = count,
            .total_time = total_time,
            .ops_per_sec = count / total_time,
            .us_per_op = (total_time * 1000000.0) / count,
            .throughput_mbps = mbps};
        print_result(&result);

        free(buf);
    }
}

/* ==========================================================================
 * Main
 * ========================================================================== */

int main(int argc, char *argv[])
{
    int duration = 2; /* seconds per benchmark */

    /* Parse arguments */
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-d") == 0 && i + 1 < argc)
        {
            duration = atoi(argv[++i]);
            if (duration < 1)
                duration = 1;
            if (duration > 60)
                duration = 60;
        }
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
        {
            printf("Usage: %s [-d duration_seconds]\n", argv[0]);
            printf("  -d N    Run each benchmark for N seconds (default: 2)\n");
            return 0;
        }
    }

    printf("=== QUAC 100 BoringSSL Integration Benchmarks ===\n");
    printf("Version: %s\n", QUAC_BORINGSSL_VERSION_STRING);
    printf("Duration: %d seconds per benchmark\n", duration);

    /* Initialize */
    int ret = QUAC_init();
    if (ret != QUAC_SUCCESS)
    {
        printf("FATAL: QUAC_init failed: %s\n", QUAC_get_error_string(ret));
        return 1;
    }

    printf("Hardware: %s\n", QUAC_is_hardware_available() ? "Yes" : "No (simulator)");

    printf("\n--- ML-KEM Benchmarks ---");
    bench_mlkem(QUAC_KEM_ML_KEM_512, "ML-KEM-512", duration);
    bench_mlkem(QUAC_KEM_ML_KEM_768, "ML-KEM-768", duration);
    bench_mlkem(QUAC_KEM_ML_KEM_1024, "ML-KEM-1024", duration);

    printf("\n--- ML-DSA Benchmarks ---");
    bench_mldsa(QUAC_SIG_ML_DSA_44, "ML-DSA-44", duration);
    bench_mldsa(QUAC_SIG_ML_DSA_65, "ML-DSA-65", duration);
    bench_mldsa(QUAC_SIG_ML_DSA_87, "ML-DSA-87", duration);

    printf("\n--- QRNG Benchmarks ---");
    bench_qrng(duration);

    printf("\n=== Benchmark Complete ===\n");

    QUAC_cleanup();

    return 0;
}