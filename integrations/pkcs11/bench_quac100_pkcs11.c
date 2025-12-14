/**
 * @file bench_pkcs11.c
 * @brief QUAC 100 PKCS#11 Module - Performance Benchmark
 *
 * Benchmarks cryptographic operations through the PKCS#11 interface.
 *
 * Usage:
 *   ./bench_pkcs11 [iterations]
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

#include "quac100_pkcs11.h"

/* ==========================================================================
 * Timing Utilities
 * ========================================================================== */

typedef struct
{
    double start;
    double end;
} bench_timer_t;

static double get_time_ms(void)
{
#ifdef _WIN32
    LARGE_INTEGER freq, counter;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart * 1000.0 / (double)freq.QuadPart;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec * 1000.0 + (double)tv.tv_usec / 1000.0;
#endif
}

static void timer_start(bench_timer_t *timer)
{
    timer->start = get_time_ms();
}

static void timer_stop(bench_timer_t *timer)
{
    timer->end = get_time_ms();
}

static double timer_elapsed_ms(bench_timer_t *timer)
{
    return timer->end - timer->start;
}

static double timer_ops_per_sec(bench_timer_t *timer, int iterations)
{
    double elapsed_sec = timer_elapsed_ms(timer) / 1000.0;
    return (double)iterations / elapsed_sec;
}

/* ==========================================================================
 * Benchmark Functions
 * ========================================================================== */

static void bench_mlkem_keygen(CK_SESSION_HANDLE hSession, int iterations)
{
    CK_RV rv;
    CK_OBJECT_HANDLE hPubKey, hPrivKey;
    bench_timer_t timer;

    CK_MECHANISM mechanism = {CKM_ML_KEM_768_KEY_PAIR_GEN, NULL, 0};

    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_ML_KEM_768;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;

    CK_ATTRIBUTE pubTemplate[] = {
        {CKA_CLASS, &pubClass, sizeof(pubClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &bFalse, sizeof(bFalse)},
        {CKA_DERIVE, &bTrue, sizeof(bTrue)},
    };

    CK_ATTRIBUTE privTemplate[] = {
        {CKA_CLASS, &privClass, sizeof(privClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &bFalse, sizeof(bFalse)},
        {CKA_DERIVE, &bTrue, sizeof(bTrue)},
    };

    printf("ML-KEM-768 Key Generation (%d iterations):\n", iterations);

    timer_start(&timer);

    for (int i = 0; i < iterations; i++)
    {
        rv = C_GenerateKeyPair(hSession, &mechanism,
                               pubTemplate, sizeof(pubTemplate) / sizeof(pubTemplate[0]),
                               privTemplate, sizeof(privTemplate) / sizeof(privTemplate[0]),
                               &hPubKey, &hPrivKey);
        if (rv != CKR_OK)
        {
            printf("  ERROR: C_GenerateKeyPair failed: 0x%08lX\n", (unsigned long)rv);
            return;
        }

        C_DestroyObject(hSession, hPubKey);
        C_DestroyObject(hSession, hPrivKey);
    }

    timer_stop(&timer);

    printf("  Total time:     %.2f ms\n", timer_elapsed_ms(&timer));
    printf("  Per operation:  %.3f ms\n", timer_elapsed_ms(&timer) / iterations);
    printf("  Throughput:     %.1f ops/sec\n", timer_ops_per_sec(&timer, iterations));
    printf("\n");
}

static void bench_mldsa_keygen(CK_SESSION_HANDLE hSession, int iterations)
{
    CK_RV rv;
    CK_OBJECT_HANDLE hPubKey, hPrivKey;
    bench_timer_t timer;

    CK_MECHANISM mechanism = {CKM_ML_DSA_65_KEY_PAIR_GEN, NULL, 0};

    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_ML_DSA_65;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;

    CK_ATTRIBUTE pubTemplate[] = {
        {CKA_CLASS, &pubClass, sizeof(pubClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &bFalse, sizeof(bFalse)},
        {CKA_VERIFY, &bTrue, sizeof(bTrue)},
    };

    CK_ATTRIBUTE privTemplate[] = {
        {CKA_CLASS, &privClass, sizeof(privClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &bFalse, sizeof(bFalse)},
        {CKA_SIGN, &bTrue, sizeof(bTrue)},
    };

    printf("ML-DSA-65 Key Generation (%d iterations):\n", iterations);

    timer_start(&timer);

    for (int i = 0; i < iterations; i++)
    {
        rv = C_GenerateKeyPair(hSession, &mechanism,
                               pubTemplate, sizeof(pubTemplate) / sizeof(pubTemplate[0]),
                               privTemplate, sizeof(privTemplate) / sizeof(privTemplate[0]),
                               &hPubKey, &hPrivKey);
        if (rv != CKR_OK)
        {
            printf("  ERROR: C_GenerateKeyPair failed: 0x%08lX\n", (unsigned long)rv);
            return;
        }

        C_DestroyObject(hSession, hPubKey);
        C_DestroyObject(hSession, hPrivKey);
    }

    timer_stop(&timer);

    printf("  Total time:     %.2f ms\n", timer_elapsed_ms(&timer));
    printf("  Per operation:  %.3f ms\n", timer_elapsed_ms(&timer) / iterations);
    printf("  Throughput:     %.1f ops/sec\n", timer_ops_per_sec(&timer, iterations));
    printf("\n");
}

static void bench_mldsa_sign(CK_SESSION_HANDLE hSession, int iterations)
{
    CK_RV rv;
    CK_OBJECT_HANDLE hPubKey, hPrivKey;
    bench_timer_t timer;

    CK_MECHANISM keygenMech = {CKM_ML_DSA_65_KEY_PAIR_GEN, NULL, 0};
    CK_MECHANISM signMech = {CKM_ML_DSA_65, NULL, 0};

    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_ML_DSA_65;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;

    CK_ATTRIBUTE pubTemplate[] = {
        {CKA_CLASS, &pubClass, sizeof(pubClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &bFalse, sizeof(bFalse)},
        {CKA_VERIFY, &bTrue, sizeof(bTrue)},
    };

    CK_ATTRIBUTE privTemplate[] = {
        {CKA_CLASS, &privClass, sizeof(privClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &bFalse, sizeof(bFalse)},
        {CKA_SIGN, &bTrue, sizeof(bTrue)},
    };

    /* Generate keypair */
    rv = C_GenerateKeyPair(hSession, &keygenMech,
                           pubTemplate, sizeof(pubTemplate) / sizeof(pubTemplate[0]),
                           privTemplate, sizeof(privTemplate) / sizeof(privTemplate[0]),
                           &hPubKey, &hPrivKey);
    if (rv != CKR_OK)
    {
        printf("  ERROR: Key generation failed: 0x%08lX\n", (unsigned long)rv);
        return;
    }

    /* Test data */
    CK_BYTE data[256];
    for (int i = 0; i < 256; i++)
        data[i] = (CK_BYTE)i;

    CK_BYTE signature[4096];
    CK_ULONG sigLen;

    printf("ML-DSA-65 Signing (%d iterations, 256-byte message):\n", iterations);

    timer_start(&timer);

    for (int i = 0; i < iterations; i++)
    {
        sigLen = sizeof(signature);

        rv = C_SignInit(hSession, &signMech, hPrivKey);
        if (rv != CKR_OK)
        {
            printf("  ERROR: C_SignInit failed: 0x%08lX\n", (unsigned long)rv);
            goto cleanup;
        }

        rv = C_Sign(hSession, data, sizeof(data), signature, &sigLen);
        if (rv != CKR_OK)
        {
            printf("  ERROR: C_Sign failed: 0x%08lX\n", (unsigned long)rv);
            goto cleanup;
        }
    }

    timer_stop(&timer);

    printf("  Total time:     %.2f ms\n", timer_elapsed_ms(&timer));
    printf("  Per operation:  %.3f ms\n", timer_elapsed_ms(&timer) / iterations);
    printf("  Throughput:     %.1f ops/sec\n", timer_ops_per_sec(&timer, iterations));
    printf("\n");

cleanup:
    C_DestroyObject(hSession, hPubKey);
    C_DestroyObject(hSession, hPrivKey);
}

static void bench_mldsa_verify(CK_SESSION_HANDLE hSession, int iterations)
{
    CK_RV rv;
    CK_OBJECT_HANDLE hPubKey, hPrivKey;
    bench_timer_t timer;

    CK_MECHANISM keygenMech = {CKM_ML_DSA_65_KEY_PAIR_GEN, NULL, 0};
    CK_MECHANISM signMech = {CKM_ML_DSA_65, NULL, 0};

    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_ML_DSA_65;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;

    CK_ATTRIBUTE pubTemplate[] = {
        {CKA_CLASS, &pubClass, sizeof(pubClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &bFalse, sizeof(bFalse)},
        {CKA_VERIFY, &bTrue, sizeof(bTrue)},
    };

    CK_ATTRIBUTE privTemplate[] = {
        {CKA_CLASS, &privClass, sizeof(privClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &bFalse, sizeof(bFalse)},
        {CKA_SIGN, &bTrue, sizeof(bTrue)},
    };

    /* Generate keypair */
    rv = C_GenerateKeyPair(hSession, &keygenMech,
                           pubTemplate, sizeof(pubTemplate) / sizeof(pubTemplate[0]),
                           privTemplate, sizeof(privTemplate) / sizeof(privTemplate[0]),
                           &hPubKey, &hPrivKey);
    if (rv != CKR_OK)
    {
        printf("  ERROR: Key generation failed: 0x%08lX\n", (unsigned long)rv);
        return;
    }

    /* Test data */
    CK_BYTE data[256];
    for (int i = 0; i < 256; i++)
        data[i] = (CK_BYTE)i;

    CK_BYTE signature[4096];
    CK_ULONG sigLen = sizeof(signature);

    /* Create signature */
    rv = C_SignInit(hSession, &signMech, hPrivKey);
    if (rv != CKR_OK)
        goto cleanup;

    rv = C_Sign(hSession, data, sizeof(data), signature, &sigLen);
    if (rv != CKR_OK)
        goto cleanup;

    printf("ML-DSA-65 Verification (%d iterations, 256-byte message):\n", iterations);

    timer_start(&timer);

    for (int i = 0; i < iterations; i++)
    {
        rv = C_VerifyInit(hSession, &signMech, hPubKey);
        if (rv != CKR_OK)
        {
            printf("  ERROR: C_VerifyInit failed: 0x%08lX\n", (unsigned long)rv);
            goto cleanup;
        }

        rv = C_Verify(hSession, data, sizeof(data), signature, sigLen);
        if (rv != CKR_OK)
        {
            printf("  ERROR: C_Verify failed: 0x%08lX\n", (unsigned long)rv);
            goto cleanup;
        }
    }

    timer_stop(&timer);

    printf("  Total time:     %.2f ms\n", timer_elapsed_ms(&timer));
    printf("  Per operation:  %.3f ms\n", timer_elapsed_ms(&timer) / iterations);
    printf("  Throughput:     %.1f ops/sec\n", timer_ops_per_sec(&timer, iterations));
    printf("\n");

cleanup:
    C_DestroyObject(hSession, hPubKey);
    C_DestroyObject(hSession, hPrivKey);
}

static void bench_random(CK_SESSION_HANDLE hSession, int iterations)
{
    CK_RV rv;
    bench_timer_t timer;
    CK_BYTE random[32];

    printf("Random Generation (%d iterations, 32 bytes each):\n", iterations);

    timer_start(&timer);

    for (int i = 0; i < iterations; i++)
    {
        rv = C_GenerateRandom(hSession, random, sizeof(random));
        if (rv != CKR_OK)
        {
            printf("  ERROR: C_GenerateRandom failed: 0x%08lX\n", (unsigned long)rv);
            return;
        }
    }

    timer_stop(&timer);

    double total_bytes = (double)iterations * sizeof(random);
    double elapsed_sec = timer_elapsed_ms(&timer) / 1000.0;

    printf("  Total time:     %.2f ms\n", timer_elapsed_ms(&timer));
    printf("  Per operation:  %.3f ms\n", timer_elapsed_ms(&timer) / iterations);
    printf("  Throughput:     %.1f ops/sec\n", timer_ops_per_sec(&timer, iterations));
    printf("  Bandwidth:      %.2f MB/s\n", (total_bytes / 1024.0 / 1024.0) / elapsed_sec);
    printf("\n");
}

/* ==========================================================================
 * All ML-KEM Variants
 * ========================================================================== */

static void bench_mlkem_all_variants(CK_SESSION_HANDLE hSession, int iterations)
{
    CK_RV rv;
    CK_OBJECT_HANDLE hPubKey, hPrivKey;
    bench_timer_t timer;

    struct
    {
        const char *name;
        CK_MECHANISM_TYPE mechType;
        CK_KEY_TYPE keyType;
    } variants[] = {
        {"ML-KEM-512", CKM_ML_KEM_512_KEY_PAIR_GEN, CKK_ML_KEM_512},
        {"ML-KEM-768", CKM_ML_KEM_768_KEY_PAIR_GEN, CKK_ML_KEM_768},
        {"ML-KEM-1024", CKM_ML_KEM_1024_KEY_PAIR_GEN, CKK_ML_KEM_1024},
    };

    printf("=== ML-KEM All Variants Key Generation ===\n\n");

    for (size_t v = 0; v < sizeof(variants) / sizeof(variants[0]); v++)
    {
        CK_MECHANISM mechanism = {variants[v].mechType, NULL, 0};

        CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
        CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
        CK_KEY_TYPE keyType = variants[v].keyType;
        CK_BBOOL bTrue = CK_TRUE;
        CK_BBOOL bFalse = CK_FALSE;

        CK_ATTRIBUTE pubTemplate[] = {
            {CKA_CLASS, &pubClass, sizeof(pubClass)},
            {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
            {CKA_TOKEN, &bFalse, sizeof(bFalse)},
            {CKA_DERIVE, &bTrue, sizeof(bTrue)},
        };

        CK_ATTRIBUTE privTemplate[] = {
            {CKA_CLASS, &privClass, sizeof(privClass)},
            {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
            {CKA_TOKEN, &bFalse, sizeof(bFalse)},
            {CKA_DERIVE, &bTrue, sizeof(bTrue)},
        };

        printf("%s Key Generation (%d iterations):\n", variants[v].name, iterations);

        timer_start(&timer);

        for (int i = 0; i < iterations; i++)
        {
            rv = C_GenerateKeyPair(hSession, &mechanism,
                                   pubTemplate, sizeof(pubTemplate) / sizeof(pubTemplate[0]),
                                   privTemplate, sizeof(privTemplate) / sizeof(privTemplate[0]),
                                   &hPubKey, &hPrivKey);
            if (rv != CKR_OK)
            {
                printf("  ERROR: C_GenerateKeyPair failed: 0x%08lX\n", (unsigned long)rv);
                break;
            }

            C_DestroyObject(hSession, hPubKey);
            C_DestroyObject(hSession, hPrivKey);
        }

        timer_stop(&timer);

        printf("  Total time:     %.2f ms\n", timer_elapsed_ms(&timer));
        printf("  Per operation:  %.3f ms\n", timer_elapsed_ms(&timer) / iterations);
        printf("  Throughput:     %.1f ops/sec\n", timer_ops_per_sec(&timer, iterations));
        printf("\n");
    }
}

/* ==========================================================================
 * All ML-DSA Variants
 * ========================================================================== */

static void bench_mldsa_all_variants(CK_SESSION_HANDLE hSession, int iterations)
{
    CK_RV rv;
    CK_OBJECT_HANDLE hPubKey, hPrivKey;
    bench_timer_t timer;

    struct
    {
        const char *name;
        CK_MECHANISM_TYPE keygenMech;
        CK_MECHANISM_TYPE signMech;
        CK_KEY_TYPE keyType;
    } variants[] = {
        {"ML-DSA-44", CKM_ML_DSA_44_KEY_PAIR_GEN, CKM_ML_DSA_44, CKK_ML_DSA_44},
        {"ML-DSA-65", CKM_ML_DSA_65_KEY_PAIR_GEN, CKM_ML_DSA_65, CKK_ML_DSA_65},
        {"ML-DSA-87", CKM_ML_DSA_87_KEY_PAIR_GEN, CKM_ML_DSA_87, CKK_ML_DSA_87},
    };

    printf("=== ML-DSA All Variants ===\n\n");

    CK_BYTE data[256];
    for (int i = 0; i < 256; i++)
        data[i] = (CK_BYTE)i;

    for (size_t v = 0; v < sizeof(variants) / sizeof(variants[0]); v++)
    {
        CK_MECHANISM keygenMechanism = {variants[v].keygenMech, NULL, 0};
        CK_MECHANISM signMechanism = {variants[v].signMech, NULL, 0};

        CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
        CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
        CK_KEY_TYPE keyType = variants[v].keyType;
        CK_BBOOL bTrue = CK_TRUE;
        CK_BBOOL bFalse = CK_FALSE;

        CK_ATTRIBUTE pubTemplate[] = {
            {CKA_CLASS, &pubClass, sizeof(pubClass)},
            {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
            {CKA_TOKEN, &bFalse, sizeof(bFalse)},
            {CKA_VERIFY, &bTrue, sizeof(bTrue)},
        };

        CK_ATTRIBUTE privTemplate[] = {
            {CKA_CLASS, &privClass, sizeof(privClass)},
            {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
            {CKA_TOKEN, &bFalse, sizeof(bFalse)},
            {CKA_SIGN, &bTrue, sizeof(bTrue)},
        };

        printf("%s (%d iterations):\n", variants[v].name, iterations);

        /* Key Generation */
        timer_start(&timer);

        for (int i = 0; i < iterations; i++)
        {
            rv = C_GenerateKeyPair(hSession, &keygenMechanism,
                                   pubTemplate, sizeof(pubTemplate) / sizeof(pubTemplate[0]),
                                   privTemplate, sizeof(privTemplate) / sizeof(privTemplate[0]),
                                   &hPubKey, &hPrivKey);
            if (rv != CKR_OK)
                break;

            C_DestroyObject(hSession, hPubKey);
            C_DestroyObject(hSession, hPrivKey);
        }

        timer_stop(&timer);
        printf("  KeyGen:   %.1f ops/sec (%.3f ms/op)\n",
               timer_ops_per_sec(&timer, iterations),
               timer_elapsed_ms(&timer) / iterations);

        /* Generate key for sign/verify */
        rv = C_GenerateKeyPair(hSession, &keygenMechanism,
                               pubTemplate, sizeof(pubTemplate) / sizeof(pubTemplate[0]),
                               privTemplate, sizeof(privTemplate) / sizeof(privTemplate[0]),
                               &hPubKey, &hPrivKey);
        if (rv != CKR_OK)
            continue;

        /* Signing */
        CK_BYTE signature[8192];
        CK_ULONG sigLen;

        timer_start(&timer);

        for (int i = 0; i < iterations; i++)
        {
            sigLen = sizeof(signature);
            rv = C_SignInit(hSession, &signMechanism, hPrivKey);
            if (rv != CKR_OK)
                break;
            rv = C_Sign(hSession, data, sizeof(data), signature, &sigLen);
            if (rv != CKR_OK)
                break;
        }

        timer_stop(&timer);
        printf("  Sign:     %.1f ops/sec (%.3f ms/op)\n",
               timer_ops_per_sec(&timer, iterations),
               timer_elapsed_ms(&timer) / iterations);

        /* Create signature for verification */
        sigLen = sizeof(signature);
        C_SignInit(hSession, &signMechanism, hPrivKey);
        C_Sign(hSession, data, sizeof(data), signature, &sigLen);

        /* Verification */
        timer_start(&timer);

        for (int i = 0; i < iterations; i++)
        {
            rv = C_VerifyInit(hSession, &signMechanism, hPubKey);
            if (rv != CKR_OK)
                break;
            rv = C_Verify(hSession, data, sizeof(data), signature, sigLen);
            if (rv != CKR_OK)
                break;
        }

        timer_stop(&timer);
        printf("  Verify:   %.1f ops/sec (%.3f ms/op)\n",
               timer_ops_per_sec(&timer, iterations),
               timer_elapsed_ms(&timer) / iterations);

        C_DestroyObject(hSession, hPubKey);
        C_DestroyObject(hSession, hPrivKey);

        printf("\n");
    }
}

/* ==========================================================================
 * Main
 * ========================================================================== */

int main(int argc, char *argv[])
{
    CK_RV rv;
    CK_SLOT_ID slotList[16];
    CK_ULONG slotCount = 16;
    CK_SESSION_HANDLE hSession;
    int iterations = 100;

    if (argc > 1)
    {
        iterations = atoi(argv[1]);
        if (iterations < 1)
            iterations = 1;
        if (iterations > 10000)
            iterations = 10000;
    }

    printf("==============================================\n");
    printf("QUAC 100 PKCS#11 Module - Performance Benchmark\n");
    printf("==============================================\n");
    printf("Iterations: %d\n\n", iterations);

    /* Initialize */
    rv = C_Initialize(NULL);
    if (rv != CKR_OK)
    {
        printf("ERROR: C_Initialize failed: 0x%08lX\n", (unsigned long)rv);
        return 1;
    }

    /* Get slot */
    rv = C_GetSlotList(CK_TRUE, slotList, &slotCount);
    if (rv != CKR_OK || slotCount == 0)
    {
        printf("ERROR: No tokens found\n");
        C_Finalize(NULL);
        return 1;
    }

    /* Open session */
    rv = C_OpenSession(slotList[0], CKF_SERIAL_SESSION | CKF_RW_SESSION,
                       NULL, NULL, &hSession);
    if (rv != CKR_OK)
    {
        printf("ERROR: C_OpenSession failed: 0x%08lX\n", (unsigned long)rv);
        C_Finalize(NULL);
        return 1;
    }

    /* Run benchmarks */
    printf("=== Individual Benchmarks ===\n\n");

    bench_mlkem_keygen(hSession, iterations);
    bench_mldsa_keygen(hSession, iterations);
    bench_mldsa_sign(hSession, iterations);
    bench_mldsa_verify(hSession, iterations);
    bench_random(hSession, iterations * 10);

    bench_mlkem_all_variants(hSession, iterations);
    bench_mldsa_all_variants(hSession, iterations);

    /* Summary */
    printf("==============================================\n");
    printf("Benchmark Complete\n");
    printf("==============================================\n");

    /* Cleanup */
    C_CloseSession(hSession);
    C_Finalize(NULL);

    return 0;
}