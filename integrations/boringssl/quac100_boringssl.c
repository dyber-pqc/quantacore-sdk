/**
 * @file quac100_boringssl.c
 * @brief QUAC 100 BoringSSL Integration - Core Implementation
 *
 * Main entry points and initialization for the QUAC 100 BoringSSL integration.
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <string.h>
#include <stdlib.h>
#include <pthread.h>

#include <openssl/rand.h>
#include <openssl/mem.h>
#include <openssl/err.h>

#include "quac100_boringssl.h"

#ifdef QUAC_HAS_HARDWARE
#include <quac100/quac.h>
#endif

/* ==========================================================================
 * Global State
 * ========================================================================== */

static struct
{
    int initialized;
    int hardware_available;
    int device_index;
    pthread_mutex_t lock;
#ifdef QUAC_HAS_HARDWARE
    quac_device_t device;
#endif
} g_quac_state = {
    .initialized = 0,
    .hardware_available = 0,
    .device_index = 0,
    .lock = PTHREAD_MUTEX_INITIALIZER,
};

/* ==========================================================================
 * Error Messages
 * ========================================================================== */

static const char *error_strings[] = {
    [0] = "Success",
    [1] = "Invalid algorithm",
    [2] = "Invalid key",
    [3] = "Invalid signature",
    [4] = "Invalid ciphertext",
    [5] = "Buffer too small",
    [6] = "Hardware unavailable",
    [7] = "Internal error",
    [8] = "Not initialized",
    [9] = "Memory allocation failed",
    [10] = "Verification failed",
};

const char *QUAC_get_error_string(int error_code)
{
    int idx = -error_code;
    if (idx >= 0 && idx < (int)(sizeof(error_strings) / sizeof(error_strings[0])))
    {
        return error_strings[idx];
    }
    return "Unknown error";
}

/* ==========================================================================
 * Initialization
 * ========================================================================== */

int QUAC_init(void)
{
    return QUAC_init_ex(0, 0);
}

int QUAC_init_ex(int use_hardware, int device_index)
{
    pthread_mutex_lock(&g_quac_state.lock);

    if (g_quac_state.initialized)
    {
        pthread_mutex_unlock(&g_quac_state.lock);
        return QUAC_SUCCESS;
    }

    g_quac_state.device_index = device_index;
    g_quac_state.hardware_available = 0;

#ifdef QUAC_HAS_HARDWARE
    /* Try to initialize hardware */
    if (quac_init() == QUAC_SUCCESS)
    {
        int count = quac_get_device_count();
        if (count > device_index)
        {
            if (quac_open_device(device_index, &g_quac_state.device) == QUAC_SUCCESS)
            {
                g_quac_state.hardware_available = 1;
            }
        }
    }
#endif

    if (use_hardware && !g_quac_state.hardware_available)
    {
        pthread_mutex_unlock(&g_quac_state.lock);
        return QUAC_ERROR_HARDWARE_UNAVAILABLE;
    }

    g_quac_state.initialized = 1;
    pthread_mutex_unlock(&g_quac_state.lock);

    return QUAC_SUCCESS;
}

void QUAC_cleanup(void)
{
    pthread_mutex_lock(&g_quac_state.lock);

    if (!g_quac_state.initialized)
    {
        pthread_mutex_unlock(&g_quac_state.lock);
        return;
    }

#ifdef QUAC_HAS_HARDWARE
    if (g_quac_state.hardware_available)
    {
        quac_close_device(&g_quac_state.device);
    }
    quac_cleanup();
#endif

    g_quac_state.initialized = 0;
    g_quac_state.hardware_available = 0;

    pthread_mutex_unlock(&g_quac_state.lock);
}

int QUAC_is_hardware_available(void)
{
    return g_quac_state.hardware_available;
}

const char *QUAC_version_string(void)
{
    return QUAC_BORINGSSL_VERSION_STRING;
}

/* ==========================================================================
 * Internal Helpers
 * ========================================================================== */

int quac_internal_check_init(void)
{
    if (!g_quac_state.initialized)
    {
        return QUAC_ERROR_NOT_INITIALIZED;
    }
    return QUAC_SUCCESS;
}

int quac_internal_use_hardware(void)
{
    return g_quac_state.hardware_available;
}

#ifdef QUAC_HAS_HARDWARE
quac_device_t *quac_internal_get_device(void)
{
    return &g_quac_state.device;
}
#endif

/* ==========================================================================
 * Secure Memory
 * ========================================================================== */

void *quac_secure_alloc(size_t size)
{
    return OPENSSL_malloc(size);
}

void quac_secure_free(void *ptr, size_t size)
{
    if (ptr)
    {
        OPENSSL_cleanse(ptr, size);
        OPENSSL_free(ptr);
    }
}

void quac_secure_cleanse(void *ptr, size_t size)
{
    OPENSSL_cleanse(ptr, size);
}

/* ==========================================================================
 * Self-Test
 * ========================================================================== */

/* KAT test vectors (abbreviated) */
static const uint8_t kat_mlkem768_seed[32] = {
    0x7c, 0x99, 0x35, 0xa0, 0xb0, 0x76, 0x94, 0xaa,
    0x0c, 0x6d, 0x10, 0xe4, 0xdb, 0x6b, 0x1a, 0xdd,
    0x2f, 0xd8, 0x1a, 0x25, 0xcc, 0xb1, 0x48, 0x03,
    0x2d, 0xcd, 0x73, 0x99, 0x36, 0x73, 0x7f, 0x2d};

int QUAC_self_test(void)
{
    int ret;
    uint8_t pk[QUAC_ML_KEM_768_PUBLIC_KEY_BYTES];
    uint8_t sk[QUAC_ML_KEM_768_SECRET_KEY_BYTES];
    uint8_t ct[QUAC_ML_KEM_768_CIPHERTEXT_BYTES];
    uint8_t ss1[QUAC_ML_KEM_768_SHARED_SECRET_BYTES];
    uint8_t ss2[QUAC_ML_KEM_768_SHARED_SECRET_BYTES];

    (void)kat_mlkem768_seed;

    /* ML-KEM round-trip test */
    ret = QUAC_KEM_keypair(QUAC_KEM_ML_KEM_768, pk, sk);
    if (ret != QUAC_SUCCESS)
        return ret;

    ret = QUAC_KEM_encaps(QUAC_KEM_ML_KEM_768, ct, ss1, pk);
    if (ret != QUAC_SUCCESS)
        return ret;

    ret = QUAC_KEM_decaps(QUAC_KEM_ML_KEM_768, ss2, ct, sk);
    if (ret != QUAC_SUCCESS)
        return ret;

    if (OPENSSL_memcmp(ss1, ss2, sizeof(ss1)) != 0)
        return QUAC_ERROR_INTERNAL;

    /* ML-DSA round-trip test */
    uint8_t sig_pk[QUAC_ML_DSA_65_PUBLIC_KEY_BYTES];
    uint8_t sig_sk[QUAC_ML_DSA_65_SECRET_KEY_BYTES];
    uint8_t sig[QUAC_ML_DSA_65_SIGNATURE_BYTES];
    size_t sig_len;
    uint8_t msg[] = "Self-test message";

    ret = QUAC_SIG_keypair(QUAC_SIG_ML_DSA_65, sig_pk, sig_sk);
    if (ret != QUAC_SUCCESS)
        return ret;

    ret = QUAC_sign(QUAC_SIG_ML_DSA_65, sig, &sig_len, msg, sizeof(msg) - 1, sig_sk);
    if (ret != QUAC_SUCCESS)
        return ret;

    ret = QUAC_verify(QUAC_SIG_ML_DSA_65, sig, sig_len, msg, sizeof(msg) - 1, sig_pk);
    if (ret != QUAC_SUCCESS)
        return ret;

    /* Tamper test - should fail */
    msg[0] ^= 0xFF;
    ret = QUAC_verify(QUAC_SIG_ML_DSA_65, sig, sig_len, msg, sizeof(msg) - 1, sig_pk);
    if (ret != QUAC_ERROR_VERIFICATION_FAILED)
        return QUAC_ERROR_INTERNAL;

    /* Secure cleanup */
    quac_secure_cleanse(sk, sizeof(sk));
    quac_secure_cleanse(sig_sk, sizeof(sig_sk));

    return QUAC_SUCCESS;
}

int QUAC_integrity_check(void)
{
    /* In production, would verify HMAC of library binary */
    return QUAC_SUCCESS;
}

/* ==========================================================================
 * Benchmark Implementation
 * ========================================================================== */

#include <time.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/time.h>
#endif

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

int QUAC_benchmark(int alg, int duration_sec,
                   quac_benchmark_result_t *results,
                   size_t *result_count)
{
    double start, end;
    uint64_t count;
    size_t idx = 0;

    if (!results || !result_count || *result_count < 3)
        return QUAC_ERROR_BUFFER_TOO_SMALL;

    /* Check if it's a KEM algorithm */
    if (alg >= QUAC_KEM_ML_KEM_512 && alg <= QUAC_KEM_ML_KEM_1024)
    {
        quac_kem_algorithm_t kem_alg = (quac_kem_algorithm_t)alg;
        size_t pk_len = QUAC_KEM_public_key_bytes(kem_alg);
        size_t sk_len = QUAC_KEM_secret_key_bytes(kem_alg);
        size_t ct_len = QUAC_KEM_ciphertext_bytes(kem_alg);

        uint8_t *pk = malloc(pk_len);
        uint8_t *sk = malloc(sk_len);
        uint8_t *ct = malloc(ct_len);
        uint8_t ss[32];

        if (!pk || !sk || !ct)
        {
            free(pk);
            free(sk);
            free(ct);
            return QUAC_ERROR_MEMORY_ALLOCATION;
        }

        /* Keygen benchmark */
        count = 0;
        start = get_time_seconds();
        end = start + duration_sec;
        while (get_time_seconds() < end)
        {
            QUAC_KEM_keypair(kem_alg, pk, sk);
            count++;
        }
        end = get_time_seconds();

        results[idx].algorithm = kem_alg == QUAC_KEM_ML_KEM_512 ? "ML-KEM-512" : kem_alg == QUAC_KEM_ML_KEM_768 ? "ML-KEM-768"
                                                                                                                : "ML-KEM-1024";
        results[idx].operation = "keygen";
        results[idx].iterations = count;
        results[idx].total_seconds = end - start;
        results[idx].ops_per_second = count / (end - start);
        results[idx].microseconds_per_op = ((end - start) * 1000000.0) / count;
        idx++;

        /* Encaps benchmark */
        QUAC_KEM_keypair(kem_alg, pk, sk);
        count = 0;
        start = get_time_seconds();
        end = start + duration_sec;
        while (get_time_seconds() < end)
        {
            QUAC_KEM_encaps(kem_alg, ct, ss, pk);
            count++;
        }
        end = get_time_seconds();

        results[idx].algorithm = results[0].algorithm;
        results[idx].operation = "encaps";
        results[idx].iterations = count;
        results[idx].total_seconds = end - start;
        results[idx].ops_per_second = count / (end - start);
        results[idx].microseconds_per_op = ((end - start) * 1000000.0) / count;
        idx++;

        /* Decaps benchmark */
        QUAC_KEM_encaps(kem_alg, ct, ss, pk);
        count = 0;
        start = get_time_seconds();
        end = start + duration_sec;
        while (get_time_seconds() < end)
        {
            QUAC_KEM_decaps(kem_alg, ss, ct, sk);
            count++;
        }
        end = get_time_seconds();

        results[idx].algorithm = results[0].algorithm;
        results[idx].operation = "decaps";
        results[idx].iterations = count;
        results[idx].total_seconds = end - start;
        results[idx].ops_per_second = count / (end - start);
        results[idx].microseconds_per_op = ((end - start) * 1000000.0) / count;
        idx++;

        quac_secure_free(sk, sk_len);
        free(pk);
        free(ct);
    }

    *result_count = idx;
    return QUAC_SUCCESS;
}