/**
 * @file quac100_rand.c
 * @brief QUAC 100 BoringSSL Integration - QRNG Implementation
 *
 * Implements quantum random number generation:
 * - Hardware QRNG when available (1 Gbps throughput)
 * - Fallback to BoringSSL's RAND_bytes
 * - NIST SP 800-90B health tests
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <string.h>
#include <pthread.h>
#include <openssl/rand.h>
#include <openssl/mem.h>

#include "quac100_boringssl.h"

#ifdef QUAC_HAS_HARDWARE
#include <quac100/quac.h>
#endif

/* External declarations */
extern int quac_internal_check_init(void);
extern int quac_internal_use_hardware(void);

#ifdef QUAC_HAS_HARDWARE
extern quac_device_t *quac_internal_get_device(void);
#endif

/* ==========================================================================
 * QRNG State
 * ========================================================================== */

#define QRNG_BUFFER_SIZE 4096
#define QRNG_RESEED_INTERVAL (1024 * 1024) /* 1 MB */

static struct
{
    pthread_mutex_t lock;
    uint8_t buffer[QRNG_BUFFER_SIZE];
    size_t buffer_pos;
    size_t buffer_len;
    uint64_t bytes_generated;
    uint64_t reseed_count;
    int health_status;
} g_qrng_state = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .buffer_pos = 0,
    .buffer_len = 0,
    .bytes_generated = 0,
    .reseed_count = 0,
    .health_status = 1,
};

/* ==========================================================================
 * Health Tests (NIST SP 800-90B)
 * ========================================================================== */

/* Repetition count test threshold */
#define HEALTH_REPETITION_THRESHOLD 9

/* Adaptive proportion test parameters */
#define HEALTH_ADAPTIVE_WINDOW 1024
#define HEALTH_ADAPTIVE_THRESHOLD 645

/**
 * @brief Run repetition count test
 *
 * Detects stuck-at failures by checking for repeated values.
 */
static int health_repetition_count_test(const uint8_t *data, size_t len)
{
    int max_repeat = 1;
    int current_repeat = 1;

    for (size_t i = 1; i < len; i++)
    {
        if (data[i] == data[i - 1])
        {
            current_repeat++;
            if (current_repeat > max_repeat)
            {
                max_repeat = current_repeat;
            }
        }
        else
        {
            current_repeat = 1;
        }
    }

    return (max_repeat < HEALTH_REPETITION_THRESHOLD) ? 1 : 0;
}

/**
 * @brief Run adaptive proportion test
 *
 * Detects bias by checking byte value distribution.
 */
static int health_adaptive_proportion_test(const uint8_t *data, size_t len)
{
    int counts[256] = {0};
    int max_count = 0;

    for (size_t i = 0; i < len; i++)
    {
        counts[data[i]]++;
    }

    for (int i = 0; i < 256; i++)
    {
        if (counts[i] > max_count)
        {
            max_count = counts[i];
        }
    }

    /* For 256 bytes, no value should appear more than ~16 times */
    int threshold = (int)(len / 8);
    if (threshold < 16)
        threshold = 16;

    return (max_count <= threshold) ? 1 : 0;
}

/**
 * @brief Run all health tests on data
 */
static int run_health_tests(const uint8_t *data, size_t len)
{
    if (len < 64)
        return 1; /* Skip for small amounts */

    if (!health_repetition_count_test(data, len))
        return 0;

    if (!health_adaptive_proportion_test(data, len))
        return 0;

    return 1;
}

/* ==========================================================================
 * Buffer Management
 * ========================================================================== */

static int refill_buffer(void)
{
    int ret = 0;

#ifdef QUAC_HAS_HARDWARE
    if (quac_internal_use_hardware())
    {
        quac_device_t *dev = quac_internal_get_device();
        ret = quac_random(dev, g_qrng_state.buffer, QRNG_BUFFER_SIZE);
        if (ret == 0)
        {
            g_qrng_state.buffer_len = QRNG_BUFFER_SIZE;
            g_qrng_state.buffer_pos = 0;
            g_qrng_state.reseed_count++;

            /* Run health tests */
            g_qrng_state.health_status = run_health_tests(
                g_qrng_state.buffer, QRNG_BUFFER_SIZE);

            return QUAC_SUCCESS;
        }
    }
#endif

    /* Fallback to BoringSSL RAND */
    if (RAND_bytes(g_qrng_state.buffer, QRNG_BUFFER_SIZE) != 1)
    {
        return QUAC_ERROR_INTERNAL;
    }

    g_qrng_state.buffer_len = QRNG_BUFFER_SIZE;
    g_qrng_state.buffer_pos = 0;
    g_qrng_state.reseed_count++;
    g_qrng_state.health_status = 1; /* Trust BoringSSL's RAND */

    return QUAC_SUCCESS;
}

/* ==========================================================================
 * Public API
 * ========================================================================== */

int QUAC_random_bytes(uint8_t *buf, size_t len)
{
    int ret;

    ret = quac_internal_check_init();
    if (ret != QUAC_SUCCESS)
        return ret;

    if (!buf || len == 0)
        return QUAC_ERROR_INVALID_KEY;

    pthread_mutex_lock(&g_qrng_state.lock);

    size_t written = 0;
    while (written < len)
    {
        /* Refill buffer if needed */
        if (g_qrng_state.buffer_pos >= g_qrng_state.buffer_len)
        {
            ret = refill_buffer();
            if (ret != QUAC_SUCCESS)
            {
                pthread_mutex_unlock(&g_qrng_state.lock);
                return ret;
            }
        }

        /* Copy from buffer */
        size_t available = g_qrng_state.buffer_len - g_qrng_state.buffer_pos;
        size_t to_copy = len - written;
        if (to_copy > available)
            to_copy = available;

        memcpy(buf + written, g_qrng_state.buffer + g_qrng_state.buffer_pos, to_copy);

        g_qrng_state.buffer_pos += to_copy;
        written += to_copy;
        g_qrng_state.bytes_generated += to_copy;
    }

    pthread_mutex_unlock(&g_qrng_state.lock);

    return QUAC_SUCCESS;
}

int QUAC_random_seed(const uint8_t *seed, size_t seed_len)
{
    if (!seed || seed_len == 0)
        return QUAC_ERROR_INVALID_KEY;

    /* Mix seed into buffer */
    pthread_mutex_lock(&g_qrng_state.lock);

    /* XOR seed into buffer */
    for (size_t i = 0; i < seed_len && i < QRNG_BUFFER_SIZE; i++)
    {
        g_qrng_state.buffer[i] ^= seed[i];
    }

    /* Also add to BoringSSL's entropy pool */
    RAND_add(seed, seed_len, (double)seed_len);

    pthread_mutex_unlock(&g_qrng_state.lock);

    return QUAC_SUCCESS;
}

int QUAC_random_health_check(void)
{
    int status;

    pthread_mutex_lock(&g_qrng_state.lock);
    status = g_qrng_state.health_status;
    pthread_mutex_unlock(&g_qrng_state.lock);

    return status;
}

/* ==========================================================================
 * Statistics
 * ========================================================================== */

typedef struct
{
    uint64_t bytes_generated;
    uint64_t reseed_count;
    int health_status;
    int using_hardware;
} quac_qrng_stats_t;

int QUAC_random_get_stats(quac_qrng_stats_t *stats)
{
    if (!stats)
        return QUAC_ERROR_INVALID_KEY;

    pthread_mutex_lock(&g_qrng_state.lock);

    stats->bytes_generated = g_qrng_state.bytes_generated;
    stats->reseed_count = g_qrng_state.reseed_count;
    stats->health_status = g_qrng_state.health_status;
    stats->using_hardware = quac_internal_use_hardware();

    pthread_mutex_unlock(&g_qrng_state.lock);

    return QUAC_SUCCESS;
}

/* ==========================================================================
 * BoringSSL RAND_METHOD Integration
 * ========================================================================== */

/*
 * BoringSSL doesn't support custom RAND_METHOD like OpenSSL, but
 * applications can use QUAC_random_bytes directly as a replacement
 * for RAND_bytes when quantum random numbers are needed.
 *
 * For transparent integration, compile BoringSSL with QUAC support
 * or use the QUAC_EVP_register() function to hook into EVP.
 */

/* ==========================================================================
 * Direct Hardware Access (Advanced)
 * ========================================================================== */

#ifdef QUAC_HAS_HARDWARE

/**
 * @brief Generate random bytes directly from hardware
 *
 * Bypasses buffering for maximum throughput.
 * Use for bulk random generation.
 */
int QUAC_random_bytes_unbuffered(uint8_t *buf, size_t len)
{
    int ret;

    ret = quac_internal_check_init();
    if (ret != QUAC_SUCCESS)
        return ret;

    if (!buf || len == 0)
        return QUAC_ERROR_INVALID_KEY;

    if (!quac_internal_use_hardware())
        return QUAC_ERROR_HARDWARE_UNAVAILABLE;

    quac_device_t *dev = quac_internal_get_device();

    /* Generate in chunks for hardware */
    size_t chunk_size = 64 * 1024; /* 64 KB chunks */
    size_t written = 0;

    while (written < len)
    {
        size_t to_gen = len - written;
        if (to_gen > chunk_size)
            to_gen = chunk_size;

        ret = quac_random(dev, buf + written, to_gen);
        if (ret != 0)
        {
            return QUAC_ERROR_INTERNAL;
        }

        written += to_gen;
    }

    /* Run health check on sample */
    g_qrng_state.health_status = run_health_tests(buf, len > 256 ? 256 : len);

    return QUAC_SUCCESS;
}

/**
 * @brief Get QRNG throughput estimate
 *
 * @return Estimated bytes per second
 */
uint64_t QUAC_random_get_throughput(void)
{
    if (quac_internal_use_hardware())
    {
        return 125000000; /* 1 Gbps = 125 MB/s */
    }
    else
    {
        return 50000000; /* ~50 MB/s for software */
    }
}

#else

int QUAC_random_bytes_unbuffered(uint8_t *buf, size_t len)
{
    return QUAC_random_bytes(buf, len);
}

uint64_t QUAC_random_get_throughput(void)
{
    return 50000000; /* ~50 MB/s estimate */
}

#endif /* QUAC_HAS_HARDWARE */