/**
 * @file kem.c
 * @brief QuantaCore SDK - KEM Operations Implementation
 *
 * Implements ML-KEM (Kyber) key encapsulation mechanism operations including
 * key generation, encapsulation, and decapsulation. Supports both hardware
 * acceleration and software simulation modes.
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include "quac100.h"
#include "quac100_types.h"
#include "quac100_error.h"
#include "quac100_kem.h"
#include "internal/quac100_ioctl.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <time.h>
#endif

/*=============================================================================
 * Error Recording Macro
 *=============================================================================*/

extern void quac_error_record(quac_result_t result, const char *file, int line,
                              const char *func, const char *fmt, ...);

#define QUAC_RECORD_ERROR(result, ...) \
    quac_error_record((result), __FILE__, __LINE__, __func__, __VA_ARGS__)

/*=============================================================================
 * Internal Device Access (from device.c)
 *=============================================================================*/

extern intptr_t quac_device_get_ioctl_fd(quac_device_t device);
extern bool quac_device_is_simulator(quac_device_t device);
extern void quac_device_inc_ops(quac_device_t device);
extern void quac_device_lock(quac_device_t device);
extern void quac_device_unlock(quac_device_t device);
extern uint32_t quac_device_get_sim_latency(quac_device_t device);

/*=============================================================================
 * ML-KEM Parameter Sets (FIPS 203)
 *=============================================================================*/

/**
 * @brief ML-KEM parameter structure
 */
typedef struct kem_params_s
{
    quac_algorithm_t algorithm;
    const char *name;
    uint32_t n;    /* Polynomial degree (256) */
    uint32_t k;    /* Module rank */
    uint32_t q;    /* Modulus (3329) */
    uint32_t eta1; /* CBD parameter for secret */
    uint32_t eta2; /* CBD parameter for noise */
    uint32_t du;   /* Compression for u */
    uint32_t dv;   /* Compression for v */
    size_t public_key_size;
    size_t secret_key_size;
    size_t ciphertext_size;
    size_t shared_secret_size;
} kem_params_t;

static const kem_params_t g_kem_params[] = {
    {
        .algorithm = QUAC_ALGORITHM_KYBER512,
        .name = "ML-KEM-512",
        .n = 256,
        .k = 2,
        .q = 3329,
        .eta1 = 3,
        .eta2 = 2,
        .du = 10,
        .dv = 4,
        .public_key_size = 800,
        .secret_key_size = 1632,
        .ciphertext_size = 768,
        .shared_secret_size = 32,
    },
    {
        .algorithm = QUAC_ALGORITHM_KYBER768,
        .name = "ML-KEM-768",
        .n = 256,
        .k = 3,
        .q = 3329,
        .eta1 = 2,
        .eta2 = 2,
        .du = 10,
        .dv = 4,
        .public_key_size = 1184,
        .secret_key_size = 2400,
        .ciphertext_size = 1088,
        .shared_secret_size = 32,
    },
    {
        .algorithm = QUAC_ALGORITHM_KYBER1024,
        .name = "ML-KEM-1024",
        .n = 256,
        .k = 4,
        .q = 3329,
        .eta1 = 2,
        .eta2 = 2,
        .du = 11,
        .dv = 5,
        .public_key_size = 1568,
        .secret_key_size = 3168,
        .ciphertext_size = 1568,
        .shared_secret_size = 32,
    },
};

#define KEM_PARAMS_COUNT (sizeof(g_kem_params) / sizeof(g_kem_params[0]))

/*=============================================================================
 * Global Statistics
 *=============================================================================*/

static quac_kem_stats_t g_kem_stats = {0};

/*=============================================================================
 * Internal Helpers
 *=============================================================================*/

/**
 * @brief Get current timestamp in microseconds
 */
static uint64_t get_timestamp_us(void)
{
#ifdef _WIN32
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (uint64_t)((count.QuadPart * 1000000ULL) / freq.QuadPart);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000;
#endif
}

/**
 * @brief Find KEM parameters for algorithm
 */
static const kem_params_t *find_kem_params(quac_algorithm_t algorithm)
{
    for (size_t i = 0; i < KEM_PARAMS_COUNT; i++)
    {
        if (g_kem_params[i].algorithm == algorithm)
        {
            return &g_kem_params[i];
        }
    }
    return NULL;
}

/**
 * @brief Validate algorithm is a KEM algorithm
 */
static bool is_kem_algorithm(quac_algorithm_t algorithm)
{
    return find_kem_params(algorithm) != NULL;
}

/**
 * @brief Simulate delay for simulator mode
 */
static void simulate_delay(quac_device_t device)
{
    uint32_t latency_us = quac_device_get_sim_latency(device);
    if (latency_us == 0)
    {
        latency_us = 700; /* Default ~700μs for ML-KEM */
    }

#ifdef _WIN32
    Sleep(latency_us / 1000);
#else
    usleep(latency_us);
#endif
}

/**
 * @brief Generate simulated random bytes
 */
static void sim_random_bytes(uint8_t *buf, size_t len)
{
    /* Simple PRNG for simulation - NOT cryptographically secure */
    static uint64_t seed = 0x123456789ABCDEF0ULL;

    for (size_t i = 0; i < len; i++)
    {
        seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
        buf[i] = (uint8_t)(seed >> 56);
    }
}

/**
 * @brief Update statistics for keygen
 */
static void update_keygen_stats(uint64_t duration_us, bool success)
{
    g_kem_stats.keygen_count++;
    if (!success)
    {
        return;
    }

    g_kem_stats.keygen_time_total_us += duration_us;

    if (duration_us < g_kem_stats.keygen_time_min_us ||
        g_kem_stats.keygen_time_min_us == 0)
    {
        g_kem_stats.keygen_time_min_us = (uint32_t)duration_us;
    }
    if (duration_us > g_kem_stats.keygen_time_max_us)
    {
        g_kem_stats.keygen_time_max_us = (uint32_t)duration_us;
    }
    g_kem_stats.keygen_time_avg_us =
        (uint32_t)(g_kem_stats.keygen_time_total_us / g_kem_stats.keygen_count);
}

/**
 * @brief Update statistics for encaps
 */
static void update_encaps_stats(uint64_t duration_us, bool success)
{
    g_kem_stats.encaps_count++;
    if (!success)
    {
        return;
    }

    g_kem_stats.encaps_time_total_us += duration_us;

    if (duration_us < g_kem_stats.encaps_time_min_us ||
        g_kem_stats.encaps_time_min_us == 0)
    {
        g_kem_stats.encaps_time_min_us = (uint32_t)duration_us;
    }
    if (duration_us > g_kem_stats.encaps_time_max_us)
    {
        g_kem_stats.encaps_time_max_us = (uint32_t)duration_us;
    }
    g_kem_stats.encaps_time_avg_us =
        (uint32_t)(g_kem_stats.encaps_time_total_us / g_kem_stats.encaps_count);
}

/**
 * @brief Update statistics for decaps
 */
static void update_decaps_stats(uint64_t duration_us, bool success)
{
    g_kem_stats.decaps_count++;
    if (!success)
    {
        return;
    }

    g_kem_stats.decaps_time_total_us += duration_us;

    if (duration_us < g_kem_stats.decaps_time_min_us ||
        g_kem_stats.decaps_time_min_us == 0)
    {
        g_kem_stats.decaps_time_min_us = (uint32_t)duration_us;
    }
    if (duration_us > g_kem_stats.decaps_time_max_us)
    {
        g_kem_stats.decaps_time_max_us = (uint32_t)duration_us;
    }
    g_kem_stats.decaps_time_avg_us =
        (uint32_t)(g_kem_stats.decaps_time_total_us / g_kem_stats.decaps_count);
}

/*=============================================================================
 * Simulator Implementation
 *=============================================================================*/

/**
 * @brief Simulated key generation
 */
static quac_result_t sim_kem_keygen(const kem_params_t *params,
                                    uint8_t *public_key,
                                    uint8_t *secret_key)
{
    /* Generate random keys for simulation */
    sim_random_bytes(public_key, params->public_key_size);
    sim_random_bytes(secret_key, params->secret_key_size);

    /* Embed public key in secret key (Kyber format) */
    memcpy(secret_key + params->secret_key_size - params->public_key_size - 64,
           public_key, params->public_key_size);

    return QUAC_SUCCESS;
}

/**
 * @brief Simulated encapsulation
 */
static quac_result_t sim_kem_encaps(const kem_params_t *params,
                                    const uint8_t *public_key,
                                    uint8_t *ciphertext,
                                    uint8_t *shared_secret)
{
    (void)public_key;

    /* Generate random ciphertext and shared secret */
    sim_random_bytes(ciphertext, params->ciphertext_size);
    sim_random_bytes(shared_secret, params->shared_secret_size);

    return QUAC_SUCCESS;
}

/**
 * @brief Simulated decapsulation
 */
static quac_result_t sim_kem_decaps(const kem_params_t *params,
                                    const uint8_t *secret_key,
                                    const uint8_t *ciphertext,
                                    uint8_t *shared_secret)
{
    (void)secret_key;
    (void)ciphertext;

    /* Generate deterministic shared secret based on ciphertext */
    /* In real impl, this would derive from secret_key + ciphertext */
    sim_random_bytes(shared_secret, params->shared_secret_size);

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Hardware Implementation
 *=============================================================================*/

/**
 * @brief Hardware key generation via IOCTL
 */
static quac_result_t hw_kem_keygen(quac_device_t device,
                                   const kem_params_t *params,
                                   uint8_t *public_key,
                                   uint8_t *secret_key)
{
    intptr_t fd = quac_device_get_ioctl_fd(device);
    if (fd < 0)
    {
        return QUAC_ERROR_DEVICE_ERROR;
    }

    struct quac_ioctl_kem_keygen req = {
        .struct_size = sizeof(req),
        .algorithm = params->algorithm,
        .flags = 0,
        .public_key_addr = (uint64_t)(uintptr_t)public_key,
        .public_key_size = params->public_key_size,
        .secret_key_addr = (uint64_t)(uintptr_t)secret_key,
        .secret_key_size = params->secret_key_size,
    };

    quac_result_t result = quac_ioctl_execute(fd, QUAC_IOC_KEM_KEYGEN,
                                              &req, sizeof(req));

    return (result == QUAC_SUCCESS) ? req.result : result;
}

/**
 * @brief Hardware encapsulation via IOCTL
 */
static quac_result_t hw_kem_encaps(quac_device_t device,
                                   const kem_params_t *params,
                                   const uint8_t *public_key,
                                   uint8_t *ciphertext,
                                   uint8_t *shared_secret)
{
    intptr_t fd = quac_device_get_ioctl_fd(device);
    if (fd < 0)
    {
        return QUAC_ERROR_DEVICE_ERROR;
    }

    struct quac_ioctl_kem_encaps req = {
        .struct_size = sizeof(req),
        .algorithm = params->algorithm,
        .flags = 0,
        .public_key_addr = (uint64_t)(uintptr_t)public_key,
        .public_key_size = params->public_key_size,
        .ciphertext_addr = (uint64_t)(uintptr_t)ciphertext,
        .ciphertext_size = params->ciphertext_size,
        .shared_secret_addr = (uint64_t)(uintptr_t)shared_secret,
        .shared_secret_size = params->shared_secret_size,
    };

    quac_result_t result = quac_ioctl_execute(fd, QUAC_IOC_KEM_ENCAPS,
                                              &req, sizeof(req));

    return (result == QUAC_SUCCESS) ? req.result : result;
}

/**
 * @brief Hardware decapsulation via IOCTL
 */
static quac_result_t hw_kem_decaps(quac_device_t device,
                                   const kem_params_t *params,
                                   const uint8_t *secret_key,
                                   const uint8_t *ciphertext,
                                   uint8_t *shared_secret)
{
    intptr_t fd = quac_device_get_ioctl_fd(device);
    if (fd < 0)
    {
        return QUAC_ERROR_DEVICE_ERROR;
    }

    struct quac_ioctl_kem_decaps req = {
        .struct_size = sizeof(req),
        .algorithm = params->algorithm,
        .flags = 0,
        .secret_key_addr = (uint64_t)(uintptr_t)secret_key,
        .secret_key_size = params->secret_key_size,
        .ciphertext_addr = (uint64_t)(uintptr_t)ciphertext,
        .ciphertext_size = params->ciphertext_size,
        .shared_secret_addr = (uint64_t)(uintptr_t)shared_secret,
        .shared_secret_size = params->shared_secret_size,
    };

    quac_result_t result = quac_ioctl_execute(fd, QUAC_IOC_KEM_DECAPS,
                                              &req, sizeof(req));

    return (result == QUAC_SUCCESS) ? req.result : result;
}

/*=============================================================================
 * Public API Implementation
 *=============================================================================*/

QUAC100_API quac_result_t QUAC100_CALL
quac_kem_get_sizes(quac_algorithm_t algorithm,
                   size_t *public_key_size,
                   size_t *secret_key_size,
                   size_t *ciphertext_size,
                   size_t *shared_secret_size)
{
    const kem_params_t *params = find_kem_params(algorithm);
    if (!params)
    {
        QUAC_RECORD_ERROR(QUAC_ERROR_INVALID_ALGORITHM,
                          "Algorithm 0x%X is not a KEM algorithm", algorithm);
        return QUAC_ERROR_INVALID_ALGORITHM;
    }

    if (public_key_size)
        *public_key_size = params->public_key_size;
    if (secret_key_size)
        *secret_key_size = params->secret_key_size;
    if (ciphertext_size)
        *ciphertext_size = params->ciphertext_size;
    if (shared_secret_size)
        *shared_secret_size = params->shared_secret_size;

    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_kem_get_params(quac_algorithm_t algorithm, quac_kem_params_t *params)
{
    QUAC_CHECK_NULL(params);

    const kem_params_t *p = find_kem_params(algorithm);
    if (!p)
    {
        QUAC_RECORD_ERROR(QUAC_ERROR_INVALID_ALGORITHM,
                          "Algorithm 0x%X is not a KEM algorithm", algorithm);
        return QUAC_ERROR_INVALID_ALGORITHM;
    }

    memset(params, 0, sizeof(*params));
    params->struct_size = sizeof(*params);
    params->algorithm = algorithm;
    params->n = p->n;
    params->k = p->k;
    params->q = p->q;
    params->eta1 = p->eta1;
    params->eta2 = p->eta2;
    params->du = p->du;
    params->dv = p->dv;
    params->public_key_size = p->public_key_size;
    params->secret_key_size = p->secret_key_size;
    params->ciphertext_size = p->ciphertext_size;
    params->shared_secret_size = p->shared_secret_size;

    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_kem_keygen(quac_device_t device,
                quac_algorithm_t algorithm,
                uint8_t *public_key,
                uint8_t *secret_key)
{
    QUAC_CHECK_NULL(public_key);
    QUAC_CHECK_NULL(secret_key);

    const kem_params_t *params = find_kem_params(algorithm);
    if (!params)
    {
        QUAC_RECORD_ERROR(QUAC_ERROR_INVALID_ALGORITHM,
                          "Algorithm 0x%X is not a KEM algorithm", algorithm);
        return QUAC_ERROR_INVALID_ALGORITHM;
    }

    if (!quac_is_algorithm_supported(device, algorithm))
    {
        QUAC_RECORD_ERROR(QUAC_ERROR_NOT_SUPPORTED,
                          "Algorithm %s not supported by device", params->name);
        return QUAC_ERROR_NOT_SUPPORTED;
    }

    uint64_t start_time = get_timestamp_us();
    quac_result_t result;

    quac_device_lock(device);

    if (quac_device_is_simulator(device))
    {
        simulate_delay(device);
        result = sim_kem_keygen(params, public_key, secret_key);
    }
    else
    {
        result = hw_kem_keygen(device, params, public_key, secret_key);
    }

    quac_device_unlock(device);

    uint64_t duration = get_timestamp_us() - start_time;
    update_keygen_stats(duration, QUAC_SUCCEEDED(result));

    if (QUAC_SUCCEEDED(result))
    {
        quac_device_inc_ops(device);
    }
    else
    {
        QUAC_RECORD_ERROR(result, "KEM key generation failed");
    }

    return result;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_kem_encaps(quac_device_t device,
                quac_algorithm_t algorithm,
                const uint8_t *public_key,
                uint8_t *ciphertext,
                uint8_t *shared_secret)
{
    QUAC_CHECK_NULL(public_key);
    QUAC_CHECK_NULL(ciphertext);
    QUAC_CHECK_NULL(shared_secret);

    const kem_params_t *params = find_kem_params(algorithm);
    if (!params)
    {
        QUAC_RECORD_ERROR(QUAC_ERROR_INVALID_ALGORITHM,
                          "Algorithm 0x%X is not a KEM algorithm", algorithm);
        return QUAC_ERROR_INVALID_ALGORITHM;
    }

    if (!quac_is_algorithm_supported(device, algorithm))
    {
        QUAC_RECORD_ERROR(QUAC_ERROR_NOT_SUPPORTED,
                          "Algorithm %s not supported by device", params->name);
        return QUAC_ERROR_NOT_SUPPORTED;
    }

    uint64_t start_time = get_timestamp_us();
    quac_result_t result;

    quac_device_lock(device);

    if (quac_device_is_simulator(device))
    {
        simulate_delay(device);
        result = sim_kem_encaps(params, public_key, ciphertext, shared_secret);
    }
    else
    {
        result = hw_kem_encaps(device, params, public_key, ciphertext, shared_secret);
    }

    quac_device_unlock(device);

    uint64_t duration = get_timestamp_us() - start_time;
    update_encaps_stats(duration, QUAC_SUCCEEDED(result));

    if (QUAC_SUCCEEDED(result))
    {
        quac_device_inc_ops(device);
    }
    else
    {
        QUAC_RECORD_ERROR(result, "KEM encapsulation failed");
    }

    return result;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_kem_decaps(quac_device_t device,
                quac_algorithm_t algorithm,
                const uint8_t *secret_key,
                const uint8_t *ciphertext,
                uint8_t *shared_secret)
{
    QUAC_CHECK_NULL(secret_key);
    QUAC_CHECK_NULL(ciphertext);
    QUAC_CHECK_NULL(shared_secret);

    const kem_params_t *params = find_kem_params(algorithm);
    if (!params)
    {
        QUAC_RECORD_ERROR(QUAC_ERROR_INVALID_ALGORITHM,
                          "Algorithm 0x%X is not a KEM algorithm", algorithm);
        return QUAC_ERROR_INVALID_ALGORITHM;
    }

    if (!quac_is_algorithm_supported(device, algorithm))
    {
        QUAC_RECORD_ERROR(QUAC_ERROR_NOT_SUPPORTED,
                          "Algorithm %s not supported by device", params->name);
        return QUAC_ERROR_NOT_SUPPORTED;
    }

    uint64_t start_time = get_timestamp_us();
    quac_result_t result;

    quac_device_lock(device);

    if (quac_device_is_simulator(device))
    {
        simulate_delay(device);
        result = sim_kem_decaps(params, secret_key, ciphertext, shared_secret);
    }
    else
    {
        result = hw_kem_decaps(device, params, secret_key, ciphertext, shared_secret);
    }

    quac_device_unlock(device);

    uint64_t duration = get_timestamp_us() - start_time;
    update_decaps_stats(duration, QUAC_SUCCEEDED(result));

    if (QUAC_SUCCEEDED(result))
    {
        quac_device_inc_ops(device);
    }
    else
    {
        QUAC_RECORD_ERROR(result, "KEM decapsulation failed");
    }

    return result;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_kem_validate_public_key(quac_algorithm_t algorithm,
                             const uint8_t *public_key,
                             size_t key_size)
{
    QUAC_CHECK_NULL(public_key);

    const kem_params_t *params = find_kem_params(algorithm);
    if (!params)
    {
        return QUAC_ERROR_INVALID_ALGORITHM;
    }

    if (key_size != params->public_key_size)
    {
        QUAC_RECORD_ERROR(QUAC_ERROR_INVALID_KEY_SIZE,
                          "Expected %zu bytes, got %zu",
                          params->public_key_size, key_size);
        return QUAC_ERROR_INVALID_KEY_SIZE;
    }

    /* Basic validation - check not all zeros */
    bool all_zero = true;
    for (size_t i = 0; i < key_size && all_zero; i++)
    {
        if (public_key[i] != 0)
        {
            all_zero = false;
        }
    }

    if (all_zero)
    {
        QUAC_RECORD_ERROR(QUAC_ERROR_INVALID_KEY, "Public key is all zeros");
        return QUAC_ERROR_INVALID_KEY;
    }

    /* Additional validation would check polynomial coefficients are in range */
    /* For full validation, need to decode and check mod q bounds */

    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_kem_validate_ciphertext(quac_algorithm_t algorithm,
                             const uint8_t *ciphertext,
                             size_t ct_size)
{
    QUAC_CHECK_NULL(ciphertext);

    const kem_params_t *params = find_kem_params(algorithm);
    if (!params)
    {
        return QUAC_ERROR_INVALID_ALGORITHM;
    }

    if (ct_size != params->ciphertext_size)
    {
        QUAC_RECORD_ERROR(QUAC_ERROR_INVALID_CIPHERTEXT,
                          "Expected %zu bytes, got %zu",
                          params->ciphertext_size, ct_size);
        return QUAC_ERROR_INVALID_CIPHERTEXT;
    }

    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_kem_get_stats(quac_kem_stats_t *stats)
{
    QUAC_CHECK_NULL(stats);

    memcpy(stats, &g_kem_stats, sizeof(*stats));
    stats->struct_size = sizeof(*stats);

    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_kem_reset_stats(void)
{
    memset(&g_kem_stats, 0, sizeof(g_kem_stats));
    g_kem_stats.struct_size = sizeof(g_kem_stats);
    return QUAC_SUCCESS;
}

/*=============================================================================
 * Extended API Implementation
 *=============================================================================*/

QUAC100_API quac_result_t QUAC100_CALL
quac_kem_keypair_alloc(quac_algorithm_t algorithm, quac_kem_keypair_t **keypair)
{
    QUAC_CHECK_NULL(keypair);

    const kem_params_t *params = find_kem_params(algorithm);
    if (!params)
    {
        return QUAC_ERROR_INVALID_ALGORITHM;
    }

    size_t total_size = sizeof(quac_kem_keypair_t) +
                        params->public_key_size +
                        params->secret_key_size;

    quac_kem_keypair_t *kp = calloc(1, total_size);
    if (!kp)
    {
        return QUAC_ERROR_OUT_OF_MEMORY;
    }

    kp->struct_size = sizeof(*kp);
    kp->algorithm = algorithm;
    kp->public_key_size = params->public_key_size;
    kp->secret_key_size = params->secret_key_size;

    /* Point to inline storage */
    uint8_t *data = (uint8_t *)(kp + 1);
    kp->public_key = data;
    kp->secret_key = data + params->public_key_size;

    *keypair = kp;
    return QUAC_SUCCESS;
}

QUAC100_API void QUAC100_CALL
quac_kem_keypair_free(quac_kem_keypair_t *keypair)
{
    if (keypair)
    {
        /* Secure wipe secret key */
        if (keypair->secret_key && keypair->secret_key_size > 0)
        {
            volatile uint8_t *p = keypair->secret_key;
            for (size_t i = 0; i < keypair->secret_key_size; i++)
            {
                p[i] = 0;
            }
        }
        free(keypair);
    }
}

QUAC100_API quac_result_t QUAC100_CALL
quac_kem_keygen_ex(quac_device_t device,
                   quac_algorithm_t algorithm,
                   quac_kem_keypair_t *keypair)
{
    QUAC_CHECK_NULL(keypair);

    if (keypair->algorithm != algorithm)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    quac_result_t result = quac_kem_keygen(device, algorithm,
                                           keypair->public_key,
                                           keypair->secret_key);

    if (QUAC_SUCCEEDED(result))
    {
        keypair->has_secret_key = true;
        /* TODO: Compute fingerprint (SHA-256 of public key) */
    }

    return result;
}