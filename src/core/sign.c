/**
 * @file sign.c
 * @brief QuantaCore SDK - Digital Signature Operations Implementation
 *
 * Implements ML-DSA (Dilithium) and SLH-DSA (SPHINCS+) digital signature
 * operations including key generation, signing, and verification.
 * Supports both hardware acceleration and software simulation modes.
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include "quac100.h"
#include "quac100_types.h"
#include "quac100_error.h"
#include "quac100_sign.h"
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
 * ML-DSA (Dilithium) Parameter Sets (FIPS 204)
 *=============================================================================*/

/**
 * @brief Signature algorithm parameter structure
 */
typedef struct sign_params_s
{
    quac_algorithm_t algorithm;
    const char *name;
    quac_sign_family_t family;

    /* Size information */
    size_t public_key_size;
    size_t secret_key_size;
    size_t signature_size;

    /* ML-DSA specific parameters */
    uint32_t n;      /* Polynomial degree (256) */
    uint32_t k;      /* Rows in A */
    uint32_t l;      /* Columns in A */
    uint32_t q;      /* Modulus */
    uint32_t eta;    /* Secret key range */
    uint32_t tau;    /* Number of ±1s in c */
    uint32_t beta;   /* tau * eta */
    uint32_t gamma1; /* y coefficient range */
    uint32_t gamma2; /* Low-order rounding range */
    uint32_t omega;  /* Max hint ones */

    /* SLH-DSA specific parameters */
    uint32_t sphincs_n; /* Security parameter */
    uint32_t sphincs_h; /* Total tree height */
    uint32_t sphincs_d; /* Layers */
    uint32_t sphincs_a; /* FORS trees */
    uint32_t sphincs_k; /* FORS leaves */
    uint32_t sphincs_w; /* Winternitz parameter */

} sign_params_t;

static const sign_params_t g_sign_params[] = {
    /* ML-DSA (Dilithium) variants */
    {
        .algorithm = QUAC_ALGORITHM_DILITHIUM2,
        .name = "ML-DSA-44",
        .family = QUAC_SIGN_FAMILY_DILITHIUM,
        .public_key_size = 1312,
        .secret_key_size = 2560,
        .signature_size = 2420,
        .n = 256,
        .k = 4,
        .l = 4,
        .q = 8380417,
        .eta = 2,
        .tau = 39,
        .beta = 78,
        .gamma1 = (1 << 17),
        .gamma2 = (8380417 - 1) / 88,
        .omega = 80,
    },
    {
        .algorithm = QUAC_ALGORITHM_DILITHIUM3,
        .name = "ML-DSA-65",
        .family = QUAC_SIGN_FAMILY_DILITHIUM,
        .public_key_size = 1952,
        .secret_key_size = 4032,
        .signature_size = 3293,
        .n = 256,
        .k = 6,
        .l = 5,
        .q = 8380417,
        .eta = 4,
        .tau = 49,
        .beta = 196,
        .gamma1 = (1 << 19),
        .gamma2 = (8380417 - 1) / 32,
        .omega = 55,
    },
    {
        .algorithm = QUAC_ALGORITHM_DILITHIUM5,
        .name = "ML-DSA-87",
        .family = QUAC_SIGN_FAMILY_DILITHIUM,
        .public_key_size = 2592,
        .secret_key_size = 4896,
        .signature_size = 4595,
        .n = 256,
        .k = 8,
        .l = 7,
        .q = 8380417,
        .eta = 2,
        .tau = 60,
        .beta = 120,
        .gamma1 = (1 << 19),
        .gamma2 = (8380417 - 1) / 32,
        .omega = 75,
    },

    /* SLH-DSA (SPHINCS+) SHA2 variants */
    {
        .algorithm = QUAC_ALGORITHM_SPHINCS_SHA2_128S,
        .name = "SLH-DSA-SHA2-128s",
        .family = QUAC_SIGN_FAMILY_SPHINCS,
        .public_key_size = 32,
        .secret_key_size = 64,
        .signature_size = 7856,
        .sphincs_n = 16,
        .sphincs_h = 63,
        .sphincs_d = 7,
        .sphincs_a = 12,
        .sphincs_k = 14,
        .sphincs_w = 16,
    },
    {
        .algorithm = QUAC_ALGORITHM_SPHINCS_SHA2_128F,
        .name = "SLH-DSA-SHA2-128f",
        .family = QUAC_SIGN_FAMILY_SPHINCS,
        .public_key_size = 32,
        .secret_key_size = 64,
        .signature_size = 17088,
        .sphincs_n = 16,
        .sphincs_h = 66,
        .sphincs_d = 22,
        .sphincs_a = 6,
        .sphincs_k = 33,
        .sphincs_w = 16,
    },
    {
        .algorithm = QUAC_ALGORITHM_SPHINCS_SHA2_192S,
        .name = "SLH-DSA-SHA2-192s",
        .family = QUAC_SIGN_FAMILY_SPHINCS,
        .public_key_size = 48,
        .secret_key_size = 96,
        .signature_size = 16224,
        .sphincs_n = 24,
        .sphincs_h = 63,
        .sphincs_d = 7,
        .sphincs_a = 14,
        .sphincs_k = 17,
        .sphincs_w = 16,
    },
    {
        .algorithm = QUAC_ALGORITHM_SPHINCS_SHA2_192F,
        .name = "SLH-DSA-SHA2-192f",
        .family = QUAC_SIGN_FAMILY_SPHINCS,
        .public_key_size = 48,
        .secret_key_size = 96,
        .signature_size = 35664,
        .sphincs_n = 24,
        .sphincs_h = 66,
        .sphincs_d = 22,
        .sphincs_a = 8,
        .sphincs_k = 33,
        .sphincs_w = 16,
    },
    {
        .algorithm = QUAC_ALGORITHM_SPHINCS_SHA2_256S,
        .name = "SLH-DSA-SHA2-256s",
        .family = QUAC_SIGN_FAMILY_SPHINCS,
        .public_key_size = 64,
        .secret_key_size = 128,
        .signature_size = 29792,
        .sphincs_n = 32,
        .sphincs_h = 64,
        .sphincs_d = 8,
        .sphincs_a = 14,
        .sphincs_k = 22,
        .sphincs_w = 16,
    },
    {
        .algorithm = QUAC_ALGORITHM_SPHINCS_SHA2_256F,
        .name = "SLH-DSA-SHA2-256f",
        .family = QUAC_SIGN_FAMILY_SPHINCS,
        .public_key_size = 64,
        .secret_key_size = 128,
        .signature_size = 49856,
        .sphincs_n = 32,
        .sphincs_h = 68,
        .sphincs_d = 17,
        .sphincs_a = 9,
        .sphincs_k = 35,
        .sphincs_w = 16,
    },
};

#define SIGN_PARAMS_COUNT (sizeof(g_sign_params) / sizeof(g_sign_params[0]))

/*=============================================================================
 * Global Statistics
 *=============================================================================*/

static quac_sign_stats_t g_sign_stats = {0};

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
 * @brief Find signature parameters for algorithm
 */
static const sign_params_t *find_sign_params(quac_algorithm_t algorithm)
{
    for (size_t i = 0; i < SIGN_PARAMS_COUNT; i++)
    {
        if (g_sign_params[i].algorithm == algorithm)
        {
            return &g_sign_params[i];
        }
    }
    return NULL;
}

/**
 * @brief Check if algorithm is a signature algorithm
 */
static bool is_sign_algorithm(quac_algorithm_t algorithm)
{
    return find_sign_params(algorithm) != NULL;
}

/**
 * @brief Simulate delay for simulator mode
 */
static void simulate_delay(quac_device_t device, const sign_params_t *params)
{
    uint32_t latency_us = quac_device_get_sim_latency(device);

    if (latency_us == 0)
    {
        /* Default latencies based on algorithm family */
        if (params->family == QUAC_SIGN_FAMILY_DILITHIUM)
        {
            latency_us = 750; /* ~750μs for ML-DSA */
        }
        else
        {
            latency_us = 5000; /* ~5ms for SLH-DSA (much slower) */
        }
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
    static uint64_t seed = 0xFEDCBA9876543210ULL;

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
    g_sign_stats.keygen_count++;
    if (!success)
        return;

    g_sign_stats.keygen_time_total_us += duration_us;
    if (duration_us < g_sign_stats.keygen_time_min_us ||
        g_sign_stats.keygen_time_min_us == 0)
    {
        g_sign_stats.keygen_time_min_us = (uint32_t)duration_us;
    }
    if (duration_us > g_sign_stats.keygen_time_max_us)
    {
        g_sign_stats.keygen_time_max_us = (uint32_t)duration_us;
    }
    g_sign_stats.keygen_time_avg_us =
        (uint32_t)(g_sign_stats.keygen_time_total_us / g_sign_stats.keygen_count);
}

/**
 * @brief Update statistics for signing
 */
static void update_sign_stats(uint64_t duration_us, bool success)
{
    g_sign_stats.sign_count++;
    if (!success)
        return;

    g_sign_stats.sign_time_total_us += duration_us;
    if (duration_us < g_sign_stats.sign_time_min_us ||
        g_sign_stats.sign_time_min_us == 0)
    {
        g_sign_stats.sign_time_min_us = (uint32_t)duration_us;
    }
    if (duration_us > g_sign_stats.sign_time_max_us)
    {
        g_sign_stats.sign_time_max_us = (uint32_t)duration_us;
    }
    g_sign_stats.sign_time_avg_us =
        (uint32_t)(g_sign_stats.sign_time_total_us / g_sign_stats.sign_count);
}

/**
 * @brief Update statistics for verification
 */
static void update_verify_stats(uint64_t duration_us, bool success)
{
    g_sign_stats.verify_count++;
    if (!success)
        return;

    g_sign_stats.verify_time_total_us += duration_us;
    if (duration_us < g_sign_stats.verify_time_min_us ||
        g_sign_stats.verify_time_min_us == 0)
    {
        g_sign_stats.verify_time_min_us = (uint32_t)duration_us;
    }
    if (duration_us > g_sign_stats.verify_time_max_us)
    {
        g_sign_stats.verify_time_max_us = (uint32_t)duration_us;
    }
    g_sign_stats.verify_time_avg_us =
        (uint32_t)(g_sign_stats.verify_time_total_us / g_sign_stats.verify_count);
}

/*=============================================================================
 * Simulator Implementation
 *=============================================================================*/

/**
 * @brief Simulated key generation
 */
static quac_result_t sim_sign_keygen(const sign_params_t *params,
                                     uint8_t *public_key,
                                     uint8_t *secret_key)
{
    /* Generate random keys for simulation */
    sim_random_bytes(public_key, params->public_key_size);
    sim_random_bytes(secret_key, params->secret_key_size);

    /* Embed public key hash in secret key (typical format) */
    memcpy(secret_key + params->secret_key_size - params->public_key_size,
           public_key,
           (params->public_key_size < 64) ? params->public_key_size : 64);

    return QUAC_SUCCESS;
}

/**
 * @brief Simulated signing
 */
static quac_result_t sim_sign(const sign_params_t *params,
                              const uint8_t *secret_key,
                              const uint8_t *message,
                              size_t message_len,
                              uint8_t *signature,
                              size_t *signature_len)
{
    (void)secret_key;
    (void)message;
    (void)message_len;

    /* Generate deterministic-looking signature */
    sim_random_bytes(signature, params->signature_size);
    *signature_len = params->signature_size;

    return QUAC_SUCCESS;
}

/**
 * @brief Simulated verification
 */
static quac_result_t sim_verify(const sign_params_t *params,
                                const uint8_t *public_key,
                                const uint8_t *message,
                                size_t message_len,
                                const uint8_t *signature,
                                size_t signature_len)
{
    (void)public_key;
    (void)message;
    (void)message_len;
    (void)signature;

    /* Check signature size */
    if (signature_len != params->signature_size)
    {
        return QUAC_ERROR_INVALID_SIGNATURE;
    }

    /* Simulator always verifies successfully */
    return QUAC_SUCCESS;
}

/*=============================================================================
 * Hardware Implementation
 *=============================================================================*/

/**
 * @brief Hardware key generation via IOCTL
 */
static quac_result_t hw_sign_keygen(quac_device_t device,
                                    const sign_params_t *params,
                                    uint8_t *public_key,
                                    uint8_t *secret_key)
{
    intptr_t fd = quac_device_get_ioctl_fd(device);
    if (fd < 0)
    {
        return QUAC_ERROR_DEVICE_ERROR;
    }

    struct quac_ioctl_sign_keygen req = {
        .struct_size = sizeof(req),
        .algorithm = params->algorithm,
        .flags = 0,
        .public_key_addr = (uint64_t)(uintptr_t)public_key,
        .public_key_size = params->public_key_size,
        .secret_key_addr = (uint64_t)(uintptr_t)secret_key,
        .secret_key_size = params->secret_key_size,
    };

    quac_result_t result = quac_ioctl_execute(fd, QUAC_IOC_SIGN_KEYGEN,
                                              &req, sizeof(req));

    return (result == QUAC_SUCCESS) ? req.result : result;
}

/**
 * @brief Hardware signing via IOCTL
 */
static quac_result_t hw_sign(quac_device_t device,
                             const sign_params_t *params,
                             const uint8_t *secret_key,
                             const uint8_t *message,
                             size_t message_len,
                             uint8_t *signature,
                             size_t *signature_len)
{
    intptr_t fd = quac_device_get_ioctl_fd(device);
    if (fd < 0)
    {
        return QUAC_ERROR_DEVICE_ERROR;
    }

    struct quac_ioctl_sign req = {
        .struct_size = sizeof(req),
        .algorithm = params->algorithm,
        .flags = 0,
        .secret_key_addr = (uint64_t)(uintptr_t)secret_key,
        .secret_key_size = params->secret_key_size,
        .message_addr = (uint64_t)(uintptr_t)message,
        .message_size = message_len,
        .signature_addr = (uint64_t)(uintptr_t)signature,
        .signature_size = params->signature_size,
    };

    quac_result_t result = quac_ioctl_execute(fd, QUAC_IOC_SIGN,
                                              &req, sizeof(req));

    if (result == QUAC_SUCCESS && req.result == QUAC_SUCCESS)
    {
        *signature_len = req.actual_signature_size;
    }

    return (result == QUAC_SUCCESS) ? req.result : result;
}

/**
 * @brief Hardware verification via IOCTL
 */
static quac_result_t hw_verify(quac_device_t device,
                               const sign_params_t *params,
                               const uint8_t *public_key,
                               const uint8_t *message,
                               size_t message_len,
                               const uint8_t *signature,
                               size_t signature_len)
{
    intptr_t fd = quac_device_get_ioctl_fd(device);
    if (fd < 0)
    {
        return QUAC_ERROR_DEVICE_ERROR;
    }

    struct quac_ioctl_verify req = {
        .struct_size = sizeof(req),
        .algorithm = params->algorithm,
        .flags = 0,
        .public_key_addr = (uint64_t)(uintptr_t)public_key,
        .public_key_size = params->public_key_size,
        .message_addr = (uint64_t)(uintptr_t)message,
        .message_size = message_len,
        .signature_addr = (uint64_t)(uintptr_t)signature,
        .signature_size = signature_len,
    };

    quac_result_t result = quac_ioctl_execute(fd, QUAC_IOC_VERIFY,
                                              &req, sizeof(req));

    return (result == QUAC_SUCCESS) ? req.result : result;
}

/*=============================================================================
 * Public API Implementation
 *=============================================================================*/

QUAC100_API quac_result_t QUAC100_CALL
quac_sign_get_sizes(quac_algorithm_t algorithm,
                    size_t *public_key_size,
                    size_t *secret_key_size,
                    size_t *signature_size)
{
    const sign_params_t *params = find_sign_params(algorithm);
    if (!params)
    {
        QUAC_RECORD_ERROR(QUAC_ERROR_INVALID_ALGORITHM,
                          "Algorithm 0x%X is not a signature algorithm", algorithm);
        return QUAC_ERROR_INVALID_ALGORITHM;
    }

    if (public_key_size)
        *public_key_size = params->public_key_size;
    if (secret_key_size)
        *secret_key_size = params->secret_key_size;
    if (signature_size)
        *signature_size = params->signature_size;

    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_sign_get_params(quac_algorithm_t algorithm, quac_sign_params_t *params)
{
    QUAC_CHECK_NULL(params);

    const sign_params_t *p = find_sign_params(algorithm);
    if (!p)
    {
        QUAC_RECORD_ERROR(QUAC_ERROR_INVALID_ALGORITHM,
                          "Algorithm 0x%X is not a signature algorithm", algorithm);
        return QUAC_ERROR_INVALID_ALGORITHM;
    }

    memset(params, 0, sizeof(*params));
    params->struct_size = sizeof(*params);
    params->algorithm = algorithm;
    params->family = p->family;
    params->public_key_size = p->public_key_size;
    params->secret_key_size = p->secret_key_size;
    params->signature_size = p->signature_size;

    if (p->family == QUAC_SIGN_FAMILY_DILITHIUM)
    {
        params->dilithium.n = p->n;
        params->dilithium.k = p->k;
        params->dilithium.l = p->l;
        params->dilithium.q = p->q;
        params->dilithium.eta = p->eta;
        params->dilithium.tau = p->tau;
        params->dilithium.beta = p->beta;
        params->dilithium.gamma1 = p->gamma1;
        params->dilithium.gamma2 = p->gamma2;
        params->dilithium.omega = p->omega;
    }
    else
    {
        params->sphincs.n = p->sphincs_n;
        params->sphincs.h = p->sphincs_h;
        params->sphincs.d = p->sphincs_d;
        params->sphincs.a = p->sphincs_a;
        params->sphincs.k = p->sphincs_k;
        params->sphincs.w = p->sphincs_w;
    }

    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_sign_keygen(quac_device_t device,
                 quac_algorithm_t algorithm,
                 uint8_t *public_key,
                 uint8_t *secret_key)
{
    QUAC_CHECK_NULL(public_key);
    QUAC_CHECK_NULL(secret_key);

    const sign_params_t *params = find_sign_params(algorithm);
    if (!params)
    {
        QUAC_RECORD_ERROR(QUAC_ERROR_INVALID_ALGORITHM,
                          "Algorithm 0x%X is not a signature algorithm", algorithm);
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
        simulate_delay(device, params);
        result = sim_sign_keygen(params, public_key, secret_key);
    }
    else
    {
        result = hw_sign_keygen(device, params, public_key, secret_key);
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
        QUAC_RECORD_ERROR(result, "Signature key generation failed");
    }

    return result;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_sign(quac_device_t device,
          quac_algorithm_t algorithm,
          const uint8_t *secret_key,
          const uint8_t *message,
          size_t message_len,
          uint8_t *signature,
          size_t *signature_len)
{
    QUAC_CHECK_NULL(secret_key);
    QUAC_CHECK_NULL(message);
    QUAC_CHECK_NULL(signature);
    QUAC_CHECK_NULL(signature_len);

    const sign_params_t *params = find_sign_params(algorithm);
    if (!params)
    {
        QUAC_RECORD_ERROR(QUAC_ERROR_INVALID_ALGORITHM,
                          "Algorithm 0x%X is not a signature algorithm", algorithm);
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
        simulate_delay(device, params);
        result = sim_sign(params, secret_key, message, message_len,
                          signature, signature_len);
    }
    else
    {
        result = hw_sign(device, params, secret_key, message, message_len,
                         signature, signature_len);
    }

    quac_device_unlock(device);

    uint64_t duration = get_timestamp_us() - start_time;
    update_sign_stats(duration, QUAC_SUCCEEDED(result));

    if (QUAC_SUCCEEDED(result))
    {
        quac_device_inc_ops(device);
    }
    else
    {
        QUAC_RECORD_ERROR(result, "Signing failed");
    }

    return result;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_verify(quac_device_t device,
            quac_algorithm_t algorithm,
            const uint8_t *public_key,
            const uint8_t *message,
            size_t message_len,
            const uint8_t *signature,
            size_t signature_len)
{
    QUAC_CHECK_NULL(public_key);
    QUAC_CHECK_NULL(message);
    QUAC_CHECK_NULL(signature);

    const sign_params_t *params = find_sign_params(algorithm);
    if (!params)
    {
        QUAC_RECORD_ERROR(QUAC_ERROR_INVALID_ALGORITHM,
                          "Algorithm 0x%X is not a signature algorithm", algorithm);
        return QUAC_ERROR_INVALID_ALGORITHM;
    }

    if (!quac_is_algorithm_supported(device, algorithm))
    {
        QUAC_RECORD_ERROR(QUAC_ERROR_NOT_SUPPORTED,
                          "Algorithm %s not supported by device", params->name);
        return QUAC_ERROR_NOT_SUPPORTED;
    }

    /* Validate signature size */
    if (signature_len != params->signature_size)
    {
        QUAC_RECORD_ERROR(QUAC_ERROR_INVALID_SIGNATURE,
                          "Invalid signature size: expected %zu, got %zu",
                          params->signature_size, signature_len);
        return QUAC_ERROR_INVALID_SIGNATURE;
    }

    uint64_t start_time = get_timestamp_us();
    quac_result_t result;

    quac_device_lock(device);

    if (quac_device_is_simulator(device))
    {
        simulate_delay(device, params);
        result = sim_verify(params, public_key, message, message_len,
                            signature, signature_len);
    }
    else
    {
        result = hw_verify(device, params, public_key, message, message_len,
                           signature, signature_len);
    }

    quac_device_unlock(device);

    uint64_t duration = get_timestamp_us() - start_time;
    update_verify_stats(duration, QUAC_SUCCEEDED(result));

    if (QUAC_SUCCEEDED(result))
    {
        quac_device_inc_ops(device);
    }
    /* Don't record verification failures as errors - they're expected */

    return result;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_sign_validate_public_key(quac_algorithm_t algorithm,
                              const uint8_t *public_key,
                              size_t key_size)
{
    QUAC_CHECK_NULL(public_key);

    const sign_params_t *params = find_sign_params(algorithm);
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

    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_sign_validate_signature(quac_algorithm_t algorithm,
                             const uint8_t *signature,
                             size_t sig_size)
{
    QUAC_CHECK_NULL(signature);

    const sign_params_t *params = find_sign_params(algorithm);
    if (!params)
    {
        return QUAC_ERROR_INVALID_ALGORITHM;
    }

    if (sig_size != params->signature_size)
    {
        QUAC_RECORD_ERROR(QUAC_ERROR_INVALID_SIGNATURE,
                          "Expected %zu bytes, got %zu",
                          params->signature_size, sig_size);
        return QUAC_ERROR_INVALID_SIGNATURE;
    }

    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_sign_get_stats(quac_sign_stats_t *stats)
{
    QUAC_CHECK_NULL(stats);

    memcpy(stats, &g_sign_stats, sizeof(*stats));
    stats->struct_size = sizeof(*stats);

    return QUAC_SUCCESS;
}

QUAC100_API quac_result_t QUAC100_CALL
quac_sign_reset_stats(void)
{
    memset(&g_sign_stats, 0, sizeof(g_sign_stats));
    g_sign_stats.struct_size = sizeof(g_sign_stats);
    return QUAC_SUCCESS;
}

/*=============================================================================
 * Extended API Implementation
 *=============================================================================*/

QUAC100_API quac_result_t QUAC100_CALL
quac_sign_keypair_alloc(quac_algorithm_t algorithm, quac_sign_keypair_t **keypair)
{
    QUAC_CHECK_NULL(keypair);

    const sign_params_t *params = find_sign_params(algorithm);
    if (!params)
    {
        return QUAC_ERROR_INVALID_ALGORITHM;
    }

    size_t total_size = sizeof(quac_sign_keypair_t) +
                        params->public_key_size +
                        params->secret_key_size;

    quac_sign_keypair_t *kp = calloc(1, total_size);
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
quac_sign_keypair_free(quac_sign_keypair_t *keypair)
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
quac_sign_keygen_ex(quac_device_t device,
                    quac_algorithm_t algorithm,
                    quac_sign_keypair_t *keypair)
{
    QUAC_CHECK_NULL(keypair);

    if (keypair->algorithm != algorithm)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    quac_result_t result = quac_sign_keygen(device, algorithm,
                                            keypair->public_key,
                                            keypair->secret_key);

    if (QUAC_SUCCEEDED(result))
    {
        keypair->has_secret_key = true;
        /* TODO: Compute fingerprint (SHA-256 of public key) */
    }

    return result;
}