/**
 * @file hal.c
 * @brief QUAC 100 SDK - Hardware Abstraction Layer (Simulation/Stub)
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 *
 * This file provides a software simulation of the QUAC 100 hardware
 * for development and testing purposes. Replace with actual hardware
 * driver implementation for production use.
 */

#include "quac100/quac100.h"
#include "internal.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

/*============================================================================
 * Simulation State
 *============================================================================*/

#define MAX_SIMULATED_DEVICES 4

static struct
{
    bool initialized;
    int device_count;
    quac_device_info_t device_info[MAX_SIMULATED_DEVICES];
    bool device_open[MAX_SIMULATED_DEVICES];
} g_hal_state = {0};

/* Simple PRNG for simulation (DO NOT use in production) */
static uint64_t g_sim_rng_state = 0;

static uint64_t sim_rand64(void)
{
    /* xorshift64* */
    g_sim_rng_state ^= g_sim_rng_state >> 12;
    g_sim_rng_state ^= g_sim_rng_state << 25;
    g_sim_rng_state ^= g_sim_rng_state >> 27;
    return g_sim_rng_state * 0x2545F4914F6CDD1DULL;
}

static void sim_rand_bytes(uint8_t *buf, size_t len)
{
    while (len >= 8)
    {
        uint64_t r = sim_rand64();
        memcpy(buf, &r, 8);
        buf += 8;
        len -= 8;
    }
    if (len > 0)
    {
        uint64_t r = sim_rand64();
        memcpy(buf, &r, len);
    }
}

/*============================================================================
 * HAL Initialization
 *============================================================================*/

quac_status_t quac_hal_init(uint32_t flags)
{
    (void)flags;

    if (g_hal_state.initialized)
    {
        return QUAC_SUCCESS;
    }

    /* Initialize simulation RNG */
    g_sim_rng_state = (uint64_t)time(NULL);
    if (g_sim_rng_state == 0)
        g_sim_rng_state = 0xDEADBEEFCAFEBABEULL;

    /* Simulate device discovery */
    g_hal_state.device_count = 1; /* One simulated device */

    /* Populate device info */
    quac_device_info_t *info = &g_hal_state.device_info[0];
    info->device_index = 0;
    info->vendor_id = 0x1D7B;  /* Dyber vendor ID */
    info->product_id = 0x0100; /* QUAC 100 */
    strncpy(info->serial_number, "QUAC100-SIM-00001", sizeof(info->serial_number) - 1);
    strncpy(info->firmware_version, "1.0.0-sim", sizeof(info->firmware_version) - 1);
    strncpy(info->hardware_version, "1.0", sizeof(info->hardware_version) - 1);
    strncpy(info->model_name, "QUAC 100 (Simulation)", sizeof(info->model_name) - 1);
    info->capabilities = 0xFFFFFFFF; /* All capabilities */
    info->max_concurrent_ops = 64;
    info->key_slots = 256;
    info->fips_mode = false;
    info->hardware_available = false; /* Simulation */

    g_hal_state.initialized = true;

    QUAC_LOG_INFO("HAL initialized (simulation mode)");

    return QUAC_SUCCESS;
}

quac_status_t quac_hal_cleanup(void)
{
    if (!g_hal_state.initialized)
    {
        return QUAC_SUCCESS;
    }

    /* Close any open devices */
    for (int i = 0; i < MAX_SIMULATED_DEVICES; i++)
    {
        g_hal_state.device_open[i] = false;
    }

    g_hal_state.initialized = false;

    return QUAC_SUCCESS;
}

quac_status_t quac_hal_discover_devices(void)
{
    /* Already done in init */
    return QUAC_SUCCESS;
}

int quac_hal_device_count(void)
{
    return g_hal_state.device_count;
}

quac_status_t quac_hal_get_device_info(int index, quac_device_info_t *info)
{
    if (index < 0 || index >= g_hal_state.device_count)
    {
        return QUAC_ERROR_DEVICE_NOT_FOUND;
    }

    if (!info)
    {
        return QUAC_ERROR_INVALID_PARAM;
    }

    *info = g_hal_state.device_info[index];
    return QUAC_SUCCESS;
}

/*============================================================================
 * Device Management
 *============================================================================*/

quac_status_t quac_hal_open_device(int index, uint32_t flags, quac_device_handle_impl **handle)
{
    if (index < 0 || index >= g_hal_state.device_count)
    {
        return QUAC_ERROR_DEVICE_NOT_FOUND;
    }

    if (g_hal_state.device_open[index])
    {
        return QUAC_ERROR_DEVICE_BUSY;
    }

    quac_device_handle_impl *h = (quac_device_handle_impl *)calloc(1, sizeof(quac_device_handle_impl));
    if (!h)
    {
        return QUAC_ERROR_OUT_OF_MEMORY;
    }

    h->device_index = index;
    h->flags = flags;
    h->is_open = true;
    h->info = g_hal_state.device_info[index];
    h->native_handle = -1; /* Simulation */

#ifdef QUAC_PLATFORM_WINDOWS
    InitializeCriticalSection(&h->lock);
#else
    pthread_mutex_init(&h->lock, NULL);
#endif

    g_hal_state.device_open[index] = true;
    *handle = h;

    return QUAC_SUCCESS;
}

quac_status_t quac_hal_close_device(quac_device_handle_impl *handle)
{
    if (!handle)
    {
        return QUAC_ERROR_INVALID_HANDLE;
    }

    int index = handle->device_index;

#ifdef QUAC_PLATFORM_WINDOWS
    DeleteCriticalSection(&handle->lock);
#else
    pthread_mutex_destroy(&handle->lock);
#endif

    g_hal_state.device_open[index] = false;
    handle->is_open = false;

    free(handle);

    return QUAC_SUCCESS;
}

quac_status_t quac_hal_send_command(
    quac_device_handle_impl *handle,
    uint32_t command,
    const void *input,
    size_t input_len,
    void *output,
    size_t *output_len)
{
    (void)handle;
    (void)input;
    (void)input_len;

    /* Simulate command responses */
    switch (command)
    {
    case 0x01: /* Get status */
        if (output && output_len && *output_len >= 32)
        {
            uint8_t *buf = (uint8_t *)output;
            float temp = 45.0f;
            memcpy(buf, &temp, 4);
            uint32_t power = 15000;
            memcpy(buf + 4, &power, 4);
            uint64_t uptime = 3600;
            memcpy(buf + 8, &uptime, 8);
            uint64_t ops = 100000;
            memcpy(buf + 16, &ops, 8);
            uint32_t ops_sec = 10000;
            memcpy(buf + 24, &ops_sec, 4);
            buf[28] = 95; /* Entropy level */
            buf[29] = 1;  /* Sessions */
            buf[30] = 5;  /* Used slots */
            buf[31] = 0;  /* Tamper status */
            *output_len = 32;
        }
        return QUAC_SUCCESS;

    case 0x02: /* Reset */
        return QUAC_SUCCESS;

    case 0x03: /* Self-test */
        if (output && output_len && *output_len >= 1)
        {
            ((uint8_t *)output)[0] = 0; /* Test passed */
            *output_len = 1;
        }
        return QUAC_SUCCESS;

    case 0x10: /* Entropy status */
        if (output && output_len && *output_len >= 11)
        {
            uint8_t *buf = (uint8_t *)output;
            buf[0] = 95; /* Level */
            buf[1] = QUAC_ENTROPY_QRNG;
            uint64_t bytes = 1000000;
            memcpy(buf + 2, &bytes, 8);
            buf[10] = 1; /* Health OK */
            *output_len = 11;
        }
        return QUAC_SUCCESS;

    case 0x11: /* Seed */
    case 0x12: /* Reseed */
        return QUAC_SUCCESS;

    default:
        return QUAC_ERROR_NOT_SUPPORTED;
    }
}

quac_status_t quac_hal_dma_write(
    quac_device_handle_impl *handle,
    const void *data,
    size_t len,
    uint64_t device_addr)
{
    (void)handle;
    (void)data;
    (void)len;
    (void)device_addr;
    return QUAC_SUCCESS;
}

quac_status_t quac_hal_dma_read(
    quac_device_handle_impl *handle,
    void *data,
    size_t len,
    uint64_t device_addr)
{
    (void)handle;
    (void)data;
    (void)len;
    (void)device_addr;
    return QUAC_SUCCESS;
}

/*============================================================================
 * Cryptographic Core Functions (Simulation)
 *============================================================================*/

quac_status_t quac_core_kem_keygen(
    quac_device_handle_impl *handle,
    quac_kem_algorithm_t algorithm,
    uint8_t *public_key,
    size_t *public_key_len,
    uint8_t *secret_key,
    size_t *secret_key_len)
{
    (void)handle;

    quac_kem_params_t params;
    quac_status_t status = quac_kem_get_params(algorithm, &params);
    if (status != QUAC_SUCCESS)
        return status;

    /* Generate random key material (simulation) */
    sim_rand_bytes(public_key, params.public_key_size);
    sim_rand_bytes(secret_key, params.secret_key_size);

    *public_key_len = params.public_key_size;
    *secret_key_len = params.secret_key_size;

    return QUAC_SUCCESS;
}

quac_status_t quac_core_kem_encaps(
    quac_device_handle_impl *handle,
    quac_kem_algorithm_t algorithm,
    const uint8_t *public_key,
    size_t public_key_len,
    uint8_t *ciphertext,
    size_t *ciphertext_len,
    uint8_t *shared_secret,
    size_t *shared_secret_len)
{
    (void)handle;
    (void)public_key;
    (void)public_key_len;

    quac_kem_params_t params;
    quac_status_t status = quac_kem_get_params(algorithm, &params);
    if (status != QUAC_SUCCESS)
        return status;

    /* Generate random ciphertext (simulation) */
    sim_rand_bytes(ciphertext, params.ciphertext_size);
    
    /* Derive shared secret deterministically from ciphertext */
    /* This ensures encaps and decaps produce the same result */
    for (size_t i = 0; i < params.shared_secret_size; i++) {
        shared_secret[i] = ciphertext[i] ^ ciphertext[params.ciphertext_size - 1 - i];
    }

    *ciphertext_len = params.ciphertext_size;
    *shared_secret_len = params.shared_secret_size;

    return QUAC_SUCCESS;
}

quac_status_t quac_core_kem_decaps(
    quac_device_handle_impl *handle,
    quac_kem_algorithm_t algorithm,
    const uint8_t *secret_key,
    size_t secret_key_len,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *shared_secret,
    size_t *shared_secret_len)
{
    (void)handle;
    (void)secret_key;
    (void)secret_key_len;
    (void)ciphertext;
    (void)ciphertext_len;

    quac_kem_params_t params;
    quac_status_t status = quac_kem_get_params(algorithm, &params);
    if (status != QUAC_SUCCESS)
        return status;

    /* Derive shared secret deterministically from ciphertext */
    /* Must match the derivation in encaps */
    for (size_t i = 0; i < params.shared_secret_size; i++) {
        shared_secret[i] = ciphertext[i] ^ ciphertext[ciphertext_len - 1 - i];
    }
    *shared_secret_len = params.shared_secret_size;

    return QUAC_SUCCESS;
}

quac_status_t quac_core_sign_keygen(
    quac_device_handle_impl *handle,
    quac_sign_algorithm_t algorithm,
    uint8_t *public_key,
    size_t *public_key_len,
    uint8_t *secret_key,
    size_t *secret_key_len)
{
    (void)handle;

    quac_sign_params_t params;
    quac_status_t status = quac_sign_get_params(algorithm, &params);
    if (status != QUAC_SUCCESS)
        return status;

    /* Generate random key material (simulation) */
    sim_rand_bytes(public_key, params.public_key_size);
    sim_rand_bytes(secret_key, params.secret_key_size);

    *public_key_len = params.public_key_size;
    *secret_key_len = params.secret_key_size;

    return QUAC_SUCCESS;
}

quac_status_t quac_core_sign(
    quac_device_handle_impl *handle,
    quac_sign_algorithm_t algorithm,
    const uint8_t *secret_key,
    size_t secret_key_len,
    const uint8_t *message,
    size_t message_len,
    uint8_t *signature,
    size_t *signature_len)
{
    (void)handle;
    (void)secret_key;
    (void)secret_key_len;
    (void)message;
    (void)message_len;

    quac_sign_params_t params;
    quac_status_t status = quac_sign_get_params(algorithm, &params);
    if (status != QUAC_SUCCESS)
        return status;

    /* Generate signature with embedded message hash (simulation) */
    sim_rand_bytes(signature, params.signature_size);
    
    /* Embed a simple hash of the message in the first 8 bytes */
    uint64_t msg_hash = 0x5A5A5A5A5A5A5A5AULL;
    for (size_t i = 0; i < message_len; i++) {
        msg_hash = msg_hash * 31ULL + message[i];
    }
    memcpy(signature, &msg_hash, sizeof(msg_hash));
    *signature_len = params.signature_size;

    return QUAC_SUCCESS;
}

quac_status_t quac_core_verify(
    quac_device_handle_impl *handle,
    quac_sign_algorithm_t algorithm,
    const uint8_t *public_key,
    size_t public_key_len,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *signature,
    size_t signature_len)
{
    (void)handle;
    (void)algorithm;
    (void)public_key;
    (void)public_key_len;
    (void)message;
    (void)message_len;
    (void)signature;
    (void)signature_len;

    /* Verify by checking embedded message hash (simulation) */
    uint64_t expected_hash = 0x5A5A5A5A5A5A5A5AULL;
    for (size_t i = 0; i < message_len; i++) {
        expected_hash = expected_hash * 31ULL + message[i];
    }
    
    uint64_t stored_hash;
    memcpy(&stored_hash, signature, sizeof(stored_hash));
    
    if (stored_hash != expected_hash) {
        return QUAC_ERROR_VERIFY_FAILED;
    }
    
    return QUAC_SUCCESS;
}

quac_status_t quac_core_random_bytes(
    quac_device_handle_impl *handle,
    uint8_t *buffer,
    size_t length,
    quac_entropy_source_t source)
{
    (void)handle;
    (void)source;

    sim_rand_bytes(buffer, length);
    return QUAC_SUCCESS;
}

quac_status_t quac_core_hash(
    quac_device_handle_impl *handle,
    quac_hash_algorithm_t algorithm,
    const uint8_t *data,
    size_t data_len,
    uint8_t *hash,
    size_t *hash_len)
{
    (void)handle;

    size_t out_len;
    quac_status_t status = quac_hash_size(algorithm, &out_len);
    if (status != QUAC_SUCCESS)
        return status;

    if (out_len == 0)
    {
        /* Variable output (SHAKE) - use provided length */
        out_len = *hash_len;
    }

    /* Simple simulation: XOR-fold the data */
    memset(hash, 0, out_len);
    for (size_t i = 0; i < data_len; i++)
    {
        hash[i % out_len] ^= data[i];
    }

    /* Add some mixing */
    for (size_t i = 0; i < out_len; i++)
    {
        hash[i] = (hash[i] * 31 + 17) ^ (hash[(i + 1) % out_len]);
    }

    *hash_len = out_len;
    return QUAC_SUCCESS;
}