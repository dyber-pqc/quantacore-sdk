/**
 * @file kem.c
 * @brief QUAC 100 SDK - ML-KEM Implementation
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 */

#include "quac100/quac100.h"
#include "internal.h"

#include <stdlib.h>
#include <string.h>

/*============================================================================
 * Static Data
 *============================================================================*/

static const quac_kem_params_t g_kem_params[] = {
    {QUAC_KEM_ML_KEM_512, 800, 1632, 768, 32, 1, "ML-KEM-512"},
    {QUAC_KEM_ML_KEM_768, 1184, 2400, 1088, 32, 3, "ML-KEM-768"},
    {QUAC_KEM_ML_KEM_1024, 1568, 3168, 1568, 32, 5, "ML-KEM-1024"},
};

#define NUM_KEM_PARAMS (sizeof(g_kem_params) / sizeof(g_kem_params[0]))

/*============================================================================
 * Parameter Functions
 *============================================================================*/

QUAC_API quac_status_t quac_kem_get_params(
    quac_kem_algorithm_t algorithm,
    quac_kem_params_t *params)
{
    QUAC_CHECK_PARAM(params != NULL);

    for (size_t i = 0; i < NUM_KEM_PARAMS; i++)
    {
        if (g_kem_params[i].algorithm == algorithm)
        {
            *params = g_kem_params[i];
            return QUAC_SUCCESS;
        }
    }

    return QUAC_ERROR_NOT_SUPPORTED;
}

QUAC_API quac_status_t quac_kem_get_sizes(
    quac_kem_algorithm_t algorithm,
    size_t *public_key_len,
    size_t *secret_key_len,
    size_t *ciphertext_len,
    size_t *shared_secret_len)
{
    quac_kem_params_t params;
    quac_status_t status = quac_kem_get_params(algorithm, &params);

    if (status != QUAC_SUCCESS)
    {
        return status;
    }

    if (public_key_len)
        *public_key_len = params.public_key_size;
    if (secret_key_len)
        *secret_key_len = params.secret_key_size;
    if (ciphertext_len)
        *ciphertext_len = params.ciphertext_size;
    if (shared_secret_len)
        *shared_secret_len = params.shared_secret_size;

    return QUAC_SUCCESS;
}

/*============================================================================
 * KEM Operations
 *============================================================================*/

QUAC_API quac_status_t quac_kem_keygen(
    quac_device_t device,
    quac_kem_algorithm_t algorithm,
    uint8_t *public_key,
    size_t *public_key_len,
    uint8_t *secret_key,
    size_t *secret_key_len)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(public_key != NULL);
    QUAC_CHECK_PARAM(public_key_len != NULL);
    QUAC_CHECK_PARAM(secret_key != NULL);
    QUAC_CHECK_PARAM(secret_key_len != NULL);

    quac_kem_params_t params;
    quac_status_t status = quac_kem_get_params(algorithm, &params);
    if (status != QUAC_SUCCESS)
    {
        return status;
    }

    if (*public_key_len < params.public_key_size ||
        *secret_key_len < params.secret_key_size)
    {
        *public_key_len = params.public_key_size;
        *secret_key_len = params.secret_key_size;
        return QUAC_ERROR_BUFFER_SMALL;
    }

    QUAC_LOG_DEBUG("KEM keygen: %s", params.name);

    quac_device_handle_impl *handle = (quac_device_handle_impl *)device;

    quac_device_lock_internal(handle);
    status = quac_core_kem_keygen(handle, algorithm,
                                  public_key, public_key_len,
                                  secret_key, secret_key_len);
    quac_device_unlock_internal(handle);

    if (status == QUAC_SUCCESS)
    {
        handle->total_ops++;
    }
    else
    {
        handle->total_errors++;
    }

    return status;
}

QUAC_API quac_status_t quac_kem_encaps(
    quac_device_t device,
    quac_kem_algorithm_t algorithm,
    const uint8_t *public_key,
    size_t public_key_len,
    uint8_t *ciphertext,
    size_t *ciphertext_len,
    uint8_t *shared_secret,
    size_t *shared_secret_len)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(public_key != NULL);
    QUAC_CHECK_PARAM(ciphertext != NULL);
    QUAC_CHECK_PARAM(ciphertext_len != NULL);
    QUAC_CHECK_PARAM(shared_secret != NULL);
    QUAC_CHECK_PARAM(shared_secret_len != NULL);

    quac_kem_params_t params;
    quac_status_t status = quac_kem_get_params(algorithm, &params);
    if (status != QUAC_SUCCESS)
    {
        return status;
    }

    if (public_key_len != params.public_key_size)
    {
        QUAC_LOG_ERROR("Invalid public key size: %zu (expected %zu)",
                       public_key_len, params.public_key_size);
        return QUAC_ERROR_INVALID_KEY;
    }

    if (*ciphertext_len < params.ciphertext_size ||
        *shared_secret_len < params.shared_secret_size)
    {
        *ciphertext_len = params.ciphertext_size;
        *shared_secret_len = params.shared_secret_size;
        return QUAC_ERROR_BUFFER_SMALL;
    }

    QUAC_LOG_DEBUG("KEM encaps: %s", params.name);

    quac_device_handle_impl *handle = (quac_device_handle_impl *)device;

    quac_device_lock_internal(handle);
    status = quac_core_kem_encaps(handle, algorithm,
                                  public_key, public_key_len,
                                  ciphertext, ciphertext_len,
                                  shared_secret, shared_secret_len);
    quac_device_unlock_internal(handle);

    if (status == QUAC_SUCCESS)
    {
        handle->total_ops++;
    }
    else
    {
        handle->total_errors++;
    }

    return status;
}

QUAC_API quac_status_t quac_kem_decaps(
    quac_device_t device,
    quac_kem_algorithm_t algorithm,
    const uint8_t *secret_key,
    size_t secret_key_len,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *shared_secret,
    size_t *shared_secret_len)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(secret_key != NULL);
    QUAC_CHECK_PARAM(ciphertext != NULL);
    QUAC_CHECK_PARAM(shared_secret != NULL);
    QUAC_CHECK_PARAM(shared_secret_len != NULL);

    quac_kem_params_t params;
    quac_status_t status = quac_kem_get_params(algorithm, &params);
    if (status != QUAC_SUCCESS)
    {
        return status;
    }

    if (secret_key_len != params.secret_key_size)
    {
        QUAC_LOG_ERROR("Invalid secret key size: %zu (expected %zu)",
                       secret_key_len, params.secret_key_size);
        return QUAC_ERROR_INVALID_KEY;
    }

    if (ciphertext_len != params.ciphertext_size)
    {
        QUAC_LOG_ERROR("Invalid ciphertext size: %zu (expected %zu)",
                       ciphertext_len, params.ciphertext_size);
        return QUAC_ERROR_INVALID_PARAM;
    }

    if (*shared_secret_len < params.shared_secret_size)
    {
        *shared_secret_len = params.shared_secret_size;
        return QUAC_ERROR_BUFFER_SMALL;
    }

    QUAC_LOG_DEBUG("KEM decaps: %s", params.name);

    quac_device_handle_impl *handle = (quac_device_handle_impl *)device;

    quac_device_lock_internal(handle);
    status = quac_core_kem_decaps(handle, algorithm,
                                  secret_key, secret_key_len,
                                  ciphertext, ciphertext_len,
                                  shared_secret, shared_secret_len);
    quac_device_unlock_internal(handle);

    if (status == QUAC_SUCCESS)
    {
        handle->total_ops++;
    }
    else
    {
        handle->total_errors++;
    }

    return status;
}

/*============================================================================
 * Batch Operations
 *============================================================================*/

QUAC_API quac_status_t quac_kem_keygen_batch(
    quac_device_t device,
    quac_kem_algorithm_t algorithm,
    size_t count,
    uint8_t **public_keys,
    uint8_t **secret_keys,
    quac_status_t *status_codes)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(count > 0);
    QUAC_CHECK_PARAM(public_keys != NULL);
    QUAC_CHECK_PARAM(secret_keys != NULL);
    QUAC_CHECK_PARAM(status_codes != NULL);

    quac_kem_params_t params;
    quac_status_t status = quac_kem_get_params(algorithm, &params);
    if (status != QUAC_SUCCESS)
    {
        return status;
    }

    quac_device_handle_impl *handle = (quac_device_handle_impl *)device;
    quac_device_lock_internal(handle);

    for (size_t i = 0; i < count; i++)
    {
        size_t pk_len = params.public_key_size;
        size_t sk_len = params.secret_key_size;

        status_codes[i] = quac_core_kem_keygen(handle, algorithm,
                                               public_keys[i], &pk_len,
                                               secret_keys[i], &sk_len);

        if (status_codes[i] == QUAC_SUCCESS)
        {
            handle->total_ops++;
        }
        else
        {
            handle->total_errors++;
        }
    }

    quac_device_unlock_internal(handle);
    return QUAC_SUCCESS;
}

QUAC_API quac_status_t quac_kem_encaps_batch(
    quac_device_t device,
    quac_kem_algorithm_t algorithm,
    size_t count,
    const uint8_t **public_keys,
    const size_t *public_key_lens,
    uint8_t **ciphertexts,
    uint8_t **shared_secrets,
    quac_status_t *status_codes)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(count > 0);
    QUAC_CHECK_PARAM(public_keys != NULL);
    QUAC_CHECK_PARAM(public_key_lens != NULL);
    QUAC_CHECK_PARAM(ciphertexts != NULL);
    QUAC_CHECK_PARAM(shared_secrets != NULL);
    QUAC_CHECK_PARAM(status_codes != NULL);

    quac_kem_params_t params;
    quac_status_t status = quac_kem_get_params(algorithm, &params);
    if (status != QUAC_SUCCESS)
    {
        return status;
    }

    quac_device_handle_impl *handle = (quac_device_handle_impl *)device;
    quac_device_lock_internal(handle);

    for (size_t i = 0; i < count; i++)
    {
        size_t ct_len = params.ciphertext_size;
        size_t ss_len = params.shared_secret_size;

        status_codes[i] = quac_core_kem_encaps(handle, algorithm,
                                               public_keys[i], public_key_lens[i],
                                               ciphertexts[i], &ct_len,
                                               shared_secrets[i], &ss_len);

        if (status_codes[i] == QUAC_SUCCESS)
        {
            handle->total_ops++;
        }
        else
        {
            handle->total_errors++;
        }
    }

    quac_device_unlock_internal(handle);
    return QUAC_SUCCESS;
}

QUAC_API quac_status_t quac_kem_decaps_batch(
    quac_device_t device,
    quac_kem_algorithm_t algorithm,
    size_t count,
    const uint8_t **secret_keys,
    const size_t *secret_key_lens,
    const uint8_t **ciphertexts,
    const size_t *ciphertext_lens,
    uint8_t **shared_secrets,
    quac_status_t *status_codes)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(count > 0);
    QUAC_CHECK_PARAM(secret_keys != NULL);
    QUAC_CHECK_PARAM(secret_key_lens != NULL);
    QUAC_CHECK_PARAM(ciphertexts != NULL);
    QUAC_CHECK_PARAM(ciphertext_lens != NULL);
    QUAC_CHECK_PARAM(shared_secrets != NULL);
    QUAC_CHECK_PARAM(status_codes != NULL);

    quac_kem_params_t params;
    quac_status_t status = quac_kem_get_params(algorithm, &params);
    if (status != QUAC_SUCCESS)
    {
        return status;
    }

    quac_device_handle_impl *handle = (quac_device_handle_impl *)device;
    quac_device_lock_internal(handle);

    for (size_t i = 0; i < count; i++)
    {
        size_t ss_len = params.shared_secret_size;

        status_codes[i] = quac_core_kem_decaps(handle, algorithm,
                                               secret_keys[i], secret_key_lens[i],
                                               ciphertexts[i], ciphertext_lens[i],
                                               shared_secrets[i], &ss_len);

        if (status_codes[i] == QUAC_SUCCESS)
        {
            handle->total_ops++;
        }
        else
        {
            handle->total_errors++;
        }
    }

    quac_device_unlock_internal(handle);
    return QUAC_SUCCESS;
}

/*============================================================================
 * Async Operations (Stub)
 *============================================================================*/

QUAC_API quac_status_t quac_kem_keygen_async(
    quac_device_t device,
    quac_kem_algorithm_t algorithm,
    uint8_t *public_key,
    size_t *public_key_len,
    uint8_t *secret_key,
    size_t *secret_key_len,
    quac_async_callback_t callback,
    void *user_data,
    quac_async_t *async_handle)
{
    /* TODO: Implement async version */
    (void)callback;
    (void)user_data;
    (void)async_handle;
    return quac_kem_keygen(device, algorithm, public_key, public_key_len, secret_key, secret_key_len);
}

QUAC_API quac_status_t quac_kem_encaps_async(
    quac_device_t device,
    quac_kem_algorithm_t algorithm,
    const uint8_t *public_key,
    size_t public_key_len,
    uint8_t *ciphertext,
    size_t *ciphertext_len,
    uint8_t *shared_secret,
    size_t *shared_secret_len,
    quac_async_callback_t callback,
    void *user_data,
    quac_async_t *async_handle)
{
    (void)callback;
    (void)user_data;
    (void)async_handle;
    return quac_kem_encaps(device, algorithm, public_key, public_key_len,
                           ciphertext, ciphertext_len, shared_secret, shared_secret_len);
}

QUAC_API quac_status_t quac_kem_decaps_async(
    quac_device_t device,
    quac_kem_algorithm_t algorithm,
    const uint8_t *secret_key,
    size_t secret_key_len,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *shared_secret,
    size_t *shared_secret_len,
    quac_async_callback_t callback,
    void *user_data,
    quac_async_t *async_handle)
{
    (void)callback;
    (void)user_data;
    (void)async_handle;
    return quac_kem_decaps(device, algorithm, secret_key, secret_key_len,
                           ciphertext, ciphertext_len, shared_secret, shared_secret_len);
}