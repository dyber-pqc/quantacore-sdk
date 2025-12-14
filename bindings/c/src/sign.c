/**
 * @file sign.c
 * @brief QUAC 100 SDK - Digital Signature Implementation
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 */

#include "quac100/quac100.h"
#include "internal.h"

#include <stdlib.h>
#include <string.h>

/*============================================================================
 * Static Data
 *============================================================================*/

static const quac_sign_params_t g_sign_params[] = {
    /* ML-DSA (Dilithium) */
    {QUAC_SIGN_ML_DSA_44, 1312, 2560, 2420, 2, "ML-DSA-44"},
    {QUAC_SIGN_ML_DSA_65, 1952, 4032, 3309, 3, "ML-DSA-65"},
    {QUAC_SIGN_ML_DSA_87, 2592, 4896, 4627, 5, "ML-DSA-87"},

    /* SLH-DSA SHA2 */
    {QUAC_SIGN_SLH_DSA_SHA2_128S, 32, 64, 7856, 1, "SLH-DSA-SHA2-128s"},
    {QUAC_SIGN_SLH_DSA_SHA2_128F, 32, 64, 17088, 1, "SLH-DSA-SHA2-128f"},
    {QUAC_SIGN_SLH_DSA_SHA2_192S, 48, 96, 16224, 3, "SLH-DSA-SHA2-192s"},
    {QUAC_SIGN_SLH_DSA_SHA2_192F, 48, 96, 35664, 3, "SLH-DSA-SHA2-192f"},
    {QUAC_SIGN_SLH_DSA_SHA2_256S, 64, 128, 29792, 5, "SLH-DSA-SHA2-256s"},
    {QUAC_SIGN_SLH_DSA_SHA2_256F, 64, 128, 49856, 5, "SLH-DSA-SHA2-256f"},

    /* SLH-DSA SHAKE */
    {QUAC_SIGN_SLH_DSA_SHAKE_128S, 32, 64, 7856, 1, "SLH-DSA-SHAKE-128s"},
    {QUAC_SIGN_SLH_DSA_SHAKE_128F, 32, 64, 17088, 1, "SLH-DSA-SHAKE-128f"},
    {QUAC_SIGN_SLH_DSA_SHAKE_192S, 48, 96, 16224, 3, "SLH-DSA-SHAKE-192s"},
    {QUAC_SIGN_SLH_DSA_SHAKE_192F, 48, 96, 35664, 3, "SLH-DSA-SHAKE-192f"},
    {QUAC_SIGN_SLH_DSA_SHAKE_256S, 64, 128, 29792, 5, "SLH-DSA-SHAKE-256s"},
    {QUAC_SIGN_SLH_DSA_SHAKE_256F, 64, 128, 49856, 5, "SLH-DSA-SHAKE-256f"},
};

#define NUM_SIGN_PARAMS (sizeof(g_sign_params) / sizeof(g_sign_params[0]))

/*============================================================================
 * Parameter Functions
 *============================================================================*/

QUAC_API quac_status_t quac_sign_get_params(
    quac_sign_algorithm_t algorithm,
    quac_sign_params_t *params)
{
    QUAC_CHECK_PARAM(params != NULL);

    for (size_t i = 0; i < NUM_SIGN_PARAMS; i++)
    {
        if (g_sign_params[i].algorithm == algorithm)
        {
            *params = g_sign_params[i];
            return QUAC_SUCCESS;
        }
    }

    return QUAC_ERROR_NOT_SUPPORTED;
}

QUAC_API quac_status_t quac_sign_get_sizes(
    quac_sign_algorithm_t algorithm,
    size_t *public_key_len,
    size_t *secret_key_len,
    size_t *signature_len)
{
    quac_sign_params_t params;
    quac_status_t status = quac_sign_get_params(algorithm, &params);

    if (status != QUAC_SUCCESS)
    {
        return status;
    }

    if (public_key_len)
        *public_key_len = params.public_key_size;
    if (secret_key_len)
        *secret_key_len = params.secret_key_size;
    if (signature_len)
        *signature_len = params.signature_size;

    return QUAC_SUCCESS;
}

/*============================================================================
 * Signature Operations
 *============================================================================*/

QUAC_API quac_status_t quac_sign_keygen(
    quac_device_t device,
    quac_sign_algorithm_t algorithm,
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

    quac_sign_params_t params;
    quac_status_t status = quac_sign_get_params(algorithm, &params);
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

    QUAC_LOG_DEBUG("Sign keygen: %s", params.name);

    quac_device_handle_impl *handle = (quac_device_handle_impl *)device;

    quac_device_lock_internal(handle);
    status = quac_core_sign_keygen(handle, algorithm,
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

QUAC_API quac_status_t quac_sign(
    quac_device_t device,
    quac_sign_algorithm_t algorithm,
    const uint8_t *secret_key,
    size_t secret_key_len,
    const uint8_t *message,
    size_t message_len,
    uint8_t *signature,
    size_t *signature_len)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(secret_key != NULL);
    QUAC_CHECK_PARAM(message != NULL || message_len == 0);
    QUAC_CHECK_PARAM(signature != NULL);
    QUAC_CHECK_PARAM(signature_len != NULL);

    quac_sign_params_t params;
    quac_status_t status = quac_sign_get_params(algorithm, &params);
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

    if (*signature_len < params.signature_size)
    {
        *signature_len = params.signature_size;
        return QUAC_ERROR_BUFFER_SMALL;
    }

    if (message_len > QUAC_MAX_MESSAGE_SIZE)
    {
        return QUAC_ERROR_INVALID_PARAM;
    }

    QUAC_LOG_DEBUG("Sign: %s, message_len=%zu", params.name, message_len);

    quac_device_handle_impl *handle = (quac_device_handle_impl *)device;

    quac_device_lock_internal(handle);
    status = quac_core_sign(handle, algorithm,
                            secret_key, secret_key_len,
                            message, message_len,
                            signature, signature_len);
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

QUAC_API quac_status_t quac_verify(
    quac_device_t device,
    quac_sign_algorithm_t algorithm,
    const uint8_t *public_key,
    size_t public_key_len,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *signature,
    size_t signature_len)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(public_key != NULL);
    QUAC_CHECK_PARAM(message != NULL || message_len == 0);
    QUAC_CHECK_PARAM(signature != NULL);

    quac_sign_params_t params;
    quac_status_t status = quac_sign_get_params(algorithm, &params);
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

    if (signature_len != params.signature_size)
    {
        QUAC_LOG_ERROR("Invalid signature size: %zu (expected %zu)",
                       signature_len, params.signature_size);
        return QUAC_ERROR_INVALID_PARAM;
    }

    QUAC_LOG_DEBUG("Verify: %s, message_len=%zu", params.name, message_len);

    quac_device_handle_impl *handle = (quac_device_handle_impl *)device;

    quac_device_lock_internal(handle);
    status = quac_core_verify(handle, algorithm,
                              public_key, public_key_len,
                              message, message_len,
                              signature, signature_len);
    quac_device_unlock_internal(handle);

    if (status == QUAC_SUCCESS || status == QUAC_ERROR_VERIFY_FAILED)
    {
        handle->total_ops++;
    }
    else
    {
        handle->total_errors++;
    }

    return status;
}

QUAC_API quac_status_t quac_sign_prehash(
    quac_device_t device,
    quac_sign_algorithm_t algorithm,
    const uint8_t *secret_key,
    size_t secret_key_len,
    const uint8_t *hash,
    size_t hash_len,
    quac_hash_algorithm_t hash_alg,
    uint8_t *signature,
    size_t *signature_len)
{
    (void)hash_alg;
    return quac_sign(device, algorithm, secret_key, secret_key_len,
                     hash, hash_len, signature, signature_len);
}

QUAC_API quac_status_t quac_verify_prehash(
    quac_device_t device,
    quac_sign_algorithm_t algorithm,
    const uint8_t *public_key,
    size_t public_key_len,
    const uint8_t *hash,
    size_t hash_len,
    quac_hash_algorithm_t hash_alg,
    const uint8_t *signature,
    size_t signature_len)
{
    (void)hash_alg;
    return quac_verify(device, algorithm, public_key, public_key_len,
                       hash, hash_len, signature, signature_len);
}

/*============================================================================
 * Batch Operations
 *============================================================================*/

QUAC_API quac_status_t quac_sign_keygen_batch(
    quac_device_t device,
    quac_sign_algorithm_t algorithm,
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

    quac_sign_params_t params;
    quac_status_t status = quac_sign_get_params(algorithm, &params);
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

        status_codes[i] = quac_core_sign_keygen(handle, algorithm,
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

QUAC_API quac_status_t quac_sign_batch(
    quac_device_t device,
    quac_sign_algorithm_t algorithm,
    const uint8_t *secret_key,
    size_t secret_key_len,
    size_t count,
    const uint8_t **messages,
    const size_t *message_lens,
    uint8_t **signatures,
    size_t *signature_lens,
    quac_status_t *status_codes)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(secret_key != NULL);
    QUAC_CHECK_PARAM(count > 0);
    QUAC_CHECK_PARAM(messages != NULL);
    QUAC_CHECK_PARAM(message_lens != NULL);
    QUAC_CHECK_PARAM(signatures != NULL);
    QUAC_CHECK_PARAM(signature_lens != NULL);
    QUAC_CHECK_PARAM(status_codes != NULL);

    quac_sign_params_t params;
    quac_status_t status = quac_sign_get_params(algorithm, &params);
    if (status != QUAC_SUCCESS)
    {
        return status;
    }

    quac_device_handle_impl *handle = (quac_device_handle_impl *)device;
    quac_device_lock_internal(handle);

    for (size_t i = 0; i < count; i++)
    {
        signature_lens[i] = params.signature_size;

        status_codes[i] = quac_core_sign(handle, algorithm,
                                         secret_key, secret_key_len,
                                         messages[i], message_lens[i],
                                         signatures[i], &signature_lens[i]);

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

QUAC_API quac_status_t quac_verify_batch(
    quac_device_t device,
    quac_sign_algorithm_t algorithm,
    const uint8_t *public_key,
    size_t public_key_len,
    size_t count,
    const uint8_t **messages,
    const size_t *message_lens,
    const uint8_t **signatures,
    const size_t *signature_lens,
    int *results,
    quac_status_t *status_codes)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(public_key != NULL);
    QUAC_CHECK_PARAM(count > 0);
    QUAC_CHECK_PARAM(messages != NULL);
    QUAC_CHECK_PARAM(message_lens != NULL);
    QUAC_CHECK_PARAM(signatures != NULL);
    QUAC_CHECK_PARAM(signature_lens != NULL);
    QUAC_CHECK_PARAM(results != NULL);
    QUAC_CHECK_PARAM(status_codes != NULL);

    quac_device_handle_impl *handle = (quac_device_handle_impl *)device;
    quac_device_lock_internal(handle);

    for (size_t i = 0; i < count; i++)
    {
        status_codes[i] = quac_core_verify(handle, algorithm,
                                           public_key, public_key_len,
                                           messages[i], message_lens[i],
                                           signatures[i], signature_lens[i]);

        results[i] = (status_codes[i] == QUAC_SUCCESS) ? 1 : 0;
        handle->total_ops++;
    }

    quac_device_unlock_internal(handle);
    return QUAC_SUCCESS;
}

/*============================================================================
 * Async Operations (Stub)
 *============================================================================*/

QUAC_API quac_status_t quac_sign_keygen_async(
    quac_device_t device,
    quac_sign_algorithm_t algorithm,
    uint8_t *public_key,
    size_t *public_key_len,
    uint8_t *secret_key,
    size_t *secret_key_len,
    quac_async_callback_t callback,
    void *user_data,
    quac_async_t *async_handle)
{
    (void)callback;
    (void)user_data;
    (void)async_handle;
    return quac_sign_keygen(device, algorithm, public_key, public_key_len, secret_key, secret_key_len);
}

QUAC_API quac_status_t quac_sign_async(
    quac_device_t device,
    quac_sign_algorithm_t algorithm,
    const uint8_t *secret_key,
    size_t secret_key_len,
    const uint8_t *message,
    size_t message_len,
    uint8_t *signature,
    size_t *signature_len,
    quac_async_callback_t callback,
    void *user_data,
    quac_async_t *async_handle)
{
    (void)callback;
    (void)user_data;
    (void)async_handle;
    return quac_sign(device, algorithm, secret_key, secret_key_len,
                     message, message_len, signature, signature_len);
}

QUAC_API quac_status_t quac_verify_async(
    quac_device_t device,
    quac_sign_algorithm_t algorithm,
    const uint8_t *public_key,
    size_t public_key_len,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *signature,
    size_t signature_len,
    quac_async_callback_t callback,
    void *user_data,
    quac_async_t *async_handle)
{
    (void)callback;
    (void)user_data;
    (void)async_handle;
    return quac_verify(device, algorithm, public_key, public_key_len,
                       message, message_len, signature, signature_len);
}