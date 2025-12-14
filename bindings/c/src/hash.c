/**
 * @file hash.c
 * @brief QUAC 100 SDK - Hash Operations Implementation
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 */

#include "quac100/quac100.h"
#include "internal.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*============================================================================
 * Hash Size Lookup
 *============================================================================*/

QUAC_API quac_status_t quac_hash_size(
    quac_hash_algorithm_t algorithm,
    size_t *size)
{
    QUAC_CHECK_PARAM(size != NULL);

    switch (algorithm)
    {
    case QUAC_HASH_SHA256:
        *size = 32;
        break;
    case QUAC_HASH_SHA384:
        *size = 48;
        break;
    case QUAC_HASH_SHA512:
        *size = 64;
        break;
    case QUAC_HASH_SHA3_256:
        *size = 32;
        break;
    case QUAC_HASH_SHA3_384:
        *size = 48;
        break;
    case QUAC_HASH_SHA3_512:
        *size = 64;
        break;
    case QUAC_HASH_SHAKE128:
        *size = 0;
        break; /* Variable */
    case QUAC_HASH_SHAKE256:
        *size = 0;
        break; /* Variable */
    default:
        return QUAC_ERROR_NOT_SUPPORTED;
    }

    return QUAC_SUCCESS;
}

/*============================================================================
 * One-Shot Hash Operations
 *============================================================================*/

QUAC_API quac_status_t quac_hash(
    quac_device_t device,
    quac_hash_algorithm_t algorithm,
    const uint8_t *data,
    size_t data_len,
    uint8_t *hash,
    size_t *hash_len)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(data != NULL || data_len == 0);
    QUAC_CHECK_PARAM(hash != NULL);
    QUAC_CHECK_PARAM(hash_len != NULL);

    size_t required_len;
    quac_status_t status = quac_hash_size(algorithm, &required_len);
    if (status != QUAC_SUCCESS)
    {
        return status;
    }

    if (required_len > 0 && *hash_len < required_len)
    {
        *hash_len = required_len;
        return QUAC_ERROR_BUFFER_SMALL;
    }

    QUAC_LOG_DEBUG("Hash: algorithm=%d, data_len=%zu", algorithm, data_len);

    quac_device_handle_impl *handle = (quac_device_handle_impl *)device;

    quac_device_lock_internal(handle);
    status = quac_core_hash(handle, algorithm, data, data_len, hash, hash_len);
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
 * Incremental Hash Operations
 *============================================================================*/

QUAC_API quac_status_t quac_hash_init(
    quac_device_t device,
    quac_hash_algorithm_t algorithm,
    quac_hash_ctx_t *ctx)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(ctx != NULL);

    quac_hash_context_impl *context = (quac_hash_context_impl *)calloc(1, sizeof(quac_hash_context_impl));
    if (!context)
    {
        return QUAC_ERROR_OUT_OF_MEMORY;
    }

    context->device = device;
    context->algorithm = algorithm;
    context->finalized = false;
    context->buffer_len = 0;

    *ctx = (quac_hash_ctx_t)context;
    return QUAC_SUCCESS;
}

QUAC_API quac_status_t quac_hash_update(
    quac_hash_ctx_t ctx,
    const uint8_t *data,
    size_t data_len)
{
    QUAC_CHECK_PARAM(ctx != NULL);
    QUAC_CHECK_PARAM(data != NULL || data_len == 0);

    quac_hash_context_impl *context = (quac_hash_context_impl *)ctx;

    if (context->finalized)
    {
        return QUAC_ERROR_INVALID_PARAM;
    }

    /* For now, buffer all data (simplified implementation) */
    /* A real implementation would process blocks incrementally */
    if (context->buffer_len + data_len > sizeof(context->buffer) + sizeof(context->state))
    {
        return QUAC_ERROR_BUFFER_SMALL;
    }

    if (context->buffer_len < sizeof(context->buffer))
    {
        size_t copy_len = sizeof(context->buffer) - context->buffer_len;
        if (copy_len > data_len)
            copy_len = data_len;
        memcpy(context->buffer + context->buffer_len, data, copy_len);
        context->buffer_len += copy_len;
        data += copy_len;
        data_len -= copy_len;
    }

    if (data_len > 0)
    {
        memcpy(context->state + context->state_size, data, data_len);
        context->state_size += data_len;
    }

    return QUAC_SUCCESS;
}

QUAC_API quac_status_t quac_hash_final(
    quac_hash_ctx_t ctx,
    uint8_t *hash,
    size_t *hash_len)
{
    QUAC_CHECK_PARAM(ctx != NULL);
    QUAC_CHECK_PARAM(hash != NULL);
    QUAC_CHECK_PARAM(hash_len != NULL);

    quac_hash_context_impl *context = (quac_hash_context_impl *)ctx;

    if (context->finalized)
    {
        return QUAC_ERROR_INVALID_PARAM;
    }

    /* Combine buffer and state for final hash */
    size_t total_len = context->buffer_len + context->state_size;
    uint8_t *combined = (uint8_t *)malloc(total_len);
    if (!combined && total_len > 0)
    {
        return QUAC_ERROR_OUT_OF_MEMORY;
    }

    if (total_len > 0)
    {
        memcpy(combined, context->buffer, context->buffer_len);
        memcpy(combined + context->buffer_len, context->state, context->state_size);
    }

    quac_status_t status = quac_hash(context->device, context->algorithm,
                                     combined, total_len, hash, hash_len);

    free(combined);

    if (status == QUAC_SUCCESS)
    {
        context->finalized = true;
    }

    return status;
}

QUAC_API quac_status_t quac_hash_free(quac_hash_ctx_t ctx)
{
    if (!ctx)
    {
        return QUAC_SUCCESS;
    }

    quac_hash_context_impl *context = (quac_hash_context_impl *)ctx;

    /* Securely clear state */
    quac_secure_zero(context, sizeof(quac_hash_context_impl));
    free(context);

    return QUAC_SUCCESS;
}

QUAC_API quac_status_t quac_hash_clone(
    quac_hash_ctx_t src,
    quac_hash_ctx_t *dst)
{
    QUAC_CHECK_PARAM(src != NULL);
    QUAC_CHECK_PARAM(dst != NULL);

    quac_hash_context_impl *src_ctx = (quac_hash_context_impl *)src;
    quac_hash_context_impl *dst_ctx = (quac_hash_context_impl *)calloc(1, sizeof(quac_hash_context_impl));

    if (!dst_ctx)
    {
        return QUAC_ERROR_OUT_OF_MEMORY;
    }

    memcpy(dst_ctx, src_ctx, sizeof(quac_hash_context_impl));
    *dst = (quac_hash_ctx_t)dst_ctx;

    return QUAC_SUCCESS;
}

QUAC_API quac_status_t quac_hash_reset(quac_hash_ctx_t ctx)
{
    QUAC_CHECK_PARAM(ctx != NULL);

    quac_hash_context_impl *context = (quac_hash_context_impl *)ctx;

    context->finalized = false;
    context->buffer_len = 0;
    context->state_size = 0;
    memset(context->buffer, 0, sizeof(context->buffer));
    memset(context->state, 0, sizeof(context->state));

    return QUAC_SUCCESS;
}

/*============================================================================
 * Convenience Functions
 *============================================================================*/

QUAC_API quac_status_t quac_sha256(
    quac_device_t device,
    const uint8_t *data,
    size_t data_len,
    uint8_t hash[QUAC_SHA256_SIZE])
{
    size_t hash_len = QUAC_SHA256_SIZE;
    return quac_hash(device, QUAC_HASH_SHA256, data, data_len, hash, &hash_len);
}

QUAC_API quac_status_t quac_sha384(
    quac_device_t device,
    const uint8_t *data,
    size_t data_len,
    uint8_t hash[QUAC_SHA384_SIZE])
{
    size_t hash_len = QUAC_SHA384_SIZE;
    return quac_hash(device, QUAC_HASH_SHA384, data, data_len, hash, &hash_len);
}

QUAC_API quac_status_t quac_sha512(
    quac_device_t device,
    const uint8_t *data,
    size_t data_len,
    uint8_t hash[QUAC_SHA512_SIZE])
{
    size_t hash_len = QUAC_SHA512_SIZE;
    return quac_hash(device, QUAC_HASH_SHA512, data, data_len, hash, &hash_len);
}

QUAC_API quac_status_t quac_sha3_256(
    quac_device_t device,
    const uint8_t *data,
    size_t data_len,
    uint8_t hash[QUAC_SHA3_256_SIZE])
{
    size_t hash_len = QUAC_SHA3_256_SIZE;
    return quac_hash(device, QUAC_HASH_SHA3_256, data, data_len, hash, &hash_len);
}

QUAC_API quac_status_t quac_sha3_512(
    quac_device_t device,
    const uint8_t *data,
    size_t data_len,
    uint8_t hash[QUAC_SHA3_512_SIZE])
{
    size_t hash_len = QUAC_SHA3_512_SIZE;
    return quac_hash(device, QUAC_HASH_SHA3_512, data, data_len, hash, &hash_len);
}

QUAC_API quac_status_t quac_shake128(
    quac_device_t device,
    const uint8_t *data,
    size_t data_len,
    uint8_t *output,
    size_t output_len)
{
    return quac_hash(device, QUAC_HASH_SHAKE128, data, data_len, output, &output_len);
}

QUAC_API quac_status_t quac_shake256(
    quac_device_t device,
    const uint8_t *data,
    size_t data_len,
    uint8_t *output,
    size_t output_len)
{
    return quac_hash(device, QUAC_HASH_SHAKE256, data, data_len, output, &output_len);
}

/*============================================================================
 * HMAC
 *============================================================================*/

QUAC_API quac_status_t quac_hmac(
    quac_device_t device,
    quac_hash_algorithm_t algorithm,
    const uint8_t *key,
    size_t key_len,
    const uint8_t *data,
    size_t data_len,
    uint8_t *mac,
    size_t *mac_len)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(key != NULL);
    QUAC_CHECK_PARAM(data != NULL || data_len == 0);
    QUAC_CHECK_PARAM(mac != NULL);
    QUAC_CHECK_PARAM(mac_len != NULL);

    size_t hash_size;
    quac_status_t status = quac_hash_size(algorithm, &hash_size);
    if (status != QUAC_SUCCESS)
    {
        return status;
    }

    if (*mac_len < hash_size)
    {
        *mac_len = hash_size;
        return QUAC_ERROR_BUFFER_SMALL;
    }

    /* Block size for SHA-2/SHA-3 */
    size_t block_size = (algorithm == QUAC_HASH_SHA384 || algorithm == QUAC_HASH_SHA512 ||
                         algorithm == QUAC_HASH_SHA3_384 || algorithm == QUAC_HASH_SHA3_512)
                            ? 128
                            : 64;

    uint8_t *k = (uint8_t *)calloc(block_size, 1);
    uint8_t *ipad = (uint8_t *)malloc(block_size + data_len);
    uint8_t *opad = (uint8_t *)malloc(block_size + hash_size);

    if (!k || !ipad || !opad)
    {
        free(k);
        free(ipad);
        free(opad);
        return QUAC_ERROR_OUT_OF_MEMORY;
    }

    /* Prepare key */
    if (key_len > block_size)
    {
        size_t k_len = hash_size;
        status = quac_hash(device, algorithm, key, key_len, k, &k_len);
        if (status != QUAC_SUCCESS)
        {
            goto cleanup;
        }
    }
    else
    {
        memcpy(k, key, key_len);
    }

    /* Inner padding */
    for (size_t i = 0; i < block_size; i++)
    {
        ipad[i] = k[i] ^ 0x36;
    }
    memcpy(ipad + block_size, data, data_len);

    /* Inner hash */
    uint8_t inner_hash[64];
    size_t inner_len = hash_size;
    status = quac_hash(device, algorithm, ipad, block_size + data_len, inner_hash, &inner_len);
    if (status != QUAC_SUCCESS)
    {
        goto cleanup;
    }

    /* Outer padding */
    for (size_t i = 0; i < block_size; i++)
    {
        opad[i] = k[i] ^ 0x5c;
    }
    memcpy(opad + block_size, inner_hash, hash_size);

    /* Outer hash */
    status = quac_hash(device, algorithm, opad, block_size + hash_size, mac, mac_len);

cleanup:
    quac_secure_zero(k, block_size);
    quac_secure_zero(ipad, block_size + data_len);
    quac_secure_zero(opad, block_size + hash_size);
    quac_secure_zero(inner_hash, sizeof(inner_hash));
    free(k);
    free(ipad);
    free(opad);

    return status;
}

/*============================================================================
 * HKDF
 *============================================================================*/

QUAC_API quac_status_t quac_hkdf(
    quac_device_t device,
    quac_hash_algorithm_t algorithm,
    const uint8_t *salt,
    size_t salt_len,
    const uint8_t *ikm,
    size_t ikm_len,
    const uint8_t *info,
    size_t info_len,
    uint8_t *okm,
    size_t okm_len)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(ikm != NULL);
    QUAC_CHECK_PARAM(okm != NULL);

    size_t hash_len;
    quac_status_t status = quac_hash_size(algorithm, &hash_len);
    if (status != QUAC_SUCCESS)
    {
        return status;
    }

    /* Extract */
    uint8_t prk[64];
    size_t prk_len = hash_len;

    if (salt == NULL || salt_len == 0)
    {
        uint8_t zero_salt[64] = {0};
        status = quac_hmac(device, algorithm, zero_salt, hash_len, ikm, ikm_len, prk, &prk_len);
    }
    else
    {
        status = quac_hmac(device, algorithm, salt, salt_len, ikm, ikm_len, prk, &prk_len);
    }

    if (status != QUAC_SUCCESS)
    {
        return status;
    }

    /* Expand */
    size_t n = (okm_len + hash_len - 1) / hash_len;
    if (n > 255)
    {
        quac_secure_zero(prk, sizeof(prk));
        return QUAC_ERROR_INVALID_PARAM;
    }

    uint8_t t[64] = {0};
    size_t t_len = 0;
    size_t offset = 0;

    uint8_t *expand_input = (uint8_t *)malloc(hash_len + info_len + 1);
    if (!expand_input)
    {
        quac_secure_zero(prk, sizeof(prk));
        return QUAC_ERROR_OUT_OF_MEMORY;
    }

    for (size_t i = 1; i <= n; i++)
    {
        size_t input_len = 0;

        if (t_len > 0)
        {
            memcpy(expand_input, t, t_len);
            input_len += t_len;
        }

        if (info != NULL && info_len > 0)
        {
            memcpy(expand_input + input_len, info, info_len);
            input_len += info_len;
        }

        expand_input[input_len++] = (uint8_t)i;

        t_len = hash_len;
        status = quac_hmac(device, algorithm, prk, prk_len, expand_input, input_len, t, &t_len);
        if (status != QUAC_SUCCESS)
        {
            break;
        }

        size_t copy_len = hash_len;
        if (offset + copy_len > okm_len)
        {
            copy_len = okm_len - offset;
        }

        memcpy(okm + offset, t, copy_len);
        offset += copy_len;
    }

    quac_secure_zero(prk, sizeof(prk));
    quac_secure_zero(t, sizeof(t));
    quac_secure_zero(expand_input, hash_len + info_len + 1);
    free(expand_input);

    return status;
}

/*============================================================================
 * File Hashing
 *============================================================================*/

QUAC_API quac_status_t quac_hash_file(
    quac_device_t device,
    quac_hash_algorithm_t algorithm,
    const char *filename,
    uint8_t *hash,
    size_t *hash_len,
    quac_progress_callback_t progress,
    void *user_data)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(filename != NULL);
    QUAC_CHECK_PARAM(hash != NULL);
    QUAC_CHECK_PARAM(hash_len != NULL);

    FILE *f = fopen(filename, "rb");
    if (!f)
    {
        return QUAC_ERROR_INVALID_PARAM;
    }

    /* Get file size */
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (file_size < 0)
    {
        fclose(f);
        return QUAC_ERROR_INVALID_PARAM;
    }

    quac_hash_ctx_t ctx;
    quac_status_t status = quac_hash_init(device, algorithm, &ctx);
    if (status != QUAC_SUCCESS)
    {
        fclose(f);
        return status;
    }

    const size_t buffer_size = 64 * 1024;
    uint8_t *buffer = (uint8_t *)malloc(buffer_size);
    if (!buffer)
    {
        quac_hash_free(ctx);
        fclose(f);
        return QUAC_ERROR_OUT_OF_MEMORY;
    }

    long bytes_read = 0;
    size_t n;

    while ((n = fread(buffer, 1, buffer_size, f)) > 0)
    {
        status = quac_hash_update(ctx, buffer, n);
        if (status != QUAC_SUCCESS)
        {
            break;
        }

        bytes_read += n;

        if (progress && file_size > 0)
        {
            int percent = (int)((bytes_read * 100) / file_size);
            progress(percent, user_data);
        }
    }

    if (status == QUAC_SUCCESS)
    {
        status = quac_hash_final(ctx, hash, hash_len);
    }

    quac_hash_free(ctx);
    free(buffer);
    fclose(f);

    return status;
}