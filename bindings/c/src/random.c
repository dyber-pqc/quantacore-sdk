/**
 * @file random.c
 * @brief QUAC 100 SDK - Quantum Random Number Generation Implementation
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 */

#include "quac100/quac100.h"
#include "internal.h"

#include <stdlib.h>
#include <string.h>
#include <math.h>

/*============================================================================
 * Random Number Generation
 *============================================================================*/

QUAC_API quac_status_t quac_random_bytes(
    quac_device_t device,
    uint8_t *buffer,
    size_t length)
{
    return quac_random_bytes_ex(device, buffer, length, QUAC_ENTROPY_QRNG);
}

QUAC_API quac_status_t quac_random_bytes_ex(
    quac_device_t device,
    uint8_t *buffer,
    size_t length,
    quac_entropy_source_t source)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(buffer != NULL);

    if (length == 0)
    {
        return QUAC_SUCCESS;
    }

    QUAC_LOG_TRACE("Random bytes: %zu bytes from source %d", length, source);

    quac_device_handle_impl *handle = (quac_device_handle_impl *)device;

    quac_device_lock_internal(handle);
    quac_status_t status = quac_core_random_bytes(handle, buffer, length, source);
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

QUAC_API quac_status_t quac_random_bytes_nonzero(
    quac_device_t device,
    uint8_t *buffer,
    size_t length)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(buffer != NULL);

    if (length == 0)
    {
        return QUAC_SUCCESS;
    }

    quac_status_t status = quac_random_bytes(device, buffer, length);
    if (status != QUAC_SUCCESS)
    {
        return status;
    }

    /* Replace any zero bytes */
    for (size_t i = 0; i < length; i++)
    {
        while (buffer[i] == 0)
        {
            status = quac_random_bytes(device, &buffer[i], 1);
            if (status != QUAC_SUCCESS)
            {
                return status;
            }
        }
    }

    return QUAC_SUCCESS;
}

QUAC_API quac_status_t quac_random_uint32(
    quac_device_t device,
    uint32_t *value)
{
    QUAC_CHECK_PARAM(value != NULL);
    return quac_random_bytes(device, (uint8_t *)value, sizeof(uint32_t));
}

QUAC_API quac_status_t quac_random_uint64(
    quac_device_t device,
    uint64_t *value)
{
    QUAC_CHECK_PARAM(value != NULL);
    return quac_random_bytes(device, (uint8_t *)value, sizeof(uint64_t));
}

QUAC_API quac_status_t quac_random_range(
    quac_device_t device,
    uint32_t max,
    uint32_t *value)
{
    QUAC_CHECK_PARAM(max > 0);
    QUAC_CHECK_PARAM(value != NULL);

    /* Use rejection sampling for unbiased results */
    uint32_t threshold = (UINT32_MAX - max + 1) % max;
    uint32_t r;

    do
    {
        quac_status_t status = quac_random_uint32(device, &r);
        if (status != QUAC_SUCCESS)
        {
            return status;
        }
    } while (r < threshold);

    *value = r % max;
    return QUAC_SUCCESS;
}

QUAC_API quac_status_t quac_random_range_ex(
    quac_device_t device,
    int64_t min,
    int64_t max,
    int64_t *value)
{
    QUAC_CHECK_PARAM(max > min);
    QUAC_CHECK_PARAM(value != NULL);

    uint64_t range = (uint64_t)(max - min);
    uint64_t threshold = (UINT64_MAX - range + 1) % range;
    uint64_t r;

    do
    {
        quac_status_t status = quac_random_uint64(device, &r);
        if (status != QUAC_SUCCESS)
        {
            return status;
        }
    } while (r < threshold);

    *value = min + (int64_t)(r % range);
    return QUAC_SUCCESS;
}

QUAC_API quac_status_t quac_random_double(
    quac_device_t device,
    double *value)
{
    QUAC_CHECK_PARAM(value != NULL);

    uint64_t r;
    quac_status_t status = quac_random_uint64(device, &r);
    if (status != QUAC_SUCCESS)
    {
        return status;
    }

    /* Use 53 bits for full double mantissa precision */
    *value = (double)(r >> 11) / (double)(1ULL << 53);
    return QUAC_SUCCESS;
}

QUAC_API quac_status_t quac_random_float(
    quac_device_t device,
    float *value)
{
    QUAC_CHECK_PARAM(value != NULL);

    uint32_t r;
    quac_status_t status = quac_random_uint32(device, &r);
    if (status != QUAC_SUCCESS)
    {
        return status;
    }

    /* Use 24 bits for full float mantissa precision */
    *value = (float)(r >> 8) / (float)(1UL << 24);
    return QUAC_SUCCESS;
}

QUAC_API quac_status_t quac_entropy_status(
    quac_device_t device,
    quac_entropy_status_t *status)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(status != NULL);

    quac_device_handle_impl *handle = (quac_device_handle_impl *)device;

    quac_device_lock_internal(handle);

    uint8_t entropy_buf[32];
    size_t entropy_len = sizeof(entropy_buf);

    quac_status_t result = quac_hal_send_command(handle, 0x10, NULL, 0, entropy_buf, &entropy_len);

    if (result == QUAC_SUCCESS)
    {
        status->level = entropy_buf[0];
        status->source = (quac_entropy_source_t)entropy_buf[1];
        memcpy(&status->bytes_generated, entropy_buf + 2, 8);
        status->health_ok = entropy_buf[10] != 0;
    }

    quac_device_unlock_internal(handle);

    return result;
}

QUAC_API quac_status_t quac_entropy_level(
    quac_device_t device,
    int *level)
{
    quac_entropy_status_t status;
    quac_status_t result = quac_entropy_status(device, &status);
    if (result == QUAC_SUCCESS)
    {
        *level = status.level;
    }
    return result;
}

QUAC_API quac_status_t quac_random_seed(
    quac_device_t device,
    const uint8_t *seed,
    size_t seed_len)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(seed != NULL);
    QUAC_CHECK_PARAM(seed_len > 0);

    quac_device_handle_impl *handle = (quac_device_handle_impl *)device;

    quac_device_lock_internal(handle);
    quac_status_t status = quac_hal_send_command(handle, 0x11, seed, seed_len, NULL, NULL);
    quac_device_unlock_internal(handle);

    return status;
}

QUAC_API quac_status_t quac_random_reseed(quac_device_t device)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);

    quac_device_handle_impl *handle = (quac_device_handle_impl *)device;

    quac_device_lock_internal(handle);
    quac_status_t status = quac_hal_send_command(handle, 0x12, NULL, 0, NULL, NULL);
    quac_device_unlock_internal(handle);

    return status;
}

QUAC_API quac_status_t quac_random_shuffle(
    quac_device_t device,
    void *array,
    size_t count,
    size_t element_size)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(array != NULL);
    QUAC_CHECK_PARAM(element_size > 0);

    if (count <= 1)
    {
        return QUAC_SUCCESS;
    }

    uint8_t *arr = (uint8_t *)array;
    uint8_t *temp = (uint8_t *)malloc(element_size);
    if (!temp)
    {
        return QUAC_ERROR_OUT_OF_MEMORY;
    }

    /* Fisher-Yates shuffle */
    for (size_t i = count - 1; i > 0; i--)
    {
        uint32_t j;
        quac_status_t status = quac_random_range(device, (uint32_t)(i + 1), &j);
        if (status != QUAC_SUCCESS)
        {
            free(temp);
            return status;
        }

        if (j != i)
        {
            memcpy(temp, arr + i * element_size, element_size);
            memcpy(arr + i * element_size, arr + j * element_size, element_size);
            memcpy(arr + j * element_size, temp, element_size);
        }
    }

    free(temp);
    return QUAC_SUCCESS;
}

QUAC_API quac_status_t quac_random_select(
    quac_device_t device,
    const void *array,
    size_t count,
    size_t element_size,
    size_t select_count,
    void *selected)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(array != NULL);
    QUAC_CHECK_PARAM(selected != NULL);
    QUAC_CHECK_PARAM(element_size > 0);
    QUAC_CHECK_PARAM(select_count <= count);

    if (select_count == 0)
    {
        return QUAC_SUCCESS;
    }

    /* Create index array */
    size_t *indices = (size_t *)malloc(count * sizeof(size_t));
    if (!indices)
    {
        return QUAC_ERROR_OUT_OF_MEMORY;
    }

    for (size_t i = 0; i < count; i++)
    {
        indices[i] = i;
    }

    /* Partial Fisher-Yates shuffle */
    const uint8_t *src = (const uint8_t *)array;
    uint8_t *dst = (uint8_t *)selected;

    for (size_t i = 0; i < select_count; i++)
    {
        uint32_t j;
        quac_status_t status = quac_random_range(device, (uint32_t)(count - i), &j);
        if (status != QUAC_SUCCESS)
        {
            free(indices);
            return status;
        }

        j += (uint32_t)i;

        /* Copy selected element */
        memcpy(dst + i * element_size, src + indices[j] * element_size, element_size);

        /* Swap indices */
        size_t tmp = indices[i];
        indices[i] = indices[j];
        indices[j] = tmp;
    }

    free(indices);
    return QUAC_SUCCESS;
}

QUAC_API quac_status_t quac_random_uuid(
    quac_device_t device,
    uint8_t uuid[16])
{
    QUAC_CHECK_PARAM(uuid != NULL);

    quac_status_t status = quac_random_bytes(device, uuid, 16);
    if (status != QUAC_SUCCESS)
    {
        return status;
    }

    /* Set version 4 (random) */
    uuid[6] = (uuid[6] & 0x0F) | 0x40;

    /* Set variant (RFC 4122) */
    uuid[8] = (uuid[8] & 0x3F) | 0x80;

    return QUAC_SUCCESS;
}

QUAC_API quac_status_t quac_random_uuid_string(
    quac_device_t device,
    char *uuid_str,
    size_t buffer_size)
{
    QUAC_CHECK_PARAM(uuid_str != NULL);
    QUAC_CHECK_PARAM(buffer_size >= 37);

    uint8_t uuid[16];
    quac_status_t status = quac_random_uuid(device, uuid);
    if (status != QUAC_SUCCESS)
    {
        return status;
    }

    snprintf(uuid_str, buffer_size,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             uuid[0], uuid[1], uuid[2], uuid[3],
             uuid[4], uuid[5], uuid[6], uuid[7],
             uuid[8], uuid[9], uuid[10], uuid[11],
             uuid[12], uuid[13], uuid[14], uuid[15]);

    return QUAC_SUCCESS;
}

QUAC_API quac_status_t quac_random_estimate_entropy(
    quac_device_t device,
    size_t sample_size,
    double *entropy)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(sample_size > 0);
    QUAC_CHECK_PARAM(entropy != NULL);

    uint8_t *buffer = (uint8_t *)malloc(sample_size);
    if (!buffer)
    {
        return QUAC_ERROR_OUT_OF_MEMORY;
    }

    quac_status_t status = quac_random_bytes(device, buffer, sample_size);
    if (status != QUAC_SUCCESS)
    {
        free(buffer);
        return status;
    }

    /* Count byte frequencies */
    size_t freq[256] = {0};
    for (size_t i = 0; i < sample_size; i++)
    {
        freq[buffer[i]]++;
    }

    /* Calculate Shannon entropy */
    double h = 0.0;
    for (int i = 0; i < 256; i++)
    {
        if (freq[i] > 0)
        {
            double p = (double)freq[i] / (double)sample_size;
            h -= p * log2(p);
        }
    }

    *entropy = h;

    free(buffer);
    return QUAC_SUCCESS;
}

QUAC_API quac_status_t quac_random_health_test(
    quac_device_t device,
    int *passed)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(passed != NULL);

    /* Simple health check: generate bytes and verify entropy */
    double entropy;
    quac_status_t status = quac_random_estimate_entropy(device, 10000, &entropy);
    if (status != QUAC_SUCCESS)
    {
        return status;
    }

    /* Entropy should be at least 7.5 bits per byte for good random data */
    *passed = (entropy >= 7.5) ? 1 : 0;

    return QUAC_SUCCESS;
}

QUAC_API quac_status_t quac_random_benchmark(
    quac_device_t device,
    size_t total_bytes,
    double *mbps)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(total_bytes > 0);
    QUAC_CHECK_PARAM(mbps != NULL);

    const size_t chunk_size = 64 * 1024; /* 64 KB chunks */
    uint8_t *buffer = (uint8_t *)malloc(chunk_size);
    if (!buffer)
    {
        return QUAC_ERROR_OUT_OF_MEMORY;
    }

    uint64_t start = quac_timestamp_ns();
    size_t generated = 0;

    while (generated < total_bytes)
    {
        size_t to_generate = chunk_size;
        if (generated + to_generate > total_bytes)
        {
            to_generate = total_bytes - generated;
        }

        quac_status_t status = quac_random_bytes(device, buffer, to_generate);
        if (status != QUAC_SUCCESS)
        {
            free(buffer);
            return status;
        }

        generated += to_generate;
    }

    uint64_t elapsed = quac_timestamp_ns() - start;
    double seconds = (double)elapsed / 1e9;
    *mbps = (double)total_bytes / (1024.0 * 1024.0 * seconds);

    free(buffer);
    return QUAC_SUCCESS;
}

QUAC_API quac_status_t quac_random_bytes_async(
    quac_device_t device,
    uint8_t *buffer,
    size_t length,
    quac_async_callback_t callback,
    void *user_data,
    quac_async_t *async_handle)
{
    (void)callback;
    (void)user_data;
    (void)async_handle;
    return quac_random_bytes(device, buffer, length);
}