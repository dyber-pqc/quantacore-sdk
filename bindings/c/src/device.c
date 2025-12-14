/**
 * @file device.c
 * @brief QUAC 100 SDK - Device Management Implementation
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 */

#include "quac100/quac100.h"
#include "internal.h"

#include <stdlib.h>
#include <string.h>

/*============================================================================
 * Device Management
 *============================================================================*/

QUAC_API quac_status_t quac_enumerate_devices(
    quac_device_info_t *devices,
    int max_devices,
    int *device_count)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_PARAM(devices != NULL);
    QUAC_CHECK_PARAM(device_count != NULL);
    QUAC_CHECK_PARAM(max_devices > 0);

    int count = quac_hal_device_count();
    *device_count = 0;

    for (int i = 0; i < count && i < max_devices; i++)
    {
        quac_status_t status = quac_hal_get_device_info(i, &devices[i]);
        if (status == QUAC_SUCCESS)
        {
            (*device_count)++;
        }
    }

    QUAC_LOG_DEBUG("Enumerated %d device(s)", *device_count);
    return QUAC_SUCCESS;
}

QUAC_API quac_status_t quac_device_count(int *count)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_PARAM(count != NULL);

    *count = quac_hal_device_count();
    return QUAC_SUCCESS;
}

QUAC_API quac_status_t quac_open_device(
    int device_index,
    uint32_t flags,
    quac_device_t *device)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_PARAM(device != NULL);
    QUAC_CHECK_PARAM(device_index >= 0);

    QUAC_LOG_INFO("Opening device %d with flags 0x%08X", device_index, flags);

    quac_device_handle_impl *handle = NULL;
    quac_status_t status = quac_hal_open_device(device_index, flags, &handle);

    if (status != QUAC_SUCCESS)
    {
        QUAC_LOG_ERROR("Failed to open device %d: %s", device_index, quac_error_string(status));
        return status;
    }

    *device = (quac_device_t)handle;
    QUAC_LOG_INFO("Device %d opened successfully", device_index);

    return QUAC_SUCCESS;
}

QUAC_API quac_status_t quac_open_first_device(quac_device_t *device)
{
    return quac_open_device(0, QUAC_FLAG_DEFAULT, device);
}

QUAC_API quac_status_t quac_close_device(quac_device_t device)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);

    quac_device_handle_impl *handle = (quac_device_handle_impl *)device;

    QUAC_LOG_INFO("Closing device %d", handle->device_index);

    quac_status_t status = quac_hal_close_device(handle);

    if (status == QUAC_SUCCESS)
    {
        QUAC_LOG_DEBUG("Device %d closed", handle->device_index);
    }

    return status;
}

QUAC_API quac_status_t quac_get_device_info(
    quac_device_t device,
    quac_device_info_t *info)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(info != NULL);

    quac_device_handle_impl *handle = (quac_device_handle_impl *)device;
    memcpy(info, &handle->info, sizeof(quac_device_info_t));

    return QUAC_SUCCESS;
}

QUAC_API quac_status_t quac_get_device_status(
    quac_device_t device,
    quac_device_status_t *status)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(status != NULL);

    quac_device_handle_impl *handle = (quac_device_handle_impl *)device;

    /* Query device for current status */
    quac_device_lock_internal(handle);

    uint8_t status_buf[64];
    size_t status_len = sizeof(status_buf);

    quac_status_t result = quac_hal_send_command(handle, 0x01, NULL, 0, status_buf, &status_len);

    if (result == QUAC_SUCCESS)
    {
        /* Parse status response */
        memcpy(&handle->status.temperature, status_buf, 4);
        memcpy(&handle->status.power_mw, status_buf + 4, 4);
        memcpy(&handle->status.uptime_seconds, status_buf + 8, 8);
        memcpy(&handle->status.total_operations, status_buf + 16, 8);
        memcpy(&handle->status.ops_per_second, status_buf + 24, 4);
        handle->status.entropy_level = status_buf[28];
        handle->status.active_sessions = status_buf[29];
        handle->status.used_key_slots = status_buf[30];
        handle->status.tamper_status = status_buf[31];
        handle->status.last_error = handle->last_error;
    }

    quac_device_unlock_internal(handle);

    memcpy(status, &handle->status, sizeof(quac_device_status_t));

    return result;
}

QUAC_API quac_status_t quac_reset_device(quac_device_t device)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);

    quac_device_handle_impl *handle = (quac_device_handle_impl *)device;

    QUAC_LOG_INFO("Resetting device %d", handle->device_index);

    quac_device_lock_internal(handle);
    quac_status_t status = quac_hal_send_command(handle, 0x02, NULL, 0, NULL, NULL);
    quac_device_unlock_internal(handle);

    return status;
}

QUAC_API quac_status_t quac_self_test(quac_device_t device)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);

    quac_device_handle_impl *handle = (quac_device_handle_impl *)device;

    QUAC_LOG_INFO("Running self-test on device %d", handle->device_index);

    quac_device_lock_internal(handle);

    uint8_t result;
    size_t result_len = sizeof(result);

    quac_status_t status = quac_hal_send_command(handle, 0x03, NULL, 0, &result, &result_len);

    quac_device_unlock_internal(handle);

    if (status == QUAC_SUCCESS && result != 0)
    {
        QUAC_LOG_ERROR("Self-test failed on device %d", handle->device_index);
        return QUAC_ERROR_SELF_TEST_FAILED;
    }

    QUAC_LOG_INFO("Self-test passed on device %d", handle->device_index);
    return status;
}

QUAC_API quac_status_t quac_get_perf_stats(
    quac_device_t device,
    quac_perf_stats_t *stats)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(stats != NULL);

    quac_device_handle_impl *handle = (quac_device_handle_impl *)device;

    /* TODO: Implement actual performance tracking */
    stats->total_operations = handle->total_ops;
    stats->total_errors = handle->total_errors;
    stats->ops_per_second = 0;
    stats->avg_latency_us = 0;
    stats->min_latency_us = 0;
    stats->max_latency_us = 0;
    stats->p99_latency_us = 0;

    return QUAC_SUCCESS;
}

QUAC_API quac_status_t quac_reset_perf_stats(quac_device_t device)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);

    quac_device_handle_impl *handle = (quac_device_handle_impl *)device;

    handle->total_ops = 0;
    handle->total_errors = 0;

    return QUAC_SUCCESS;
}

QUAC_API quac_status_t quac_set_device_flags(
    quac_device_t device,
    uint32_t flags)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);

    quac_device_handle_impl *handle = (quac_device_handle_impl *)device;
    handle->flags = flags;

    return QUAC_SUCCESS;
}

QUAC_API quac_status_t quac_get_device_flags(
    quac_device_t device,
    uint32_t *flags)
{
    QUAC_CHECK_INIT();
    QUAC_CHECK_DEVICE(device);
    QUAC_CHECK_PARAM(flags != NULL);

    quac_device_handle_impl *handle = (quac_device_handle_impl *)device;
    *flags = handle->flags;

    return QUAC_SUCCESS;
}

QUAC_API int quac_device_is_open(quac_device_t device)
{
    if (!device)
        return 0;
    quac_device_handle_impl *handle = (quac_device_handle_impl *)device;
    return handle->is_open ? 1 : 0;
}

QUAC_API int quac_get_device_index(quac_device_t device)
{
    if (!device)
        return -1;
    quac_device_handle_impl *handle = (quac_device_handle_impl *)device;
    return handle->device_index;
}

/*============================================================================
 * Internal Device Functions
 *============================================================================*/

int quac_device_is_valid(quac_device_t device)
{
    if (!device)
        return 0;
    quac_device_handle_impl *handle = (quac_device_handle_impl *)device;
    return handle->is_open;
}

void quac_device_lock_internal(quac_device_handle_impl *handle)
{
#ifdef QUAC_PLATFORM_WINDOWS
    EnterCriticalSection(&handle->lock);
#else
    pthread_mutex_lock(&handle->lock);
#endif
}

void quac_device_unlock_internal(quac_device_handle_impl *handle)
{
#ifdef QUAC_PLATFORM_WINDOWS
    LeaveCriticalSection(&handle->lock);
#else
    pthread_mutex_unlock(&handle->lock);
#endif
}

QUAC_API quac_status_t quac_device_lock(quac_device_t device)
{
    QUAC_CHECK_DEVICE(device);
    quac_device_lock_internal((quac_device_handle_impl *)device);
    return QUAC_SUCCESS;
}

QUAC_API quac_status_t quac_device_unlock(quac_device_t device)
{
    QUAC_CHECK_DEVICE(device);
    quac_device_unlock_internal((quac_device_handle_impl *)device);
    return QUAC_SUCCESS;
}

QUAC_API quac_status_t quac_device_trylock(quac_device_t device)
{
    QUAC_CHECK_DEVICE(device);
    quac_device_handle_impl *handle = (quac_device_handle_impl *)device;

#ifdef QUAC_PLATFORM_WINDOWS
    if (TryEnterCriticalSection(&handle->lock))
    {
        return QUAC_SUCCESS;
    }
#else
    if (pthread_mutex_trylock(&handle->lock) == 0)
    {
        return QUAC_SUCCESS;
    }
#endif

    return QUAC_ERROR_DEVICE_BUSY;
}