/**
 * @file device.h
 * @brief QUAC 100 SDK - Device Management API
 * @copyright Copyright © 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_DEVICE_H
#define QUAC100_DEVICE_H

#include "types.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * @defgroup Device Device Management
     * @brief Functions for managing QUAC 100 device connections
     * @{
     */

    /**
     * @brief Enumerate available QUAC 100 devices
     *
     * @param[out] devices Array to store device information
     * @param[in] max_devices Maximum number of devices to enumerate
     * @param[out] device_count Number of devices found
     * @return QUAC_SUCCESS on success, error code on failure
     *
     * @code
     * quac_device_info_t devices[QUAC_MAX_DEVICES];
     * int count;
     * quac_status_t status = quac_enumerate_devices(devices, QUAC_MAX_DEVICES, &count);
     * for (int i = 0; i < count; i++) {
     *     printf("Device %d: %s (S/N: %s)\n", i, devices[i].model_name, devices[i].serial_number);
     * }
     * @endcode
     */
    QUAC_API quac_status_t quac_enumerate_devices(
        quac_device_info_t *devices,
        int max_devices,
        int *device_count);

    /**
     * @brief Get the number of available devices
     *
     * @param[out] count Number of available devices
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_device_count(int *count);

    /**
     * @brief Open a device connection
     *
     * @param[in] device_index Device index (0 for first device)
     * @param[in] flags Device flags (see quac_flags_t)
     * @param[out] device Device handle
     * @return QUAC_SUCCESS on success, error code on failure
     *
     * @code
     * quac_device_t device;
     * quac_status_t status = quac_open_device(0, QUAC_FLAG_DEFAULT, &device);
     * if (status != QUAC_SUCCESS) {
     *     fprintf(stderr, "Failed to open device: %s\n", quac_error_string(status));
     *     return 1;
     * }
     * // Use device...
     * quac_close_device(device);
     * @endcode
     */
    QUAC_API quac_status_t quac_open_device(
        int device_index,
        uint32_t flags,
        quac_device_t *device);

    /**
     * @brief Open the first available device
     *
     * Convenience function that opens device index 0 with default flags.
     *
     * @param[out] device Device handle
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_open_first_device(quac_device_t *device);

    /**
     * @brief Close a device connection
     *
     * @param[in] device Device handle
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_close_device(quac_device_t device);

    /**
     * @brief Get device information
     *
     * @param[in] device Device handle
     * @param[out] info Device information structure
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_get_device_info(
        quac_device_t device,
        quac_device_info_t *info);

    /**
     * @brief Get device status
     *
     * @param[in] device Device handle
     * @param[out] status Device status structure
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_get_device_status(
        quac_device_t device,
        quac_device_status_t *status);

    /**
     * @brief Reset the device
     *
     * Performs a soft reset of the device. All active operations are cancelled.
     *
     * @param[in] device Device handle
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_reset_device(quac_device_t device);

    /**
     * @brief Run device self-test
     *
     * Performs known-answer tests and hardware verification.
     *
     * @param[in] device Device handle
     * @return QUAC_SUCCESS if tests pass, QUAC_ERROR_SELF_TEST_FAILED if tests fail
     */
    QUAC_API quac_status_t quac_self_test(quac_device_t device);

    /**
     * @brief Get performance statistics
     *
     * @param[in] device Device handle
     * @param[out] stats Performance statistics
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_get_perf_stats(
        quac_device_t device,
        quac_perf_stats_t *stats);

    /**
     * @brief Reset performance statistics
     *
     * @param[in] device Device handle
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_reset_perf_stats(quac_device_t device);

    /**
     * @brief Set device flags
     *
     * @param[in] device Device handle
     * @param[in] flags New flags to set
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_set_device_flags(
        quac_device_t device,
        uint32_t flags);

    /**
     * @brief Get device flags
     *
     * @param[in] device Device handle
     * @param[out] flags Current device flags
     * @return QUAC_SUCCESS on success, error code on failure
     */
    QUAC_API quac_status_t quac_get_device_flags(
        quac_device_t device,
        uint32_t *flags);

    /**
     * @brief Check if device is open
     *
     * @param[in] device Device handle
     * @return Non-zero if open, zero otherwise
     */
    QUAC_API int quac_device_is_open(quac_device_t device);

    /**
     * @brief Get device index
     *
     * @param[in] device Device handle
     * @return Device index or -1 on error
     */
    QUAC_API int quac_get_device_index(quac_device_t device);

    /** @} */ /* end of Device group */

#ifdef __cplusplus
}
#endif

#endif /* QUAC100_DEVICE_H */