/**
 * @file device.h
 * @brief QUAC 100 CLI - Device Management
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC_CLI_DEVICE_H
#define QUAC_CLI_DEVICE_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /*=============================================================================
     * Device Information
     *=============================================================================*/

#define MAX_DEVICE_NAME 64
#define MAX_VERSION_STRING 32
#define MAX_SERIAL_NUMBER 64

    typedef struct
    {
        char name[MAX_DEVICE_NAME];
        char firmware_version[MAX_VERSION_STRING];
        char hardware_version[MAX_VERSION_STRING];
        char serial_number[MAX_SERIAL_NUMBER];
        int index;
        bool available;
        bool is_simulator;

        /* Capabilities */
        bool supports_kem;
        bool supports_sign;
        bool supports_random;
        bool supports_batch;

        /* Status */
        uint32_t temperature;
        uint32_t operations_count;
        uint32_t error_count;
    } device_info_t;

    /*=============================================================================
     * Context Handle
     *=============================================================================*/

    typedef struct cli_context cli_context_t;
    typedef struct cli_device cli_device_t;

    /*=============================================================================
     * Context Management
     *=============================================================================*/

    /**
     * @brief Initialize CLI context
     * @return Context handle or NULL
     */
    cli_context_t *cli_context_init(void);

    /**
     * @brief Cleanup CLI context
     */
    void cli_context_cleanup(cli_context_t *ctx);

    /*=============================================================================
     * Device Management
     *=============================================================================*/

    /**
     * @brief Get number of available devices
     */
    int cli_get_device_count(cli_context_t *ctx);

    /**
     * @brief Get device information
     */
    int cli_get_device_info(cli_context_t *ctx, int index, device_info_t *info);

    /**
     * @brief Open a device
     */
    cli_device_t *cli_open_device(cli_context_t *ctx, int index);

    /**
     * @brief Open simulator
     */
    cli_device_t *cli_open_simulator(cli_context_t *ctx);

    /**
     * @brief Close device
     */
    void cli_close_device(cli_device_t *dev);

    /**
     * @brief Get device info from open device
     */
    int cli_device_get_info(cli_device_t *dev, device_info_t *info);

    /**
     * @brief Check if device is simulator
     */
    bool cli_device_is_simulator(cli_device_t *dev);

    /*=============================================================================
     * Global Device Access
     *=============================================================================*/

    /**
     * @brief Get or open the current device based on global options
     */
    cli_device_t *cli_get_current_device(void);

    /**
     * @brief Release the current device
     */
    void cli_release_current_device(void);

#ifdef __cplusplus
}
#endif

#endif /* QUAC_CLI_DEVICE_H */