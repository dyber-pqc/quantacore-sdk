/**
 * @file device.c
 * @brief QUAC 100 CLI - Device Management Implementation
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "device.h"
#include "commands.h"
#include "utils.h"

#ifdef HAVE_QUAC_SDK
#include <quac100.h>
#endif

/*=============================================================================
 * Internal Structures
 *=============================================================================*/

struct cli_context
{
    void *sdk_handle;
    bool initialized;
};

struct cli_device
{
    void *handle;
    device_info_t info;
    bool is_simulator;
};

/* Global context and device */
static cli_context_t *g_context = NULL;
static cli_device_t *g_device = NULL;

/*=============================================================================
 * Context Management
 *=============================================================================*/

cli_context_t *cli_context_init(void)
{
    cli_context_t *ctx = calloc(1, sizeof(cli_context_t));
    if (!ctx)
        return NULL;

#ifdef HAVE_QUAC_SDK
    if (quac_init(&ctx->sdk_handle) != QUAC_SUCCESS)
    {
        ctx->sdk_handle = NULL;
    }
#else
    ctx->sdk_handle = NULL;
#endif

    ctx->initialized = true;
    return ctx;
}

void cli_context_cleanup(cli_context_t *ctx)
{
    if (!ctx)
        return;

#ifdef HAVE_QUAC_SDK
    if (ctx->sdk_handle)
    {
        quac_shutdown(ctx->sdk_handle);
    }
#endif

    free(ctx);
}

/*=============================================================================
 * Device Management
 *=============================================================================*/

int cli_get_device_count(cli_context_t *ctx)
{
    if (!ctx)
        return 0;

#ifdef HAVE_QUAC_SDK
    if (ctx->sdk_handle)
    {
        uint32_t count = 0;
        if (quac_get_device_count(ctx->sdk_handle, &count) == QUAC_SUCCESS)
        {
            return (int)count;
        }
    }
#endif

    /* Simulator always available */
    return 1;
}

int cli_get_device_info(cli_context_t *ctx, int index, device_info_t *info)
{
    if (!ctx || !info)
        return -1;

    memset(info, 0, sizeof(*info));
    info->index = index;

#ifdef HAVE_QUAC_SDK
    if (ctx->sdk_handle)
    {
        quac_device_info_t sdk_info;
        if (quac_get_device_info(ctx->sdk_handle, index, &sdk_info) == QUAC_SUCCESS)
        {
            strncpy(info->name, sdk_info.name, sizeof(info->name) - 1);
            strncpy(info->firmware_version, sdk_info.firmware_version,
                    sizeof(info->firmware_version) - 1);
            strncpy(info->serial_number, sdk_info.serial_number,
                    sizeof(info->serial_number) - 1);
            info->available = true;
            info->is_simulator = false;
            info->supports_kem = true;
            info->supports_sign = true;
            info->supports_random = true;
            info->supports_batch = true;
            return 0;
        }
    }
#endif

    /* Simulator info */
    strncpy(info->name, "QUAC 100 Simulator", sizeof(info->name) - 1);
    strncpy(info->firmware_version, "1.0.0-sim", sizeof(info->firmware_version) - 1);
    strncpy(info->hardware_version, "N/A", sizeof(info->hardware_version) - 1);
    strncpy(info->serial_number, "SIM-00000000", sizeof(info->serial_number) - 1);
    info->available = true;
    info->is_simulator = true;
    info->supports_kem = true;
    info->supports_sign = true;
    info->supports_random = true;
    info->supports_batch = true;

    return 0;
}

cli_device_t *cli_open_device(cli_context_t *ctx, int index)
{
    if (!ctx)
        return NULL;

    cli_device_t *dev = calloc(1, sizeof(cli_device_t));
    if (!dev)
        return NULL;

#ifdef HAVE_QUAC_SDK
    if (ctx->sdk_handle)
    {
        if (quac_open_device(ctx->sdk_handle, index, &dev->handle) == QUAC_SUCCESS)
        {
            cli_get_device_info(ctx, index, &dev->info);
            dev->is_simulator = false;
            return dev;
        }
    }
#endif

    /* Fall back to simulator */
    dev->handle = NULL;
    dev->is_simulator = true;
    cli_get_device_info(ctx, 0, &dev->info);

    return dev;
}

cli_device_t *cli_open_simulator(cli_context_t *ctx)
{
    if (!ctx)
        return NULL;

    cli_device_t *dev = calloc(1, sizeof(cli_device_t));
    if (!dev)
        return NULL;

    dev->handle = NULL;
    dev->is_simulator = true;

    strncpy(dev->info.name, "QUAC 100 Simulator", sizeof(dev->info.name) - 1);
    strncpy(dev->info.firmware_version, "1.0.0-sim",
            sizeof(dev->info.firmware_version) - 1);
    strncpy(dev->info.serial_number, "SIM-00000000",
            sizeof(dev->info.serial_number) - 1);
    dev->info.index = 0;
    dev->info.available = true;
    dev->info.is_simulator = true;
    dev->info.supports_kem = true;
    dev->info.supports_sign = true;
    dev->info.supports_random = true;
    dev->info.supports_batch = true;

    return dev;
}

void cli_close_device(cli_device_t *dev)
{
    if (!dev)
        return;

#ifdef HAVE_QUAC_SDK
    if (dev->handle)
    {
        quac_close_device(dev->handle);
    }
#endif

    free(dev);
}

int cli_device_get_info(cli_device_t *dev, device_info_t *info)
{
    if (!dev || !info)
        return -1;
    memcpy(info, &dev->info, sizeof(device_info_t));
    return 0;
}

bool cli_device_is_simulator(cli_device_t *dev)
{
    return dev ? dev->is_simulator : true;
}

/*=============================================================================
 * Global Device Access
 *=============================================================================*/

cli_device_t *cli_get_current_device(void)
{
    if (g_device)
        return g_device;

    /* Initialize context if needed */
    if (!g_context)
    {
        g_context = cli_context_init();
        if (!g_context)
        {
            cli_error("Failed to initialize context");
            return NULL;
        }
    }

    /* Open device based on global options */
    if (g_options.use_simulator)
    {
        g_device = cli_open_simulator(g_context);
    }
    else
    {
        g_device = cli_open_device(g_context, g_options.device_index);
    }

    if (!g_device)
    {
        cli_error("Failed to open device %d", g_options.device_index);
        return NULL;
    }

    return g_device;
}

void cli_release_current_device(void)
{
    if (g_device)
    {
        cli_close_device(g_device);
        g_device = NULL;
    }

    if (g_context)
    {
        cli_context_cleanup(g_context);
        g_context = NULL;
    }
}

/*=============================================================================
 * Device Commands
 *=============================================================================*/

int cmd_list(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    cli_context_t *ctx = cli_context_init();
    if (!ctx)
    {
        cli_error("Failed to initialize context");
        return CLI_ERR_GENERAL;
    }

    int count = cli_get_device_count(ctx);

    if (g_options.json_output)
    {
        printf("{\n");
        printf("  \"devices\": [\n");

        for (int i = 0; i < count; i++)
        {
            device_info_t info;
            cli_get_device_info(ctx, i, &info);

            printf("    {\n");
            printf("      \"index\": %d,\n", i);
            printf("      \"name\": \"%s\",\n", info.name);
            printf("      \"firmware\": \"%s\",\n", info.firmware_version);
            printf("      \"serial\": \"%s\",\n", info.serial_number);
            printf("      \"available\": %s,\n", info.available ? "true" : "false");
            printf("      \"simulator\": %s\n", info.is_simulator ? "true" : "false");
            printf("    }%s\n", (i < count - 1) ? "," : "");
        }

        printf("  ]\n");
        printf("}\n");
    }
    else
    {
        if (!g_options.quiet)
        {
            printf("Available QUAC Devices:\n");
            printf("=======================\n\n");
        }

        if (count == 0)
        {
            printf("No devices found.\n");
            printf("Use -s/--simulator to use the software simulator.\n");
        }
        else
        {
            printf("  Index  Name                    Firmware    Serial          Status\n");
            printf("  -----  ----------------------  ----------  --------------  --------\n");

            for (int i = 0; i < count; i++)
            {
                device_info_t info;
                cli_get_device_info(ctx, i, &info);

                printf("  %-5d  %-22s  %-10s  %-14s  %s\n",
                       i, info.name, info.firmware_version,
                       info.serial_number,
                       info.available ? "Ready" : "In Use");
            }
        }
    }

    cli_context_cleanup(ctx);
    return CLI_OK;
}

int cmd_info(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    cli_device_t *dev = cli_get_current_device();
    if (!dev)
    {
        return CLI_ERR_DEVICE;
    }

    device_info_t info;
    cli_device_get_info(dev, &info);

    if (g_options.json_output)
    {
        printf("{\n");
        printf("  \"device\": {\n");
        printf("    \"index\": %d,\n", info.index);
        printf("    \"name\": \"%s\",\n", info.name);
        printf("    \"firmware\": \"%s\",\n", info.firmware_version);
        printf("    \"hardware\": \"%s\",\n", info.hardware_version);
        printf("    \"serial\": \"%s\",\n", info.serial_number);
        printf("    \"simulator\": %s,\n", info.is_simulator ? "true" : "false");
        printf("    \"capabilities\": {\n");
        printf("      \"kem\": %s,\n", info.supports_kem ? "true" : "false");
        printf("      \"sign\": %s,\n", info.supports_sign ? "true" : "false");
        printf("      \"random\": %s,\n", info.supports_random ? "true" : "false");
        printf("      \"batch\": %s\n", info.supports_batch ? "true" : "false");
        printf("    }\n");
        printf("  }\n");
        printf("}\n");
    }
    else
    {
        printf("Device Information\n");
        printf("==================\n\n");
        printf("  Name:         %s\n", info.name);
        printf("  Index:        %d\n", info.index);
        printf("  Firmware:     %s\n", info.firmware_version);
        printf("  Hardware:     %s\n", info.hardware_version);
        printf("  Serial:       %s\n", info.serial_number);
        printf("  Type:         %s\n", info.is_simulator ? "Simulator" : "Hardware");
        printf("\n");
        printf("Capabilities:\n");
        printf("  KEM:          %s\n", info.supports_kem ? "Yes" : "No");
        printf("  Signatures:   %s\n", info.supports_sign ? "Yes" : "No");
        printf("  Random:       %s\n", info.supports_random ? "Yes" : "No");
        printf("  Batch:        %s\n", info.supports_batch ? "Yes" : "No");
    }

    return CLI_OK;
}