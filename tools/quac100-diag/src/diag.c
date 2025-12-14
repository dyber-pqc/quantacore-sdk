/**
 * @file diag.c
 * @brief QUAC 100 Diagnostics - Core Implementation
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "diag.h"
#include "hardware.h"

/*=============================================================================
 * Internal Structures
 *=============================================================================*/

struct diag_context
{
    diag_options_t options;
    void *device_handle;
    bool is_simulator;
    hw_info_t hw_info;
};

/*=============================================================================
 * Context Management
 *=============================================================================*/

diag_context_t *diag_init(const diag_options_t *options)
{
    if (!options)
        return NULL;

    diag_context_t *ctx = calloc(1, sizeof(diag_context_t));
    if (!ctx)
        return NULL;

    memcpy(&ctx->options, options, sizeof(diag_options_t));

    /* Initialize hardware */
    if (options->use_simulator)
    {
        ctx->is_simulator = true;
        ctx->device_handle = NULL;

        /* Fill in simulated info */
        strncpy(ctx->hw_info.name, "QUAC 100 Simulator",
                sizeof(ctx->hw_info.name) - 1);
        strncpy(ctx->hw_info.serial, "SIM-00000000",
                sizeof(ctx->hw_info.serial) - 1);
        strncpy(ctx->hw_info.firmware, "1.0.0-sim",
                sizeof(ctx->hw_info.firmware) - 1);
        ctx->hw_info.temperature = 35;
        ctx->hw_info.pcie_gen = 4;
        ctx->hw_info.pcie_lanes = 4;
    }
    else
    {
        ctx->is_simulator = false;

        /* Try to open real hardware */
        int result = hw_open(options->device_index, &ctx->device_handle);
        if (result != 0)
        {
            /* Fall back to simulator */
            if (options->verbose)
            {
                printf("Hardware not found, using simulator\n");
            }
            ctx->is_simulator = true;
            ctx->device_handle = NULL;

            strncpy(ctx->hw_info.name, "QUAC 100 Simulator",
                    sizeof(ctx->hw_info.name) - 1);
            strncpy(ctx->hw_info.serial, "SIM-00000000",
                    sizeof(ctx->hw_info.serial) - 1);
            strncpy(ctx->hw_info.firmware, "1.0.0-sim",
                    sizeof(ctx->hw_info.firmware) - 1);
            ctx->hw_info.temperature = 35;
            ctx->hw_info.pcie_gen = 4;
            ctx->hw_info.pcie_lanes = 4;
        }
        else
        {
            hw_get_info(ctx, &ctx->hw_info);
        }
    }

    return ctx;
}

void diag_cleanup(diag_context_t *ctx)
{
    if (!ctx)
        return;

    if (ctx->device_handle)
    {
        hw_close(ctx->device_handle);
    }

    free(ctx);
}

const diag_options_t *diag_get_options(diag_context_t *ctx)
{
    return ctx ? &ctx->options : NULL;
}

bool diag_is_simulator(diag_context_t *ctx)
{
    return ctx ? ctx->is_simulator : true;
}