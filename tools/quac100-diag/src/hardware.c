/**
 * @file hardware.c
 * @brief QUAC 100 Diagnostics - Hardware Interface Implementation
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hardware.h"

/*=============================================================================
 * Device Listing
 *=============================================================================*/

void hw_list_devices(void)
{
    printf("Available QUAC Devices:\n");
    printf("=======================\n\n");

    /* In a real implementation, this would scan for PCIe devices */
    printf("  Index  Name                    Serial          Status\n");
    printf("  -----  ----------------------  --------------  --------\n");

    /* Simulated device list */
    printf("  0      QUAC 100 Simulator      SIM-00000000    Available\n");

    printf("\nNote: Real hardware detection requires SDK and drivers.\n");
    printf("Use -s to use the software simulator.\n");
}

/*=============================================================================
 * Hardware Access
 *=============================================================================*/

int hw_open(int index, void **handle)
{
    (void)index;

    /* In a real implementation, this would open the PCIe device */
    /* For now, always fail to force simulator mode */
    *handle = NULL;
    return -1;
}

void hw_close(void *handle)
{
    (void)handle;
    /* Would close the device handle */
}

int hw_get_info(diag_context_t *ctx, hw_info_t *info)
{
    if (!ctx || !info)
        return -1;

    /* Fill with simulated values */
    memset(info, 0, sizeof(*info));

    if (diag_is_simulator(ctx))
    {
        strncpy(info->name, "QUAC 100 Simulator", sizeof(info->name) - 1);
        strncpy(info->serial, "SIM-00000000", sizeof(info->serial) - 1);
        strncpy(info->firmware, "1.0.0-sim", sizeof(info->firmware) - 1);
        strncpy(info->hardware, "N/A", sizeof(info->hardware) - 1);
        info->temperature = 35;
        info->pcie_gen = 4;
        info->pcie_lanes = 4;
        info->memory_size = 4ULL * 1024 * 1024 * 1024; /* 4GB */
        info->core_clock_mhz = 1000;
        info->ntt_clock_mhz = 500;
    }
    else
    {
        strncpy(info->name, "QUAC 100 PCIe", sizeof(info->name) - 1);
        strncpy(info->serial, "QC100-2025-00001", sizeof(info->serial) - 1);
        strncpy(info->firmware, "1.2.3", sizeof(info->firmware) - 1);
        strncpy(info->hardware, "RevB", sizeof(info->hardware) - 1);
        info->temperature = 42;
        info->pcie_gen = 4;
        info->pcie_lanes = 4;
        info->memory_size = 4ULL * 1024 * 1024 * 1024;
        info->core_clock_mhz = 1000;
        info->ntt_clock_mhz = 500;
    }

    return 0;
}

int hw_reg_read(void *handle, uint32_t offset, uint32_t *value)
{
    (void)handle;
    (void)offset;

    /* Simulated register read */
    *value = 0xDEADBEEF;
    return 0;
}

int hw_reg_write(void *handle, uint32_t offset, uint32_t value)
{
    (void)handle;
    (void)offset;
    (void)value;

    /* Simulated register write */
    return 0;
}

int hw_dma_transfer(void *handle, const void *src, void *dst, size_t size)
{
    (void)handle;

    /* Simulated DMA - just memcpy */
    if (src && dst && size > 0)
    {
        memcpy(dst, src, size);
    }
    return 0;
}

int hw_get_temperature(void *handle)
{
    (void)handle;

    /* Simulated temperature reading */
    return 35 + (rand() % 10);
}

int hw_get_pcie_info(void *handle, int *gen, int *lanes)
{
    (void)handle;

    /* Simulated PCIe info */
    if (gen)
        *gen = 4;
    if (lanes)
        *lanes = 4;
    return 0;
}