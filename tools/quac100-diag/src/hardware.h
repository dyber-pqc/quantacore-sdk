/**
 * @file hardware.h
 * @brief QUAC 100 Diagnostics - Hardware Interface
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC_DIAG_HARDWARE_H
#define QUAC_DIAG_HARDWARE_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "diag.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /*=============================================================================
     * Hardware Information
     *=============================================================================*/

#define MAX_HW_NAME 64
#define MAX_HW_SERIAL 32
#define MAX_HW_VERSION 16

    typedef struct
    {
        char name[MAX_HW_NAME];
        char serial[MAX_HW_SERIAL];
        char firmware[MAX_HW_VERSION];
        char hardware[MAX_HW_VERSION];

        int temperature;
        int pcie_gen;
        int pcie_lanes;

        uint64_t memory_size;
        uint32_t core_clock_mhz;
        uint32_t ntt_clock_mhz;
    } hw_info_t;

    /*=============================================================================
     * Hardware Access
     *=============================================================================*/

    /**
     * @brief List available devices
     */
    void hw_list_devices(void);

    /**
     * @brief Open hardware device
     * @param index Device index
     * @param handle Output handle
     * @return 0 on success
     */
    int hw_open(int index, void **handle);

    /**
     * @brief Close hardware device
     */
    void hw_close(void *handle);

    /**
     * @brief Get hardware info from context
     */
    int hw_get_info(diag_context_t *ctx, hw_info_t *info);

    /**
     * @brief Read register
     */
    int hw_reg_read(void *handle, uint32_t offset, uint32_t *value);

    /**
     * @brief Write register
     */
    int hw_reg_write(void *handle, uint32_t offset, uint32_t value);

    /**
     * @brief DMA transfer
     */
    int hw_dma_transfer(void *handle, const void *src, void *dst, size_t size);

    /**
     * @brief Get temperature
     */
    int hw_get_temperature(void *handle);

    /**
     * @brief Get PCIe link info
     */
    int hw_get_pcie_info(void *handle, int *gen, int *lanes);

#ifdef __cplusplus
}
#endif

#endif /* QUAC_DIAG_HARDWARE_H */