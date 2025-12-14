// SPDX-License-Identifier: GPL-2.0-only
/*
 * QuantaCore QUAC 100 Post-Quantum Cryptographic Accelerator
 * Linux Kernel Driver - PCIe Operations
 *
 * Copyright (C) 2025 Dyber, Inc. All Rights Reserved.
 */

#include <linux/pci.h>
#include <linux/dma-mapping.h>
#include <linux/delay.h>

#include "quac100_drv.h"

/*=============================================================================
 * PCIe Initialization
 *=============================================================================*/

int quac100_pcie_init(struct quac100_device *qdev)
{
    struct pci_dev *pdev = qdev->pdev;
    int ret;

    /* Enable PCI device */
    ret = pci_enable_device(pdev);
    if (ret)
    {
        dev_err(&pdev->dev, "Failed to enable PCI device: %d\n", ret);
        return ret;
    }

    /* Request regions */
    ret = pci_request_regions(pdev, QUAC100_DRIVER_NAME);
    if (ret)
    {
        dev_err(&pdev->dev, "Failed to request regions: %d\n", ret);
        goto err_disable;
    }

    /* Set DMA mask */
    ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));
    if (ret)
    {
        ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));
        if (ret)
        {
            dev_err(&pdev->dev, "Failed to set DMA mask: %d\n", ret);
            goto err_regions;
        }
        dev_warn(&pdev->dev, "Using 32-bit DMA\n");
    }

    /* Enable bus mastering */
    pci_set_master(pdev);

    /* Map BAR0 (control registers) */
    qdev->bar0_len = pci_resource_len(pdev, QUAC100_BAR_REGS);
    if (qdev->bar0_len < QUAC100_BAR0_SIZE)
    {
        dev_warn(&pdev->dev, "BAR0 smaller than expected: %llu < %u\n",
                 (unsigned long long)qdev->bar0_len, QUAC100_BAR0_SIZE);
    }

    qdev->bar0 = pci_iomap(pdev, QUAC100_BAR_REGS, qdev->bar0_len);
    if (!qdev->bar0)
    {
        dev_err(&pdev->dev, "Failed to map BAR0\n");
        ret = -ENOMEM;
        goto err_master;
    }

    /* Map BAR2 (MSI-X table) if available */
    qdev->bar2_len = pci_resource_len(pdev, QUAC100_BAR_MSIX);
    if (qdev->bar2_len > 0)
    {
        qdev->bar2 = pci_iomap(pdev, QUAC100_BAR_MSIX, qdev->bar2_len);
        if (!qdev->bar2)
            dev_warn(&pdev->dev, "Failed to map BAR2 (MSI-X)\n");
    }

    /* Map BAR4 (SRAM) if available */
    qdev->bar4_len = pci_resource_len(pdev, QUAC100_BAR_SRAM);
    if (qdev->bar4_len > 0)
    {
        qdev->bar4 = pci_iomap(pdev, QUAC100_BAR_SRAM, qdev->bar4_len);
        if (!qdev->bar4)
            dev_warn(&pdev->dev, "Failed to map BAR4 (SRAM)\n");
    }

    /* Verify device is accessible */
    {
        u32 id = quac100_read32(qdev, QUAC100_REG_DEVICE_ID);
        if (id == 0xFFFFFFFF)
        {
            dev_err(&pdev->dev, "Device not responding\n");
            ret = -EIO;
            goto err_bar0;
        }
        quac100_info(qdev, "Device ID: 0x%08x\n", id);
    }

    /* Test scratch register */
    quac100_write32(qdev, QUAC100_REG_SCRATCH, 0xDEADBEEF);
    {
        u32 scratch = quac100_read32(qdev, QUAC100_REG_SCRATCH);
        if (scratch != 0xDEADBEEF)
        {
            dev_warn(&pdev->dev, "Scratch test failed: 0x%08x\n", scratch);
        }
    }

    quac100_info(qdev, "PCIe initialized: BAR0=%pR\n",
                 &pdev->resource[QUAC100_BAR_REGS]);
    return 0;

err_bar0:
    if (qdev->bar4)
        pci_iounmap(pdev, qdev->bar4);
    if (qdev->bar2)
        pci_iounmap(pdev, qdev->bar2);
    pci_iounmap(pdev, qdev->bar0);
err_master:
    pci_clear_master(pdev);
err_regions:
    pci_release_regions(pdev);
err_disable:
    pci_disable_device(pdev);
    return ret;
}

void quac100_pcie_cleanup(struct quac100_device *qdev)
{
    struct pci_dev *pdev = qdev->pdev;

    if (qdev->bar4)
    {
        pci_iounmap(pdev, qdev->bar4);
        qdev->bar4 = NULL;
    }

    if (qdev->bar2)
    {
        pci_iounmap(pdev, qdev->bar2);
        qdev->bar2 = NULL;
    }

    if (qdev->bar0)
    {
        pci_iounmap(pdev, qdev->bar0);
        qdev->bar0 = NULL;
    }

    pci_clear_master(pdev);
    pci_release_regions(pdev);
    pci_disable_device(pdev);
}

int quac100_pcie_enable_device(struct quac100_device *qdev)
{
    struct pci_dev *pdev = qdev->pdev;
    u16 cmd;
    int ret;

    /* Restore PCI config if needed */
    ret = pci_enable_device(pdev);
    if (ret)
    {
        quac100_err(qdev, "Failed to enable PCI device: %d\n", ret);
        return ret;
    }

    /* Enable memory and bus master */
    pci_read_config_word(pdev, PCI_COMMAND, &cmd);
    cmd |= PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER;
    pci_write_config_word(pdev, PCI_COMMAND, cmd);

    /* Re-establish DMA mask */
    ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));
    if (ret)
    {
        ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));
        if (ret)
        {
            quac100_err(qdev, "Failed to set DMA mask: %d\n", ret);
            return ret;
        }
    }

    pci_set_master(pdev);

    return 0;
}

void quac100_pcie_disable_device(struct quac100_device *qdev)
{
    pci_clear_master(qdev->pdev);
}

/*=============================================================================
 * PCIe Link Status
 *=============================================================================*/

int quac100_pcie_get_link_info(struct quac100_device *qdev,
                               u8 *gen, u8 *width, u32 *speed_mbps)
{
    struct pci_dev *pdev = qdev->pdev;
    u16 linkstat;
    int ret;

    ret = pcie_capability_read_word(pdev, PCI_EXP_LNKSTA, &linkstat);
    if (ret)
        return ret;

    if (gen)
        *gen = (linkstat & PCI_EXP_LNKSTA_CLS);

    if (width)
        *width = (linkstat & PCI_EXP_LNKSTA_NLW) >> PCI_EXP_LNKSTA_NLW_SHIFT;

    if (speed_mbps)
    {
        u8 current_gen = linkstat & PCI_EXP_LNKSTA_CLS;
        u8 current_width = (linkstat & PCI_EXP_LNKSTA_NLW) >>
                           PCI_EXP_LNKSTA_NLW_SHIFT;

        /* Calculate speed based on generation */
        u32 lane_speed;
        switch (current_gen)
        {
        case 1:
            lane_speed = 250;
            break; /* Gen1: 2.5 GT/s */
        case 2:
            lane_speed = 500;
            break; /* Gen2: 5 GT/s */
        case 3:
            lane_speed = 985;
            break; /* Gen3: 8 GT/s */
        case 4:
            lane_speed = 1969;
            break; /* Gen4: 16 GT/s */
        case 5:
            lane_speed = 3938;
            break; /* Gen5: 32 GT/s */
        default:
            lane_speed = 0;
        }
        *speed_mbps = lane_speed * current_width;
    }

    return 0;
}

/*=============================================================================
 * PCIe Error Handling
 *=============================================================================*/

void quac100_pcie_check_errors(struct quac100_device *qdev)
{
    struct pci_dev *pdev = qdev->pdev;
    u16 status;

    pci_read_config_word(pdev, PCI_STATUS, &status);

    if (status & (PCI_STATUS_DETECTED_PARITY |
                  PCI_STATUS_SIG_SYSTEM_ERROR |
                  PCI_STATUS_REC_MASTER_ABORT |
                  PCI_STATUS_REC_TARGET_ABORT |
                  PCI_STATUS_SIG_TARGET_ABORT |
                  PCI_STATUS_PARITY))
    {
        quac100_err(qdev, "PCI status error: 0x%04x\n", status);

        /* Clear error bits */
        pci_write_config_word(pdev, PCI_STATUS, status);
    }
}