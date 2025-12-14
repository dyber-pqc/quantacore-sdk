// SPDX-License-Identifier: GPL-2.0-only
/*
 * QuantaCore QUAC 100 Post-Quantum Cryptographic Accelerator
 * Linux Kernel Driver - Interrupt Handling
 *
 * Copyright (C) 2025 Dyber, Inc. All Rights Reserved.
 */

#include <linux/interrupt.h>
#include <linux/pci.h>

#include "quac100_drv.h"

/*=============================================================================
 * Interrupt Handler
 *=============================================================================*/

static irqreturn_t quac100_irq_handler(int irq, void *dev_id)
{
    struct quac100_device *qdev = dev_id;
    u32 status;
    irqreturn_t ret = IRQ_NONE;

    /* Read interrupt status */
    status = quac100_read32(qdev, QUAC100_REG_INT_STATUS);
    if (!status)
        return IRQ_NONE;

    /* Acknowledge interrupts */
    quac100_write32(qdev, QUAC100_REG_INT_STATUS, status);

    quac100_trace(qdev, "IRQ: status=0x%08x\n", status);

    /* Handle DMA completions */
    if (status & QUAC100_INT_DMA_TX0_DONE)
    {
        quac100_dma_process_completions(qdev, 0);
        ret = IRQ_HANDLED;
    }

    if (status & QUAC100_INT_DMA_TX1_DONE)
    {
        quac100_dma_process_completions(qdev, 1);
        ret = IRQ_HANDLED;
    }

    if (status & QUAC100_INT_DMA_RX0_DONE)
    {
        quac100_dma_process_completions(qdev, 2);
        ret = IRQ_HANDLED;
    }

    if (status & QUAC100_INT_DMA_RX1_DONE)
    {
        quac100_dma_process_completions(qdev, 3);
        ret = IRQ_HANDLED;
    }

    /* Handle DMA errors */
    if (status & QUAC100_INT_DMA_ERROR)
    {
        quac100_err(qdev, "DMA error interrupt\n");
        atomic64_inc(&qdev->stats.errors);
        ret = IRQ_HANDLED;
    }

    /* Handle crypto completion */
    if (status & QUAC100_INT_CRYPTO_DONE)
    {
        quac100_trace(qdev, "Crypto operation complete\n");
        ret = IRQ_HANDLED;
    }

    /* Handle crypto errors */
    if (status & QUAC100_INT_CRYPTO_ERROR)
    {
        quac100_err(qdev, "Crypto error interrupt\n");
        atomic64_inc(&qdev->stats.errors);
        ret = IRQ_HANDLED;
    }

    /* Handle entropy low warning */
    if (status & QUAC100_INT_ENTROPY_LOW)
    {
        quac100_warn(qdev, "Entropy pool low\n");
        ret = IRQ_HANDLED;
    }

    /* Handle temperature alert */
    if (status & QUAC100_INT_TEMP_ALERT)
    {
        s32 temp = quac100_read32(qdev, QUAC100_REG_TEMP_CORE);
        quac100_warn(qdev, "Temperature alert: %d C\n", temp);
        ret = IRQ_HANDLED;
    }

    /* Handle general error */
    if (status & QUAC100_INT_ERROR)
    {
        quac100_err(qdev, "General error interrupt\n");
        atomic64_inc(&qdev->stats.errors);
        ret = IRQ_HANDLED;
    }

    /* Handle fatal error */
    if (status & QUAC100_INT_FATAL)
    {
        quac100_err(qdev, "Fatal error interrupt - device needs reset\n");
        atomic64_inc(&qdev->stats.errors);
        /* TODO: Schedule recovery work */
        ret = IRQ_HANDLED;
    }

    return ret;
}

/*=============================================================================
 * MSI-X Handler (per-vector)
 *=============================================================================*/

static irqreturn_t quac100_msix_handler(int irq, void *dev_id)
{
    struct quac100_device *qdev = dev_id;
    int vector;

    /* Find which vector this is */
    for (vector = 0; vector < qdev->num_vectors; vector++)
    {
        if (qdev->irqs[vector] == irq)
            break;
    }

    if (vector >= qdev->num_vectors)
    {
        quac100_err(qdev, "Unknown MSI-X vector IRQ %d\n", irq);
        return IRQ_NONE;
    }

    quac100_trace(qdev, "MSI-X vector %d triggered\n", vector);

    /* Route based on vector assignment */
    switch (vector)
    {
    case 0:
        /* General interrupts */
        return quac100_irq_handler(irq, qdev);

    case 1:
        /* DMA TX0 */
        quac100_dma_process_completions(qdev, 0);
        return IRQ_HANDLED;

    case 2:
        /* DMA TX1 */
        quac100_dma_process_completions(qdev, 1);
        return IRQ_HANDLED;

    case 3:
        /* DMA RX0 */
        quac100_dma_process_completions(qdev, 2);
        return IRQ_HANDLED;

    case 4:
        /* DMA RX1 */
        quac100_dma_process_completions(qdev, 3);
        return IRQ_HANDLED;

    default:
        /* Additional vectors for crypto engines, etc. */
        return quac100_irq_handler(irq, qdev);
    }
}

/*=============================================================================
 * MSI-X Setup
 *=============================================================================*/

static int quac100_setup_msix(struct quac100_device *qdev)
{
    int i, ret, num_vectors;

    /* Determine number of vectors to request */
    num_vectors = min_t(int, msix_vectors, QUAC100_MAX_MSIX_VECTORS);

    /* Allocate MSI-X entries */
    qdev->msix_entries = kcalloc(num_vectors, sizeof(struct msix_entry),
                                 GFP_KERNEL);
    if (!qdev->msix_entries)
        return -ENOMEM;

    for (i = 0; i < num_vectors; i++)
        qdev->msix_entries[i].entry = i;

    /* Enable MSI-X */
    ret = pci_enable_msix_range(qdev->pdev, qdev->msix_entries,
                                1, num_vectors);
    if (ret < 0)
    {
        quac100_warn(qdev, "Failed to enable MSI-X: %d\n", ret);
        kfree(qdev->msix_entries);
        qdev->msix_entries = NULL;
        return ret;
    }

    qdev->num_vectors = ret;
    quac100_info(qdev, "MSI-X enabled with %d vectors\n", qdev->num_vectors);

    /* Request IRQs for each vector */
    for (i = 0; i < qdev->num_vectors; i++)
    {
        qdev->irqs[i] = qdev->msix_entries[i].vector;

        ret = request_irq(qdev->irqs[i], quac100_msix_handler,
                          0, qdev->name, qdev);
        if (ret)
        {
            quac100_err(qdev, "Failed to request MSI-X IRQ %d: %d\n",
                        qdev->irqs[i], ret);
            goto err_free_irqs;
        }
    }

    return 0;

err_free_irqs:
    while (--i >= 0)
        free_irq(qdev->irqs[i], qdev);
    pci_disable_msix(qdev->pdev);
    kfree(qdev->msix_entries);
    qdev->msix_entries = NULL;
    qdev->num_vectors = 0;
    return ret;
}

static void quac100_teardown_msix(struct quac100_device *qdev)
{
    int i;

    if (!qdev->msix_entries)
        return;

    for (i = 0; i < qdev->num_vectors; i++)
    {
        if (qdev->irqs[i])
            free_irq(qdev->irqs[i], qdev);
    }

    pci_disable_msix(qdev->pdev);
    kfree(qdev->msix_entries);
    qdev->msix_entries = NULL;
    qdev->num_vectors = 0;
}

/*=============================================================================
 * Legacy INTx Fallback
 *=============================================================================*/

static int quac100_setup_intx(struct quac100_device *qdev)
{
    int ret;

    ret = request_irq(qdev->pdev->irq, quac100_irq_handler,
                      IRQF_SHARED, qdev->name, qdev);
    if (ret)
    {
        quac100_err(qdev, "Failed to request legacy IRQ %d: %d\n",
                    qdev->pdev->irq, ret);
        return ret;
    }

    qdev->irqs[0] = qdev->pdev->irq;
    qdev->num_vectors = 1;

    quac100_info(qdev, "Using legacy INTx IRQ %d\n", qdev->pdev->irq);
    return 0;
}

static void quac100_teardown_intx(struct quac100_device *qdev)
{
    if (qdev->irqs[0])
    {
        free_irq(qdev->irqs[0], qdev);
        qdev->irqs[0] = 0;
    }
    qdev->num_vectors = 0;
}

/*=============================================================================
 * IRQ Initialization
 *=============================================================================*/

int quac100_irq_init(struct quac100_device *qdev)
{
    int ret;

    /* Try MSI-X first */
    ret = quac100_setup_msix(qdev);
    if (ret == 0)
        return 0;

    /* Fall back to legacy INTx */
    quac100_warn(qdev, "MSI-X unavailable, falling back to INTx\n");
    ret = quac100_setup_intx(qdev);
    if (ret)
        return ret;

    return 0;
}

void quac100_irq_cleanup(struct quac100_device *qdev)
{
    /* Disable interrupts first */
    quac100_irq_disable(qdev);

    if (qdev->msix_entries)
        quac100_teardown_msix(qdev);
    else
        quac100_teardown_intx(qdev);
}

/*=============================================================================
 * IRQ Enable/Disable
 *=============================================================================*/

void quac100_irq_enable(struct quac100_device *qdev)
{
    u32 mask;

    /* Enable all interrupt sources */
    mask = QUAC100_INT_DMA_ALL |
           QUAC100_INT_CRYPTO_DONE |
           QUAC100_INT_CRYPTO_ERROR |
           QUAC100_INT_ENTROPY_LOW |
           QUAC100_INT_TEMP_ALERT |
           QUAC100_INT_ERROR |
           QUAC100_INT_FATAL;

    quac100_write32(qdev, QUAC100_REG_INT_ENABLE, mask);
    quac100_write32(qdev, QUAC100_REG_INT_MASK, 0);

    quac100_dbg(qdev, "Interrupts enabled: mask=0x%08x\n", mask);
}

void quac100_irq_disable(struct quac100_device *qdev)
{
    /* Disable all interrupts */
    quac100_write32(qdev, QUAC100_REG_INT_ENABLE, 0);
    quac100_write32(qdev, QUAC100_REG_INT_MASK, 0xFFFFFFFF);

    /* Clear any pending interrupts */
    quac100_write32(qdev, QUAC100_REG_INT_STATUS, 0xFFFFFFFF);

    quac100_dbg(qdev, "Interrupts disabled\n");
}