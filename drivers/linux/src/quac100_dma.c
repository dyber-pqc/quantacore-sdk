// SPDX-License-Identifier: GPL-2.0-only
/*
 * QuantaCore QUAC 100 Post-Quantum Cryptographic Accelerator
 * Linux Kernel Driver - DMA Engine
 *
 * Copyright (C) 2025 Dyber, Inc. All Rights Reserved.
 */

#include <linux/dmapool.h>
#include <linux/delay.h>
#include <linux/completion.h>

#include "quac100_drv.h"

/*=============================================================================
 * DMA Channel Register Access
 *=============================================================================*/

static inline void __iomem *quac100_dma_ch_reg(struct quac100_device *qdev,
                                               u32 channel, u32 offset)
{
    return qdev->bar0 + QUAC100_REG_DMA_CH_BASE +
           (channel * QUAC100_REG_DMA_CH_STRIDE) + offset;
}

static inline u32 quac100_dma_read(struct quac100_device *qdev,
                                   u32 channel, u32 offset)
{
    return ioread32(quac100_dma_ch_reg(qdev, channel, offset));
}

static inline void quac100_dma_write(struct quac100_device *qdev,
                                     u32 channel, u32 offset, u32 value)
{
    iowrite32(value, quac100_dma_ch_reg(qdev, channel, offset));
}

/*=============================================================================
 * DMA Ring Management
 *=============================================================================*/

static int quac100_dma_ring_alloc(struct quac100_device *qdev,
                                  struct quac100_dma_ring *ring,
                                  u32 size)
{
    size_t desc_bytes;

    /* Ensure power of 2 and within limits */
    size = roundup_pow_of_two(size);
    if (size > QUAC100_MAX_DMA_RING_SIZE)
        size = QUAC100_MAX_DMA_RING_SIZE;

    desc_bytes = size * sizeof(struct quac100_dma_desc);

    /* Allocate descriptor ring */
    ring->descs = dma_alloc_coherent(&qdev->pdev->dev, desc_bytes,
                                     &ring->descs_dma, GFP_KERNEL);
    if (!ring->descs)
        return -ENOMEM;

    memset(ring->descs, 0, desc_bytes);

    ring->ring_size = size;
    ring->head = 0;
    ring->tail = 0;
    spin_lock_init(&ring->lock);
    init_completion(&ring->completion);

    quac100_dbg(qdev, "DMA ring allocated: size=%u descs=%p dma=%pad\n",
                size, ring->descs, &ring->descs_dma);

    return 0;
}

static void quac100_dma_ring_free(struct quac100_device *qdev,
                                  struct quac100_dma_ring *ring)
{
    if (ring->descs)
    {
        size_t desc_bytes = ring->ring_size * sizeof(struct quac100_dma_desc);
        dma_free_coherent(&qdev->pdev->dev, desc_bytes,
                          ring->descs, ring->descs_dma);
        ring->descs = NULL;
    }
}

/*=============================================================================
 * DMA Channel Initialization
 *=============================================================================*/

static int quac100_dma_channel_init(struct quac100_device *qdev, u32 channel)
{
    struct quac100_dma_channel *ch = &qdev->dma_channels[channel];
    int ret;

    ch->qdev = qdev;
    ch->channel_id = channel;
    ch->regs = quac100_dma_ch_reg(qdev, channel, 0);

    /* TX channels (0, 1) are to device, RX channels (2, 3) are from device */
    ch->direction = (channel < 2) ? DMA_TO_DEVICE : DMA_FROM_DEVICE;

    /* Allocate descriptor ring */
    ret = quac100_dma_ring_alloc(qdev, &ch->ring, dma_ring_size);
    if (ret)
    {
        quac100_err(qdev, "Failed to allocate DMA ring for channel %u: %d\n",
                    channel, ret);
        return ret;
    }

    /* Reset channel */
    quac100_dma_write(qdev, channel, QUAC100_REG_DMA_CH_CTRL,
                      QUAC100_DMA_CH_RESET);
    udelay(10);

    /* Configure descriptor ring */
    quac100_dma_write(qdev, channel, QUAC100_REG_DMA_CH_DESC_LO,
                      lower_32_bits(ch->ring.descs_dma));
    quac100_dma_write(qdev, channel, QUAC100_REG_DMA_CH_DESC_HI,
                      upper_32_bits(ch->ring.descs_dma));
    quac100_dma_write(qdev, channel, QUAC100_REG_DMA_CH_SIZE,
                      ch->ring.ring_size);

    /* Clear head/tail pointers */
    quac100_dma_write(qdev, channel, QUAC100_REG_DMA_CH_HEAD, 0);
    quac100_dma_write(qdev, channel, QUAC100_REG_DMA_CH_TAIL, 0);

    ch->bytes_transferred = 0;
    ch->transfers_completed = 0;
    ch->errors = 0;
    ch->enabled = false;

    quac100_dbg(qdev, "DMA channel %u initialized\n", channel);
    return 0;
}

static void quac100_dma_channel_cleanup(struct quac100_device *qdev, u32 channel)
{
    struct quac100_dma_channel *ch = &qdev->dma_channels[channel];

    quac100_dma_channel_stop(qdev, channel);
    quac100_dma_ring_free(qdev, &ch->ring);
}

/*=============================================================================
 * DMA Initialization
 *=============================================================================*/

int quac100_dma_init(struct quac100_device *qdev)
{
    int ret, i;

    /* Create DMA descriptor pool */
    qdev->desc_pool = dma_pool_create("quac100_desc", &qdev->pdev->dev,
                                      sizeof(struct quac100_dma_desc),
                                      QUAC100_DMA_DESC_ALIGNMENT, 0);
    if (!qdev->desc_pool)
    {
        quac100_err(qdev, "Failed to create DMA descriptor pool\n");
        return -ENOMEM;
    }

    /* Initialize each DMA channel */
    for (i = 0; i < QUAC100_DMA_CHANNELS; i++)
    {
        ret = quac100_dma_channel_init(qdev, i);
        if (ret)
            goto err_cleanup;
    }

    /* Enable global DMA */
    quac100_write32(qdev, QUAC100_REG_DMA_CONTROL, QUAC100_DEVCTL_DMA_ENABLE);

    quac100_info(qdev, "DMA engine initialized with %d channels\n",
                 QUAC100_DMA_CHANNELS);
    return 0;

err_cleanup:
    while (--i >= 0)
        quac100_dma_channel_cleanup(qdev, i);
    dma_pool_destroy(qdev->desc_pool);
    qdev->desc_pool = NULL;
    return ret;
}

void quac100_dma_cleanup(struct quac100_device *qdev)
{
    int i;

    /* Disable global DMA */
    quac100_write32(qdev, QUAC100_REG_DMA_CONTROL, 0);

    /* Cleanup each channel */
    for (i = 0; i < QUAC100_DMA_CHANNELS; i++)
        quac100_dma_channel_cleanup(qdev, i);

    /* Destroy descriptor pool */
    if (qdev->desc_pool)
    {
        dma_pool_destroy(qdev->desc_pool);
        qdev->desc_pool = NULL;
    }
}

/*=============================================================================
 * DMA Channel Control
 *=============================================================================*/

int quac100_dma_channel_start(struct quac100_device *qdev, u32 channel)
{
    struct quac100_dma_channel *ch;
    u32 ctrl;

    if (channel >= QUAC100_DMA_CHANNELS)
        return -EINVAL;

    ch = &qdev->dma_channels[channel];

    if (ch->enabled)
        return 0;

    /* Enable channel with interrupts */
    ctrl = QUAC100_DMA_CH_ENABLE | QUAC100_DMA_CH_IRQ_ENABLE;
    quac100_dma_write(qdev, channel, QUAC100_REG_DMA_CH_CTRL, ctrl);

    ch->enabled = true;
    quac100_dbg(qdev, "DMA channel %u started\n", channel);

    return 0;
}

void quac100_dma_channel_stop(struct quac100_device *qdev, u32 channel)
{
    struct quac100_dma_channel *ch;

    if (channel >= QUAC100_DMA_CHANNELS)
        return;

    ch = &qdev->dma_channels[channel];

    if (!ch->enabled)
        return;

    /* Stop and reset channel */
    quac100_dma_write(qdev, channel, QUAC100_REG_DMA_CH_CTRL,
                      QUAC100_DMA_CH_STOP);
    udelay(10);
    quac100_dma_write(qdev, channel, QUAC100_REG_DMA_CH_CTRL,
                      QUAC100_DMA_CH_RESET);

    ch->enabled = false;
    quac100_dbg(qdev, "DMA channel %u stopped\n", channel);
}

/*=============================================================================
 * DMA Transfer Operations
 *=============================================================================*/

static inline u32 quac100_dma_ring_space(struct quac100_dma_ring *ring)
{
    u32 head = ring->head;
    u32 tail = ring->tail;

    if (head >= tail)
        return ring->ring_size - head + tail - 1;
    return tail - head - 1;
}

int quac100_dma_submit(struct quac100_device *qdev, u32 channel,
                       dma_addr_t addr, size_t len, u32 flags)
{
    struct quac100_dma_channel *ch;
    struct quac100_dma_ring *ring;
    struct quac100_dma_desc *desc;
    unsigned long irqflags;
    u32 next_head;

    if (channel >= QUAC100_DMA_CHANNELS)
        return -EINVAL;

    if (len > QUAC100_DMA_MAX_XFER_SIZE)
        return -EINVAL;

    ch = &qdev->dma_channels[channel];
    ring = &ch->ring;

    spin_lock_irqsave(&ring->lock, irqflags);

    /* Check for space */
    if (quac100_dma_ring_space(ring) == 0)
    {
        spin_unlock_irqrestore(&ring->lock, irqflags);
        return -EBUSY;
    }

    /* Get next descriptor */
    desc = &ring->descs[ring->head];

    /* Fill descriptor */
    desc->buffer_addr = cpu_to_le64(addr);
    desc->length = cpu_to_le32(len);
    desc->flags = cpu_to_le16(QUAC100_DESC_FLAG_SOP | QUAC100_DESC_FLAG_EOP |
                              QUAC100_DESC_FLAG_IRQ);
    desc->tag = cpu_to_le16(ring->head);
    desc->status = 0;
    desc->bytes_xfer = 0;

    /* Memory barrier before updating head */
    wmb();

    /* Update head pointer */
    next_head = (ring->head + 1) & (ring->ring_size - 1);
    ring->head = next_head;

    /* Ring doorbell to notify hardware */
    quac100_dma_write(qdev, channel, QUAC100_REG_DMA_CH_HEAD, next_head);

    spin_unlock_irqrestore(&ring->lock, irqflags);

    quac100_trace(qdev, "DMA submit: ch=%u addr=%pad len=%zu head=%u\n",
                  channel, &addr, len, next_head);

    return 0;
}

int quac100_dma_wait(struct quac100_device *qdev, u32 channel, u32 timeout_ms)
{
    struct quac100_dma_channel *ch;
    struct quac100_dma_ring *ring;
    unsigned long ret;

    if (channel >= QUAC100_DMA_CHANNELS)
        return -EINVAL;

    ch = &qdev->dma_channels[channel];
    ring = &ch->ring;

    ret = wait_for_completion_timeout(&ring->completion,
                                      msecs_to_jiffies(timeout_ms));
    if (ret == 0)
        return -ETIMEDOUT;

    return 0;
}

/*=============================================================================
 * DMA Completion Processing
 *=============================================================================*/

void quac100_dma_process_completions(struct quac100_device *qdev, u32 channel)
{
    struct quac100_dma_channel *ch;
    struct quac100_dma_ring *ring;
    struct quac100_dma_desc *desc;
    unsigned long flags;
    u32 hw_tail, completed = 0;

    if (channel >= QUAC100_DMA_CHANNELS)
        return;

    ch = &qdev->dma_channels[channel];
    ring = &ch->ring;

    /* Read hardware tail pointer */
    hw_tail = quac100_dma_read(qdev, channel, QUAC100_REG_DMA_CH_TAIL);

    spin_lock_irqsave(&ring->lock, flags);

    /* Process completed descriptors */
    while (ring->tail != hw_tail)
    {
        desc = &ring->descs[ring->tail];

        /* Memory barrier before reading descriptor */
        rmb();

        /* Check for completion */
        if (le16_to_cpu(desc->flags) & QUAC100_DESC_FLAG_COMPLETE)
        {
            u32 bytes = le32_to_cpu(desc->bytes_xfer);

            ch->transfers_completed++;
            ch->bytes_transferred += bytes;

            /* Check for errors */
            if (le16_to_cpu(desc->flags) & QUAC100_DESC_FLAG_ERROR)
            {
                ch->errors++;
                quac100_err(qdev, "DMA error on channel %u, desc %u\n",
                            channel, ring->tail);
            }

            completed++;
        }

        /* Advance tail */
        ring->tail = (ring->tail + 1) & (ring->ring_size - 1);
    }

    spin_unlock_irqrestore(&ring->lock, flags);

    /* Signal completion if any descriptors were processed */
    if (completed > 0)
    {
        complete(&ring->completion);
        quac100_trace(qdev, "DMA ch %u: %u completions\n", channel, completed);
    }
}

/*=============================================================================
 * DMA Buffer Allocation (for userspace)
 *=============================================================================*/

void *quac100_dma_alloc_coherent(struct quac100_device *qdev,
                                 size_t size, dma_addr_t *dma_addr)
{
    return dma_alloc_coherent(&qdev->pdev->dev, size, dma_addr, GFP_KERNEL);
}

void quac100_dma_free_coherent(struct quac100_device *qdev,
                               size_t size, void *vaddr, dma_addr_t dma_addr)
{
    dma_free_coherent(&qdev->pdev->dev, size, vaddr, dma_addr);
}