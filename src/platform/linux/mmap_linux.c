/**
 * @file mmap_linux.c
 * @brief QuantaCore SDK - Linux Memory-Mapped I/O Implementation
 *
 * Implements memory-mapped access to device registers, DMA buffer mapping,
 * and coherent memory management for the QUAC 100 accelerator.
 *
 * Memory Regions:
 * - BAR0: Control/Status Registers (16 MB)
 * - BAR2: DMA Buffer Space (256 MB)
 *
 * DMA Buffer Types:
 * - Coherent: Cache-coherent, no explicit sync needed
 * - Streaming: Higher performance, requires explicit sync
 * - User: User-space allocated, pinned for DMA
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <pthread.h>

#include "quac100.h"
#include "quac100_types.h"
#include "quac100_error.h"
#include "internal/quac100_dma.h"

/*=============================================================================
 * Constants
 *=============================================================================*/

/** BAR0 size (Control/Status Registers) */
#define QUAC_BAR0_SIZE (16 * 1024 * 1024)

/** BAR2 size (DMA Buffer Space) */
#define QUAC_BAR2_SIZE (256 * 1024 * 1024)

/** Maximum DMA allocations tracked */
#define QUAC_MAX_DMA_ALLOCS 256

/** Page size (typically 4KB) */
#define QUAC_PAGE_SIZE 4096

/** Huge page size (2MB) */
#define QUAC_HUGE_PAGE_SIZE (2 * 1024 * 1024)

/** DMA buffer alignment */
#define QUAC_DMA_ALIGNMENT 64

/** Mapping magic number */
#define QUAC_MMAP_MAGIC 0x4D4D4150 /* "MMAP" */

/*=============================================================================
 * Register Offsets
 *=============================================================================*/

/** Device identification */
#define QUAC_REG_DEVICE_ID 0x0000
#define QUAC_REG_VERSION 0x0004
#define QUAC_REG_CAPABILITIES 0x0008
#define QUAC_REG_STATUS 0x000C

/** Control registers */
#define QUAC_REG_CONTROL 0x0100
#define QUAC_REG_INTERRUPT_ENABLE 0x0104
#define QUAC_REG_INTERRUPT_STATUS 0x0108
#define QUAC_REG_INTERRUPT_CLEAR 0x010C

/** DMA engine registers */
#define QUAC_REG_DMA_CONTROL 0x0200
#define QUAC_REG_DMA_STATUS 0x0204
#define QUAC_REG_DMA_SRC_ADDR_LO 0x0208
#define QUAC_REG_DMA_SRC_ADDR_HI 0x020C
#define QUAC_REG_DMA_DST_ADDR_LO 0x0210
#define QUAC_REG_DMA_DST_ADDR_HI 0x0214
#define QUAC_REG_DMA_LENGTH 0x0218
#define QUAC_REG_DMA_NEXT_DESC_LO 0x021C
#define QUAC_REG_DMA_NEXT_DESC_HI 0x0220

/** Crypto engine registers */
#define QUAC_REG_CRYPTO_CONTROL 0x0400
#define QUAC_REG_CRYPTO_STATUS 0x0404
#define QUAC_REG_CRYPTO_ALGORITHM 0x0408
#define QUAC_REG_CRYPTO_KEY_SLOT 0x040C

/** QRNG registers */
#define QUAC_REG_QRNG_CONTROL 0x0800
#define QUAC_REG_QRNG_STATUS 0x0804
#define QUAC_REG_QRNG_ENTROPY 0x0808
#define QUAC_REG_QRNG_HEALTH 0x080C

/** Temperature and power */
#define QUAC_REG_TEMPERATURE 0x0C00
#define QUAC_REG_POWER 0x0C04

/*=============================================================================
 * DMA Sync Directions
 *=============================================================================*/

#define QUAC_DMA_TO_DEVICE 0
#define QUAC_DMA_FROM_DEVICE 1
#define QUAC_DMA_BIDIRECTIONAL 2

/*=============================================================================
 * Internal Structures
 *=============================================================================*/

/**
 * @brief Memory mapping descriptor
 */
typedef struct quac_mmap_s
{
    uint32_t magic;  /**< Magic number */
    int fd;          /**< File descriptor */
    void *base;      /**< Mapped base address */
    size_t size;     /**< Mapping size */
    uint64_t offset; /**< File offset */
    uint32_t flags;  /**< Mapping flags */
    bool valid;      /**< Is mapping valid */
} quac_mmap_t;

/**
 * @brief DMA buffer descriptor
 */
typedef struct quac_dma_buffer_s
{
    uint64_t handle;      /**< Unique handle */
    void *vaddr;          /**< Virtual address */
    uint64_t paddr;       /**< Physical/bus address */
    size_t size;          /**< Buffer size */
    uint32_t flags;       /**< Buffer flags */
    bool coherent;        /**< Is coherent mapping */
    bool user_buffer;     /**< User-provided buffer */
    uint64_t mmap_offset; /**< Offset for mmap */
    bool in_use;          /**< Is allocated */
} quac_dma_buffer_t;

/**
 * @brief Device memory mapping state
 */
typedef struct quac_mmap_state_s
{
    int fd; /**< Device file descriptor */

    /* BAR mappings */
    quac_mmap_t bar0; /**< BAR0 mapping (registers) */
    quac_mmap_t bar2; /**< BAR2 mapping (DMA) */

    /* DMA buffer tracking */
    quac_dma_buffer_t dma_buffers[QUAC_MAX_DMA_ALLOCS];
    pthread_mutex_t dma_lock;
    uint64_t next_handle;

    /* Statistics */
    uint64_t total_allocated;
    uint64_t total_freed;
    uint64_t current_allocated;
    uint64_t peak_allocated;

    bool initialized;
} quac_mmap_state_t;

/*=============================================================================
 * Internal Helpers
 *=============================================================================*/

/**
 * @brief Round up to page boundary
 */
static size_t page_align(size_t size)
{
    return (size + QUAC_PAGE_SIZE - 1) & ~(QUAC_PAGE_SIZE - 1);
}

/**
 * @brief Round up to DMA alignment
 */
static size_t dma_align(size_t size)
{
    return (size + QUAC_DMA_ALIGNMENT - 1) & ~(QUAC_DMA_ALIGNMENT - 1);
}

/**
 * @brief Find free DMA buffer slot
 */
static int find_free_dma_slot(quac_mmap_state_t *state)
{
    for (int i = 0; i < QUAC_MAX_DMA_ALLOCS; i++)
    {
        if (!state->dma_buffers[i].in_use)
        {
            return i;
        }
    }
    return -1;
}

/**
 * @brief Find DMA buffer by handle
 */
static quac_dma_buffer_t *find_dma_buffer(quac_mmap_state_t *state,
                                          uint64_t handle)
{
    for (int i = 0; i < QUAC_MAX_DMA_ALLOCS; i++)
    {
        if (state->dma_buffers[i].in_use &&
            state->dma_buffers[i].handle == handle)
        {
            return &state->dma_buffers[i];
        }
    }
    return NULL;
}

/**
 * @brief Memory barrier
 */
static inline void memory_barrier(void)
{
    __sync_synchronize();
}

/**
 * @brief Read memory barrier
 */
static inline void read_barrier(void)
{
    __asm__ __volatile__("" ::: "memory");
}

/**
 * @brief Write memory barrier
 */
static inline void write_barrier(void)
{
    __asm__ __volatile__("" ::: "memory");
}

/*=============================================================================
 * BAR Mapping
 *=============================================================================*/

/**
 * @brief Map a BAR region
 */
static quac_result_t map_bar(int fd, quac_mmap_t *map,
                             uint64_t offset, size_t size)
{
    if (fd < 0 || !map)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    /* Unmap if already mapped */
    if (map->valid && map->base)
    {
        munmap(map->base, map->size);
        map->valid = false;
    }

    /* Map the BAR */
    void *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
                     MAP_SHARED, fd, offset);

    if (ptr == MAP_FAILED)
    {
        return QUAC_ERROR_OUT_OF_MEMORY;
    }

    map->magic = QUAC_MMAP_MAGIC;
    map->fd = fd;
    map->base = ptr;
    map->size = size;
    map->offset = offset;
    map->valid = true;

    return QUAC_SUCCESS;
}

/**
 * @brief Unmap a BAR region
 */
static void unmap_bar(quac_mmap_t *map)
{
    if (map && map->valid && map->base)
    {
        munmap(map->base, map->size);
        map->valid = false;
        map->base = NULL;
    }
}

/*=============================================================================
 * Register Access
 *=============================================================================*/

/**
 * @brief Read 32-bit register
 */
static inline uint32_t reg_read32(volatile void *base, uint32_t offset)
{
    read_barrier();
    uint32_t value = *(volatile uint32_t *)((uint8_t *)base + offset);
    read_barrier();
    return value;
}

/**
 * @brief Write 32-bit register
 */
static inline void reg_write32(volatile void *base, uint32_t offset,
                               uint32_t value)
{
    write_barrier();
    *(volatile uint32_t *)((uint8_t *)base + offset) = value;
    write_barrier();
}

/**
 * @brief Read 64-bit register
 */
static inline uint64_t reg_read64(volatile void *base, uint32_t offset)
{
    read_barrier();
    uint64_t value = *(volatile uint64_t *)((uint8_t *)base + offset);
    read_barrier();
    return value;
}

/**
 * @brief Write 64-bit register
 */
static inline void reg_write64(volatile void *base, uint32_t offset,
                               uint64_t value)
{
    write_barrier();
    *(volatile uint64_t *)((uint8_t *)base + offset) = value;
    write_barrier();
}

/*=============================================================================
 * Public API - Initialization
 *=============================================================================*/

/**
 * @brief Create memory mapping context
 */
quac_result_t quac_mmap_create(int fd, quac_mmap_state_t **state)
{
    if (fd < 0 || !state)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    quac_mmap_state_t *s = calloc(1, sizeof(quac_mmap_state_t));
    if (!s)
    {
        return QUAC_ERROR_OUT_OF_MEMORY;
    }

    s->fd = fd;
    pthread_mutex_init(&s->dma_lock, NULL);
    s->next_handle = 1;
    s->initialized = true;

    *state = s;
    return QUAC_SUCCESS;
}

/**
 * @brief Destroy memory mapping context
 */
void quac_mmap_destroy(quac_mmap_state_t *state)
{
    if (!state)
    {
        return;
    }

    /* Unmap BARs */
    unmap_bar(&state->bar0);
    unmap_bar(&state->bar2);

    /* Free all DMA buffers */
    pthread_mutex_lock(&state->dma_lock);

    for (int i = 0; i < QUAC_MAX_DMA_ALLOCS; i++)
    {
        quac_dma_buffer_t *buf = &state->dma_buffers[i];
        if (buf->in_use && buf->vaddr && !buf->user_buffer)
        {
            if (buf->coherent)
            {
                munmap(buf->vaddr, buf->size);
            }
            else
            {
                free(buf->vaddr);
            }
        }
    }

    pthread_mutex_unlock(&state->dma_lock);
    pthread_mutex_destroy(&state->dma_lock);

    free(state);
}

/**
 * @brief Map BAR0 (registers)
 */
quac_result_t quac_mmap_bar0(quac_mmap_state_t *state)
{
    if (!state || !state->initialized)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    return map_bar(state->fd, &state->bar0, 0, QUAC_BAR0_SIZE);
}

/**
 * @brief Map BAR2 (DMA space)
 */
quac_result_t quac_mmap_bar2(quac_mmap_state_t *state)
{
    if (!state || !state->initialized)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    /* BAR2 is at offset after BAR0 in mmap space */
    return map_bar(state->fd, &state->bar2, QUAC_BAR0_SIZE, QUAC_BAR2_SIZE);
}

/**
 * @brief Get BAR0 base address
 */
void *quac_mmap_get_bar0(quac_mmap_state_t *state)
{
    if (!state || !state->bar0.valid)
    {
        return NULL;
    }
    return state->bar0.base;
}

/**
 * @brief Get BAR2 base address
 */
void *quac_mmap_get_bar2(quac_mmap_state_t *state)
{
    if (!state || !state->bar2.valid)
    {
        return NULL;
    }
    return state->bar2.base;
}

/*=============================================================================
 * Public API - Register Access
 *=============================================================================*/

/**
 * @brief Read device register
 */
quac_result_t quac_mmap_reg_read(quac_mmap_state_t *state, uint32_t offset,
                                 uint32_t *value)
{
    if (!state || !state->bar0.valid || !value)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    if (offset >= state->bar0.size)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    *value = reg_read32(state->bar0.base, offset);
    return QUAC_SUCCESS;
}

/**
 * @brief Write device register
 */
quac_result_t quac_mmap_reg_write(quac_mmap_state_t *state, uint32_t offset,
                                  uint32_t value)
{
    if (!state || !state->bar0.valid)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    if (offset >= state->bar0.size)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    reg_write32(state->bar0.base, offset, value);
    return QUAC_SUCCESS;
}

/**
 * @brief Read 64-bit device register
 */
quac_result_t quac_mmap_reg_read64(quac_mmap_state_t *state, uint32_t offset,
                                   uint64_t *value)
{
    if (!state || !state->bar0.valid || !value)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    if (offset + 8 > state->bar0.size)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    *value = reg_read64(state->bar0.base, offset);
    return QUAC_SUCCESS;
}

/**
 * @brief Write 64-bit device register
 */
quac_result_t quac_mmap_reg_write64(quac_mmap_state_t *state, uint32_t offset,
                                    uint64_t value)
{
    if (!state || !state->bar0.valid)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    if (offset + 8 > state->bar0.size)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    reg_write64(state->bar0.base, offset, value);
    return QUAC_SUCCESS;
}

/**
 * @brief Bulk read registers
 */
quac_result_t quac_mmap_reg_read_bulk(quac_mmap_state_t *state,
                                      uint32_t offset,
                                      uint32_t *values,
                                      size_t count)
{
    if (!state || !state->bar0.valid || !values)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    if (offset + (count * 4) > state->bar0.size)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    volatile uint32_t *src = (volatile uint32_t *)((uint8_t *)state->bar0.base + offset);

    read_barrier();
    for (size_t i = 0; i < count; i++)
    {
        values[i] = src[i];
    }
    read_barrier();

    return QUAC_SUCCESS;
}

/**
 * @brief Bulk write registers
 */
quac_result_t quac_mmap_reg_write_bulk(quac_mmap_state_t *state,
                                       uint32_t offset,
                                       const uint32_t *values,
                                       size_t count)
{
    if (!state || !state->bar0.valid || !values)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    if (offset + (count * 4) > state->bar0.size)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    volatile uint32_t *dst = (volatile uint32_t *)((uint8_t *)state->bar0.base + offset);

    write_barrier();
    for (size_t i = 0; i < count; i++)
    {
        dst[i] = values[i];
    }
    write_barrier();

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Public API - DMA Buffer Management
 *=============================================================================*/

/**
 * @brief Allocate DMA buffer
 */
quac_result_t quac_mmap_dma_alloc(quac_mmap_state_t *state,
                                  size_t size,
                                  uint32_t flags,
                                  quac_dma_buffer_info_t *info)
{
    if (!state || !state->initialized || size == 0 || !info)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    /* Align size */
    size_t aligned_size = page_align(size);

    pthread_mutex_lock(&state->dma_lock);

    /* Find free slot */
    int slot = find_free_dma_slot(state);
    if (slot < 0)
    {
        pthread_mutex_unlock(&state->dma_lock);
        return QUAC_ERROR_OUT_OF_MEMORY;
    }

    quac_dma_buffer_t *buf = &state->dma_buffers[slot];
    memset(buf, 0, sizeof(*buf));

    /* Allocate memory */
    void *ptr = NULL;
    bool coherent = (flags & QUAC_DMA_FLAG_COHERENT) != 0;

    if (coherent)
    {
        /* Use mmap for coherent memory (if driver supports it) */
        /* Fall back to posix_memalign with mlock */
        if (posix_memalign(&ptr, QUAC_PAGE_SIZE, aligned_size) != 0)
        {
            pthread_mutex_unlock(&state->dma_lock);
            return QUAC_ERROR_OUT_OF_MEMORY;
        }

        /* Lock pages in memory */
        if (mlock(ptr, aligned_size) != 0)
        {
            free(ptr);
            pthread_mutex_unlock(&state->dma_lock);
            return QUAC_ERROR_OUT_OF_MEMORY;
        }

        /* Zero the buffer */
        memset(ptr, 0, aligned_size);
    }
    else
    {
        /* Regular aligned allocation */
        if (posix_memalign(&ptr, QUAC_DMA_ALIGNMENT, aligned_size) != 0)
        {
            pthread_mutex_unlock(&state->dma_lock);
            return QUAC_ERROR_OUT_OF_MEMORY;
        }
    }

    /* Fill buffer info */
    buf->handle = state->next_handle++;
    buf->vaddr = ptr;
    buf->paddr = 0; /* Would be set by driver after pinning */
    buf->size = aligned_size;
    buf->flags = flags;
    buf->coherent = coherent;
    buf->user_buffer = false;
    buf->in_use = true;

    /* Update statistics */
    state->total_allocated += aligned_size;
    state->current_allocated += aligned_size;
    if (state->current_allocated > state->peak_allocated)
    {
        state->peak_allocated = state->current_allocated;
    }

    pthread_mutex_unlock(&state->dma_lock);

    /* Return info to caller */
    memset(info, 0, sizeof(*info));
    info->struct_size = sizeof(*info);
    info->handle = buf->handle;
    info->vaddr = buf->vaddr;
    info->paddr = buf->paddr;
    info->size = buf->size;
    info->flags = buf->flags;

    return QUAC_SUCCESS;
}

/**
 * @brief Free DMA buffer
 */
quac_result_t quac_mmap_dma_free(quac_mmap_state_t *state, uint64_t handle)
{
    if (!state || !state->initialized)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    pthread_mutex_lock(&state->dma_lock);

    quac_dma_buffer_t *buf = find_dma_buffer(state, handle);
    if (!buf)
    {
        pthread_mutex_unlock(&state->dma_lock);
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    /* Free memory */
    if (buf->vaddr && !buf->user_buffer)
    {
        if (buf->coherent)
        {
            munlock(buf->vaddr, buf->size);
        }
        free(buf->vaddr);
    }

    /* Update statistics */
    state->total_freed += buf->size;
    state->current_allocated -= buf->size;

    /* Clear slot */
    memset(buf, 0, sizeof(*buf));

    pthread_mutex_unlock(&state->dma_lock);

    return QUAC_SUCCESS;
}

/**
 * @brief Get DMA buffer info
 */
quac_result_t quac_mmap_dma_get_info(quac_mmap_state_t *state,
                                     uint64_t handle,
                                     quac_dma_buffer_info_t *info)
{
    if (!state || !state->initialized || !info)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    pthread_mutex_lock(&state->dma_lock);

    quac_dma_buffer_t *buf = find_dma_buffer(state, handle);
    if (!buf)
    {
        pthread_mutex_unlock(&state->dma_lock);
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    memset(info, 0, sizeof(*info));
    info->struct_size = sizeof(*info);
    info->handle = buf->handle;
    info->vaddr = buf->vaddr;
    info->paddr = buf->paddr;
    info->size = buf->size;
    info->flags = buf->flags;

    pthread_mutex_unlock(&state->dma_lock);

    return QUAC_SUCCESS;
}

/**
 * @brief Sync DMA buffer for device access
 */
quac_result_t quac_mmap_dma_sync_for_device(quac_mmap_state_t *state,
                                            uint64_t handle,
                                            uint64_t offset,
                                            size_t size)
{
    if (!state || !state->initialized)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    pthread_mutex_lock(&state->dma_lock);

    quac_dma_buffer_t *buf = find_dma_buffer(state, handle);
    if (!buf)
    {
        pthread_mutex_unlock(&state->dma_lock);
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    if (offset + size > buf->size)
    {
        pthread_mutex_unlock(&state->dma_lock);
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    pthread_mutex_unlock(&state->dma_lock);

    /* Coherent buffers don't need sync */
    if (buf->coherent)
    {
        return QUAC_SUCCESS;
    }

    /* Flush CPU caches */
    /* On x86, this is typically handled by the DMA API in kernel */
    /* For user-space, we ensure memory ordering */
    memory_barrier();

    /* Could use clflush for specific cache line flush on x86 */
    /* __builtin___clear_cache((char*)buf->vaddr + offset,
     *                        (char*)buf->vaddr + offset + size);
     */

    return QUAC_SUCCESS;
}

/**
 * @brief Sync DMA buffer for CPU access
 */
quac_result_t quac_mmap_dma_sync_for_cpu(quac_mmap_state_t *state,
                                         uint64_t handle,
                                         uint64_t offset,
                                         size_t size)
{
    if (!state || !state->initialized)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    pthread_mutex_lock(&state->dma_lock);

    quac_dma_buffer_t *buf = find_dma_buffer(state, handle);
    if (!buf)
    {
        pthread_mutex_unlock(&state->dma_lock);
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    if (offset + size > buf->size)
    {
        pthread_mutex_unlock(&state->dma_lock);
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    pthread_mutex_unlock(&state->dma_lock);

    /* Coherent buffers don't need sync */
    if (buf->coherent)
    {
        return QUAC_SUCCESS;
    }

    /* Invalidate CPU caches */
    memory_barrier();

    return QUAC_SUCCESS;
}

/**
 * @brief Map user buffer for DMA
 */
quac_result_t quac_mmap_dma_map_user(quac_mmap_state_t *state,
                                     void *user_buffer,
                                     size_t size,
                                     uint32_t direction,
                                     quac_dma_buffer_info_t *info)
{
    if (!state || !state->initialized || !user_buffer || size == 0 || !info)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    pthread_mutex_lock(&state->dma_lock);

    int slot = find_free_dma_slot(state);
    if (slot < 0)
    {
        pthread_mutex_unlock(&state->dma_lock);
        return QUAC_ERROR_OUT_OF_MEMORY;
    }

    quac_dma_buffer_t *buf = &state->dma_buffers[slot];
    memset(buf, 0, sizeof(*buf));

    /* Lock user pages */
    if (mlock(user_buffer, size) != 0)
    {
        pthread_mutex_unlock(&state->dma_lock);
        return QUAC_ERROR_OUT_OF_MEMORY;
    }

    buf->handle = state->next_handle++;
    buf->vaddr = user_buffer;
    buf->paddr = 0; /* Would be set by driver */
    buf->size = size;
    buf->flags = direction;
    buf->coherent = false;
    buf->user_buffer = true;
    buf->in_use = true;

    pthread_mutex_unlock(&state->dma_lock);

    memset(info, 0, sizeof(*info));
    info->struct_size = sizeof(*info);
    info->handle = buf->handle;
    info->vaddr = buf->vaddr;
    info->paddr = buf->paddr;
    info->size = buf->size;
    info->flags = buf->flags;

    return QUAC_SUCCESS;
}

/**
 * @brief Unmap user buffer from DMA
 */
quac_result_t quac_mmap_dma_unmap_user(quac_mmap_state_t *state,
                                       uint64_t handle)
{
    if (!state || !state->initialized)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    pthread_mutex_lock(&state->dma_lock);

    quac_dma_buffer_t *buf = find_dma_buffer(state, handle);
    if (!buf || !buf->user_buffer)
    {
        pthread_mutex_unlock(&state->dma_lock);
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    /* Unlock pages */
    if (buf->vaddr)
    {
        munlock(buf->vaddr, buf->size);
    }

    /* Clear slot (don't free user buffer) */
    memset(buf, 0, sizeof(*buf));

    pthread_mutex_unlock(&state->dma_lock);

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Public API - Statistics
 *=============================================================================*/

/**
 * @brief Get DMA statistics
 */
quac_result_t quac_mmap_get_stats(quac_mmap_state_t *state,
                                  quac_dma_stats_t *stats)
{
    if (!state || !state->initialized || !stats)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    pthread_mutex_lock(&state->dma_lock);

    memset(stats, 0, sizeof(*stats));
    stats->struct_size = sizeof(*stats);
    stats->total_allocated = state->total_allocated;
    stats->total_freed = state->total_freed;
    stats->current_allocated = state->current_allocated;
    stats->peak_allocated = state->peak_allocated;

    /* Count active buffers */
    for (int i = 0; i < QUAC_MAX_DMA_ALLOCS; i++)
    {
        if (state->dma_buffers[i].in_use)
        {
            stats->active_buffers++;
        }
    }

    stats->max_buffers = QUAC_MAX_DMA_ALLOCS;

    pthread_mutex_unlock(&state->dma_lock);

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Convenience Register Access Functions
 *=============================================================================*/

/**
 * @brief Read device ID register
 */
quac_result_t quac_mmap_read_device_id(quac_mmap_state_t *state,
                                       uint32_t *device_id)
{
    return quac_mmap_reg_read(state, QUAC_REG_DEVICE_ID, device_id);
}

/**
 * @brief Read device version register
 */
quac_result_t quac_mmap_read_version(quac_mmap_state_t *state,
                                     uint32_t *version)
{
    return quac_mmap_reg_read(state, QUAC_REG_VERSION, version);
}

/**
 * @brief Read device status register
 */
quac_result_t quac_mmap_read_status(quac_mmap_state_t *state,
                                    uint32_t *status)
{
    return quac_mmap_reg_read(state, QUAC_REG_STATUS, status);
}

/**
 * @brief Write control register
 */
quac_result_t quac_mmap_write_control(quac_mmap_state_t *state,
                                      uint32_t control)
{
    return quac_mmap_reg_write(state, QUAC_REG_CONTROL, control);
}

/**
 * @brief Enable interrupts
 */
quac_result_t quac_mmap_enable_interrupts(quac_mmap_state_t *state,
                                          uint32_t mask)
{
    return quac_mmap_reg_write(state, QUAC_REG_INTERRUPT_ENABLE, mask);
}

/**
 * @brief Disable interrupts
 */
quac_result_t quac_mmap_disable_interrupts(quac_mmap_state_t *state)
{
    return quac_mmap_reg_write(state, QUAC_REG_INTERRUPT_ENABLE, 0);
}

/**
 * @brief Read interrupt status
 */
quac_result_t quac_mmap_read_interrupt_status(quac_mmap_state_t *state,
                                              uint32_t *status)
{
    return quac_mmap_reg_read(state, QUAC_REG_INTERRUPT_STATUS, status);
}

/**
 * @brief Clear interrupts
 */
quac_result_t quac_mmap_clear_interrupts(quac_mmap_state_t *state,
                                         uint32_t mask)
{
    return quac_mmap_reg_write(state, QUAC_REG_INTERRUPT_CLEAR, mask);
}

/**
 * @brief Read temperature
 */
quac_result_t quac_mmap_read_temperature(quac_mmap_state_t *state,
                                         int32_t *celsius)
{
    uint32_t raw;
    quac_result_t result = quac_mmap_reg_read(state, QUAC_REG_TEMPERATURE, &raw);
    if (result == QUAC_SUCCESS && celsius)
    {
        /* Convert raw value to Celsius (implementation-specific) */
        *celsius = (int32_t)raw; /* May need scaling */
    }
    return result;
}

/**
 * @brief Read power consumption
 */
quac_result_t quac_mmap_read_power(quac_mmap_state_t *state,
                                   uint32_t *milliwatts)
{
    return quac_mmap_reg_read(state, QUAC_REG_POWER, milliwatts);
}

/**
 * @brief Read entropy available
 */
quac_result_t quac_mmap_read_entropy(quac_mmap_state_t *state,
                                     uint32_t *bits_available)
{
    return quac_mmap_reg_read(state, QUAC_REG_QRNG_ENTROPY, bits_available);
}
