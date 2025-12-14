/**
 * @file quac100_dma.h
 * @brief QuantaCore SDK - Internal DMA Engine Interface
 *
 * Low-level Direct Memory Access (DMA) engine interface for high-performance
 * data transfers between host memory and the QUAC 100 device. Provides
 * scatter-gather DMA, descriptor ring management, and zero-copy transfers.
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 * @doc QUAC100-SDK-DEV-001
 *
 * @internal
 * This header is for internal SDK use only. Applications should use the
 * public API which handles DMA transparently.
 *
 * @par DMA Architecture
 * The QUAC 100 implements a high-performance DMA engine with:
 * - 4 independent DMA channels (2 TX, 2 RX)
 * - Scatter-gather descriptor rings (up to 4096 descriptors per ring)
 * - 64-bit addressing for large memory support
 * - Hardware completion notifications via MSI-X interrupts
 * - AXI4 Stream interface to cryptographic engines
 *
 * @par Memory Model
 * - Coherent DMA: Cache-coherent memory for descriptors and small transfers
 * - Streaming DMA: Non-coherent memory with explicit sync for bulk transfers
 * - User-pinned: User buffers pinned and mapped for zero-copy transfers
 */

#ifndef QUAC100_DMA_H
#define QUAC100_DMA_H

#include "../quac100_types.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*=============================================================================
 * DMA Constants
 *=============================================================================*/

/** Number of DMA channels */
#define QUAC_DMA_CHANNEL_COUNT 4

/** TX channels (host to device) */
#define QUAC_DMA_CHANNEL_TX0 0
#define QUAC_DMA_CHANNEL_TX1 1

/** RX channels (device to host) */
#define QUAC_DMA_CHANNEL_RX0 2
#define QUAC_DMA_CHANNEL_RX1 3

/** Maximum descriptors per ring */
#define QUAC_DMA_MAX_DESCRIPTORS 4096

/** Default descriptor ring size */
#define QUAC_DMA_DEFAULT_RING_SIZE 256

/** Maximum scatter-gather entries per transfer */
#define QUAC_DMA_MAX_SG_ENTRIES 256

/** Maximum transfer size per descriptor (bytes) */
#define QUAC_DMA_MAX_XFER_SIZE (16 * 1024 * 1024) /* 16 MiB */

/** Minimum transfer alignment (bytes) */
#define QUAC_DMA_ALIGNMENT 64

/** Descriptor alignment (bytes) */
#define QUAC_DMA_DESC_ALIGNMENT 64

/** DMA timeout (milliseconds) */
#define QUAC_DMA_DEFAULT_TIMEOUT 5000

    /*=============================================================================
     * DMA Direction
     *=============================================================================*/

    /**
     * @brief DMA transfer direction
     */
    typedef enum quac_dma_direction_e
    {
        QUAC_DMA_TO_DEVICE = 0,     /**< Host to device (TX) */
        QUAC_DMA_FROM_DEVICE = 1,   /**< Device to host (RX) */
        QUAC_DMA_BIDIRECTIONAL = 2, /**< Both directions */
        QUAC_DMA_NONE = 3,          /**< No DMA (for sync only) */
    } quac_dma_direction_t;

    /*=============================================================================
     * DMA Buffer Management
     *=============================================================================*/

    /**
     * @brief DMA buffer type
     */
    typedef enum quac_dma_buf_type_e
    {
        QUAC_DMA_BUF_COHERENT = 0,  /**< Cache-coherent DMA memory */
        QUAC_DMA_BUF_STREAMING = 1, /**< Streaming DMA (requires sync) */
        QUAC_DMA_BUF_USER = 2,      /**< User-pinned memory */
    } quac_dma_buf_type_t;

    /**
     * @brief DMA buffer descriptor
     */
    typedef struct quac_dma_buffer_s
    {
        uint64_t handle;                /**< Buffer handle */
        quac_dma_buf_type_t type;       /**< Buffer type */
        quac_dma_direction_t direction; /**< DMA direction */

        /* Host memory */
        void *virt_addr;    /**< Virtual address */
        uint64_t phys_addr; /**< Physical/bus address */
        size_t size;        /**< Buffer size */

        /* DMA mapping */
        uint64_t dma_addr; /**< DMA address (IOMMU mapped) */
        bool mapped;       /**< Currently mapped */

        /* Scatter-gather (for user buffers) */
        uint32_t sg_count; /**< Number of SG entries */
        struct
        {
            uint64_t dma_addr;              /**< Segment DMA address */
            uint32_t length;                /**< Segment length */
        } sg_list[QUAC_DMA_MAX_SG_ENTRIES]; /**< Scatter-gather list */

        /* State */
        bool in_use;        /**< Currently in use by DMA */
        uint64_t user_data; /**< User context */
    } quac_dma_buffer_t;

    /**
     * @brief Allocate coherent DMA buffer
     *
     * Allocates cache-coherent DMA memory suitable for descriptors and
     * small transfers. No explicit sync required.
     *
     * @param[in]  device       Device handle
     * @param[in]  size         Buffer size (bytes)
     * @param[out] buffer       Pointer to receive buffer descriptor
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_OUT_OF_MEMORY on allocation failure
     */
    quac_result_t quac_dma_alloc_coherent(quac_device_t device,
                                          size_t size,
                                          quac_dma_buffer_t *buffer);

    /**
     * @brief Allocate streaming DMA buffer
     *
     * Allocates non-coherent DMA memory for bulk transfers.
     * Requires explicit sync before/after DMA operations.
     *
     * @param[in]  device       Device handle
     * @param[in]  size         Buffer size (bytes)
     * @param[in]  direction    DMA direction
     * @param[out] buffer       Pointer to receive buffer descriptor
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_dma_alloc_streaming(quac_device_t device,
                                           size_t size,
                                           quac_dma_direction_t direction,
                                           quac_dma_buffer_t *buffer);

    /**
     * @brief Free DMA buffer
     *
     * @param[in] device        Device handle
     * @param[in] buffer        Buffer to free
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_dma_free(quac_device_t device, quac_dma_buffer_t *buffer);

    /**
     * @brief Map user buffer for DMA
     *
     * Pins user memory pages and creates DMA mapping. Supports scatter-gather
     * for non-contiguous physical pages.
     *
     * @param[in]  device       Device handle
     * @param[in]  user_addr    User virtual address
     * @param[in]  size         Buffer size
     * @param[in]  direction    DMA direction
     * @param[out] buffer       Pointer to receive buffer descriptor
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_INVALID_PARAMETER if address not page-aligned
     */
    quac_result_t quac_dma_map_user(quac_device_t device,
                                    void *user_addr, size_t size,
                                    quac_dma_direction_t direction,
                                    quac_dma_buffer_t *buffer);

    /**
     * @brief Unmap user buffer
     *
     * @param[in] device        Device handle
     * @param[in] buffer        Buffer to unmap
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_dma_unmap_user(quac_device_t device,
                                      quac_dma_buffer_t *buffer);

    /*=============================================================================
     * DMA Synchronization
     *=============================================================================*/

    /**
     * @brief Sync direction for streaming DMA
     */
    typedef enum quac_dma_sync_e
    {
        QUAC_DMA_SYNC_FOR_DEVICE = 0, /**< Sync before device access */
        QUAC_DMA_SYNC_FOR_CPU = 1,    /**< Sync before CPU access */
    } quac_dma_sync_t;

    /**
     * @brief Synchronize DMA buffer
     *
     * Required for streaming DMA buffers:
     * - SYNC_FOR_DEVICE: Call before starting DMA (flushes CPU caches)
     * - SYNC_FOR_CPU: Call after DMA completes (invalidates CPU caches)
     *
     * @param[in] device        Device handle
     * @param[in] buffer        Buffer to sync
     * @param[in] offset        Offset in buffer
     * @param[in] size          Size to sync (0 = entire buffer)
     * @param[in] sync_type     Sync direction
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_dma_sync(quac_device_t device,
                                quac_dma_buffer_t *buffer,
                                size_t offset, size_t size,
                                quac_dma_sync_t sync_type);

/**
 * @brief Sync entire buffer for device
 */
#define quac_dma_sync_for_device(dev, buf) \
    quac_dma_sync((dev), (buf), 0, 0, QUAC_DMA_SYNC_FOR_DEVICE)

/**
 * @brief Sync entire buffer for CPU
 */
#define quac_dma_sync_for_cpu(dev, buf) \
    quac_dma_sync((dev), (buf), 0, 0, QUAC_DMA_SYNC_FOR_CPU)

    /*=============================================================================
     * DMA Descriptor Ring
     *=============================================================================*/

    /**
     * @brief DMA descriptor flags
     */
    typedef enum quac_dma_desc_flags_e
    {
        QUAC_DMA_DESC_FLAG_NONE = 0x0000,
        QUAC_DMA_DESC_FLAG_SOP = 0x0001,      /**< Start of packet */
        QUAC_DMA_DESC_FLAG_EOP = 0x0002,      /**< End of packet */
        QUAC_DMA_DESC_FLAG_IRQ = 0x0004,      /**< Generate interrupt on completion */
        QUAC_DMA_DESC_FLAG_CHAIN = 0x0008,    /**< Chain to next descriptor */
        QUAC_DMA_DESC_FLAG_ERROR = 0x0100,    /**< (Status) Error occurred */
        QUAC_DMA_DESC_FLAG_COMPLETE = 0x0200, /**< (Status) Transfer complete */
    } quac_dma_desc_flags_t;

    /**
     * @brief Hardware DMA descriptor (64 bytes, cache-line aligned)
     */
    typedef struct quac_dma_descriptor_s
    {
        /* Word 0-1: Buffer address */
        uint64_t buffer_addr; /**< Buffer physical/DMA address */

        /* Word 2: Control */
        uint32_t length; /**< Transfer length (bytes) */
        uint16_t flags;  /**< Descriptor flags */
        uint16_t tag;    /**< User tag (returned on completion) */

        /* Word 3: Next descriptor (for chained) */
        uint64_t next_desc; /**< Next descriptor address */

        /* Word 4-5: Metadata */
        uint32_t operation; /**< Operation type */
        uint32_t algorithm; /**< Algorithm ID */
        uint64_t user_data; /**< User context */

        /* Word 6-7: Status (written by hardware) */
        uint32_t status;     /**< Completion status */
        uint32_t bytes_xfer; /**< Actual bytes transferred */
        uint64_t timestamp;  /**< Completion timestamp */
    } __attribute__((aligned(64))) quac_dma_descriptor_t;

    /**
     * @brief Descriptor ring structure
     */
    typedef struct quac_dma_ring_s
    {
        uint32_t channel;               /**< DMA channel */
        quac_dma_direction_t direction; /**< Ring direction */

        /* Descriptor ring */
        quac_dma_descriptor_t *descriptors; /**< Descriptor array */
        uint64_t desc_dma_addr;             /**< Descriptors DMA address */
        uint32_t ring_size;                 /**< Number of descriptors */
        uint32_t desc_size;                 /**< Size of each descriptor */

        /* Ring pointers */
        volatile uint32_t head;    /**< Head index (software) */
        volatile uint32_t tail;    /**< Tail index (hardware) */
        volatile uint32_t pending; /**< Pending submissions */

        /* Completion tracking */
        uint64_t completions; /**< Total completions */
        uint64_t errors;      /**< Error count */

        /* Synchronization */
        void *lock;             /**< Ring lock */
        void *completion_event; /**< Completion event/semaphore */
    } quac_dma_ring_t;

    /**
     * @brief Create descriptor ring
     *
     * @param[in]  device       Device handle
     * @param[in]  channel      DMA channel
     * @param[in]  ring_size    Number of descriptors
     * @param[out] ring         Pointer to receive ring structure
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_dma_ring_create(quac_device_t device,
                                       uint32_t channel,
                                       uint32_t ring_size,
                                       quac_dma_ring_t **ring);

    /**
     * @brief Destroy descriptor ring
     *
     * @param[in] device        Device handle
     * @param[in] ring          Ring to destroy
     */
    void quac_dma_ring_destroy(quac_device_t device, quac_dma_ring_t *ring);

    /**
     * @brief Reset descriptor ring
     *
     * @param[in] device        Device handle
     * @param[in] ring          Ring to reset
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_dma_ring_reset(quac_device_t device, quac_dma_ring_t *ring);

    /**
     * @brief Get available ring slots
     *
     * @param[in] ring          Descriptor ring
     *
     * @return Number of available slots
     */
    uint32_t quac_dma_ring_available(const quac_dma_ring_t *ring);

/**
 * @brief Check if ring is full
 */
#define quac_dma_ring_full(ring) (quac_dma_ring_available(ring) == 0)

/**
 * @brief Check if ring is empty
 */
#define quac_dma_ring_empty(ring) ((ring)->pending == 0)

    /*=============================================================================
     * DMA Transfer Operations
     *=============================================================================*/

    /**
     * @brief DMA transfer request
     */
    typedef struct quac_dma_request_s
    {
        /* Source/destination */
        quac_dma_buffer_t *buffer; /**< DMA buffer */
        size_t offset;             /**< Offset in buffer */
        size_t length;             /**< Transfer length */

        /* Operation context */
        uint32_t operation; /**< Operation type */
        uint32_t algorithm; /**< Algorithm ID */
        uint16_t tag;       /**< User tag */
        uint64_t user_data; /**< User context */

        /* Flags */
        uint32_t flags;    /**< Transfer flags */
        bool generate_irq; /**< Generate completion IRQ */

        /* Completion */
        void (*callback)(struct quac_dma_request_s *req, quac_result_t result);
        void *callback_data; /**< Callback context */
    } quac_dma_request_t;

    /**
     * @brief Submit DMA transfer
     *
     * Submits a DMA transfer request to the specified ring.
     *
     * @param[in] device        Device handle
     * @param[in] ring          Descriptor ring
     * @param[in] request       Transfer request
     *
     * @return QUAC_SUCCESS on success
     * @return QUAC_ERROR_QUEUE_FULL if ring is full
     */
    quac_result_t quac_dma_submit(quac_device_t device,
                                  quac_dma_ring_t *ring,
                                  quac_dma_request_t *request);

    /**
     * @brief Submit scatter-gather DMA transfer
     *
     * @param[in] device        Device handle
     * @param[in] ring          Descriptor ring
     * @param[in] sg_list       Scatter-gather entries
     * @param[in] sg_count      Number of SG entries
     * @param[in] request       Transfer request (buffer field ignored)
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_dma_submit_sg(quac_device_t device,
                                     quac_dma_ring_t *ring,
                                     const quac_dma_buffer_t *sg_list,
                                     uint32_t sg_count,
                                     quac_dma_request_t *request);

    /**
     * @brief Ring doorbell to start transfers
     *
     * Notifies hardware that new descriptors are available.
     *
     * @param[in] device        Device handle
     * @param[in] ring          Descriptor ring
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_dma_ring_doorbell(quac_device_t device,
                                         quac_dma_ring_t *ring);

    /**
     * @brief Poll for DMA completions
     *
     * @param[in]  device       Device handle
     * @param[in]  ring         Descriptor ring
     * @param[out] completed    Number of completions processed
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_dma_poll(quac_device_t device,
                                quac_dma_ring_t *ring,
                                uint32_t *completed);

    /**
     * @brief Wait for DMA completion
     *
     * @param[in] device        Device handle
     * @param[in] ring          Descriptor ring
     * @param[in] tag           Tag to wait for (0 = any)
     * @param[in] timeout_ms    Timeout in milliseconds
     *
     * @return QUAC_SUCCESS on completion
     * @return QUAC_ERROR_TIMEOUT on timeout
     */
    quac_result_t quac_dma_wait(quac_device_t device,
                                quac_dma_ring_t *ring,
                                uint16_t tag,
                                uint32_t timeout_ms);

    /**
     * @brief Cancel pending DMA transfers
     *
     * @param[in] device        Device handle
     * @param[in] ring          Descriptor ring
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_dma_cancel(quac_device_t device, quac_dma_ring_t *ring);

    /*=============================================================================
     * Simple Transfer API
     *=============================================================================*/

    /**
     * @brief Synchronous DMA transfer to device
     *
     * Convenience function for simple host-to-device transfers.
     *
     * @param[in] device        Device handle
     * @param[in] src           Source buffer (host memory)
     * @param[in] dst_offset    Destination offset in device memory
     * @param[in] length        Transfer length
     * @param[in] timeout_ms    Timeout
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_dma_write(quac_device_t device,
                                 const void *src,
                                 uint64_t dst_offset,
                                 size_t length,
                                 uint32_t timeout_ms);

    /**
     * @brief Synchronous DMA transfer from device
     *
     * Convenience function for simple device-to-host transfers.
     *
     * @param[in]  device       Device handle
     * @param[in]  src_offset   Source offset in device memory
     * @param[out] dst          Destination buffer (host memory)
     * @param[in]  length       Transfer length
     * @param[in]  timeout_ms   Timeout
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_dma_read(quac_device_t device,
                                uint64_t src_offset,
                                void *dst,
                                size_t length,
                                uint32_t timeout_ms);

    /**
     * @brief Zero-copy transfer using user buffer
     *
     * @param[in] device        Device handle
     * @param[in] user_buf      User buffer
     * @param[in] size          Transfer size
     * @param[in] direction     Transfer direction
     * @param[in] timeout_ms    Timeout
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_dma_transfer_user(quac_device_t device,
                                         void *user_buf,
                                         size_t size,
                                         quac_dma_direction_t direction,
                                         uint32_t timeout_ms);

    /*=============================================================================
     * DMA Channel Management
     *=============================================================================*/

    /**
     * @brief DMA channel status
     */
    typedef struct quac_dma_channel_status_s
    {
        uint32_t channel;     /**< Channel number */
        bool enabled;         /**< Channel enabled */
        bool running;         /**< Transfers in progress */
        bool error;           /**< Error state */
        uint32_t pending;     /**< Pending descriptors */
        uint64_t bytes_xfer;  /**< Total bytes transferred */
        uint64_t completions; /**< Total completions */
        uint64_t errors;      /**< Total errors */
        uint32_t head;        /**< Current head pointer */
        uint32_t tail;        /**< Current tail pointer */
    } quac_dma_channel_status_t;

    /**
     * @brief Get DMA channel status
     *
     * @param[in]  device       Device handle
     * @param[in]  channel      Channel number
     * @param[out] status       Pointer to receive status
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_dma_get_channel_status(quac_device_t device,
                                              uint32_t channel,
                                              quac_dma_channel_status_t *status);

    /**
     * @brief Enable DMA channel
     *
     * @param[in] device        Device handle
     * @param[in] channel       Channel number
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_dma_channel_enable(quac_device_t device, uint32_t channel);

    /**
     * @brief Disable DMA channel
     *
     * @param[in] device        Device handle
     * @param[in] channel       Channel number
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_dma_channel_disable(quac_device_t device, uint32_t channel);

    /**
     * @brief Reset DMA channel
     *
     * @param[in] device        Device handle
     * @param[in] channel       Channel number
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_dma_channel_reset(quac_device_t device, uint32_t channel);

    /*=============================================================================
     * DMA Statistics
     *=============================================================================*/

    /**
     * @brief DMA statistics
     */
    typedef struct quac_dma_stats_s
    {
        uint32_t struct_size; /**< Size of this structure */

        /* Transfer statistics */
        uint64_t tx_bytes;     /**< Total TX bytes */
        uint64_t rx_bytes;     /**< Total RX bytes */
        uint64_t tx_transfers; /**< TX transfer count */
        uint64_t rx_transfers; /**< RX transfer count */

        /* Descriptor statistics */
        uint64_t descs_submitted; /**< Descriptors submitted */
        uint64_t descs_completed; /**< Descriptors completed */
        uint64_t descs_errors;    /**< Descriptor errors */

        /* Timing */
        uint64_t total_xfer_time_ns; /**< Total transfer time (ns) */
        uint32_t avg_xfer_time_us;   /**< Average transfer time (μs) */
        uint32_t max_xfer_time_us;   /**< Maximum transfer time (μs) */

        /* Throughput */
        uint64_t peak_throughput_bps; /**< Peak throughput (bytes/sec) */
        uint64_t avg_throughput_bps;  /**< Average throughput (bytes/sec) */

        /* Buffer statistics */
        uint32_t buffers_allocated; /**< DMA buffers allocated */
        uint64_t buffer_bytes;      /**< Total buffer memory */
        uint32_t user_mappings;     /**< Active user mappings */

        /* Error breakdown */
        uint64_t timeout_errors;  /**< Timeout errors */
        uint64_t underrun_errors; /**< Underrun errors */
        uint64_t overrun_errors;  /**< Overrun errors */
        uint64_t protocol_errors; /**< Protocol errors */
    } quac_dma_stats_t;

    /**
     * @brief Get DMA statistics
     *
     * @param[in]  device       Device handle
     * @param[out] stats        Pointer to receive statistics
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_dma_get_stats(quac_device_t device, quac_dma_stats_t *stats);

    /**
     * @brief Reset DMA statistics
     *
     * @param[in] device        Device handle
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_dma_reset_stats(quac_device_t device);

    /*=============================================================================
     * DMA Engine Initialization
     *=============================================================================*/

    /**
     * @brief Initialize DMA engine
     *
     * @param[in] device        Device handle
     *
     * @return QUAC_SUCCESS on success
     */
    quac_result_t quac_dma_init(quac_device_t device);

    /**
     * @brief Shutdown DMA engine
     *
     * @param[in] device        Device handle
     */
    void quac_dma_shutdown(quac_device_t device);

#ifdef __cplusplus
}
#endif

#endif /* QUAC100_DMA_H */
