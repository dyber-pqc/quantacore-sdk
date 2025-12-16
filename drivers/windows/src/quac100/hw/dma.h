/**
 * @file dma.h
 * @brief QUAC 100 DMA Engine Interface
 *
 * Direct Memory Access engine management for high-performance data transfers
 * between host memory and the cryptographic accelerator.
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_DMA_H
#define QUAC100_DMA_H

#include <ntddk.h>
#include <wdf.h>
#include "registers.h"

#ifdef __cplusplus
extern "C" {
#endif

/*=============================================================================
 * Forward Declarations
 *=============================================================================*/

struct _DEVICE_CONTEXT;
typedef struct _DEVICE_CONTEXT DEVICE_CONTEXT, *PDEVICE_CONTEXT;

/*=============================================================================
 * DMA Channel Definitions
 *=============================================================================*/

/** Number of DMA channels */
#define QUAC_DMA_NUM_CHANNELS       4

/** Channel indices */
#define QUAC_DMA_CH_TX0             0   /**< Host to device (command/data) */
#define QUAC_DMA_CH_TX1             1   /**< Host to device (keys) */
#define QUAC_DMA_CH_RX0             2   /**< Device to host (results) */
#define QUAC_DMA_CH_RX1             3   /**< Device to host (random) */

/** Maximum descriptors per channel */
#define QUAC_DMA_MAX_DESC_PER_CH    64

/** Maximum transfer size per descriptor */
#define QUAC_DMA_MAX_TRANSFER_SIZE  (4 * 1024 * 1024)   /* 4 MB */

/*=============================================================================
 * DMA Channel Context
 *=============================================================================*/

/**
 * @brief DMA channel state
 */
typedef enum _QUAC_DMA_CHANNEL_STATE {
    QuacDmaChannelIdle = 0,
    QuacDmaChannelRunning,
    QuacDmaChannelStopped,
    QuacDmaChannelError
} QUAC_DMA_CHANNEL_STATE;

/**
 * @brief DMA channel context
 */
typedef struct _QUAC_DMA_CHANNEL {
    /** Channel index */
    ULONG Index;
    
    /** Channel state */
    QUAC_DMA_CHANNEL_STATE State;
    
    /** Descriptor ring physical address */
    PHYSICAL_ADDRESS DescRingPhysical;
    
    /** Descriptor ring virtual address */
    PQUAC_DMA_DESCRIPTOR DescRing;
    
    /** Number of descriptors in ring */
    ULONG DescCount;
    
    /** Current head index (HW write pointer) */
    volatile ULONG Head;
    
    /** Current tail index (SW write pointer) */
    volatile ULONG Tail;
    
    /** DMA common buffer handle */
    WDFCOMMONBUFFER DescBuffer;
    
    /** Pending transfer count */
    volatile LONG PendingCount;
    
    /** Bytes transferred */
    ULONGLONG BytesTransferred;
    
    /** Transfer errors */
    ULONG Errors;
    
    /** Channel lock */
    KSPIN_LOCK Lock;
    
    /** Completion event */
    KEVENT CompleteEvent;
    
} QUAC_DMA_CHANNEL, *PQUAC_DMA_CHANNEL;

/**
 * @brief DMA engine context
 */
typedef struct _QUAC_DMA_ENGINE {
    /** Parent device context */
    PDEVICE_CONTEXT DeviceContext;
    
    /** DMA enabler */
    WDFDMAENABLER Enabler;
    
    /** DMA profile */
    WDF_DMA_PROFILE Profile;
    
    /** Channels */
    QUAC_DMA_CHANNEL Channels[QUAC_DMA_NUM_CHANNELS];
    
    /** Engine initialized */
    BOOLEAN Initialized;
    
    /** Global lock */
    KSPIN_LOCK Lock;
    
} QUAC_DMA_ENGINE, *PQUAC_DMA_ENGINE;

/*=============================================================================
 * DMA Transfer Request
 *=============================================================================*/

/**
 * @brief DMA transfer direction
 */
typedef enum _QUAC_DMA_DIRECTION {
    QuacDmaToDevice = 0,    /**< Host to device */
    QuacDmaFromDevice = 1   /**< Device to host */
} QUAC_DMA_DIRECTION;

/**
 * @brief DMA transfer request
 */
typedef struct _QUAC_DMA_REQUEST {
    /** Source address (host physical or device offset) */
    PHYSICAL_ADDRESS SourceAddress;
    
    /** Destination address */
    PHYSICAL_ADDRESS DestAddress;
    
    /** Transfer length */
    ULONG Length;
    
    /** Direction */
    QUAC_DMA_DIRECTION Direction;
    
    /** Channel to use */
    ULONG Channel;
    
    /** Generate interrupt on completion */
    BOOLEAN NotifyOnComplete;
    
    /** User-defined tag */
    ULONG Tag;
    
    /** Completion status */
    NTSTATUS Status;
    
    /** Completion callback (optional) */
    VOID (*CompletionCallback)(struct _QUAC_DMA_REQUEST* Request, PVOID Context);
    
    /** Callback context */
    PVOID CallbackContext;
    
} QUAC_DMA_REQUEST, *PQUAC_DMA_REQUEST;

/*=============================================================================
 * DMA Engine Functions
 *=============================================================================*/

/**
 * @brief Initialize DMA engine
 *
 * @param[in] DeviceContext     Device context
 * @param[in] DmaEngine         DMA engine context to initialize
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100DmaInitialize(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _Out_ PQUAC_DMA_ENGINE DmaEngine
    );

/**
 * @brief Shutdown DMA engine
 *
 * @param[in] DmaEngine         DMA engine context
 */
VOID
Quac100DmaShutdown(
    _In_ PQUAC_DMA_ENGINE DmaEngine
    );

/**
 * @brief Enable DMA engine
 *
 * @param[in] DmaEngine         DMA engine context
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100DmaEnable(
    _In_ PQUAC_DMA_ENGINE DmaEngine
    );

/**
 * @brief Disable DMA engine
 *
 * @param[in] DmaEngine         DMA engine context
 */
VOID
Quac100DmaDisable(
    _In_ PQUAC_DMA_ENGINE DmaEngine
    );

/**
 * @brief Reset DMA engine
 *
 * @param[in] DmaEngine         DMA engine context
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100DmaReset(
    _In_ PQUAC_DMA_ENGINE DmaEngine
    );

/*=============================================================================
 * DMA Channel Functions
 *=============================================================================*/

/**
 * @brief Initialize a DMA channel
 *
 * @param[in] DmaEngine         DMA engine context
 * @param[in] ChannelIndex      Channel to initialize
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100DmaChannelInit(
    _In_ PQUAC_DMA_ENGINE DmaEngine,
    _In_ ULONG ChannelIndex
    );

/**
 * @brief Start a DMA channel
 *
 * @param[in] DmaEngine         DMA engine context
 * @param[in] ChannelIndex      Channel to start
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100DmaChannelStart(
    _In_ PQUAC_DMA_ENGINE DmaEngine,
    _In_ ULONG ChannelIndex
    );

/**
 * @brief Stop a DMA channel
 *
 * @param[in] DmaEngine         DMA engine context
 * @param[in] ChannelIndex      Channel to stop
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100DmaChannelStop(
    _In_ PQUAC_DMA_ENGINE DmaEngine,
    _In_ ULONG ChannelIndex
    );

/**
 * @brief Reset a DMA channel
 *
 * @param[in] DmaEngine         DMA engine context
 * @param[in] ChannelIndex      Channel to reset
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100DmaChannelReset(
    _In_ PQUAC_DMA_ENGINE DmaEngine,
    _In_ ULONG ChannelIndex
    );

/**
 * @brief Get channel status
 *
 * @param[in]  DmaEngine        DMA engine context
 * @param[in]  ChannelIndex     Channel index
 * @param[out] State            Current channel state
 * @param[out] Pending          Number of pending transfers
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100DmaChannelGetStatus(
    _In_ PQUAC_DMA_ENGINE DmaEngine,
    _In_ ULONG ChannelIndex,
    _Out_ PQUAC_DMA_CHANNEL_STATE State,
    _Out_ PULONG Pending
    );

/*=============================================================================
 * DMA Transfer Functions
 *=============================================================================*/

/**
 * @brief Submit a DMA transfer
 *
 * @param[in]     DmaEngine     DMA engine context
 * @param[in,out] Request       Transfer request
 *
 * @return STATUS_SUCCESS if submitted successfully
 */
NTSTATUS
Quac100DmaTransferSubmit(
    _In_ PQUAC_DMA_ENGINE DmaEngine,
    _Inout_ PQUAC_DMA_REQUEST Request
    );

/**
 * @brief Wait for DMA transfer completion
 *
 * @param[in] DmaEngine         DMA engine context
 * @param[in] ChannelIndex      Channel to wait on
 * @param[in] TimeoutMs         Timeout in milliseconds (0 = infinite)
 *
 * @return STATUS_SUCCESS on completion, STATUS_TIMEOUT on timeout
 */
NTSTATUS
Quac100DmaTransferWait(
    _In_ PQUAC_DMA_ENGINE DmaEngine,
    _In_ ULONG ChannelIndex,
    _In_ ULONG TimeoutMs
    );

/**
 * @brief Cancel pending DMA transfers on a channel
 *
 * @param[in] DmaEngine         DMA engine context
 * @param[in] ChannelIndex      Channel to cancel
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100DmaTransferCancel(
    _In_ PQUAC_DMA_ENGINE DmaEngine,
    _In_ ULONG ChannelIndex
    );

/*=============================================================================
 * DMA Interrupt Handling
 *=============================================================================*/

/**
 * @brief Process DMA completion interrupt
 *
 * @param[in] DmaEngine         DMA engine context
 * @param[in] ChannelIndex      Channel that completed
 *
 * @return TRUE if interrupt was handled
 */
BOOLEAN
Quac100DmaProcessCompletion(
    _In_ PQUAC_DMA_ENGINE DmaEngine,
    _In_ ULONG ChannelIndex
    );

/**
 * @brief Process DMA error interrupt
 *
 * @param[in] DmaEngine         DMA engine context
 * @param[in] ChannelIndex      Channel with error
 *
 * @return TRUE if error was handled
 */
BOOLEAN
Quac100DmaProcessError(
    _In_ PQUAC_DMA_ENGINE DmaEngine,
    _In_ ULONG ChannelIndex
    );

/*=============================================================================
 * Utility Functions
 *=============================================================================*/

/**
 * @brief Allocate DMA-capable buffer
 *
 * @param[in]  DmaEngine        DMA engine context
 * @param[in]  Size             Buffer size
 * @param[out] VirtualAddress   Virtual address
 * @param[out] PhysicalAddress  Physical address
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100DmaAllocateBuffer(
    _In_ PQUAC_DMA_ENGINE DmaEngine,
    _In_ SIZE_T Size,
    _Out_ PVOID* VirtualAddress,
    _Out_ PPHYSICAL_ADDRESS PhysicalAddress
    );

/**
 * @brief Free DMA buffer
 *
 * @param[in] DmaEngine         DMA engine context
 * @param[in] VirtualAddress    Virtual address to free
 * @param[in] Size              Buffer size
 */
VOID
Quac100DmaFreeBuffer(
    _In_ PQUAC_DMA_ENGINE DmaEngine,
    _In_ PVOID VirtualAddress,
    _In_ SIZE_T Size
    );

#ifdef __cplusplus
}
#endif

#endif /* QUAC100_DMA_H */
