/**
 * @file interrupt.h
 * @brief QUAC 100 Interrupt Handling
 *
 * MSI-X interrupt management for the QUAC 100 cryptographic accelerator.
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_INTERRUPT_H
#define QUAC100_INTERRUPT_H

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
 * Interrupt Types
 *=============================================================================*/

/**
 * @brief Interrupt source flags
 */
typedef enum _QUAC_INTERRUPT_SOURCE {
    QuacIntSourceNone       = 0x0000,
    QuacIntSourceDmaTx0     = 0x0001,
    QuacIntSourceDmaTx1     = 0x0002,
    QuacIntSourceDmaRx0     = 0x0004,
    QuacIntSourceDmaRx1     = 0x0008,
    QuacIntSourceDmaError   = 0x0010,
    QuacIntSourceCrypto     = 0x0100,
    QuacIntSourceCryptoErr  = 0x0200,
    QuacIntSourceEntropy    = 0x1000,
    QuacIntSourceTemp       = 0x2000,
    QuacIntSourceError      = 0x4000,
    QuacIntSourceFatal      = 0x8000,
} QUAC_INTERRUPT_SOURCE;

/**
 * @brief Interrupt statistics
 */
typedef struct _QUAC_INTERRUPT_STATS {
    ULONGLONG TotalInterrupts;
    ULONGLONG DmaInterrupts;
    ULONGLONG CryptoInterrupts;
    ULONGLONG EntropyInterrupts;
    ULONGLONG ErrorInterrupts;
    ULONGLONG SpuriousInterrupts;
} QUAC_INTERRUPT_STATS, *PQUAC_INTERRUPT_STATS;

/**
 * @brief Interrupt context
 */
typedef struct _QUAC_INTERRUPT_CONTEXT {
    /** Parent device context */
    PDEVICE_CONTEXT DeviceContext;
    
    /** WDF interrupt object */
    WDFINTERRUPT Interrupt;
    
    /** MSI-X supported */
    BOOLEAN MsixSupported;
    
    /** Number of MSI-X vectors */
    ULONG MsixVectorCount;
    
    /** Interrupt mask (enabled sources) */
    ULONG EnableMask;
    
    /** Statistics */
    QUAC_INTERRUPT_STATS Stats;
    
    /** Lock for interrupt handling */
    KSPIN_LOCK Lock;
    
    /** DPC for deferred processing */
    KDPC Dpc;
    
    /** Pending interrupt sources for DPC */
    volatile LONG PendingSources;
    
} QUAC_INTERRUPT_CONTEXT, *PQUAC_INTERRUPT_CONTEXT;

/*=============================================================================
 * Interrupt Initialization
 *=============================================================================*/

/**
 * @brief Create and initialize interrupt object
 *
 * @param[in]  DeviceContext    Device context
 * @param[out] InterruptContext Interrupt context to initialize
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100InterruptCreate(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _Out_ PQUAC_INTERRUPT_CONTEXT InterruptContext
    );

/**
 * @brief Delete interrupt object
 *
 * @param[in] InterruptContext  Interrupt context
 */
VOID
Quac100InterruptDelete(
    _In_ PQUAC_INTERRUPT_CONTEXT InterruptContext
    );

/**
 * @brief Enable interrupts
 *
 * @param[in] InterruptContext  Interrupt context
 * @param[in] Sources           Interrupt sources to enable
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100InterruptEnable(
    _In_ PQUAC_INTERRUPT_CONTEXT InterruptContext,
    _In_ ULONG Sources
    );

/**
 * @brief Disable interrupts
 *
 * @param[in] InterruptContext  Interrupt context
 * @param[in] Sources           Interrupt sources to disable
 */
VOID
Quac100InterruptDisable(
    _In_ PQUAC_INTERRUPT_CONTEXT InterruptContext,
    _In_ ULONG Sources
    );

/**
 * @brief Disable all interrupts
 *
 * @param[in] InterruptContext  Interrupt context
 */
VOID
Quac100InterruptDisableAll(
    _In_ PQUAC_INTERRUPT_CONTEXT InterruptContext
    );

/*=============================================================================
 * Interrupt Callbacks (WDF)
 *=============================================================================*/

/**
 * @brief ISR callback
 */
EVT_WDF_INTERRUPT_ISR Quac100EvtInterruptIsr;

/**
 * @brief DPC callback
 */
EVT_WDF_INTERRUPT_DPC Quac100EvtInterruptDpc;

/**
 * @brief Interrupt enable callback
 */
EVT_WDF_INTERRUPT_ENABLE Quac100EvtInterruptEnableCallback;

/**
 * @brief Interrupt disable callback
 */
EVT_WDF_INTERRUPT_DISABLE Quac100EvtInterruptDisableCallback;

/*=============================================================================
 * Interrupt Status Functions
 *=============================================================================*/

/**
 * @brief Read and clear interrupt status
 *
 * @param[in]  InterruptContext Interrupt context
 * @param[out] Sources          Active interrupt sources
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100InterruptReadStatus(
    _In_ PQUAC_INTERRUPT_CONTEXT InterruptContext,
    _Out_ PULONG Sources
    );

/**
 * @brief Acknowledge interrupts
 *
 * @param[in] InterruptContext  Interrupt context
 * @param[in] Sources           Sources to acknowledge
 */
VOID
Quac100InterruptAcknowledge(
    _In_ PQUAC_INTERRUPT_CONTEXT InterruptContext,
    _In_ ULONG Sources
    );

/**
 * @brief Get interrupt statistics
 *
 * @param[in]  InterruptContext Interrupt context
 * @param[out] Stats            Statistics structure
 */
VOID
Quac100InterruptGetStats(
    _In_ PQUAC_INTERRUPT_CONTEXT InterruptContext,
    _Out_ PQUAC_INTERRUPT_STATS Stats
    );

/**
 * @brief Reset interrupt statistics
 *
 * @param[in] InterruptContext  Interrupt context
 */
VOID
Quac100InterruptResetStats(
    _In_ PQUAC_INTERRUPT_CONTEXT InterruptContext
    );

/*=============================================================================
 * MSI-X Functions
 *=============================================================================*/

/**
 * @brief Configure MSI-X interrupts
 *
 * @param[in] InterruptContext  Interrupt context
 * @param[in] NumVectors        Number of vectors to request
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100MsixConfigure(
    _In_ PQUAC_INTERRUPT_CONTEXT InterruptContext,
    _In_ ULONG NumVectors
    );

/**
 * @brief Set MSI-X vector affinity
 *
 * @param[in] InterruptContext  Interrupt context
 * @param[in] Vector            Vector index
 * @param[in] Processor         Target processor
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100MsixSetAffinity(
    _In_ PQUAC_INTERRUPT_CONTEXT InterruptContext,
    _In_ ULONG Vector,
    _In_ ULONG Processor
    );

#ifdef __cplusplus
}
#endif

#endif /* QUAC100_INTERRUPT_H */
