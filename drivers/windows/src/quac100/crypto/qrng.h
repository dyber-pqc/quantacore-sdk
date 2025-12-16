/**
 * @file qrng.h
 * @brief QUAC 100 Quantum Random Number Generator Interface
 *
 * Hardware quantum random number generation with health monitoring
 * and entropy pool management.
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_QRNG_H
#define QUAC100_QRNG_H

#include <ntddk.h>
#include <wdf.h>

#ifdef __cplusplus
extern "C" {
#endif

/*=============================================================================
 * Forward Declarations
 *=============================================================================*/

struct _DEVICE_CONTEXT;
typedef struct _DEVICE_CONTEXT DEVICE_CONTEXT, *PDEVICE_CONTEXT;

/*=============================================================================
 * QRNG Constants
 *=============================================================================*/

/** Maximum bytes per QRNG request */
#define QUAC_QRNG_MAX_REQUEST_SIZE      (64 * 1024)     /* 64 KB */

/** Minimum entropy pool level (bits) */
#define QUAC_QRNG_MIN_ENTROPY           256

/** QRNG FIFO depth (bytes) */
#define QUAC_QRNG_FIFO_SIZE             4096

/*=============================================================================
 * QRNG Quality Levels
 *=============================================================================*/

/**
 * @brief Random number quality level
 */
typedef enum _QUAC_QRNG_QUALITY {
    QuacQrngQualityFast = 0,        /**< Fastest, lower entropy density */
    QuacQrngQualityNormal = 1,      /**< Balanced speed/quality */
    QuacQrngQualityHigh = 2,        /**< High quality, slower */
    QuacQrngQualityFips = 3,        /**< FIPS-compliant (SP 800-90B) */
} QUAC_QRNG_QUALITY;

/*=============================================================================
 * QRNG Status
 *=============================================================================*/

/**
 * @brief QRNG health status
 */
typedef enum _QUAC_QRNG_HEALTH {
    QuacQrngHealthOk = 0,           /**< QRNG healthy */
    QuacQrngHealthWarning = 1,      /**< Warning - reduced quality */
    QuacQrngHealthDegraded = 2,     /**< Degraded operation */
    QuacQrngHealthFailed = 3,       /**< QRNG failure */
} QUAC_QRNG_HEALTH;

/**
 * @brief QRNG status information
 */
typedef struct _QUAC_QRNG_STATUS {
    /** Health status */
    QUAC_QRNG_HEALTH Health;
    
    /** Available entropy (bits) */
    ULONG EntropyAvailable;
    
    /** QRNG enabled */
    BOOLEAN Enabled;
    
    /** Continuous health test passed */
    BOOLEAN HealthTestOk;
    
    /** Repetition count test failures */
    ULONG RepetitionFailures;
    
    /** Adaptive proportion test failures */
    ULONG ProportionFailures;
    
    /** Total bytes generated */
    ULONGLONG BytesGenerated;
    
    /** Generation rate (bytes/second) */
    ULONG GenerationRate;
    
} QUAC_QRNG_STATUS, *PQUAC_QRNG_STATUS;

/*=============================================================================
 * QRNG Initialization
 *=============================================================================*/

/**
 * @brief Initialize QRNG subsystem
 *
 * @param[in] DeviceContext     Device context
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100QrngInitialize(
    _In_ PDEVICE_CONTEXT DeviceContext
    );

/**
 * @brief Shutdown QRNG subsystem
 *
 * @param[in] DeviceContext     Device context
 */
VOID
Quac100QrngShutdown(
    _In_ PDEVICE_CONTEXT DeviceContext
    );

/**
 * @brief Enable QRNG
 *
 * @param[in] DeviceContext     Device context
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100QrngEnable(
    _In_ PDEVICE_CONTEXT DeviceContext
    );

/**
 * @brief Disable QRNG
 *
 * @param[in] DeviceContext     Device context
 */
VOID
Quac100QrngDisable(
    _In_ PDEVICE_CONTEXT DeviceContext
    );

/*=============================================================================
 * Random Number Generation
 *=============================================================================*/

/**
 * @brief Generate random bytes
 *
 * @param[in]  DeviceContext    Device context
 * @param[out] Buffer           Output buffer
 * @param[in]  Length           Requested length
 * @param[in]  Quality          Quality level
 *
 * @return STATUS_SUCCESS on success
 * @return STATUS_DEVICE_BUSY if not enough entropy
 */
NTSTATUS
Quac100QrngGenerate(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _Out_writes_bytes_(Length) PUCHAR Buffer,
    _In_ SIZE_T Length,
    _In_ QUAC_QRNG_QUALITY Quality
    );

/**
 * @brief Generate random bytes (async)
 *
 * @param[in]  DeviceContext    Device context
 * @param[out] Buffer           Output buffer
 * @param[in]  Length           Requested length
 * @param[in]  Quality          Quality level
 * @param[in]  Callback         Completion callback
 * @param[in]  Context          Callback context
 *
 * @return STATUS_PENDING if submitted successfully
 */
NTSTATUS
Quac100QrngGenerateAsync(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _Out_writes_bytes_(Length) PUCHAR Buffer,
    _In_ SIZE_T Length,
    _In_ QUAC_QRNG_QUALITY Quality,
    _In_ VOID (*Callback)(NTSTATUS Status, PVOID Context),
    _In_ PVOID Context
    );

/**
 * @brief Get available entropy
 *
 * @param[in]  DeviceContext    Device context
 * @param[out] EntropyBits      Available entropy in bits
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100QrngGetEntropy(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _Out_ PULONG EntropyBits
    );

/**
 * @brief Wait for entropy
 *
 * Blocks until the specified amount of entropy is available.
 *
 * @param[in] DeviceContext     Device context
 * @param[in] MinEntropyBits    Minimum entropy required
 * @param[in] TimeoutMs         Timeout in milliseconds (0 = infinite)
 *
 * @return STATUS_SUCCESS when entropy available
 * @return STATUS_TIMEOUT on timeout
 */
NTSTATUS
Quac100QrngWaitForEntropy(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ ULONG MinEntropyBits,
    _In_ ULONG TimeoutMs
    );

/*=============================================================================
 * QRNG Health and Status
 *=============================================================================*/

/**
 * @brief Get QRNG status
 *
 * @param[in]  DeviceContext    Device context
 * @param[out] Status           Status information
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100QrngGetStatus(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _Out_ PQUAC_QRNG_STATUS Status
    );

/**
 * @brief Run QRNG health test
 *
 * Performs continuous health tests as specified in NIST SP 800-90B.
 *
 * @param[in]  DeviceContext    Device context
 * @param[out] Passed           TRUE if test passed
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100QrngHealthTest(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _Out_ PBOOLEAN Passed
    );

/**
 * @brief Reseed QRNG
 *
 * Forces a reseed of the conditioning component.
 *
 * @param[in] DeviceContext     Device context
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100QrngReseed(
    _In_ PDEVICE_CONTEXT DeviceContext
    );

/*=============================================================================
 * QRNG Configuration
 *=============================================================================*/

/**
 * @brief Set QRNG quality level
 *
 * @param[in] DeviceContext     Device context
 * @param[in] Quality           Default quality level
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100QrngSetQuality(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ QUAC_QRNG_QUALITY Quality
    );

/**
 * @brief Enable/disable health checking
 *
 * @param[in] DeviceContext     Device context
 * @param[in] Enable            TRUE to enable health checks
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100QrngSetHealthCheck(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ BOOLEAN Enable
    );

/*=============================================================================
 * QRNG Interrupt Handling
 *=============================================================================*/

/**
 * @brief Process QRNG interrupt
 *
 * Called when entropy becomes available.
 *
 * @param[in] DeviceContext     Device context
 *
 * @return TRUE if interrupt was handled
 */
BOOLEAN
Quac100QrngProcessInterrupt(
    _In_ PDEVICE_CONTEXT DeviceContext
    );

#ifdef __cplusplus
}
#endif

#endif /* QUAC100_QRNG_H */
