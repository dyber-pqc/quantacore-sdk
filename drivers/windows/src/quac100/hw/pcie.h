/**
 * @file pcie.h
 * @brief QUAC 100 PCIe Hardware Abstraction Layer
 *
 * Functions for BAR access, register read/write, and PCIe management.
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_PCIE_H
#define QUAC100_PCIE_H

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
 * PCIe Configuration Functions
 *=============================================================================*/

/**
 * @brief Initialize PCIe resources for a device
 *
 * Maps BARs and validates device identification.
 *
 * @param[in] DeviceContext     Device context
 * @param[in] ResourcesTranslated Translated CM resources
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100PcieInitialize(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ WDFCMRESLIST ResourcesTranslated
    );

/**
 * @brief Release PCIe resources
 *
 * @param[in] DeviceContext     Device context
 */
VOID
Quac100PcieRelease(
    _In_ PDEVICE_CONTEXT DeviceContext
    );

/**
 * @brief Verify device identification
 *
 * Checks vendor/device ID match expected values.
 *
 * @param[in] DeviceContext     Device context
 *
 * @return STATUS_SUCCESS if valid QUAC 100 device
 */
NTSTATUS
Quac100PcieVerifyDevice(
    _In_ PDEVICE_CONTEXT DeviceContext
    );

/*=============================================================================
 * Register Access Functions
 *=============================================================================*/

/**
 * @brief Read 32-bit register
 *
 * @param[in] DeviceContext     Device context
 * @param[in] Offset            Register offset from BAR0
 *
 * @return Register value, or 0xFFFFFFFF on error
 */
ULONG
Quac100RegRead32(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ ULONG Offset
    );

/**
 * @brief Write 32-bit register
 *
 * @param[in] DeviceContext     Device context
 * @param[in] Offset            Register offset from BAR0
 * @param[in] Value             Value to write
 */
VOID
Quac100RegWrite32(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ ULONG Offset,
    _In_ ULONG Value
    );

/**
 * @brief Read 64-bit register
 *
 * @param[in] DeviceContext     Device context
 * @param[in] Offset            Register offset from BAR0
 *
 * @return Register value
 */
ULONGLONG
Quac100RegRead64(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ ULONG Offset
    );

/**
 * @brief Write 64-bit register
 *
 * @param[in] DeviceContext     Device context
 * @param[in] Offset            Register offset from BAR0
 * @param[in] Value             Value to write
 */
VOID
Quac100RegWrite64(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ ULONG Offset,
    _In_ ULONGLONG Value
    );

/**
 * @brief Read-modify-write 32-bit register
 *
 * Atomically sets bits specified in SetMask and clears bits in ClearMask.
 *
 * @param[in] DeviceContext     Device context
 * @param[in] Offset            Register offset
 * @param[in] SetMask           Bits to set
 * @param[in] ClearMask         Bits to clear
 */
VOID
Quac100RegModify32(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ ULONG Offset,
    _In_ ULONG SetMask,
    _In_ ULONG ClearMask
    );

/**
 * @brief Poll register for expected value
 *
 * @param[in] DeviceContext     Device context
 * @param[in] Offset            Register offset
 * @param[in] Mask              Bits to check
 * @param[in] ExpectedValue     Expected value after mask
 * @param[in] TimeoutUs         Timeout in microseconds
 *
 * @return STATUS_SUCCESS if condition met, STATUS_TIMEOUT otherwise
 */
NTSTATUS
Quac100RegPoll32(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ ULONG Offset,
    _In_ ULONG Mask,
    _In_ ULONG ExpectedValue,
    _In_ ULONG TimeoutUs
    );

/*=============================================================================
 * Device Control Functions
 *=============================================================================*/

/**
 * @brief Enable the device
 *
 * @param[in] DeviceContext     Device context
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100PcieEnableDevice(
    _In_ PDEVICE_CONTEXT DeviceContext
    );

/**
 * @brief Disable the device
 *
 * @param[in] DeviceContext     Device context
 */
VOID
Quac100PcieDisableDevice(
    _In_ PDEVICE_CONTEXT DeviceContext
    );

/**
 * @brief Perform soft reset
 *
 * @param[in] DeviceContext     Device context
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100PcieSoftReset(
    _In_ PDEVICE_CONTEXT DeviceContext
    );

/**
 * @brief Get device status
 *
 * @param[in]  DeviceContext    Device context
 * @param[out] Status           Device status register value
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100PcieGetStatus(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _Out_ PULONG Status
    );

/**
 * @brief Get device capabilities
 *
 * @param[in]  DeviceContext    Device context
 * @param[out] Caps             Capabilities register value
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100PcieGetCapabilities(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _Out_ PULONG Caps
    );

/*=============================================================================
 * Firmware Information
 *=============================================================================*/

/**
 * @brief Get firmware version
 *
 * @param[in]  DeviceContext    Device context
 * @param[out] Major            Major version
 * @param[out] Minor            Minor version
 * @param[out] Patch            Patch version
 * @param[out] Build            Build number
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100PcieGetFwVersion(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _Out_ PUSHORT Major,
    _Out_ PUSHORT Minor,
    _Out_ PUSHORT Patch,
    _Out_ PULONG Build
    );

/**
 * @brief Get device serial number
 *
 * @param[in]  DeviceContext    Device context
 * @param[out] Serial           Buffer for serial string (min 32 chars)
 * @param[in]  SerialSize       Buffer size
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100PcieGetSerial(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _Out_writes_(SerialSize) PWCHAR Serial,
    _In_ size_t SerialSize
    );

/*=============================================================================
 * Temperature and Power Monitoring
 *=============================================================================*/

/**
 * @brief Get core temperature
 *
 * @param[in]  DeviceContext    Device context
 * @param[out] MilliCelsius     Temperature in milli-degrees Celsius
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100PcieGetTemperature(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _Out_ PLONG MilliCelsius
    );

/**
 * @brief Get power consumption
 *
 * @param[in]  DeviceContext    Device context
 * @param[out] Milliwatts       Power in milliwatts
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100PcieGetPowerDraw(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _Out_ PULONG Milliwatts
    );

/*=============================================================================
 * Statistics
 *=============================================================================*/

/**
 * @brief Get operation counters
 *
 * @param[in]  DeviceContext    Device context
 * @param[out] Completed        Operations completed
 * @param[out] Failed           Operations failed
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100PcieGetOpCounters(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _Out_ PULONGLONG Completed,
    _Out_ PULONGLONG Failed
    );

/**
 * @brief Get device uptime
 *
 * @param[in]  DeviceContext    Device context
 * @param[out] Seconds          Uptime in seconds
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100PcieGetUptime(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _Out_ PULONGLONG Seconds
    );

#ifdef __cplusplus
}
#endif

#endif /* QUAC100_PCIE_H */
