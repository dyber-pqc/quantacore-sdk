/*++

Module Name:
    power.h

Abstract:
    QUAC 100 power management interface definitions.
    Defines power states, transitions, and management functions.

Environment:
    Kernel mode only.

Copyright:
    Copyright (c) 2025 Dyber, Inc. All Rights Reserved.

--*/

#pragma once

#include <ntddk.h>
#include <wdf.h>

//
// Forward declarations
//
typedef struct _QUAC_DEVICE_CONTEXT *PQUAC_DEVICE_CONTEXT;

//
// Device power states (maps to Windows Dx states)
//
typedef enum _QUAC_POWER_STATE {
    QuacPowerD0 = 0,        // Fully operational
    QuacPowerD1 = 1,        // Light sleep (clocks gated)
    QuacPowerD2 = 2,        // Deep sleep (most power off)
    QuacPowerD3 = 3,        // Off (minimal power)
    QuacPowerD3Cold = 4     // Power removed
} QUAC_POWER_STATE;

//
// Power capabilities
//
#define QUAC_POWER_CAP_D1_SUPPORTED     0x00000001
#define QUAC_POWER_CAP_D2_SUPPORTED     0x00000002
#define QUAC_POWER_CAP_WAKE_D1          0x00000004
#define QUAC_POWER_CAP_WAKE_D2          0x00000008
#define QUAC_POWER_CAP_PME              0x00000010
#define QUAC_POWER_CAP_RUNTIME_PM       0x00000020

//
// Power state information
//
typedef struct _QUAC_POWER_INFO {
    QUAC_POWER_STATE CurrentState;
    QUAC_POWER_STATE TargetState;
    UINT32 Capabilities;
    UINT32 IdleTimeoutMs;
    UINT32 PowerConsumptionMw;
    UINT64 D0ResidencyMs;
    UINT64 D1ResidencyMs;
    UINT64 D2ResidencyMs;
    UINT64 D3ResidencyMs;
    UINT32 TransitionCount;
} QUAC_POWER_INFO, *PQUAC_POWER_INFO;

//
// Hardware state to save/restore
//
typedef struct _QUAC_HARDWARE_STATE {
    UINT32 DeviceControl;
    UINT32 InterruptMask;
    UINT32 DmaConfig;
    UINT32 QrngConfig;
    UINT32 KemConfig;
    UINT32 SignConfig;
    // Add more registers as needed
} QUAC_HARDWARE_STATE, *PQUAC_HARDWARE_STATE;

//
// Power context (stored in device context)
//
typedef struct _QUAC_POWER_CONTEXT {
    QUAC_POWER_STATE CurrentState;
    QUAC_POWER_STATE RequestedState;
    UINT32 Capabilities;
    UINT32 IdleTimeoutMs;
    BOOLEAN RuntimePmEnabled;
    BOOLEAN WakeEnabled;
    KEVENT TransitionComplete;
    QUAC_HARDWARE_STATE SavedState;
    
    // Statistics
    UINT64 D0EntryTime;
    UINT64 TotalD0Time;
    UINT64 TotalD1Time;
    UINT64 TotalD2Time;
    UINT64 TotalD3Time;
    UINT32 TransitionCount;
} QUAC_POWER_CONTEXT, *PQUAC_POWER_CONTEXT;

//
// WDF Power callbacks
//
EVT_WDF_DEVICE_D0_ENTRY Quac100EvtDeviceD0Entry;
EVT_WDF_DEVICE_D0_EXIT Quac100EvtDeviceD0Exit;
EVT_WDF_DEVICE_D0_ENTRY_POST_INTERRUPTS_ENABLED Quac100EvtDeviceD0EntryPostInterruptsEnabled;
EVT_WDF_DEVICE_D0_EXIT_PRE_INTERRUPTS_DISABLED Quac100EvtDeviceD0ExitPreInterruptsDisabled;
EVT_WDF_DEVICE_PREPARE_HARDWARE Quac100EvtDevicePrepareHardware;
EVT_WDF_DEVICE_RELEASE_HARDWARE Quac100EvtDeviceReleaseHardware;
EVT_WDF_DEVICE_SELF_MANAGED_IO_INIT Quac100EvtDeviceSelfManagedIoInit;
EVT_WDF_DEVICE_SELF_MANAGED_IO_CLEANUP Quac100EvtDeviceSelfManagedIoCleanup;
EVT_WDF_DEVICE_ARM_WAKE_FROM_S0 Quac100EvtDeviceArmWakeFromS0;
EVT_WDF_DEVICE_DISARM_WAKE_FROM_S0 Quac100EvtDeviceDisarmWakeFromS0;

//
// Initialization and shutdown
//
NTSTATUS
Quac100PowerInitialize(
    _In_ PQUAC_DEVICE_CONTEXT DeviceContext
    );

VOID
Quac100PowerShutdown(
    _In_ PQUAC_DEVICE_CONTEXT DeviceContext
    );

//
// Power policy
//
NTSTATUS
Quac100PowerSetPolicy(
    _In_ PQUAC_DEVICE_CONTEXT DeviceContext,
    _In_ UINT32 IdleTimeoutMs,
    _In_ BOOLEAN EnableRuntimePm
    );

//
// State management
//
NTSTATUS
Quac100PowerSaveHardwareState(
    _In_ PQUAC_DEVICE_CONTEXT DeviceContext
    );

NTSTATUS
Quac100PowerRestoreHardwareState(
    _In_ PQUAC_DEVICE_CONTEXT DeviceContext
    );

//
// Query functions
//
NTSTATUS
Quac100PowerGetInfo(
    _In_ PQUAC_DEVICE_CONTEXT DeviceContext,
    _Out_ PQUAC_POWER_INFO PowerInfo
    );

QUAC_POWER_STATE
Quac100PowerGetCurrentState(
    _In_ PQUAC_DEVICE_CONTEXT DeviceContext
    );

BOOLEAN
Quac100PowerIsD0(
    _In_ PQUAC_DEVICE_CONTEXT DeviceContext
    );

//
// Runtime PM control
//
NTSTATUS
Quac100PowerReference(
    _In_ PQUAC_DEVICE_CONTEXT DeviceContext,
    _In_ BOOLEAN Wait
    );

VOID
Quac100PowerDereference(
    _In_ PQUAC_DEVICE_CONTEXT DeviceContext
    );

//
// Wake support
//
NTSTATUS
Quac100PowerEnableWake(
    _In_ PQUAC_DEVICE_CONTEXT DeviceContext,
    _In_ BOOLEAN Enable
    );

//
// Power transitions (internal)
//
NTSTATUS
Quac100PowerTransitionToD0(
    _In_ PQUAC_DEVICE_CONTEXT DeviceContext
    );

NTSTATUS
Quac100PowerTransitionToLowPower(
    _In_ PQUAC_DEVICE_CONTEXT DeviceContext,
    _In_ QUAC_POWER_STATE TargetState
    );
