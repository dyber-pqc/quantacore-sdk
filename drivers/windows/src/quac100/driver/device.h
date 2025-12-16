/**
 * @file device.h
 * @brief QUAC 100 KMDF Driver - Device Context and Functions
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_DEVICE_H
#define QUAC100_DEVICE_H

#include <ntddk.h>
#include <wdf.h>

//
// Forward declarations
//
typedef struct _DEVICE_CONTEXT DEVICE_CONTEXT, *PDEVICE_CONTEXT;

//
// BAR information
//
typedef struct _BAR_INFO {
    PHYSICAL_ADDRESS PhysicalAddress;
    PVOID VirtualAddress;
    SIZE_T Length;
    BOOLEAN IsMapped;
} BAR_INFO, *PBAR_INFO;

//
// Device capabilities
//
typedef struct _DEVICE_CAPS {
    ULONG Capabilities;
    ULONG MaxBatchSize;
    ULONG MaxPendingJobs;
    ULONG KeySlots;
    BOOLEAN SriovSupported;
    USHORT NumVFs;
} DEVICE_CAPS, *PDEVICE_CAPS;

//
// Hardware state
//
typedef struct _HW_STATE {
    BOOLEAN Initialized;
    BOOLEAN DmaEnabled;
    BOOLEAN InterruptsEnabled;
    LONG TemperatureCelsius;
    ULONG EntropyAvailable;
    ULONG CurrentStatus;
} HW_STATE, *PHW_STATE;

//
// Device context structure
//
typedef struct _DEVICE_CONTEXT {
    //
    // WDF handles
    //
    WDFDEVICE Device;
    WDFINTERRUPT Interrupt;
    WDFDMAENABLER DmaEnabler;
    
    //
    // Device identification
    //
    ULONG DeviceIndex;
    WCHAR SerialNumber[32];
    USHORT VendorId;
    USHORT DeviceId;
    UCHAR HardwareRevision;
    
    //
    // PCIe resources
    //
    BAR_INFO Bars[6];
    BUS_INTERFACE_STANDARD BusInterface;
    
    //
    // Hardware state
    //
    DEVICE_CAPS Caps;
    HW_STATE HwState;
    
    //
    // Synchronization
    //
    KSPIN_LOCK HwLock;
    KEVENT InitEvent;
    
    //
    // Statistics
    //
    ULONGLONG OperationsCompleted;
    ULONGLONG OperationsFailed;
    
} DEVICE_CONTEXT, *PDEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_CONTEXT, GetDeviceContext)

//
// Function prototypes
//

NTSTATUS
Quac100CreateDevice(
    _Inout_ PWDFDEVICE_INIT DeviceInit
    );

EVT_WDF_DEVICE_PREPARE_HARDWARE     Quac100EvtDevicePrepareHardware;
EVT_WDF_DEVICE_RELEASE_HARDWARE     Quac100EvtDeviceReleaseHardware;
EVT_WDF_DEVICE_D0_ENTRY             Quac100EvtDeviceD0Entry;
EVT_WDF_DEVICE_D0_EXIT              Quac100EvtDeviceD0Exit;

//
// Hardware initialization
//
NTSTATUS
Quac100HwInitialize(
    _In_ PDEVICE_CONTEXT DeviceContext
    );

VOID
Quac100HwShutdown(
    _In_ PDEVICE_CONTEXT DeviceContext
    );

//
// Register access
//
ULONG
Quac100ReadRegister32(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ ULONG Offset
    );

VOID
Quac100WriteRegister32(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ ULONG Offset,
    _In_ ULONG Value
    );

#endif /* QUAC100_DEVICE_H */