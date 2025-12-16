/**
 * @file driver.h
 * @brief QUAC 100 KMDF Driver - Main Header
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_DRIVER_H
#define QUAC100_DRIVER_H

#include <ntddk.h>
#include <wdf.h>
#include <initguid.h>
#include <wdmguid.h>

#include "trace.h"
#include "device.h"
#include "queue.h"

//
// Driver-wide definitions
//

#define QUAC100_POOL_TAG        'CAUQ'  // 'QUAC' reversed
#define QUAC100_DRIVER_NAME     L"QUAC100"

//
// PCI identification
//
#define QUAC_PCI_VENDOR_ID      0x1DFB  // Placeholder vendor ID
#define QUAC_PCI_DEVICE_ID      0x0100  // QUAC 100 device ID

//
// Driver context
//
typedef struct _DRIVER_CONTEXT {
    WDFDRIVER Driver;
    ULONG DeviceCount;
    BOOLEAN Initialized;
} DRIVER_CONTEXT, *PDRIVER_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DRIVER_CONTEXT, GetDriverContext)

//
// Function prototypes
//

DRIVER_INITIALIZE DriverEntry;

EVT_WDF_DRIVER_DEVICE_ADD       Quac100EvtDeviceAdd;
EVT_WDF_OBJECT_CONTEXT_CLEANUP  Quac100EvtDriverContextCleanup;

//
// Debug helpers
//
#if DBG
#define QUAC_DEBUG_PRINT(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, \
               "QUAC100: " fmt "\n", ##__VA_ARGS__)
#else
#define QUAC_DEBUG_PRINT(fmt, ...)
#endif

#endif /* QUAC100_DRIVER_H */