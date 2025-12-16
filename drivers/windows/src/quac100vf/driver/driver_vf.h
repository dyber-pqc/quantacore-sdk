/*
 * QUAC 100 VF Driver - Header
 * Copyright (c) 2024 Dyber, Inc. All rights reserved.
 */

#ifndef QUAC100VF_DRIVER_H
#define QUAC100VF_DRIVER_H

#include <ntddk.h>
#include <wdf.h>

/* VF-specific device interface GUID */
/* {A7B8C9D0-1234-5678-9ABC-DEF012345679} */
DEFINE_GUID(GUID_DEVINTERFACE_QUAC100VF,
    0xa7b8c9d0, 0x1234, 0x5678, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x79);

/* VF device context */
typedef struct _QUAC100VF_DEVICE_CONTEXT {
    WDFDEVICE               Device;
    WDFQUEUE                DefaultQueue;
    PHYSICAL_ADDRESS        BarBase;
    SIZE_T                  BarLength;
    PVOID                   BarMapped;
    UINT32                  VfIndex;
    BOOLEAN                 IsInitialized;
} QUAC100VF_DEVICE_CONTEXT, *PQUAC100VF_DEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(QUAC100VF_DEVICE_CONTEXT, Quac100VfGetDeviceContext)

/* Function declarations */
EVT_WDF_DRIVER_DEVICE_ADD Quac100VfEvtDeviceAdd;

#endif /* QUAC100VF_DRIVER_H */
