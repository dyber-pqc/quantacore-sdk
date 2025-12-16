/**
 * @file queue.h
 * @brief QUAC 100 KMDF Driver - I/O Queue Definitions
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_QUEUE_H
#define QUAC100_QUEUE_H

#include <ntddk.h>
#include <wdf.h>

//
// Queue context
//
typedef struct _QUEUE_CONTEXT {
    WDFQUEUE Queue;
    WDFDEVICE Device;
} QUEUE_CONTEXT, *PQUEUE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(QUEUE_CONTEXT, GetQueueContext)

//
// Function prototypes
//

NTSTATUS
Quac100QueueInitialize(
    _In_ WDFDEVICE Device
    );

EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL Quac100EvtIoDeviceControl;
EVT_WDF_IO_QUEUE_IO_STOP           Quac100EvtIoStop;

#endif /* QUAC100_QUEUE_H */