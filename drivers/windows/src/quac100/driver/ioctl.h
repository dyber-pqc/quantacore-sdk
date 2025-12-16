/**
 * @file ioctl.h
 * @brief QUAC 100 KMDF Driver - IOCTL Handler Definitions
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_IOCTL_H
#define QUAC100_IOCTL_H

#include <ntddk.h>
#include <wdf.h>
#include "device.h"

//
// Include public IOCTL definitions
//
#include "../../include/quac100_ioctl.h"

//
// IOCTL dispatch function
//
NTSTATUS
Quac100DispatchIoctl(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ WDFREQUEST Request,
    _In_ ULONG IoControlCode,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    );

//
// Individual IOCTL handlers
//
NTSTATUS
Quac100IoctlGetVersion(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ WDFREQUEST Request,
    _Out_ size_t* BytesReturned
    );

NTSTATUS
Quac100IoctlGetInfo(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ WDFREQUEST Request,
    _Out_ size_t* BytesReturned
    );

NTSTATUS
Quac100IoctlKemKeygen(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ WDFREQUEST Request,
    _Out_ size_t* BytesReturned
    );

NTSTATUS
Quac100IoctlRandom(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ WDFREQUEST Request,
    _Out_ size_t* BytesReturned
    );

#endif /* QUAC100_IOCTL_H */