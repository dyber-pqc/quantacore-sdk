/**
 * @file ioctl_win.c
 * @brief QuantaCore SDK - Windows IOCTL Interface Implementation
 *
 * Implements the Windows-specific DeviceIoControl interface for communicating
 * with the QUAC 100 kernel driver. Provides synchronous and asynchronous
 * (overlapped) I/O operations.
 *
 * IOCTL Command Categories:
 * - Device Control (0x800-0x81F): Info, reset, status
 * - Cryptographic Operations (0x820-0x87F): KEM, signatures, random
 * - Key Management (0x880-0x89F): Key storage operations
 * - DMA Management (0x8A0-0x8BF): Buffer allocation, mapping
 * - Diagnostics (0x8C0-0x8DF): Health, self-test, logging
 * - Batch Operations (0x8E0-0x8FF): Multi-operation submission
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "quac100.h"
#include "quac100_types.h"
#include "quac100_error.h"
#include "internal/quac100_ioctl.h"

/*=============================================================================
 * IOCTL Definitions
 *=============================================================================*/

/** QUAC device type */
#define FILE_DEVICE_QUAC 0x8000

/** IOCTL function code base */
#define QUAC_IOCTL_BASE 0x800

/** IOCTL access rights */
#define QUAC_IOCTL_ACCESS (FILE_READ_ACCESS | FILE_WRITE_ACCESS)

/** IOCTL method */
#define QUAC_IOCTL_METHOD METHOD_BUFFERED

/** Construct IOCTL code */
#define QUAC_CTL_CODE(func)                                \
    CTL_CODE(FILE_DEVICE_QUAC, (QUAC_IOCTL_BASE + (func)), \
             QUAC_IOCTL_METHOD, QUAC_IOCTL_ACCESS)

/*=============================================================================
 * IOCTL Command Codes
 *=============================================================================*/

/* Device Control (0x00-0x1F) */
#define IOCTL_QUAC_GET_INFO QUAC_CTL_CODE(0x00)
#define IOCTL_QUAC_GET_STATUS QUAC_CTL_CODE(0x01)
#define IOCTL_QUAC_RESET QUAC_CTL_CODE(0x02)
#define IOCTL_QUAC_GET_CAPS QUAC_CTL_CODE(0x03)
#define IOCTL_QUAC_SET_CONFIG QUAC_CTL_CODE(0x04)
#define IOCTL_QUAC_GET_CONFIG QUAC_CTL_CODE(0x05)
#define IOCTL_QUAC_SYNC QUAC_CTL_CODE(0x06)
#define IOCTL_QUAC_WAIT_IDLE QUAC_CTL_CODE(0x07)

/* Cryptographic Operations (0x20-0x7F) */
#define IOCTL_QUAC_KEM_KEYGEN QUAC_CTL_CODE(0x20)
#define IOCTL_QUAC_KEM_ENCAPS QUAC_CTL_CODE(0x21)
#define IOCTL_QUAC_KEM_DECAPS QUAC_CTL_CODE(0x22)
#define IOCTL_QUAC_SIGN_KEYGEN QUAC_CTL_CODE(0x30)
#define IOCTL_QUAC_SIGN QUAC_CTL_CODE(0x31)
#define IOCTL_QUAC_VERIFY QUAC_CTL_CODE(0x32)
#define IOCTL_QUAC_RANDOM QUAC_CTL_CODE(0x40)
#define IOCTL_QUAC_RANDOM_RESEED QUAC_CTL_CODE(0x41)

/* Key Management (0x80-0x9F) */
#define IOCTL_QUAC_KEY_GENERATE QUAC_CTL_CODE(0x80)
#define IOCTL_QUAC_KEY_IMPORT QUAC_CTL_CODE(0x81)
#define IOCTL_QUAC_KEY_EXPORT QUAC_CTL_CODE(0x82)
#define IOCTL_QUAC_KEY_DELETE QUAC_CTL_CODE(0x83)
#define IOCTL_QUAC_KEY_LIST QUAC_CTL_CODE(0x84)
#define IOCTL_QUAC_KEY_INFO QUAC_CTL_CODE(0x85)

/* DMA Management (0xA0-0xBF) */
#define IOCTL_QUAC_DMA_ALLOC QUAC_CTL_CODE(0xA0)
#define IOCTL_QUAC_DMA_FREE QUAC_CTL_CODE(0xA1)
#define IOCTL_QUAC_DMA_MAP QUAC_CTL_CODE(0xA2)
#define IOCTL_QUAC_DMA_UNMAP QUAC_CTL_CODE(0xA3)
#define IOCTL_QUAC_DMA_SYNC QUAC_CTL_CODE(0xA4)

/* Diagnostics (0xC0-0xDF) */
#define IOCTL_QUAC_GET_HEALTH QUAC_CTL_CODE(0xC0)
#define IOCTL_QUAC_SELF_TEST QUAC_CTL_CODE(0xC1)
#define IOCTL_QUAC_GET_TEMP QUAC_CTL_CODE(0xC2)
#define IOCTL_QUAC_GET_COUNTERS QUAC_CTL_CODE(0xC3)
#define IOCTL_QUAC_GET_LOG QUAC_CTL_CODE(0xC4)

/* Batch Operations (0xE0-0xFF) */
#define IOCTL_QUAC_BATCH_SUBMIT QUAC_CTL_CODE(0xE0)
#define IOCTL_QUAC_BATCH_POLL QUAC_CTL_CODE(0xE1)
#define IOCTL_QUAC_BATCH_WAIT QUAC_CTL_CODE(0xE2)
#define IOCTL_QUAC_BATCH_CANCEL QUAC_CTL_CODE(0xE3)

/*=============================================================================
 * IOCTL Data Structures
 *=============================================================================*/

#pragma pack(push, 1)

/**
 * @brief Device information structure
 */
typedef struct QUAC_IOCTL_DEVICE_INFO
{
    ULONG StructSize;
    ULONG DriverVersion;
    ULONG FirmwareVersion;
    ULONG HardwareVersion;
    CHAR Serial[32];
    CHAR Name[64];
    ULONG Capabilities;
    ULONG MaxBatchSize;
    ULONG MaxPendingJobs;
    ULONG KeySlots;
    ULONG PcieGen;
    ULONG PcieLanes;
} QUAC_IOCTL_DEVICE_INFO, *PQUAC_IOCTL_DEVICE_INFO;

/**
 * @brief Device status structure
 */
typedef struct QUAC_IOCTL_STATUS
{
    ULONG StructSize;
    ULONG State;
    ULONG PendingOps;
    ULONG CompletedOps;
    ULONG64 UptimeMs;
    LONG Temperature;
    ULONG PowerMw;
    ULONG EntropyBits;
} QUAC_IOCTL_STATUS, *PQUAC_IOCTL_STATUS;

/**
 * @brief KEM key generation request
 */
typedef struct QUAC_IOCTL_KEM_KEYGEN
{
    ULONG StructSize;
    ULONG Algorithm;
    ULONG64 PublicKey; /* User buffer pointer */
    ULONG PublicKeySize;
    ULONG64 SecretKey; /* User buffer pointer */
    ULONG SecretKeySize;
    ULONG Flags;
    LONG Result;        /* Output: operation result */
    ULONG64 DurationNs; /* Output: operation duration */
} QUAC_IOCTL_KEM_KEYGEN, *PQUAC_IOCTL_KEM_KEYGEN;

/**
 * @brief KEM encapsulation request
 */
typedef struct QUAC_IOCTL_KEM_ENCAPS
{
    ULONG StructSize;
    ULONG Algorithm;
    ULONG64 PublicKey;
    ULONG PublicKeySize;
    ULONG64 Ciphertext;
    ULONG CiphertextSize;
    ULONG64 SharedSecret;
    ULONG SharedSecretSize;
    ULONG Flags;
    LONG Result;
    ULONG64 DurationNs;
} QUAC_IOCTL_KEM_ENCAPS, *PQUAC_IOCTL_KEM_ENCAPS;

/**
 * @brief KEM decapsulation request
 */
typedef struct QUAC_IOCTL_KEM_DECAPS
{
    ULONG StructSize;
    ULONG Algorithm;
    ULONG64 SecretKey;
    ULONG SecretKeySize;
    ULONG64 Ciphertext;
    ULONG CiphertextSize;
    ULONG64 SharedSecret;
    ULONG SharedSecretSize;
    ULONG Flags;
    LONG Result;
    ULONG64 DurationNs;
} QUAC_IOCTL_KEM_DECAPS, *PQUAC_IOCTL_KEM_DECAPS;

/**
 * @brief Signature key generation request
 */
typedef struct QUAC_IOCTL_SIGN_KEYGEN
{
    ULONG StructSize;
    ULONG Algorithm;
    ULONG64 PublicKey;
    ULONG PublicKeySize;
    ULONG64 SecretKey;
    ULONG SecretKeySize;
    ULONG Flags;
    LONG Result;
    ULONG64 DurationNs;
} QUAC_IOCTL_SIGN_KEYGEN, *PQUAC_IOCTL_SIGN_KEYGEN;

/**
 * @brief Sign request
 */
typedef struct QUAC_IOCTL_SIGN
{
    ULONG StructSize;
    ULONG Algorithm;
    ULONG64 SecretKey;
    ULONG SecretKeySize;
    ULONG64 Message;
    ULONG MessageSize;
    ULONG64 Signature;
    ULONG SignatureSize; /* In/Out */
    ULONG Flags;
    LONG Result;
    ULONG64 DurationNs;
} QUAC_IOCTL_SIGN, *PQUAC_IOCTL_SIGN;

/**
 * @brief Verify request
 */
typedef struct QUAC_IOCTL_VERIFY
{
    ULONG StructSize;
    ULONG Algorithm;
    ULONG64 PublicKey;
    ULONG PublicKeySize;
    ULONG64 Message;
    ULONG MessageSize;
    ULONG64 Signature;
    ULONG SignatureSize;
    ULONG Flags;
    LONG Result; /* 0 = valid, -1 = invalid */
    ULONG64 DurationNs;
} QUAC_IOCTL_VERIFY, *PQUAC_IOCTL_VERIFY;

/**
 * @brief Random bytes request
 */
typedef struct QUAC_IOCTL_RANDOM
{
    ULONG StructSize;
    ULONG64 Buffer;
    ULONG Size;
    ULONG Quality;
    ULONG Flags;
    LONG Result;
    ULONG64 DurationNs;
} QUAC_IOCTL_RANDOM, *PQUAC_IOCTL_RANDOM;

/**
 * @brief DMA allocation request
 */
typedef struct QUAC_IOCTL_DMA_ALLOC
{
    ULONG StructSize;
    ULONG64 Size;
    ULONG Flags;
    ULONG64 Handle;   /* Output */
    ULONG64 PhysAddr; /* Output */
    ULONG64 UserVa;   /* Output: user-mode virtual address */
} QUAC_IOCTL_DMA_ALLOC, *PQUAC_IOCTL_DMA_ALLOC;

/**
 * @brief DMA sync request
 */
typedef struct QUAC_IOCTL_DMA_SYNC
{
    ULONG StructSize;
    ULONG64 Handle;
    ULONG64 Offset;
    ULONG64 Size;
    ULONG Direction;
} QUAC_IOCTL_DMA_SYNC, *PQUAC_IOCTL_DMA_SYNC;

/**
 * @brief Health status request
 */
typedef struct QUAC_IOCTL_HEALTH
{
    ULONG StructSize;
    ULONG State;
    ULONG Flags;
    LONG TempCore;
    LONG TempMemory;
    LONG TempBoard;
    ULONG VoltageCoreMv;
    ULONG VoltageMemMv;
    ULONG PowerMw;
    ULONG ClockMhz;
    ULONG64 EntropyAvailable;
    ULONG EntropySources;
    ULONG PcieErrors;
    ULONG64 OpsCompleted;
    ULONG64 OpsFailed;
} QUAC_IOCTL_HEALTH, *PQUAC_IOCTL_HEALTH;

/**
 * @brief Self-test request
 */
typedef struct QUAC_IOCTL_SELF_TEST
{
    ULONG StructSize;
    ULONG TestsToRun;
    ULONG TestsRun;        /* Output */
    ULONG TestsPassed;     /* Output */
    ULONG TestsFailed;     /* Output */
    ULONG OverallPassed;   /* Output */
    ULONG TotalDurationUs; /* Output */
} QUAC_IOCTL_SELF_TEST, *PQUAC_IOCTL_SELF_TEST;

/**
 * @brief Batch submission request
 */
typedef struct QUAC_IOCTL_BATCH
{
    ULONG StructSize;
    ULONG64 Items; /* Pointer to item array */
    ULONG ItemCount;
    ULONG Flags;
    ULONG64 BatchId; /* Output */
    ULONG Submitted; /* Output */
} QUAC_IOCTL_BATCH, *PQUAC_IOCTL_BATCH;

/**
 * @brief Batch poll request
 */
typedef struct QUAC_IOCTL_BATCH_POLL
{
    ULONG StructSize;
    ULONG64 BatchId;
    ULONG Status;    /* Output */
    ULONG Completed; /* Output */
    ULONG Failed;    /* Output */
} QUAC_IOCTL_BATCH_POLL, *PQUAC_IOCTL_BATCH_POLL;

/**
 * @brief Batch wait request
 */
typedef struct QUAC_IOCTL_BATCH_WAIT
{
    ULONG StructSize;
    ULONG64 BatchId;
    ULONG TimeoutMs;
    ULONG Status;    /* Output */
    ULONG Completed; /* Output */
    ULONG Failed;    /* Output */
    ULONG64 Results; /* Pointer to results array */
} QUAC_IOCTL_BATCH_WAIT, *PQUAC_IOCTL_BATCH_WAIT;

#pragma pack(pop)

/*=============================================================================
 * Constants
 *=============================================================================*/

/** Maximum IOCTL retries */
#define IOCTL_MAX_RETRIES 3

/** Default IOCTL timeout (ms) */
#define IOCTL_DEFAULT_TIMEOUT 5000

/*=============================================================================
 * Internal Helpers
 *=============================================================================*/

/**
 * @brief Map Windows error to quac_result_t
 */
static quac_result_t win_error_to_result(DWORD err)
{
    switch (err)
    {
    case ERROR_SUCCESS:
        return QUAC_SUCCESS;
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
        return QUAC_ERROR_DEVICE_NOT_FOUND;
    case ERROR_ACCESS_DENIED:
        return QUAC_ERROR_AUTHORIZATION;
    case ERROR_SHARING_VIOLATION:
    case ERROR_BUSY:
        return QUAC_ERROR_DEVICE_BUSY;
    case ERROR_INVALID_PARAMETER:
    case ERROR_INVALID_FUNCTION:
        return QUAC_ERROR_INVALID_PARAMETER;
    case ERROR_NOT_ENOUGH_MEMORY:
    case ERROR_OUTOFMEMORY:
        return QUAC_ERROR_OUT_OF_MEMORY;
    case ERROR_TIMEOUT:
    case WAIT_TIMEOUT:
        return QUAC_ERROR_TIMEOUT;
    case ERROR_NOT_SUPPORTED:
    case ERROR_CALL_NOT_IMPLEMENTED:
        return QUAC_ERROR_NOT_SUPPORTED;
    case ERROR_GEN_FAILURE:
    case ERROR_IO_DEVICE:
        return QUAC_ERROR_DEVICE_ERROR;
    case ERROR_OPERATION_ABORTED:
        return QUAC_ERROR_CANCELLED;
    default:
        return QUAC_ERROR_UNKNOWN;
    }
}

/**
 * @brief Execute synchronous DeviceIoControl
 */
static BOOL device_ioctl_sync(HANDLE handle, DWORD code,
                              LPVOID inBuf, DWORD inSize,
                              LPVOID outBuf, DWORD outSize,
                              LPDWORD bytesReturned)
{
    DWORD returned = 0;

    BOOL result = DeviceIoControl(handle, code,
                                  inBuf, inSize,
                                  outBuf, outSize,
                                  &returned, NULL);

    if (bytesReturned)
    {
        *bytesReturned = returned;
    }

    return result;
}

/**
 * @brief Execute asynchronous DeviceIoControl with timeout
 */
static quac_result_t device_ioctl_async(HANDLE handle, DWORD code,
                                        LPVOID inBuf, DWORD inSize,
                                        LPVOID outBuf, DWORD outSize,
                                        DWORD timeoutMs,
                                        LPDWORD bytesReturned)
{
    OVERLAPPED overlapped = {0};
    DWORD returned = 0;

    overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!overlapped.hEvent)
    {
        return win_error_to_result(GetLastError());
    }

    BOOL result = DeviceIoControl(handle, code,
                                  inBuf, inSize,
                                  outBuf, outSize,
                                  &returned, &overlapped);

    if (!result)
    {
        DWORD err = GetLastError();

        if (err == ERROR_IO_PENDING)
        {
            /* Wait for completion */
            DWORD waitResult = WaitForSingleObject(overlapped.hEvent, timeoutMs);

            if (waitResult == WAIT_OBJECT_0)
            {
                /* Get result */
                result = GetOverlappedResult(handle, &overlapped, &returned, FALSE);
                if (!result)
                {
                    err = GetLastError();
                }
            }
            else if (waitResult == WAIT_TIMEOUT)
            {
                /* Cancel I/O and return timeout */
                CancelIoEx(handle, &overlapped);
                CloseHandle(overlapped.hEvent);
                return QUAC_ERROR_TIMEOUT;
            }
            else
            {
                err = GetLastError();
                CloseHandle(overlapped.hEvent);
                return win_error_to_result(err);
            }
        }
        else
        {
            CloseHandle(overlapped.hEvent);
            return win_error_to_result(err);
        }
    }

    CloseHandle(overlapped.hEvent);

    if (bytesReturned)
    {
        *bytesReturned = returned;
    }

    return result ? QUAC_SUCCESS : win_error_to_result(GetLastError());
}

/*=============================================================================
 * Public API Implementation
 *=============================================================================*/

/**
 * @brief Execute generic IOCTL command
 */
quac_result_t quac_win_ioctl_execute(HANDLE handle, DWORD code,
                                     void *data, size_t size)
{
    if (handle == INVALID_HANDLE_VALUE)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    DWORD returned = 0;
    BOOL result = device_ioctl_sync(handle, code,
                                    data, (DWORD)size,
                                    data, (DWORD)size,
                                    &returned);

    if (!result)
    {
        return win_error_to_result(GetLastError());
    }

    return QUAC_SUCCESS;
}

/**
 * @brief Execute IOCTL with separate input/output buffers
 */
quac_result_t quac_win_ioctl_execute_ex(HANDLE handle, DWORD code,
                                        const void *inBuf, size_t inSize,
                                        void *outBuf, size_t outSize,
                                        size_t *bytesReturned)
{
    if (handle == INVALID_HANDLE_VALUE)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    DWORD returned = 0;
    BOOL result = device_ioctl_sync(handle, code,
                                    (LPVOID)inBuf, (DWORD)inSize,
                                    outBuf, (DWORD)outSize,
                                    &returned);

    if (bytesReturned)
    {
        *bytesReturned = returned;
    }

    if (!result)
    {
        return win_error_to_result(GetLastError());
    }

    return QUAC_SUCCESS;
}

/**
 * @brief Get device information via IOCTL
 */
quac_result_t quac_win_ioctl_get_device_info(HANDLE handle,
                                             quac_device_info_t *info)
{
    if (handle == INVALID_HANDLE_VALUE || !info)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    QUAC_IOCTL_DEVICE_INFO ioctlInfo = {0};
    ioctlInfo.StructSize = sizeof(ioctlInfo);

    DWORD returned = 0;
    BOOL result = device_ioctl_sync(handle, IOCTL_QUAC_GET_INFO,
                                    &ioctlInfo, sizeof(ioctlInfo),
                                    &ioctlInfo, sizeof(ioctlInfo),
                                    &returned);

    if (!result)
    {
        return win_error_to_result(GetLastError());
    }

    /* Convert to public structure */
    memset(info, 0, sizeof(*info));
    info->struct_size = sizeof(*info);

    strncpy_s(info->name, sizeof(info->name), ioctlInfo.Name, _TRUNCATE);
    strncpy_s(info->serial, sizeof(info->serial), ioctlInfo.Serial, _TRUNCATE);

    info->hardware_version = ioctlInfo.HardwareVersion;
    info->firmware_version = ioctlInfo.FirmwareVersion;
    info->driver_version = ioctlInfo.DriverVersion;
    info->capabilities = ioctlInfo.Capabilities;

    return QUAC_SUCCESS;
}

/**
 * @brief Get device status via IOCTL
 */
quac_result_t quac_win_ioctl_get_status(HANDLE handle,
                                        uint32_t *state,
                                        uint32_t *pending,
                                        uint32_t *completed)
{
    if (handle == INVALID_HANDLE_VALUE)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    QUAC_IOCTL_STATUS status = {0};
    status.StructSize = sizeof(status);

    DWORD returned = 0;
    BOOL result = device_ioctl_sync(handle, IOCTL_QUAC_GET_STATUS,
                                    &status, sizeof(status),
                                    &status, sizeof(status),
                                    &returned);

    if (!result)
    {
        return win_error_to_result(GetLastError());
    }

    if (state)
        *state = status.State;
    if (pending)
        *pending = status.PendingOps;
    if (completed)
        *completed = status.CompletedOps;

    return QUAC_SUCCESS;
}

/**
 * @brief Reset device via IOCTL
 */
quac_result_t quac_win_ioctl_reset(HANDLE handle, uint32_t resetType)
{
    if (handle == INVALID_HANDLE_VALUE)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    DWORD returned = 0;
    BOOL result = device_ioctl_sync(handle, IOCTL_QUAC_RESET,
                                    &resetType, sizeof(resetType),
                                    NULL, 0,
                                    &returned);

    if (!result)
    {
        return win_error_to_result(GetLastError());
    }

    return QUAC_SUCCESS;
}

/**
 * @brief Sync device (flush pending operations)
 */
quac_result_t quac_win_ioctl_sync(HANDLE handle)
{
    if (handle == INVALID_HANDLE_VALUE)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    DWORD returned = 0;
    BOOL result = device_ioctl_sync(handle, IOCTL_QUAC_SYNC,
                                    NULL, 0, NULL, 0, &returned);

    if (!result)
    {
        return win_error_to_result(GetLastError());
    }

    return QUAC_SUCCESS;
}

/*=============================================================================
 * KEM Operations
 *=============================================================================*/

quac_result_t quac_win_ioctl_kem_keygen(HANDLE handle, uint32_t algorithm,
                                        void *pk, size_t pkSize,
                                        void *sk, size_t skSize)
{
    if (handle == INVALID_HANDLE_VALUE || !pk || !sk)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    QUAC_IOCTL_KEM_KEYGEN req = {0};
    req.StructSize = sizeof(req);
    req.Algorithm = algorithm;
    req.PublicKey = (ULONG64)(ULONG_PTR)pk;
    req.PublicKeySize = (ULONG)pkSize;
    req.SecretKey = (ULONG64)(ULONG_PTR)sk;
    req.SecretKeySize = (ULONG)skSize;

    DWORD returned = 0;
    BOOL result = device_ioctl_sync(handle, IOCTL_QUAC_KEM_KEYGEN,
                                    &req, sizeof(req),
                                    &req, sizeof(req),
                                    &returned);

    if (!result)
    {
        return win_error_to_result(GetLastError());
    }

    return (quac_result_t)req.Result;
}

quac_result_t quac_win_ioctl_kem_encaps(HANDLE handle, uint32_t algorithm,
                                        const void *pk, size_t pkSize,
                                        void *ct, size_t ctSize,
                                        void *ss, size_t ssSize)
{
    if (handle == INVALID_HANDLE_VALUE || !pk || !ct || !ss)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    QUAC_IOCTL_KEM_ENCAPS req = {0};
    req.StructSize = sizeof(req);
    req.Algorithm = algorithm;
    req.PublicKey = (ULONG64)(ULONG_PTR)pk;
    req.PublicKeySize = (ULONG)pkSize;
    req.Ciphertext = (ULONG64)(ULONG_PTR)ct;
    req.CiphertextSize = (ULONG)ctSize;
    req.SharedSecret = (ULONG64)(ULONG_PTR)ss;
    req.SharedSecretSize = (ULONG)ssSize;

    DWORD returned = 0;
    BOOL result = device_ioctl_sync(handle, IOCTL_QUAC_KEM_ENCAPS,
                                    &req, sizeof(req),
                                    &req, sizeof(req),
                                    &returned);

    if (!result)
    {
        return win_error_to_result(GetLastError());
    }

    return (quac_result_t)req.Result;
}

quac_result_t quac_win_ioctl_kem_decaps(HANDLE handle, uint32_t algorithm,
                                        const void *sk, size_t skSize,
                                        const void *ct, size_t ctSize,
                                        void *ss, size_t ssSize)
{
    if (handle == INVALID_HANDLE_VALUE || !sk || !ct || !ss)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    QUAC_IOCTL_KEM_DECAPS req = {0};
    req.StructSize = sizeof(req);
    req.Algorithm = algorithm;
    req.SecretKey = (ULONG64)(ULONG_PTR)sk;
    req.SecretKeySize = (ULONG)skSize;
    req.Ciphertext = (ULONG64)(ULONG_PTR)ct;
    req.CiphertextSize = (ULONG)ctSize;
    req.SharedSecret = (ULONG64)(ULONG_PTR)ss;
    req.SharedSecretSize = (ULONG)ssSize;

    DWORD returned = 0;
    BOOL result = device_ioctl_sync(handle, IOCTL_QUAC_KEM_DECAPS,
                                    &req, sizeof(req),
                                    &req, sizeof(req),
                                    &returned);

    if (!result)
    {
        return win_error_to_result(GetLastError());
    }

    return (quac_result_t)req.Result;
}

/*=============================================================================
 * Signature Operations
 *=============================================================================*/

quac_result_t quac_win_ioctl_sign_keygen(HANDLE handle, uint32_t algorithm,
                                         void *pk, size_t pkSize,
                                         void *sk, size_t skSize)
{
    if (handle == INVALID_HANDLE_VALUE || !pk || !sk)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    QUAC_IOCTL_SIGN_KEYGEN req = {0};
    req.StructSize = sizeof(req);
    req.Algorithm = algorithm;
    req.PublicKey = (ULONG64)(ULONG_PTR)pk;
    req.PublicKeySize = (ULONG)pkSize;
    req.SecretKey = (ULONG64)(ULONG_PTR)sk;
    req.SecretKeySize = (ULONG)skSize;

    DWORD returned = 0;
    BOOL result = device_ioctl_sync(handle, IOCTL_QUAC_SIGN_KEYGEN,
                                    &req, sizeof(req),
                                    &req, sizeof(req),
                                    &returned);

    if (!result)
    {
        return win_error_to_result(GetLastError());
    }

    return (quac_result_t)req.Result;
}

quac_result_t quac_win_ioctl_sign(HANDLE handle, uint32_t algorithm,
                                  const void *sk, size_t skSize,
                                  const void *msg, size_t msgSize,
                                  void *sig, size_t *sigSize)
{
    if (handle == INVALID_HANDLE_VALUE || !sk || !msg || !sig || !sigSize)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    QUAC_IOCTL_SIGN req = {0};
    req.StructSize = sizeof(req);
    req.Algorithm = algorithm;
    req.SecretKey = (ULONG64)(ULONG_PTR)sk;
    req.SecretKeySize = (ULONG)skSize;
    req.Message = (ULONG64)(ULONG_PTR)msg;
    req.MessageSize = (ULONG)msgSize;
    req.Signature = (ULONG64)(ULONG_PTR)sig;
    req.SignatureSize = (ULONG)*sigSize;

    DWORD returned = 0;
    BOOL result = device_ioctl_sync(handle, IOCTL_QUAC_SIGN,
                                    &req, sizeof(req),
                                    &req, sizeof(req),
                                    &returned);

    if (!result)
    {
        return win_error_to_result(GetLastError());
    }

    *sigSize = req.SignatureSize;
    return (quac_result_t)req.Result;
}

quac_result_t quac_win_ioctl_verify(HANDLE handle, uint32_t algorithm,
                                    const void *pk, size_t pkSize,
                                    const void *msg, size_t msgSize,
                                    const void *sig, size_t sigSize)
{
    if (handle == INVALID_HANDLE_VALUE || !pk || !msg || !sig)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    QUAC_IOCTL_VERIFY req = {0};
    req.StructSize = sizeof(req);
    req.Algorithm = algorithm;
    req.PublicKey = (ULONG64)(ULONG_PTR)pk;
    req.PublicKeySize = (ULONG)pkSize;
    req.Message = (ULONG64)(ULONG_PTR)msg;
    req.MessageSize = (ULONG)msgSize;
    req.Signature = (ULONG64)(ULONG_PTR)sig;
    req.SignatureSize = (ULONG)sigSize;

    DWORD returned = 0;
    BOOL result = device_ioctl_sync(handle, IOCTL_QUAC_VERIFY,
                                    &req, sizeof(req),
                                    &req, sizeof(req),
                                    &returned);

    if (!result)
    {
        return win_error_to_result(GetLastError());
    }

    return (req.Result == 0) ? QUAC_SUCCESS : QUAC_ERROR_VERIFICATION_FAILED;
}

/*=============================================================================
 * Random Number Generation
 *=============================================================================*/

quac_result_t quac_win_ioctl_random(HANDLE handle, void *buffer, size_t size,
                                    uint32_t quality)
{
    if (handle == INVALID_HANDLE_VALUE || !buffer || size == 0)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    QUAC_IOCTL_RANDOM req = {0};
    req.StructSize = sizeof(req);
    req.Buffer = (ULONG64)(ULONG_PTR)buffer;
    req.Size = (ULONG)size;
    req.Quality = quality;

    DWORD returned = 0;
    BOOL result = device_ioctl_sync(handle, IOCTL_QUAC_RANDOM,
                                    &req, sizeof(req),
                                    &req, sizeof(req),
                                    &returned);

    if (!result)
    {
        return win_error_to_result(GetLastError());
    }

    return (quac_result_t)req.Result;
}

/*=============================================================================
 * DMA Operations
 *=============================================================================*/

quac_result_t quac_win_ioctl_dma_alloc(HANDLE handle, size_t size,
                                       uint32_t flags,
                                       uint64_t *dmaHandle,
                                       uint64_t *physAddr,
                                       void **userVa)
{
    if (handle == INVALID_HANDLE_VALUE || size == 0)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    QUAC_IOCTL_DMA_ALLOC req = {0};
    req.StructSize = sizeof(req);
    req.Size = (ULONG64)size;
    req.Flags = flags;

    DWORD returned = 0;
    BOOL result = device_ioctl_sync(handle, IOCTL_QUAC_DMA_ALLOC,
                                    &req, sizeof(req),
                                    &req, sizeof(req),
                                    &returned);

    if (!result)
    {
        return win_error_to_result(GetLastError());
    }

    if (dmaHandle)
        *dmaHandle = req.Handle;
    if (physAddr)
        *physAddr = req.PhysAddr;
    if (userVa)
        *userVa = (void *)(ULONG_PTR)req.UserVa;

    return QUAC_SUCCESS;
}

quac_result_t quac_win_ioctl_dma_free(HANDLE handle, uint64_t dmaHandle)
{
    if (handle == INVALID_HANDLE_VALUE)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    DWORD returned = 0;
    BOOL result = device_ioctl_sync(handle, IOCTL_QUAC_DMA_FREE,
                                    &dmaHandle, sizeof(dmaHandle),
                                    NULL, 0,
                                    &returned);

    if (!result)
    {
        return win_error_to_result(GetLastError());
    }

    return QUAC_SUCCESS;
}

quac_result_t quac_win_ioctl_dma_sync(HANDLE handle, uint64_t dmaHandle,
                                      uint64_t offset, size_t size,
                                      uint32_t direction)
{
    if (handle == INVALID_HANDLE_VALUE)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    QUAC_IOCTL_DMA_SYNC req = {0};
    req.StructSize = sizeof(req);
    req.Handle = dmaHandle;
    req.Offset = offset;
    req.Size = (ULONG64)size;
    req.Direction = direction;

    DWORD returned = 0;
    BOOL result = device_ioctl_sync(handle, IOCTL_QUAC_DMA_SYNC,
                                    &req, sizeof(req),
                                    NULL, 0,
                                    &returned);

    if (!result)
    {
        return win_error_to_result(GetLastError());
    }

    return QUAC_SUCCESS;
}

/*=============================================================================
 * Health and Diagnostics
 *=============================================================================*/

quac_result_t quac_win_ioctl_get_health(HANDLE handle,
                                        quac_health_status_t *status)
{
    if (handle == INVALID_HANDLE_VALUE || !status)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    QUAC_IOCTL_HEALTH req = {0};
    req.StructSize = sizeof(req);

    DWORD returned = 0;
    BOOL result = device_ioctl_sync(handle, IOCTL_QUAC_GET_HEALTH,
                                    &req, sizeof(req),
                                    &req, sizeof(req),
                                    &returned);

    if (!result)
    {
        return win_error_to_result(GetLastError());
    }

    /* Convert to public structure */
    memset(status, 0, sizeof(*status));
    status->struct_size = sizeof(*status);
    status->state = req.State;
    status->flags = req.Flags;
    status->temp_core_celsius = req.TempCore;
    status->temp_memory_celsius = req.TempMemory;
    status->temp_board_celsius = req.TempBoard;
    status->voltage_core_mv = req.VoltageCoreMv;
    status->power_draw_mw = req.PowerMw;
    status->clock_core_mhz = req.ClockMhz;
    status->entropy_available_bits = req.EntropyAvailable;
    status->entropy_sources_ok = req.EntropySources;
    status->pcie_errors = req.PcieErrors;
    status->operations_completed = req.OpsCompleted;
    status->operations_failed = req.OpsFailed;

    return QUAC_SUCCESS;
}

quac_result_t quac_win_ioctl_self_test(HANDLE handle, uint32_t tests,
                                       quac_self_test_summary_t *summary)
{
    if (handle == INVALID_HANDLE_VALUE || !summary)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    QUAC_IOCTL_SELF_TEST req = {0};
    req.StructSize = sizeof(req);
    req.TestsToRun = tests;

    DWORD returned = 0;
    BOOL result = device_ioctl_sync(handle, IOCTL_QUAC_SELF_TEST,
                                    &req, sizeof(req),
                                    &req, sizeof(req),
                                    &returned);

    if (!result)
    {
        return win_error_to_result(GetLastError());
    }

    /* Convert to public structure */
    memset(summary, 0, sizeof(*summary));
    summary->struct_size = sizeof(*summary);
    summary->tests_run = req.TestsRun;
    summary->tests_passed = req.TestsPassed;
    summary->tests_failed = req.TestsFailed;
    summary->overall_passed = (req.OverallPassed != 0);
    summary->total_duration_us = req.TotalDurationUs;

    return req.OverallPassed ? QUAC_SUCCESS : QUAC_ERROR_SELF_TEST_FAILED;
}

/*=============================================================================
 * Batch Operations
 *=============================================================================*/

quac_result_t quac_win_ioctl_batch_submit(HANDLE handle, void *items,
                                          uint32_t count, uint32_t flags,
                                          uint64_t *batchId)
{
    if (handle == INVALID_HANDLE_VALUE || !items || count == 0)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    QUAC_IOCTL_BATCH req = {0};
    req.StructSize = sizeof(req);
    req.Items = (ULONG64)(ULONG_PTR)items;
    req.ItemCount = count;
    req.Flags = flags;

    DWORD returned = 0;
    BOOL result = device_ioctl_sync(handle, IOCTL_QUAC_BATCH_SUBMIT,
                                    &req, sizeof(req),
                                    &req, sizeof(req),
                                    &returned);

    if (!result)
    {
        return win_error_to_result(GetLastError());
    }

    if (batchId)
        *batchId = req.BatchId;

    return QUAC_SUCCESS;
}

quac_result_t quac_win_ioctl_batch_poll(HANDLE handle, uint64_t batchId,
                                        uint32_t *status,
                                        uint32_t *completed,
                                        uint32_t *failed)
{
    if (handle == INVALID_HANDLE_VALUE)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    QUAC_IOCTL_BATCH_POLL req = {0};
    req.StructSize = sizeof(req);
    req.BatchId = batchId;

    DWORD returned = 0;
    BOOL result = device_ioctl_sync(handle, IOCTL_QUAC_BATCH_POLL,
                                    &req, sizeof(req),
                                    &req, sizeof(req),
                                    &returned);

    if (!result)
    {
        return win_error_to_result(GetLastError());
    }

    if (status)
        *status = req.Status;
    if (completed)
        *completed = req.Completed;
    if (failed)
        *failed = req.Failed;

    return QUAC_SUCCESS;
}

quac_result_t quac_win_ioctl_batch_wait(HANDLE handle, uint64_t batchId,
                                        uint32_t timeoutMs, void *results)
{
    if (handle == INVALID_HANDLE_VALUE)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    QUAC_IOCTL_BATCH_WAIT req = {0};
    req.StructSize = sizeof(req);
    req.BatchId = batchId;
    req.TimeoutMs = timeoutMs;
    req.Results = (ULONG64)(ULONG_PTR)results;

    return device_ioctl_async(handle, IOCTL_QUAC_BATCH_WAIT,
                              &req, sizeof(req),
                              &req, sizeof(req),
                              timeoutMs, NULL);
}

quac_result_t quac_win_ioctl_batch_cancel(HANDLE handle, uint64_t batchId)
{
    if (handle == INVALID_HANDLE_VALUE)
    {
        return QUAC_ERROR_INVALID_PARAMETER;
    }

    DWORD returned = 0;
    BOOL result = device_ioctl_sync(handle, IOCTL_QUAC_BATCH_CANCEL,
                                    &batchId, sizeof(batchId),
                                    NULL, 0,
                                    &returned);

    if (!result)
    {
        return win_error_to_result(GetLastError());
    }

    return QUAC_SUCCESS;
}

#endif /* _WIN32 */