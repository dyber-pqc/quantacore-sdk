/**
 * @file quac100_ioctl.h
 * @brief QUAC 100 Public IOCTL Definitions
 *
 * This header defines the IOCTL interface between user-mode applications
 * and the QUAC 100 kernel driver.
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_PUBLIC_IOCTL_H
#define QUAC100_PUBLIC_IOCTL_H

#ifdef _WIN32
#include <windows.h>
#include <winioctl.h>
#else
#error "This header is Windows-specific"
#endif

#ifdef __cplusplus
extern "C" {
#endif

//
// Device type for QUAC 100 (vendor-defined range)
//
#define FILE_DEVICE_QUAC100     0x8000

//
// IOCTL Function codes
//
#define QUAC_FUNC_GET_VERSION           0x800
#define QUAC_FUNC_GET_INFO              0x801
#define QUAC_FUNC_GET_CAPS              0x802
#define QUAC_FUNC_GET_STATUS            0x803
#define QUAC_FUNC_RESET                 0x804

#define QUAC_FUNC_KEM_KEYGEN            0x840
#define QUAC_FUNC_KEM_ENCAPS            0x841
#define QUAC_FUNC_KEM_DECAPS            0x842

#define QUAC_FUNC_SIGN_KEYGEN           0x850
#define QUAC_FUNC_SIGN                  0x851
#define QUAC_FUNC_VERIFY                0x852

#define QUAC_FUNC_RANDOM                0x860
#define QUAC_FUNC_RANDOM_EX             0x861

#define QUAC_FUNC_ASYNC_SUBMIT          0x880
#define QUAC_FUNC_ASYNC_POLL            0x881
#define QUAC_FUNC_ASYNC_WAIT            0x882
#define QUAC_FUNC_ASYNC_CANCEL          0x883

#define QUAC_FUNC_BATCH_SUBMIT          0x890
#define QUAC_FUNC_BATCH_STATUS          0x891

#define QUAC_FUNC_KEY_GENERATE          0x8A0
#define QUAC_FUNC_KEY_IMPORT            0x8A1
#define QUAC_FUNC_KEY_EXPORT            0x8A2
#define QUAC_FUNC_KEY_DELETE            0x8A3
#define QUAC_FUNC_KEY_LIST              0x8A4

#define QUAC_FUNC_DIAG_SELF_TEST        0x8C0
#define QUAC_FUNC_DIAG_GET_HEALTH       0x8C1
#define QUAC_FUNC_DIAG_GET_TEMP         0x8C2
#define QUAC_FUNC_DIAG_GET_COUNTERS     0x8C3

//
// IOCTL Definitions
//

// Device Management
#define IOCTL_QUAC_GET_VERSION \
    CTL_CODE(FILE_DEVICE_QUAC100, QUAC_FUNC_GET_VERSION, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_QUAC_GET_INFO \
    CTL_CODE(FILE_DEVICE_QUAC100, QUAC_FUNC_GET_INFO, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_QUAC_GET_CAPS \
    CTL_CODE(FILE_DEVICE_QUAC100, QUAC_FUNC_GET_CAPS, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_QUAC_GET_STATUS \
    CTL_CODE(FILE_DEVICE_QUAC100, QUAC_FUNC_GET_STATUS, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_QUAC_RESET \
    CTL_CODE(FILE_DEVICE_QUAC100, QUAC_FUNC_RESET, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// KEM Operations
#define IOCTL_QUAC_KEM_KEYGEN \
    CTL_CODE(FILE_DEVICE_QUAC100, QUAC_FUNC_KEM_KEYGEN, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_QUAC_KEM_ENCAPS \
    CTL_CODE(FILE_DEVICE_QUAC100, QUAC_FUNC_KEM_ENCAPS, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_QUAC_KEM_DECAPS \
    CTL_CODE(FILE_DEVICE_QUAC100, QUAC_FUNC_KEM_DECAPS, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// Signature Operations
#define IOCTL_QUAC_SIGN_KEYGEN \
    CTL_CODE(FILE_DEVICE_QUAC100, QUAC_FUNC_SIGN_KEYGEN, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_QUAC_SIGN \
    CTL_CODE(FILE_DEVICE_QUAC100, QUAC_FUNC_SIGN, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_QUAC_VERIFY \
    CTL_CODE(FILE_DEVICE_QUAC100, QUAC_FUNC_VERIFY, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// Random Number Generation
#define IOCTL_QUAC_RANDOM \
    CTL_CODE(FILE_DEVICE_QUAC100, QUAC_FUNC_RANDOM, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_QUAC_RANDOM_EX \
    CTL_CODE(FILE_DEVICE_QUAC100, QUAC_FUNC_RANDOM_EX, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Async Operations
#define IOCTL_QUAC_ASYNC_SUBMIT \
    CTL_CODE(FILE_DEVICE_QUAC100, QUAC_FUNC_ASYNC_SUBMIT, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_QUAC_ASYNC_POLL \
    CTL_CODE(FILE_DEVICE_QUAC100, QUAC_FUNC_ASYNC_POLL, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_QUAC_ASYNC_WAIT \
    CTL_CODE(FILE_DEVICE_QUAC100, QUAC_FUNC_ASYNC_WAIT, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_QUAC_ASYNC_CANCEL \
    CTL_CODE(FILE_DEVICE_QUAC100, QUAC_FUNC_ASYNC_CANCEL, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// Batch Operations
#define IOCTL_QUAC_BATCH_SUBMIT \
    CTL_CODE(FILE_DEVICE_QUAC100, QUAC_FUNC_BATCH_SUBMIT, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_QUAC_BATCH_STATUS \
    CTL_CODE(FILE_DEVICE_QUAC100, QUAC_FUNC_BATCH_STATUS, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Key Management
#define IOCTL_QUAC_KEY_GENERATE \
    CTL_CODE(FILE_DEVICE_QUAC100, QUAC_FUNC_KEY_GENERATE, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_QUAC_KEY_IMPORT \
    CTL_CODE(FILE_DEVICE_QUAC100, QUAC_FUNC_KEY_IMPORT, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_QUAC_KEY_EXPORT \
    CTL_CODE(FILE_DEVICE_QUAC100, QUAC_FUNC_KEY_EXPORT, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_QUAC_KEY_DELETE \
    CTL_CODE(FILE_DEVICE_QUAC100, QUAC_FUNC_KEY_DELETE, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_QUAC_KEY_LIST \
    CTL_CODE(FILE_DEVICE_QUAC100, QUAC_FUNC_KEY_LIST, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Diagnostics
#define IOCTL_QUAC_DIAG_SELF_TEST \
    CTL_CODE(FILE_DEVICE_QUAC100, QUAC_FUNC_DIAG_SELF_TEST, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define IOCTL_QUAC_DIAG_GET_HEALTH \
    CTL_CODE(FILE_DEVICE_QUAC100, QUAC_FUNC_DIAG_GET_HEALTH, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_QUAC_DIAG_GET_TEMP \
    CTL_CODE(FILE_DEVICE_QUAC100, QUAC_FUNC_DIAG_GET_TEMP, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_QUAC_DIAG_GET_COUNTERS \
    CTL_CODE(FILE_DEVICE_QUAC100, QUAC_FUNC_DIAG_GET_COUNTERS, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Algorithm Identifiers (matches SDK definitions)
//
typedef enum _QUAC_ALGORITHM {
    QUAC_ALG_NONE = 0x0000,
    
    // ML-KEM (Kyber)
    QUAC_ALG_KYBER512 = 0x1100,
    QUAC_ALG_KYBER768 = 0x1101,
    QUAC_ALG_KYBER1024 = 0x1102,
    
    // ML-DSA (Dilithium)
    QUAC_ALG_DILITHIUM2 = 0x2100,
    QUAC_ALG_DILITHIUM3 = 0x2101,
    QUAC_ALG_DILITHIUM5 = 0x2102,
    
    // SLH-DSA (SPHINCS+)
    QUAC_ALG_SPHINCS_SHA2_128S = 0x2200,
    QUAC_ALG_SPHINCS_SHA2_128F = 0x2201,
    QUAC_ALG_SPHINCS_SHA2_192S = 0x2202,
    QUAC_ALG_SPHINCS_SHA2_192F = 0x2203,
    QUAC_ALG_SPHINCS_SHA2_256S = 0x2204,
    QUAC_ALG_SPHINCS_SHA2_256F = 0x2205,
} QUAC_ALGORITHM;

//
// Result/Status codes
//
typedef enum _QUAC_STATUS {
    QUAC_STATUS_SUCCESS = 0,
    QUAC_STATUS_ERROR = 1,
    QUAC_STATUS_INVALID_PARAMETER = 2,
    QUAC_STATUS_BUFFER_TOO_SMALL = 3,
    QUAC_STATUS_NOT_SUPPORTED = 4,
    QUAC_STATUS_DEVICE_ERROR = 5,
    QUAC_STATUS_TIMEOUT = 6,
    QUAC_STATUS_BUSY = 7,
} QUAC_STATUS;

//
// IOCTL Input/Output Structures
//

#pragma pack(push, 8)

typedef struct _QUAC_VERSION_INFO {
    ULONG StructSize;
    ULONG DriverVersionMajor;
    ULONG DriverVersionMinor;
    ULONG DriverVersionPatch;
    ULONG DriverVersionBuild;
    ULONG FirmwareVersionMajor;
    ULONG FirmwareVersionMinor;
    ULONG FirmwareVersionPatch;
    ULONG ApiVersion;
} QUAC_VERSION_INFO, *PQUAC_VERSION_INFO;

typedef struct _QUAC_DEVICE_INFO {
    ULONG StructSize;
    ULONG DeviceIndex;
    WCHAR DeviceName[64];
    WCHAR SerialNumber[32];
    USHORT VendorId;
    USHORT DeviceId;
    USHORT SubsystemId;
    UCHAR HardwareRevision;
    ULONG Capabilities;
    ULONG Status;
    ULONG MaxBatchSize;
    ULONG MaxPendingJobs;
    ULONG KeySlotsTotal;
    ULONG KeySlotsUsed;
    LONG TemperatureCelsius;
    ULONG EntropyAvailable;
    ULONGLONG OperationsCompleted;
    ULONGLONG OperationsFailed;
} QUAC_DEVICE_INFO, *PQUAC_DEVICE_INFO;

typedef struct _QUAC_KEM_KEYGEN_REQUEST {
    ULONG StructSize;
    QUAC_ALGORITHM Algorithm;
    ULONG Flags;
    ULONG PublicKeySize;
    ULONG SecretKeySize;
    // Variable-length output follows
} QUAC_KEM_KEYGEN_REQUEST, *PQUAC_KEM_KEYGEN_REQUEST;

typedef struct _QUAC_KEM_ENCAPS_REQUEST {
    ULONG StructSize;
    QUAC_ALGORITHM Algorithm;
    ULONG Flags;
    ULONG PublicKeyOffset;
    ULONG PublicKeySize;
    ULONG CiphertextSize;
    ULONG SharedSecretSize;
    // Variable-length data follows
} QUAC_KEM_ENCAPS_REQUEST, *PQUAC_KEM_ENCAPS_REQUEST;

typedef struct _QUAC_KEM_DECAPS_REQUEST {
    ULONG StructSize;
    QUAC_ALGORITHM Algorithm;
    ULONG Flags;
    ULONG CiphertextOffset;
    ULONG CiphertextSize;
    ULONG SecretKeyOffset;
    ULONG SecretKeySize;
    ULONG SharedSecretSize;
    // Variable-length data follows
} QUAC_KEM_DECAPS_REQUEST, *PQUAC_KEM_DECAPS_REQUEST;

typedef struct _QUAC_SIGN_KEYGEN_REQUEST {
    ULONG StructSize;
    QUAC_ALGORITHM Algorithm;
    ULONG Flags;
    ULONG PublicKeySize;
    ULONG SecretKeySize;
} QUAC_SIGN_KEYGEN_REQUEST, *PQUAC_SIGN_KEYGEN_REQUEST;

typedef struct _QUAC_SIGN_REQUEST {
    ULONG StructSize;
    QUAC_ALGORITHM Algorithm;
    ULONG Flags;
    ULONG SecretKeyOffset;
    ULONG SecretKeySize;
    ULONG MessageOffset;
    ULONG MessageSize;
    ULONG SignatureSize;
    ULONG ContextOffset;
    ULONG ContextSize;
} QUAC_SIGN_REQUEST, *PQUAC_SIGN_REQUEST;

typedef struct _QUAC_VERIFY_REQUEST {
    ULONG StructSize;
    QUAC_ALGORITHM Algorithm;
    ULONG Flags;
    ULONG PublicKeyOffset;
    ULONG PublicKeySize;
    ULONG MessageOffset;
    ULONG MessageSize;
    ULONG SignatureOffset;
    ULONG SignatureSize;
    ULONG ContextOffset;
    ULONG ContextSize;
} QUAC_VERIFY_REQUEST, *PQUAC_VERIFY_REQUEST;

typedef struct _QUAC_RANDOM_REQUEST {
    ULONG StructSize;
    ULONG Length;
    ULONG Quality;
    ULONG Flags;
} QUAC_RANDOM_REQUEST, *PQUAC_RANDOM_REQUEST;

typedef struct _QUAC_ASYNC_SUBMIT_REQUEST {
    ULONG StructSize;
    ULONG Operation;
    QUAC_ALGORITHM Algorithm;
    ULONG Priority;
    ULONG TimeoutMs;
    ULONG InputOffset;
    ULONG InputSize;
    ULONG OutputSize;
    ULONGLONG JobId;  // Output
} QUAC_ASYNC_SUBMIT_REQUEST, *PQUAC_ASYNC_SUBMIT_REQUEST;

typedef struct _QUAC_ASYNC_POLL_REQUEST {
    ULONG StructSize;
    ULONGLONG JobId;
    ULONG Status;       // Output
    ULONG Progress;     // Output
    QUAC_STATUS Result; // Output
} QUAC_ASYNC_POLL_REQUEST, *PQUAC_ASYNC_POLL_REQUEST;

typedef struct _QUAC_HEALTH_INFO {
    ULONG StructSize;
    ULONG HealthState;
    ULONG HealthFlags;
    LONG TemperatureCore;
    LONG TemperatureMemory;
    ULONG VoltageCoreMv;
    ULONG PowerDrawMw;
    ULONG ClockMhz;
    ULONG EntropyAvailable;
    ULONGLONG UptimeSeconds;
    ULONGLONG OpsCompleted;
    ULONGLONG OpsFailed;
} QUAC_HEALTH_INFO, *PQUAC_HEALTH_INFO;

typedef struct _QUAC_SELF_TEST_REQUEST {
    ULONG StructSize;
    ULONG TestsToRun;
    ULONG TestsPassed;    // Output
    ULONG TestsFailed;    // Output
    ULONG DurationUs;     // Output
    QUAC_STATUS Result;   // Output
} QUAC_SELF_TEST_REQUEST, *PQUAC_SELF_TEST_REQUEST;

#pragma pack(pop)

//
// Capability flags
//
#define QUAC_CAP_KEM_KYBER          0x00000001
#define QUAC_CAP_SIGN_DILITHIUM     0x00000002
#define QUAC_CAP_SIGN_SPHINCS       0x00000004
#define QUAC_CAP_QRNG               0x00000008
#define QUAC_CAP_KEY_STORAGE        0x00000010
#define QUAC_CAP_ASYNC              0x00000020
#define QUAC_CAP_BATCH              0x00000040
#define QUAC_CAP_DMA                0x00000080
#define QUAC_CAP_SRIOV              0x00000100
#define QUAC_CAP_FIPS               0x00000200

//
// Device status flags
//
#define QUAC_DEV_STATUS_OK              0x00000000
#define QUAC_DEV_STATUS_BUSY            0x00000001
#define QUAC_DEV_STATUS_ERROR           0x00000002
#define QUAC_DEV_STATUS_INITIALIZING    0x00000004
#define QUAC_DEV_STATUS_SELF_TEST       0x00000008
#define QUAC_DEV_STATUS_LOW_ENTROPY     0x00000010
#define QUAC_DEV_STATUS_TEMP_WARNING    0x00000020

//
// Self-test flags
//
#define QUAC_TEST_KAT_KEM           0x00000001
#define QUAC_TEST_KAT_SIGN          0x00000002
#define QUAC_TEST_KAT_ALL           0x00000003
#define QUAC_TEST_HW_MEMORY         0x00000100
#define QUAC_TEST_HW_DMA            0x00000200
#define QUAC_TEST_HW_ALL            0x00000F00
#define QUAC_TEST_ENTROPY           0x00001000
#define QUAC_TEST_ALL               0x0000FFFF

#ifdef __cplusplus
}
#endif

#endif /* QUAC100_PUBLIC_IOCTL_H */