# QUAC 100 IOCTL Reference

This document provides a complete reference for all IOCTLs supported by the QUAC 100 Windows driver.

## Overview

The QUAC 100 driver communicates with user-mode applications through Device I/O Control (IOCTL) requests. Applications use the `DeviceIoControl` Win32 API or the `quac100lib.dll` wrapper library.

### IOCTL Format

All QUAC 100 IOCTLs follow the Windows IOCTL format:
```
CTL_CODE(DeviceType, Function, Method, Access)
```

- **DeviceType**: FILE_DEVICE_UNKNOWN (0x22)
- **Function**: 0x800 - 0x8FF (vendor-defined range)
- **Method**: METHOD_BUFFERED or METHOD_IN_DIRECT/METHOD_OUT_DIRECT
- **Access**: FILE_ANY_ACCESS, FILE_READ_ACCESS, FILE_WRITE_ACCESS

## Device IOCTLs

### IOCTL_QUAC_GET_VERSION

Get driver and firmware version information.

```c
#define IOCTL_QUAC_GET_VERSION  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
```

**Input**: None

**Output**:
```c
typedef struct _QUAC_VERSION_INFO {
    UINT32 DriverVersionMajor;
    UINT32 DriverVersionMinor;
    UINT32 DriverVersionPatch;
    UINT32 DriverVersionBuild;
    UINT32 FirmwareVersionMajor;
    UINT32 FirmwareVersionMinor;
    UINT32 FirmwareVersionPatch;
    UINT32 HardwareRevision;
    CHAR   DriverVersionString[64];
    CHAR   FirmwareVersionString[64];
} QUAC_VERSION_INFO, *PQUAC_VERSION_INFO;
```

**Example**:
```c
QUAC_VERSION_INFO version;
DWORD bytesReturned;

DeviceIoControl(hDevice, IOCTL_QUAC_GET_VERSION,
    NULL, 0,
    &version, sizeof(version),
    &bytesReturned, NULL);

printf("Driver: %s\n", version.DriverVersionString);
printf("Firmware: %s\n", version.FirmwareVersionString);
```

---

### IOCTL_QUAC_GET_INFO

Get device capabilities and configuration.

```c
#define IOCTL_QUAC_GET_INFO  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
```

**Input**: None

**Output**:
```c
typedef struct _QUAC_DEVICE_INFO {
    UINT32 Capabilities;         // QUAC_CAP_* flags
    UINT32 MaxConcurrentOps;     // Max parallel operations
    UINT32 DmaChannels;          // Number of DMA channels
    UINT32 QrngPoolSize;         // QRNG buffer size
    UINT64 SerialNumber;         // Device serial number
    UINT32 TemperatureCelsius;   // Current temperature
    UINT32 PowerStateMilliwatts; // Current power consumption
    CHAR   DeviceName[64];       // Friendly name
} QUAC_DEVICE_INFO, *PQUAC_DEVICE_INFO;

// Capability flags
#define QUAC_CAP_KEM_KYBER512    0x00000001
#define QUAC_CAP_KEM_KYBER768    0x00000002
#define QUAC_CAP_KEM_KYBER1024   0x00000004
#define QUAC_CAP_SIGN_DILITHIUM2 0x00000010
#define QUAC_CAP_SIGN_DILITHIUM3 0x00000020
#define QUAC_CAP_SIGN_DILITHIUM5 0x00000040
#define QUAC_CAP_SIGN_SPHINCS    0x00000080
#define QUAC_CAP_QRNG            0x00000100
#define QUAC_CAP_KEY_STORAGE     0x00000200
#define QUAC_CAP_SRIOV           0x00000400
```

---

### IOCTL_QUAC_RESET

Reset the device to default state.

```c
#define IOCTL_QUAC_RESET  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_WRITE_ACCESS)
```

**Input**: None (or optional reset flags)

**Output**: None

**Notes**: 
- Aborts all pending operations
- Clears internal buffers
- Re-initializes crypto engines

---

## KEM IOCTLs

### IOCTL_QUAC_KEM_KEYGEN

Generate a KEM key pair.

```c
#define IOCTL_QUAC_KEM_KEYGEN  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
```

**Input**:
```c
typedef struct _QUAC_KEM_KEYGEN_INPUT {
    UINT32 Algorithm;  // QUAC_KEM_KYBER512/768/1024
} QUAC_KEM_KEYGEN_INPUT;
```

**Output**:
```c
typedef struct _QUAC_KEM_KEYGEN_OUTPUT {
    UINT32 PublicKeySize;
    UINT32 SecretKeySize;
    BYTE   Keys[];  // PublicKey followed by SecretKey
} QUAC_KEM_KEYGEN_OUTPUT;
```

**Algorithm Sizes**:
| Algorithm | Public Key | Secret Key |
|-----------|-----------|------------|
| Kyber512  | 800 | 1632 |
| Kyber768  | 1184 | 2400 |
| Kyber1024 | 1568 | 3168 |

**Example**:
```c
QUAC_KEM_KEYGEN_INPUT input = { QUAC_KEM_KYBER768 };
BYTE output[4096];
DWORD bytesReturned;

DeviceIoControl(hDevice, IOCTL_QUAC_KEM_KEYGEN,
    &input, sizeof(input),
    output, sizeof(output),
    &bytesReturned, NULL);

QUAC_KEM_KEYGEN_OUTPUT* result = (QUAC_KEM_KEYGEN_OUTPUT*)output;
BYTE* publicKey = result->Keys;
BYTE* secretKey = result->Keys + result->PublicKeySize;
```

---

### IOCTL_QUAC_KEM_ENCAPS

Encapsulate a shared secret using a public key.

```c
#define IOCTL_QUAC_KEM_ENCAPS  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)
```

**Input**:
```c
typedef struct _QUAC_KEM_ENCAPS_INPUT {
    UINT32 Algorithm;
    UINT32 PublicKeySize;
    BYTE   PublicKey[];
} QUAC_KEM_ENCAPS_INPUT;
```

**Output**:
```c
typedef struct _QUAC_KEM_ENCAPS_OUTPUT {
    UINT32 CiphertextSize;
    UINT32 SharedSecretSize;  // Always 32 bytes
    BYTE   Data[];  // Ciphertext followed by SharedSecret
} QUAC_KEM_ENCAPS_OUTPUT;
```

**Ciphertext Sizes**:
| Algorithm | Ciphertext |
|-----------|-----------|
| Kyber512  | 768 |
| Kyber768  | 1088 |
| Kyber1024 | 1568 |

---

### IOCTL_QUAC_KEM_DECAPS

Decapsulate to recover the shared secret.

```c
#define IOCTL_QUAC_KEM_DECAPS  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)
```

**Input**:
```c
typedef struct _QUAC_KEM_DECAPS_INPUT {
    UINT32 Algorithm;
    UINT32 SecretKeySize;
    UINT32 CiphertextSize;
    BYTE   Data[];  // SecretKey followed by Ciphertext
} QUAC_KEM_DECAPS_INPUT;
```

**Output**:
```c
typedef struct _QUAC_KEM_DECAPS_OUTPUT {
    UINT32 SharedSecretSize;  // Always 32 bytes
    BYTE   SharedSecret[32];
} QUAC_KEM_DECAPS_OUTPUT;
```

---

## Signature IOCTLs

### IOCTL_QUAC_SIGN_KEYGEN

Generate a signature key pair.

```c
#define IOCTL_QUAC_SIGN_KEYGEN  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x820, METHOD_BUFFERED, FILE_ANY_ACCESS)
```

**Input**:
```c
typedef struct _QUAC_SIGN_KEYGEN_INPUT {
    UINT32 Algorithm;  // QUAC_SIGN_DILITHIUM2/3/5 or SPHINCS+ variants
} QUAC_SIGN_KEYGEN_INPUT;
```

**Output**:
```c
typedef struct _QUAC_SIGN_KEYGEN_OUTPUT {
    UINT32 PublicKeySize;
    UINT32 SecretKeySize;
    BYTE   Keys[];  // PublicKey followed by SecretKey
} QUAC_SIGN_KEYGEN_OUTPUT;
```

**Algorithm Sizes**:
| Algorithm | Public Key | Secret Key |
|-----------|-----------|------------|
| Dilithium2 | 1312 | 2528 |
| Dilithium3 | 1952 | 4000 |
| Dilithium5 | 2592 | 4864 |
| SPHINCS+-128s | 32 | 64 |
| SPHINCS+-128f | 32 | 64 |
| SPHINCS+-192s | 48 | 96 |
| SPHINCS+-192f | 48 | 96 |
| SPHINCS+-256s | 64 | 128 |
| SPHINCS+-256f | 64 | 128 |

---

### IOCTL_QUAC_SIGN

Sign a message.

```c
#define IOCTL_QUAC_SIGN  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x821, METHOD_IN_DIRECT, FILE_ANY_ACCESS)
```

**Input**:
```c
typedef struct _QUAC_SIGN_INPUT {
    UINT32 Algorithm;
    UINT32 SecretKeySize;
    UINT32 MessageSize;
    UINT32 ContextSize;  // Optional, 0-255 bytes
    BYTE   Data[];       // SecretKey || Context || Message
} QUAC_SIGN_INPUT;
```

**Output**:
```c
typedef struct _QUAC_SIGN_OUTPUT {
    UINT32 SignatureSize;
    BYTE   Signature[];
} QUAC_SIGN_OUTPUT;
```

**Signature Sizes**:
| Algorithm | Max Signature |
|-----------|--------------|
| Dilithium2 | 2420 |
| Dilithium3 | 3293 |
| Dilithium5 | 4595 |
| SPHINCS+-128s | 7856 |
| SPHINCS+-128f | 17088 |
| SPHINCS+-192s | 16224 |
| SPHINCS+-192f | 35664 |
| SPHINCS+-256s | 29792 |
| SPHINCS+-256f | 49856 |

---

### IOCTL_QUAC_VERIFY

Verify a signature.

```c
#define IOCTL_QUAC_VERIFY  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x822, METHOD_IN_DIRECT, FILE_READ_ACCESS)
```

**Input**:
```c
typedef struct _QUAC_VERIFY_INPUT {
    UINT32 Algorithm;
    UINT32 PublicKeySize;
    UINT32 SignatureSize;
    UINT32 MessageSize;
    UINT32 ContextSize;
    BYTE   Data[];  // PublicKey || Signature || Context || Message
} QUAC_VERIFY_INPUT;
```

**Output**:
```c
typedef struct _QUAC_VERIFY_OUTPUT {
    UINT32 Valid;  // 1 = valid, 0 = invalid
} QUAC_VERIFY_OUTPUT;
```

---

## QRNG IOCTLs

### IOCTL_QUAC_RANDOM

Generate quantum random bytes.

```c
#define IOCTL_QUAC_RANDOM  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x830, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
```

**Input**:
```c
typedef struct _QUAC_RANDOM_INPUT {
    UINT32 RequestedBytes;  // Max 65536
    UINT32 Quality;         // QUAC_RNG_QUALITY_*
} QUAC_RANDOM_INPUT;

#define QUAC_RNG_QUALITY_FAST   0  // Fastest, less post-processing
#define QUAC_RNG_QUALITY_NORMAL 1  // Balanced
#define QUAC_RNG_QUALITY_HIGH   2  // Maximum quality
#define QUAC_RNG_QUALITY_FIPS   3  // FIPS 140-3 compliant
```

**Output**: Raw random bytes (length = RequestedBytes)

**Notes**:
- Maximum 64 KB per request
- Higher quality = slower generation
- FIPS mode performs continuous testing

---

### IOCTL_QUAC_RNG_STATUS

Get QRNG status and health.

```c
#define IOCTL_QUAC_RNG_STATUS  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x831, METHOD_BUFFERED, FILE_ANY_ACCESS)
```

**Input**: None

**Output**:
```c
typedef struct _QUAC_RNG_STATUS {
    UINT32 State;           // QUAC_RNG_STATE_*
    UINT32 Health;          // QUAC_RNG_HEALTH_*
    UINT32 EntropyBits;     // Available entropy
    UINT32 TotalGenerated;  // Total bytes generated
    UINT32 HealthTestsPassed;
    UINT32 HealthTestsFailed;
    UINT32 ReseedCount;
} QUAC_RNG_STATUS;

#define QUAC_RNG_STATE_DISABLED    0
#define QUAC_RNG_STATE_INITIALIZING 1
#define QUAC_RNG_STATE_READY       2
#define QUAC_RNG_STATE_ERROR       3

#define QUAC_RNG_HEALTH_OK        0
#define QUAC_RNG_HEALTH_WARNING   1
#define QUAC_RNG_HEALTH_DEGRADED  2
#define QUAC_RNG_HEALTH_FAILED    3
```

---

### IOCTL_QUAC_RNG_HEALTH

Trigger a health check.

```c
#define IOCTL_QUAC_RNG_HEALTH  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x832, METHOD_BUFFERED, FILE_ANY_ACCESS)
```

**Input**: None

**Output**:
```c
typedef struct _QUAC_RNG_HEALTH_RESULT {
    UINT32 Passed;        // 1 = passed, 0 = failed
    UINT32 TestsRun;      // Number of tests executed
    UINT32 TestsPassed;   // Number that passed
    CHAR   Details[256];  // Human-readable details
} QUAC_RNG_HEALTH_RESULT;
```

---

## Diagnostic IOCTLs

### IOCTL_QUAC_SELFTEST

Run hardware self-test.

```c
#define IOCTL_QUAC_SELFTEST  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x840, METHOD_BUFFERED, FILE_ANY_ACCESS)
```

**Input**:
```c
typedef struct _QUAC_SELFTEST_INPUT {
    UINT32 TestMask;  // QUAC_TEST_* flags, 0 = all tests
} QUAC_SELFTEST_INPUT;

#define QUAC_TEST_REGISTERS  0x00000001
#define QUAC_TEST_MEMORY     0x00000002
#define QUAC_TEST_DMA        0x00000004
#define QUAC_TEST_KEM        0x00000008
#define QUAC_TEST_SIGN       0x00000010
#define QUAC_TEST_QRNG       0x00000020
#define QUAC_TEST_ALL        0xFFFFFFFF
```

**Output**:
```c
typedef struct _QUAC_SELFTEST_RESULT {
    UINT32 Passed;
    UINT32 TestsRun;
    UINT32 TestsPassed;
    UINT32 FailedTestMask;
    CHAR   Details[512];
} QUAC_SELFTEST_RESULT;
```

---

### IOCTL_QUAC_GET_STATS

Get performance statistics.

```c
#define IOCTL_QUAC_GET_STATS  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x841, METHOD_BUFFERED, FILE_ANY_ACCESS)
```

**Input**: None

**Output**:
```c
typedef struct _QUAC_STATISTICS {
    UINT64 KemOperations;
    UINT64 SignOperations;
    UINT64 VerifyOperations;
    UINT64 RandomBytesGenerated;
    UINT64 DmaBytesTransferred;
    UINT64 InterruptsHandled;
    UINT64 ErrorsDetected;
    UINT64 UptimeSeconds;
    // Performance metrics
    UINT32 AvgKemLatencyUs;
    UINT32 AvgSignLatencyUs;
    UINT32 AvgVerifyLatencyUs;
    UINT32 QrngThroughputKBps;
} QUAC_STATISTICS;
```

---

### IOCTL_QUAC_RESET_STATS

Reset statistics counters.

```c
#define IOCTL_QUAC_RESET_STATS  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x842, METHOD_BUFFERED, FILE_WRITE_ACCESS)
```

**Input**: None
**Output**: None

---

## Async IOCTLs

### IOCTL_QUAC_ASYNC_SUBMIT

Submit an asynchronous operation.

```c
#define IOCTL_QUAC_ASYNC_SUBMIT  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x850, METHOD_BUFFERED, FILE_ANY_ACCESS)
```

**Input**:
```c
typedef struct _QUAC_ASYNC_SUBMIT {
    UINT32 OperationType;  // QUAC_OP_*
    UINT32 Priority;       // QUAC_PRIORITY_*
    UINT32 InputSize;
    BYTE   Input[];        // Operation-specific input
} QUAC_ASYNC_SUBMIT;

#define QUAC_OP_KEM_KEYGEN    1
#define QUAC_OP_KEM_ENCAPS    2
#define QUAC_OP_KEM_DECAPS    3
#define QUAC_OP_SIGN_KEYGEN   4
#define QUAC_OP_SIGN          5
#define QUAC_OP_VERIFY        6
#define QUAC_OP_RANDOM        7

#define QUAC_PRIORITY_LOW     0
#define QUAC_PRIORITY_NORMAL  1
#define QUAC_PRIORITY_HIGH    2
#define QUAC_PRIORITY_REALTIME 3
```

**Output**:
```c
typedef struct _QUAC_ASYNC_HANDLE {
    UINT64 JobId;
} QUAC_ASYNC_HANDLE;
```

---

### IOCTL_QUAC_ASYNC_POLL

Poll for operation completion.

```c
#define IOCTL_QUAC_ASYNC_POLL  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x851, METHOD_BUFFERED, FILE_ANY_ACCESS)
```

**Input**:
```c
typedef struct _QUAC_ASYNC_POLL_INPUT {
    UINT64 JobId;
} QUAC_ASYNC_POLL_INPUT;
```

**Output**:
```c
typedef struct _QUAC_ASYNC_POLL_OUTPUT {
    UINT32 State;   // QUAC_JOB_STATE_*
    UINT32 Status;  // NTSTATUS if completed
} QUAC_ASYNC_POLL_OUTPUT;

#define QUAC_JOB_STATE_PENDING   0
#define QUAC_JOB_STATE_RUNNING   1
#define QUAC_JOB_STATE_COMPLETED 2
#define QUAC_JOB_STATE_FAILED    3
#define QUAC_JOB_STATE_CANCELLED 4
```

---

### IOCTL_QUAC_ASYNC_WAIT

Wait for operation completion.

```c
#define IOCTL_QUAC_ASYNC_WAIT  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x852, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
```

**Input**:
```c
typedef struct _QUAC_ASYNC_WAIT_INPUT {
    UINT64 JobId;
    UINT32 TimeoutMs;  // 0 = no timeout
} QUAC_ASYNC_WAIT_INPUT;
```

**Output**: Operation-specific result data

---

### IOCTL_QUAC_ASYNC_CANCEL

Cancel a pending operation.

```c
#define IOCTL_QUAC_ASYNC_CANCEL  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x853, METHOD_BUFFERED, FILE_ANY_ACCESS)
```

**Input**:
```c
typedef struct _QUAC_ASYNC_CANCEL_INPUT {
    UINT64 JobId;
} QUAC_ASYNC_CANCEL_INPUT;
```

**Output**:
```c
typedef struct _QUAC_ASYNC_CANCEL_OUTPUT {
    UINT32 Cancelled;  // 1 = cancelled, 0 = already completed
} QUAC_ASYNC_CANCEL_OUTPUT;
```

---

## Error Codes

All IOCTLs return standard NTSTATUS codes:

| Code | Name | Description |
|------|------|-------------|
| 0x00000000 | STATUS_SUCCESS | Operation successful |
| 0xC0000001 | STATUS_UNSUCCESSFUL | Generic failure |
| 0xC000000D | STATUS_INVALID_PARAMETER | Invalid input parameter |
| 0xC0000023 | STATUS_BUFFER_TOO_SMALL | Output buffer too small |
| 0xC00000B5 | STATUS_IO_TIMEOUT | Operation timed out |
| 0xC0000185 | STATUS_IO_DEVICE_ERROR | Hardware error |
| 0xC00000BB | STATUS_NOT_SUPPORTED | Algorithm not supported |

Custom QUAC error codes (returned in output structures):

| Code | Name | Description |
|------|------|-------------|
| 0x00 | QUAC_SUCCESS | Success |
| 0x01 | QUAC_ERROR_INVALID_PARAM | Invalid parameter |
| 0x02 | QUAC_ERROR_DEVICE_NOT_FOUND | Device not found |
| 0x03 | QUAC_ERROR_DEVICE_BUSY | Device busy |
| 0x04 | QUAC_ERROR_NOT_SUPPORTED | Not supported |
| 0x05 | QUAC_ERROR_BUFFER_TOO_SMALL | Buffer too small |
| 0x06 | QUAC_ERROR_TIMEOUT | Timeout |
| 0x07 | QUAC_ERROR_CRYPTO_FAILED | Crypto operation failed |
| 0x08 | QUAC_ERROR_ENTROPY_LOW | Insufficient entropy |
| 0x09 | QUAC_ERROR_HEALTH_CHECK_FAILED | Health check failed |

---

## See Also

- [Architecture Overview](architecture.md)
- [API Reference](../lib/quac100lib/quac100lib.h)
- [Sample Code](../samples/)

---

Copyright © 2025 Dyber, Inc. All Rights Reserved.
