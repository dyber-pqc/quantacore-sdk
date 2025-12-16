/*++

Module Name:
    keystore.h

Abstract:
    QUAC 100 secure key storage interface definitions.
    
    The key storage module provides secure storage for cryptographic
    keys within the hardware's protected memory region. Keys stored
    in the hardware cannot be extracted and are protected from
    software attacks.

Features:
    - Hardware-protected key storage
    - Key import/export (wrapped)
    - Key usage policies
    - Key lifecycle management
    - Secure key derivation

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
// Maximum number of keys in hardware storage
//
#define QUAC_MAX_STORED_KEYS        64

//
// Key handle (opaque reference to stored key)
//
typedef UINT32 QUAC_KEY_HANDLE;

#define QUAC_INVALID_KEY_HANDLE     0xFFFFFFFF

//
// Key types
//
typedef enum _QUAC_KEY_TYPE {
    QuacKeyTypeKemPublic = 0,       // ML-KEM public key
    QuacKeyTypeKemSecret,           // ML-KEM secret key
    QuacKeyTypeKemPair,             // ML-KEM key pair
    QuacKeyTypeSignPublic,          // ML-DSA/SLH-DSA public key
    QuacKeyTypeSignSecret,          // ML-DSA/SLH-DSA secret key
    QuacKeyTypeSignPair,            // Signature key pair
    QuacKeyTypeSymmetric,           // Symmetric key (derived)
    QuacKeyTypeRaw,                 // Raw key material
} QUAC_KEY_TYPE;

//
// Key algorithms
//
typedef enum _QUAC_KEY_ALGORITHM {
    QuacKeyAlgKyber512 = 0,
    QuacKeyAlgKyber768,
    QuacKeyAlgKyber1024,
    QuacKeyAlgDilithium2,
    QuacKeyAlgDilithium3,
    QuacKeyAlgDilithium5,
    QuacKeyAlgSphincsShake128s,
    QuacKeyAlgSphincsShake128f,
    QuacKeyAlgSphincsShake192s,
    QuacKeyAlgSphincsShake192f,
    QuacKeyAlgSphincsShake256s,
    QuacKeyAlgSphincsShake256f,
    QuacKeyAlgAes128,
    QuacKeyAlgAes256,
    QuacKeyAlgRaw,
} QUAC_KEY_ALGORITHM;

//
// Key usage flags
//
#define QUAC_KEY_USAGE_ENCRYPT      0x00000001  // Can encrypt/encapsulate
#define QUAC_KEY_USAGE_DECRYPT      0x00000002  // Can decrypt/decapsulate
#define QUAC_KEY_USAGE_SIGN         0x00000004  // Can sign
#define QUAC_KEY_USAGE_VERIFY       0x00000008  // Can verify
#define QUAC_KEY_USAGE_DERIVE       0x00000010  // Can derive other keys
#define QUAC_KEY_USAGE_WRAP         0x00000020  // Can wrap other keys
#define QUAC_KEY_USAGE_UNWRAP       0x00000040  // Can unwrap other keys
#define QUAC_KEY_USAGE_EXPORT       0x00000080  // Can be exported (wrapped)

#define QUAC_KEY_USAGE_ALL          0x000000FF

//
// Key attributes
//
#define QUAC_KEY_ATTR_PERSISTENT    0x00000001  // Survives power cycle
#define QUAC_KEY_ATTR_SENSITIVE     0x00000002  // Never leaves hardware
#define QUAC_KEY_ATTR_EXTRACTABLE   0x00000004  // Can be exported wrapped
#define QUAC_KEY_ATTR_MODIFIABLE    0x00000008  // Attributes can be changed
#define QUAC_KEY_ATTR_COPYABLE      0x00000010  // Can be duplicated
#define QUAC_KEY_ATTR_DESTROYABLE   0x00000020  // Can be deleted

#define QUAC_KEY_ATTR_DEFAULT       (QUAC_KEY_ATTR_DESTROYABLE | QUAC_KEY_ATTR_MODIFIABLE)

//
// Key information structure
//
typedef struct _QUAC_KEY_INFO {
    QUAC_KEY_HANDLE Handle;
    QUAC_KEY_TYPE Type;
    QUAC_KEY_ALGORITHM Algorithm;
    UINT32 UsageFlags;
    UINT32 Attributes;
    UINT32 KeySizeBits;
    UINT32 PublicKeySizeBytes;
    UINT32 SecretKeySizeBytes;
    UINT64 CreationTime;
    UINT64 LastUsedTime;
    UINT32 UseCount;
    CHAR Label[64];
} QUAC_KEY_INFO, *PQUAC_KEY_INFO;

//
// Key generation parameters
//
typedef struct _QUAC_KEY_GEN_PARAMS {
    QUAC_KEY_TYPE Type;
    QUAC_KEY_ALGORITHM Algorithm;
    UINT32 UsageFlags;
    UINT32 Attributes;
    PCSTR Label;                    // Optional label
} QUAC_KEY_GEN_PARAMS, *PQUAC_KEY_GEN_PARAMS;

//
// Key import parameters
//
typedef struct _QUAC_KEY_IMPORT_PARAMS {
    QUAC_KEY_TYPE Type;
    QUAC_KEY_ALGORITHM Algorithm;
    UINT32 UsageFlags;
    UINT32 Attributes;
    PCSTR Label;
    const BYTE* KeyData;            // Key material
    UINT32 KeyDataSize;
    QUAC_KEY_HANDLE WrappingKey;    // For wrapped import
} QUAC_KEY_IMPORT_PARAMS, *PQUAC_KEY_IMPORT_PARAMS;

//
// Key derivation parameters
//
typedef struct _QUAC_KEY_DERIVE_PARAMS {
    QUAC_KEY_HANDLE BaseKey;
    QUAC_KEY_ALGORITHM DerivedAlgorithm;
    UINT32 DerivedUsage;
    UINT32 DerivedAttributes;
    const BYTE* Context;            // Derivation context/info
    UINT32 ContextSize;
    UINT32 DerivedKeyBits;
} QUAC_KEY_DERIVE_PARAMS, *PQUAC_KEY_DERIVE_PARAMS;

//
// Key store context (stored in device context)
//
typedef struct _QUAC_KEYSTORE_CONTEXT {
    UINT32 MaxKeys;
    UINT32 UsedSlots;
    FAST_MUTEX Lock;
    struct {
        BOOLEAN InUse;
        QUAC_KEY_INFO Info;
        UINT32 HardwareSlot;        // Slot in hardware key storage
    } Keys[QUAC_MAX_STORED_KEYS];
} QUAC_KEYSTORE_CONTEXT, *PQUAC_KEYSTORE_CONTEXT;

//
// Initialization and shutdown
//
NTSTATUS
Quac100KeyStoreInitialize(
    _In_ PQUAC_DEVICE_CONTEXT DeviceContext
    );

VOID
Quac100KeyStoreShutdown(
    _In_ PQUAC_DEVICE_CONTEXT DeviceContext
    );

//
// Key generation
//
NTSTATUS
Quac100KeyGenerate(
    _In_ PQUAC_DEVICE_CONTEXT DeviceContext,
    _In_ PQUAC_KEY_GEN_PARAMS Params,
    _Out_ PQUAC_KEY_HANDLE KeyHandle
    );

//
// Key import/export
//
NTSTATUS
Quac100KeyImport(
    _In_ PQUAC_DEVICE_CONTEXT DeviceContext,
    _In_ PQUAC_KEY_IMPORT_PARAMS Params,
    _Out_ PQUAC_KEY_HANDLE KeyHandle
    );

NTSTATUS
Quac100KeyExport(
    _In_ PQUAC_DEVICE_CONTEXT DeviceContext,
    _In_ QUAC_KEY_HANDLE KeyHandle,
    _In_ QUAC_KEY_HANDLE WrappingKey,   // INVALID for public keys
    _Out_writes_bytes_opt_(*BufferSize) BYTE* Buffer,
    _Inout_ PUINT32 BufferSize
    );

NTSTATUS
Quac100KeyExportPublic(
    _In_ PQUAC_DEVICE_CONTEXT DeviceContext,
    _In_ QUAC_KEY_HANDLE KeyHandle,
    _Out_writes_bytes_(*BufferSize) BYTE* Buffer,
    _Inout_ PUINT32 BufferSize
    );

//
// Key derivation
//
NTSTATUS
Quac100KeyDerive(
    _In_ PQUAC_DEVICE_CONTEXT DeviceContext,
    _In_ PQUAC_KEY_DERIVE_PARAMS Params,
    _Out_ PQUAC_KEY_HANDLE DerivedKeyHandle
    );

//
// Key management
//
NTSTATUS
Quac100KeyGetInfo(
    _In_ PQUAC_DEVICE_CONTEXT DeviceContext,
    _In_ QUAC_KEY_HANDLE KeyHandle,
    _Out_ PQUAC_KEY_INFO Info
    );

NTSTATUS
Quac100KeySetLabel(
    _In_ PQUAC_DEVICE_CONTEXT DeviceContext,
    _In_ QUAC_KEY_HANDLE KeyHandle,
    _In_ PCSTR Label
    );

NTSTATUS
Quac100KeyDestroy(
    _In_ PQUAC_DEVICE_CONTEXT DeviceContext,
    _In_ QUAC_KEY_HANDLE KeyHandle
    );

NTSTATUS
Quac100KeyDestroyAll(
    _In_ PQUAC_DEVICE_CONTEXT DeviceContext
    );

//
// Key enumeration
//
NTSTATUS
Quac100KeyEnumerate(
    _In_ PQUAC_DEVICE_CONTEXT DeviceContext,
    _Out_writes_opt_(*Count) QUAC_KEY_HANDLE* Handles,
    _Inout_ PUINT32 Count
    );

NTSTATUS
Quac100KeyFindByLabel(
    _In_ PQUAC_DEVICE_CONTEXT DeviceContext,
    _In_ PCSTR Label,
    _Out_ PQUAC_KEY_HANDLE KeyHandle
    );

//
// Key operations (use stored key)
//
NTSTATUS
Quac100KeyKemEncaps(
    _In_ PQUAC_DEVICE_CONTEXT DeviceContext,
    _In_ QUAC_KEY_HANDLE PublicKeyHandle,
    _Out_writes_bytes_(CiphertextSize) BYTE* Ciphertext,
    _In_ UINT32 CiphertextSize,
    _Out_writes_bytes_(SharedSecretSize) BYTE* SharedSecret,
    _In_ UINT32 SharedSecretSize
    );

NTSTATUS
Quac100KeyKemDecaps(
    _In_ PQUAC_DEVICE_CONTEXT DeviceContext,
    _In_ QUAC_KEY_HANDLE SecretKeyHandle,
    _In_reads_bytes_(CiphertextSize) const BYTE* Ciphertext,
    _In_ UINT32 CiphertextSize,
    _Out_writes_bytes_(SharedSecretSize) BYTE* SharedSecret,
    _In_ UINT32 SharedSecretSize
    );

NTSTATUS
Quac100KeySign(
    _In_ PQUAC_DEVICE_CONTEXT DeviceContext,
    _In_ QUAC_KEY_HANDLE SecretKeyHandle,
    _In_reads_bytes_(MessageSize) const BYTE* Message,
    _In_ UINT32 MessageSize,
    _In_reads_bytes_opt_(ContextSize) const BYTE* Context,
    _In_ UINT32 ContextSize,
    _Out_writes_bytes_(*SignatureSize) BYTE* Signature,
    _Inout_ PUINT32 SignatureSize
    );

NTSTATUS
Quac100KeyVerify(
    _In_ PQUAC_DEVICE_CONTEXT DeviceContext,
    _In_ QUAC_KEY_HANDLE PublicKeyHandle,
    _In_reads_bytes_(MessageSize) const BYTE* Message,
    _In_ UINT32 MessageSize,
    _In_reads_bytes_opt_(ContextSize) const BYTE* Context,
    _In_ UINT32 ContextSize,
    _In_reads_bytes_(SignatureSize) const BYTE* Signature,
    _In_ UINT32 SignatureSize,
    _Out_ PBOOLEAN Valid
    );

//
// Utility functions
//
UINT32
Quac100KeyGetPublicKeySize(
    _In_ QUAC_KEY_ALGORITHM Algorithm
    );

UINT32
Quac100KeyGetSecretKeySize(
    _In_ QUAC_KEY_ALGORITHM Algorithm
    );

UINT32
Quac100KeyGetCiphertextSize(
    _In_ QUAC_KEY_ALGORITHM Algorithm
    );

UINT32
Quac100KeyGetSignatureSize(
    _In_ QUAC_KEY_ALGORITHM Algorithm
    );

BOOLEAN
Quac100KeyIsValidHandle(
    _In_ PQUAC_DEVICE_CONTEXT DeviceContext,
    _In_ QUAC_KEY_HANDLE KeyHandle
    );
