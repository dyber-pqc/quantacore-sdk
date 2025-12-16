/**
 * @file kem.h
 * @brief QUAC 100 Key Encapsulation Mechanism Operations
 *
 * Hardware-accelerated ML-KEM (Kyber) operations for post-quantum
 * key establishment.
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_KEM_H
#define QUAC100_KEM_H

#include <ntddk.h>
#include <wdf.h>
#include "../../include/quac100_ioctl.h"

#ifdef __cplusplus
extern "C" {
#endif

/*=============================================================================
 * Forward Declarations
 *=============================================================================*/

struct _DEVICE_CONTEXT;
typedef struct _DEVICE_CONTEXT DEVICE_CONTEXT, *PDEVICE_CONTEXT;

/*=============================================================================
 * KEM Key Sizes
 *=============================================================================*/

/** ML-KEM-512 (Kyber512) */
#define QUAC_KEM_KYBER512_PK_SIZE       800
#define QUAC_KEM_KYBER512_SK_SIZE       1632
#define QUAC_KEM_KYBER512_CT_SIZE       768
#define QUAC_KEM_KYBER512_SS_SIZE       32

/** ML-KEM-768 (Kyber768) */
#define QUAC_KEM_KYBER768_PK_SIZE       1184
#define QUAC_KEM_KYBER768_SK_SIZE       2400
#define QUAC_KEM_KYBER768_CT_SIZE       1088
#define QUAC_KEM_KYBER768_SS_SIZE       32

/** ML-KEM-1024 (Kyber1024) */
#define QUAC_KEM_KYBER1024_PK_SIZE      1568
#define QUAC_KEM_KYBER1024_SK_SIZE      3168
#define QUAC_KEM_KYBER1024_CT_SIZE      1568
#define QUAC_KEM_KYBER1024_SS_SIZE      32

/*=============================================================================
 * KEM Initialization
 *=============================================================================*/

/**
 * @brief Initialize KEM subsystem
 *
 * @param[in] DeviceContext     Device context
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100KemInitialize(
    _In_ PDEVICE_CONTEXT DeviceContext
    );

/**
 * @brief Shutdown KEM subsystem
 *
 * @param[in] DeviceContext     Device context
 */
VOID
Quac100KemShutdown(
    _In_ PDEVICE_CONTEXT DeviceContext
    );

/*=============================================================================
 * Key Generation
 *=============================================================================*/

/**
 * @brief Generate KEM key pair
 *
 * @param[in]  DeviceContext    Device context
 * @param[in]  Algorithm        KEM algorithm (QUAC_ALG_KYBER*)
 * @param[out] PublicKey        Public key buffer
 * @param[in]  PublicKeySize    Public key buffer size
 * @param[out] SecretKey        Secret key buffer
 * @param[in]  SecretKeySize    Secret key buffer size
 *
 * @return STATUS_SUCCESS on success
 * @return STATUS_BUFFER_TOO_SMALL if buffers too small
 */
NTSTATUS
Quac100KemKeyGen(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ QUAC_ALGORITHM Algorithm,
    _Out_writes_bytes_(PublicKeySize) PUCHAR PublicKey,
    _In_ SIZE_T PublicKeySize,
    _Out_writes_bytes_(SecretKeySize) PUCHAR SecretKey,
    _In_ SIZE_T SecretKeySize
    );

/**
 * @brief Generate KEM key pair (async)
 *
 * @param[in]  DeviceContext    Device context
 * @param[in]  Algorithm        KEM algorithm
 * @param[out] PublicKey        Public key buffer
 * @param[in]  PublicKeySize    Public key buffer size
 * @param[out] SecretKey        Secret key buffer
 * @param[in]  SecretKeySize    Secret key buffer size
 * @param[in]  Callback         Completion callback
 * @param[in]  Context          Callback context
 *
 * @return STATUS_PENDING if submitted successfully
 */
NTSTATUS
Quac100KemKeyGenAsync(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ QUAC_ALGORITHM Algorithm,
    _Out_writes_bytes_(PublicKeySize) PUCHAR PublicKey,
    _In_ SIZE_T PublicKeySize,
    _Out_writes_bytes_(SecretKeySize) PUCHAR SecretKey,
    _In_ SIZE_T SecretKeySize,
    _In_ VOID (*Callback)(NTSTATUS Status, PVOID Context),
    _In_ PVOID Context
    );

/*=============================================================================
 * Encapsulation
 *=============================================================================*/

/**
 * @brief Encapsulate shared secret
 *
 * @param[in]  DeviceContext    Device context
 * @param[in]  Algorithm        KEM algorithm
 * @param[in]  PublicKey        Recipient's public key
 * @param[in]  PublicKeySize    Public key size
 * @param[out] Ciphertext       Ciphertext output
 * @param[in]  CiphertextSize   Ciphertext buffer size
 * @param[out] SharedSecret     Shared secret output
 * @param[in]  SharedSecretSize Shared secret buffer size
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100KemEncaps(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ QUAC_ALGORITHM Algorithm,
    _In_reads_bytes_(PublicKeySize) const PUCHAR PublicKey,
    _In_ SIZE_T PublicKeySize,
    _Out_writes_bytes_(CiphertextSize) PUCHAR Ciphertext,
    _In_ SIZE_T CiphertextSize,
    _Out_writes_bytes_(SharedSecretSize) PUCHAR SharedSecret,
    _In_ SIZE_T SharedSecretSize
    );

/**
 * @brief Encapsulate shared secret (async)
 *
 * @param[in]  DeviceContext    Device context
 * @param[in]  Algorithm        KEM algorithm
 * @param[in]  PublicKey        Recipient's public key
 * @param[in]  PublicKeySize    Public key size
 * @param[out] Ciphertext       Ciphertext output
 * @param[in]  CiphertextSize   Ciphertext buffer size
 * @param[out] SharedSecret     Shared secret output
 * @param[in]  SharedSecretSize Shared secret buffer size
 * @param[in]  Callback         Completion callback
 * @param[in]  Context          Callback context
 *
 * @return STATUS_PENDING if submitted successfully
 */
NTSTATUS
Quac100KemEncapsAsync(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ QUAC_ALGORITHM Algorithm,
    _In_reads_bytes_(PublicKeySize) const PUCHAR PublicKey,
    _In_ SIZE_T PublicKeySize,
    _Out_writes_bytes_(CiphertextSize) PUCHAR Ciphertext,
    _In_ SIZE_T CiphertextSize,
    _Out_writes_bytes_(SharedSecretSize) PUCHAR SharedSecret,
    _In_ SIZE_T SharedSecretSize,
    _In_ VOID (*Callback)(NTSTATUS Status, PVOID Context),
    _In_ PVOID Context
    );

/*=============================================================================
 * Decapsulation
 *=============================================================================*/

/**
 * @brief Decapsulate shared secret
 *
 * @param[in]  DeviceContext    Device context
 * @param[in]  Algorithm        KEM algorithm
 * @param[in]  Ciphertext       Ciphertext from encapsulation
 * @param[in]  CiphertextSize   Ciphertext size
 * @param[in]  SecretKey        Recipient's secret key
 * @param[in]  SecretKeySize    Secret key size
 * @param[out] SharedSecret     Shared secret output
 * @param[in]  SharedSecretSize Shared secret buffer size
 *
 * @return STATUS_SUCCESS on success
 * @return STATUS_INVALID_PARAMETER if decapsulation fails
 */
NTSTATUS
Quac100KemDecaps(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ QUAC_ALGORITHM Algorithm,
    _In_reads_bytes_(CiphertextSize) const PUCHAR Ciphertext,
    _In_ SIZE_T CiphertextSize,
    _In_reads_bytes_(SecretKeySize) const PUCHAR SecretKey,
    _In_ SIZE_T SecretKeySize,
    _Out_writes_bytes_(SharedSecretSize) PUCHAR SharedSecret,
    _In_ SIZE_T SharedSecretSize
    );

/**
 * @brief Decapsulate shared secret (async)
 *
 * @param[in]  DeviceContext    Device context
 * @param[in]  Algorithm        KEM algorithm
 * @param[in]  Ciphertext       Ciphertext from encapsulation
 * @param[in]  CiphertextSize   Ciphertext size
 * @param[in]  SecretKey        Recipient's secret key
 * @param[in]  SecretKeySize    Secret key size
 * @param[out] SharedSecret     Shared secret output
 * @param[in]  SharedSecretSize Shared secret buffer size
 * @param[in]  Callback         Completion callback
 * @param[in]  Context          Callback context
 *
 * @return STATUS_PENDING if submitted successfully
 */
NTSTATUS
Quac100KemDecapsAsync(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ QUAC_ALGORITHM Algorithm,
    _In_reads_bytes_(CiphertextSize) const PUCHAR Ciphertext,
    _In_ SIZE_T CiphertextSize,
    _In_reads_bytes_(SecretKeySize) const PUCHAR SecretKey,
    _In_ SIZE_T SecretKeySize,
    _Out_writes_bytes_(SharedSecretSize) PUCHAR SharedSecret,
    _In_ SIZE_T SharedSecretSize,
    _In_ VOID (*Callback)(NTSTATUS Status, PVOID Context),
    _In_ PVOID Context
    );

/*=============================================================================
 * Utility Functions
 *=============================================================================*/

/**
 * @brief Get key sizes for algorithm
 *
 * @param[in]  Algorithm        KEM algorithm
 * @param[out] PublicKeySize    Public key size
 * @param[out] SecretKeySize    Secret key size
 * @param[out] CiphertextSize   Ciphertext size
 * @param[out] SharedSecretSize Shared secret size
 *
 * @return STATUS_SUCCESS on success
 * @return STATUS_INVALID_PARAMETER for invalid algorithm
 */
NTSTATUS
Quac100KemGetSizes(
    _In_ QUAC_ALGORITHM Algorithm,
    _Out_opt_ PSIZE_T PublicKeySize,
    _Out_opt_ PSIZE_T SecretKeySize,
    _Out_opt_ PSIZE_T CiphertextSize,
    _Out_opt_ PSIZE_T SharedSecretSize
    );

/**
 * @brief Check if algorithm is supported KEM
 *
 * @param[in] DeviceContext     Device context
 * @param[in] Algorithm         Algorithm to check
 *
 * @return TRUE if supported
 */
BOOLEAN
Quac100KemIsSupported(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ QUAC_ALGORITHM Algorithm
    );

/*=============================================================================
 * IOCTL Handlers
 *=============================================================================*/

/**
 * @brief Handle KEM keygen IOCTL
 *
 * @param[in]  DeviceContext    Device context
 * @param[in]  Request          WDF request
 * @param[out] BytesReturned    Bytes returned to caller
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100IoctlKemKeyGenHandler(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ WDFREQUEST Request,
    _Out_ size_t* BytesReturned
    );

/**
 * @brief Handle KEM encaps IOCTL
 *
 * @param[in]  DeviceContext    Device context
 * @param[in]  Request          WDF request
 * @param[out] BytesReturned    Bytes returned to caller
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100IoctlKemEncapsHandler(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ WDFREQUEST Request,
    _Out_ size_t* BytesReturned
    );

/**
 * @brief Handle KEM decaps IOCTL
 *
 * @param[in]  DeviceContext    Device context
 * @param[in]  Request          WDF request
 * @param[out] BytesReturned    Bytes returned to caller
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100IoctlKemDecapsHandler(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ WDFREQUEST Request,
    _Out_ size_t* BytesReturned
    );

#ifdef __cplusplus
}
#endif

#endif /* QUAC100_KEM_H */
