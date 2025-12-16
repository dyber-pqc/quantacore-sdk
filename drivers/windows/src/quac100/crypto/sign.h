/**
 * @file sign.h
 * @brief QUAC 100 Digital Signature Operations
 *
 * Hardware-accelerated ML-DSA (Dilithium) and SLH-DSA (SPHINCS+)
 * post-quantum digital signature operations.
 *
 * @version 1.0.0
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_SIGN_H
#define QUAC100_SIGN_H

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
 * ML-DSA (Dilithium) Key Sizes
 *=============================================================================*/

/** ML-DSA-44 (Dilithium2) */
#define QUAC_SIGN_DILITHIUM2_PK_SIZE    1312
#define QUAC_SIGN_DILITHIUM2_SK_SIZE    2528
#define QUAC_SIGN_DILITHIUM2_SIG_SIZE   2420

/** ML-DSA-65 (Dilithium3) */
#define QUAC_SIGN_DILITHIUM3_PK_SIZE    1952
#define QUAC_SIGN_DILITHIUM3_SK_SIZE    4000
#define QUAC_SIGN_DILITHIUM3_SIG_SIZE   3293

/** ML-DSA-87 (Dilithium5) */
#define QUAC_SIGN_DILITHIUM5_PK_SIZE    2592
#define QUAC_SIGN_DILITHIUM5_SK_SIZE    4864
#define QUAC_SIGN_DILITHIUM5_SIG_SIZE   4595

/*=============================================================================
 * SLH-DSA (SPHINCS+) Key Sizes
 *=============================================================================*/

/** SLH-DSA-SHA2-128s */
#define QUAC_SIGN_SPHINCS_128S_PK_SIZE  32
#define QUAC_SIGN_SPHINCS_128S_SK_SIZE  64
#define QUAC_SIGN_SPHINCS_128S_SIG_SIZE 7856

/** SLH-DSA-SHA2-128f */
#define QUAC_SIGN_SPHINCS_128F_PK_SIZE  32
#define QUAC_SIGN_SPHINCS_128F_SK_SIZE  64
#define QUAC_SIGN_SPHINCS_128F_SIG_SIZE 17088

/** SLH-DSA-SHA2-192s */
#define QUAC_SIGN_SPHINCS_192S_PK_SIZE  48
#define QUAC_SIGN_SPHINCS_192S_SK_SIZE  96
#define QUAC_SIGN_SPHINCS_192S_SIG_SIZE 16224

/** SLH-DSA-SHA2-192f */
#define QUAC_SIGN_SPHINCS_192F_PK_SIZE  48
#define QUAC_SIGN_SPHINCS_192F_SK_SIZE  96
#define QUAC_SIGN_SPHINCS_192F_SIG_SIZE 35664

/** SLH-DSA-SHA2-256s */
#define QUAC_SIGN_SPHINCS_256S_PK_SIZE  64
#define QUAC_SIGN_SPHINCS_256S_SK_SIZE  128
#define QUAC_SIGN_SPHINCS_256S_SIG_SIZE 29792

/** SLH-DSA-SHA2-256f */
#define QUAC_SIGN_SPHINCS_256F_PK_SIZE  64
#define QUAC_SIGN_SPHINCS_256F_SK_SIZE  128
#define QUAC_SIGN_SPHINCS_256F_SIG_SIZE 49856

/*=============================================================================
 * Signature Constants
 *=============================================================================*/

/** Maximum message size for signing */
#define QUAC_SIGN_MAX_MESSAGE_SIZE      (16 * 1024 * 1024)  /* 16 MB */

/** Maximum context size */
#define QUAC_SIGN_MAX_CONTEXT_SIZE      255

/*=============================================================================
 * Signature Initialization
 *=============================================================================*/

/**
 * @brief Initialize signature subsystem
 *
 * @param[in] DeviceContext     Device context
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100SignInitialize(
    _In_ PDEVICE_CONTEXT DeviceContext
    );

/**
 * @brief Shutdown signature subsystem
 *
 * @param[in] DeviceContext     Device context
 */
VOID
Quac100SignShutdown(
    _In_ PDEVICE_CONTEXT DeviceContext
    );

/*=============================================================================
 * Key Generation
 *=============================================================================*/

/**
 * @brief Generate signature key pair
 *
 * @param[in]  DeviceContext    Device context
 * @param[in]  Algorithm        Signature algorithm
 * @param[out] PublicKey        Public key buffer
 * @param[in]  PublicKeySize    Public key buffer size
 * @param[out] SecretKey        Secret key buffer
 * @param[in]  SecretKeySize    Secret key buffer size
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100SignKeyGen(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ QUAC_ALGORITHM Algorithm,
    _Out_writes_bytes_(PublicKeySize) PUCHAR PublicKey,
    _In_ SIZE_T PublicKeySize,
    _Out_writes_bytes_(SecretKeySize) PUCHAR SecretKey,
    _In_ SIZE_T SecretKeySize
    );

/**
 * @brief Generate signature key pair (async)
 *
 * @param[in]  DeviceContext    Device context
 * @param[in]  Algorithm        Signature algorithm
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
Quac100SignKeyGenAsync(
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
 * Signing
 *=============================================================================*/

/**
 * @brief Sign a message
 *
 * @param[in]  DeviceContext    Device context
 * @param[in]  Algorithm        Signature algorithm
 * @param[in]  SecretKey        Signing key
 * @param[in]  SecretKeySize    Secret key size
 * @param[in]  Message          Message to sign
 * @param[in]  MessageSize      Message size
 * @param[in]  Context          Optional context string (may be NULL)
 * @param[in]  ContextSize      Context string size (0 if NULL)
 * @param[out] Signature        Signature output
 * @param[in]  SignatureSize    Signature buffer size
 * @param[out] ActualSigSize    Actual signature size (may vary for SPHINCS+)
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100Sign(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ QUAC_ALGORITHM Algorithm,
    _In_reads_bytes_(SecretKeySize) const PUCHAR SecretKey,
    _In_ SIZE_T SecretKeySize,
    _In_reads_bytes_(MessageSize) const PUCHAR Message,
    _In_ SIZE_T MessageSize,
    _In_reads_bytes_opt_(ContextSize) const PUCHAR Context,
    _In_ SIZE_T ContextSize,
    _Out_writes_bytes_(SignatureSize) PUCHAR Signature,
    _In_ SIZE_T SignatureSize,
    _Out_ PSIZE_T ActualSigSize
    );

/**
 * @brief Sign a message (async)
 *
 * @param[in]  DeviceContext    Device context
 * @param[in]  Algorithm        Signature algorithm
 * @param[in]  SecretKey        Signing key
 * @param[in]  SecretKeySize    Secret key size
 * @param[in]  Message          Message to sign
 * @param[in]  MessageSize      Message size
 * @param[in]  Context          Optional context string (may be NULL)
 * @param[in]  ContextSize      Context string size
 * @param[out] Signature        Signature output
 * @param[in]  SignatureSize    Signature buffer size
 * @param[out] ActualSigSize    Actual signature size
 * @param[in]  Callback         Completion callback
 * @param[in]  CallbackContext  Callback context
 *
 * @return STATUS_PENDING if submitted successfully
 */
NTSTATUS
Quac100SignAsync(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ QUAC_ALGORITHM Algorithm,
    _In_reads_bytes_(SecretKeySize) const PUCHAR SecretKey,
    _In_ SIZE_T SecretKeySize,
    _In_reads_bytes_(MessageSize) const PUCHAR Message,
    _In_ SIZE_T MessageSize,
    _In_reads_bytes_opt_(ContextSize) const PUCHAR Context,
    _In_ SIZE_T ContextSize,
    _Out_writes_bytes_(SignatureSize) PUCHAR Signature,
    _In_ SIZE_T SignatureSize,
    _Out_ PSIZE_T ActualSigSize,
    _In_ VOID (*Callback)(NTSTATUS Status, PVOID Context),
    _In_ PVOID CallbackContext
    );

/*=============================================================================
 * Verification
 *=============================================================================*/

/**
 * @brief Verify a signature
 *
 * @param[in]  DeviceContext    Device context
 * @param[in]  Algorithm        Signature algorithm
 * @param[in]  PublicKey        Verification key
 * @param[in]  PublicKeySize    Public key size
 * @param[in]  Message          Signed message
 * @param[in]  MessageSize      Message size
 * @param[in]  Context          Optional context string (may be NULL)
 * @param[in]  ContextSize      Context string size
 * @param[in]  Signature        Signature to verify
 * @param[in]  SignatureSize    Signature size
 * @param[out] Valid            TRUE if signature valid
 *
 * @return STATUS_SUCCESS on success (check Valid for result)
 */
NTSTATUS
Quac100Verify(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ QUAC_ALGORITHM Algorithm,
    _In_reads_bytes_(PublicKeySize) const PUCHAR PublicKey,
    _In_ SIZE_T PublicKeySize,
    _In_reads_bytes_(MessageSize) const PUCHAR Message,
    _In_ SIZE_T MessageSize,
    _In_reads_bytes_opt_(ContextSize) const PUCHAR Context,
    _In_ SIZE_T ContextSize,
    _In_reads_bytes_(SignatureSize) const PUCHAR Signature,
    _In_ SIZE_T SignatureSize,
    _Out_ PBOOLEAN Valid
    );

/**
 * @brief Verify a signature (async)
 *
 * @param[in]  DeviceContext    Device context
 * @param[in]  Algorithm        Signature algorithm
 * @param[in]  PublicKey        Verification key
 * @param[in]  PublicKeySize    Public key size
 * @param[in]  Message          Signed message
 * @param[in]  MessageSize      Message size
 * @param[in]  Context          Optional context string
 * @param[in]  ContextSize      Context string size
 * @param[in]  Signature        Signature to verify
 * @param[in]  SignatureSize    Signature size
 * @param[out] Valid            TRUE if signature valid
 * @param[in]  Callback         Completion callback
 * @param[in]  CallbackContext  Callback context
 *
 * @return STATUS_PENDING if submitted successfully
 */
NTSTATUS
Quac100VerifyAsync(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ QUAC_ALGORITHM Algorithm,
    _In_reads_bytes_(PublicKeySize) const PUCHAR PublicKey,
    _In_ SIZE_T PublicKeySize,
    _In_reads_bytes_(MessageSize) const PUCHAR Message,
    _In_ SIZE_T MessageSize,
    _In_reads_bytes_opt_(ContextSize) const PUCHAR Context,
    _In_ SIZE_T ContextSize,
    _In_reads_bytes_(SignatureSize) const PUCHAR Signature,
    _In_ SIZE_T SignatureSize,
    _Out_ PBOOLEAN Valid,
    _In_ VOID (*Callback)(NTSTATUS Status, PVOID Context),
    _In_ PVOID CallbackContext
    );

/*=============================================================================
 * Utility Functions
 *=============================================================================*/

/**
 * @brief Get key sizes for signature algorithm
 *
 * @param[in]  Algorithm        Signature algorithm
 * @param[out] PublicKeySize    Public key size
 * @param[out] SecretKeySize    Secret key size
 * @param[out] SignatureSize    Maximum signature size
 *
 * @return STATUS_SUCCESS on success
 */
NTSTATUS
Quac100SignGetSizes(
    _In_ QUAC_ALGORITHM Algorithm,
    _Out_opt_ PSIZE_T PublicKeySize,
    _Out_opt_ PSIZE_T SecretKeySize,
    _Out_opt_ PSIZE_T SignatureSize
    );

/**
 * @brief Check if algorithm is supported signature
 *
 * @param[in] DeviceContext     Device context
 * @param[in] Algorithm         Algorithm to check
 *
 * @return TRUE if supported
 */
BOOLEAN
Quac100SignIsSupported(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ QUAC_ALGORITHM Algorithm
    );

/**
 * @brief Check if algorithm is Dilithium
 *
 * @param[in] Algorithm         Algorithm to check
 *
 * @return TRUE if Dilithium algorithm
 */
BOOLEAN
Quac100SignIsDilithium(
    _In_ QUAC_ALGORITHM Algorithm
    );

/**
 * @brief Check if algorithm is SPHINCS+
 *
 * @param[in] Algorithm         Algorithm to check
 *
 * @return TRUE if SPHINCS+ algorithm
 */
BOOLEAN
Quac100SignIsSphincs(
    _In_ QUAC_ALGORITHM Algorithm
    );

/*=============================================================================
 * IOCTL Handlers
 *=============================================================================*/

/**
 * @brief Handle signature keygen IOCTL
 */
NTSTATUS
Quac100IoctlSignKeyGenHandler(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ WDFREQUEST Request,
    _Out_ size_t* BytesReturned
    );

/**
 * @brief Handle sign IOCTL
 */
NTSTATUS
Quac100IoctlSignHandler(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ WDFREQUEST Request,
    _Out_ size_t* BytesReturned
    );

/**
 * @brief Handle verify IOCTL
 */
NTSTATUS
Quac100IoctlVerifyHandler(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ WDFREQUEST Request,
    _Out_ size_t* BytesReturned
    );

#ifdef __cplusplus
}
#endif

#endif /* QUAC100_SIGN_H */
