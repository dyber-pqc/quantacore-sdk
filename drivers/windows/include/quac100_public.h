/**
 * @file quac100_public.h
 * @brief QUAC 100 Public API for Windows Applications
 *
 * This header provides the user-mode interface to the QUAC 100 driver.
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_PUBLIC_H
#define QUAC100_PUBLIC_H

#ifdef _WIN32
#include <windows.h>
#endif

#include "quac100_ioctl.h"
#include "quac100_guid.h"

#ifdef __cplusplus
extern "C" {
#endif

//
// Device path format
//
#define QUAC100_DEVICE_PATH_FORMAT L"\\\\.\\QUAC100_%u"
#define QUAC100_MAX_DEVICES 16

//
// Helper macros
//
#define QUAC_SUCCEEDED(s)   ((s) == QUAC_STATUS_SUCCESS)
#define QUAC_FAILED(s)      ((s) != QUAC_STATUS_SUCCESS)

//
// Key sizes (bytes) - ML-KEM (Kyber)
//
#define QUAC_KYBER512_PUBLIC_KEY_SIZE       800
#define QUAC_KYBER512_SECRET_KEY_SIZE       1632
#define QUAC_KYBER512_CIPHERTEXT_SIZE       768
#define QUAC_KYBER512_SHARED_SECRET_SIZE    32

#define QUAC_KYBER768_PUBLIC_KEY_SIZE       1184
#define QUAC_KYBER768_SECRET_KEY_SIZE       2400
#define QUAC_KYBER768_CIPHERTEXT_SIZE       1088
#define QUAC_KYBER768_SHARED_SECRET_SIZE    32

#define QUAC_KYBER1024_PUBLIC_KEY_SIZE      1568
#define QUAC_KYBER1024_SECRET_KEY_SIZE      3168
#define QUAC_KYBER1024_CIPHERTEXT_SIZE      1568
#define QUAC_KYBER1024_SHARED_SECRET_SIZE   32

//
// Key sizes (bytes) - ML-DSA (Dilithium)
//
#define QUAC_DILITHIUM2_PUBLIC_KEY_SIZE     1312
#define QUAC_DILITHIUM2_SECRET_KEY_SIZE     2528
#define QUAC_DILITHIUM2_SIGNATURE_SIZE      2420

#define QUAC_DILITHIUM3_PUBLIC_KEY_SIZE     1952
#define QUAC_DILITHIUM3_SECRET_KEY_SIZE     4000
#define QUAC_DILITHIUM3_SIGNATURE_SIZE      3293

#define QUAC_DILITHIUM5_PUBLIC_KEY_SIZE     2592
#define QUAC_DILITHIUM5_SECRET_KEY_SIZE     4864
#define QUAC_DILITHIUM5_SIGNATURE_SIZE      4595

#ifdef __cplusplus
}
#endif

#endif /* QUAC100_PUBLIC_H */