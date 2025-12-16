/*++

Module Name:
    hwsim.h

Abstract:
    QUAC 100 Hardware Simulator public interface.
    Applications can link against the simulator library to test
    without hardware.

Copyright:
    Copyright (c) 2025 Dyber, Inc. All Rights Reserved.

--*/

#pragma once

#include <windows.h>
#include <stdbool.h>

#ifdef HWSIM_EXPORTS
#define HWSIM_API __declspec(dllexport)
#else
#define HWSIM_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

//
// Configuration
//
typedef struct _HWSIM_CONFIG {
    bool Verbose;
    bool BreakOnError;
    bool EnableLatency;
    bool AccurateMode;
    
    DWORD KemKeyGenLatencyUs;
    DWORD KemEncapsLatencyUs;
    DWORD KemDecapsLatencyUs;
    DWORD SignKeyGenLatencyUs;
    DWORD SignLatencyUs;
    DWORD VerifyLatencyUs;
    DWORD QrngLatencyPerByteUs;
    
    double ErrorRate;
    DWORD ErrorMask;
    
    double QrngBias;
    bool QrngHealthy;
    DWORD QrngEntropyBits;
    
    bool EnableProfiling;
    
    FILE* LogFile;
    DWORD LogLevel;
} HWSIM_CONFIG, *PHWSIM_CONFIG;

//
// Initialization
//
HWSIM_API void HwSimSetDefaultConfig(PHWSIM_CONFIG config);
HWSIM_API DWORD HwSimInitialize(PHWSIM_CONFIG config);
HWSIM_API void HwSimShutdown(void);

//
// KEM Operations
//
HWSIM_API DWORD HwSimKemKeyGen(DWORD algorithm, BYTE* publicKey, BYTE* secretKey);
HWSIM_API DWORD HwSimKemEncaps(DWORD algorithm, const BYTE* publicKey, BYTE* ciphertext, BYTE* sharedSecret);
HWSIM_API DWORD HwSimKemDecaps(DWORD algorithm, const BYTE* secretKey, const BYTE* ciphertext, BYTE* sharedSecret);

//
// Signature Operations
//
HWSIM_API DWORD HwSimSignKeyGen(DWORD algorithm, BYTE* publicKey, BYTE* secretKey);
HWSIM_API DWORD HwSimSign(DWORD algorithm, const BYTE* secretKey, const BYTE* message, DWORD messageLen, BYTE* signature, DWORD* signatureLen);
HWSIM_API DWORD HwSimVerify(DWORD algorithm, const BYTE* publicKey, const BYTE* message, DWORD messageLen, const BYTE* signature, DWORD signatureLen, bool* valid);

//
// QRNG Operations
//
HWSIM_API DWORD HwSimRandomGenerate(BYTE* buffer, DWORD length, DWORD quality);
HWSIM_API DWORD HwSimRandomHealthTest(bool* passed);

//
// Device Management
//
HWSIM_API DWORD HwSimGetVersion(DWORD* driverMajor, DWORD* driverMinor, DWORD* fwMajor, DWORD* fwMinor);
HWSIM_API DWORD HwSimGetHealth(DWORD* status, DWORD* temperature, DWORD* powerMw);
HWSIM_API DWORD HwSimReset(void);
HWSIM_API DWORD HwSimGetStatistics(UINT64* kemKeyGen, UINT64* kemEncaps, UINT64* kemDecaps, UINT64* signKeyGen, UINT64* signOps, UINT64* verifyOps, UINT64* randomBytes);

#ifdef __cplusplus
}
#endif
