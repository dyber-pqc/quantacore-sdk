<#
.SYNOPSIS
    Sets up the QUAC 100 Windows Driver directory structure for Visual Studio 2022.

.DESCRIPTION
    This script creates the complete directory structure and scaffolded files
    for the QUAC 100 Post-Quantum Cryptographic Accelerator Windows KMDF driver.

.PARAMETER BasePath
    The base path where the driver structure will be created.
    Default: D:\quantacore-sdk\drivers\windows

.PARAMETER Force
    If specified, overwrites existing files.

.EXAMPLE
    .\setup_windows_driver.ps1
    
.EXAMPLE
    .\setup_windows_driver.ps1 -BasePath "C:\MyDrivers\quac100" -Force

.NOTES
    Author: QuantaCore SDK Team
    Version: 1.0.0
    Requires: PowerShell 5.1 or later
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$BasePath = "D:\quantacore-sdk\drivers\windows",
    
    [Parameter(Mandatory = $false)]
    [switch]$Force
)

$ErrorActionPreference = "Stop"

# ============================================================================
# Configuration
# ============================================================================

$Script:FilesCreated = 0
$Script:DirsCreated = 0
$Script:FilesSkipped = 0

# Version info
$Version = @{
    Major = 1
    Minor = 0
    Patch = 0
    Build = 0
}

# GUIDs (pre-generated for consistency)
$GUIDs = @{
    DeviceInterface = "f7d5e47a-3b2c-4d8e-9f1a-6c5b4a3d2e1f"
    DeviceClass     = "8c2d3e4f-5a6b-7c8d-9e0f-1a2b3c4d5e6f"
    VFInterface     = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    CoInstaller     = "12345678-90ab-cdef-1234-567890abcdef"
}

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Status {
    param([string]$Message, [string]$Type = "Info")
    
    $color = switch ($Type) {
        "Info" { "Cyan" }
        "Success" { "Green" }
        "Warning" { "Yellow" }
        "Error" { "Red" }
        default { "White" }
    }
    
    $prefix = switch ($Type) {
        "Info" { "[*]" }
        "Success" { "[+]" }
        "Warning" { "[!]" }
        "Error" { "[-]" }
        default { "[ ]" }
    }
    
    Write-Host "$prefix $Message" -ForegroundColor $color
}

function New-Directory {
    param([string]$Path)
    
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
        $Script:DirsCreated++
        Write-Verbose "Created directory: $Path"
    }
}

function New-FileWithContent {
    param(
        [string]$Path,
        [string]$Content
    )
    
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path $dir)) {
        New-Directory -Path $dir
    }
    
    if ((Test-Path $Path) -and -not $Force) {
        $Script:FilesSkipped++
        Write-Verbose "Skipped (exists): $Path"
        return
    }
    
    # Ensure Windows line endings (CRLF)
    $Content = $Content -replace "`r`n", "`n" -replace "`n", "`r`n"
    
    Set-Content -Path $Path -Value $Content -Encoding UTF8 -NoNewline
    $Script:FilesCreated++
    Write-Verbose "Created file: $Path"
}

# ============================================================================
# Directory Structure
# ============================================================================

function New-DirectoryStructure {
    Write-Status "Creating directory structure..."
    
    $directories = @(
        # Source directories
        "src/quac100/driver"
        "src/quac100/hw"
        "src/quac100/crypto"
        "src/quac100/key"
        "src/quac100/async"
        "src/quac100/power"
        "src/quac100/diag"
        "src/quac100/inf"
        
        # VF driver
        "src/quac100vf/driver"
        "src/quac100vf/inf"
        
        # Common code
        "src/common"
        
        # Public headers
        "include"
        
        # User-mode library
        "lib/quac100lib"
        
        # Tests
        "test/quac100test"
        "test/devcon"
        "test/hwsim"
        
        # Tools
        "tools/sign"
        "tools/package"
        "tools/deploy"
        
        # WPP tracing
        "wpp"
        
        # HLK
        "hlk/playlist"
        "hlk/scripts"
        
        # Documentation
        "docs"
        
        # Samples
        "samples/cpp/basic_usage"
        "samples/cpp/async_operations"
        "samples/cpp/batch_processing"
        "samples/csharp/QuacSample"
        
        # Scripts
        "scripts"
    )
    
    foreach ($dir in $directories) {
        New-Directory -Path (Join-Path $BasePath $dir)
    }
}

# ============================================================================
# File Content Generators
# ============================================================================

function Get-ReadmeContent {
    return @"
# QUAC 100 Windows Driver

Windows Kernel-Mode Driver Framework (KMDF) driver for the QUAC 100 Post-Quantum Cryptographic Accelerator.

## Overview

This driver provides Windows support for the QUAC 100 PCIe hardware accelerator, enabling:

- **ML-KEM (Kyber)**: Post-quantum key encapsulation (512, 768, 1024)
- **ML-DSA (Dilithium)**: Post-quantum digital signatures (2, 3, 5)
- **SLH-DSA (SPHINCS+)**: Hash-based signatures (128s/f, 192s/f, 256s/f)
- **QRNG**: Hardware quantum random number generation

## Requirements

### Development
- Windows 11 SDK (10.0.22621.0 or later)
- Windows Driver Kit (WDK) 11
- Visual Studio 2022 with "Desktop development with C++"
- Spectre-mitigated libraries

### Runtime
- Windows 11 (Build 22000 or later)
- Windows 10 Version 21H2 or later (with limitations)
- PCIe Gen3 x8 slot (Gen4 recommended)

## Building

1. Open ``quac100.sln`` in Visual Studio 2022
2. Select configuration (Debug/Release) and platform (x64/ARM64)
3. Build solution (Ctrl+Shift+B)

Or use PowerShell:
``````powershell
.\scripts\build.ps1 -Configuration Release -Platform x64
``````

## Installation

### Test Signing (Development)
``````powershell
# Enable test signing (requires reboot)
.\tools\deploy\enable_testsigning.ps1

# Install driver
.\tools\deploy\install_driver.ps1
``````

### Production (Signed Driver)
``````powershell
# Install signed driver package
pnputil /add-driver quac100.inf /install
``````

## Project Structure

| Directory | Description |
|-----------|-------------|
| ``src/quac100/`` | Main KMDF driver (Physical Function) |
| ``src/quac100vf/`` | SR-IOV Virtual Function driver |
| ``src/common/`` | Shared code between PF/VF drivers |
| ``include/`` | Public headers for applications |
| ``lib/`` | User-mode interface library |
| ``test/`` | Test applications |
| ``tools/`` | Build, signing, deployment tools |

## Documentation

- [Architecture Overview](docs/architecture.md)
- [Building Guide](docs/building.md)
- [Installation Guide](docs/installation.md)
- [IOCTL Reference](docs/ioctl_reference.md)
- [Debugging Guide](docs/debugging.md)
- [Troubleshooting](docs/troubleshooting.md)

## License

Copyright 2025 Dyber, Inc. All Rights Reserved.

## Support

For support, contact: support@dyber.org
"@
}

function Get-SolutionFileContent {
    return @"

Microsoft Visual Studio Solution File, Format Version 12.00
# Visual Studio Version 17
VisualStudioVersion = 17.0.31903.59
MinimumVisualStudioVersion = 10.0.40219.1
Project("{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942}") = "quac100", "src\quac100\quac100.vcxproj", "{$(([guid]::NewGuid()).ToString().ToUpper())}"
EndProject
Project("{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942}") = "quac100vf", "src\quac100vf\quac100vf.vcxproj", "{$(([guid]::NewGuid()).ToString().ToUpper())}"
EndProject
Project("{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942}") = "quac100lib", "lib\quac100lib\quac100lib.vcxproj", "{$(([guid]::NewGuid()).ToString().ToUpper())}"
EndProject
Project("{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942}") = "quac100test", "test\quac100test\quac100test.vcxproj", "{$(([guid]::NewGuid()).ToString().ToUpper())}"
EndProject
Project("{2150E333-8FDC-42A3-9474-1A3956D46DE8}") = "Solution Items", "Solution Items", "{$(([guid]::NewGuid()).ToString().ToUpper())}"
	ProjectSection(SolutionItems) = preProject
		README.md = README.md
	EndProjectSection
EndProject
Global
	GlobalSection(SolutionConfigurationPlatforms) = preSolution
		Debug|ARM64 = Debug|ARM64
		Debug|x64 = Debug|x64
		Release|ARM64 = Release|ARM64
		Release|x64 = Release|x64
	EndGlobalSection
	GlobalSection(ProjectConfigurationPlatforms) = postSolution
	EndGlobalSection
	GlobalSection(SolutionProperties) = preSolution
		HideSolutionNode = FALSE
	EndGlobalSection
EndGlobal
"@
}

function Get-VersionHeaderContent {
    return @"
/**
 * @file version.h
 * @brief QUAC 100 Windows Driver Version Information
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_VERSION_H
#define QUAC100_VERSION_H

#define QUAC100_VERSION_MAJOR       $($Version.Major)
#define QUAC100_VERSION_MINOR       $($Version.Minor)
#define QUAC100_VERSION_PATCH       $($Version.Patch)
#define QUAC100_VERSION_BUILD       $($Version.Build)

#define QUAC100_VERSION_STRING      "$($Version.Major).$($Version.Minor).$($Version.Patch).$($Version.Build)"
#define QUAC100_VERSION_HEX         0x$('{0:X2}{1:X2}{2:X2}{3:X2}' -f $Version.Major, $Version.Minor, $Version.Patch, $Version.Build)

#define QUAC100_COMPANY_NAME        "Dyber, Inc."
#define QUAC100_PRODUCT_NAME        "QUAC 100 Post-Quantum Cryptographic Accelerator"
#define QUAC100_COPYRIGHT           "Copyright (C) 2025 Dyber, Inc. All Rights Reserved."

#endif /* QUAC100_VERSION_H */
"@
}

function Get-GuidHeaderContent {
    return @"
/**
 * @file quac100_guid.h
 * @brief QUAC 100 Device Interface GUIDs
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_GUID_H
#define QUAC100_GUID_H

#include <initguid.h>

//
// Device Interface GUID for QUAC 100 Physical Function
// {$($GUIDs.DeviceInterface.ToUpper())}
//
DEFINE_GUID(GUID_DEVINTERFACE_QUAC100,
    0x$($GUIDs.DeviceInterface.Substring(0,8)), 0x$($GUIDs.DeviceInterface.Substring(9,4)), 0x$($GUIDs.DeviceInterface.Substring(14,4)),
    0x$($GUIDs.DeviceInterface.Substring(19,2)), 0x$($GUIDs.DeviceInterface.Substring(21,2)),
    0x$($GUIDs.DeviceInterface.Substring(24,2)), 0x$($GUIDs.DeviceInterface.Substring(26,2)),
    0x$($GUIDs.DeviceInterface.Substring(28,2)), 0x$($GUIDs.DeviceInterface.Substring(30,2)),
    0x$($GUIDs.DeviceInterface.Substring(32,2)), 0x$($GUIDs.DeviceInterface.Substring(34,2)));

//
// Device Interface GUID for QUAC 100 Virtual Function (SR-IOV)
// {$($GUIDs.VFInterface.ToUpper())}
//
DEFINE_GUID(GUID_DEVINTERFACE_QUAC100_VF,
    0x$($GUIDs.VFInterface.Substring(0,8)), 0x$($GUIDs.VFInterface.Substring(9,4)), 0x$($GUIDs.VFInterface.Substring(14,4)),
    0x$($GUIDs.VFInterface.Substring(19,2)), 0x$($GUIDs.VFInterface.Substring(21,2)),
    0x$($GUIDs.VFInterface.Substring(24,2)), 0x$($GUIDs.VFInterface.Substring(26,2)),
    0x$($GUIDs.VFInterface.Substring(28,2)), 0x$($GUIDs.VFInterface.Substring(30,2)),
    0x$($GUIDs.VFInterface.Substring(32,2)), 0x$($GUIDs.VFInterface.Substring(34,2)));

//
// Device Setup Class GUID
// {$($GUIDs.DeviceClass.ToUpper())}
//
DEFINE_GUID(GUID_DEVCLASS_QUAC100,
    0x$($GUIDs.DeviceClass.Substring(0,8)), 0x$($GUIDs.DeviceClass.Substring(9,4)), 0x$($GUIDs.DeviceClass.Substring(14,4)),
    0x$($GUIDs.DeviceClass.Substring(19,2)), 0x$($GUIDs.DeviceClass.Substring(21,2)),
    0x$($GUIDs.DeviceClass.Substring(24,2)), 0x$($GUIDs.DeviceClass.Substring(26,2)),
    0x$($GUIDs.DeviceClass.Substring(28,2)), 0x$($GUIDs.DeviceClass.Substring(30,2)),
    0x$($GUIDs.DeviceClass.Substring(32,2)), 0x$($GUIDs.DeviceClass.Substring(34,2)));

#endif /* QUAC100_GUID_H */
"@
}

function Get-PublicIoctlHeaderContent {
    return @'
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
'@
}

function Get-PublicHeaderContent {
    return @'
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
'@
}

function Get-DriverHeaderContent {
    return @'
/**
 * @file driver.h
 * @brief QUAC 100 KMDF Driver - Main Header
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_DRIVER_H
#define QUAC100_DRIVER_H

#include <ntddk.h>
#include <wdf.h>
#include <initguid.h>
#include <wdmguid.h>

#include "trace.h"
#include "device.h"
#include "queue.h"

//
// Driver-wide definitions
//

#define QUAC100_POOL_TAG        'CAUQ'  // 'QUAC' reversed
#define QUAC100_DRIVER_NAME     L"QUAC100"

//
// PCI identification
//
#define QUAC_PCI_VENDOR_ID      0x1DFB  // Placeholder vendor ID
#define QUAC_PCI_DEVICE_ID      0x0100  // QUAC 100 device ID

//
// Driver context
//
typedef struct _DRIVER_CONTEXT {
    WDFDRIVER Driver;
    ULONG DeviceCount;
    BOOLEAN Initialized;
} DRIVER_CONTEXT, *PDRIVER_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DRIVER_CONTEXT, GetDriverContext)

//
// Function prototypes
//

DRIVER_INITIALIZE DriverEntry;

EVT_WDF_DRIVER_DEVICE_ADD       Quac100EvtDeviceAdd;
EVT_WDF_OBJECT_CONTEXT_CLEANUP  Quac100EvtDriverContextCleanup;

//
// Debug helpers
//
#if DBG
#define QUAC_DEBUG_PRINT(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, \
               "QUAC100: " fmt "\n", ##__VA_ARGS__)
#else
#define QUAC_DEBUG_PRINT(fmt, ...)
#endif

#endif /* QUAC100_DRIVER_H */
'@
}

function Get-DriverSourceContent {
    return @'
/**
 * @file driver.c
 * @brief QUAC 100 KMDF Driver - Entry Point and Initialization
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include "precomp.h"
#include "driver.h"
#include "driver.tmh"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, Quac100EvtDeviceAdd)
#pragma alloc_text(PAGE, Quac100EvtDriverContextCleanup)
#endif

/**
 * @brief Driver entry point
 *
 * @param DriverObject Pointer to driver object
 * @param RegistryPath Path to driver's registry key
 * @return NTSTATUS
 */
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;
    WDF_DRIVER_CONFIG config;
    WDF_OBJECT_ATTRIBUTES attributes;
    WDFDRIVER driver;
    PDRIVER_CONTEXT driverContext;

    //
    // Initialize WPP tracing
    //
    WPP_INIT_TRACING(DriverObject, RegistryPath);
    
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER,
                "QUAC 100 Driver Entry - Version %d.%d.%d",
                QUAC100_VERSION_MAJOR,
                QUAC100_VERSION_MINOR,
                QUAC100_VERSION_PATCH);

    //
    // Initialize driver configuration
    //
    WDF_DRIVER_CONFIG_INIT(&config, Quac100EvtDeviceAdd);

    //
    // Set up driver attributes with context
    //
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, DRIVER_CONTEXT);
    attributes.EvtCleanupCallback = Quac100EvtDriverContextCleanup;

    //
    // Create the driver object
    //
    status = WdfDriverCreate(
        DriverObject,
        RegistryPath,
        &attributes,
        &config,
        &driver
        );

    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER,
                    "WdfDriverCreate failed: %!STATUS!", status);
        WPP_CLEANUP(DriverObject);
        return status;
    }

    //
    // Initialize driver context
    //
    driverContext = GetDriverContext(driver);
    driverContext->Driver = driver;
    driverContext->DeviceCount = 0;
    driverContext->Initialized = TRUE;

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER,
                "Driver initialization complete");

    return STATUS_SUCCESS;
}

/**
 * @brief Device add callback
 *
 * Called by PnP manager for each device instance.
 *
 * @param Driver Driver object
 * @param DeviceInit Device initialization structure
 * @return NTSTATUS
 */
NTSTATUS
Quac100EvtDeviceAdd(
    _In_ WDFDRIVER Driver,
    _Inout_ PWDFDEVICE_INIT DeviceInit
    )
{
    NTSTATUS status;
    PDRIVER_CONTEXT driverContext;

    PAGED_CODE();
    
    UNREFERENCED_PARAMETER(DeviceInit);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER,
                "%!FUNC! Entry");

    driverContext = GetDriverContext(Driver);

    //
    // Create and initialize the device
    //
    status = Quac100CreateDevice(DeviceInit);
    
    if (NT_SUCCESS(status)) {
        driverContext->DeviceCount++;
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER,
                    "Device %lu added successfully",
                    driverContext->DeviceCount);
    } else {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER,
                    "Failed to create device: %!STATUS!", status);
    }

    return status;
}

/**
 * @brief Driver cleanup callback
 *
 * @param DriverObject Driver object being cleaned up
 */
VOID
Quac100EvtDriverContextCleanup(
    _In_ WDFOBJECT DriverObject
    )
{
    PAGED_CODE();

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER,
                "%!FUNC! Entry");

    //
    // Stop WPP tracing
    //
    WPP_CLEANUP(WdfDriverWdmGetDriverObject((WDFDRIVER)DriverObject));
}
'@
}

function Get-DeviceHeaderContent {
    return @'
/**
 * @file device.h
 * @brief QUAC 100 KMDF Driver - Device Context and Functions
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_DEVICE_H
#define QUAC100_DEVICE_H

#include <ntddk.h>
#include <wdf.h>

//
// Forward declarations
//
typedef struct _DEVICE_CONTEXT DEVICE_CONTEXT, *PDEVICE_CONTEXT;

//
// BAR information
//
typedef struct _BAR_INFO {
    PHYSICAL_ADDRESS PhysicalAddress;
    PVOID VirtualAddress;
    SIZE_T Length;
    BOOLEAN IsMapped;
} BAR_INFO, *PBAR_INFO;

//
// Device capabilities
//
typedef struct _DEVICE_CAPS {
    ULONG Capabilities;
    ULONG MaxBatchSize;
    ULONG MaxPendingJobs;
    ULONG KeySlots;
    BOOLEAN SriovSupported;
    USHORT NumVFs;
} DEVICE_CAPS, *PDEVICE_CAPS;

//
// Hardware state
//
typedef struct _HW_STATE {
    BOOLEAN Initialized;
    BOOLEAN DmaEnabled;
    BOOLEAN InterruptsEnabled;
    LONG TemperatureCelsius;
    ULONG EntropyAvailable;
    ULONG CurrentStatus;
} HW_STATE, *PHW_STATE;

//
// Device context structure
//
typedef struct _DEVICE_CONTEXT {
    //
    // WDF handles
    //
    WDFDEVICE Device;
    WDFINTERRUPT Interrupt;
    WDFDMAENABLER DmaEnabler;
    
    //
    // Device identification
    //
    ULONG DeviceIndex;
    WCHAR SerialNumber[32];
    USHORT VendorId;
    USHORT DeviceId;
    UCHAR HardwareRevision;
    
    //
    // PCIe resources
    //
    BAR_INFO Bars[6];
    BUS_INTERFACE_STANDARD BusInterface;
    
    //
    // Hardware state
    //
    DEVICE_CAPS Caps;
    HW_STATE HwState;
    
    //
    // Synchronization
    //
    KSPIN_LOCK HwLock;
    KEVENT InitEvent;
    
    //
    // Statistics
    //
    ULONGLONG OperationsCompleted;
    ULONGLONG OperationsFailed;
    
} DEVICE_CONTEXT, *PDEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_CONTEXT, GetDeviceContext)

//
// Function prototypes
//

NTSTATUS
Quac100CreateDevice(
    _Inout_ PWDFDEVICE_INIT DeviceInit
    );

EVT_WDF_DEVICE_PREPARE_HARDWARE     Quac100EvtDevicePrepareHardware;
EVT_WDF_DEVICE_RELEASE_HARDWARE     Quac100EvtDeviceReleaseHardware;
EVT_WDF_DEVICE_D0_ENTRY             Quac100EvtDeviceD0Entry;
EVT_WDF_DEVICE_D0_EXIT              Quac100EvtDeviceD0Exit;

//
// Hardware initialization
//
NTSTATUS
Quac100HwInitialize(
    _In_ PDEVICE_CONTEXT DeviceContext
    );

VOID
Quac100HwShutdown(
    _In_ PDEVICE_CONTEXT DeviceContext
    );

//
// Register access
//
ULONG
Quac100ReadRegister32(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ ULONG Offset
    );

VOID
Quac100WriteRegister32(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ ULONG Offset,
    _In_ ULONG Value
    );

#endif /* QUAC100_DEVICE_H */
'@
}

function Get-DeviceSourceContent {
    return @'
/**
 * @file device.c
 * @brief QUAC 100 KMDF Driver - Device Initialization
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include "precomp.h"
#include "driver.h"
#include "device.h"
#include "queue.h"
#include "device.tmh"

#include "../include/quac100_guid.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, Quac100CreateDevice)
#pragma alloc_text(PAGE, Quac100EvtDevicePrepareHardware)
#pragma alloc_text(PAGE, Quac100EvtDeviceReleaseHardware)
#endif

/**
 * @brief Create and initialize a device object
 *
 * @param DeviceInit Device initialization structure
 * @return NTSTATUS
 */
NTSTATUS
Quac100CreateDevice(
    _Inout_ PWDFDEVICE_INIT DeviceInit
    )
{
    NTSTATUS status;
    WDF_OBJECT_ATTRIBUTES deviceAttributes;
    WDF_PNPPOWER_EVENT_CALLBACKS pnpPowerCallbacks;
    WDFDEVICE device;
    PDEVICE_CONTEXT deviceContext;

    PAGED_CODE();

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DEVICE,
                "%!FUNC! Entry");

    //
    // Configure PnP/Power callbacks
    //
    WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnpPowerCallbacks);
    pnpPowerCallbacks.EvtDevicePrepareHardware = Quac100EvtDevicePrepareHardware;
    pnpPowerCallbacks.EvtDeviceReleaseHardware = Quac100EvtDeviceReleaseHardware;
    pnpPowerCallbacks.EvtDeviceD0Entry = Quac100EvtDeviceD0Entry;
    pnpPowerCallbacks.EvtDeviceD0Exit = Quac100EvtDeviceD0Exit;

    WdfDeviceInitSetPnpPowerEventCallbacks(DeviceInit, &pnpPowerCallbacks);

    //
    // Set device attributes
    //
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, DEVICE_CONTEXT);

    //
    // Create the device
    //
    status = WdfDeviceCreate(&DeviceInit, &deviceAttributes, &device);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DEVICE,
                    "WdfDeviceCreate failed: %!STATUS!", status);
        return status;
    }

    //
    // Initialize device context
    //
    deviceContext = GetDeviceContext(device);
    RtlZeroMemory(deviceContext, sizeof(DEVICE_CONTEXT));
    deviceContext->Device = device;
    KeInitializeSpinLock(&deviceContext->HwLock);
    KeInitializeEvent(&deviceContext->InitEvent, NotificationEvent, FALSE);

    //
    // Create device interface
    //
    status = WdfDeviceCreateDeviceInterface(
        device,
        &GUID_DEVINTERFACE_QUAC100,
        NULL
        );
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DEVICE,
                    "WdfDeviceCreateDeviceInterface failed: %!STATUS!", status);
        return status;
    }

    //
    // Create I/O queues
    //
    status = Quac100QueueInitialize(device);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DEVICE,
                    "Quac100QueueInitialize failed: %!STATUS!", status);
        return status;
    }

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DEVICE,
                "Device created successfully");

    return status;
}

/**
 * @brief Prepare hardware callback
 *
 * @param Device Device object
 * @param ResourcesRaw Raw resources
 * @param ResourcesTranslated Translated resources
 * @return NTSTATUS
 */
NTSTATUS
Quac100EvtDevicePrepareHardware(
    _In_ WDFDEVICE Device,
    _In_ WDFCMRESLIST ResourcesRaw,
    _In_ WDFCMRESLIST ResourcesTranslated
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PDEVICE_CONTEXT deviceContext;
    ULONG resourceCount;
    ULONG i;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR descriptor;
    ULONG barIndex = 0;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(ResourcesRaw);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DEVICE,
                "%!FUNC! Entry");

    deviceContext = GetDeviceContext(Device);
    resourceCount = WdfCmResourceListGetCount(ResourcesTranslated);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DEVICE,
                "Resource count: %lu", resourceCount);

    //
    // Parse resources and map BARs
    //
    for (i = 0; i < resourceCount; i++) {
        descriptor = WdfCmResourceListGetDescriptor(ResourcesTranslated, i);
        
        if (descriptor == NULL) {
            continue;
        }

        switch (descriptor->Type) {
        case CmResourceTypeMemory:
            if (barIndex < 6) {
                deviceContext->Bars[barIndex].PhysicalAddress = 
                    descriptor->u.Memory.Start;
                deviceContext->Bars[barIndex].Length = 
                    descriptor->u.Memory.Length;
                
                //
                // Map the BAR
                //
                deviceContext->Bars[barIndex].VirtualAddress = 
                    MmMapIoSpace(
                        descriptor->u.Memory.Start,
                        descriptor->u.Memory.Length,
                        MmNonCached
                        );
                
                if (deviceContext->Bars[barIndex].VirtualAddress != NULL) {
                    deviceContext->Bars[barIndex].IsMapped = TRUE;
                    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DEVICE,
                                "BAR%lu mapped: PA=0x%llX, VA=0x%p, Len=0x%llX",
                                barIndex,
                                descriptor->u.Memory.Start.QuadPart,
                                deviceContext->Bars[barIndex].VirtualAddress,
                                (ULONGLONG)descriptor->u.Memory.Length);
                } else {
                    TraceEvents(TRACE_LEVEL_ERROR, TRACE_DEVICE,
                                "Failed to map BAR%lu", barIndex);
                    status = STATUS_INSUFFICIENT_RESOURCES;
                }
                barIndex++;
            }
            break;

        case CmResourceTypeInterrupt:
            TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DEVICE,
                        "Interrupt resource: Level=%lu, Vector=%lu",
                        descriptor->u.Interrupt.Level,
                        descriptor->u.Interrupt.Vector);
            break;

        default:
            break;
        }
    }

    if (NT_SUCCESS(status)) {
        //
        // Initialize hardware
        //
        status = Quac100HwInitialize(deviceContext);
    }

    return status;
}

/**
 * @brief Release hardware callback
 *
 * @param Device Device object
 * @param ResourcesTranslated Translated resources
 * @return NTSTATUS
 */
NTSTATUS
Quac100EvtDeviceReleaseHardware(
    _In_ WDFDEVICE Device,
    _In_ WDFCMRESLIST ResourcesTranslated
    )
{
    PDEVICE_CONTEXT deviceContext;
    ULONG i;

    PAGED_CODE();
    UNREFERENCED_PARAMETER(ResourcesTranslated);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DEVICE,
                "%!FUNC! Entry");

    deviceContext = GetDeviceContext(Device);

    //
    // Shutdown hardware
    //
    Quac100HwShutdown(deviceContext);

    //
    // Unmap BARs
    //
    for (i = 0; i < 6; i++) {
        if (deviceContext->Bars[i].IsMapped && 
            deviceContext->Bars[i].VirtualAddress != NULL) {
            MmUnmapIoSpace(
                deviceContext->Bars[i].VirtualAddress,
                deviceContext->Bars[i].Length
                );
            deviceContext->Bars[i].VirtualAddress = NULL;
            deviceContext->Bars[i].IsMapped = FALSE;
        }
    }

    return STATUS_SUCCESS;
}

/**
 * @brief D0 entry callback (power up)
 */
NTSTATUS
Quac100EvtDeviceD0Entry(
    _In_ WDFDEVICE Device,
    _In_ WDF_POWER_DEVICE_STATE PreviousState
    )
{
    PDEVICE_CONTEXT deviceContext;

    UNREFERENCED_PARAMETER(PreviousState);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DEVICE,
                "%!FUNC! from %!WDF_POWER_DEVICE_STATE!", PreviousState);

    deviceContext = GetDeviceContext(Device);

    //
    // Re-initialize hardware if coming from low power state
    //
    if (PreviousState != WdfPowerDeviceD0) {
        // Restore hardware state
        deviceContext->HwState.Initialized = TRUE;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief D0 exit callback (power down)
 */
NTSTATUS
Quac100EvtDeviceD0Exit(
    _In_ WDFDEVICE Device,
    _In_ WDF_POWER_DEVICE_STATE TargetState
    )
{
    PDEVICE_CONTEXT deviceContext;

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DEVICE,
                "%!FUNC! to %!WDF_POWER_DEVICE_STATE!", TargetState);

    deviceContext = GetDeviceContext(Device);

    //
    // Save hardware state before power down
    //
    if (TargetState != WdfPowerDeviceD0) {
        deviceContext->HwState.Initialized = FALSE;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief Initialize hardware
 */
NTSTATUS
Quac100HwInitialize(
    _In_ PDEVICE_CONTEXT DeviceContext
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DEVICE,
                "%!FUNC! Entry");

    //
    // Verify BAR0 is mapped (control registers)
    //
    if (!DeviceContext->Bars[0].IsMapped) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DEVICE,
                    "BAR0 not mapped, cannot initialize hardware");
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Read device identification
    //
    // TODO: Read from hardware registers
    // DeviceContext->VendorId = Quac100ReadRegister32(DeviceContext, QUAC_REG_DEVICE_ID) & 0xFFFF;
    
    //
    // Initialize device capabilities
    //
    DeviceContext->Caps.Capabilities = 
        QUAC_CAP_KEM_KYBER | 
        QUAC_CAP_SIGN_DILITHIUM | 
        QUAC_CAP_SIGN_SPHINCS |
        QUAC_CAP_QRNG |
        QUAC_CAP_ASYNC |
        QUAC_CAP_BATCH |
        QUAC_CAP_DMA;
    
    DeviceContext->Caps.MaxBatchSize = 1024;
    DeviceContext->Caps.MaxPendingJobs = 4096;
    DeviceContext->Caps.KeySlots = 256;

    DeviceContext->HwState.Initialized = TRUE;

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DEVICE,
                "Hardware initialized successfully");

    return status;
}

/**
 * @brief Shutdown hardware
 */
VOID
Quac100HwShutdown(
    _In_ PDEVICE_CONTEXT DeviceContext
    )
{
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DEVICE,
                "%!FUNC! Entry");

    DeviceContext->HwState.Initialized = FALSE;

    //
    // TODO: Perform hardware shutdown sequence
    //
}

/**
 * @brief Read 32-bit register
 */
ULONG
Quac100ReadRegister32(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ ULONG Offset
    )
{
    if (!DeviceContext->Bars[0].IsMapped) {
        return 0xFFFFFFFF;
    }

    return READ_REGISTER_ULONG(
        (PULONG)((PUCHAR)DeviceContext->Bars[0].VirtualAddress + Offset)
        );
}

/**
 * @brief Write 32-bit register
 */
VOID
Quac100WriteRegister32(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ ULONG Offset,
    _In_ ULONG Value
    )
{
    if (!DeviceContext->Bars[0].IsMapped) {
        return;
    }

    WRITE_REGISTER_ULONG(
        (PULONG)((PUCHAR)DeviceContext->Bars[0].VirtualAddress + Offset),
        Value
        );
}
'@
}

function Get-QueueHeaderContent {
    return @'
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
'@
}

function Get-QueueSourceContent {
    return @'
/**
 * @file queue.c
 * @brief QUAC 100 KMDF Driver - I/O Queue Implementation
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include "precomp.h"
#include "driver.h"
#include "queue.h"
#include "ioctl.h"
#include "queue.tmh"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, Quac100QueueInitialize)
#endif

/**
 * @brief Initialize I/O queues
 *
 * @param Device Device object
 * @return NTSTATUS
 */
NTSTATUS
Quac100QueueInitialize(
    _In_ WDFDEVICE Device
    )
{
    NTSTATUS status;
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDF_OBJECT_ATTRIBUTES queueAttributes;
    WDFQUEUE queue;
    PQUEUE_CONTEXT queueContext;

    PAGED_CODE();

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE,
                "%!FUNC! Entry");

    //
    // Configure the default queue for IOCTLs
    //
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(
        &queueConfig,
        WdfIoQueueDispatchParallel
        );

    queueConfig.EvtIoDeviceControl = Quac100EvtIoDeviceControl;
    queueConfig.EvtIoStop = Quac100EvtIoStop;

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&queueAttributes, QUEUE_CONTEXT);

    status = WdfIoQueueCreate(
        Device,
        &queueConfig,
        &queueAttributes,
        &queue
        );

    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_QUEUE,
                    "WdfIoQueueCreate failed: %!STATUS!", status);
        return status;
    }

    queueContext = GetQueueContext(queue);
    queueContext->Queue = queue;
    queueContext->Device = Device;

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE,
                "Queue initialized successfully");

    return status;
}

/**
 * @brief Handle IOCTL requests
 *
 * @param Queue Queue object
 * @param Request Request object
 * @param OutputBufferLength Output buffer length
 * @param InputBufferLength Input buffer length
 * @param IoControlCode IOCTL code
 */
VOID
Quac100EvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
    )
{
    NTSTATUS status;
    PQUEUE_CONTEXT queueContext;
    PDEVICE_CONTEXT deviceContext;
    size_t bytesReturned = 0;

    TraceEvents(TRACE_LEVEL_VERBOSE, TRACE_QUEUE,
                "%!FUNC! IOCTL=0x%08X, InLen=%Iu, OutLen=%Iu",
                IoControlCode, InputBufferLength, OutputBufferLength);

    queueContext = GetQueueContext(Queue);
    deviceContext = GetDeviceContext(queueContext->Device);

    //
    // Dispatch to IOCTL handler
    //
    status = Quac100DispatchIoctl(
        deviceContext,
        Request,
        IoControlCode,
        InputBufferLength,
        OutputBufferLength,
        &bytesReturned
        );

    WdfRequestCompleteWithInformation(Request, status, bytesReturned);
}

/**
 * @brief Handle queue stop events
 *
 * @param Queue Queue object
 * @param Request Request object
 * @param ActionFlags Action flags
 */
VOID
Quac100EvtIoStop(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ ULONG ActionFlags
    )
{
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_QUEUE,
                "%!FUNC! ActionFlags=0x%08X", ActionFlags);

    UNREFERENCED_PARAMETER(Queue);

    if (ActionFlags & WdfRequestStopActionSuspend) {
        WdfRequestStopAcknowledge(Request, FALSE);
    } else if (ActionFlags & WdfRequestStopActionPurge) {
        WdfRequestCancelSentRequest(Request);
    }
}
'@
}

function Get-IoctlHeaderContent {
    return @'
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
'@
}

function Get-IoctlSourceContent {
    return @'
/**
 * @file ioctl.c
 * @brief QUAC 100 KMDF Driver - IOCTL Handler Implementation
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#include "precomp.h"
#include "driver.h"
#include "ioctl.h"
#include "ioctl.tmh"

/**
 * @brief Dispatch IOCTL requests
 */
NTSTATUS
Quac100DispatchIoctl(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ WDFREQUEST Request,
    _In_ ULONG IoControlCode,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    *BytesReturned = 0;

    TraceEvents(TRACE_LEVEL_VERBOSE, TRACE_IOCTL,
                "%!FUNC! IOCTL=0x%08X", IoControlCode);

    switch (IoControlCode) {
    
    case IOCTL_QUAC_GET_VERSION:
        status = Quac100IoctlGetVersion(DeviceContext, Request, BytesReturned);
        break;
        
    case IOCTL_QUAC_GET_INFO:
        status = Quac100IoctlGetInfo(DeviceContext, Request, BytesReturned);
        break;

    case IOCTL_QUAC_GET_CAPS:
        // TODO: Implement
        status = STATUS_NOT_IMPLEMENTED;
        break;

    case IOCTL_QUAC_GET_STATUS:
        // TODO: Implement
        status = STATUS_NOT_IMPLEMENTED;
        break;

    case IOCTL_QUAC_RESET:
        // TODO: Implement
        status = STATUS_NOT_IMPLEMENTED;
        break;

    case IOCTL_QUAC_KEM_KEYGEN:
        status = Quac100IoctlKemKeygen(DeviceContext, Request, BytesReturned);
        break;

    case IOCTL_QUAC_KEM_ENCAPS:
        // TODO: Implement
        status = STATUS_NOT_IMPLEMENTED;
        break;

    case IOCTL_QUAC_KEM_DECAPS:
        // TODO: Implement
        status = STATUS_NOT_IMPLEMENTED;
        break;

    case IOCTL_QUAC_RANDOM:
        status = Quac100IoctlRandom(DeviceContext, Request, BytesReturned);
        break;

    default:
        TraceEvents(TRACE_LEVEL_WARNING, TRACE_IOCTL,
                    "Unknown IOCTL: 0x%08X", IoControlCode);
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    return status;
}

/**
 * @brief Handle GET_VERSION IOCTL
 */
NTSTATUS
Quac100IoctlGetVersion(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ WDFREQUEST Request,
    _Out_ size_t* BytesReturned
    )
{
    NTSTATUS status;
    PQUAC_VERSION_INFO versionInfo;
    size_t bufferSize;

    UNREFERENCED_PARAMETER(DeviceContext);

    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(QUAC_VERSION_INFO),
        (PVOID*)&versionInfo,
        &bufferSize
        );

    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_IOCTL,
                    "WdfRequestRetrieveOutputBuffer failed: %!STATUS!", status);
        return status;
    }

    RtlZeroMemory(versionInfo, sizeof(QUAC_VERSION_INFO));
    versionInfo->StructSize = sizeof(QUAC_VERSION_INFO);
    versionInfo->DriverVersionMajor = QUAC100_VERSION_MAJOR;
    versionInfo->DriverVersionMinor = QUAC100_VERSION_MINOR;
    versionInfo->DriverVersionPatch = QUAC100_VERSION_PATCH;
    versionInfo->DriverVersionBuild = QUAC100_VERSION_BUILD;
    versionInfo->ApiVersion = 0x00010000;  // 1.0.0

    *BytesReturned = sizeof(QUAC_VERSION_INFO);

    return STATUS_SUCCESS;
}

/**
 * @brief Handle GET_INFO IOCTL
 */
NTSTATUS
Quac100IoctlGetInfo(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ WDFREQUEST Request,
    _Out_ size_t* BytesReturned
    )
{
    NTSTATUS status;
    PQUAC_DEVICE_INFO deviceInfo;
    size_t bufferSize;

    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(QUAC_DEVICE_INFO),
        (PVOID*)&deviceInfo,
        &bufferSize
        );

    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_IOCTL,
                    "WdfRequestRetrieveOutputBuffer failed: %!STATUS!", status);
        return status;
    }

    RtlZeroMemory(deviceInfo, sizeof(QUAC_DEVICE_INFO));
    deviceInfo->StructSize = sizeof(QUAC_DEVICE_INFO);
    deviceInfo->DeviceIndex = DeviceContext->DeviceIndex;
    
    RtlStringCbCopyW(deviceInfo->DeviceName, sizeof(deviceInfo->DeviceName),
                      L"QUAC 100 PQC Accelerator");
    RtlStringCbCopyW(deviceInfo->SerialNumber, sizeof(deviceInfo->SerialNumber),
                      DeviceContext->SerialNumber);
    
    deviceInfo->VendorId = DeviceContext->VendorId;
    deviceInfo->DeviceId = DeviceContext->DeviceId;
    deviceInfo->HardwareRevision = DeviceContext->HardwareRevision;
    deviceInfo->Capabilities = DeviceContext->Caps.Capabilities;
    deviceInfo->Status = DeviceContext->HwState.CurrentStatus;
    deviceInfo->MaxBatchSize = DeviceContext->Caps.MaxBatchSize;
    deviceInfo->MaxPendingJobs = DeviceContext->Caps.MaxPendingJobs;
    deviceInfo->KeySlotsTotal = DeviceContext->Caps.KeySlots;
    deviceInfo->TemperatureCelsius = DeviceContext->HwState.TemperatureCelsius;
    deviceInfo->EntropyAvailable = DeviceContext->HwState.EntropyAvailable;
    deviceInfo->OperationsCompleted = DeviceContext->OperationsCompleted;
    deviceInfo->OperationsFailed = DeviceContext->OperationsFailed;

    *BytesReturned = sizeof(QUAC_DEVICE_INFO);

    return STATUS_SUCCESS;
}

/**
 * @brief Handle KEM_KEYGEN IOCTL
 */
NTSTATUS
Quac100IoctlKemKeygen(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ WDFREQUEST Request,
    _Out_ size_t* BytesReturned
    )
{
    UNREFERENCED_PARAMETER(DeviceContext);
    UNREFERENCED_PARAMETER(Request);
    
    *BytesReturned = 0;
    
    // TODO: Implement KEM key generation via hardware
    
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_IOCTL,
                "KEM Keygen - Not yet implemented");
    
    return STATUS_NOT_IMPLEMENTED;
}

/**
 * @brief Handle RANDOM IOCTL
 */
NTSTATUS
Quac100IoctlRandom(
    _In_ PDEVICE_CONTEXT DeviceContext,
    _In_ WDFREQUEST Request,
    _Out_ size_t* BytesReturned
    )
{
    NTSTATUS status;
    PQUAC_RANDOM_REQUEST randomRequest;
    PUCHAR outputBuffer;
    size_t inputSize;
    size_t outputSize;

    UNREFERENCED_PARAMETER(DeviceContext);

    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(QUAC_RANDOM_REQUEST),
        (PVOID*)&randomRequest,
        &inputSize
        );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = WdfRequestRetrieveOutputBuffer(
        Request,
        randomRequest->Length,
        (PVOID*)&outputBuffer,
        &outputSize
        );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // TODO: Get random from hardware QRNG
    // For now, use system RNG as placeholder
    //
    status = BCryptGenRandom(
        NULL,
        outputBuffer,
        randomRequest->Length,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
        );

    if (NT_SUCCESS(status)) {
        *BytesReturned = randomRequest->Length;
        DeviceContext->OperationsCompleted++;
    } else {
        DeviceContext->OperationsFailed++;
    }

    return status;
}
'@
}

function Get-TraceHeaderContent {
    return @'
/**
 * @file trace.h
 * @brief QUAC 100 KMDF Driver - WPP Tracing Definitions
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_TRACE_H
#define QUAC100_TRACE_H

//
// Define the tracing flags
//
#define WPP_CONTROL_GUIDS \
    WPP_DEFINE_CONTROL_GUID( \
        Quac100TraceGuid, (f7d5e47a,3b2c,4d8e,9f1a,6c5b4a3d2e1f), \
        WPP_DEFINE_BIT(TRACE_DRIVER)    \
        WPP_DEFINE_BIT(TRACE_DEVICE)    \
        WPP_DEFINE_BIT(TRACE_QUEUE)     \
        WPP_DEFINE_BIT(TRACE_IOCTL)     \
        WPP_DEFINE_BIT(TRACE_DMA)       \
        WPP_DEFINE_BIT(TRACE_CRYPTO)    \
        WPP_DEFINE_BIT(TRACE_INTERRUPT) \
        WPP_DEFINE_BIT(TRACE_POWER)     \
        )

#define WPP_FLAG_LEVEL_LOGGER(flag, level) \
    WPP_LEVEL_LOGGER(flag)

#define WPP_FLAG_LEVEL_ENABLED(flag, level) \
    (WPP_LEVEL_ENABLED(flag) && WPP_CONTROL(WPP_BIT_ ## flag).Level >= level)

//
// WPP_DEFINE_BIT creates log levels
//
#define WPP_LEVEL_FLAGS_LOGGER(lvl, flags) \
    WPP_LEVEL_LOGGER(flags)

#define WPP_LEVEL_FLAGS_ENABLED(lvl, flags) \
    (WPP_LEVEL_ENABLED(flags) && WPP_CONTROL(WPP_BIT_ ## flags).Level >= lvl)

//
// TraceEvents macro
//
// begin_wpp config
// FUNC TraceEvents(LEVEL, FLAGS, MSG, ...);
// end_wpp
//

#endif /* QUAC100_TRACE_H */
'@
}

function Get-PrecompHeaderContent {
    return @'
/**
 * @file precomp.h
 * @brief QUAC 100 KMDF Driver - Precompiled Header
 *
 * @copyright 2025 Dyber, Inc. All Rights Reserved.
 */

#ifndef QUAC100_PRECOMP_H
#define QUAC100_PRECOMP_H

//
// Windows kernel headers
//
#include <ntddk.h>
#include <wdf.h>
#include <initguid.h>
#include <wdmguid.h>
#include <ntstrsafe.h>
#include <bcrypt.h>

//
// Project version
//
#include "../common/version.h"

//
// WPP tracing
//
#include "trace.h"

#endif /* QUAC100_PRECOMP_H */
'@
}

function Get-InfContent {
    return @"
;
; quac100.inf
;
; QUAC 100 Post-Quantum Cryptographic Accelerator Driver
;
; Copyright 2025 Dyber, Inc. All Rights Reserved.
;

[Version]
Signature   = "`$WINDOWS NT`$"
Class       = SecurityDevices
ClassGuid   = {d94ee5d8-d189-4994-83d2-f68d7d41b0e6}
Provider    = %ManufacturerName%
CatalogFile = quac100.cat
DriverVer   = 01/01/2025,$($Version.Major).$($Version.Minor).$($Version.Patch).$($Version.Build)
PnpLockdown = 1

[DestinationDirs]
DefaultDestDir = 13

[SourceDisksNames]
1 = %DiskName%,,,""

[SourceDisksFiles]
quac100.sys = 1,,

;*****************************************
; QUAC 100 Install Section
;*****************************************

[Manufacturer]
%ManufacturerName% = Standard,NTamd64.10.0...22000,NTarm64.10.0...22000

[Standard.NTamd64.10.0...22000]
%DeviceDesc% = Quac100_Device, PCI\VEN_1DFB&DEV_0100
%DeviceDesc% = Quac100_Device, PCI\VEN_1DFB&DEV_0100&SUBSYS_00011DFB
%DeviceDesc% = Quac100_Device, PCI\VEN_1DFB&DEV_0100&SUBSYS_00021DFB
%DeviceDesc% = Quac100_Device, PCI\VEN_1DFB&DEV_0100&SUBSYS_00031DFB

[Standard.NTarm64.10.0...22000]
%DeviceDesc% = Quac100_Device, PCI\VEN_1DFB&DEV_0100
%DeviceDesc% = Quac100_Device, PCI\VEN_1DFB&DEV_0100&SUBSYS_00011DFB

[Quac100_Device.NT]
CopyFiles = Quac100_Device.NT.Copy
AddReg = Quac100_Device.NT.AddReg

[Quac100_Device.NT.Copy]
quac100.sys

[Quac100_Device.NT.AddReg]
HKR,,FriendlyName,,%DeviceDesc%

;-------------- Service installation
[Quac100_Device.NT.Services]
AddService = quac100,%SPSVCINST_ASSOCSERVICE%, Quac100_Service_Inst

; -------------- quac100 driver install sections
[Quac100_Service_Inst]
DisplayName    = %ServiceDesc%
ServiceType    = 1               ; SERVICE_KERNEL_DRIVER
StartType      = 3               ; SERVICE_DEMAND_START
ErrorControl   = 1               ; SERVICE_ERROR_NORMAL
ServiceBinary  = %13%\quac100.sys

;-------------- WDF specific section
[Quac100_Device.NT.Wdf]
KmdfService = quac100, Quac100_wdfsect

[Quac100_wdfsect]
KmdfLibraryVersion = `$KMDFVERSION`$

;-------------- Security section
[Quac100_Device.NT.HW]
AddReg = Quac100_Device.NT.HW.AddReg

[Quac100_Device.NT.HW.AddReg]
; Allow access for system and administrators
HKR,,Security,,"D:P(A;;GA;;;SY)(A;;GA;;;BA)"

;-------------- Device interface section
[Quac100_Device.NT.Interfaces]
AddInterface = {$($GUIDs.DeviceInterface.ToUpper())}, , Quac100_AddInterface

[Quac100_AddInterface]
AddReg = Quac100_AddInterface.AddReg

[Quac100_AddInterface.AddReg]
HKR,,FriendlyName,,%DeviceDesc%

[Strings]
SPSVCINST_ASSOCSERVICE = 0x00000002
ManufacturerName = "Dyber, Inc."
DiskName = "QUAC 100 Installation Disk"
DeviceDesc = "QUAC 100 Post-Quantum Cryptographic Accelerator"
ServiceDesc = "QUAC 100 Driver Service"
"@
}

function Get-VcxprojContent {
    param([string]$ProjectName, [string]$ProjectGuid)
    
    return @"
<?xml version="1.0" encoding="utf-8"?>
<Project DefaultTargets="Build" ToolsVersion="Current" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <PropertyGroup Label="Globals">
    <ProjectGuid>{$ProjectGuid}</ProjectGuid>
    <TemplateGuid>{dd38f7fc-d7bd-488b-9242-7d8754cde80d}</TemplateGuid>
    <TargetFrameworkVersion>v4.5</TargetFrameworkVersion>
    <MinimumVisualStudioVersion>14.0</MinimumVisualStudioVersion>
    <Configuration>Debug</Configuration>
    <Platform Condition="'`$(Platform)' == ''">x64</Platform>
    <RootNamespace>$ProjectName</RootNamespace>
    <DriverType>KMDF</DriverType>
    <DriverTargetPlatform>Universal</DriverTargetPlatform>
    <KMDF_VERSION_MAJOR>1</KMDF_VERSION_MAJOR>
    <KMDF_VERSION_MINOR>33</KMDF_VERSION_MINOR>
  </PropertyGroup>
  
  <Import Project="`$(VCTargetsPath)\Microsoft.Cpp.Default.props" />
  
  <PropertyGroup Condition="'`$(Configuration)|`$(Platform)'=='Debug|x64'" Label="Configuration">
    <TargetVersion>Windows11</TargetVersion>
    <UseDebugLibraries>true</UseDebugLibraries>
    <PlatformToolset>WindowsKernelModeDriver10.0</PlatformToolset>
    <ConfigurationType>Driver</ConfigurationType>
    <Driver_SpectreMitigation>Spectre</Driver_SpectreMitigation>
  </PropertyGroup>
  <PropertyGroup Condition="'`$(Configuration)|`$(Platform)'=='Release|x64'" Label="Configuration">
    <TargetVersion>Windows11</TargetVersion>
    <UseDebugLibraries>false</UseDebugLibraries>
    <PlatformToolset>WindowsKernelModeDriver10.0</PlatformToolset>
    <ConfigurationType>Driver</ConfigurationType>
    <Driver_SpectreMitigation>Spectre</Driver_SpectreMitigation>
  </PropertyGroup>
  <PropertyGroup Condition="'`$(Configuration)|`$(Platform)'=='Debug|ARM64'" Label="Configuration">
    <TargetVersion>Windows11</TargetVersion>
    <UseDebugLibraries>true</UseDebugLibraries>
    <PlatformToolset>WindowsKernelModeDriver10.0</PlatformToolset>
    <ConfigurationType>Driver</ConfigurationType>
    <Driver_SpectreMitigation>Spectre</Driver_SpectreMitigation>
  </PropertyGroup>
  <PropertyGroup Condition="'`$(Configuration)|`$(Platform)'=='Release|ARM64'" Label="Configuration">
    <TargetVersion>Windows11</TargetVersion>
    <UseDebugLibraries>false</UseDebugLibraries>
    <PlatformToolset>WindowsKernelModeDriver10.0</PlatformToolset>
    <ConfigurationType>Driver</ConfigurationType>
    <Driver_SpectreMitigation>Spectre</Driver_SpectreMitigation>
  </PropertyGroup>

  <Import Project="`$(VCTargetsPath)\Microsoft.Cpp.props" />
  <ImportGroup Label="ExtensionSettings">
  </ImportGroup>
  <ImportGroup Label="PropertySheets">
    <Import Project="`$(UserRootDir)\Microsoft.Cpp.`$(Platform).user.props" Condition="exists('`$(UserRootDir)\Microsoft.Cpp.`$(Platform).user.props')" Label="LocalAppDataPlatform" />
  </ImportGroup>
  <PropertyGroup Label="UserMacros" />

  <ItemDefinitionGroup Condition="'`$(Configuration)'=='Debug'">
    <ClCompile>
      <PreprocessorDefinitions>DBG=1;QUAC_DEBUG;%(PreprocessorDefinitions)</PreprocessorDefinitions>
      <AdditionalIncludeDirectories>`$(ProjectDir)..\common;`$(ProjectDir)..\..\include;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
      <WppEnabled>true</WppEnabled>
      <WppScanConfigurationData>`$(ProjectDir)driver\trace.h</WppScanConfigurationData>
      <WppSearchPath>`$(ProjectDir)driver</WppSearchPath>
      <PrecompiledHeader>Use</PrecompiledHeader>
      <PrecompiledHeaderFile>precomp.h</PrecompiledHeaderFile>
    </ClCompile>
    <Link>
      <AdditionalDependencies>bcrypt.lib;%(AdditionalDependencies)</AdditionalDependencies>
    </Link>
  </ItemDefinitionGroup>
  
  <ItemDefinitionGroup Condition="'`$(Configuration)'=='Release'">
    <ClCompile>
      <PreprocessorDefinitions>%(PreprocessorDefinitions)</PreprocessorDefinitions>
      <AdditionalIncludeDirectories>`$(ProjectDir)..\common;`$(ProjectDir)..\..\include;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
      <WppEnabled>true</WppEnabled>
      <WppScanConfigurationData>`$(ProjectDir)driver\trace.h</WppScanConfigurationData>
      <WppSearchPath>`$(ProjectDir)driver</WppSearchPath>
      <PrecompiledHeader>Use</PrecompiledHeader>
      <PrecompiledHeaderFile>precomp.h</PrecompiledHeaderFile>
    </ClCompile>
    <Link>
      <AdditionalDependencies>bcrypt.lib;%(AdditionalDependencies)</AdditionalDependencies>
    </Link>
  </ItemDefinitionGroup>

  <ItemGroup>
    <FilesToPackage Include="`$(TargetPath)" />
    <FilesToPackage Include="`$(OutputPath)$ProjectName.pdb" />
    <FilesToPackage Include="@(Inf->'%(CopyOutput)')" Condition="'@(Inf)'!=''" />
  </ItemGroup>

  <ItemGroup>
    <ClCompile Include="driver\driver.c" />
    <ClCompile Include="driver\device.c" />
    <ClCompile Include="driver\queue.c" />
    <ClCompile Include="driver\ioctl.c" />
    <ClCompile Include="driver\precomp.c">
      <PrecompiledHeader>Create</PrecompiledHeader>
    </ClCompile>
  </ItemGroup>

  <ItemGroup>
    <ClInclude Include="driver\driver.h" />
    <ClInclude Include="driver\device.h" />
    <ClInclude Include="driver\queue.h" />
    <ClInclude Include="driver\ioctl.h" />
    <ClInclude Include="driver\trace.h" />
    <ClInclude Include="driver\precomp.h" />
    <ClInclude Include="..\common\version.h" />
  </ItemGroup>

  <ItemGroup>
    <Inf Include="inf\$ProjectName.inf" />
  </ItemGroup>

  <ItemGroup>
    <ResourceCompile Include="inf\$ProjectName.rc" />
  </ItemGroup>

  <Import Project="`$(VCTargetsPath)\Microsoft.Cpp.targets" />
  <ImportGroup Label="ExtensionTargets">
  </ImportGroup>
</Project>
"@
}

function Get-PrecompSourceContent {
    return @'
/**
 * @file precomp.c
 * @brief Precompiled header source
 */

#include "precomp.h"
'@
}

function Get-ResourceFileContent {
    param([string]$ProjectName)
    
    return @"
//
// $ProjectName.rc
// Resource file for version information
//

#include <windows.h>
#include <ntverp.h>
#include "../common/version.h"

#define VER_FILETYPE                VFT_DRV
#define VER_FILESUBTYPE             VFT2_DRV_SYSTEM
#define VER_FILEDESCRIPTION_STR     "QUAC 100 Post-Quantum Cryptographic Accelerator Driver"
#define VER_INTERNALNAME_STR        "$ProjectName.sys"
#define VER_ORIGINALFILENAME_STR    "$ProjectName.sys"
#define VER_LEGALCOPYRIGHT_STR      QUAC100_COPYRIGHT
#define VER_COMPANYNAME_STR         QUAC100_COMPANY_NAME
#define VER_PRODUCTNAME_STR         QUAC100_PRODUCT_NAME

#define VER_FILEVERSION             QUAC100_VERSION_MAJOR,QUAC100_VERSION_MINOR,QUAC100_VERSION_PATCH,QUAC100_VERSION_BUILD
#define VER_FILEVERSION_STR         QUAC100_VERSION_STRING
#define VER_PRODUCTVERSION          QUAC100_VERSION_MAJOR,QUAC100_VERSION_MINOR,QUAC100_VERSION_PATCH,QUAC100_VERSION_BUILD
#define VER_PRODUCTVERSION_STR      QUAC100_VERSION_STRING

#include <common.ver>
"@
}

function Get-BuildScriptContent {
    return @'
<#
.SYNOPSIS
    Build script for QUAC 100 Windows Driver

.PARAMETER Configuration
    Build configuration (Debug/Release)

.PARAMETER Platform
    Target platform (x64/ARM64)

.PARAMETER Clean
    Clean before building
#>

param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",
    
    [ValidateSet("x64", "ARM64")]
    [string]$Platform = "x64",
    
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Split-Path -Parent $ScriptDir

# Find MSBuild
$msbuild = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" `
    -latest -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe | Select-Object -First 1

if (-not $msbuild) {
    Write-Error "MSBuild not found. Ensure Visual Studio 2022 is installed."
    exit 1
}

Write-Host "Using MSBuild: $msbuild" -ForegroundColor Cyan

$solution = Join-Path $RootDir "quac100.sln"

if ($Clean) {
    Write-Host "Cleaning solution..." -ForegroundColor Yellow
    & $msbuild $solution /t:Clean /p:Configuration=$Configuration /p:Platform=$Platform /v:minimal
}

Write-Host "Building $Configuration|$Platform..." -ForegroundColor Green
& $msbuild $solution /t:Build /p:Configuration=$Configuration /p:Platform=$Platform /v:minimal

if ($LASTEXITCODE -eq 0) {
    Write-Host "Build succeeded!" -ForegroundColor Green
} else {
    Write-Error "Build failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}
'@
}

function Get-InstallScriptContent {
    return @'
<#
.SYNOPSIS
    Install QUAC 100 Windows Driver

.PARAMETER InfPath
    Path to the INF file

.PARAMETER Force
    Force installation even if driver exists
#>

param(
    [string]$InfPath,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

# Require admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script requires administrator privileges."
    exit 1
}

# Find INF file
if (-not $InfPath) {
    $ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $RootDir = Split-Path -Parent (Split-Path -Parent $ScriptDir)
    $InfPath = Get-ChildItem -Path $RootDir -Recurse -Filter "quac100.inf" | Select-Object -First 1 -ExpandProperty FullName
}

if (-not (Test-Path $InfPath)) {
    Write-Error "INF file not found: $InfPath"
    exit 1
}

Write-Host "Installing driver from: $InfPath" -ForegroundColor Cyan

# Install using pnputil
$args = @("/add-driver", $InfPath, "/install")
if ($Force) {
    $args += "/force"
}

$result = & pnputil.exe $args

if ($LASTEXITCODE -eq 0) {
    Write-Host "Driver installed successfully!" -ForegroundColor Green
    Write-Host $result
} else {
    Write-Error "Driver installation failed: $result"
    exit $LASTEXITCODE
}
'@
}

function Get-TestSigningScriptContent {
    return @'
<#
.SYNOPSIS
    Enable test signing mode for driver development

.DESCRIPTION
    Enables Windows test signing mode, which allows loading of test-signed drivers.
    Requires a reboot to take effect.

.PARAMETER Disable
    Disable test signing mode instead of enabling
#>

param(
    [switch]$Disable
)

$ErrorActionPreference = "Stop"

# Require admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script requires administrator privileges."
    exit 1
}

if ($Disable) {
    Write-Host "Disabling test signing mode..." -ForegroundColor Yellow
    bcdedit /set testsigning off
} else {
    Write-Host "Enabling test signing mode..." -ForegroundColor Yellow
    bcdedit /set testsigning on
}

if ($LASTEXITCODE -eq 0) {
    Write-Host "Success! Please reboot for changes to take effect." -ForegroundColor Green
} else {
    Write-Error "Failed to modify boot configuration."
    exit $LASTEXITCODE
}
'@
}

# ============================================================================
# Main Script
# ============================================================================

Write-Host @"

╔══════════════════════════════════════════════════════════════════════════════╗
║                    QUAC 100 Windows Driver Setup Script                      ║
║                         Version $($Version.Major).$($Version.Minor).$($Version.Patch)                                         ║
╚══════════════════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

Write-Status "Base path: $BasePath"

# Create directory structure
New-DirectoryStructure

# Create files
Write-Status "Creating files..."

# Root files
New-FileWithContent -Path (Join-Path $BasePath "README.md") -Content (Get-ReadmeContent)
New-FileWithContent -Path (Join-Path $BasePath "quac100.sln") -Content (Get-SolutionFileContent)
New-FileWithContent -Path (Join-Path $BasePath "LICENSE") -Content @"
Copyright 2025 Dyber, Inc. All Rights Reserved.

Proprietary and confidential. Unauthorized copying of this file,
via any medium, is strictly prohibited.
"@

# Include files
New-FileWithContent -Path (Join-Path $BasePath "include/quac100_public.h") -Content (Get-PublicHeaderContent)
New-FileWithContent -Path (Join-Path $BasePath "include/quac100_ioctl.h") -Content (Get-PublicIoctlHeaderContent)
New-FileWithContent -Path (Join-Path $BasePath "include/quac100_guid.h") -Content (Get-GuidHeaderContent)

# Common files
New-FileWithContent -Path (Join-Path $BasePath "src/common/version.h") -Content (Get-VersionHeaderContent)

# Driver source files
$driverPath = Join-Path $BasePath "src/quac100"
New-FileWithContent -Path (Join-Path $driverPath "driver/driver.h") -Content (Get-DriverHeaderContent)
New-FileWithContent -Path (Join-Path $driverPath "driver/driver.c") -Content (Get-DriverSourceContent)
New-FileWithContent -Path (Join-Path $driverPath "driver/device.h") -Content (Get-DeviceHeaderContent)
New-FileWithContent -Path (Join-Path $driverPath "driver/device.c") -Content (Get-DeviceSourceContent)
New-FileWithContent -Path (Join-Path $driverPath "driver/queue.h") -Content (Get-QueueHeaderContent)
New-FileWithContent -Path (Join-Path $driverPath "driver/queue.c") -Content (Get-QueueSourceContent)
New-FileWithContent -Path (Join-Path $driverPath "driver/ioctl.h") -Content (Get-IoctlHeaderContent)
New-FileWithContent -Path (Join-Path $driverPath "driver/ioctl.c") -Content (Get-IoctlSourceContent)
New-FileWithContent -Path (Join-Path $driverPath "driver/trace.h") -Content (Get-TraceHeaderContent)
New-FileWithContent -Path (Join-Path $driverPath "driver/precomp.h") -Content (Get-PrecompHeaderContent)
New-FileWithContent -Path (Join-Path $driverPath "driver/precomp.c") -Content (Get-PrecompSourceContent)

# INF and project files
New-FileWithContent -Path (Join-Path $driverPath "inf/quac100.inf") -Content (Get-InfContent)
New-FileWithContent -Path (Join-Path $driverPath "inf/quac100.rc") -Content (Get-ResourceFileContent -ProjectName "quac100")
New-FileWithContent -Path (Join-Path $driverPath "quac100.vcxproj") -Content (Get-VcxprojContent -ProjectName "quac100" -ProjectGuid ([guid]::NewGuid().ToString().ToUpper()))

# Scripts
New-FileWithContent -Path (Join-Path $BasePath "scripts/build.ps1") -Content (Get-BuildScriptContent)
New-FileWithContent -Path (Join-Path $BasePath "tools/deploy/install_driver.ps1") -Content (Get-InstallScriptContent)
New-FileWithContent -Path (Join-Path $BasePath "tools/deploy/enable_testsigning.ps1") -Content (Get-TestSigningScriptContent)

# Placeholder files for remaining directories
$placeholders = @(
    "src/quac100/hw/pcie.c"
    "src/quac100/hw/pcie.h"
    "src/quac100/hw/registers.c"
    "src/quac100/hw/registers.h"
    "src/quac100/hw/dma.c"
    "src/quac100/hw/dma.h"
    "src/quac100/hw/interrupt.c"
    "src/quac100/hw/interrupt.h"
    "src/quac100/crypto/kem.c"
    "src/quac100/crypto/kem.h"
    "src/quac100/crypto/sign.c"
    "src/quac100/crypto/sign.h"
    "src/quac100/crypto/qrng.c"
    "src/quac100/crypto/qrng.h"
    "src/quac100/async/jobqueue.c"
    "src/quac100/async/jobqueue.h"
    "src/quac100/power/power.c"
    "src/quac100/power/power.h"
    "src/quac100/diag/selftest.c"
    "src/quac100/diag/health.c"
    "docs/architecture.md"
    "docs/building.md"
    "docs/debugging.md"
    "docs/installation.md"
    "docs/ioctl_reference.md"
)

foreach ($placeholder in $placeholders) {
    $filePath = Join-Path $BasePath $placeholder
    $fileName = Split-Path -Leaf $placeholder
    $content = "// TODO: Implement $fileName`n"
    if ($placeholder -like "*.md") {
        # Use .NET method for PowerShell 5.1 compatibility (instead of Split-Path -LeafBase)
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($placeholder)
        $content = "# $baseName`n`nTODO: Add documentation`n"
    }
    New-FileWithContent -Path $filePath -Content $content
}

# Summary
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Status "Setup complete!" "Success"
Write-Host ""
Write-Host "  Directories created: $Script:DirsCreated" -ForegroundColor White
Write-Host "  Files created:       $Script:FilesCreated" -ForegroundColor White
Write-Host "  Files skipped:       $Script:FilesSkipped" -ForegroundColor White
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Open $BasePath\quac100.sln in Visual Studio 2022"
Write-Host "  2. Ensure WDK 11 is installed"
Write-Host "  3. Build the solution (Ctrl+Shift+B)"
Write-Host "  4. Enable test signing: .\tools\deploy\enable_testsigning.ps1"
Write-Host "  5. Reboot and install driver: .\tools\deploy\install_driver.ps1"
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan