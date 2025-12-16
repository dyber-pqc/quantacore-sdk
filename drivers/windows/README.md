# QUAC 100 Windows Driver

<p align="center">
  <img src="https://dyber.org/images/quac100-logo.png" alt="QUAC 100 Logo" width="200"/>
</p>

<p align="center">
  <strong>Windows Kernel-Mode Driver Framework (KMDF) driver for the QUAC 100 Post-Quantum Cryptographic Accelerator</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#requirements">Requirements</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#documentation">Documentation</a> •
  <a href="#support">Support</a>
</p>

---

## Overview

The QUAC 100 Windows driver provides comprehensive Windows support for the QUAC 100 PCIe hardware accelerator, a next-generation post-quantum cryptographic device manufactured by [Dyber, Inc.](https://dyber.org). This driver enables Windows applications to leverage hardware-accelerated post-quantum cryptographic operations that are resistant to both classical and quantum computer attacks.

The driver is implemented using the Windows Driver Framework (WDF/KMDF) and follows Microsoft's best practices for kernel-mode driver development, ensuring reliability, security, and optimal performance.

## Features

### Cryptographic Algorithms

| Algorithm | Type | Security Level | Performance |
|-----------|------|----------------|-------------|
| **ML-KEM (Kyber-512)** | Key Encapsulation | NIST Level 1 | ~50,000 ops/sec |
| **ML-KEM (Kyber-768)** | Key Encapsulation | NIST Level 3 | ~35,000 ops/sec |
| **ML-KEM (Kyber-1024)** | Key Encapsulation | NIST Level 5 | ~25,000 ops/sec |
| **ML-DSA (Dilithium-2)** | Digital Signature | NIST Level 2 | ~10,000 signs/sec |
| **ML-DSA (Dilithium-3)** | Digital Signature | NIST Level 3 | ~7,000 signs/sec |
| **ML-DSA (Dilithium-5)** | Digital Signature | NIST Level 5 | ~5,000 signs/sec |
| **SLH-DSA (SPHINCS+)** | Hash-Based Signature | Configurable | ~500 signs/sec |
| **QRNG** | Random Number Generation | NIST SP 800-90B | ~100 MB/sec |

### Driver Capabilities

- **High-Performance DMA Engine**: Scatter-gather DMA with up to 4 simultaneous channels
- **MSI-X Interrupt Support**: Low-latency interrupt handling with per-vector affinity
- **SR-IOV Virtualization**: Hardware virtualization support for VM environments
- **Power Management**: Full D-state support with runtime power management
- **Health Monitoring**: Continuous hardware health monitoring and alerting
- **Diagnostic Tools**: Built-in self-test and diagnostic capabilities

### Platform Support

| Platform | Architecture | Status |
|----------|--------------|--------|
| Windows 11 23H2+ | x64 | ✅ Full Support |
| Windows 11 22H2 | x64 | ✅ Full Support |
| Windows 11 | ARM64 | ✅ Full Support |
| Windows 10 22H2 | x64 | ⚠️ Limited Support |
| Windows Server 2022 | x64 | ✅ Full Support |
| Windows Server 2019 | x64 | ⚠️ Limited Support |

## Requirements

### Hardware Requirements

- QUAC 100 PCIe accelerator card
- PCIe Gen3 x4 slot (minimum), Gen4 x8 recommended
- 8 GB RAM minimum, 16 GB recommended
- 64-bit processor (x64 or ARM64)

### Development Requirements

- **Visual Studio 2022** (17.4 or later)
  - Workload: "Desktop development with C++"
  - Component: MSVC v143 build tools
  - Component: Spectre-mitigated libraries
- **Windows 11 SDK** (10.0.22621.0 or later)
- **Windows Driver Kit (WDK) 11**
- **WDK Visual Studio Extension**

### Runtime Requirements

- Windows 11 Build 22000 or later (Windows 10 21H2 with limitations)
- Administrator privileges for driver installation
- Test signing enabled (for development builds)

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/dyber-pqc/quantacore-sdk.git
cd quantacore-sdk/drivers/windows
```

### 2. Build the Driver

**Using PowerShell (Recommended):**

```powershell
# Quick build and install
.\scripts\quickstart.ps1 -Action All

# Or step-by-step
.\scripts\build.ps1 -Configuration Release -Platform x64
```

**Using Visual Studio:**

1. Open `quac100.sln` in Visual Studio 2022
2. Select **Release** | **x64**
3. Build → Build Solution (Ctrl+Shift+B)

### 3. Install the Driver

```powershell
# Enable test signing (requires reboot)
.\tools\deploy\enable_testsigning.ps1

# After reboot, install the driver
.\tools\deploy\install_driver.ps1
```

### 4. Verify Installation

```powershell
# Run diagnostics
.\tools\deploy\diagnose.ps1

# Run self-test
.\scripts\test.ps1 -Category All
```

## Project Structure

```
drivers/windows/
├── src/
│   ├── quac100/           # Main Physical Function driver
│   │   ├── driver/        # Core KMDF framework code
│   │   ├── hw/            # Hardware abstraction layer
│   │   ├── crypto/        # Cryptographic engine interfaces
│   │   ├── diag/          # Diagnostics and health monitoring
│   │   └── power/         # Power management
│   ├── quac100vf/         # SR-IOV Virtual Function driver
│   └── common/            # Shared code
├── include/               # Public headers for applications
├── lib/
│   └── quac100lib/        # User-mode interface library
├── test/
│   ├── quac100test/       # Test application
│   ├── devcon/            # Device console utility
│   └── hwsim/             # Hardware simulator
├── tools/
│   ├── deploy/            # Deployment scripts
│   ├── sign/              # Code signing tools
│   └── package/           # Packaging tools
├── scripts/               # Build and automation scripts
├── hlk/                   # HLK test configuration
├── docs/                  # Documentation
└── samples/               # Sample code
```

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture Overview](docs/architecture.md) | Driver architecture and design |
| [Building Guide](docs/building.md) | Complete build instructions |
| [Installation Guide](docs/installation.md) | Installation and configuration |
| [IOCTL Reference](docs/ioctl_reference.md) | Complete IOCTL documentation |
| [Debugging Guide](docs/debugging.md) | Debugging and troubleshooting |

## API Overview

### User-Mode Library (quac100lib.dll)

The user-mode library provides a simple C API for applications:

```c
#include <quac100lib.h>

// Initialize the library
QUAC_HANDLE hDevice;
Quac100_Open(&hDevice);

// Generate KEM key pair
BYTE publicKey[KYBER768_PK_SIZE];
BYTE secretKey[KYBER768_SK_SIZE];
Quac100_KemKeyGen(hDevice, QUAC_KEM_KYBER768, publicKey, secretKey);

// Generate quantum random bytes
BYTE randomData[256];
Quac100_Random(hDevice, randomData, sizeof(randomData), QUAC_RNG_QUALITY_HIGH);

// Sign a message
BYTE signature[DILITHIUM3_SIG_SIZE];
DWORD sigLen;
Quac100_Sign(hDevice, QUAC_SIGN_DILITHIUM3, secretKey, 
             message, messageLen, signature, &sigLen);

// Cleanup
Quac100_Close(hDevice);
```

### Direct IOCTL Interface

For advanced use cases, applications can use DeviceIoControl directly:

```c
#include <quac100_ioctl.h>

HANDLE hDevice = CreateFile(
    L"\\\\.\\QUAC100-0",
    GENERIC_READ | GENERIC_WRITE,
    FILE_SHARE_READ | FILE_SHARE_WRITE,
    NULL, OPEN_EXISTING, 0, NULL);

QUAC_RANDOM_INPUT input = { .RequestedBytes = 256, .Quality = QUAC_RNG_QUALITY_HIGH };
BYTE output[256];
DWORD bytesReturned;

DeviceIoControl(hDevice, IOCTL_QUAC_RANDOM,
    &input, sizeof(input),
    output, sizeof(output),
    &bytesReturned, NULL);

CloseHandle(hDevice);
```

## Tools

### Device Console (quaccon.exe)

Command-line utility for device management:

```powershell
# List devices
quaccon list

# Show device status
quaccon status

# Run self-test
quaccon test

# Generate random bytes
quaccon random 1024 output.bin

# Show health information
quaccon health

# Benchmark performance
quaccon benchmark
```

### Hardware Simulator (quac100sim.exe)

Software simulator for development without hardware:

```powershell
# Start simulator with default settings
quac100sim

# Start with verbose output
quac100sim --verbose

# Start with error injection
quac100sim --error-rate 0.01
```

## Performance Benchmarking

```powershell
# Run comprehensive benchmark
.\scripts\benchmark.ps1 -Algorithm All -Iterations 10000 -OutputFormat CSV

# Quick benchmark
.\scripts\benchmark.ps1 -Algorithm KEM -Iterations 1000
```

Sample results (i9-12900K, QUAC 100 Rev B):

| Operation | Algorithm | Ops/sec | Latency (μs) |
|-----------|-----------|---------|--------------|
| KeyGen | ML-KEM-768 | 48,500 | 20.6 |
| Encaps | ML-KEM-768 | 52,300 | 19.1 |
| Decaps | ML-KEM-768 | 51,800 | 19.3 |
| KeyGen | ML-DSA-3 | 8,200 | 122 |
| Sign | ML-DSA-3 | 6,800 | 147 |
| Verify | ML-DSA-3 | 24,500 | 40.8 |
| Random | QRNG | 105 MB/s | - |

## Debugging

### Enable WPP Tracing

```powershell
# Start tracing
.\scripts\trace.ps1 -Action Start -Level Verbose

# Reproduce issue
# ...

# View traces
.\scripts\trace.ps1 -Action View
```

### Enable Driver Verifier

```powershell
# Standard verification
.\scripts\verifier.ps1 -Action Enable

# Full verification (performance impact)
.\scripts\verifier.ps1 -Action Full

# Check status
.\scripts\verifier.ps1 -Action Status
```

### Collect Diagnostics

```powershell
.\tools\deploy\diagnose.ps1 -IncludeLogs -IncludeMemoryDump -OutputDir C:\QuacDiag
```

## Certification

### Windows Hardware Lab Kit (HLK)

The driver is designed to pass WHQL certification:

```powershell
# Run HLK tests
.\hlk\scripts\run_hlk_tests.ps1
```

### Security Certifications

- FIPS 140-3 (In Progress)
- Common Criteria EAL4+ (Planned)

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Reporting Issues

Please report issues on our [GitHub Issues](https://github.com/dyber-pqc/quantacore-sdk/issues) page with:

1. Windows version and build number
2. Driver version (`quaccon version`)
3. Hardware revision (`quaccon info`)
4. Diagnostic output (`.\tools\deploy\diagnose.ps1`)
5. Steps to reproduce

## License

This software is proprietary and confidential. See [LICENSE](LICENSE) for terms.

Copyright © 2025 Dyber, Inc. All Rights Reserved.

## Support

| Channel | Contact |
|---------|---------|
| Documentation | [https://docs.dyber.org](https://docs.dyber.org) |
| GitHub Issues | [https://github.com/dyber-pqc/quantacore-sdk/issues](https://github.com/dyber-pqc/quantacore-sdk/issues) |
| Email Support | support@dyber.org |
| Enterprise Support | enterprise@dyber.org |

---

<p align="center">
  Made with ❤️ by <a href="https://dyber.org">Dyber, Inc.</a>
</p>
