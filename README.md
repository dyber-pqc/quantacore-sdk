<p align="center">
  <img src="docs/assets/quantacore-logo.png" alt="QuantaCore SDK" width="400">
</p>

<h1 align="center">QuantaCore SDK</h1>

<p align="center">
  <strong>Post-Quantum Cryptographic Acceleration for the QUAC 100 Hardware Security Module</strong>
</p>

<p align="center">
  <a href="https://github.com/dyber-pqc/quantacore-sdk/releases"><img src="https://img.shields.io/github/v/release/dyber-pqc/quantacore-sdk?style=flat-square&color=blue" alt="Release"></a>
  <a href="https://github.com/dyber-pqc/quantacore-sdk/actions"><img src="https://img.shields.io/github/actions/workflow/status/dyber-pqc/quantacore-sdk/ci.yml?style=flat-square" alt="Build Status"></a>
  <a href="LICENSE.txt"><img src="https://img.shields.io/badge/license-Proprietary-red?style=flat-square" alt="License"></a>
  <a href="https://docs.dyber.org/quac100"><img src="https://img.shields.io/badge/docs-dyber.org-blue?style=flat-square" alt="Documentation"></a>
  <img src="https://img.shields.io/badge/FIPS%20140--3-Level%203-green?style=flat-square" alt="FIPS 140-3">
  <img src="https://img.shields.io/badge/PQC-NIST%20Standardized-purple?style=flat-square" alt="PQC Ready">
</p>

<p align="center">
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-features">Features</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-language-bindings">Bindings</a> •
  <a href="#-documentation">Documentation</a> •
  <a href="#-support">Support</a>
</p>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [The QUAC 100 Hardware](#-the-quac-100-hardware)
- [Features](#-features)
- [Supported Algorithms](#-supported-algorithms)
- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Language Bindings](#-language-bindings)
- [Integrations](#-integrations)
- [Command-Line Tools](#-command-line-tools)
- [Simulator Mode](#-simulator-mode)
- [Performance](#-performance)
- [API Overview](#-api-overview)
- [Building from Source](#-building-from-source)
- [Testing](#-testing)
- [Repository Structure](#-repository-structure)
- [Security Considerations](#-security-considerations)
- [Documentation](#-documentation)
- [Changelog](#-changelog)
- [License](#-license)
- [Support](#-support)

---

## 🌟 Overview

The **QuantaCore SDK** is the official software development kit for the **QUAC 100** Post-Quantum Cryptographic Accelerator, developed by [Dyber, Inc](https://dyber.com). This SDK enables developers to leverage hardware-accelerated post-quantum cryptography in their applications, providing protection against both classical and quantum computing attacks.

As quantum computers advance toward cryptographic relevance, traditional public-key algorithms like RSA and ECC will become vulnerable. The QUAC 100 and QuantaCore SDK provide a migration path to quantum-resistant cryptography using NIST-standardized algorithms.

### Why QuantaCore?

| Challenge | QuantaCore Solution |
|-----------|---------------------|
| **Quantum Threat** | NIST-standardized post-quantum algorithms (FIPS 203, 204, 205) |
| **Performance** | Hardware acceleration: millions of operations per second |
| **Integration** | Drop-in providers for OpenSSL, PKCS#11, and more |
| **Security** | FIPS 140-3 Level 3 certified HSM with tamper detection |
| **Entropy** | Hardware QRNG with 2+ Gbps throughput |
| **Flexibility** | Bindings for C, C++, Python, Rust, Go, Java, Node.js, C# |

---

## 🔧 The QUAC 100 Hardware

The **QUAC 100** is a PCIe-based Hardware Security Module (HSM) designed specifically for post-quantum cryptographic operations.

### Hardware Specifications

| Specification | Details |
|---------------|---------|
| **Form Factor** | PCIe Gen4 x8 half-height, half-length |
| **Interface** | PCIe 4.0 (16 GT/s per lane, ~16 GB/s total) |
| **Memory** | 64 MB on-chip SRAM + 256 secure key slots |
| **Power** | 25W typical, 35W maximum |
| **Operating Temp** | 0°C to 70°C |
| **Certifications** | FIPS 140-3 Level 3, Common Criteria EAL4+ |

### Cryptographic Engines

| Engine | Description |
|--------|-------------|
| **NTT Accelerator** | 8 parallel Number Theoretic Transform units |
| **Polynomial ALU** | Dedicated lattice polynomial arithmetic |
| **Hash Engine** | SHA-2, SHA-3, SHAKE with 4 GB/s throughput |
| **QRNG** | 8 avalanche noise sources, 2+ Gbps entropy |
| **Key Store** | 256 slots with hardware isolation |

### Supported Platforms

| Platform | Architecture | Driver Status |
|----------|--------------|---------------|
| **Linux** | x86_64, ARM64 | ✅ Production |
| **Windows** | x86_64 | ✅ Production |
| **macOS** | x86_64, ARM64 | ⚠️ Simulator only |

---

## ✨ Features

### Post-Quantum Cryptography
- **ML-KEM (Kyber)** - FIPS 203 Key Encapsulation Mechanism
- **ML-DSA (Dilithium)** - FIPS 204 Digital Signatures
- **SLH-DSA (SPHINCS+)** - FIPS 205 Stateless Hash-Based Signatures

### Hardware Security
- **FIPS 140-3 Level 3** certified cryptographic boundary
- **Tamper Detection** with automatic key zeroization
- **Secure Boot** with firmware signature verification
- **Side-Channel Resistance** with constant-time implementations

### High Performance
- **Batch Processing** - Up to 20x throughput improvement
- **Async Operations** - Non-blocking API with callbacks
- **DMA Transfers** - Zero-copy data movement
- **SR-IOV Support** - Hardware virtualization for cloud deployments

### Quantum Random Number Generation
- **True Random** - Hardware quantum entropy sources
- **SP 800-90B Compliant** - Continuous health monitoring
- **High Throughput** - 2+ Gbps conditioned output
- **Multiple Quality Levels** - Standard, High, Maximum, Fast

### Developer Experience
- **8 Language Bindings** - C, C++, Python, Rust, Go, Java, Node.js, C#
- **Software Simulator** - Full API compatibility for development
- **Comprehensive Documentation** - API reference, guides, examples
- **CLI Tools** - Device management, testing, benchmarking

---

## 🔐 Supported Algorithms

### ML-KEM (FIPS 203) - Key Encapsulation

| Algorithm | Security Level | Public Key | Secret Key | Ciphertext | Shared Secret |
|-----------|----------------|------------|------------|------------|---------------|
| **ML-KEM-512** | NIST Level 1 | 800 bytes | 1,632 bytes | 768 bytes | 32 bytes |
| **ML-KEM-768** | NIST Level 3 | 1,184 bytes | 2,400 bytes | 1,088 bytes | 32 bytes |
| **ML-KEM-1024** | NIST Level 5 | 1,568 bytes | 3,168 bytes | 1,568 bytes | 32 bytes |

### ML-DSA (FIPS 204) - Digital Signatures

| Algorithm | Security Level | Public Key | Secret Key | Signature |
|-----------|----------------|------------|------------|-----------|
| **ML-DSA-44** | NIST Level 2 | 1,312 bytes | 2,528 bytes | 2,420 bytes |
| **ML-DSA-65** | NIST Level 3 | 1,952 bytes | 4,000 bytes | 3,293 bytes |
| **ML-DSA-87** | NIST Level 5 | 2,592 bytes | 4,864 bytes | 4,595 bytes |

### SLH-DSA (FIPS 205) - Hash-Based Signatures

| Algorithm | Security Level | Public Key | Secret Key | Signature |
|-----------|----------------|------------|------------|-----------|
| **SLH-DSA-SHA2-128s** | NIST Level 1 | 32 bytes | 64 bytes | 7,856 bytes |
| **SLH-DSA-SHA2-128f** | NIST Level 1 | 32 bytes | 64 bytes | 17,088 bytes |
| **SLH-DSA-SHA2-192s** | NIST Level 3 | 48 bytes | 96 bytes | 16,224 bytes |
| **SLH-DSA-SHA2-192f** | NIST Level 3 | 48 bytes | 96 bytes | 35,664 bytes |
| **SLH-DSA-SHA2-256s** | NIST Level 5 | 64 bytes | 128 bytes | 29,792 bytes |
| **SLH-DSA-SHA2-256f** | NIST Level 5 | 64 bytes | 128 bytes | 49,856 bytes |

> **Note:** "s" variants prioritize smaller signatures; "f" variants prioritize faster signing.

---

## 🚀 Quick Start

### C Example

```c
#include <stdio.h>
#include <quac100.h>

int main(void) {
    quac_result_t result;
    quac_device_t device;
    
    // Initialize SDK
    result = quac_init(NULL);
    if (QUAC_FAILED(result)) {
        fprintf(stderr, "Init failed: %s\n", quac_error_string(result));
        return 1;
    }
    
    // Open device (or simulator)
    result = quac_open(0, &device);
    if (QUAC_FAILED(result)) {
        quac_set_simulator_mode(true);
        quac_open(0, &device);
    }
    
    // Generate ML-KEM-768 keypair
    uint8_t public_key[QUAC_KYBER768_PUBLIC_KEY_SIZE];
    uint8_t secret_key[QUAC_KYBER768_SECRET_KEY_SIZE];
    
    result = quac_kem_keygen(device, QUAC_ALGORITHM_KYBER768,
                             public_key, sizeof(public_key),
                             secret_key, sizeof(secret_key));
    
    if (QUAC_SUCCEEDED(result)) {
        printf("Generated ML-KEM-768 keypair!\n");
        printf("Public key: %zu bytes\n", sizeof(public_key));
    }
    
    // Generate quantum random bytes
    uint8_t random_bytes[32];
    quac_random_bytes(device, random_bytes, sizeof(random_bytes));
    
    printf("Random: ");
    for (int i = 0; i < 32; i++) printf("%02x", random_bytes[i]);
    printf("\n");
    
    // Cleanup
    quac_close(device);
    quac_shutdown();
    return 0;
}
```

**Build and run:**
```bash
gcc -o quickstart quickstart.c -lquac100
./quickstart
```

### Python Example

```python
import quantacore

# Initialize
quantacore.initialize()

try:
    # Open device (falls back to simulator)
    with quantacore.open_first_device() as device:
        # ML-KEM key exchange
        kem = device.kem()
        
        # Alice generates keypair
        with kem.generate_keypair_768() as keypair:
            print(f"Public key: {len(keypair.public_key)} bytes")
            
            # Bob encapsulates to Alice's public key
            with kem.encapsulate(keypair.public_key) as encap:
                ciphertext = encap.ciphertext
                bob_secret = encap.shared_secret
                
                # Alice decapsulates
                alice_secret = kem.decapsulate(keypair.secret_key, ciphertext)
                
                assert bob_secret == alice_secret
                print(f"Shared secret: {quantacore.to_hex(alice_secret)}")
        
        # Generate quantum random bytes
        random_bytes = device.random().bytes(32)
        print(f"Random: {random_bytes.hex()}")

finally:
    quantacore.cleanup()
```

**Install and run:**
```bash
pip install quantacore-sdk
python quickstart.py
```

### Rust Example

```rust
use quantacore::{initialize, cleanup, open_first_device, KemAlgorithm};

fn main() -> quantacore::Result<()> {
    // Initialize
    initialize()?;
    
    // Open device
    let device = open_first_device()?;
    let kem = device.kem();
    
    // Generate ML-KEM-768 keypair
    let keypair = kem.generate_keypair(KemAlgorithm::MlKem768)?;
    println!("Public key: {} bytes", keypair.public_key().len());
    
    // Encapsulate
    let (ciphertext, sender_secret) = kem.encapsulate(
        keypair.public_key(),
        KemAlgorithm::MlKem768
    )?;
    
    // Decapsulate
    let receiver_secret = kem.decapsulate(
        keypair.secret_key(),
        &ciphertext,
        KemAlgorithm::MlKem768
    )?;
    
    assert_eq!(sender_secret, receiver_secret);
    println!("Key exchange successful!");
    
    // Cleanup
    drop(device);
    cleanup()?;
    Ok(())
}
```

**Build and run:**
```bash
cargo add quantacore-sdk
cargo run
```

---

## 📦 Installation

### System Requirements

- **Operating System:** Linux (kernel 5.4+), Windows 10/11, macOS 12+
- **Architecture:** x86_64 or ARM64
- **Memory:** 4 GB RAM minimum
- **Disk:** 500 MB for SDK, 2 GB for full development environment

### Linux Installation

#### Driver Installation (for hardware)

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install dkms linux-headers-$(uname -r)

# Install QUAC 100 driver
cd drivers/linux
sudo make install
sudo modprobe quac100

# Verify installation
lsmod | grep quac100
ls /dev/quac100*
```

#### SDK Installation

```bash
# Option 1: Package manager (recommended)
# Ubuntu/Debian
sudo add-apt-repository ppa:dyber/quantacore
sudo apt update
sudo apt install quantacore-sdk quantacore-sdk-dev

# RHEL/CentOS/Fedora
sudo dnf config-manager --add-repo https://rpm.dyber.com/quantacore.repo
sudo dnf install quantacore-sdk quantacore-sdk-devel

# Option 2: From source
git clone https://github.com/dyber-pqc/quantacore-sdk.git
cd quantacore-sdk
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
sudo make install
```

### Windows Installation

#### Driver Installation

1. Download the QUAC 100 Windows driver package from [dyber.com/downloads](https://dyber.com/downloads)
2. Run `QUAC100_Driver_Setup.exe` as Administrator
3. Follow the installation wizard
4. Restart when prompted

#### SDK Installation

```powershell
# Option 1: MSI Installer (recommended)
# Download from https://dyber.com/downloads
# Run QuantaCore-SDK-1.0.0-x64.msi

# Option 2: vcpkg
vcpkg install quantacore-sdk

# Option 3: From source
git clone https://github.com/dyber-pqc/quantacore-sdk.git
cd quantacore-sdk
mkdir build && cd build
cmake -G "Visual Studio 17 2022" -A x64 ..
cmake --build . --config Release
cmake --install . --config Release
```

### macOS Installation (Simulator Only)

```bash
# Homebrew
brew tap dyber/quantacore
brew install quantacore-sdk

# From source
git clone https://github.com/dyber-pqc/quantacore-sdk.git
cd quantacore-sdk
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -DQUAC_BUILD_SIMULATOR=ON ..
make -j$(sysctl -n hw.ncpu)
sudo make install
```

---

## 🌐 Language Bindings

The QuantaCore SDK provides official bindings for 8 programming languages:

| Language | Package | Installation | Documentation |
|----------|---------|--------------|---------------|
| **C** | `libquac100` | System package | [docs/api](docs/api/) |
| **C++** | `libquac100++` | System package | [bindings/c++](bindings/c++/) |
| **Python** | `quantacore-sdk` | `pip install quantacore-sdk` | [bindings/python](bindings/python/) |
| **Rust** | `quantacore-sdk` | `cargo add quantacore-sdk` | [bindings/rust](bindings/rust/) |
| **Go** | `quantacore` | `go get github.com/dyber-pqc/quantacore-go` | [bindings/go](bindings/go/) |
| **Java** | `quantacore-sdk` | Maven Central | [bindings/java](bindings/java/) |
| **Node.js** | `@dyber/quantacore` | `npm install @dyber/quantacore` | [bindings/nodejs](bindings/nodejs/) |
| **C#** | `Dyber.QuantaCore` | NuGet | [bindings/csharp](bindings/csharp/) |

### Python

```bash
pip install quantacore-sdk
```

```python
import quantacore

quantacore.initialize()
device = quantacore.open_first_device()

# ML-KEM
kem = device.kem()
keypair = kem.generate_keypair_768()

# ML-DSA
sign = device.sign()
sig_keypair = sign.generate_keypair_65()
signature = sign.sign(sig_keypair.secret_key, b"message")

# QRNG
random_data = device.random().bytes(64)

quantacore.cleanup()
```

### Rust

```toml
[dependencies]
quantacore-sdk = "1.0"
```

```rust
use quantacore::{initialize, open_first_device, KemAlgorithm, SignAlgorithm};

fn main() -> quantacore::Result<()> {
    initialize()?;
    let device = open_first_device()?;
    
    // ML-KEM
    let kem = device.kem();
    let keypair = kem.generate_keypair(KemAlgorithm::MlKem768)?;
    
    // ML-DSA
    let sign = device.sign();
    let sig_keypair = sign.generate_keypair(SignAlgorithm::MlDsa65)?;
    let signature = sign.sign(sig_keypair.secret_key(), b"message")?;
    
    // QRNG
    let random_data = device.random().bytes(64)?;
    
    cleanup()?;
    Ok(())
}
```

### Go

```bash
go get github.com/dyber-pqc/quantacore-go
```

```go
package main

import (
    "fmt"
    quac "github.com/dyber-pqc/quantacore-go"
)

func main() {
    quac.Initialize()
    defer quac.Cleanup()
    
    device, _ := quac.OpenFirstDevice()
    defer device.Close()
    
    // ML-KEM
    kem := device.KEM()
    keypair, _ := kem.GenerateKeypair768()
    
    // ML-DSA
    sign := device.Sign()
    sigKeypair, _ := sign.GenerateKeypair65()
    signature, _ := sign.Sign(sigKeypair.SecretKey, []byte("message"))
    
    // QRNG
    randomData, _ := device.Random().Bytes(64)
    
    fmt.Printf("Random: %x\n", randomData)
}
```

### Java

```xml
<dependency>
    <groupId>com.dyber</groupId>
    <artifactId>quantacore-sdk</artifactId>
    <version>1.0.0</version>
</dependency>
```

```java
import com.dyber.quantacore.*;

public class QuickStart {
    public static void main(String[] args) {
        QuantaCore.initialize();
        
        try (Device device = QuantaCore.openFirstDevice()) {
            // ML-KEM
            KEM kem = device.kem();
            KeyPair keypair = kem.generateKeypair768();
            
            // ML-DSA
            Sign sign = device.sign();
            KeyPair sigKeypair = sign.generateKeypair65();
            byte[] signature = sign.sign(sigKeypair.getSecretKey(), "message".getBytes());
            
            // QRNG
            byte[] randomData = device.random().bytes(64);
            
            System.out.println("Random: " + Hex.encode(randomData));
        }
        
        QuantaCore.cleanup();
    }
}
```

---

## 🔌 Integrations

### OpenSSL 3.x Provider

Transparent post-quantum acceleration for any OpenSSL-based application.

```bash
# Build and install
cd integrations/openssl
mkdir build && cd build
cmake -DQUAC100_ROOT=/usr/local ..
make && sudo make install

# Configure OpenSSL
export OPENSSL_MODULES=/usr/local/lib/ossl-modules
export OPENSSL_CONF=/etc/ssl/openssl-quac100.cnf

# Verify
openssl list -providers -provider quac100
```

**Usage:**
```bash
# Generate ML-KEM keypair
openssl genpkey -provider quac100 -algorithm ML-KEM-768 -out mlkem768.pem

# Generate ML-DSA keypair
openssl genpkey -provider quac100 -algorithm ML-DSA-65 -out mldsa65.pem

# Sign a file
openssl dgst -provider quac100 -sign mldsa65.pem -out sig.bin document.pdf

# Generate random bytes
openssl rand -provider quac100 64
```

### PKCS#11 Module

Standard cryptographic token interface for enterprise applications.

```bash
# Build
cd integrations/pkcs11
mkdir build && cd build
cmake ..
make && sudo make install

# Configure
export QUAC100_PKCS11_MODULE=/usr/local/lib/libquac100_pkcs11.so

# Test with pkcs11-tool
pkcs11-tool --module $QUAC100_PKCS11_MODULE --list-slots
```

**Integration with applications:**
- **Firefox/Thunderbird:** Add module in Security Devices settings
- **Java (SunPKCS11):** Configure provider in `java.security`
- **OpenSSL:** Use `pkcs11` engine
- **SSH:** Configure `PKCS11Provider` in ssh_config

### TLS Integration

Ready-to-use examples for post-quantum TLS:

```bash
# Build examples
cd integrations/tls
make

# Run PQ-TLS server
./pq_tls_server --cert server.pem --key server-key.pem --port 8443

# Run PQ-TLS client
./pq_tls_client --host localhost --port 8443
```

---

## 💻 Command-Line Tools

### quac100-cli

Interactive command-line interface for all QUAC 100 operations.

```bash
# Device information
quac100-cli info
quac100-cli list

# KEM operations
quac100-cli kem keygen -a ml-kem-768 --pk public.bin --sk secret.bin
quac100-cli kem encaps -a ml-kem-768 -p public.bin --ct ct.bin --ss shared.bin
quac100-cli kem decaps -a ml-kem-768 -s secret.bin -c ct.bin --ss shared.bin

# Signature operations
quac100-cli sign keygen -a ml-dsa-65 --pk public.bin --sk secret.bin
quac100-cli sign sign -a ml-dsa-65 -s secret.bin -m document.pdf -o signature.bin
quac100-cli sign verify -a ml-dsa-65 -p public.bin -m document.pdf -g signature.bin

# Random generation
quac100-cli random 32 --hex
quac100-cli random 1024 -o random.bin

# Diagnostics
quac100-cli diag selftest
quac100-cli diag health
quac100-cli diag firmware

# Interactive shell
quac100-cli shell
```

### quac100-bench

Performance benchmarking tool.

```bash
# Run all benchmarks
quac100-bench

# Specific algorithm
quac100-bench --algorithm ml-kem-768 --iterations 10000

# Batch benchmarks
quac100-bench --batch-sizes 1,16,64,256,1024

# Export results
quac100-bench --json -o results.json
```

### quac100-diag

Device diagnostics and health monitoring.

```bash
# Full diagnostic report
quac100-diag --full-report -o diagnostic.txt

# Monitor temperature
quac100-diag --monitor --interval 1

# FIPS self-test
quac100-diag --fips-test

# Entropy analysis
quac100-diag --entropy-test --samples 1000000
```

---

## 🎮 Simulator Mode

The SDK includes a full software simulator for development and testing without hardware.

### Enabling Simulator

**C:**
```c
quac_set_simulator_mode(true);
quac_init(NULL);
```

**Python:**
```python
quantacore.initialize(flags=quantacore.InitFlags.SIMULATOR)
```

**Rust:**
```rust
quantacore::initialize_with_flags(InitFlags::SIMULATOR)?;
```

**Environment Variable:**
```bash
export QUAC_SIMULATOR=1
./your_application
```

**CLI:**
```bash
quac100-cli -s info
quac100-cli --simulator kem keygen -a ml-kem-768
```

### Simulator Features

| Feature | Hardware | Simulator |
|---------|----------|-----------|
| All algorithms | ✅ | ✅ |
| Key storage | ✅ | ✅ (memory) |
| Async operations | ✅ | ✅ |
| Batch processing | ✅ | ✅ |
| QRNG | Hardware entropy | CSPRNG |
| Performance | Full speed | ~10-100x slower |
| FIPS mode | ✅ | ❌ |

### Configuring Simulator

```c
// Set simulated latency (microseconds)
quac_simulator_config(100, 0);  // 100μs per operation

// Set simulated throughput (ops/second)
quac_simulator_config(0, 10000);  // 10,000 ops/sec
```

---

## ⚡ Performance

### Single Operation Latency

| Operation | QUAC 100 Hardware | Software (Reference) | Speedup |
|-----------|-------------------|----------------------|---------|
| ML-KEM-768 KeyGen | 1.0 μs | 45 μs | 45x |
| ML-KEM-768 Encaps | 0.6 μs | 52 μs | 87x |
| ML-KEM-768 Decaps | 0.12 μs | 58 μs | 483x |
| ML-DSA-65 KeyGen | 1.1 μs | 120 μs | 109x |
| ML-DSA-65 Sign | 1.1 μs | 280 μs | 255x |
| ML-DSA-65 Verify | 0.25 μs | 95 μs | 380x |
| SHA3-256 (1KB) | 0.2 μs | 8 μs | 40x |
| QRNG (32 bytes) | 0.01 μs | N/A | N/A |

### Throughput (Operations/Second)

| Operation | Single | Batch (256) | Batch (1024) |
|-----------|--------|-------------|--------------|
| ML-KEM-768 KeyGen | 1,000,000 | 15,000,000 | 18,000,000 |
| ML-KEM-768 Encaps | 1,700,000 | 25,000,000 | 30,000,000 |
| ML-KEM-768 Decaps | 8,000,000 | 120,000,000 | 150,000,000 |
| ML-DSA-65 Sign | 900,000 | 14,000,000 | 17,000,000 |
| ML-DSA-65 Verify | 4,000,000 | 60,000,000 | 75,000,000 |

### Batch Processing Scaling

| Batch Size | Relative Throughput |
|------------|---------------------|
| 1 | 1.0x (baseline) |
| 8 | 6-8x |
| 16 | 8-10x |
| 64 | 12-15x |
| 256 | 15-18x |
| 1024 | 18-20x |

### QRNG Performance

| Quality Level | Throughput | Use Case |
|---------------|------------|----------|
| Fast | 4 Gbps | Nonces, IVs |
| Standard | 2 Gbps | Keys, general crypto |
| High | 500 Mbps | Long-term keys |
| Maximum | 100 Mbps | Highest security |

---

## 📖 API Overview

### Core Functions

```c
// Initialization
quac_result_t quac_init(const quac_init_options_t *options);
void quac_shutdown(void);
bool quac_is_initialized(void);
const char *quac_version_string(void);

// Device Management
quac_result_t quac_device_count(uint32_t *count);
quac_result_t quac_open(uint32_t index, quac_device_t *device);
quac_result_t quac_open_by_serial(const char *serial, quac_device_t *device);
quac_result_t quac_close(quac_device_t device);
quac_result_t quac_get_info(quac_device_t device, quac_device_info_t *info);
quac_result_t quac_reset(quac_device_t device);

// ML-KEM (Key Encapsulation)
quac_result_t quac_kem_keygen(quac_device_t device, quac_algorithm_t algorithm,
                              uint8_t *public_key, size_t pk_size,
                              uint8_t *secret_key, size_t sk_size);
quac_result_t quac_kem_encaps(quac_device_t device, quac_algorithm_t algorithm,
                              const uint8_t *public_key, size_t pk_size,
                              uint8_t *ciphertext, size_t ct_size,
                              uint8_t *shared_secret, size_t ss_size);
quac_result_t quac_kem_decaps(quac_device_t device, quac_algorithm_t algorithm,
                              const uint8_t *ciphertext, size_t ct_size,
                              const uint8_t *secret_key, size_t sk_size,
                              uint8_t *shared_secret, size_t ss_size);

// ML-DSA / SLH-DSA (Digital Signatures)
quac_result_t quac_sign_keygen(quac_device_t device, quac_algorithm_t algorithm,
                               uint8_t *public_key, size_t pk_size,
                               uint8_t *secret_key, size_t sk_size);
quac_result_t quac_sign(quac_device_t device, quac_algorithm_t algorithm,
                        const uint8_t *secret_key, size_t sk_size,
                        const uint8_t *message, size_t msg_size,
                        uint8_t *signature, size_t sig_size, size_t *sig_len);
quac_result_t quac_verify(quac_device_t device, quac_algorithm_t algorithm,
                          const uint8_t *public_key, size_t pk_size,
                          const uint8_t *message, size_t msg_size,
                          const uint8_t *signature, size_t sig_size);

// QRNG (Random Number Generation)
quac_result_t quac_random_bytes(quac_device_t device, uint8_t *buffer, size_t length);
quac_result_t quac_random_available(quac_device_t device, uint32_t *bits);
quac_result_t quac_random_reseed(quac_device_t device, const uint8_t *seed, size_t seed_len);

// Key Management
quac_result_t quac_key_generate(quac_device_t device, const quac_key_attr_t *attr,
                                quac_key_handle_t *handle);
quac_result_t quac_key_import(quac_device_t device, const quac_key_attr_t *attr,
                              const uint8_t *key_data, size_t key_len,
                              quac_key_handle_t *handle);
quac_result_t quac_key_export(quac_device_t device, quac_key_handle_t handle,
                              uint8_t *key_data, size_t key_len, size_t *actual_len);
quac_result_t quac_key_destroy(quac_device_t device, quac_key_handle_t handle);

// Diagnostics
quac_result_t quac_self_test(quac_device_t device);
quac_result_t quac_get_health(quac_device_t device, quac_device_status_t *status);
quac_result_t quac_get_temperature(quac_device_t device, int32_t *celsius);
const char *quac_error_string(quac_result_t result);
```

### Algorithm Constants

```c
// ML-KEM (Kyber)
QUAC_ALGORITHM_KYBER512   // NIST Level 1
QUAC_ALGORITHM_KYBER768   // NIST Level 3 (recommended)
QUAC_ALGORITHM_KYBER1024  // NIST Level 5

// ML-DSA (Dilithium)
QUAC_ALGORITHM_DILITHIUM2  // NIST Level 2
QUAC_ALGORITHM_DILITHIUM3  // NIST Level 3 (recommended)
QUAC_ALGORITHM_DILITHIUM5  // NIST Level 5

// SLH-DSA (SPHINCS+)
QUAC_ALGORITHM_SPHINCS_SHA2_128S  // Small signatures
QUAC_ALGORITHM_SPHINCS_SHA2_128F  // Fast signing
QUAC_ALGORITHM_SPHINCS_SHA2_192S
QUAC_ALGORITHM_SPHINCS_SHA2_192F
QUAC_ALGORITHM_SPHINCS_SHA2_256S
QUAC_ALGORITHM_SPHINCS_SHA2_256F
```

### Size Constants

```c
// ML-KEM-768 (recommended)
QUAC_KYBER768_PUBLIC_KEY_SIZE      // 1,184 bytes
QUAC_KYBER768_SECRET_KEY_SIZE      // 2,400 bytes
QUAC_KYBER768_CIPHERTEXT_SIZE      // 1,088 bytes
QUAC_KYBER768_SHARED_SECRET_SIZE   // 32 bytes

// ML-DSA-65 (recommended)
QUAC_DILITHIUM3_PUBLIC_KEY_SIZE    // 1,952 bytes
QUAC_DILITHIUM3_SECRET_KEY_SIZE    // 4,000 bytes
QUAC_DILITHIUM3_SIGNATURE_SIZE     // 3,293 bytes
```

---

## 🛠️ Building from Source

### Prerequisites

| Dependency | Version | Required |
|------------|---------|----------|
| CMake | 3.16+ | Yes |
| C Compiler | C11 (GCC 7+, Clang 6+, MSVC 2019+) | Yes |
| C++ Compiler | C++17 | For C++ bindings |
| Python | 3.8+ | For Python bindings |
| Rust | 1.70+ | For Rust bindings |
| OpenSSL | 3.0+ | For OpenSSL provider |

### Build Steps

```bash
# Clone repository
git clone https://github.com/dyber-pqc/quantacore-sdk.git
cd quantacore-sdk

# Create build directory
mkdir build && cd build

# Configure (Linux/macOS)
cmake -DCMAKE_BUILD_TYPE=Release \
      -DQUAC_BUILD_TESTS=ON \
      -DQUAC_BUILD_EXAMPLES=ON \
      -DQUAC_BUILD_SIMULATOR=ON \
      -DQUAC_BUILD_OPENSSL=ON \
      -DQUAC_BUILD_PYTHON=ON \
      ..

# Configure (Windows)
cmake -G "Visual Studio 17 2022" -A x64 \
      -DQUAC_BUILD_TESTS=ON \
      -DQUAC_BUILD_EXAMPLES=ON \
      ..

# Build
cmake --build . --config Release -j$(nproc)

# Test
ctest --output-on-failure

# Install
sudo cmake --install .
```

### Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `BUILD_SHARED_LIBS` | ON | Build shared libraries |
| `QUAC_BUILD_SIMULATOR` | ON | Build software simulator |
| `QUAC_BUILD_TESTS` | ON | Build test suite |
| `QUAC_BUILD_EXAMPLES` | ON | Build examples |
| `QUAC_BUILD_TOOLS` | ON | Build CLI tools |
| `QUAC_BUILD_DOCS` | OFF | Build documentation |
| `QUAC_BUILD_OPENSSL` | ON | Build OpenSSL provider |
| `QUAC_BUILD_PKCS11` | ON | Build PKCS#11 module |
| `QUAC_BUILD_PYTHON` | ON | Build Python bindings |
| `QUAC_BUILD_RUST` | OFF | Build Rust bindings |
| `QUAC_BUILD_JAVA` | OFF | Build Java bindings |
| `QUAC_BUILD_GO` | OFF | Build Go bindings |
| `QUAC_ENABLE_FIPS_MODE` | OFF | Enable FIPS 140-3 mode |
| `QUAC_ENABLE_ZEROIZE` | ON | Secure memory zeroization |

---

## 🧪 Testing

### Running Tests

```bash
# All tests
cd build
ctest --output-on-failure

# Specific test category
ctest -R unit
ctest -R integration
ctest -R performance

# With verbose output
ctest -V

# Parallel execution
ctest -j$(nproc)
```

### Test Categories

| Directory | Description |
|-----------|-------------|
| `tests/unit/` | Unit tests for individual functions |
| `tests/integration/` | Integration tests with device |
| `tests/performance/` | Performance benchmarks |
| `tests/conformance/` | NIST KAT (Known Answer Tests) |
| `tests/kat/` | Algorithm test vectors |

### Running KAT Tests

```bash
# NIST Known Answer Tests
cd tests/kat
./run_kat_tests.sh

# Specific algorithm
./kat_runner --algorithm ml-kem-768 --vectors nist-kat-mlkem768.rsp
```

### Code Coverage

```bash
# Configure with coverage
cmake -DCMAKE_BUILD_TYPE=Debug -DQUAC_ENABLE_COVERAGE=ON ..
make
ctest

# Generate report
lcov --capture --directory . --output-file coverage.info
genhtml coverage.info --output-directory coverage_report
```

---

## 📁 Repository Structure

```
quantacore-sdk/
├── README.md                 # This file
├── LICENSE.txt               # Proprietary license
├── VERSION                   # Version number (1.0.0)
├── CHANGELOG.md              # Release history
├── CMakeLists.txt            # Main CMake configuration
├── setup.py                  # Python package setup
├── go.mod                    # Go module definition
├── quantacore-sdk.sln        # Visual Studio solution
│
├── include/                  # Public C/C++ headers
│   ├── quac100.h             # Main API header
│   ├── quac100_types.h       # Type definitions
│   ├── quac100_kem.h         # KEM operations
│   ├── quac100_sign.h        # Signature operations
│   ├── quac100_random.h      # QRNG operations
│   ├── quac100_async.h       # Async operations
│   ├── quac100_batch.h       # Batch processing
│   ├── quac100_diag.h        # Diagnostics
│   └── quac100_error.h       # Error handling
│
├── src/                      # Source code
│   ├── core/                 # Core library implementation
│   ├── platform/             # Platform-specific code
│   └── util/                 # Utility functions
│
├── bindings/                 # Language bindings
│   ├── c/                    # C examples and utilities
│   ├── c++/                  # C++ wrapper
│   ├── python/               # Python package (PyPI)
│   ├── rust/                 # Rust crate (crates.io)
│   ├── go/                   # Go module
│   ├── java/                 # Java JNI bindings
│   ├── nodejs/               # Node.js N-API bindings
│   └── csharp/               # C# P/Invoke bindings
│
├── integrations/             # Third-party integrations
│   ├── openssl/              # OpenSSL 3.x provider
│   ├── boringssl/            # BoringSSL engine
│   ├── pkcs11/               # PKCS#11 module
│   └── tls/                  # TLS examples
│
├── drivers/                  # Kernel drivers
│   ├── linux/                # Linux kernel module
│   └── windows/              # Windows KMDF driver
│
├── simulator/                # Software simulator
│   ├── include/              # Simulator headers
│   ├── src/                  # Simulator implementation
│   └── config/               # Configuration files
│
├── tools/                    # Command-line tools
│   ├── quac100-cli/          # Main CLI tool
│   ├── quac100-bench/        # Benchmarking tool
│   ├── quac100-diag/         # Diagnostics tool
│   └── bindgen/              # Binding generators
│
├── examples/                 # Example applications
│   ├── c/                    # C examples
│   ├── python/               # Python examples
│   ├── rust/                 # Rust examples
│   ├── go/                   # Go examples
│   └── java/                 # Java examples
│
├── tests/                    # Test suite
│   ├── unit/                 # Unit tests
│   ├── integration/          # Integration tests
│   ├── performance/          # Performance tests
│   ├── conformance/          # Conformance tests
│   └── kat/                  # Known Answer Tests
│
├── docs/                     # Documentation
│   ├── api/                  # API reference
│   ├── guides/               # User guides
│   └── reference/            # Technical reference
│
├── cmake/                    # CMake modules
├── packaging/                # Distribution packages
│   ├── deb/                  # Debian packages
│   ├── rpm/                  # RPM packages
│   └── msi/                  # Windows installers
│
├── scripts/                  # Utility scripts
│   ├── build/                # Build scripts
│   ├── test/                 # Test scripts
│   └── release/              # Release scripts
│
└── lib/                      # Pre-built libraries
    ├── linux-x64/
    ├── windows-x64/
    └── macos-x64/
```

---

## 🔒 Security Considerations

### Key Management Best Practices

1. **Use Hardware Key Storage** - Store sensitive keys in device slots
2. **Minimize Key Lifetime** - Use ephemeral keys when possible
3. **Enable Zeroization** - Ensure `QUAC_ENABLE_ZEROIZE` is ON
4. **Verify Signatures** - Always verify before trusting signed data
5. **Check Return Values** - Handle all error codes appropriately

### FIPS 140-3 Compliance

The QUAC 100 supports FIPS 140-3 Level 3 mode:

```c
quac_init_options_t opts = {0};
opts.flags = QUAC_INIT_FIPS_MODE;
quac_init(&opts);
```

In FIPS mode:
- Only approved algorithms are available
- Power-up self-tests are mandatory
- Key zeroization is enforced
- Tamper detection is active

### Secure Development

```c
// Always check return values
quac_result_t result = quac_kem_keygen(...);
if (QUAC_FAILED(result)) {
    // Handle error
    fprintf(stderr, "Error: %s\n", quac_error_string(result));
}

// Use secure memory clearing
uint8_t secret_key[QUAC_KYBER768_SECRET_KEY_SIZE];
// ... use key ...
quac_secure_zero(secret_key, sizeof(secret_key));

// Constant-time comparison for secrets
if (quac_secure_compare(secret1, secret2, len)) {
    // Secrets match
}
```

### Reporting Security Issues

Please report security vulnerabilities to [security@dyber.com](mailto:security@dyber.com). Do not open public GitHub issues for security-sensitive matters.

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [API Reference](docs/api/README.md) | Complete API documentation |
| [Getting Started Guide](docs/guides/getting-started.md) | Installation and first steps |
| [KEM Operations Guide](docs/guides/kem-operations.md) | Key encapsulation tutorial |
| [Signature Operations Guide](docs/guides/signature-operations.md) | Digital signature tutorial |
| [QRNG Guide](docs/guides/random-numbers.md) | Random number generation |
| [Integration Guide](docs/guides/integration.md) | System integration |
| [Best Practices](docs/guides/best-practices.md) | Security and performance tips |
| [Technical Reference](docs/reference/README.md) | Hardware and algorithm details |

### Online Documentation

- **Developer Portal**: [docs.dyber.org/quac100](https://docs.dyber.org/quac100)
- **API Reference**: [docs.dyber.org/quac100/api](https://docs.dyber.org/quac100/api)
- **Tutorials**: [docs.dyber.org/quac100/tutorials](https://docs.dyber.org/quac100/tutorials)

---

## 📝 Changelog

See [CHANGELOG.md](CHANGELOG.md) for release history.

### Latest Release: v1.0.0 (2025)

**Features:**
- Initial release
- ML-KEM (FIPS 203): ML-KEM-512, ML-KEM-768, ML-KEM-1024
- ML-DSA (FIPS 204): ML-DSA-44, ML-DSA-65, ML-DSA-87
- SLH-DSA (FIPS 205): All SHA-2 variants
- Hardware QRNG with SP 800-90B compliance
- Async and batch operations
- OpenSSL 3.x provider
- PKCS#11 module
- 8 language bindings
- Full software simulator

---

## 📄 License

Copyright © 2025 Dyber, Inc. All Rights Reserved.

This software is proprietary and confidential. Unauthorized copying, distribution, or use of this software is strictly prohibited. See [LICENSE.txt](LICENSE.txt) for the full license agreement.

The QUAC 100 hardware and QuantaCore SDK are available under commercial license from Dyber, Inc.

---

## 🆘 Support

### Getting Help

| Resource | Link |
|----------|------|
| **Documentation** | [docs.dyber.org/quac100](https://docs.dyber.org/quac100) |
| **GitHub Issues** | [github.com/dyber-pqc/quantacore-sdk/issues](https://github.com/dyber-pqc/quantacore-sdk/issues) |
| **Email Support** | [support@dyber.com](mailto:support@dyber.com) |
| **Enterprise Support** | [enterprise@dyber.com](mailto:enterprise@dyber.com) |

### Community

- **Discord**: [discord.gg/m4U6wSZE](https://discord.gg/m4U6wSZE)
- **Twitter/X**: [@DyberPQC](https://twitter.com/DyberPQC)
- **LinkedIn**: [Dyber, Inc.](https://linkedin.com/company/dyber)

### Enterprise Support

Enterprise customers receive:
- Priority email and phone support
- Dedicated technical account manager
- Custom integration assistance
- Extended maintenance and security updates
- Training and certification programs

Contact [enterprise@dyber.com](mailto:enterprise@dyber.com) for more information.

---

<p align="center">
  <strong>Built with ❤️ by <a href="https://dyber.com">Dyber, Inc.</a></strong>
  <br>
  <em>Securing the Post-Quantum Future</em>
</p>

<p align="center">
  <a href="https://dyber.com">Website</a> •
  <a href="https://docs.dyber.org">Documentation</a> •
  <a href="https://github.com/dyber-pqc">GitHub</a> •
</p>
