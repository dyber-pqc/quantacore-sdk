# Changelog

All notable changes to the QuantaCore SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2024-12-16

### Added

#### Windows Driver Package
- Complete KMDF (Kernel-Mode Driver Framework) driver for Windows 10/11
- CNG (Cryptography Next Generation) provider integration
- WDF-based device and queue management
- Visual Studio 2022 solution with proper project configuration
- PowerShell setup script for driver development environment
- HLK (Hardware Lab Kit) test configurations
- Driver signing infrastructure and documentation
- Sample applications demonstrating driver usage

#### QuacTestSuite Application
- WPF test application built with .NET 8 and MaterialDesign themes
- Key Management view for ML-KEM, ML-DSA, and SLH-DSA operations
- Cryptographic demonstration panels
- API testing interface
- Entropy analysis and visualization tools
- Hardware diagnostics dashboard

#### Linux Driver Package
- DKMS-enabled kernel module for Linux 5.x/6.x kernels
- Debian packaging (.deb) with proper dependencies
- RPM packaging (.rpm) for RHEL/Fedora/openSUSE
- systemd service integration
- udev rules for device permissions
- Secure Boot signing support documentation

#### Language Bindings
- **C** - Native header files with comprehensive Doxygen documentation
- **C++** - Modern C++17 wrapper classes with RAII support
- **Python** - ctypes-based bindings with type hints
- **Rust** - Safe Rust bindings with proper error handling
- **Go** - cgo-based bindings with Go-idiomatic API
- **Java** - JNI bindings with Maven/Gradle support
- **Node.js** - N-API bindings with async support
- **C#/.NET** - P/Invoke bindings for .NET 6+

#### Core API
- ML-KEM (Kyber) key encapsulation: 512, 768, 1024 parameter sets
- ML-DSA (Dilithium) digital signatures: 44, 65, 87 parameter sets
- SLH-DSA (SPHINCS+) stateless signatures: multiple parameter sets
- Hardware QRNG (Quantum Random Number Generator) access
- Batch operations for high-throughput scenarios
- Asynchronous operation support
- Comprehensive error handling and diagnostics
- DMA transfer management

#### Integrations
- OpenSSL engine/provider for transparent PQC support
- PKCS#11 module for HSM-style integration
- TPM integration support

#### Tools and Utilities
- Command-line interface for all cryptographic operations
- Performance benchmarking tools
- Hardware diagnostics utilities
- Key format conversion utilities

#### Software Simulator
- Full software emulation of QUAC 100 hardware
- Useful for development and testing without hardware
- Configurable performance characteristics

#### Documentation
- Comprehensive API reference (Doxygen)
- Integration guides for all supported languages
- Hardware installation guides
- Security considerations and best practices

#### Build System
- CMake-based cross-platform build system
- Visual Studio solution for Windows components
- Packaging scripts for multiple distributions

[Unreleased]: https://github.com/dyber-pqc/quantacore-sdk/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/dyber-pqc/quantacore-sdk/releases/tag/v1.0.0
