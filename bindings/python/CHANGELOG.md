# Changelog

All notable changes to the QUAC 100 Python SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-01-15

### Added
- Initial release of QUAC 100 Python SDK
- ML-KEM (Kyber) key encapsulation: ML-KEM-512, ML-KEM-768, ML-KEM-1024
- ML-DSA (Dilithium) digital signatures: ML-DSA-44, ML-DSA-65, ML-DSA-87
- Quantum Random Number Generation (QRNG)
- Hardware-accelerated hashing: SHA-2, SHA-3, SHAKE, HMAC, HKDF
- HSM key storage support
- Full type hints (PEP 561)
- Context manager support for automatic resource cleanup
- Cross-platform support: Windows x64, Linux x64, macOS x64/arm64
- Comprehensive test suite
- Example scripts for all major features

### Security
- Secure memory zeroing for sensitive data
- Constant-time comparison for cryptographic values
- Automatic cleanup of key material via context managers

## [Unreleased]

### Planned
- Additional SPHINCS+ signature support
- Falcon signature support
- Extended HSM key management features
- Performance benchmarking tools