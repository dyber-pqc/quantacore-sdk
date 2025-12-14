# QuantaCore SDK for Rust

Rust bindings for the QUAC 100 Post-Quantum Cryptographic Accelerator.

[![Crates.io](https://img.shields.io/crates/v/quantacore-sdk.svg)](https://crates.io/crates/quantacore-sdk)
[![Documentation](https://docs.rs/quantacore-sdk/badge.svg)](https://docs.rs/quantacore-sdk)
[![License](https://img.shields.io/badge/license-Proprietary-blue.svg)](LICENSE)

## Features

- **ML-KEM (Kyber)**: Post-quantum key encapsulation (512, 768, 1024 security levels)
- **ML-DSA (Dilithium)**: Post-quantum digital signatures (44, 65, 87 security levels)
- **QRNG**: Quantum random number generation with hardware entropy
- **Hardware Hashing**: SHA-2, SHA-3, SHAKE, HMAC, HKDF
- **HSM Key Storage**: Secure key management in hardware
- **Thread-Safe**: Device handles are `Send + Sync`
- **Memory-Safe**: Automatic zeroization of secrets via `zeroize` crate

## Test Results

```
99 tests passed, 0 failed
31 hardware tests (ignored without device)
27 doc-tests passed
```

## Requirements

- Rust 1.70 or later
- QUAC 100 device and native library installed
- Linux, Windows, or macOS

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
quantacore-sdk = "1.0"
```

## Quick Start

```rust
use quantacore::{initialize, cleanup, open_first_device, KemAlgorithm};

fn main() -> quantacore::Result<()> {
    // Initialize library
    initialize()?;

    // Open device
    let device = open_first_device()?;

    // Generate ML-KEM-768 key pair
    let kem = device.kem();
    let keypair = kem.generate_keypair(KemAlgorithm::MlKem768)?;

    // Encapsulate (sender side)
    let (ciphertext, shared_secret) = kem.encapsulate(
        keypair.public_key(),
        KemAlgorithm::MlKem768
    )?;

    // Decapsulate (receiver side)
    let decap_secret = kem.decapsulate(
        keypair.secret_key(),
        &ciphertext,
        KemAlgorithm::MlKem768
    )?;

    assert_eq!(shared_secret, decap_secret);

    // Cleanup
    drop(device);
    cleanup()?;

    Ok(())
}
```

## Examples

### Key Exchange (ML-KEM)

```rust
use quantacore::{initialize, cleanup, open_first_device};

fn main() -> quantacore::Result<()> {
    initialize()?;
    let device = open_first_device()?;
    let kem = device.kem();

    // Generate key pair (convenience method for ML-KEM-768)
    let keypair = kem.generate_keypair_768()?;

    // Encapsulate
    let (ciphertext, sender_secret) = kem.encapsulate_768(keypair.public_key())?;

    // Decapsulate
    let receiver_secret = kem.decapsulate_768(keypair.secret_key(), &ciphertext)?;

    assert_eq!(sender_secret, receiver_secret);
    cleanup()?;
    Ok(())
}
```

### Digital Signatures (ML-DSA)

```rust
use quantacore::{initialize, cleanup, open_first_device, SignAlgorithm};

fn main() -> quantacore::Result<()> {
    initialize()?;
    let device = open_first_device()?;
    let sign = device.sign();

    // Generate key pair
    let keypair = sign.generate_keypair(SignAlgorithm::MlDsa65)?;

    // Sign message
    let message = b"Hello, quantum world!";
    let signature = sign.sign(keypair.secret_key(), message, SignAlgorithm::MlDsa65)?;

    // Verify signature
    let valid = sign.verify(
        keypair.public_key(),
        message,
        &signature,
        SignAlgorithm::MlDsa65
    )?;
    assert!(valid);

    cleanup()?;
    Ok(())
}
```

### Hashing

```rust
use quantacore::{initialize, cleanup, open_first_device, HashAlgorithm};

fn main() -> quantacore::Result<()> {
    initialize()?;
    let device = open_first_device()?;
    let hash = device.hash();

    // One-shot hashing
    let digest = hash.sha256(b"Hello, World!")?;
    println!("SHA-256: {}", hex::encode(&digest));

    // Incremental hashing
    let mut ctx = hash.create_context(HashAlgorithm::Sha3_256)?;
    ctx.update(b"Hello, ")?;
    ctx.update(b"World!")?;
    let digest = ctx.finalize()?;

    // HMAC
    let mac = hash.hmac_sha256(b"secret key", b"message")?;

    // HKDF key derivation
    let derived = hash.hkdf_sha256(b"ikm", b"salt", b"info", 32)?;

    cleanup()?;
    Ok(())
}
```

### Random Number Generation (QRNG)

```rust
use quantacore::{initialize, cleanup, open_first_device};

fn main() -> quantacore::Result<()> {
    initialize()?;
    let device = open_first_device()?;
    let random = device.random();

    // Generate random bytes
    let bytes = random.bytes(32)?;

    // Generate integers
    let value = random.next_u64()?;
    let dice = random.randint(1, 6)?;

    // Generate UUID
    let uuid = random.uuid()?;
    println!("UUID: {}", uuid);

    // Shuffle a collection
    let mut items = vec![1, 2, 3, 4, 5];
    random.shuffle(&mut items)?;

    cleanup()?;
    Ok(())
}
```

### HSM Key Storage

```rust
use quantacore::{initialize, cleanup, open_first_device, KeyType, KeyUsage};

fn main() -> quantacore::Result<()> {
    initialize()?;
    let device = open_first_device()?;
    let keys = device.keys();

    // Store a key
    let key_data = vec![0u8; 32];
    keys.store(
        0,  // slot
        KeyType::Secret,
        0,  // algorithm
        KeyUsage::ENCRYPT | KeyUsage::DECRYPT,
        "my-key",
        &key_data,
    )?;

    // Load the key
    let loaded = keys.load(0)?;
    assert_eq!(loaded, key_data);

    // Get key info
    let info = keys.get_info(0)?;
    println!("Key label: {}", info.label);

    // Delete the key
    keys.delete(0)?;

    cleanup()?;
    Ok(())
}
```

## RAII Pattern

Use `LibraryContext` for automatic cleanup:

```rust
use quantacore::{LibraryContext, open_first_device};

fn main() -> quantacore::Result<()> {
    let _ctx = LibraryContext::new()?;  // Auto-cleanup on drop
    
    let device = open_first_device()?;
    // ... use device ...
    
    Ok(())  // Library cleaned up automatically
}
```

## Running Examples

```bash
cargo run --example basic
cargo run --example kem
cargo run --example sign
cargo run --example hash
cargo run --example random
```

## Running Tests

```bash
# Unit tests (no hardware required)
cargo test

# Integration tests (requires QUAC 100 hardware)
cargo test --test integration -- --ignored
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `QUAC100_LIB_DIR` | Custom library search path |
| `QUAC100_INCLUDE_DIR` | Custom include path |

## Feature Flags

| Feature | Description |
|---------|-------------|
| `std` | Standard library support (default) |
| `software-fallback` | Enable software fallback when hardware unavailable |
| `fips` | Enable FIPS 140-3 compliant mode |
| `debug` | Enable additional debug output |

## Thread Safety

The `Device` struct is `Send` and `Sync`, allowing it to be shared across threads safely. The underlying hardware operations are serialized by the device driver.

## Memory Safety

- All secret keys are automatically zeroed when dropped using the `zeroize` crate
- Constant-time operations for cryptographic comparisons
- Safe Rust wrappers around unsafe FFI calls

## Supported Platforms

| Platform | Architecture |
|----------|--------------|
| Linux | x86_64, aarch64 |
| Windows | x86_64 |
| macOS | x86_64, aarch64 |

## API Reference

### Algorithms

| Type | Variants |
|------|----------|
| `KemAlgorithm` | `MlKem512`, `MlKem768`, `MlKem1024` |
| `SignAlgorithm` | `MlDsa44`, `MlDsa65`, `MlDsa87` |
| `HashAlgorithm` | `Sha256`, `Sha384`, `Sha512`, `Sha3_256`, `Sha3_384`, `Sha3_512`, `Shake128`, `Shake256` |

### Key Sizes (bytes)

| Algorithm | Public Key | Secret Key | Ciphertext/Signature |
|-----------|------------|------------|---------------------|
| ML-KEM-512 | 800 | 1632 | 768 |
| ML-KEM-768 | 1184 | 2400 | 1088 |
| ML-KEM-1024 | 1568 | 3168 | 1568 |
| ML-DSA-44 | 1312 | 2560 | 2420 |
| ML-DSA-65 | 1952 | 4032 | 3309 |
| ML-DSA-87 | 2592 | 4896 | 4627 |

## Documentation

- [API Documentation](https://docs.rs/quantacore-sdk)
- [QUAC 100 Hardware Guide](https://docs.dyber.org/quac100)
- [QuantaCore SDK Overview](https://docs.dyber.org/sdk)

## License

Copyright © 2024-2025 Dyber, Inc. All rights reserved.

This software is proprietary and confidential. See [LICENSE](LICENSE) for details.

## Support

- Email: support@dyber.org
- Website: https://dyber.org
- GitHub Issues: https://github.com/dyber-pqc/quantacore-sdk/issues