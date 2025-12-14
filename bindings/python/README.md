# QUAC 100 Python SDK

[![PyPI version](https://img.shields.io/pypi/v/quantacore-sdk.svg)](https://pypi.org/project/quantacore-sdk/)
[![Python](https://img.shields.io/pypi/pyversions/quantacore-sdk.svg)](https://pypi.org/project/quantacore-sdk/)
[![License](https://img.shields.io/badge/License-Proprietary-red.svg)](LICENSE)
[![Documentation](https://img.shields.io/badge/docs-dyber.org-blue.svg)](https://docs.dyber.org/quac100/python)

Python bindings for the **QUAC 100** Post-Quantum Cryptographic Accelerator.

## Overview

The QUAC 100 Python SDK provides a Pythonic interface to the QUAC 100 hardware accelerator, enabling high-performance post-quantum cryptographic operations with an easy-to-use API.

### Features

- **ML-KEM (Kyber)** - Post-quantum key encapsulation (ML-KEM-512/768/1024)
- **ML-DSA (Dilithium)** - Post-quantum digital signatures (ML-DSA-44/65/87)
- **QRNG** - Quantum random number generation
- **Hardware-accelerated hashing** - SHA-2, SHA-3, SHAKE, HMAC, HKDF
- **HSM Key Storage** - Secure key management with 256 key slots
- **Type hints** - Full type annotation support (PEP 561)
- **Context managers** - Automatic resource cleanup
- **Cross-platform** - Windows, Linux, macOS support

## Requirements

- **Python 3.8** or later
- **QUAC 100 hardware** or simulation mode

### Platform Support

| Platform | Architecture | Status |
|----------|--------------|--------|
| Windows  | x64          | ✅ Supported |
| Linux    | x64          | ✅ Supported |
| macOS    | x64/arm64    | ✅ Supported |

## Installation

### From PyPI (Recommended)

```bash
pip install quantacore-sdk
```

### From Source

```bash
git clone https://github.com/dyber-pqc/quantacore-sdk.git
cd quantacore-sdk/bindings/python
pip install -e .
```

### With Development Dependencies

```bash
pip install quantacore-sdk[dev]
```

## Quick Start

```python
import quantacore

# Initialize library
quantacore.initialize()

try:
    # Open device
    device = quantacore.open_first_device()
    
    # ML-KEM key exchange
    kem = device.kem()
    with kem.generate_keypair(quantacore.KemAlgorithm.ML_KEM_768) as keypair:
        # Sender: encapsulate
        with kem.encapsulate(keypair.public_key) as encap:
            ciphertext = encap.ciphertext
            sender_secret = encap.shared_secret
            
            # Recipient: decapsulate
            recipient_secret = kem.decapsulate(keypair.secret_key, ciphertext)
            
            assert sender_secret == recipient_secret
            print(f"Shared secret: {quantacore.to_hex(sender_secret)}")
    
    device.close()
finally:
    quantacore.cleanup()
```

## API Reference

### Library Management

```python
import quantacore

# Initialize with default flags
quantacore.initialize()

# Initialize with specific flags
quantacore.initialize(
    quantacore.InitFlags.HARDWARE_ACCEL | 
    quantacore.InitFlags.FIPS_MODE
)

# Check initialization
if quantacore.is_initialized():
    print("Library ready")

# Get version info
print(f"Version: {quantacore.get_version()}")
print(f"Build: {quantacore.get_build_info()}")

# Enumerate devices
devices = quantacore.enumerate_devices()
for dev in devices:
    print(f"Device {dev.index}: {dev.model} ({dev.serial_number})")

# Open device
device = quantacore.open_first_device()
# or: device = quantacore.open_device(0)

# Clean up
quantacore.cleanup()
```

### Device Operations

```python
device = quantacore.open_first_device()

# Get device info
info = device.get_info()
print(f"Model: {info.model}")
print(f"Serial: {info.serial_number}")
print(f"Firmware: {info.firmware_version}")
print(f"Key Slots: {info.key_slots}")

# Get device status
status = device.get_status()
print(f"Temperature: {status.temperature}°C")
print(f"Entropy Level: {status.entropy_level}%")
print(f"Healthy: {status.is_healthy}")

# Run self-test
device.self_test()

# Reset device
device.reset()

# Close device
device.close()
```

### Key Encapsulation (ML-KEM/Kyber)

```python
kem = device.kem()

# Generate key pair
keypair = kem.generate_keypair(quantacore.KemAlgorithm.ML_KEM_768)
# Convenience methods: generate_keypair_512(), generate_keypair_768(), generate_keypair_1024()

print(f"Public key: {len(keypair.public_key)} bytes")
print(f"Secret key: {len(keypair.secret_key)} bytes")

# Encapsulate (sender)
encap = kem.encapsulate(keypair.public_key, quantacore.KemAlgorithm.ML_KEM_768)
ciphertext = encap.ciphertext      # Send to recipient
shared_secret = encap.shared_secret  # Use for encryption

# Decapsulate (recipient)
shared_secret = kem.decapsulate(
    keypair.secret_key, 
    ciphertext, 
    quantacore.KemAlgorithm.ML_KEM_768
)

# Clean up sensitive data
keypair.close()
encap.close()
```

### Digital Signatures (ML-DSA/Dilithium)

```python
sign = device.sign()

# Generate signing key pair
keypair = sign.generate_keypair(quantacore.SignAlgorithm.ML_DSA_65)
# Convenience methods: generate_keypair_44(), generate_keypair_65(), generate_keypair_87()

# Sign a message
message = b"Important document"
signature = sign.sign(
    keypair.secret_key, 
    message, 
    quantacore.SignAlgorithm.ML_DSA_65
)

print(f"Signature: {len(signature)} bytes")

# Verify signature
valid = sign.verify(
    keypair.public_key, 
    message, 
    signature, 
    quantacore.SignAlgorithm.ML_DSA_65
)
print(f"Valid: {valid}")

# Verify and raise exception if invalid
try:
    sign.verify_or_raise(keypair.public_key, message, signature)
except quantacore.VerificationError:
    print("Signature verification failed!")

keypair.close()
```

### Random Number Generation (QRNG)

```python
random = device.random()

# Check entropy status
status = random.get_entropy_status()
print(f"Entropy level: {status.level}%")
print(f"Healthy: {status.is_healthy}")

# Generate random bytes
data = random.bytes(32)

# Fill buffer
buffer = bytearray(64)
random.next_bytes(buffer)

# Random integers
value = random.next_int()          # 32-bit
value = random.next_int(100)       # [0, 100)
value = random.randint(10, 20)     # [10, 20]

# Random floats
f = random.next_float()            # [0.0, 1.0)
f = random.uniform(10.0, 20.0)     # [10.0, 20.0)

# Random boolean
b = random.next_bool()

# UUID
uuid_str = random.uuid()           # String format
uuid_obj = random.next_uuid()      # UUID object

# Choose from sequence
item = random.choice(['a', 'b', 'c'])

# Sample without replacement
sample = random.sample(range(100), 5)

# Shuffle in place
items = [1, 2, 3, 4, 5]
random.shuffle(items)

# Get shuffled copy
shuffled = random.shuffled([1, 2, 3, 4, 5])
```

### Hashing

```python
hash = device.hash()

# One-shot hashing
digest = hash.hash(quantacore.HashAlgorithm.SHA3_256, b"data")

# Convenience methods
digest = hash.sha256(b"data")
digest = hash.sha384(b"data")
digest = hash.sha512(b"data")
digest = hash.sha3_256(b"data")
digest = hash.sha3_512(b"data")

# String input
digest = hash.sha256("Hello, World!")

# SHAKE (variable output)
output = hash.shake128(b"data", output_length=64)
output = hash.shake256(b"data", output_length=128)

# Incremental hashing
with hash.create_context(quantacore.HashAlgorithm.SHA256) as ctx:
    ctx.update(b"Part 1")
    ctx.update(b"Part 2")
    ctx.update("Part 3")  # String also accepted
    digest = ctx.digest()

# HMAC
mac = hash.hmac_sha256(key, data)
mac = hash.hmac_sha512(key, data)
mac = hash.hmac(quantacore.HashAlgorithm.SHA256, key, data)

# HKDF key derivation
derived_key = hash.hkdf(
    quantacore.HashAlgorithm.SHA256,
    ikm=input_key_material,
    salt=b"salt",
    info=b"context",
    length=32
)
```

### Utility Functions

```python
from quantacore import to_hex, from_hex, to_base64, from_base64
from quantacore import secure_zero, secure_compare

# Hex encoding
hex_str = to_hex(b'\xde\xad\xbe\xef')  # 'deadbeef'
data = from_hex('deadbeef')             # b'\xde\xad\xbe\xef'

# Base64 encoding
b64 = to_base64(data)
data = from_base64(b64)

# URL-safe Base64
b64url = to_base64url(data)
data = from_base64url(b64url)

# Secure operations
secret = bytearray(b"sensitive")
secure_zero(secret)                     # Zero memory

# Constant-time comparison
if secure_compare(hash1, hash2):
    print("Hashes match")
```

## Exception Handling

```python
try:
    device = quantacore.open_first_device()
except quantacore.DeviceError as e:
    print(f"Device error: {e}")
except quantacore.InitializationError as e:
    print(f"Not initialized: {e}")

try:
    sign.verify_or_raise(pk, msg, sig)
except quantacore.VerificationError:
    print("Invalid signature")
except quantacore.CryptoError as e:
    print(f"Crypto error: {e}")
except quantacore.QuacError as e:
    print(f"Error [{e.error_code}]: {e.message}")
```

### Error Codes

| Code | Name | Description |
|------|------|-------------|
| 0 | `SUCCESS` | Operation completed |
| -4 | `DEVICE_NOT_FOUND` | No device found |
| -6 | `DEVICE_ERROR` | Device error |
| -13 | `VERIFICATION_FAILED` | Signature invalid |
| -17 | `NOT_INITIALIZED` | Library not initialized |
| -26 | `INVALID_ALGORITHM` | Invalid algorithm |
| -27 | `CRYPTO_ERROR` | Cryptographic error |

## Context Managers

The SDK uses context managers for automatic resource cleanup:

```python
# Recommended: use context managers
with quantacore.open_first_device() as device:
    kem = device.kem()
    with kem.generate_keypair() as kp:
        with kem.encapsulate(kp.public_key) as encap:
            # Use encap.shared_secret
            pass
        # encap automatically cleaned up
    # keypair automatically cleaned up
# device automatically closed
```

## Testing

```bash
# Install test dependencies
pip install quantacore-sdk[test]

# Run tests
pytest

# Run with coverage
pytest --cov=quantacore

# Run specific test
pytest tests/test_kem.py -v
```

## Performance

Typical performance on QUAC 100 hardware:

| Operation | Performance |
|-----------|------------|
| ML-KEM-768 KeyGen | ~1,000,000 ops/sec |
| ML-KEM-768 Encaps | ~1,700,000 ops/sec |
| ML-KEM-768 Decaps | ~8,000,000 ops/sec |
| ML-DSA-65 Sign | ~900,000 ops/sec |
| ML-DSA-65 Verify | ~4,000,000 ops/sec |
| SHA3-256 | ~500 MB/sec |
| QRNG | ~2,000 MB/sec |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `QUAC100_LIBRARY_PATH` | Path to native library |

## Troubleshooting

### Library Not Found

```
OSError: Failed to load QUAC 100 native library
```

**Solution**: Set the library path:
```bash
export QUAC100_LIBRARY_PATH=/path/to/libquac100.so
```

### Device Not Found

```
DeviceError: No QUAC 100 device found
```

**Solution**: 
1. Check device is connected
2. Verify drivers are installed
3. Run with elevated privileges if needed

### Not Initialized

```
InitializationError: Library not initialized
```

**Solution**: Call `quantacore.initialize()` first.

## Building from Source

```bash
# Clone repository
git clone https://github.com/dyber-pqc/quantacore-sdk.git
cd quantacore-sdk/bindings/python

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Install in development mode
pip install -e .[dev]

# Run tests
pytest

# Build wheel
pip install build
python -m build
```

## Publishing to PyPI

```bash
# Build
python -m build

# Upload to TestPyPI
twine upload --repository testpypi dist/*

# Upload to PyPI
twine upload dist/*
```

## Project Structure

```
python/
├── pyproject.toml          # Package configuration
├── setup.py                # Legacy support
├── README.md               # This file
├── quantacore/             # Main package
│   ├── __init__.py
│   ├── library.py          # Library management
│   ├── device.py           # Device class
│   ├── kem.py              # Key encapsulation
│   ├── sign.py             # Digital signatures
│   ├── hash.py             # Hashing
│   ├── random.py           # QRNG
│   ├── keys.py             # Key storage
│   ├── types.py            # Type definitions
│   ├── exceptions.py       # Exceptions
│   ├── utils.py            # Utilities
│   └── native/             # Native libraries
│       ├── windows-x64/
│       ├── linux-x64/
│       └── macos-x64/
└── tests/                  # Test suite
    ├── test_library.py
    ├── test_kem.py
    ├── test_sign.py
    └── test_utils.py
```

## License

Copyright © 2025 Dyber, Inc. All Rights Reserved.

This software is proprietary and confidential.

## Support

- **Documentation**: https://docs.dyber.org/quac100/python
- **Issues**: https://github.com/dyber-pqc/quantacore-sdk/issues
- **Email**: support@dyber.org
- **Website**: https://dyber.org