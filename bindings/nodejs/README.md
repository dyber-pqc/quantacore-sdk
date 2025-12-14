# @dyber/quantacore-sdk

Node.js bindings for the QUAC 100 Post-Quantum Cryptographic Accelerator.

[![npm version](https://badge.fury.io/js/@dyber%2Fquantacore-sdk.svg)](https://www.npmjs.com/package/@dyber/quantacore-sdk)
[![License](https://img.shields.io/badge/license-Proprietary-blue.svg)](LICENSE)

## Features

- **ML-KEM (Kyber)**: Post-quantum key encapsulation (512, 768, 1024 security levels)
- **ML-DSA (Dilithium)**: Post-quantum digital signatures (44, 65, 87 security levels)
- **QRNG**: Quantum random number generation with hardware entropy
- **Hardware Hashing**: SHA-2, SHA-3, SHAKE, HMAC, HKDF
- **HSM Key Storage**: Secure key management in hardware
- **TypeScript**: Full type definitions included

## Requirements

- Node.js 16.0 or later
- QUAC 100 device and native library installed
- Linux, Windows, or macOS

## Installation

```bash
npm install @dyber/quantacore-sdk
```

## Quick Start

```typescript
import {
  initialize,
  cleanup,
  openFirstDevice,
  KemAlgorithm,
} from '@dyber/quantacore-sdk';

// Initialize library
initialize();

// Open device
const device = openFirstDevice();

// Generate ML-KEM-768 key pair
const keypair = device.kem.generateKeypair(KemAlgorithm.MlKem768);

// Encapsulate (sender)
const { ciphertext, sharedSecret } = device.kem.encapsulate(
  keypair.publicKey,
  KemAlgorithm.MlKem768
);

// Decapsulate (receiver)
const decrypted = device.kem.decapsulate(
  keypair.secretKey,
  ciphertext,
  KemAlgorithm.MlKem768
);

// Clean up
device.close();
cleanup();
```

## Examples

### Key Exchange (ML-KEM)

```typescript
import { initialize, cleanup, openFirstDevice, KemAlgorithm } from '@dyber/quantacore-sdk';

initialize();
const device = openFirstDevice();
const kem = device.kem;

// Generate key pair
const keypair = kem.generateKeypair768();

// Encapsulate
const { ciphertext, sharedSecret } = kem.encapsulate768(keypair.publicKey);

// Decapsulate
const decrypted = kem.decapsulate768(keypair.secretKey, ciphertext);

console.log('Secrets match:', sharedSecret.equals(decrypted));

device.close();
cleanup();
```

### Digital Signatures (ML-DSA)

```typescript
import { initialize, cleanup, openFirstDevice, SignAlgorithm } from '@dyber/quantacore-sdk';

initialize();
const device = openFirstDevice();
const sign = device.sign;

// Generate key pair
const keypair = sign.generateKeypair(SignAlgorithm.MlDsa65);

// Sign
const message = Buffer.from('Hello, World!');
const signature = sign.sign(keypair.secretKey, message, SignAlgorithm.MlDsa65);

// Verify
const isValid = sign.verify(keypair.publicKey, message, signature, SignAlgorithm.MlDsa65);
console.log('Signature valid:', isValid);

device.close();
cleanup();
```

### Hashing

```typescript
import { initialize, cleanup, openFirstDevice, HashAlgorithm } from '@dyber/quantacore-sdk';

initialize();
const device = openFirstDevice();
const hash = device.hash;

// One-shot hash
const digest = hash.sha256('Hello, World!');
console.log('SHA-256:', digest.toString('hex'));

// Incremental hash
const ctx = hash.createContext(HashAlgorithm.Sha3_256);
ctx.update('Hello, ');
ctx.update('World!');
console.log('SHA3-256:', ctx.finalize().toString('hex'));

// HMAC
const key = Buffer.from('secret');
const mac = hash.hmacSha256(key, 'message');
console.log('HMAC:', mac.toString('hex'));

// HKDF
const derived = hash.hkdfSha256(
  Buffer.from('ikm'),
  Buffer.from('salt'),
  Buffer.from('info'),
  32
);

device.close();
cleanup();
```

### Random Number Generation (QRNG)

```typescript
import { initialize, cleanup, openFirstDevice } from '@dyber/quantacore-sdk';

initialize();
const device = openFirstDevice();
const random = device.random;

// Random bytes
const bytes = random.bytes(32);
console.log('Random bytes:', bytes.toString('hex'));

// Random integers
console.log('Dice roll:', random.int(1, 6));
console.log('Random uint32:', random.uint32());

// Random float
console.log('Random float:', random.float());

// UUID
console.log('UUID:', random.uuid());

// Shuffle array
const items = [1, 2, 3, 4, 5];
random.shuffle(items);
console.log('Shuffled:', items);

device.close();
cleanup();
```

### HSM Key Storage

```typescript
import { initialize, cleanup, openFirstDevice, KeyType, KeyUsage } from '@dyber/quantacore-sdk';

initialize();
const device = openFirstDevice();
const keys = device.keys;

// Store a key
const keyData = Buffer.alloc(32).fill(0x42);
keys.store(0, KeyType.Secret, 0, KeyUsage.Encrypt | KeyUsage.Decrypt, 'my-key', keyData);

// Load the key
const loaded = keys.load(0);
console.log('Key loaded:', loaded.equals(keyData));

// Get key info
const info = keys.getInfo(0);
console.log('Label:', info.label);

// Delete the key
keys.delete(0);

device.close();
cleanup();
```

## API Reference

### Library Functions

- `initialize(flags?)` - Initialize the library
- `cleanup()` - Clean up the library
- `isInitialized()` - Check initialization state
- `getVersion()` - Get library version
- `openFirstDevice()` - Open first available device
- `openDevice(index)` - Open device by index
- `getDeviceCount()` - Get number of devices
- `enumerateDevices()` - List all devices

### Device

- `device.kem` - KEM operations
- `device.sign` - Signature operations
- `device.hash` - Hash operations
- `device.random` - Random number generation
- `device.keys` - HSM key storage
- `device.getInfo()` - Get device information
- `device.getStatus()` - Get device status
- `device.selfTest()` - Run self-test
- `device.close()` - Close device

### Algorithms

| Type | Variants |
|------|----------|
| `KemAlgorithm` | `MlKem512`, `MlKem768`, `MlKem1024` |
| `SignAlgorithm` | `MlDsa44`, `MlDsa65`, `MlDsa87` |
| `HashAlgorithm` | `Sha256`, `Sha384`, `Sha512`, `Sha3_256`, `Sha3_384`, `Sha3_512`, `Shake128`, `Shake256` |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `QUAC100_LIB_PATH` | Path to native library |

## Running Tests

```bash
npm test
npm run test:coverage
```

## Running Examples

```bash
npm run example:basic
npm run example:kem
npm run example:sign
npm run example:hash
npm run example:random
```

## Documentation

- [API Documentation](https://docs.dyber.org/quac100/nodejs)
- [QUAC 100 Hardware Guide](https://docs.dyber.org/quac100)

## License

Copyright © 2024-2025 Dyber, Inc. All rights reserved.

This software is proprietary and confidential. See [LICENSE](LICENSE) for details.

## Support

- Email: support@dyber.org
- Website: https://dyber.org
- GitHub Issues: https://github.com/dyber-pqc/quantacore-sdk/issues