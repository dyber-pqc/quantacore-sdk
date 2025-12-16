# QUAC 100 C++ Samples

This directory contains C++ sample applications demonstrating how to use the QUAC 100 Windows driver and library.

## Samples Overview

| Sample | Description |
|--------|-------------|
| [basic_usage.cpp](basic_usage.cpp) | Basic device operations - KEM, signatures, QRNG |
| [async_operations.cpp](async_operations.cpp) | Async/concurrent operations for high throughput |
| [secure_channel.cpp](secure_channel.cpp) | Post-quantum secure channel establishment |

## Prerequisites

- QUAC 100 driver installed and device present (or simulator running)
- Visual Studio 2022 with C++17 support
- quac100.lib and quac100.dll in path

## Building

### Using Visual Studio

1. Open the parent solution (`quac100.sln`)
2. Build the `quac100lib` project first
3. Build the sample you want to run

### Using Command Line

```powershell
# From the samples\cpp directory
cl /std:c++17 /EHsc /I..\..\include /I..\..\lib\quac100lib basic_usage.cpp /link quac100.lib bcrypt.lib
```

## Sample Details

### basic_usage.cpp

Demonstrates fundamental QUAC 100 operations:

- **Device Management**: Opening/closing device handles
- **KEM Operations**: Key generation, encapsulation, decapsulation
- **Signature Operations**: Key generation, signing, verification
- **QRNG**: Quantum random number generation
- **Device Info**: Retrieving version, capabilities, health

```cpp
// Quick example
Quac100Device device;  // RAII wrapper

// Generate a Kyber-768 key pair
std::vector<uint8_t> pk(KYBER768_PUBLIC_KEY_SIZE);
std::vector<uint8_t> sk(KYBER768_SECRET_KEY_SIZE);
Quac100_KemKeyGen(device, QUAC_KEM_KYBER768, pk.data(), sk.data());

// Generate quantum random bytes
std::vector<uint8_t> random(64);
Quac100_Random(device, random.data(), 64, QUAC_RNG_QUALITY_HIGH);
```

### async_operations.cpp

Demonstrates high-throughput async patterns:

- **AsyncJobManager**: Class for managing async operations
- **Batch Processing**: Submit many operations and wait for completion
- **Producer-Consumer**: Thread-safe pattern with QRNG

```cpp
// Submit async jobs
AsyncJobManager jobs(device, 4);  // 4 worker threads

for (int i = 0; i < 1000; i++) {
    jobs.SubmitKemKeyGen(QUAC_KEM_KYBER768, pk[i], sk[i],
        [](uint64_t id, QUAC_STATUS status, void* result) {
            // Completion callback
        });
}
```

### secure_channel.cpp

Demonstrates a complete post-quantum secure channel:

- **Identity Keys**: Long-term ML-DSA keys for authentication
- **Key Exchange**: ML-KEM ephemeral key exchange
- **Session Encryption**: AES-GCM with derived session key
- **Mutual Authentication**: Both parties verify signatures

Protocol flow:
```
Alice                                    Bob
  |                                       |
  |  1. Generate ephemeral KEM keypair    |
  |  2. Sign ephemeral public key         |
  |  ---- ephemeral_pk + signature -----> |
  |                                       |
  |  3. Verify Alice's signature          |
  |  4. Encapsulate shared secret         |
  |  5. Sign ciphertext                   |
  |  <---- ciphertext + signature ------  |
  |                                       |
  |  6. Verify Bob's signature            |
  |  7. Decapsulate shared secret         |
  |                                       |
  |  [Both now have same session key]     |
  |                                       |
  |  <==== Encrypted messages =========>  |
```

## Error Handling

All samples use exception-based error handling:

```cpp
try {
    Quac100Device device;
    // ... operations ...
} catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << std::endl;
    return 1;
}
```

In production code, check return values:

```cpp
QUAC_STATUS status = Quac100_KemKeyGen(...);
if (status != QUAC_SUCCESS) {
    // Handle error
    const char* errMsg = Quac100_GetErrorString(status);
}
```

## Security Notes

1. **Key Zeroization**: Always clear secret keys after use
   ```cpp
   SecureZeroMemory(secretKey.data(), secretKey.size());
   ```

2. **Random Quality**: Use `QUAC_RNG_QUALITY_HIGH` for cryptographic purposes

3. **Signature Context**: Use context strings to bind signatures to purposes
   ```cpp
   Quac100_Sign(..., context, contextLen, ...);
   ```

4. **Error Checking**: Always verify signatures and check return codes

## Performance Tips

1. **Async Operations**: Use async API for high throughput
2. **Batch Processing**: Group operations to amortize overhead
3. **Thread Pools**: Use multiple threads for parallel operations
4. **Buffer Reuse**: Pre-allocate buffers to avoid allocation overhead

## Related Documentation

- [IOCTL Reference](../../docs/ioctl_reference.md)
- [API Reference](../../lib/quac100lib/quac100lib.h)
- [Building Guide](../../docs/building.md)

---

Copyright © 2025 Dyber, Inc. All Rights Reserved.
