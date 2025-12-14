# QUAC 100 C++ SDK

Modern C++17 SDK for the QUAC 100 Post-Quantum Cryptographic Accelerator.

## Features

- ✅ **Modern C++17** - RAII resource management, exceptions, smart pointers
- ✅ **Type-safe** - Strong typing with enums and structured error handling
- ✅ **STL Integration** - Works with standard containers and algorithms
- ✅ **High Performance** - Thin wrapper over C library with minimal overhead
- ✅ **Comprehensive** - Full access to all QUAC 100 features

## Requirements

- C++17 compiler (GCC 8+, Clang 7+, MSVC 2019+)
- CMake 3.16+
- QUAC 100 C library (quac100)

## Quick Start

```cpp
#include <quac100/quac100.hpp>
#include <iostream>

int main() {
    // Initialize library (RAII)
    quac100::Library lib;
    
    // Open device
    auto device = lib.openFirstDevice();
    
    // Generate ML-KEM-768 key pair
    auto aliceKeys = device.kem().generateKeyPair(quac100::KemAlgorithm::ML_KEM_768);
    
    // Encapsulate (sender)
    auto bobResult = device.kem().encapsulate(
        quac100::KemAlgorithm::ML_KEM_768, 
        aliceKeys.publicKey);
    
    // Decapsulate (receiver)
    auto aliceSecret = device.kem().decapsulate(
        quac100::KemAlgorithm::ML_KEM_768,
        aliceKeys.secretKey, 
        bobResult.ciphertext);
    
    // Shared secrets match!
    assert(bobResult.sharedSecret == aliceSecret);
    
    std::cout << "Key exchange successful!\n";
    return 0;
}
```

## Building

### Windows (MSVC)

```powershell
# Create build directory
mkdir build
cd build

# Configure
cmake .. -G "Visual Studio 17 2022" -A x64

# Build
cmake --build . --config Release

# Run examples
.\Release\cpp_basic_example.exe
.\Release\cpp_kem_example.exe
.\Release\cpp_sign_example.exe
.\Release\cpp_hash_example.exe
.\Release\cpp_random_example.exe
```

### Linux/macOS

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Run examples
./cpp_basic_example
./cpp_kem_example
```

## Installation

```bash
cmake --install . --prefix /usr/local
```

## API Overview

### Library Initialization

```cpp
// RAII initialization
quac100::Library lib;

// With flags
quac100::Library lib(quac100::FLAG_VERBOSE);

// Version info
std::cout << quac100::Library::version() << std::endl;
std::cout << quac100::Library::buildInfo() << std::endl;
```

### Device Management

```cpp
// Enumerate devices
auto devices = lib.enumerateDevices();
for (const auto& info : devices) {
    std::cout << "Device " << info.index << ": " << info.modelName << std::endl;
    std::cout << "  Serial: " << info.serialNumber << std::endl;
    std::cout << "  Firmware: " << info.firmwareVersion << std::endl;
}

// Open device
auto device = lib.openFirstDevice();
auto device = lib.openDevice(0);

// Device status
auto status = device.status();
std::cout << "Temperature: " << status.temperature << " C" << std::endl;
std::cout << "Entropy: " << status.entropyLevel << "%" << std::endl;
std::cout << "Health: " << (status.isHealthy ? "OK" : "WARNING") << std::endl;

// Self-test
device.selfTest();
```

### Key Encapsulation (ML-KEM/Kyber)

```cpp
// Get algorithm parameters
auto params = device.kem().getParams(quac100::KemAlgorithm::ML_KEM_768);
std::cout << "Public Key Size: " << params.publicKeySize << " bytes" << std::endl;
std::cout << "Ciphertext Size: " << params.ciphertextSize << " bytes" << std::endl;
std::cout << "Security Level: " << params.securityLevel << std::endl;

// Generate key pair
auto keys = device.kem().generateKeyPair(quac100::KemAlgorithm::ML_KEM_768);
// keys.publicKey, keys.secretKey

// Encapsulate (create shared secret)
auto result = device.kem().encapsulate(
    quac100::KemAlgorithm::ML_KEM_768, 
    keys.publicKey);
// result.ciphertext, result.sharedSecret

// Decapsulate (recover shared secret)
auto secret = device.kem().decapsulate(
    quac100::KemAlgorithm::ML_KEM_768,
    keys.secretKey, 
    result.ciphertext);

// Available algorithms
quac100::KemAlgorithm::ML_KEM_512   // NIST Level 1
quac100::KemAlgorithm::ML_KEM_768   // NIST Level 3 (recommended)
quac100::KemAlgorithm::ML_KEM_1024  // NIST Level 5
```

### Digital Signatures (ML-DSA/Dilithium)

```cpp
// Get algorithm parameters
auto params = device.sign().getParams(quac100::SignAlgorithm::ML_DSA_65);
std::cout << "Signature Size: " << params.signatureSize << " bytes" << std::endl;

// Generate signing key pair
auto keys = device.sign().generateKeyPair(quac100::SignAlgorithm::ML_DSA_65);

// Sign message
std::string message = "Important document";
quac100::Bytes msgBytes(message.begin(), message.end());
auto signature = device.sign().sign(
    quac100::SignAlgorithm::ML_DSA_65,
    keys.secretKey, 
    msgBytes);

// Verify signature
bool valid = device.sign().verify(
    quac100::SignAlgorithm::ML_DSA_65,
    keys.publicKey, 
    msgBytes, 
    signature);

// Verification with exception on failure
try {
    device.sign().verify(alg, publicKey, message, signature);
    std::cout << "Signature valid!" << std::endl;
} catch (const quac100::VerificationException& e) {
    std::cout << "Invalid signature!" << std::endl;
}

// Available algorithms
quac100::SignAlgorithm::ML_DSA_44  // NIST Level 2
quac100::SignAlgorithm::ML_DSA_65  // NIST Level 3 (recommended)
quac100::SignAlgorithm::ML_DSA_87  // NIST Level 5
```

### Random Number Generation (QRNG)

```cpp
// Check entropy status
auto entropy = device.random().entropyStatus();
std::cout << "Entropy Level: " << entropy.level << "%" << std::endl;
std::cout << "Health: " << (entropy.healthOk ? "OK" : "WARNING") << std::endl;

// Random bytes
auto bytes = device.random().bytes(32);

// Random integers
uint32_t val32 = device.random().uint32();
uint64_t val64 = device.random().uint64();
uint32_t inRange = device.random().range(100);      // [0, 100)
uint32_t inRange = device.random().range(10, 20);   // [10, 20)

// Random floating point
double d = device.random().uniform();  // [0.0, 1.0)

// UUID generation
std::string uuid = device.random().uuid();
// e.g., "550e8400-e29b-41d4-a716-446655440000"
```

### Hash Functions

```cpp
// SHA-2 family
auto sha256 = device.hash().sha256(data);
auto sha384 = device.hash().sha384(data);
auto sha512 = device.hash().sha512(data);

// SHA-3 family
auto sha3_256 = device.hash().sha3_256(data);
auto sha3_512 = device.hash().sha3_512(data);

// SHAKE (variable output length)
auto shake128 = device.hash().shake128(data, 64);  // 64 bytes output
auto shake256 = device.hash().shake256(data, 128); // 128 bytes output

// Incremental hashing
auto ctx = device.hash().createContext(quac100::HashAlgorithm::SHA256);
ctx.update(chunk1);
ctx.update(chunk2);
ctx.update(chunk3);
auto hash = ctx.finalize();

// HMAC
auto hmac = device.hash().hmac(quac100::HashAlgorithm::SHA256, key, data);

// HKDF key derivation
auto derivedKey = device.hash().hkdf(
    quac100::HashAlgorithm::SHA256,
    inputKeyMaterial,
    salt,
    info,
    32);  // output length
```

### HSM Key Storage

```cpp
// Store a key
device.keys().store(
    0,                              // slot
    "my-signing-key",               // label
    quac100::KeyType::SECRET,       // type
    static_cast<int>(quac100::SignAlgorithm::ML_DSA_65),
    keyData,                        // key bytes
    quac100::KeyUsage::SIGN,        // usage
    false);                         // not exportable

// Find key by label
int slot = device.keys().findByLabel("my-signing-key");
if (slot >= 0) {
    auto info = device.keys().getInfo(slot);
    std::cout << "Found key: " << info.label << std::endl;
}

// List all keys
auto allKeys = device.keys().list();
for (const auto& key : allKeys) {
    std::cout << "Slot " << key.slot << ": " << key.label << std::endl;
}

// Delete key
device.keys().remove(0);
```

### Utilities

```cpp
// Hex encoding
std::string hex = quac100::utils::toHex(data);
auto bytes = quac100::utils::fromHex("deadbeef");

// Base64 encoding
std::string b64 = quac100::utils::toBase64(data);
auto bytes = quac100::utils::fromBase64(b64);

// Secure memory operations
quac100::utils::secureZero(sensitiveBuffer);
bool equal = quac100::utils::secureCompare(a, b);

// Timing
auto start = std::chrono::high_resolution_clock::now();
// ... operations ...
auto end = std::chrono::high_resolution_clock::now();
double ms = std::chrono::duration<double, std::milli>(end - start).count();
```

## Exception Handling

All errors throw `quac100::Exception` or derived types:

```cpp
try {
    auto device = lib.openFirstDevice();
    auto keys = device.kem().generateKeyPair(quac100::KemAlgorithm::ML_KEM_768);
} catch (const quac100::DeviceException& e) {
    std::cerr << "Device error: " << e.what() << std::endl;
} catch (const quac100::CryptoException& e) {
    std::cerr << "Crypto error: " << e.what() << std::endl;
} catch (const quac100::VerificationException& e) {
    std::cerr << "Verification failed: " << e.what() << std::endl;
} catch (const quac100::Exception& e) {
    std::cerr << "Error [" << e.codeInt() << "]: " << e.what() << std::endl;
}
```

## CMake Integration

### Using find_package

```cmake
find_package(quac100pp REQUIRED)
target_link_libraries(myapp PRIVATE quac100pp::quac100pp)
```

### Using FetchContent

```cmake
include(FetchContent)
FetchContent_Declare(quac100pp
    GIT_REPOSITORY https://github.com/dyber-pqc-quantacore-sdk.git
    GIT_TAG v1.0.0
    SOURCE_SUBDIR bindings/c++)
FetchContent_MakeAvailable(quac100pp)
target_link_libraries(myapp PRIVATE quac100pp)
```

### Using add_subdirectory

```cmake
add_subdirectory(path/to/quantacore-sdk/bindings/c++)
target_link_libraries(myapp PRIVATE quac100pp)
```

## Directory Structure

```
c++/
├── include/
│   └── quac100/
│       ├── quac100.hpp      # Main header (includes all)
│       ├── types.hpp        # Type definitions
│       ├── exception.hpp    # Exception classes
│       ├── device.hpp       # Device management
│       ├── kem.hpp          # KEM operations
│       ├── sign.hpp         # Signature operations
│       ├── random.hpp       # Random generation
│       ├── hash.hpp         # Hash functions
│       ├── keys.hpp         # HSM key storage
│       └── utils.hpp        # Utilities
├── src/
│   ├── quac100.cpp
│   ├── device.cpp
│   ├── kem.cpp
│   ├── sign.cpp
│   ├── random.cpp
│   ├── hash.cpp
│   ├── keys.cpp
│   └── utils.cpp
├── examples/
│   ├── basic_example.cpp    # Library init, device info
│   ├── kem_example.cpp      # Key encapsulation
│   ├── sign_example.cpp     # Digital signatures
│   ├── hash_example.cpp     # Hash functions
│   └── random_example.cpp   # Random generation
├── tests/
│   └── test_quac100pp.cpp
├── cmake/
│   └── quac100ppConfig.cmake.in
├── CMakeLists.txt
└── README.md
```

## Performance

Benchmark results from example programs (simulated hardware):

| Operation | Performance |
|-----------|-------------|
| ML-KEM-768 KeyGen | ~978,000 ops/sec |
| ML-KEM-768 Encaps | ~1,740,000 ops/sec |
| ML-KEM-768 Decaps | ~8,150,000 ops/sec |
| ML-DSA-65 Sign | ~904,000 ops/sec |
| ML-DSA-65 Verify | ~4,184,000 ops/sec |
| SHA-256 (1KB) | ~513 MB/sec |
| SHA3-256 (1KB) | ~506 MB/sec |
| QRNG Throughput | ~2,192 MB/sec |

## Thread Safety

- Library initialization is NOT thread-safe (call once at startup)
- Device operations are thread-safe (one device handle per thread recommended)
- Hash contexts are NOT thread-safe (create one per thread)
- Random operations are thread-safe

## Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `QUAC_BUILD_EXAMPLES` | ON | Build example programs |
| `QUAC_BUILD_TESTS` | OFF | Build test suite |
| `QUAC_BUILD_SHARED` | ON | Build shared library (.dll/.so) |
| `QUAC_BUILD_STATIC` | ON | Build static library (.lib/.a) |

```bash
cmake .. -DQUAC_BUILD_TESTS=ON -DQUAC_BUILD_EXAMPLES=OFF
```

## Troubleshooting

### Windows: Program runs but no output

The C library DLL (`quac100.dll`) must be in the same directory as the executable or in the system PATH. The CMake build automatically copies this DLL to the output directory.

### Linux: Library not found

```bash
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
# or
sudo ldconfig
```

### CMake can't find C library

Ensure the C library is built first:
```bash
cd ../c
mkdir build && cd build
cmake .. && make
```

## License

Copyright © 2025 Dyber, Inc. All Rights Reserved.

## Support

- Documentation: https://docs.dyber.io/quac100
- GitHub: https://github.com/dyber-pqc-quantacore-sdk
- Issues: https://github.com/dyber-pqc-quantacore-sdk/issues
- Email: support@dyber.io