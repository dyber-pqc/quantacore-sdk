# QUAC 100 PKCS#11 Module

A standards-compliant PKCS#11 (Cryptoki) v2.40 interface for the QUAC 100 post-quantum cryptographic accelerator. This module enables hardware-accelerated ML-KEM, ML-DSA, and QRNG operations through the industry-standard PKCS#11 API.

## Overview

The QUAC 100 PKCS#11 module provides:

- **Full PKCS#11 v2.40 Compliance**: All 68 standard functions implemented
- **Post-Quantum Cryptography**: Hardware-accelerated ML-KEM and ML-DSA operations
- **Quantum Random Number Generation**: True entropy from quantum sources
- **HSM-Style Security**: PIN protection, session management, secure key storage
- **Cross-Platform Support**: Linux, macOS, and Windows
- **Software Fallback**: Operates without hardware using OpenSSL simulation

### Supported Algorithms

| Algorithm | Key Sizes | Operations |
|-----------|-----------|------------|
| ML-KEM (Kyber) | 512, 768, 1024 | KeyGen, Encaps, Decaps |
| ML-DSA (Dilithium) | 44, 65, 87 | KeyGen, Sign, Verify |
| QRNG | N/A | Random generation |

### Performance (Hardware Accelerated)

| Operation | Throughput |
|-----------|------------|
| ML-KEM-768 KeyGen | ~500,000 ops/sec |
| ML-KEM-768 Encaps | ~700,000 ops/sec |
| ML-KEM-768 Decaps | ~600,000 ops/sec |
| ML-DSA-65 Sign | ~400,000 ops/sec |
| ML-DSA-65 Verify | ~450,000 ops/sec |
| QRNG | ~100 MB/s |

## Quick Start

### Prerequisites

- C compiler (GCC, Clang, or MSVC)
- OpenSSL 1.1+ development files
- CMake 3.16+ (optional, for CMake builds)
- QUAC 100 SDK (optional, for hardware acceleration)

### Building

**Using Make (Linux/macOS):**

```bash
cd integrations/pkcs11
make
```

**Using CMake:**

```bash
cd integrations/pkcs11
mkdir build && cd build
cmake ..
cmake --build .
```

**With Hardware Support:**

```bash
make QUAC_SDK_PATH=/opt/quac-sdk
# or
cmake -DQUAC_SDK_PATH=/opt/quac-sdk ..
```

### Testing

```bash
make test
./test_quac100_pkcs11
```

### Installation

```bash
sudo make install PREFIX=/usr/local
```

## Usage

### Loading the Module

```c
#include "quac100_pkcs11.h"

int main() {
    CK_FUNCTION_LIST_PTR funcs;
    CK_RV rv;
    
    // Get function list
    rv = C_GetFunctionList(&funcs);
    if (rv != CKR_OK) return 1;
    
    // Initialize library
    rv = funcs->C_Initialize(NULL);
    if (rv != CKR_OK) return 1;
    
    // ... use PKCS#11 functions ...
    
    // Cleanup
    funcs->C_Finalize(NULL);
    return 0;
}
```

### Dynamic Loading

```c
#include <dlfcn.h>
#include "quac100_pkcs11.h"

int main() {
    void *handle = dlopen("libquac100_pkcs11.so", RTLD_NOW);
    if (!handle) return 1;
    
    CK_C_GetFunctionList pGetFunctionList = 
        (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
    
    CK_FUNCTION_LIST_PTR funcs;
    pGetFunctionList(&funcs);
    
    funcs->C_Initialize(NULL);
    // ... use PKCS#11 functions ...
    funcs->C_Finalize(NULL);
    
    dlclose(handle);
    return 0;
}
```

### ML-KEM Key Exchange

```c
CK_SESSION_HANDLE hSession;
CK_OBJECT_HANDLE hPubKey, hPrivKey;
CK_MECHANISM mech = { CKM_ML_KEM_768_KEY_PAIR_GEN, NULL, 0 };

// Key attributes
CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
CK_KEY_TYPE keyType = CKK_ML_KEM_768;
CK_BBOOL bTrue = CK_TRUE;

CK_ATTRIBUTE pubTemplate[] = {
    { CKA_CLASS, &pubClass, sizeof(pubClass) },
    { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
    { CKA_DERIVE, &bTrue, sizeof(bTrue) },
};

CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;

CK_ATTRIBUTE privTemplate[] = {
    { CKA_CLASS, &privClass, sizeof(privClass) },
    { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
    { CKA_DERIVE, &bTrue, sizeof(bTrue) },
};

// Generate keypair
C_GenerateKeyPair(hSession, &mech,
                  pubTemplate, 3, privTemplate, 3,
                  &hPubKey, &hPrivKey);

// Get public key for distribution
CK_BYTE pubKeyValue[1184];
CK_ATTRIBUTE getPub = { CKA_VALUE, pubKeyValue, sizeof(pubKeyValue) };
C_GetAttributeValue(hSession, hPubKey, &getPub, 1);
```

### ML-DSA Digital Signatures

```c
CK_SESSION_HANDLE hSession;
CK_OBJECT_HANDLE hPubKey, hPrivKey;

// Generate ML-DSA-65 keypair
CK_MECHANISM keygenMech = { CKM_ML_DSA_65_KEY_PAIR_GEN, NULL, 0 };
CK_MECHANISM signMech = { CKM_ML_DSA_65, NULL, 0 };

// ... setup templates ...

C_GenerateKeyPair(hSession, &keygenMech,
                  pubTemplate, pubCount, privTemplate, privCount,
                  &hPubKey, &hPrivKey);

// Sign data
CK_BYTE data[] = "Message to sign";
CK_BYTE signature[3309];  // ML-DSA-65 signature size
CK_ULONG sigLen = sizeof(signature);

C_SignInit(hSession, &signMech, hPrivKey);
C_Sign(hSession, data, sizeof(data) - 1, signature, &sigLen);

// Verify signature
C_VerifyInit(hSession, &signMech, hPubKey);
CK_RV rv = C_Verify(hSession, data, sizeof(data) - 1, signature, sigLen);
if (rv == CKR_OK) {
    printf("Signature valid!\n");
}
```

### Random Number Generation

```c
CK_SESSION_HANDLE hSession;
CK_BYTE random[32];

// Generate random bytes
C_GenerateRandom(hSession, random, sizeof(random));

// Optional: add application entropy
CK_BYTE seed[] = "additional entropy";
C_SeedRandom(hSession, seed, sizeof(seed) - 1);
```

## Integration with Applications

### OpenSSL Engine

The module can be used alongside the OpenSSL engine for applications that support PKCS#11:

```bash
# Use with pkcs11-tool (OpenSC)
pkcs11-tool --module libquac100_pkcs11.so --list-mechanisms

# Generate keypair
pkcs11-tool --module libquac100_pkcs11.so --keypairgen \
    --key-type ML-KEM-768 --label "my-key"
```

### Firefox/NSS

1. Open Firefox Settings → Privacy & Security → Security Devices
2. Click "Load"
3. Browse to `libquac100_pkcs11.so` (or `.dll` on Windows)
4. Enter name: "QUAC 100 PQC Module"

### Java (SunPKCS11)

```java
// pkcs11.cfg
name = QUAC100
library = /usr/local/lib/libquac100_pkcs11.so

// Java code
Provider provider = Security.getProvider("SunPKCS11");
provider = provider.configure("/path/to/pkcs11.cfg");
Security.addProvider(provider);

KeyStore ks = KeyStore.getInstance("PKCS11", provider);
ks.load(null, pin);
```

### Python (PyKCS11)

```python
import PyKCS11

lib = PyKCS11.PyKCS11Lib()
lib.load('/usr/local/lib/libquac100_pkcs11.so')

# Get slot list
slots = lib.getSlotList(tokenPresent=True)
session = lib.openSession(slots[0], PyKCS11.CKF_SERIAL_SESSION)

# Generate random
random_data = session.generateRandom(32)
```

## API Reference

### Mechanism Types

| Mechanism | Type | Description |
|-----------|------|-------------|
| `CKM_ML_KEM_512_KEY_PAIR_GEN` | 0x80000401 | ML-KEM-512 key generation |
| `CKM_ML_KEM_768_KEY_PAIR_GEN` | 0x80000402 | ML-KEM-768 key generation |
| `CKM_ML_KEM_1024_KEY_PAIR_GEN` | 0x80000403 | ML-KEM-1024 key generation |
| `CKM_ML_KEM_512_ENCAPS` | 0x80000411 | ML-KEM-512 encapsulation |
| `CKM_ML_KEM_768_ENCAPS` | 0x80000412 | ML-KEM-768 encapsulation |
| `CKM_ML_KEM_1024_ENCAPS` | 0x80000413 | ML-KEM-1024 encapsulation |
| `CKM_ML_KEM_512_DECAPS` | 0x80000421 | ML-KEM-512 decapsulation |
| `CKM_ML_KEM_768_DECAPS` | 0x80000422 | ML-KEM-768 decapsulation |
| `CKM_ML_KEM_1024_DECAPS` | 0x80000423 | ML-KEM-1024 decapsulation |
| `CKM_ML_DSA_44_KEY_PAIR_GEN` | 0x80000501 | ML-DSA-44 key generation |
| `CKM_ML_DSA_65_KEY_PAIR_GEN` | 0x80000502 | ML-DSA-65 key generation |
| `CKM_ML_DSA_87_KEY_PAIR_GEN` | 0x80000503 | ML-DSA-87 key generation |
| `CKM_ML_DSA_44` | 0x80000511 | ML-DSA-44 sign/verify |
| `CKM_ML_DSA_65` | 0x80000512 | ML-DSA-65 sign/verify |
| `CKM_ML_DSA_87` | 0x80000513 | ML-DSA-87 sign/verify |
| `CKM_QUAC_QRNG` | 0x80000601 | QRNG random generation |

### Key Types

| Key Type | Value | Description |
|----------|-------|-------------|
| `CKK_ML_KEM_512` | 0x80000041 | ML-KEM-512 keys |
| `CKK_ML_KEM_768` | 0x80000042 | ML-KEM-768 keys |
| `CKK_ML_KEM_1024` | 0x80000043 | ML-KEM-1024 keys |
| `CKK_ML_DSA_44` | 0x80000051 | ML-DSA-44 keys |
| `CKK_ML_DSA_65` | 0x80000052 | ML-DSA-65 keys |
| `CKK_ML_DSA_87` | 0x80000053 | ML-DSA-87 keys |

### Key Sizes

| Algorithm | Public Key | Secret Key | Ciphertext/Signature |
|-----------|------------|------------|----------------------|
| ML-KEM-512 | 800 | 1,632 | 768 |
| ML-KEM-768 | 1,184 | 2,400 | 1,088 |
| ML-KEM-1024 | 1,568 | 3,168 | 1,568 |
| ML-DSA-44 | 1,312 | 2,560 | 2,420 |
| ML-DSA-65 | 1,952 | 4,032 | 3,309 |
| ML-DSA-87 | 2,592 | 4,896 | 4,627 |

## Building for Windows

### Visual Studio Command Line

```batch
set OPENSSL_ROOT=C:\OpenSSL-Win64
cl /LD /O2 /MD /DNDEBUG ^
   /I%OPENSSL_ROOT%\include ^
   /DEF:quac100_pkcs11.def ^
   quac100_pkcs11.c quac100_pkcs11_slot.c quac100_pkcs11_session.c ^
   quac100_pkcs11_object.c quac100_pkcs11_crypto.c ^
   /link /LIBPATH:%OPENSSL_ROOT%\lib\VC\x64\MD libcrypto.lib
```

### CMake with Visual Studio

```batch
mkdir build
cd build
cmake -G "Visual Studio 17 2022" ^
      -DOPENSSL_ROOT_DIR=C:\OpenSSL-Win64 ..
cmake --build . --config Release
```

## Troubleshooting

### Common Issues

**"CKR_TOKEN_NOT_PRESENT"**
- Ensure QUAC 100 hardware is connected and drivers installed
- Module will use software fallback if hardware unavailable

**"CKR_MECHANISM_INVALID"**
- Check mechanism type matches key type
- Use ML-DSA mechanisms with ML-DSA keys, ML-KEM with ML-KEM keys

**"CKR_SIGNATURE_INVALID"**
- Verify data hasn't been modified between sign and verify
- Ensure correct public key is used for verification

**OpenSSL linking errors**
- Install OpenSSL development packages
- Set `OPENSSL_ROOT_DIR` or use pkg-config

### Debug Build

```bash
make DEBUG=1
# or
cmake -DCMAKE_BUILD_TYPE=Debug ..
```

### Logging

Set environment variable for debug output:
```bash
export QUAC_PKCS11_DEBUG=1
./your_application
```

## Files

| File | Description |
|------|-------------|
| `quac100_pkcs11.h` | Public PKCS#11 API header |
| `quac100_pkcs11_internal.h` | Internal structures and definitions |
| `quac100_pkcs11.c` | Core PKCS#11 implementation |
| `quac100_pkcs11_slot.c` | Slot and token management |
| `quac100_pkcs11_session.c` | Session management |
| `quac100_pkcs11_object.c` | Object management |
| `quac100_pkcs11_crypto.c` | Cryptographic operations |
| `quac100_pkcs11.def` | Windows DLL export definitions |
| `CMakeLists.txt` | CMake build configuration |
| `Makefile` | Make build configuration |
| `test_quac100_pkcs11.c` | Test suite |
| `example_pkcs11.c` | Usage examples |
| `bench_pkcs11.c` | Performance benchmark |

## License

Copyright 2025 Dyber, Inc. All Rights Reserved.

## Support

- Documentation: https://docs.dyber.io/quac100/pkcs11
- Issues: https://github.com/dyber/quac100-sdk/issues
- Email: support@dyber.io

## See Also

- [QUAC 100 Hardware Documentation](../../docs/hardware/)
- [QuantaCore SDK Overview](../../README.md)
- [OpenSSL Engine Integration](../openssl/)
- [PKCS#11 Specification](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html)