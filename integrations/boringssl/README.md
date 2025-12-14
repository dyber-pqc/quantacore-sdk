# QUAC 100 BoringSSL Integration

Post-quantum cryptographic acceleration for BoringSSL applications using the QUAC 100 hardware accelerator.

## Overview

This integration provides ML-KEM (FIPS 203) key encapsulation and ML-DSA (FIPS 204) digital signatures for applications using BoringSSL. Unlike OpenSSL 3.x's provider model, BoringSSL uses direct API integration, requiring applications to call QUAC functions explicitly or link against a modified BoringSSL build.

### Features

- **ML-KEM Key Encapsulation**: ML-KEM-512, ML-KEM-768, ML-KEM-1024
- **ML-DSA Digital Signatures**: ML-DSA-44, ML-DSA-65, ML-DSA-87
- **Quantum Random Numbers**: Hardware QRNG with 1 Gbps throughput
- **TLS 1.3 Hybrid Key Exchange**: X25519_ML-KEM-768, P-384_ML-KEM-1024
- **ASN.1 Encoding**: DER/PEM for SubjectPublicKeyInfo and PKCS#8
- **Hardware Acceleration**: 1.4M+ ops/sec with QUAC 100 hardware
- **Software Fallback**: Simulator mode when hardware unavailable

### Performance

| Algorithm | Operation | Software | Hardware |
|-----------|-----------|----------|----------|
| ML-KEM-768 | Keygen | ~10K ops/s | ~500K ops/s |
| ML-KEM-768 | Encaps | ~15K ops/s | ~700K ops/s |
| ML-KEM-768 | Decaps | ~12K ops/s | ~600K ops/s |
| ML-DSA-65 | Sign | ~5K ops/s | ~200K ops/s |
| ML-DSA-65 | Verify | ~8K ops/s | ~300K ops/s |
| QRNG | Generate | ~50 MB/s | ~125 MB/s |

## Files

```
integrations/boringssl/
├── quac100_boringssl.h    # Public header with all API declarations
├── quac100_boringssl.c    # Core initialization and utilities
├── quac100_kem.c          # ML-KEM implementation
├── quac100_sig.c          # ML-DSA implementation
├── quac100_rand.c         # QRNG with health tests
├── quac100_evp.c          # EVP_PKEY integration layer
├── quac100_tls.c          # TLS 1.3 hybrid key exchange
├── quac100_asn1.c         # ASN.1/DER/PEM encoding using CBS/CBB
└── README.md              # This file
```

## Building

### Prerequisites

- BoringSSL (latest from https://boringssl.googlesource.com/boringssl)
- CMake 3.16+
- C11 compiler (GCC 9+, Clang 10+, MSVC 2019+)
- Optional: QUAC 100 SDK for hardware acceleration

### Build Commands

```bash
# Clone BoringSSL if needed
git clone https://boringssl.googlesource.com/boringssl
cd boringssl && mkdir build && cd build
cmake .. && make -j$(nproc)
cd ../..

# Build QUAC integration
mkdir build && cd build
cmake .. \
    -DBORINGSSL_ROOT=/path/to/boringssl \
    -DQUAC_SDK_PATH=/opt/quantacore-sdk  # Optional
make -j$(nproc)

# Install
sudo make install
```

### CMakeLists.txt Example

```cmake
cmake_minimum_required(VERSION 3.16)
project(quac100_boringssl C)

set(CMAKE_C_STANDARD 11)

# Find BoringSSL
set(BORINGSSL_ROOT "" CACHE PATH "Path to BoringSSL")
if(NOT BORINGSSL_ROOT)
    message(FATAL_ERROR "Set BORINGSSL_ROOT to BoringSSL directory")
endif()

include_directories(${BORINGSSL_ROOT}/include)
link_directories(${BORINGSSL_ROOT}/build/ssl ${BORINGSSL_ROOT}/build/crypto)

# Optional QUAC SDK
set(QUAC_SDK_PATH "" CACHE PATH "Path to QUAC SDK")
if(QUAC_SDK_PATH)
    add_definitions(-DQUAC_HAS_HARDWARE)
    include_directories(${QUAC_SDK_PATH}/include)
    link_directories(${QUAC_SDK_PATH}/lib)
endif()

# Build library
add_library(quac100_boringssl SHARED
    quac100_boringssl.c
    quac100_kem.c
    quac100_sig.c
    quac100_rand.c
    quac100_evp.c
    quac100_tls.c
    quac100_asn1.c
)

target_link_libraries(quac100_boringssl
    ssl crypto pthread
    $<$<BOOL:${QUAC_SDK_PATH}>:quac100>
)

install(TARGETS quac100_boringssl DESTINATION lib)
install(FILES quac100_boringssl.h DESTINATION include)
```

## API Reference

### Initialization

```c
#include "quac100_boringssl.h"

// Initialize (auto-detect hardware)
int ret = QUAC_init();

// Initialize with options
ret = QUAC_init_ex(
    1,  // use_hardware: 1=require, 0=allow fallback
    0   // device_index: which QUAC device
);

// Check hardware status
if (QUAC_is_hardware_available()) {
    printf("Using QUAC 100 hardware acceleration\n");
}

// Cleanup on exit
QUAC_cleanup();
```

### ML-KEM (Key Encapsulation)

```c
// Key sizes
size_t pk_len = QUAC_KEM_public_key_bytes(QUAC_KEM_ML_KEM_768);  // 1184
size_t sk_len = QUAC_KEM_secret_key_bytes(QUAC_KEM_ML_KEM_768);  // 2400
size_t ct_len = QUAC_KEM_ciphertext_bytes(QUAC_KEM_ML_KEM_768);  // 1088
size_t ss_len = QUAC_KEM_shared_secret_bytes(QUAC_KEM_ML_KEM_768); // 32

// Allocate buffers
uint8_t pk[QUAC_ML_KEM_768_PUBLIC_KEY_BYTES];
uint8_t sk[QUAC_ML_KEM_768_SECRET_KEY_BYTES];
uint8_t ct[QUAC_ML_KEM_768_CIPHERTEXT_BYTES];
uint8_t ss_sender[32], ss_receiver[32];

// Generate keypair
int ret = QUAC_KEM_keypair(QUAC_KEM_ML_KEM_768, pk, sk);

// Sender: encapsulate
ret = QUAC_KEM_encaps(QUAC_KEM_ML_KEM_768, ct, ss_sender, pk);

// Receiver: decapsulate
ret = QUAC_KEM_decaps(QUAC_KEM_ML_KEM_768, ss_receiver, ct, sk);

// ss_sender == ss_receiver (32-byte shared secret)
```

### ML-DSA (Digital Signatures)

```c
// Key sizes
size_t pk_len = QUAC_SIG_public_key_bytes(QUAC_SIG_ML_DSA_65);  // 1952
size_t sk_len = QUAC_SIG_secret_key_bytes(QUAC_SIG_ML_DSA_65);  // 4032
size_t sig_max = QUAC_SIG_signature_bytes(QUAC_SIG_ML_DSA_65);  // 3309

// Allocate buffers
uint8_t pk[QUAC_ML_DSA_65_PUBLIC_KEY_BYTES];
uint8_t sk[QUAC_ML_DSA_65_SECRET_KEY_BYTES];
uint8_t sig[QUAC_ML_DSA_65_SIGNATURE_BYTES];
size_t sig_len;

// Generate keypair
int ret = QUAC_SIG_keypair(QUAC_SIG_ML_DSA_65, pk, sk);

// Sign message
const uint8_t *msg = (uint8_t *)"Hello, Post-Quantum World!";
size_t msg_len = strlen((char *)msg);

ret = QUAC_sign(QUAC_SIG_ML_DSA_65, sig, &sig_len, msg, msg_len, sk);

// Verify signature
ret = QUAC_verify(QUAC_SIG_ML_DSA_65, sig, sig_len, msg, msg_len, pk);
if (ret == QUAC_SUCCESS) {
    printf("Signature valid\n");
} else if (ret == QUAC_ERROR_VERIFICATION_FAILED) {
    printf("Signature invalid\n");
}
```

### QRNG (Random Number Generation)

```c
// Generate random bytes
uint8_t random_data[64];
int ret = QUAC_random_bytes(random_data, sizeof(random_data));

// Add entropy (optional)
uint8_t seed[32] = { /* application entropy */ };
QUAC_random_seed(seed, sizeof(seed));

// Check QRNG health
if (!QUAC_random_health_check()) {
    fprintf(stderr, "QRNG health degraded\n");
}

// High-throughput unbuffered (hardware only)
uint8_t bulk_random[1024 * 1024];  // 1 MB
ret = QUAC_random_bytes_unbuffered(bulk_random, sizeof(bulk_random));
```

### ASN.1 Key Encoding

```c
// Encode public key to DER
uint8_t der[2048];
size_t der_len = sizeof(der);
int ret = QUAC_encode_public_key_der(QUAC_KEM_ML_KEM_768, pk, pk_len, der, &der_len);

// Decode public key from DER
int alg;
uint8_t decoded_pk[QUAC_KEM_MAX_PUBLIC_KEY_BYTES];
size_t decoded_len = sizeof(decoded_pk);
ret = QUAC_decode_public_key_der(der, der_len, &alg, decoded_pk, &decoded_len);

// Encode to PEM
char pem[4096];
size_t pem_len = sizeof(pem);
ret = QUAC_encode_public_key_pem(QUAC_KEM_ML_KEM_768, pk, pk_len, pem, &pem_len);
// Output: -----BEGIN ML-KEM PUBLIC KEY-----\n<base64>\n-----END ML-KEM PUBLIC KEY-----

// Private keys (PKCS#8)
ret = QUAC_encode_private_key_der(QUAC_SIG_ML_DSA_65, sk, sk_len, der, &der_len);
ret = QUAC_encode_private_key_pem(QUAC_SIG_ML_DSA_65, sk, sk_len, pem, &pem_len);
```

### TLS 1.3 Hybrid Key Exchange

```c
// Create hybrid context
QUAC_HYBRID_CTX *ctx = QUAC_hybrid_ctx_new(QUAC_GROUP_X25519_ML_KEM_768);

// Generate keypair (client or server)
int ret = QUAC_hybrid_generate_keypair(ctx);

// Get public key to send to peer
uint8_t my_public[2048];
size_t my_public_len = sizeof(my_public);
ret = QUAC_hybrid_get_public_key(ctx, my_public, &my_public_len);

// Set peer's public key
ret = QUAC_hybrid_set_peer_public_key(ctx, peer_public, peer_public_len);

// Derive shared secret
uint8_t shared_secret[64];
size_t ss_len = sizeof(shared_secret);
ret = QUAC_hybrid_derive(ctx, shared_secret, &ss_len);
// ss_len = 64 (32 from X25519 + 32 from ML-KEM-768)

// Cleanup
QUAC_hybrid_ctx_free(ctx);
```

### Self-Test (FIPS Compliance)

```c
// Run all self-tests
int ret = QUAC_self_test();
if (ret != QUAC_SUCCESS) {
    fprintf(stderr, "Self-test failed: %s\n", QUAC_get_error_string(ret));
    exit(1);
}

// Verify module integrity
ret = QUAC_integrity_check();
```

### Benchmarking

```c
quac_benchmark_result_t results[10];
size_t result_count = 10;

int ret = QUAC_benchmark(QUAC_KEM_ML_KEM_768, 3, results, &result_count);

for (size_t i = 0; i < result_count; i++) {
    printf("%s %s: %.0f ops/sec (%.2f µs/op)\n",
           results[i].algorithm,
           results[i].operation,
           results[i].ops_per_second,
           results[i].microseconds_per_op);
}
```

## Integration Patterns

### Pattern 1: Direct API Usage

The simplest approach - call QUAC functions directly in your application:

```c
#include "quac100_boringssl.h"

int main() {
    QUAC_init();
    
    // Use QUAC functions for PQC operations
    uint8_t pk[QUAC_ML_KEM_768_PUBLIC_KEY_BYTES];
    uint8_t sk[QUAC_ML_KEM_768_SECRET_KEY_BYTES];
    QUAC_KEM_keypair(QUAC_KEM_ML_KEM_768, pk, sk);
    
    // Use BoringSSL for classical operations
    // ...
    
    QUAC_cleanup();
    return 0;
}
```

### Pattern 2: Wrapper Functions

Create wrapper functions that match your application's conventions:

```c
// my_crypto.h
typedef struct {
    int type;  // 0=classical, 1=PQC
    union {
        EVP_PKEY *classical;
        struct {
            int alg;
            uint8_t *pk;
            uint8_t *sk;
        } pqc;
    };
} MY_KEYPAIR;

MY_KEYPAIR *my_generate_keypair(const char *algorithm);
int my_sign(MY_KEYPAIR *key, const uint8_t *msg, size_t len, uint8_t *sig, size_t *sig_len);
int my_verify(MY_KEYPAIR *key, const uint8_t *msg, size_t len, const uint8_t *sig, size_t sig_len);
```

### Pattern 3: Modified BoringSSL Build

For transparent integration, patch BoringSSL to call QUAC functions. Key files to modify:

1. `crypto/evp/evp.c` - Add ML-KEM/ML-DSA to EVP_PKEY types
2. `ssl/ssl_key_share.cc` - Add hybrid groups
3. `ssl/internal.h` - Define new group constants
4. `include/openssl/nid.h` - Add NIDs for PQC algorithms

Example patch for hybrid groups:

```cpp
// ssl/ssl_key_share.cc
case SSL_GROUP_X25519_MLKEM768:
    return quac_hybrid_generate(QUAC_GROUP_X25519_ML_KEM_768, out_public_key);
```

### Pattern 4: Nginx/Envoy Integration

For TLS termination proxies:

```c
// nginx module or envoy filter
static int pqc_ssl_ctx_setup(SSL_CTX *ctx) {
    // Initialize QUAC
    QUAC_init();
    QUAC_TLS_register_groups();
    
    // Configure hybrid groups
    SSL_CTX_set1_groups_list(ctx, "X25519_MLKEM768:X25519:P-256");
    
    return 1;
}
```

## Algorithm Selection Guide

### ML-KEM Variants

| Variant | Security | Public Key | Ciphertext | Use Case |
|---------|----------|------------|------------|----------|
| ML-KEM-512 | Level 1 | 800 B | 768 B | IoT, constrained |
| ML-KEM-768 | Level 3 | 1184 B | 1088 B | **General purpose** |
| ML-KEM-1024 | Level 5 | 1568 B | 1568 B | High security |

### ML-DSA Variants

| Variant | Security | Public Key | Signature | Use Case |
|---------|----------|------------|-----------|----------|
| ML-DSA-44 | Level 2 | 1312 B | 2420 B | Fast verification |
| ML-DSA-65 | Level 3 | 1952 B | 3309 B | **Balanced** |
| ML-DSA-87 | Level 5 | 2592 B | 4627 B | Maximum security |

### TLS Hybrid Groups

| Group | Classical | PQC | Total Public Key | Use Case |
|-------|-----------|-----|------------------|----------|
| X25519_ML-KEM-768 | X25519 | ML-KEM-768 | 1216 B | **Recommended** |
| P-384_ML-KEM-1024 | ECDH P-384 | ML-KEM-1024 | 1665 B | High security |
| X25519_ML-KEM-512 | X25519 | ML-KEM-512 | 832 B | Constrained |

## Error Handling

All functions return `int` status codes:

```c
typedef enum {
    QUAC_SUCCESS = 0,
    QUAC_ERROR_INVALID_ALGORITHM = -1,
    QUAC_ERROR_INVALID_KEY = -2,
    QUAC_ERROR_INVALID_SIGNATURE = -3,
    QUAC_ERROR_INVALID_CIPHERTEXT = -4,
    QUAC_ERROR_BUFFER_TOO_SMALL = -5,
    QUAC_ERROR_HARDWARE_UNAVAILABLE = -6,
    QUAC_ERROR_INTERNAL = -7,
    QUAC_ERROR_NOT_INITIALIZED = -8,
    QUAC_ERROR_MEMORY_ALLOCATION = -9,
    QUAC_ERROR_VERIFICATION_FAILED = -10,
} quac_error_t;

// Get human-readable error
const char *msg = QUAC_get_error_string(ret);
```

## Thread Safety

- All functions are thread-safe after `QUAC_init()`
- Internal state protected by pthread mutexes
- Each thread can perform concurrent operations
- Hardware operations serialized internally

## Security Considerations

1. **Key Zeroization**: Secret keys are cleared with `OPENSSL_cleanse()` on free
2. **Constant-Time**: Hardware implementations are constant-time
3. **Side-Channel Resistance**: QUAC 100 includes DPA/SPA countermeasures
4. **FIPS Compliance**: Self-tests and integrity checks for FIPS 140-3

## Differences from OpenSSL Integration

| Feature | OpenSSL 3.x | BoringSSL |
|---------|-------------|-----------|
| Integration Model | Provider (dynamic) | Direct API (static) |
| EVP Support | Full EVP_PKEY | Limited wrapper |
| Algorithm Registration | Automatic | Manual/patching |
| TLS Groups | Provider-based | Requires patches |
| Configuration | openssl.cnf | Compile-time |

## Troubleshooting

### Hardware Not Detected

```c
if (!QUAC_is_hardware_available()) {
    // Check:
    // 1. PCIe device present: lspci | grep QUAC
    // 2. Driver loaded: lsmod | grep quac100
    // 3. Permissions: ls -la /dev/quac*
    // 4. SDK installed: pkg-config --exists quac100
}
```

### Initialization Fails

```c
int ret = QUAC_init();
if (ret != QUAC_SUCCESS) {
    fprintf(stderr, "Init failed: %s\n", QUAC_get_error_string(ret));
    // Common causes:
    // - QUAC_ERROR_HARDWARE_UNAVAILABLE: No device or driver
    // - QUAC_ERROR_INTERNAL: SDK version mismatch
}
```

### Performance Issues

```bash
# Check if using hardware
export QUAC_LOG_LEVEL=debug
./my_app 2>&1 | grep "hardware"

# Run benchmark
quac_benchmark_result_t results[3];
size_t count = 3;
QUAC_benchmark(QUAC_KEM_ML_KEM_768, 1, results, &count);
```

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2025-01 | Initial release |

## License

Copyright 2025 Dyber, Inc. All Rights Reserved.

This software is proprietary and confidential. Unauthorized copying, transfer, or use is strictly prohibited.

## Support

- Documentation: https://docs.dyber.io/quac100/boringssl
- Issues: https://github.com/dyber-inc/quac100-sdk/issues
- Email: support@dyber.io