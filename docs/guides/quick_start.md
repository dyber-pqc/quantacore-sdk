# Quick Start Guide

## QuantaCore SDK - Get Up and Running in 5 Minutes

This guide will help you write your first program using the QUAC 100 Post-Quantum Cryptographic Accelerator.

---

## Prerequisites

Before starting, ensure you have:
- QuantaCore SDK installed (see [Installation Guide](installation.md))
- QUAC 100 hardware installed OR simulator mode enabled
- C compiler (GCC, Clang, or MSVC)

---

## Your First Program

### Step 1: Create a New Project

```bash
mkdir my_quac_project
cd my_quac_project
```

### Step 2: Write the Code

Create `main.c`:

```c
/**
 * QuantaCore SDK - Quick Start Example
 * 
 * This example demonstrates:
 * - SDK initialization
 * - Device opening
 * - ML-KEM (Kyber) key generation, encapsulation, and decapsulation
 * - Proper cleanup
 */

#include <quac100.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    quac_result_t result;
    quac_device_t device;
    
    printf("QuantaCore SDK Quick Start Example\n");
    printf("===================================\n\n");

    /*
     * Step 1: Initialize the SDK
     * 
     * This must be called before any other SDK function.
     * Pass NULL for default options.
     */
    result = quac_init(NULL);
    if (QUAC_FAILED(result)) {
        fprintf(stderr, "Failed to initialize SDK: %s\n", 
                quac_error_string(result));
        return 1;
    }
    printf("[OK] SDK initialized (version %s)\n", quac_version_string());

    /*
     * Step 2: Open a device
     * 
     * Device index 0 is the first available device.
     * In simulator mode, a virtual device is provided.
     */
    result = quac_open(0, &device);
    if (QUAC_FAILED(result)) {
        fprintf(stderr, "Failed to open device: %s\n", 
                quac_error_string(result));
        quac_shutdown();
        return 1;
    }
    
    /* Get device info */
    quac_device_info_t info;
    info.struct_size = sizeof(info);
    quac_get_info(device, &info);
    printf("[OK] Opened device: %s (Serial: %s)\n", 
           info.device_name, info.serial_number);

    /*
     * Step 3: Generate a Kyber-768 key pair
     * 
     * ML-KEM-768 (Kyber768) provides NIST Security Level 3.
     */
    uint8_t public_key[QUAC_KYBER768_PUBLIC_KEY_SIZE];
    uint8_t secret_key[QUAC_KYBER768_SECRET_KEY_SIZE];

    result = quac_kem_keygen(device, QUAC_ALGORITHM_KYBER768,
                             public_key, sizeof(public_key),
                             secret_key, sizeof(secret_key));
    if (QUAC_FAILED(result)) {
        fprintf(stderr, "Failed to generate key pair: %s\n", 
                quac_error_string(result));
        quac_close(device);
        quac_shutdown();
        return 1;
    }
    printf("[OK] Generated Kyber768 key pair\n");
    printf("    Public key size:  %zu bytes\n", sizeof(public_key));
    printf("    Secret key size:  %zu bytes\n", sizeof(secret_key));

    /*
     * Step 4: Encapsulate a shared secret
     * 
     * Alice uses Bob's public key to create a ciphertext
     * and derive a shared secret.
     */
    uint8_t ciphertext[QUAC_KYBER768_CIPHERTEXT_SIZE];
    uint8_t shared_secret_alice[QUAC_KYBER768_SHARED_SECRET_SIZE];

    result = quac_kem_encaps(device, QUAC_ALGORITHM_KYBER768,
                             public_key, sizeof(public_key),
                             ciphertext, sizeof(ciphertext),
                             shared_secret_alice, sizeof(shared_secret_alice));
    if (QUAC_FAILED(result)) {
        fprintf(stderr, "Encapsulation failed: %s\n", 
                quac_error_string(result));
        quac_close(device);
        quac_shutdown();
        return 1;
    }
    printf("[OK] Encapsulated shared secret\n");
    printf("    Ciphertext size:  %zu bytes\n", sizeof(ciphertext));

    /*
     * Step 5: Decapsulate the shared secret
     * 
     * Bob uses his secret key to recover the shared secret
     * from the ciphertext.
     */
    uint8_t shared_secret_bob[QUAC_KYBER768_SHARED_SECRET_SIZE];

    result = quac_kem_decaps(device, QUAC_ALGORITHM_KYBER768,
                             ciphertext, sizeof(ciphertext),
                             secret_key, sizeof(secret_key),
                             shared_secret_bob, sizeof(shared_secret_bob));
    if (QUAC_FAILED(result)) {
        fprintf(stderr, "Decapsulation failed: %s\n", 
                quac_error_string(result));
        quac_close(device);
        quac_shutdown();
        return 1;
    }
    printf("[OK] Decapsulated shared secret\n");

    /*
     * Step 6: Verify the shared secrets match
     */
    if (memcmp(shared_secret_alice, shared_secret_bob, 
               QUAC_KYBER768_SHARED_SECRET_SIZE) == 0) {
        printf("[OK] Shared secrets match! Key exchange successful.\n");
    } else {
        fprintf(stderr, "[FAIL] Shared secrets do not match!\n");
        quac_close(device);
        quac_shutdown();
        return 1;
    }

    /* Print first 16 bytes of shared secret */
    printf("\n    Shared secret (first 16 bytes): ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", shared_secret_alice[i]);
    }
    printf("...\n");

    /*
     * Step 7: Cleanup
     * 
     * Always close devices and shutdown the SDK when done.
     */
    quac_close(device);
    quac_shutdown();
    
    printf("\n[OK] Example completed successfully!\n");
    return 0;
}
```

### Step 3: Compile the Program

**Linux:**
```bash
gcc -o my_first_quac main.c $(pkg-config --cflags --libs quac100)
```

Or without pkg-config:
```bash
gcc -o my_first_quac main.c -I/usr/local/include -L/usr/local/lib -lquac100
```

**Windows:**
```cmd
cl main.c /I"C:\Program Files\QuantaCore\include" /link /LIBPATH:"C:\Program Files\QuantaCore\lib" quac100.lib
```

### Step 4: Run the Program

```bash
./my_first_quac
```

**Expected Output:**
```
QuantaCore SDK Quick Start Example
===================================

[OK] SDK initialized (version 1.0.0)
[OK] Opened device: QUAC 100 (Serial: QC100-2025-00001)
[OK] Generated Kyber768 key pair
    Public key size:  1184 bytes
    Secret key size:  2400 bytes
[OK] Encapsulated shared secret
    Ciphertext size:  1088 bytes
[OK] Decapsulated shared secret
[OK] Shared secrets match! Key exchange successful.

    Shared secret (first 16 bytes): a3b7c2d9e1f0...

[OK] Example completed successfully!
```

---

## Using Simulator Mode

If you don't have QUAC 100 hardware, use the simulator:

```c
#include <quac100.h>

int main(void)
{
    quac_result_t result;
    
    /* Enable simulator mode BEFORE quac_init() */
    result = quac_set_simulator_mode(true);
    if (QUAC_FAILED(result)) {
        fprintf(stderr, "Failed to enable simulator: %s\n",
                quac_error_string(result));
        return 1;
    }
    
    /* Optional: Configure simulator latency */
    quac_simulator_config(100, 10000);  /* 100µs latency, 10K ops/sec */
    
    /* Now initialize and use normally */
    result = quac_init(NULL);
    // ... rest of your code
}
```

---

## Digital Signature Example

Here's a quick example of ML-DSA (Dilithium) signing:

```c
#include <quac100.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    quac_result_t result;
    quac_device_t device;
    
    /* Initialize SDK and open device */
    quac_init(NULL);
    quac_open(0, &device);
    
    /* Generate Dilithium3 key pair */
    uint8_t pk[QUAC_DILITHIUM3_PUBLIC_KEY_SIZE];
    uint8_t sk[QUAC_DILITHIUM3_SECRET_KEY_SIZE];
    
    result = quac_sign_keygen(device, QUAC_ALGORITHM_DILITHIUM3,
                              pk, sizeof(pk), sk, sizeof(sk));
    if (QUAC_FAILED(result)) {
        fprintf(stderr, "Key generation failed: %s\n", 
                quac_error_string(result));
        goto cleanup;
    }
    printf("[OK] Generated Dilithium3 key pair\n");
    
    /* Sign a message */
    const char *message = "Hello, Post-Quantum World!";
    uint8_t signature[QUAC_DILITHIUM3_SIGNATURE_SIZE];
    size_t sig_len;
    
    result = quac_sign(device, QUAC_ALGORITHM_DILITHIUM3,
                       sk, sizeof(sk),
                       (const uint8_t *)message, strlen(message),
                       signature, sizeof(signature), &sig_len);
    if (QUAC_FAILED(result)) {
        fprintf(stderr, "Signing failed: %s\n", 
                quac_error_string(result));
        goto cleanup;
    }
    printf("[OK] Signed message (%zu byte signature)\n", sig_len);
    
    /* Verify the signature */
    result = quac_verify(device, QUAC_ALGORITHM_DILITHIUM3,
                         pk, sizeof(pk),
                         (const uint8_t *)message, strlen(message),
                         signature, sig_len);
    if (result == QUAC_SUCCESS) {
        printf("[OK] Signature verified successfully!\n");
    } else {
        fprintf(stderr, "[FAIL] Signature verification failed!\n");
    }

cleanup:
    quac_close(device);
    quac_shutdown();
    return (result == QUAC_SUCCESS) ? 0 : 1;
}
```

---

## Quantum Random Number Generation

Generate cryptographically secure random numbers from hardware QRNG:

```c
#include <quac100.h>
#include <stdio.h>

int main(void)
{
    quac_result_t result;
    quac_device_t device;
    
    quac_init(NULL);
    quac_open(0, &device);
    
    /* Generate 32 random bytes */
    uint8_t random_bytes[32];
    
    result = quac_random_bytes(device, random_bytes, sizeof(random_bytes));
    if (QUAC_FAILED(result)) {
        fprintf(stderr, "Random generation failed: %s\n",
                quac_error_string(result));
        goto cleanup;
    }
    
    printf("Random bytes: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", random_bytes[i]);
    }
    printf("\n");
    
    /* Check available entropy */
    uint32_t entropy_bits;
    quac_random_available(device, &entropy_bits);
    printf("Available entropy: %u bits\n", entropy_bits);

cleanup:
    quac_close(device);
    quac_shutdown();
    return 0;
}
```

---

## CMake Integration

Create `CMakeLists.txt` for your project:

```cmake
cmake_minimum_required(VERSION 3.20)
project(my_quac_project C)

# Find QuantaCore SDK
find_package(QuantaCore REQUIRED)

# Create executable
add_executable(my_app main.c)

# Link with SDK
target_link_libraries(my_app PRIVATE QuantaCore::quac100)
```

Build with:
```bash
mkdir build && cd build
cmake ..
make
```

---

## Error Handling Best Practices

Always check return values and handle errors appropriately:

```c
#include <quac100.h>
#include <stdio.h>

#define CHECK_RESULT(result, msg) \
    do { \
        if (QUAC_FAILED(result)) { \
            fprintf(stderr, "%s: %s\n", msg, quac_error_string(result)); \
            goto cleanup; \
        } \
    } while(0)

int main(void)
{
    quac_result_t result;
    quac_device_t device = QUAC_INVALID_DEVICE;
    int exit_code = 1;
    
    /* Initialize SDK */
    result = quac_init(NULL);
    CHECK_RESULT(result, "SDK initialization failed");
    
    /* Open device */
    result = quac_open(0, &device);
    CHECK_RESULT(result, "Device open failed");
    
    /* Your cryptographic operations here... */
    
    exit_code = 0;  /* Success */

cleanup:
    /* Always cleanup, even on error */
    if (device != QUAC_INVALID_DEVICE) {
        quac_close(device);
    }
    if (quac_is_initialized()) {
        quac_shutdown();
    }
    
    return exit_code;
}
```

---

## Quick Reference

### Supported Algorithms

| Algorithm | Function | Security Level | Use Case |
|-----------|----------|----------------|----------|
| ML-KEM-512 | `QUAC_ALGORITHM_KYBER512` | Level 1 | Key exchange (lightweight) |
| ML-KEM-768 | `QUAC_ALGORITHM_KYBER768` | Level 3 | Key exchange (recommended) |
| ML-KEM-1024 | `QUAC_ALGORITHM_KYBER1024` | Level 5 | Key exchange (high security) |
| ML-DSA-44 | `QUAC_ALGORITHM_DILITHIUM2` | Level 2 | Digital signatures |
| ML-DSA-65 | `QUAC_ALGORITHM_DILITHIUM3` | Level 3 | Digital signatures (recommended) |
| ML-DSA-87 | `QUAC_ALGORITHM_DILITHIUM5` | Level 5 | Digital signatures (high security) |
| SLH-DSA | `QUAC_ALGORITHM_SPHINCS_*` | Levels 1,3,5 | Stateless signatures |

### Key Sizes

| Algorithm | Public Key | Secret Key | Ciphertext/Signature |
|-----------|-----------|------------|---------------------|
| Kyber512 | 800 B | 1,632 B | 768 B |
| Kyber768 | 1,184 B | 2,400 B | 1,088 B |
| Kyber1024 | 1,568 B | 3,168 B | 1,568 B |
| Dilithium2 | 1,312 B | 2,528 B | 2,420 B |
| Dilithium3 | 1,952 B | 4,000 B | 3,293 B |
| Dilithium5 | 2,592 B | 4,864 B | 4,595 B |

### Common Error Codes

| Code | Meaning |
|------|---------|
| `QUAC_SUCCESS` | Operation succeeded |
| `QUAC_ERROR_NOT_INITIALIZED` | Call `quac_init()` first |
| `QUAC_ERROR_NO_DEVICE` | No QUAC 100 hardware found |
| `QUAC_ERROR_BUFFER_TOO_SMALL` | Increase buffer size |
| `QUAC_ERROR_INVALID_ALGORITHM` | Wrong algorithm for operation |
| `QUAC_ERROR_VERIFICATION_FAILED` | Signature is invalid |

---

## Next Steps

1. **[Programming Guide](programming_guide.md)** - Deep dive into all API features
2. **[Simulator Guide](simulator_guide.md)** - Develop without hardware
3. **[API Reference](../api/README.md)** - Complete function documentation
4. **Examples** - Explore `examples/` directory for more use cases

---

*Document Version: 1.0.0*
*Last Updated: 2025*
*Copyright © 2025 Dyber, Inc. All Rights Reserved.*
