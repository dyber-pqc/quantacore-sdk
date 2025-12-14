# QuantaCore SDK API Reference

> **QUAC 100 Post-Quantum Cryptographic Accelerator SDK**  
> Version 1.0.0 | © 2025 Dyber, Inc.

This document provides a complete API reference for the QuantaCore SDK, which enables hardware-accelerated post-quantum cryptographic operations using the QUAC 100 accelerator.

---

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Initialization & Shutdown](#initialization--shutdown)
- [Device Management](#device-management)
- [ML-KEM (Kyber) Operations](#ml-kem-kyber-operations)
- [ML-DSA (Dilithium) / SLH-DSA (SPHINCS+) Operations](#ml-dsa-dilithium--slh-dsa-sphincs-operations)
- [Quantum Random Number Generation (QRNG)](#quantum-random-number-generation-qrng)
- [Key Management](#key-management)
- [Asynchronous Operations](#asynchronous-operations)
- [Batch Operations](#batch-operations)
- [Diagnostics & Health Monitoring](#diagnostics--health-monitoring)
- [Error Handling](#error-handling)
- [Constants & Sizes](#constants--sizes)
- [Type Reference](#type-reference)

---

## Overview

The QuantaCore SDK provides a C API for the QUAC 100 Post-Quantum Cryptographic Accelerator. It supports:

| Algorithm Family | Algorithms | NIST Standard |
|------------------|------------|---------------|
| **ML-KEM** (Key Encapsulation) | Kyber-512, Kyber-768, Kyber-1024 | FIPS 203 |
| **ML-DSA** (Digital Signatures) | Dilithium2, Dilithium3, Dilithium5 | FIPS 204 |
| **SLH-DSA** (Hash-Based Signatures) | SPHINCS+ 128/192/256 (s/f variants) | FIPS 205 |
| **QRNG** | Hardware quantum random number generation | SP 800-90B |

### Include Header

```c
#include <quac100.h>
```

This single header provides access to all SDK functionality. For extended features, include the specialized headers:

```c
#include <quac100_kem.h>      // Extended KEM operations
#include <quac100_sign.h>     // Extended signature operations
#include <quac100_random.h>   // Extended QRNG operations
#include <quac100_async.h>    // Async operations
#include <quac100_batch.h>    // Batch operations
#include <quac100_diag.h>     // Diagnostics
#include <quac100_error.h>    // Extended error handling
```

---

## Quick Start

```c
#include <quac100.h>

int main(void) {
    quac_result_t result;
    quac_device_t device;

    // Initialize SDK
    result = quac_init(NULL);
    if (QUAC_FAILED(result)) {
        printf("Init failed: %s\n", quac_error_string(result));
        return 1;
    }

    // Open device
    result = quac_open(0, &device);
    if (QUAC_FAILED(result)) {
        quac_shutdown();
        return 1;
    }

    // Generate Kyber-768 key pair
    uint8_t public_key[QUAC_KYBER768_PUBLIC_KEY_SIZE];
    uint8_t secret_key[QUAC_KYBER768_SECRET_KEY_SIZE];

    result = quac_kem_keygen(device, QUAC_ALGORITHM_KYBER768,
                             public_key, sizeof(public_key),
                             secret_key, sizeof(secret_key));

    if (QUAC_SUCCEEDED(result)) {
        printf("Key pair generated successfully!\n");
    }

    // Cleanup
    quac_close(device);
    quac_shutdown();
    return 0;
}
```

---

## Initialization & Shutdown

### quac_init

Initialize the QuantaCore SDK. Must be called before any other SDK function.

```c
quac_result_t quac_init(const quac_init_options_t *options);
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `options` | `const quac_init_options_t*` | Initialization options (NULL for defaults) |

**Returns:**
- `QUAC_SUCCESS` on success
- `QUAC_ERROR_ALREADY_INITIALIZED` if already initialized
- `QUAC_ERROR_OUT_OF_MEMORY` on memory allocation failure
- `QUAC_ERROR_NO_DEVICE` if no device found and simulator disabled

**Example:**
```c
// Default initialization
quac_init(NULL);

// With options
quac_init_options_t opts = {0};
opts.struct_size = sizeof(opts);
opts.flags = QUAC_INIT_SIMULATOR;  // Use simulator if no hardware
opts.log_level = 2;                // Info level logging
quac_init(&opts);
```

**Initialization Flags:**
| Flag | Value | Description |
|------|-------|-------------|
| `QUAC_INIT_DEFAULT` | 0x00 | Default behavior |
| `QUAC_INIT_SIMULATOR` | 0x01 | Use simulator if no hardware |
| `QUAC_INIT_FORCE_SIMULATOR` | 0x02 | Always use simulator |
| `QUAC_INIT_FIPS_MODE` | 0x04 | Enable FIPS mode |
| `QUAC_INIT_DEBUG_LOGGING` | 0x10 | Enable debug logging |

---

### quac_shutdown

Shutdown the QuantaCore SDK and release all resources.

```c
void quac_shutdown(void);
```

All device handles become invalid after this call. Safe to call multiple times.

---

### quac_is_initialized

Check if SDK is initialized.

```c
bool quac_is_initialized(void);
```

**Returns:** `true` if initialized, `false` otherwise.

---

### quac_version_string / quac_version_hex

Get SDK version information.

```c
const char* quac_version_string(void);  // Returns "1.0.0"
uint32_t quac_version_hex(void);        // Returns 0x010000
```

---

## Device Management

### quac_device_count

Get the number of available QUAC 100 devices.

```c
quac_result_t quac_device_count(uint32_t *count);
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `count` | `uint32_t*` | Pointer to receive device count |

---

### quac_open

Open a device by index.

```c
quac_result_t quac_open(uint32_t index, quac_device_t *device);
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `index` | `uint32_t` | Device index (0 to count-1) |
| `device` | `quac_device_t*` | Pointer to receive device handle |

**Returns:**
- `QUAC_SUCCESS` on success
- `QUAC_ERROR_DEVICE_NOT_FOUND` if index invalid
- `QUAC_ERROR_DEVICE_OPEN_FAILED` on open failure

---

### quac_open_by_serial

Open a device by serial number.

```c
quac_result_t quac_open_by_serial(const char *serial, quac_device_t *device);
```

---

### quac_close

Close a device handle.

```c
quac_result_t quac_close(quac_device_t device);
```

---

### quac_get_info

Get detailed device information.

```c
quac_result_t quac_get_info(quac_device_t device, quac_device_info_t *info);
```

**Example:**
```c
quac_device_info_t info;
info.struct_size = sizeof(info);
quac_get_info(device, &info);

printf("Device: %s\n", info.device_name);
printf("Serial: %s\n", info.serial_number);
printf("Firmware: %d.%d.%d\n", 
       info.firmware_major, info.firmware_minor, info.firmware_patch);
printf("Temperature: %d°C\n", info.temperature_celsius);
```

---

### quac_reset

Perform a soft reset of the device. All pending operations are cancelled.

```c
quac_result_t quac_reset(quac_device_t device);
```

---

## ML-KEM (Kyber) Operations

ML-KEM (Module-Lattice Key Encapsulation Mechanism), also known as Kyber, provides quantum-resistant key encapsulation for secure key exchange.

### Supported Algorithms

| Algorithm | Security Level | Public Key | Secret Key | Ciphertext | Shared Secret |
|-----------|----------------|------------|------------|------------|---------------|
| `QUAC_ALGORITHM_KYBER512` | Level 1 | 800 B | 1632 B | 768 B | 32 B |
| `QUAC_ALGORITHM_KYBER768` | Level 3 | 1184 B | 2400 B | 1088 B | 32 B |
| `QUAC_ALGORITHM_KYBER1024` | Level 5 | 1568 B | 3168 B | 1568 B | 32 B |

### quac_kem_keygen

Generate a KEM key pair.

```c
quac_result_t quac_kem_keygen(
    quac_device_t device,
    quac_algorithm_t algorithm,
    uint8_t *public_key, size_t pk_size,
    uint8_t *secret_key, size_t sk_size
);
```

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `device` | `quac_device_t` | Device handle |
| `algorithm` | `quac_algorithm_t` | KEM algorithm (`QUAC_ALGORITHM_KYBER*`) |
| `public_key` | `uint8_t*` | Buffer for public key |
| `pk_size` | `size_t` | Size of public key buffer |
| `secret_key` | `uint8_t*` | Buffer for secret key |
| `sk_size` | `size_t` | Size of secret key buffer |

**Example:**
```c
uint8_t pk[QUAC_KYBER768_PUBLIC_KEY_SIZE];
uint8_t sk[QUAC_KYBER768_SECRET_KEY_SIZE];

result = quac_kem_keygen(device, QUAC_ALGORITHM_KYBER768,
                         pk, sizeof(pk), sk, sizeof(sk));
```

---

### quac_kem_encaps

Encapsulate a shared secret using a public key.

```c
quac_result_t quac_kem_encaps(
    quac_device_t device,
    quac_algorithm_t algorithm,
    const uint8_t *public_key, size_t pk_size,
    uint8_t *ciphertext, size_t ct_size,
    uint8_t *shared_secret, size_t ss_size
);
```

**Example:**
```c
uint8_t ct[QUAC_KYBER768_CIPHERTEXT_SIZE];
uint8_t ss[QUAC_KYBER768_SHARED_SECRET_SIZE];

result = quac_kem_encaps(device, QUAC_ALGORITHM_KYBER768,
                         pk, sizeof(pk),
                         ct, sizeof(ct),
                         ss, sizeof(ss));
// ss now contains the shared secret
// ct is sent to the recipient
```

---

### quac_kem_decaps

Decapsulate a shared secret using a secret key.

```c
quac_result_t quac_kem_decaps(
    quac_device_t device,
    quac_algorithm_t algorithm,
    const uint8_t *ciphertext, size_t ct_size,
    const uint8_t *secret_key, size_t sk_size,
    uint8_t *shared_secret, size_t ss_size
);
```

**Example:**
```c
uint8_t ss[QUAC_KYBER768_SHARED_SECRET_SIZE];

result = quac_kem_decaps(device, QUAC_ALGORITHM_KYBER768,
                         ct, sizeof(ct),
                         sk, sizeof(sk),
                         ss, sizeof(ss));
// ss now contains the same shared secret as the sender
```

---

### quac_kem_sizes

Get algorithm-specific sizes.

```c
quac_result_t quac_kem_sizes(
    quac_algorithm_t algorithm,
    size_t *pk_size,    // Public key size (may be NULL)
    size_t *sk_size,    // Secret key size (may be NULL)
    size_t *ct_size,    // Ciphertext size (may be NULL)
    size_t *ss_size     // Shared secret size (may be NULL)
);
```

---

## ML-DSA (Dilithium) / SLH-DSA (SPHINCS+) Operations

### Supported Signature Algorithms

**ML-DSA (Dilithium) - FIPS 204:**

| Algorithm | Security Level | Public Key | Secret Key | Signature |
|-----------|----------------|------------|------------|-----------|
| `QUAC_ALGORITHM_DILITHIUM2` | Level 2 | 1312 B | 2528 B | 2420 B |
| `QUAC_ALGORITHM_DILITHIUM3` | Level 3 | 1952 B | 4000 B | 3293 B |
| `QUAC_ALGORITHM_DILITHIUM5` | Level 5 | 2592 B | 4864 B | 4595 B |

**SLH-DSA (SPHINCS+) - FIPS 205:**

| Algorithm | Security Level | Public Key | Secret Key | Signature |
|-----------|----------------|------------|------------|-----------|
| `QUAC_ALGORITHM_SPHINCS_SHA2_128S` | Level 1 | 32 B | 64 B | 7856 B |
| `QUAC_ALGORITHM_SPHINCS_SHA2_128F` | Level 1 | 32 B | 64 B | 17088 B |
| `QUAC_ALGORITHM_SPHINCS_SHA2_192S` | Level 3 | 48 B | 96 B | 16224 B |
| `QUAC_ALGORITHM_SPHINCS_SHA2_192F` | Level 3 | 48 B | 96 B | 35664 B |
| `QUAC_ALGORITHM_SPHINCS_SHA2_256S` | Level 5 | 64 B | 128 B | 29792 B |
| `QUAC_ALGORITHM_SPHINCS_SHA2_256F` | Level 5 | 64 B | 128 B | 49856 B |

> **Note:** "s" variants are smaller signatures, "f" variants are faster signing.

---

### quac_sign_keygen

Generate a signature key pair.

```c
quac_result_t quac_sign_keygen(
    quac_device_t device,
    quac_algorithm_t algorithm,
    uint8_t *public_key, size_t pk_size,
    uint8_t *secret_key, size_t sk_size
);
```

**Example:**
```c
uint8_t pk[QUAC_DILITHIUM3_PUBLIC_KEY_SIZE];
uint8_t sk[QUAC_DILITHIUM3_SECRET_KEY_SIZE];

result = quac_sign_keygen(device, QUAC_ALGORITHM_DILITHIUM3,
                          pk, sizeof(pk), sk, sizeof(sk));
```

---

### quac_sign

Sign a message.

```c
quac_result_t quac_sign(
    quac_device_t device,
    quac_algorithm_t algorithm,
    const uint8_t *secret_key, size_t sk_size,
    const uint8_t *message, size_t msg_size,
    uint8_t *signature, size_t sig_size,
    size_t *sig_len  // Actual signature length (may be NULL)
);
```

**Example:**
```c
uint8_t signature[QUAC_DILITHIUM3_SIGNATURE_SIZE];
size_t sig_len;
const char *message = "Hello, quantum-safe world!";

result = quac_sign(device, QUAC_ALGORITHM_DILITHIUM3,
                   sk, sizeof(sk),
                   (const uint8_t*)message, strlen(message),
                   signature, sizeof(signature),
                   &sig_len);
```

---

### quac_verify

Verify a signature.

```c
quac_result_t quac_verify(
    quac_device_t device,
    quac_algorithm_t algorithm,
    const uint8_t *public_key, size_t pk_size,
    const uint8_t *message, size_t msg_size,
    const uint8_t *signature, size_t sig_size
);
```

**Returns:**
- `QUAC_SUCCESS` if signature is valid
- `QUAC_ERROR_VERIFICATION_FAILED` if signature is invalid
- `QUAC_ERROR_INVALID_SIGNATURE` if signature is malformed

**Example:**
```c
result = quac_verify(device, QUAC_ALGORITHM_DILITHIUM3,
                     pk, sizeof(pk),
                     (const uint8_t*)message, strlen(message),
                     signature, sig_len);

if (result == QUAC_SUCCESS) {
    printf("Signature is valid!\n");
} else {
    printf("Signature verification failed!\n");
}
```

---

### quac_sign_sizes

Get signature algorithm sizes.

```c
quac_result_t quac_sign_sizes(
    quac_algorithm_t algorithm,
    size_t *pk_size,   // Public key size
    size_t *sk_size,   // Secret key size
    size_t *sig_size   // Maximum signature size
);
```

---

## Quantum Random Number Generation (QRNG)

The QUAC 100 includes a hardware quantum random number generator providing cryptographically secure random bytes.

### quac_random_bytes

Generate random bytes from the hardware QRNG.

```c
quac_result_t quac_random_bytes(
    quac_device_t device,
    uint8_t *buffer,
    size_t length
);
```

**Returns:**
- `QUAC_SUCCESS` on success
- `QUAC_ERROR_ENTROPY_DEPLETED` if entropy pool depleted
- `QUAC_ERROR_QRNG_FAILURE` on hardware failure

**Example:**
```c
uint8_t nonce[32];
result = quac_random_bytes(device, nonce, sizeof(nonce));

// Generate a random key
uint8_t key[32];
quac_random_bytes(device, key, sizeof(key));
```

---

### quac_random_available

Get available entropy in the pool.

```c
quac_result_t quac_random_available(quac_device_t device, uint32_t *bits);
```

---

### quac_random_reseed

Force reseed of the QRNG with optional additional seed data.

```c
quac_result_t quac_random_reseed(
    quac_device_t device,
    const uint8_t *seed,    // Optional additional seed (may be NULL)
    size_t seed_len
);
```

---

## Key Management

Store and manage keys securely on the device.

### quac_key_generate

Generate and store a key pair on the device.

```c
quac_result_t quac_key_generate(
    quac_device_t device,
    const quac_key_attr_t *attr,
    quac_key_handle_t *handle
);
```

**Example:**
```c
quac_key_attr_t attr = {0};
attr.struct_size = sizeof(attr);
attr.algorithm = QUAC_ALGORITHM_KYBER768;
attr.usage = QUAC_KEY_USAGE_ENCAPSULATE | QUAC_KEY_USAGE_DECAPSULATE;
attr.extractable = false;  // Key cannot leave the device
attr.persistent = true;    // Survive reboots
strcpy(attr.label, "my-kem-key");

quac_key_handle_t handle;
result = quac_key_generate(device, &attr, &handle);
```

---

### quac_key_import

Import a key to device storage.

```c
quac_result_t quac_key_import(
    quac_device_t device,
    const quac_key_attr_t *attr,
    const uint8_t *key_data, size_t key_len,
    quac_key_handle_t *handle
);
```

---

### quac_key_export

Export a key from device storage.

```c
quac_result_t quac_key_export(
    quac_device_t device,
    quac_key_handle_t handle,
    uint8_t *key_data, size_t key_len,
    size_t *actual_len
);
```

**Returns:**
- `QUAC_ERROR_KEY_EXPORT_DENIED` if key is not extractable

---

### quac_key_destroy

Delete a key from device storage.

```c
quac_result_t quac_key_destroy(quac_device_t device, quac_key_handle_t handle);
```

---

### quac_key_get_attr

Get key attributes.

```c
quac_result_t quac_key_get_attr(
    quac_device_t device,
    quac_key_handle_t handle,
    quac_key_attr_t *attr
);
```

---

## Asynchronous Operations

Submit operations for non-blocking execution.

### quac_async_kem_keygen

Submit async KEM key generation.

```c
quac_result_t quac_async_kem_keygen(
    quac_device_t device,
    quac_algorithm_t algorithm,
    uint8_t *public_key, size_t pk_size,
    uint8_t *secret_key, size_t sk_size,
    quac_async_callback_t callback,
    void *user_data,
    quac_job_id_t *job_id
);
```

**Callback Signature:**
```c
void callback(quac_device_t device, quac_job_id_t job_id, 
              quac_result_t result, void *user_data);
```

---

### quac_async_wait

Wait for a job to complete.

```c
quac_result_t quac_async_wait(
    quac_device_t device,
    quac_job_id_t job_id,
    uint32_t timeout_ms  // 0 = infinite
);
```

---

### quac_async_poll

Non-blocking check of job status.

```c
quac_result_t quac_async_poll(
    quac_device_t device,
    quac_job_id_t job_id,
    bool *completed
);
```

---

### quac_async_cancel

Cancel a pending job.

```c
quac_result_t quac_async_cancel(quac_device_t device, quac_job_id_t job_id);
```

---

## Batch Operations

Execute multiple operations in a single call for maximum throughput.

### Performance Characteristics

| Batch Size | Relative Throughput |
|------------|---------------------|
| 1 | 1.0x (baseline) |
| 16 | 8-10x |
| 64 | 12-15x |
| 256 | 15-18x |
| 1024 | 18-20x |

### quac_batch_submit

Submit a batch of operations.

```c
quac_result_t quac_batch_submit(
    quac_device_t device,
    quac_batch_item_t *items,
    size_t count
);
```

**Returns:**
- `QUAC_SUCCESS` if all operations succeeded
- `QUAC_ERROR_BATCH_PARTIAL` if some operations failed (check individual results)

**Example:**
```c
#define BATCH_SIZE 100

quac_batch_kem_keygen_t items[BATCH_SIZE];
uint8_t pk_buffers[BATCH_SIZE][QUAC_KYBER768_PUBLIC_KEY_SIZE];
uint8_t sk_buffers[BATCH_SIZE][QUAC_KYBER768_SECRET_KEY_SIZE];

for (int i = 0; i < BATCH_SIZE; i++) {
    items[i].operation = QUAC_BATCH_OP_KEM_KEYGEN;
    items[i].algorithm = QUAC_ALGORITHM_KYBER768;
    items[i].public_key = pk_buffers[i];
    items[i].pk_size = sizeof(pk_buffers[i]);
    items[i].secret_key = sk_buffers[i];
    items[i].sk_size = sizeof(sk_buffers[i]);
}

result = quac_batch_submit(device, (quac_batch_item_t*)items, BATCH_SIZE);

// Check individual results
for (int i = 0; i < BATCH_SIZE; i++) {
    if (QUAC_FAILED(items[i].result)) {
        printf("Item %d failed: %s\n", i, quac_error_string(items[i].result));
    }
}
```

---

## Diagnostics & Health Monitoring

### quac_self_test

Run FIPS-required cryptographic self-tests.

```c
quac_result_t quac_self_test(quac_device_t device);
```

**Returns:**
- `QUAC_SUCCESS` if all tests pass
- `QUAC_ERROR_SELF_TEST_FAILED` if any test fails

---

### quac_get_health

Get device health status.

```c
quac_result_t quac_get_health(quac_device_t device, quac_device_status_t *status);
```

---

### quac_get_temperature

Get device temperature.

```c
quac_result_t quac_get_temperature(quac_device_t device, int32_t *celsius);
```

---

## Error Handling

### quac_error_string

Get a human-readable error message.

```c
const char* quac_error_string(quac_result_t result);
```

**Example:**
```c
result = quac_kem_keygen(device, QUAC_ALGORITHM_KYBER768, pk, pk_size, sk, sk_size);
if (QUAC_FAILED(result)) {
    printf("Error: %s\n", quac_error_string(result));
}
```

---

### quac_get_last_error

Get last error for current thread.

```c
quac_result_t quac_get_last_error(void);
```

---

### quac_get_last_error_detail

Get extended error information.

```c
quac_result_t quac_get_last_error_detail(char *buffer, size_t size);
```

---

### Result Macros

```c
#define QUAC_SUCCEEDED(r)  ((r) == QUAC_SUCCESS)
#define QUAC_FAILED(r)     ((r) != QUAC_SUCCESS)
```

---

## Constants & Sizes

### ML-KEM (Kyber) Sizes

```c
// Kyber-512
#define QUAC_KYBER512_PUBLIC_KEY_SIZE     800
#define QUAC_KYBER512_SECRET_KEY_SIZE     1632
#define QUAC_KYBER512_CIPHERTEXT_SIZE     768
#define QUAC_KYBER512_SHARED_SECRET_SIZE  32

// Kyber-768
#define QUAC_KYBER768_PUBLIC_KEY_SIZE     1184
#define QUAC_KYBER768_SECRET_KEY_SIZE     2400
#define QUAC_KYBER768_CIPHERTEXT_SIZE     1088
#define QUAC_KYBER768_SHARED_SECRET_SIZE  32

// Kyber-1024
#define QUAC_KYBER1024_PUBLIC_KEY_SIZE    1568
#define QUAC_KYBER1024_SECRET_KEY_SIZE    3168
#define QUAC_KYBER1024_CIPHERTEXT_SIZE    1568
#define QUAC_KYBER1024_SHARED_SECRET_SIZE 32
```

### ML-DSA (Dilithium) Sizes

```c
// Dilithium2
#define QUAC_DILITHIUM2_PUBLIC_KEY_SIZE   1312
#define QUAC_DILITHIUM2_SECRET_KEY_SIZE   2528
#define QUAC_DILITHIUM2_SIGNATURE_SIZE    2420

// Dilithium3
#define QUAC_DILITHIUM3_PUBLIC_KEY_SIZE   1952
#define QUAC_DILITHIUM3_SECRET_KEY_SIZE   4000
#define QUAC_DILITHIUM3_SIGNATURE_SIZE    3293

// Dilithium5
#define QUAC_DILITHIUM5_PUBLIC_KEY_SIZE   2592
#define QUAC_DILITHIUM5_SECRET_KEY_SIZE   4864
#define QUAC_DILITHIUM5_SIGNATURE_SIZE    4595
```

### Maximum Sizes

```c
#define QUAC_MAX_PUBLIC_KEY_SIZE      2592   // Dilithium5
#define QUAC_MAX_SECRET_KEY_SIZE      4864   // Dilithium5
#define QUAC_MAX_CIPHERTEXT_SIZE      1568   // Kyber1024
#define QUAC_MAX_SIGNATURE_SIZE       49856  // SPHINCS+ SHA2-256f
#define QUAC_MAX_SHARED_SECRET_SIZE   32
```

### Device Limits

```c
#define QUAC_MAX_DEVICES        16
#define QUAC_MAX_BATCH_SIZE     1024
#define QUAC_MAX_KEY_SLOTS      256
```

---

## Type Reference

### quac_result_t

Result codes returned by all SDK functions.

| Code | Value | Description |
|------|-------|-------------|
| `QUAC_SUCCESS` | 0x0000 | Operation succeeded |
| `QUAC_ERROR_NOT_INITIALIZED` | 0x0002 | SDK not initialized |
| `QUAC_ERROR_INVALID_PARAMETER` | 0x0004 | Invalid parameter |
| `QUAC_ERROR_NULL_POINTER` | 0x0005 | Null pointer provided |
| `QUAC_ERROR_BUFFER_TOO_SMALL` | 0x0006 | Buffer too small |
| `QUAC_ERROR_OUT_OF_MEMORY` | 0x0007 | Memory allocation failed |
| `QUAC_ERROR_TIMEOUT` | 0x0009 | Operation timed out |
| `QUAC_ERROR_DEVICE_NOT_FOUND` | 0x0101 | Device not found |
| `QUAC_ERROR_INVALID_ALGORITHM` | 0x0200 | Invalid algorithm |
| `QUAC_ERROR_INVALID_KEY` | 0x0201 | Invalid key |
| `QUAC_ERROR_VERIFICATION_FAILED` | 0x0206 | Signature verification failed |
| `QUAC_ERROR_ENTROPY_DEPLETED` | 0x0400 | Entropy pool depleted |
| `QUAC_ERROR_SELF_TEST_FAILED` | 0x0605 | Self-test failed |

See `quac100_types.h` for complete list.

---

### quac_algorithm_t

Cryptographic algorithm identifiers.

```c
typedef enum {
    QUAC_ALGORITHM_NONE = 0x0000,
    
    // ML-KEM (Kyber)
    QUAC_ALGORITHM_KYBER512  = 0x1100,
    QUAC_ALGORITHM_KYBER768  = 0x1101,
    QUAC_ALGORITHM_KYBER1024 = 0x1102,
    
    // ML-DSA (Dilithium)
    QUAC_ALGORITHM_DILITHIUM2 = 0x2100,
    QUAC_ALGORITHM_DILITHIUM3 = 0x2101,
    QUAC_ALGORITHM_DILITHIUM5 = 0x2102,
    
    // SLH-DSA (SPHINCS+)
    QUAC_ALGORITHM_SPHINCS_SHA2_128S = 0x2200,
    QUAC_ALGORITHM_SPHINCS_SHA2_128F = 0x2201,
    // ... and more
} quac_algorithm_t;
```

---

### quac_device_t

Opaque device handle. Use `QUAC_INVALID_DEVICE` to check for invalid handles.

```c
typedef struct quac_device_s *quac_device_t;
#define QUAC_INVALID_DEVICE ((quac_device_t)NULL)
```

---

### quac_key_handle_t

Handle for stored keys.

```c
typedef uint64_t quac_key_handle_t;
#define QUAC_INVALID_KEY_HANDLE ((quac_key_handle_t)0)
```

---

### quac_job_id_t

Identifier for asynchronous jobs.

```c
typedef uint64_t quac_job_id_t;
#define QUAC_INVALID_JOB_ID ((quac_job_id_t)0)
```

---

## See Also

- [Getting Started Guide](../guides/getting-started.md)
- [KEM Operations Guide](../guides/kem-operations.md)
- [Signature Operations Guide](../guides/signature-operations.md)
- [QRNG Guide](../guides/random-numbers.md)
- [Technical Reference](../reference/README.md)