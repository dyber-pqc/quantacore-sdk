# QuantaCore SDK API Reference

Complete API reference for the QUAC 100 Post-Quantum Cryptographic Accelerator SDK.

## Table of Contents

- [Overview](#overview)
- [Headers](#headers)
- [Types](#types)
- [Constants](#constants)
- [Core API](#core-api)
- [KEM Operations](#kem-operations)
- [Signature Operations](#signature-operations)
- [Random Number Generation](#random-number-generation)
- [Key Management](#key-management)
- [Asynchronous Operations](#asynchronous-operations)
- [Batch Operations](#batch-operations)
- [Diagnostics](#diagnostics)
- [Error Handling](#error-handling)

---

## Overview

The QuantaCore SDK provides a C API for interacting with the QUAC 100 hardware accelerator. All functions are thread-safe unless otherwise noted.

### Basic Usage Pattern

```c
#include <quac100.h>

int main(void) {
    quac_result_t result;
    quac_device_t device;

    // 1. Initialize SDK
    result = quac_init(NULL);
    if (QUAC_FAILED(result)) return 1;

    // 2. Open device
    result = quac_open(0, &device);
    if (QUAC_FAILED(result)) {
        quac_shutdown();
        return 1;
    }

    // 3. Perform operations
    // ...

    // 4. Cleanup
    quac_close(device);
    quac_shutdown();
    return 0;
}
```

---

## Headers

| Header | Description |
|--------|-------------|
| `quac100.h` | Main header - includes all public API |
| `quac100_types.h` | Type definitions, constants, structures |
| `quac100_kem.h` | Extended KEM operations |
| `quac100_sign.h` | Extended signature operations |
| `quac100_random.h` | Extended QRNG operations |
| `quac100_async.h` | Asynchronous operation interface |
| `quac100_batch.h` | Batch processing interface |
| `quac100_diag.h` | Diagnostics and health monitoring |
| `quac100_error.h` | Extended error handling |

---

## Types

### Handle Types

```c
typedef struct quac_device_s *quac_device_t;    // Device handle
typedef uint64_t quac_key_handle_t;              // Stored key handle
typedef uint64_t quac_job_id_t;                  // Async job identifier
```

### Invalid Handle Constants

```c
#define QUAC_INVALID_DEVICE     ((quac_device_t)NULL)
#define QUAC_INVALID_KEY_HANDLE ((quac_key_handle_t)0)
#define QUAC_INVALID_JOB_ID     ((quac_job_id_t)0)
```

### Result Type

```c
typedef enum quac_result_e {
    QUAC_SUCCESS = 0,
    // See Error Codes section for complete list
} quac_result_t;
```

### Algorithm Identifiers

```c
typedef enum quac_algorithm_e {
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
    QUAC_ALGORITHM_SPHINCS_SHA2_192S = 0x2202,
    QUAC_ALGORITHM_SPHINCS_SHA2_192F = 0x2203,
    QUAC_ALGORITHM_SPHINCS_SHA2_256S = 0x2204,
    QUAC_ALGORITHM_SPHINCS_SHA2_256F = 0x2205,
} quac_algorithm_t;
```

### Device Information

```c
typedef struct quac_device_info_s {
    uint32_t struct_size;
    uint32_t device_index;
    char device_name[64];
    char serial_number[32];
    uint32_t vendor_id;
    uint32_t device_id;
    uint8_t hardware_rev;
    uint8_t firmware_major;
    uint8_t firmware_minor;
    uint8_t firmware_patch;
    quac_device_caps_t capabilities;
    quac_device_status_t status;
    uint32_t max_batch_size;
    uint32_t max_pending_jobs;
    uint32_t key_slots_total;
    uint32_t key_slots_used;
    int32_t temperature_celsius;
    uint32_t entropy_available;
    uint64_t operations_completed;
    uint64_t operations_failed;
    uint64_t uptime_seconds;
} quac_device_info_t;
```

### Key Attributes

```c
typedef struct quac_key_attr_s {
    uint32_t struct_size;
    quac_algorithm_t algorithm;
    quac_key_type_t type;
    quac_key_usage_t usage;
    bool extractable;
    bool persistent;
    char label[64];
    uint8_t id[32];
    size_t id_len;
} quac_key_attr_t;
```

---

## Constants

### Key Sizes - ML-KEM (Kyber)

| Algorithm | Public Key | Secret Key | Ciphertext | Shared Secret |
|-----------|------------|------------|------------|---------------|
| Kyber512 | 800 | 1632 | 768 | 32 |
| Kyber768 | 1184 | 2400 | 1088 | 32 |
| Kyber1024 | 1568 | 3168 | 1568 | 32 |

```c
#define QUAC_KYBER512_PUBLIC_KEY_SIZE     800
#define QUAC_KYBER512_SECRET_KEY_SIZE     1632
#define QUAC_KYBER512_CIPHERTEXT_SIZE     768
#define QUAC_KYBER512_SHARED_SECRET_SIZE  32

#define QUAC_KYBER768_PUBLIC_KEY_SIZE     1184
#define QUAC_KYBER768_SECRET_KEY_SIZE     2400
#define QUAC_KYBER768_CIPHERTEXT_SIZE     1088
#define QUAC_KYBER768_SHARED_SECRET_SIZE  32

#define QUAC_KYBER1024_PUBLIC_KEY_SIZE    1568
#define QUAC_KYBER1024_SECRET_KEY_SIZE    3168
#define QUAC_KYBER1024_CIPHERTEXT_SIZE    1568
#define QUAC_KYBER1024_SHARED_SECRET_SIZE 32
```

### Key Sizes - ML-DSA (Dilithium)

| Algorithm | Public Key | Secret Key | Signature |
|-----------|------------|------------|-----------|
| Dilithium2 | 1312 | 2528 | 2420 |
| Dilithium3 | 1952 | 4000 | 3293 |
| Dilithium5 | 2592 | 4864 | 4595 |

```c
#define QUAC_DILITHIUM2_PUBLIC_KEY_SIZE  1312
#define QUAC_DILITHIUM2_SECRET_KEY_SIZE  2528
#define QUAC_DILITHIUM2_SIGNATURE_SIZE   2420

#define QUAC_DILITHIUM3_PUBLIC_KEY_SIZE  1952
#define QUAC_DILITHIUM3_SECRET_KEY_SIZE  4000
#define QUAC_DILITHIUM3_SIGNATURE_SIZE   3293

#define QUAC_DILITHIUM5_PUBLIC_KEY_SIZE  2592
#define QUAC_DILITHIUM5_SECRET_KEY_SIZE  4864
#define QUAC_DILITHIUM5_SIGNATURE_SIZE   4595
```

### Key Sizes - SLH-DSA (SPHINCS+)

| Algorithm | Public Key | Secret Key | Signature |
|-----------|------------|------------|-----------|
| SHA2-128s | 32 | 64 | 7856 |
| SHA2-128f | 32 | 64 | 17088 |
| SHA2-192s | 48 | 96 | 16224 |
| SHA2-192f | 48 | 96 | 35664 |
| SHA2-256s | 64 | 128 | 29792 |
| SHA2-256f | 64 | 128 | 49856 |

### Maximum Sizes

```c
#define QUAC_MAX_PUBLIC_KEY_SIZE    2592   // Dilithium5
#define QUAC_MAX_SECRET_KEY_SIZE    4864   // Dilithium5
#define QUAC_MAX_CIPHERTEXT_SIZE    1568   // Kyber1024
#define QUAC_MAX_SIGNATURE_SIZE     49856  // SPHINCS+ SHA2-256f
#define QUAC_MAX_SHARED_SECRET_SIZE 32
```

### Device Limits

```c
#define QUAC_MAX_DEVICES      16
#define QUAC_MAX_BATCH_SIZE   1024
#define QUAC_MAX_KEY_SLOTS    256
```

---

## Core API

### Initialization

#### quac_init

```c
quac_result_t quac_init(const quac_init_options_t *options);
```

Initialize the SDK. Must be called before any other function.

**Parameters:**
- `options` - Initialization options (NULL for defaults)

**Returns:** `QUAC_SUCCESS` or error code

**Example:**
```c
// Default initialization
quac_init(NULL);

// Custom initialization
quac_init_options_t opts = {0};
opts.struct_size = sizeof(opts);
opts.flags = QUAC_INIT_FIPS_MODE;
quac_init(&opts);
```

---

#### quac_shutdown

```c
void quac_shutdown(void);
```

Shutdown the SDK and release all resources. All device handles become invalid.

---

#### quac_is_initialized

```c
bool quac_is_initialized(void);
```

Check if SDK is initialized.

**Returns:** `true` if initialized

---

#### quac_version_string

```c
const char *quac_version_string(void);
```

Get SDK version as string.

**Returns:** Version string (e.g., "1.0.0")

---

#### quac_version_hex

```c
uint32_t quac_version_hex(void);
```

Get SDK version as hexadecimal.

**Returns:** Version as hex (e.g., `0x010000` for 1.0.0)

---

### Device Management

#### quac_device_count

```c
quac_result_t quac_device_count(uint32_t *count);
```

Get number of available devices.

**Parameters:**
- `count` - Pointer to receive device count

**Returns:** `QUAC_SUCCESS` or error code

---

#### quac_open

```c
quac_result_t quac_open(uint32_t index, quac_device_t *device);
```

Open a device by index.

**Parameters:**
- `index` - Device index (0 to count-1)
- `device` - Pointer to receive device handle

**Returns:** `QUAC_SUCCESS` or error code

---

#### quac_open_by_serial

```c
quac_result_t quac_open_by_serial(const char *serial, quac_device_t *device);
```

Open a device by serial number.

**Parameters:**
- `serial` - Device serial number string
- `device` - Pointer to receive device handle

**Returns:** `QUAC_SUCCESS` or error code

---

#### quac_close

```c
quac_result_t quac_close(quac_device_t device);
```

Close a device handle.

**Parameters:**
- `device` - Device handle to close

**Returns:** `QUAC_SUCCESS` or error code

---

#### quac_get_info

```c
quac_result_t quac_get_info(quac_device_t device, quac_device_info_t *info);
```

Get device information.

**Parameters:**
- `device` - Device handle
- `info` - Pointer to receive device information

**Returns:** `QUAC_SUCCESS` or error code

---

#### quac_reset

```c
quac_result_t quac_reset(quac_device_t device);
```

Perform a soft reset of the device.

**Parameters:**
- `device` - Device handle

**Returns:** `QUAC_SUCCESS` or error code

---

## KEM Operations

### quac_kem_keygen

```c
quac_result_t quac_kem_keygen(
    quac_device_t device,
    quac_algorithm_t algorithm,
    uint8_t *public_key, size_t pk_size,
    uint8_t *secret_key, size_t sk_size
);
```

Generate a KEM key pair.

**Parameters:**
- `device` - Device handle
- `algorithm` - KEM algorithm (`QUAC_ALGORITHM_KYBER*`)
- `public_key` - Buffer for public key
- `pk_size` - Size of public key buffer
- `secret_key` - Buffer for secret key
- `sk_size` - Size of secret key buffer

**Returns:** `QUAC_SUCCESS` or error code

**Example:**
```c
uint8_t pk[QUAC_KYBER768_PUBLIC_KEY_SIZE];
uint8_t sk[QUAC_KYBER768_SECRET_KEY_SIZE];

result = quac_kem_keygen(device, QUAC_ALGORITHM_KYBER768,
                         pk, sizeof(pk), sk, sizeof(sk));
```

---

### quac_kem_encaps

```c
quac_result_t quac_kem_encaps(
    quac_device_t device,
    quac_algorithm_t algorithm,
    const uint8_t *public_key, size_t pk_size,
    uint8_t *ciphertext, size_t ct_size,
    uint8_t *shared_secret, size_t ss_size
);
```

Encapsulate a shared secret.

**Parameters:**
- `device` - Device handle
- `algorithm` - KEM algorithm
- `public_key` - Recipient's public key
- `pk_size` - Public key size
- `ciphertext` - Buffer for ciphertext
- `ct_size` - Ciphertext buffer size
- `shared_secret` - Buffer for shared secret
- `ss_size` - Shared secret buffer size

**Returns:** `QUAC_SUCCESS` or error code

---

### quac_kem_decaps

```c
quac_result_t quac_kem_decaps(
    quac_device_t device,
    quac_algorithm_t algorithm,
    const uint8_t *ciphertext, size_t ct_size,
    const uint8_t *secret_key, size_t sk_size,
    uint8_t *shared_secret, size_t ss_size
);
```

Decapsulate a shared secret.

**Parameters:**
- `device` - Device handle
- `algorithm` - KEM algorithm
- `ciphertext` - Ciphertext from encapsulation
- `ct_size` - Ciphertext size
- `secret_key` - Recipient's secret key
- `sk_size` - Secret key size
- `shared_secret` - Buffer for shared secret
- `ss_size` - Shared secret buffer size

**Returns:** `QUAC_SUCCESS` or error code

---

### quac_kem_sizes

```c
quac_result_t quac_kem_sizes(
    quac_algorithm_t algorithm,
    size_t *pk_size,
    size_t *sk_size,
    size_t *ct_size,
    size_t *ss_size
);
```

Get KEM algorithm sizes.

**Parameters:**
- `algorithm` - KEM algorithm
- `pk_size` - Receives public key size (may be NULL)
- `sk_size` - Receives secret key size (may be NULL)
- `ct_size` - Receives ciphertext size (may be NULL)
- `ss_size` - Receives shared secret size (may be NULL)

**Returns:** `QUAC_SUCCESS` or error code

---

## Signature Operations

### quac_sign_keygen

```c
quac_result_t quac_sign_keygen(
    quac_device_t device,
    quac_algorithm_t algorithm,
    uint8_t *public_key, size_t pk_size,
    uint8_t *secret_key, size_t sk_size
);
```

Generate a signature key pair.

**Parameters:**
- `device` - Device handle
- `algorithm` - Signature algorithm (`QUAC_ALGORITHM_DILITHIUM*` or `QUAC_ALGORITHM_SPHINCS*`)
- `public_key` - Buffer for public key
- `pk_size` - Public key buffer size
- `secret_key` - Buffer for secret key
- `sk_size` - Secret key buffer size

**Returns:** `QUAC_SUCCESS` or error code

---

### quac_sign

```c
quac_result_t quac_sign(
    quac_device_t device,
    quac_algorithm_t algorithm,
    const uint8_t *secret_key, size_t sk_size,
    const uint8_t *message, size_t msg_size,
    uint8_t *signature, size_t sig_size,
    size_t *sig_len
);
```

Sign a message.

**Parameters:**
- `device` - Device handle
- `algorithm` - Signature algorithm
- `secret_key` - Signing key
- `sk_size` - Secret key size
- `message` - Message to sign
- `msg_size` - Message size
- `signature` - Buffer for signature
- `sig_size` - Signature buffer size
- `sig_len` - Receives actual signature length (may be NULL)

**Returns:** `QUAC_SUCCESS` or error code

---

### quac_verify

```c
quac_result_t quac_verify(
    quac_device_t device,
    quac_algorithm_t algorithm,
    const uint8_t *public_key, size_t pk_size,
    const uint8_t *message, size_t msg_size,
    const uint8_t *signature, size_t sig_size
);
```

Verify a signature.

**Parameters:**
- `device` - Device handle
- `algorithm` - Signature algorithm
- `public_key` - Verification key
- `pk_size` - Public key size
- `message` - Original message
- `msg_size` - Message size
- `signature` - Signature to verify
- `sig_size` - Signature size

**Returns:** `QUAC_SUCCESS` if valid, `QUAC_ERROR_VERIFICATION_FAILED` if invalid

---

### quac_sign_sizes

```c
quac_result_t quac_sign_sizes(
    quac_algorithm_t algorithm,
    size_t *pk_size,
    size_t *sk_size,
    size_t *sig_size
);
```

Get signature algorithm sizes.

**Parameters:**
- `algorithm` - Signature algorithm
- `pk_size` - Receives public key size (may be NULL)
- `sk_size` - Receives secret key size (may be NULL)
- `sig_size` - Receives maximum signature size (may be NULL)

**Returns:** `QUAC_SUCCESS` or error code

---

## Random Number Generation

### quac_random_bytes

```c
quac_result_t quac_random_bytes(
    quac_device_t device,
    uint8_t *buffer,
    size_t length
);
```

Generate random bytes from hardware QRNG.

**Parameters:**
- `device` - Device handle
- `buffer` - Buffer to receive random bytes
- `length` - Number of bytes to generate

**Returns:** `QUAC_SUCCESS` or error code

**Example:**
```c
uint8_t nonce[32];
quac_random_bytes(device, nonce, sizeof(nonce));
```

---

### quac_random_available

```c
quac_result_t quac_random_available(
    quac_device_t device,
    uint32_t *bits
);
```

Get available entropy in bits.

**Parameters:**
- `device` - Device handle
- `bits` - Receives available entropy

**Returns:** `QUAC_SUCCESS` or error code

---

### quac_random_reseed

```c
quac_result_t quac_random_reseed(
    quac_device_t device,
    const uint8_t *seed,
    size_t seed_len
);
```

Reseed the QRNG with additional entropy.

**Parameters:**
- `device` - Device handle
- `seed` - Additional seed data (may be NULL)
- `seed_len` - Seed length

**Returns:** `QUAC_SUCCESS` or error code

---

## Key Management

### quac_key_generate

```c
quac_result_t quac_key_generate(
    quac_device_t device,
    const quac_key_attr_t *attr,
    quac_key_handle_t *handle
);
```

Generate and store a key pair on device.

**Parameters:**
- `device` - Device handle
- `attr` - Key attributes
- `handle` - Receives key handle

**Returns:** `QUAC_SUCCESS` or error code

---

### quac_key_import

```c
quac_result_t quac_key_import(
    quac_device_t device,
    const quac_key_attr_t *attr,
    const uint8_t *key_data, size_t key_len,
    quac_key_handle_t *handle
);
```

Import a key to device storage.

**Parameters:**
- `device` - Device handle
- `attr` - Key attributes
- `key_data` - Key data to import
- `key_len` - Key data length
- `handle` - Receives key handle

**Returns:** `QUAC_SUCCESS` or error code

---

### quac_key_export

```c
quac_result_t quac_key_export(
    quac_device_t device,
    quac_key_handle_t handle,
    uint8_t *key_data, size_t key_len,
    size_t *actual_len
);
```

Export a key from device storage.

**Parameters:**
- `device` - Device handle
- `handle` - Key handle
- `key_data` - Buffer for key data
- `key_len` - Buffer size
- `actual_len` - Receives actual key length

**Returns:** `QUAC_SUCCESS` or `QUAC_ERROR_KEY_EXPORT_DENIED`

---

### quac_key_destroy

```c
quac_result_t quac_key_destroy(
    quac_device_t device,
    quac_key_handle_t handle
);
```

Delete a key from device storage.

**Parameters:**
- `device` - Device handle
- `handle` - Key handle

**Returns:** `QUAC_SUCCESS` or error code

---

### quac_key_get_attr

```c
quac_result_t quac_key_get_attr(
    quac_device_t device,
    quac_key_handle_t handle,
    quac_key_attr_t *attr
);
```

Get key attributes.

**Parameters:**
- `device` - Device handle
- `handle` - Key handle
- `attr` - Receives key attributes

**Returns:** `QUAC_SUCCESS` or error code

---

## Asynchronous Operations

### quac_async_kem_keygen

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

Submit async KEM key generation.

**Parameters:**
- `device` - Device handle
- `algorithm` - KEM algorithm
- `public_key` - Buffer for public key
- `pk_size` - Public key buffer size
- `secret_key` - Buffer for secret key
- `sk_size` - Secret key buffer size
- `callback` - Completion callback (may be NULL)
- `user_data` - User context for callback
- `job_id` - Receives job identifier

**Returns:** `QUAC_SUCCESS` or error code

---

### quac_async_wait

```c
quac_result_t quac_async_wait(
    quac_device_t device,
    quac_job_id_t job_id,
    uint32_t timeout_ms
);
```

Wait for async job completion.

**Parameters:**
- `device` - Device handle
- `job_id` - Job identifier
- `timeout_ms` - Timeout in milliseconds (0 = infinite)

**Returns:** `QUAC_SUCCESS` if completed, `QUAC_ERROR_TIMEOUT` on timeout

---

### quac_async_poll

```c
quac_result_t quac_async_poll(
    quac_device_t device,
    quac_job_id_t job_id,
    bool *completed
);
```

Poll job completion status.

**Parameters:**
- `device` - Device handle
- `job_id` - Job identifier
- `completed` - Receives completion status

**Returns:** `QUAC_SUCCESS` or error code

---

### quac_async_cancel

```c
quac_result_t quac_async_cancel(
    quac_device_t device,
    quac_job_id_t job_id
);
```

Cancel a pending async job.

**Parameters:**
- `device` - Device handle
- `job_id` - Job identifier

**Returns:** `QUAC_SUCCESS` or error code

---

## Batch Operations

### quac_batch_submit

```c
quac_result_t quac_batch_submit(
    quac_device_t device,
    quac_batch_item_t *items,
    size_t count
);
```

Submit a batch of operations.

**Parameters:**
- `device` - Device handle
- `items` - Array of batch items
- `count` - Number of items

**Returns:** `QUAC_SUCCESS` if all succeeded, `QUAC_ERROR_BATCH_PARTIAL` if some failed

---

### quac_batch_wait

```c
quac_result_t quac_batch_wait(
    quac_device_t device,
    uint32_t timeout_ms
);
```

Wait for batch completion.

**Parameters:**
- `device` - Device handle
- `timeout_ms` - Timeout in milliseconds

**Returns:** `QUAC_SUCCESS` or `QUAC_ERROR_TIMEOUT`

---

## Diagnostics

### quac_self_test

```c
quac_result_t quac_self_test(quac_device_t device);
```

Run device self-tests (FIPS-required).

**Parameters:**
- `device` - Device handle

**Returns:** `QUAC_SUCCESS` if all tests pass

---

### quac_get_health

```c
quac_result_t quac_get_health(
    quac_device_t device,
    quac_device_status_t *status
);
```

Get device health status.

**Parameters:**
- `device` - Device handle
- `status` - Receives status flags

**Returns:** `QUAC_SUCCESS` or error code

---

### quac_get_temperature

```c
quac_result_t quac_get_temperature(
    quac_device_t device,
    int32_t *celsius
);
```

Get device temperature.

**Parameters:**
- `device` - Device handle
- `celsius` - Receives temperature in Celsius

**Returns:** `QUAC_SUCCESS` or error code

---

## Error Handling

### Result Macros

```c
#define QUAC_SUCCEEDED(r)  ((r) == QUAC_SUCCESS)
#define QUAC_FAILED(r)     ((r) != QUAC_SUCCESS)
```

### quac_error_string

```c
const char *quac_error_string(quac_result_t result);
```

Get human-readable error message.

**Parameters:**
- `result` - Result code

**Returns:** Error message string (never NULL)

---

### quac_get_last_error

```c
quac_result_t quac_get_last_error(void);
```

Get last error for current thread.

**Returns:** Last error code

---

### quac_get_last_error_detail

```c
quac_result_t quac_get_last_error_detail(char *buffer, size_t size);
```

Get extended error information.

**Parameters:**
- `buffer` - Buffer for error message
- `size` - Buffer size

**Returns:** `QUAC_SUCCESS` if extended info available

---

### Error Codes

| Code | Name | Description |
|------|------|-------------|
| 0x0000 | `QUAC_SUCCESS` | Operation completed successfully |
| 0x0001 | `QUAC_ERROR_UNKNOWN` | Unknown error |
| 0x0002 | `QUAC_ERROR_NOT_INITIALIZED` | SDK not initialized |
| 0x0003 | `QUAC_ERROR_ALREADY_INITIALIZED` | SDK already initialized |
| 0x0004 | `QUAC_ERROR_INVALID_PARAMETER` | Invalid parameter |
| 0x0005 | `QUAC_ERROR_NULL_POINTER` | Null pointer provided |
| 0x0006 | `QUAC_ERROR_BUFFER_TOO_SMALL` | Output buffer too small |
| 0x0007 | `QUAC_ERROR_OUT_OF_MEMORY` | Memory allocation failed |
| 0x0008 | `QUAC_ERROR_NOT_SUPPORTED` | Operation not supported |
| 0x0009 | `QUAC_ERROR_TIMEOUT` | Operation timed out |
| 0x0100 | `QUAC_ERROR_NO_DEVICE` | No device found |
| 0x0101 | `QUAC_ERROR_DEVICE_NOT_FOUND` | Specified device not found |
| 0x0102 | `QUAC_ERROR_DEVICE_OPEN_FAILED` | Failed to open device |
| 0x0104 | `QUAC_ERROR_DEVICE_ERROR` | General device error |
| 0x0200 | `QUAC_ERROR_INVALID_ALGORITHM` | Invalid algorithm |
| 0x0201 | `QUAC_ERROR_INVALID_KEY` | Invalid key data |
| 0x0205 | `QUAC_ERROR_DECAPSULATION_FAILED` | Decapsulation failed |
| 0x0206 | `QUAC_ERROR_VERIFICATION_FAILED` | Signature verification failed |
| 0x0207 | `QUAC_ERROR_KEY_GENERATION_FAILED` | Key generation failed |
| 0x0208 | `QUAC_ERROR_SIGNING_FAILED` | Signing failed |
| 0x0300 | `QUAC_ERROR_KEY_NOT_FOUND` | Key not found |
| 0x0302 | `QUAC_ERROR_KEY_SLOT_FULL` | No available key slots |
| 0x0307 | `QUAC_ERROR_KEY_EXPORT_DENIED` | Key export not permitted |
| 0x0400 | `QUAC_ERROR_ENTROPY_DEPLETED` | Entropy pool depleted |
| 0x0402 | `QUAC_ERROR_QRNG_FAILURE` | QRNG hardware failure |
| 0x0500 | `QUAC_ERROR_INVALID_JOB_ID` | Invalid job identifier |
| 0x0504 | `QUAC_ERROR_QUEUE_FULL` | Job queue is full |
| 0x0505 | `QUAC_ERROR_BATCH_PARTIAL` | Batch partially completed |
| 0x0605 | `QUAC_ERROR_SELF_TEST_FAILED` | Self-test failed |

---

## Simulator API

### quac_set_simulator_mode

```c
quac_result_t quac_set_simulator_mode(bool use_simulator);
```

Enable or disable simulator mode. Must be called before `quac_init()`.

**Parameters:**
- `use_simulator` - true to use simulator

**Returns:** `QUAC_SUCCESS` or error code

---

### quac_is_simulator

```c
bool quac_is_simulator(void);
```

Check if running in simulator mode.

**Returns:** true if using simulator

---

### quac_simulator_config

```c
quac_result_t quac_simulator_config(
    uint32_t latency_us,
    uint32_t throughput_ops
);
```

Configure simulator parameters.

**Parameters:**
- `latency_us` - Simulated operation latency (microseconds)
- `throughput_ops` - Simulated throughput (operations/second)

**Returns:** `QUAC_SUCCESS` or error code

---

## Algorithm Queries

### quac_is_algorithm_supported

```c
bool quac_is_algorithm_supported(
    quac_device_t device,
    quac_algorithm_t algorithm
);
```

Check if algorithm is supported.

**Parameters:**
- `device` - Device handle (NULL to check SDK support)
- `algorithm` - Algorithm to check

**Returns:** true if supported

---

### quac_algorithm_name

```c
const char *quac_algorithm_name(quac_algorithm_t algorithm);
```

Get algorithm name string.

**Parameters:**
- `algorithm` - Algorithm identifier

**Returns:** Algorithm name (e.g., "ML-KEM-768") or "Unknown"

---

## See Also

- [Installation Guide](../guides/installation.md)
- [Quick Start Guide](../guides/quick_start.md)
- [Programming Guide](../guides/programming_guide.md)
- [Simulator Guide](../guides/simulator_guide.md)
