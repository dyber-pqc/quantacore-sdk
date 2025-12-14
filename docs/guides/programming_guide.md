# Programming Guide

## QuantaCore SDK - Comprehensive Developer Reference

This guide provides in-depth coverage of the QuantaCore SDK APIs, best practices, and advanced usage patterns for the QUAC 100 Post-Quantum Cryptographic Accelerator.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [SDK Initialization](#sdk-initialization)
3. [Device Management](#device-management)
4. [ML-KEM (Kyber) Operations](#ml-kem-kyber-operations)
5. [ML-DSA (Dilithium) Operations](#ml-dsa-dilithium-operations)
6. [SLH-DSA (SPHINCS+) Operations](#slh-dsa-sphincs-operations)
7. [Quantum Random Number Generation](#quantum-random-number-generation)
8. [Key Management](#key-management)
9. [Asynchronous Operations](#asynchronous-operations)
10. [Batch Processing](#batch-processing)
11. [Diagnostics and Health Monitoring](#diagnostics-and-health-monitoring)
12. [Error Handling](#error-handling)
13. [Thread Safety](#thread-safety)
14. [Performance Optimization](#performance-optimization)
15. [Security Considerations](#security-considerations)

---

## Architecture Overview

### SDK Layer Structure

```
┌─────────────────────────────────────────┐
│           Application Layer             │
├─────────────────────────────────────────┤
│         QuantaCore SDK API              │
│  ┌─────────┬─────────┬─────────┬──────┐ │
│  │   KEM   │  Sign   │  QRNG   │ Key  │ │
│  │   API   │   API   │   API   │ Mgmt │ │
│  └────┬────┴────┬────┴────┬────┴──┬───┘ │
│       │         │         │       │     │
│  ┌────┴─────────┴─────────┴───────┴───┐ │
│  │     Async/Batch Processing Layer   │ │
│  └────────────────┬───────────────────┘ │
│                   │                     │
│  ┌────────────────┴───────────────────┐ │
│  │         DMA Engine Layer           │ │
│  └────────────────┬───────────────────┘ │
├───────────────────┼─────────────────────┤
│  ┌────────────────┴───────────────────┐ │
│  │       Kernel Driver (IOCTL)        │ │
│  └────────────────┬───────────────────┘ │
├───────────────────┼─────────────────────┤
│  ┌────────────────┴───────────────────┐ │
│  │     QUAC 100 Hardware / Simulator  │ │
│  └────────────────────────────────────┘ │
└─────────────────────────────────────────┘
```

### Header File Organization

| Header | Purpose |
|--------|---------|
| `quac100.h` | Main header - includes all public APIs |
| `quac100_types.h` | Type definitions, constants, result codes |
| `quac100_kem.h` | Extended KEM (Kyber) operations |
| `quac100_sign.h` | Extended signature operations |
| `quac100_random.h` | QRNG interface |
| `quac100_async.h` | Asynchronous operations |
| `quac100_batch.h` | Batch processing |
| `quac100_diag.h` | Diagnostics and health monitoring |
| `quac100_error.h` | Extended error handling |

For most applications, simply include the main header:

```c
#include <quac100.h>
```

---

## SDK Initialization

### Basic Initialization

```c
#include <quac100.h>

int main(void)
{
    quac_result_t result;
    
    /* Initialize with default options */
    result = quac_init(NULL);
    if (QUAC_FAILED(result)) {
        fprintf(stderr, "Init failed: %s\n", quac_error_string(result));
        return 1;
    }
    
    /* Your code here... */
    
    /* Shutdown when done */
    quac_shutdown();
    return 0;
}
```

### Custom Initialization Options

```c
#include <quac100.h>
#include <string.h>

/* Custom log callback */
void my_log_callback(int level, const char *message, void *user_data)
{
    const char *levels[] = {"ERROR", "WARN", "INFO", "DEBUG", "TRACE"};
    printf("[%s] %s\n", levels[level], message);
}

int main(void)
{
    quac_result_t result;
    quac_init_options_t options;
    
    /* Initialize options structure */
    memset(&options, 0, sizeof(options));
    options.struct_size = sizeof(options);
    
    /* Configure options */
    options.flags = QUAC_INIT_ASYNC_THREAD_POOL | QUAC_INIT_DEBUG_LOGGING;
    options.log_callback = my_log_callback;
    options.log_user_data = NULL;
    options.log_level = 3;  /* DEBUG level */
    options.async_thread_count = 4;  /* 4 worker threads */
    
    /* Initialize with custom options */
    result = quac_init(&options);
    if (QUAC_FAILED(result)) {
        return 1;
    }
    
    /* ... */
    
    quac_shutdown();
    return 0;
}
```

### Initialization Flags

| Flag | Description |
|------|-------------|
| `QUAC_INIT_DEFAULT` | Default settings |
| `QUAC_INIT_SIMULATOR` | Fall back to simulator if no hardware |
| `QUAC_INIT_FORCE_SIMULATOR` | Always use simulator |
| `QUAC_INIT_FIPS_MODE` | Enable FIPS 140-3 mode |
| `QUAC_INIT_NO_AUTO_DETECT` | Don't auto-detect devices |
| `QUAC_INIT_DEBUG_LOGGING` | Enable debug logging |
| `QUAC_INIT_ASYNC_THREAD_POOL` | Create async thread pool |

### Checking Initialization State

```c
/* Check if SDK is initialized */
if (quac_is_initialized()) {
    printf("SDK is ready\n");
}

/* Get version information */
printf("SDK Version: %s\n", quac_version_string());
printf("SDK Version (hex): 0x%08X\n", quac_version_hex());
```

---

## Device Management

### Opening Devices

```c
quac_device_t device;
quac_result_t result;

/* Open by index (0 = first device) */
result = quac_open(0, &device);
if (QUAC_FAILED(result)) {
    fprintf(stderr, "Failed to open device: %s\n", quac_error_string(result));
    return 1;
}

/* Or open by serial number */
result = quac_open_by_serial("QC100-2025-00001", &device);
```

### Device Enumeration

```c
uint32_t count;
quac_result_t result;

/* Get number of devices */
result = quac_device_count(&count);
if (QUAC_SUCCEEDED(result)) {
    printf("Found %u QUAC 100 device(s)\n", count);
}

/* Enumerate all devices */
for (uint32_t i = 0; i < count; i++) {
    quac_device_t dev;
    quac_device_info_t info;
    
    if (QUAC_SUCCEEDED(quac_open(i, &dev))) {
        info.struct_size = sizeof(info);
        quac_get_info(dev, &info);
        
        printf("Device %u: %s (Serial: %s)\n", 
               i, info.device_name, info.serial_number);
        printf("  Firmware: %d.%d.%d\n", 
               info.firmware_major, info.firmware_minor, info.firmware_patch);
        printf("  Temperature: %d°C\n", info.temperature_celsius);
        printf("  Operations: %lu completed, %lu failed\n",
               info.operations_completed, info.operations_failed);
        
        quac_close(dev);
    }
}
```

### Device Information Structure

```c
typedef struct quac_device_info_s {
    uint32_t struct_size;           /* Size of this structure */
    uint32_t device_index;          /* Device index (0-based) */
    char device_name[64];           /* Human-readable name */
    char serial_number[32];         /* Serial number */
    uint32_t vendor_id;             /* PCI vendor ID */
    uint32_t device_id;             /* PCI device ID */
    uint32_t subsystem_id;          /* PCI subsystem ID */
    uint8_t hardware_rev;           /* Hardware revision */
    uint8_t firmware_major;         /* Firmware major version */
    uint8_t firmware_minor;         /* Firmware minor version */
    uint8_t firmware_patch;         /* Firmware patch version */
    quac_device_caps_t capabilities; /* Device capabilities */
    quac_device_status_t status;    /* Current device status */
    uint32_t max_batch_size;        /* Maximum batch size */
    uint32_t max_pending_jobs;      /* Maximum pending async jobs */
    uint32_t key_slots_total;       /* Total key storage slots */
    uint32_t key_slots_used;        /* Used key storage slots */
    int32_t temperature_celsius;    /* Current temperature (°C) */
    uint32_t entropy_available;     /* Available entropy (bits) */
    uint64_t operations_completed;  /* Total operations completed */
    uint64_t operations_failed;     /* Total operations failed */
    uint64_t uptime_seconds;        /* Device uptime in seconds */
} quac_device_info_t;
```

### Device Capabilities

```c
quac_device_info_t info;
info.struct_size = sizeof(info);
quac_get_info(device, &info);

/* Check capabilities */
if (info.capabilities & QUAC_CAP_KEM_KYBER) {
    printf("Device supports ML-KEM (Kyber)\n");
}
if (info.capabilities & QUAC_CAP_SIGN_DILITHIUM) {
    printf("Device supports ML-DSA (Dilithium)\n");
}
if (info.capabilities & QUAC_CAP_SIGN_SPHINCS) {
    printf("Device supports SLH-DSA (SPHINCS+)\n");
}
if (info.capabilities & QUAC_CAP_QRNG) {
    printf("Device has hardware QRNG\n");
}
if (info.capabilities & QUAC_CAP_FIPS) {
    printf("Device is FIPS 140-3 certified\n");
}
if (info.capabilities & QUAC_CAP_SIMULATOR) {
    printf("This is a simulated device\n");
}
```

### Device Reset

```c
/* Soft reset - cancels pending operations */
result = quac_reset(device);
if (QUAC_FAILED(result)) {
    fprintf(stderr, "Reset failed: %s\n", quac_error_string(result));
}
```

---

## ML-KEM (Kyber) Operations

ML-KEM (Module-Lattice Key Encapsulation Mechanism), based on Kyber, provides post-quantum secure key exchange.

### Algorithm Selection

| Algorithm | Security Level | Public Key | Secret Key | Ciphertext | Shared Secret |
|-----------|---------------|------------|------------|------------|---------------|
| ML-KEM-512 | Level 1 | 800 B | 1,632 B | 768 B | 32 B |
| ML-KEM-768 | Level 3 | 1,184 B | 2,400 B | 1,088 B | 32 B |
| ML-KEM-1024 | Level 5 | 1,568 B | 3,168 B | 1,568 B | 32 B |

### Key Generation

```c
uint8_t public_key[QUAC_KYBER768_PUBLIC_KEY_SIZE];
uint8_t secret_key[QUAC_KYBER768_SECRET_KEY_SIZE];

result = quac_kem_keygen(device, QUAC_ALGORITHM_KYBER768,
                         public_key, sizeof(public_key),
                         secret_key, sizeof(secret_key));
if (QUAC_FAILED(result)) {
    fprintf(stderr, "Key generation failed: %s\n", quac_error_string(result));
}
```

### Getting Algorithm Sizes Dynamically

```c
size_t pk_size, sk_size, ct_size, ss_size;

result = quac_kem_sizes(QUAC_ALGORITHM_KYBER768, 
                        &pk_size, &sk_size, &ct_size, &ss_size);
if (QUAC_SUCCEEDED(result)) {
    printf("Public key: %zu bytes\n", pk_size);
    printf("Secret key: %zu bytes\n", sk_size);
    printf("Ciphertext: %zu bytes\n", ct_size);
    printf("Shared secret: %zu bytes\n", ss_size);
}

/* Allocate buffers dynamically */
uint8_t *public_key = malloc(pk_size);
uint8_t *secret_key = malloc(sk_size);
```

### Encapsulation

```c
uint8_t ciphertext[QUAC_KYBER768_CIPHERTEXT_SIZE];
uint8_t shared_secret[QUAC_KYBER768_SHARED_SECRET_SIZE];

result = quac_kem_encaps(device, QUAC_ALGORITHM_KYBER768,
                         public_key, sizeof(public_key),
                         ciphertext, sizeof(ciphertext),
                         shared_secret, sizeof(shared_secret));
if (QUAC_FAILED(result)) {
    if (result == QUAC_ERROR_INVALID_KEY) {
        fprintf(stderr, "Invalid public key\n");
    } else {
        fprintf(stderr, "Encapsulation failed: %s\n", quac_error_string(result));
    }
}
```

### Decapsulation

```c
uint8_t recovered_secret[QUAC_KYBER768_SHARED_SECRET_SIZE];

result = quac_kem_decaps(device, QUAC_ALGORITHM_KYBER768,
                         ciphertext, sizeof(ciphertext),
                         secret_key, sizeof(secret_key),
                         recovered_secret, sizeof(recovered_secret));
if (QUAC_FAILED(result)) {
    if (result == QUAC_ERROR_INVALID_CIPHERTEXT) {
        fprintf(stderr, "Invalid or corrupted ciphertext\n");
    } else if (result == QUAC_ERROR_DECAPSULATION_FAILED) {
        fprintf(stderr, "Decapsulation failed\n");
    }
}
```

### Extended KEM API

The `quac100_kem.h` header provides additional functionality:

```c
#include <quac100.h>

/* Allocate key pair structure */
quac_kem_keypair_t *keypair;
result = quac_kem_keypair_alloc(QUAC_ALGORITHM_KYBER768, &keypair);

/* Generate into structure */
result = quac_kem_keygen_ex(device, QUAC_ALGORITHM_KYBER768, keypair);

/* Compute fingerprint */
quac_kem_keypair_fingerprint(keypair);
printf("Key fingerprint: ");
for (int i = 0; i < 32; i++) {
    printf("%02x", keypair->fingerprint[i]);
}
printf("\n");

/* Validate keys */
result = quac_kem_validate_public_key(QUAC_ALGORITHM_KYBER768,
                                       public_key, pk_size);
if (result == QUAC_ERROR_INVALID_KEY) {
    fprintf(stderr, "Malformed public key\n");
}

/* Check key pair match */
result = quac_kem_check_keypair(QUAC_ALGORITHM_KYBER768,
                                 public_key, pk_size,
                                 secret_key, sk_size);
if (QUAC_FAILED(result)) {
    fprintf(stderr, "Key pair mismatch!\n");
}

/* Free key pair (securely zeroizes) */
quac_kem_keypair_free(keypair);
```

### Deterministic Key Generation

For testing or key recovery scenarios:

```c
/* WARNING: Seed must be kept secret and never reused */
uint8_t seed[64] = { /* 64 bytes of secure random seed */ };

result = quac_kem_keygen_deterministic(device, QUAC_ALGORITHM_KYBER768,
                                        seed,
                                        public_key, sizeof(public_key),
                                        secret_key, sizeof(secret_key));
```

---

## ML-DSA (Dilithium) Operations

ML-DSA (Module-Lattice Digital Signature Algorithm), based on Dilithium, provides post-quantum secure digital signatures.

### Algorithm Selection

| Algorithm | Security Level | Public Key | Secret Key | Signature |
|-----------|---------------|------------|------------|-----------|
| ML-DSA-44 | Level 2 | 1,312 B | 2,528 B | 2,420 B |
| ML-DSA-65 | Level 3 | 1,952 B | 4,000 B | 3,293 B |
| ML-DSA-87 | Level 5 | 2,592 B | 4,864 B | 4,595 B |

### Key Generation

```c
uint8_t public_key[QUAC_DILITHIUM3_PUBLIC_KEY_SIZE];
uint8_t secret_key[QUAC_DILITHIUM3_SECRET_KEY_SIZE];

result = quac_sign_keygen(device, QUAC_ALGORITHM_DILITHIUM3,
                          public_key, sizeof(public_key),
                          secret_key, sizeof(secret_key));
```

### Signing

```c
const uint8_t *message = (const uint8_t *)"Message to sign";
size_t msg_len = strlen((const char *)message);

uint8_t signature[QUAC_DILITHIUM3_SIGNATURE_SIZE];
size_t sig_len;

result = quac_sign(device, QUAC_ALGORITHM_DILITHIUM3,
                   secret_key, sizeof(secret_key),
                   message, msg_len,
                   signature, sizeof(signature), &sig_len);

if (QUAC_SUCCEEDED(result)) {
    printf("Generated %zu byte signature\n", sig_len);
}
```

### Verification

```c
result = quac_verify(device, QUAC_ALGORITHM_DILITHIUM3,
                     public_key, sizeof(public_key),
                     message, msg_len,
                     signature, sig_len);

if (result == QUAC_SUCCESS) {
    printf("Signature is VALID\n");
} else if (result == QUAC_ERROR_VERIFICATION_FAILED) {
    printf("Signature is INVALID\n");
} else {
    fprintf(stderr, "Verification error: %s\n", quac_error_string(result));
}
```

### Signing with Context String

FIPS 204 supports domain separation via context strings:

```c
quac_sign_options_t options;
memset(&options, 0, sizeof(options));
options.struct_size = sizeof(options);

/* Set context string (max 255 bytes) */
const char *context = "MyApplication-v1.0";
options.context = (const uint8_t *)context;
options.context_len = strlen(context);

uint8_t signature[QUAC_DILITHIUM3_SIGNATURE_SIZE];
size_t sig_len;

result = quac_sign_ex(device, QUAC_ALGORITHM_DILITHIUM3,
                      secret_key, sizeof(secret_key),
                      message, msg_len,
                      &options,
                      signature, sizeof(signature), &sig_len);

/* Verification must use same context */
result = quac_verify_ex(device, QUAC_ALGORITHM_DILITHIUM3,
                        public_key, sizeof(public_key),
                        message, msg_len,
                        &options,
                        signature, sig_len);
```

### Pre-hashed Signing (HashML-DSA)

For signing large messages efficiently:

```c
#include <openssl/sha.h>

/* Hash the message first */
uint8_t hash[SHA512_DIGEST_LENGTH];
SHA512(message, msg_len, hash);

/* Sign the hash */
result = quac_sign_prehashed(device, QUAC_ALGORITHM_DILITHIUM3,
                              secret_key, sizeof(secret_key),
                              hash, sizeof(hash),
                              QUAC_ALGORITHM_SHA512,  /* Hash algorithm used */
                              NULL, 0,  /* No context */
                              signature, sizeof(signature), &sig_len);

/* Verify the hash */
result = quac_verify_prehashed(device, QUAC_ALGORITHM_DILITHIUM3,
                                public_key, sizeof(public_key),
                                hash, sizeof(hash),
                                QUAC_ALGORITHM_SHA512,
                                NULL, 0,
                                signature, sig_len);
```

---

## SLH-DSA (SPHINCS+) Operations

SLH-DSA (Stateless Hash-Based Digital Signature Algorithm), based on SPHINCS+, provides hash-based post-quantum signatures with minimal security assumptions.

### Algorithm Variants

| Variant | Security | Public Key | Secret Key | Signature | Speed |
|---------|----------|------------|------------|-----------|-------|
| SHA2-128s | Level 1 | 32 B | 64 B | 7,856 B | Slow |
| SHA2-128f | Level 1 | 32 B | 64 B | 17,088 B | Fast |
| SHA2-192s | Level 3 | 48 B | 96 B | 16,224 B | Slow |
| SHA2-192f | Level 3 | 48 B | 96 B | 35,664 B | Fast |
| SHA2-256s | Level 5 | 64 B | 128 B | 29,792 B | Slow |
| SHA2-256f | Level 5 | 64 B | 128 B | 49,856 B | Fast |

The 's' (small) variants produce smaller signatures but sign slower.
The 'f' (fast) variants sign faster but produce larger signatures.

### Usage

```c
/* Use small signatures for bandwidth-constrained applications */
uint8_t pk[QUAC_SPHINCS_SHA2_128S_PUBLIC_KEY_SIZE];
uint8_t sk[QUAC_SPHINCS_SHA2_128S_SECRET_KEY_SIZE];
uint8_t sig[QUAC_SPHINCS_SHA2_128S_SIGNATURE_SIZE];
size_t sig_len;

result = quac_sign_keygen(device, QUAC_ALGORITHM_SPHINCS_SHA2_128S,
                          pk, sizeof(pk), sk, sizeof(sk));

result = quac_sign(device, QUAC_ALGORITHM_SPHINCS_SHA2_128S,
                   sk, sizeof(sk),
                   message, msg_len,
                   sig, sizeof(sig), &sig_len);

/* Or use fast signing for performance-critical applications */
uint8_t sig_fast[QUAC_SPHINCS_SHA2_128F_SIGNATURE_SIZE];
result = quac_sign(device, QUAC_ALGORITHM_SPHINCS_SHA2_128F,
                   sk, sizeof(sk),
                   message, msg_len,
                   sig_fast, sizeof(sig_fast), &sig_len);
```

---

## Quantum Random Number Generation

The QUAC 100 includes hardware quantum random number generators (QRNG) providing true randomness.

### Basic Random Generation

```c
uint8_t random_bytes[256];

result = quac_random_bytes(device, random_bytes, sizeof(random_bytes));
if (QUAC_FAILED(result)) {
    if (result == QUAC_ERROR_ENTROPY_DEPLETED) {
        fprintf(stderr, "Entropy pool depleted - wait and retry\n");
    } else if (result == QUAC_ERROR_QRNG_FAILURE) {
        fprintf(stderr, "QRNG hardware failure\n");
    }
}
```

### Checking Available Entropy

```c
uint32_t entropy_bits;
result = quac_random_available(device, &entropy_bits);
if (QUAC_SUCCEEDED(result)) {
    printf("Available entropy: %u bits\n", entropy_bits);
}
```

### Quality Levels

```c
/* Standard quality (default) - full entropy conditioning */
result = quac_random_bytes_ex(device, buffer, length,
                              QUAC_RANDOM_QUALITY_STANDARD);

/* High quality - extra mixing and health checks */
result = quac_random_bytes_ex(device, buffer, length,
                              QUAC_RANDOM_QUALITY_HIGH);

/* Maximum quality - multiple independent sources XORed */
result = quac_random_bytes_ex(device, buffer, length,
                              QUAC_RANDOM_QUALITY_MAX);

/* Fast quality - for nonces/IVs */
result = quac_random_bytes_ex(device, buffer, length,
                              QUAC_RANDOM_QUALITY_FAST);
```

### Typed Random Generation

```c
uint32_t rand32;
uint64_t rand64;
double rand_double;
uint64_t rand_range;

/* Generate typed values */
quac_random_uint32(device, &rand32);
quac_random_uint64(device, &rand64);
quac_random_double(device, &rand_double);  /* [0.0, 1.0) */

/* Random in range [0, max) */
quac_random_range(device, 100, &rand_range);  /* 0-99 */

/* Random in range [min, max] inclusive */
int64_t rand_inclusive;
quac_random_range_inclusive(device, -50, 50, &rand_inclusive);
```

### QRNG Health Monitoring

```c
/* Check if QRNG is healthy */
bool healthy;
quac_random_is_healthy(device, &healthy);
if (!healthy) {
    fprintf(stderr, "QRNG health check failed!\n");
}

/* Run full health tests */
quac_random_test_result_t test_result;
result = quac_random_run_tests(device, QUAC_RANDOM_TEST_ALL, &test_result);

if (test_result.overall_pass) {
    printf("All QRNG tests passed\n");
    printf("Estimated min-entropy: %.2f bits/sample\n", 
           test_result.min_entropy_estimate);
} else {
    fprintf(stderr, "QRNG tests failed!\n");
}

/* Get entropy source information */
quac_random_info_t info;
quac_random_get_info(device, &info);
printf("Active entropy sources: %u/%u\n", 
       info.active_sources, info.source_count);
printf("Pool available: %lu bits\n", info.pool_available_bits);
```

### Reseeding and Flushing

```c
/* Reseed with additional entropy */
uint8_t additional_seed[32] = { /* external entropy */ };
quac_random_reseed(device, additional_seed, sizeof(additional_seed));

/* Flush pool and refill (defense in depth) */
quac_random_flush(device);
```

---

## Key Management

The QUAC 100 supports on-device key storage with hardware protection.

### Generating Stored Keys

```c
quac_key_attr_t attr;
memset(&attr, 0, sizeof(attr));
attr.struct_size = sizeof(attr);
attr.algorithm = QUAC_ALGORITHM_KYBER768;
attr.type = QUAC_KEY_TYPE_KEYPAIR;
attr.usage = QUAC_KEY_USAGE_ENCAPSULATE | QUAC_KEY_USAGE_DECAPSULATE;
attr.extractable = false;  /* Key cannot be exported */
attr.persistent = true;    /* Survive reboots */
strncpy(attr.label, "my-key-pair", sizeof(attr.label) - 1);

quac_key_handle_t handle;
result = quac_key_generate(device, &attr, &handle);
if (QUAC_SUCCEEDED(result)) {
    printf("Key stored with handle: %lu\n", handle);
}
```

### Using Stored Keys

```c
/* Decapsulate using stored key - secret key never leaves device */
result = quac_kem_decaps_stored(device, handle,
                                 ciphertext, sizeof(ciphertext),
                                 shared_secret, sizeof(shared_secret));
```

### Importing Keys

```c
quac_key_attr_t attr;
memset(&attr, 0, sizeof(attr));
attr.struct_size = sizeof(attr);
attr.algorithm = QUAC_ALGORITHM_DILITHIUM3;
attr.type = QUAC_KEY_TYPE_SECRET;
attr.usage = QUAC_KEY_USAGE_SIGN;
attr.extractable = false;

quac_key_handle_t handle;
result = quac_key_import(device, &attr,
                         secret_key, sizeof(secret_key),
                         &handle);
```

### Exporting Keys

```c
/* Only works if key was created with extractable=true */
uint8_t exported_key[QUAC_MAX_SECRET_KEY_SIZE];
size_t actual_len;

result = quac_key_export(device, handle,
                         exported_key, sizeof(exported_key),
                         &actual_len);

if (result == QUAC_ERROR_KEY_EXPORT_DENIED) {
    fprintf(stderr, "Key is not extractable\n");
}
```

### Deleting Keys

```c
result = quac_key_destroy(device, handle);
if (QUAC_SUCCEEDED(result)) {
    printf("Key securely destroyed\n");
}
```

---

## Asynchronous Operations

For high-throughput applications, use async operations to overlap computation with other work.

### Basic Async Pattern

```c
quac_job_id_t job_id;

/* Submit async key generation */
result = quac_async_kem_keygen(device, QUAC_ALGORITHM_KYBER768,
                               public_key, sizeof(public_key),
                               secret_key, sizeof(secret_key),
                               NULL,      /* options */
                               &job_id);
if (QUAC_FAILED(result)) {
    fprintf(stderr, "Submit failed: %s\n", quac_error_string(result));
    return;
}

printf("Job submitted: %lu\n", job_id);

/* Do other work while job executes... */

/* Wait for completion */
result = quac_async_wait(device, job_id, 5000);  /* 5 second timeout */
if (result == QUAC_ERROR_TIMEOUT) {
    fprintf(stderr, "Job timed out\n");
    quac_async_cancel(device, job_id);
} else if (QUAC_SUCCEEDED(result)) {
    printf("Job completed successfully\n");
}
```

### Using Callbacks

```c
void my_callback(quac_device_t device, quac_job_id_t job_id,
                 quac_result_t result, void *user_data)
{
    int *completed = (int *)user_data;
    
    if (QUAC_SUCCEEDED(result)) {
        printf("Job %lu completed successfully\n", job_id);
    } else {
        fprintf(stderr, "Job %lu failed: %s\n", job_id, 
                quac_error_string(result));
    }
    
    (*completed)++;
}

int main(void)
{
    int completed = 0;
    quac_async_options_t options;
    
    memset(&options, 0, sizeof(options));
    options.struct_size = sizeof(options);
    options.callback = my_callback;
    options.user_data = &completed;
    options.priority = QUAC_PRIORITY_NORMAL;
    
    quac_job_id_t job_id;
    result = quac_async_kem_keygen(device, QUAC_ALGORITHM_KYBER768,
                                   public_key, sizeof(public_key),
                                   secret_key, sizeof(secret_key),
                                   &options, &job_id);
    
    /* Callback will be invoked on completion */
    while (completed == 0) {
        /* Do other work or sleep */
        usleep(1000);
    }
}
```

### Polling for Completion

```c
bool completed = false;

while (!completed) {
    result = quac_async_poll(device, job_id, &completed);
    if (QUAC_FAILED(result)) {
        break;
    }
    
    if (!completed) {
        /* Job still running - do other work */
        process_other_tasks();
    }
}
```

### Waiting for Multiple Jobs

```c
quac_job_id_t jobs[10];

/* Submit multiple jobs */
for (int i = 0; i < 10; i++) {
    quac_async_kem_keygen(device, QUAC_ALGORITHM_KYBER768,
                          public_keys[i], pk_size,
                          secret_keys[i], sk_size,
                          NULL, &jobs[i]);
}

/* Wait for first to complete */
quac_job_id_t completed_id;
result = quac_async_wait_any(device, jobs, 10, 10000, &completed_id);
printf("Job %lu completed first\n", completed_id);

/* Wait for all to complete */
quac_result_t results[10];
result = quac_async_wait_all(device, jobs, 10, 10000, results);
```

### Job Information

```c
quac_job_info_t info;
info.struct_size = sizeof(info);

result = quac_async_get_info(device, job_id, &info);
if (QUAC_SUCCEEDED(result)) {
    printf("Job status: %s\n", quac_job_status_string(info.status));
    printf("Queue time: %u µs\n", info.queue_time_us);
    printf("Execution time: %u µs\n", info.exec_time_us);
    printf("Progress: %u%%\n", info.progress_percent);
}
```

---

## Batch Processing

Batch operations maximize throughput by processing multiple operations in parallel.

### Basic Batch Execution

```c
#define BATCH_SIZE 100

quac_batch_kem_keygen_t items[BATCH_SIZE];

/* Setup batch items */
for (int i = 0; i < BATCH_SIZE; i++) {
    items[i].operation = QUAC_BATCH_OP_KEM_KEYGEN;
    items[i].algorithm = QUAC_ALGORITHM_KYBER768;
    items[i].flags = 0;
    items[i].public_key = public_keys[i];
    items[i].pk_size = QUAC_KYBER768_PUBLIC_KEY_SIZE;
    items[i].secret_key = secret_keys[i];
    items[i].sk_size = QUAC_KYBER768_SECRET_KEY_SIZE;
}

/* Execute batch */
quac_batch_result_t batch_result;
result = quac_batch_execute(device, (quac_batch_item_t *)items, BATCH_SIZE,
                            NULL, &batch_result);

printf("Batch completed: %u succeeded, %u failed\n",
       batch_result.completed, batch_result.failed);
printf("Throughput: %u ops/sec\n", batch_result.throughput_ops);

/* Check individual results */
for (int i = 0; i < BATCH_SIZE; i++) {
    if (QUAC_FAILED(items[i].result)) {
        fprintf(stderr, "Item %d failed: %s\n", i,
                quac_error_string(items[i].result));
    }
}
```

### Homogeneous Batch API

For batches where all operations use the same algorithm:

```c
uint8_t *public_keys[BATCH_SIZE];
uint8_t *secret_keys[BATCH_SIZE];
quac_result_t results[BATCH_SIZE];

/* Allocate buffers */
for (int i = 0; i < BATCH_SIZE; i++) {
    public_keys[i] = malloc(QUAC_KYBER768_PUBLIC_KEY_SIZE);
    secret_keys[i] = malloc(QUAC_KYBER768_SECRET_KEY_SIZE);
}

/* Batch key generation */
result = quac_batch_kem_keygen(device, QUAC_ALGORITHM_KYBER768,
                               public_keys, QUAC_KYBER768_PUBLIC_KEY_SIZE,
                               secret_keys, QUAC_KYBER768_SECRET_KEY_SIZE,
                               results, BATCH_SIZE);
```

### Batch Builder (Heterogeneous Batches)

For batches with mixed operation types:

```c
quac_batch_builder_t builder;

/* Create builder */
result = quac_batch_builder_create(device, 100, &builder);

/* Add different operations */
quac_batch_builder_add_kem_keygen(builder, QUAC_ALGORITHM_KYBER768,
                                  pk1, pk1_size, sk1, sk1_size, NULL);

quac_batch_builder_add_kem_encaps(builder, QUAC_ALGORITHM_KYBER768,
                                  pk2, pk2_size, ct, ct_size, ss, ss_size, NULL);

quac_batch_builder_add_sign(builder, QUAC_ALGORITHM_DILITHIUM3,
                            sk_sign, sk_sign_size, msg, msg_len,
                            sig, sig_size, &sig_len, NULL);

quac_batch_builder_add_random(builder, random_buf, 256, NULL);

/* Execute */
quac_batch_result_t result;
quac_batch_builder_execute(builder, NULL, &result);

/* Get individual results */
for (size_t i = 0; i < result.total_items; i++) {
    quac_result_t item_result;
    void *user_data;
    quac_batch_builder_get_result(builder, i, &item_result, &user_data);
}

/* Cleanup */
quac_batch_builder_destroy(builder);
```

### Batch Options

```c
quac_batch_options_t options;
memset(&options, 0, sizeof(options));
options.struct_size = sizeof(options);
options.flags = QUAC_BATCH_FLAG_STOP_ON_ERROR;  /* Stop at first failure */
options.timeout_ms = 30000;  /* 30 second timeout */
options.max_parallel = 16;   /* Limit parallelism */

result = quac_batch_execute(device, items, count, &options, &batch_result);
```

---

## Diagnostics and Health Monitoring

### Device Health Status

```c
quac_health_status_t health;
health.struct_size = sizeof(health);

result = quac_diag_get_health(device, &health);
if (QUAC_SUCCEEDED(result)) {
    printf("Health state: %s\n", quac_health_state_string(health.state));
    printf("Core temperature: %d°C\n", health.temp_core);
    printf("Memory temperature: %d°C\n", health.temp_memory);
    printf("Power draw: %u mW\n", health.power_draw_mw);
    printf("Available entropy: %u bits\n", health.entropy_available);
    printf("Operations completed: %lu\n", health.ops_completed);
    
    /* Check specific flags */
    if (health.flags & QUAC_HEALTH_FLAG_TEMP_CRITICAL) {
        fprintf(stderr, "WARNING: Temperature critical!\n");
    }
    if (health.flags & QUAC_HEALTH_FLAG_ENTROPY_LOW) {
        fprintf(stderr, "WARNING: Entropy pool low\n");
    }
}
```

### Self-Tests

```c
quac_self_test_summary_t summary;

/* Run FIPS startup tests */
result = quac_diag_self_test(device, QUAC_TEST_FIPS_STARTUP, &summary);

if (summary.overall_pass) {
    printf("All self-tests passed (%lu µs)\n", summary.total_duration_us);
} else {
    fprintf(stderr, "Self-tests FAILED!\n");
    fprintf(stderr, "Failed tests: 0x%08X\n", summary.tests_failed);
}

/* Run specific tests */
result = quac_diag_self_test(device, 
                             QUAC_TEST_KAT_KEM_KEYGEN | 
                             QUAC_TEST_ENTROPY_CONTINUOUS,
                             &summary);
```

### Performance Counters

```c
quac_perf_value_t counter;

/* Get specific counter */
result = quac_diag_get_counter(device, QUAC_PERF_KEM_KEYGEN_COUNT, &counter);
if (QUAC_SUCCEEDED(result)) {
    printf("KEM keygens: %lu\n", counter.value);
}

/* Get all counters */
quac_perf_value_t counters[64];
size_t count;
result = quac_diag_get_all_counters(device, counters, 64, &count);

for (size_t i = 0; i < count; i++) {
    printf("%s: %lu\n", counters[i].name, counters[i].value);
}

/* Reset counters */
quac_diag_reset_counters(device);
```

### Temperature Monitoring

```c
int32_t temp;
result = quac_diag_get_temperature(device, &temp);
printf("Temperature: %d°C\n", temp);

/* Register temperature alert callback */
void temp_alert(quac_device_t dev, uint32_t sensor_id, int32_t temp,
                quac_health_flags_t flags, void *user_data)
{
    fprintf(stderr, "Temperature alert! Sensor %u: %d°C\n", sensor_id, temp);
    if (flags & QUAC_HEALTH_FLAG_TEMP_CRITICAL) {
        /* Take action - reduce workload, etc. */
    }
}

quac_diag_set_temp_callback(device, temp_alert, NULL);
```

### Diagnostic Report

```c
/* Generate comprehensive diagnostic report */
char report[65536];
size_t report_size;

result = quac_diag_generate_report(device, report, sizeof(report), &report_size);
if (QUAC_SUCCEEDED(result)) {
    printf("%s\n", report);
}

/* Or export to file */
quac_diag_export_report(device, "/tmp/quac_diagnostic.txt");
```

---

## Error Handling

### Result Code Checking

```c
quac_result_t result = some_operation();

/* Simple check */
if (QUAC_FAILED(result)) {
    fprintf(stderr, "Operation failed: %s\n", quac_error_string(result));
}

/* Detailed error handling */
switch (result) {
    case QUAC_SUCCESS:
        /* Operation succeeded */
        break;
        
    case QUAC_ERROR_NOT_INITIALIZED:
        fprintf(stderr, "SDK not initialized - call quac_init() first\n");
        break;
        
    case QUAC_ERROR_NO_DEVICE:
        fprintf(stderr, "No QUAC 100 device found\n");
        break;
        
    case QUAC_ERROR_BUFFER_TOO_SMALL:
        fprintf(stderr, "Output buffer too small\n");
        break;
        
    case QUAC_ERROR_ENTROPY_DEPLETED:
        fprintf(stderr, "Entropy pool depleted - wait and retry\n");
        break;
        
    default:
        fprintf(stderr, "Error 0x%04X: %s\n", result, quac_error_string(result));
}
```

### Extended Error Information

```c
quac_error_info_t error_info;

/* Get detailed error information */
result = quac_error_get_info(&error_info);
if (QUAC_SUCCEEDED(result)) {
    printf("Error: %s\n", quac_error_name(error_info.result));
    printf("Category: %s\n", quac_error_category_name(error_info.category));
    printf("Severity: %s\n", quac_error_severity_name(error_info.severity));
    printf("Message: %s\n", error_info.message);
    printf("Detail: %s\n", error_info.detail);
    printf("OS Error: %u\n", error_info.os_error);
    
    if (quac_error_is_recoverable(error_info.result)) {
        printf("This error may be recoverable\n");
    }
}

/* Clear last error */
quac_error_clear();
```

### Error Callback

```c
void error_callback(const quac_error_info_t *info, void *user_data)
{
    /* Log all errors centrally */
    log_error("QUAC Error: [%s] %s - %s",
              quac_error_severity_name(info->severity),
              quac_error_name(info->result),
              info->message);
}

/* Register callback */
quac_error_set_callback(error_callback, NULL);

/* Filter to only critical errors */
quac_error_set_filter(QUAC_ERROR_FILTER_CRITICAL | QUAC_ERROR_FILTER_FATAL);
```

### Error Statistics

```c
quac_error_stats_t stats;
result = quac_error_get_stats(&stats);

printf("Total errors: %lu\n", stats.total_errors);
printf("  Warnings: %lu\n", stats.warnings);
printf("  Errors: %lu\n", stats.errors);
printf("  Critical: %lu\n", stats.critical);
printf("  Fatal: %lu\n", stats.fatal);
printf("Most frequent: %s (%lu times)\n",
       quac_error_string(stats.most_frequent),
       stats.most_frequent_count);

/* Reset statistics */
quac_error_reset_stats();
```

---

## Thread Safety

The QuantaCore SDK is thread-safe with the following guarantees:

### Thread-Safe Operations

- All cryptographic operations can be called from multiple threads
- Multiple threads can share the same device handle
- Async callbacks are invoked from a dedicated thread pool
- Internal synchronization protects shared state

### Best Practices

```c
/* Safe: Multiple threads using same device */
void *thread_func(void *arg) {
    quac_device_t device = (quac_device_t)arg;
    
    uint8_t pk[QUAC_KYBER768_PUBLIC_KEY_SIZE];
    uint8_t sk[QUAC_KYBER768_SECRET_KEY_SIZE];
    
    /* This is thread-safe */
    quac_kem_keygen(device, QUAC_ALGORITHM_KYBER768,
                    pk, sizeof(pk), sk, sizeof(sk));
    
    return NULL;
}

/* Create multiple threads using same device */
for (int i = 0; i < num_threads; i++) {
    pthread_create(&threads[i], NULL, thread_func, device);
}
```

### Initialization and Shutdown

```c
/* quac_init() and quac_shutdown() are NOT thread-safe */
/* Call these from a single thread only */

/* Safe pattern: Initialize once before creating threads */
quac_init(NULL);

/* Create worker threads... */

/* Wait for all threads to finish... */

/* Shutdown after all threads done */
quac_shutdown();
```

---

## Performance Optimization

### Batch Operations

Batch operations provide the best throughput:

| Batch Size | Relative Throughput |
|------------|---------------------|
| 1 | 1.0x (baseline) |
| 16 | 8-10x |
| 64 | 12-15x |
| 256 | 15-18x |
| 1024 | 18-20x |

### Async vs Sync

- Use sync operations for simple use cases
- Use async operations when you can overlap computation
- Use batch operations for maximum throughput

### Memory Alignment

```c
/* Align buffers to 64 bytes for best DMA performance */
uint8_t *buffer;
posix_memalign((void **)&buffer, 64, buffer_size);

/* Or use SDK allocation */
quac_dma_buffer_t dma_buf;
quac_dma_alloc_coherent(device, size, &dma_buf);
```

### Buffer Reuse

```c
/* Pre-allocate buffers for high-throughput scenarios */
typedef struct {
    uint8_t pk[QUAC_KYBER768_PUBLIC_KEY_SIZE];
    uint8_t sk[QUAC_KYBER768_SECRET_KEY_SIZE];
    uint8_t ct[QUAC_KYBER768_CIPHERTEXT_SIZE];
    uint8_t ss[QUAC_KYBER768_SHARED_SECRET_SIZE];
} key_buffers_t;

key_buffers_t *buffers = malloc(POOL_SIZE * sizeof(key_buffers_t));

/* Reuse buffers across operations */
```

---

## Security Considerations

### Key Handling

```c
/* 1. Use non-extractable stored keys when possible */
attr.extractable = false;
quac_key_generate(device, &attr, &handle);

/* 2. Securely zeroize sensitive data when done */
#include <string.h>
void secure_zero(void *ptr, size_t len) {
    volatile uint8_t *p = ptr;
    while (len--) *p++ = 0;
}

/* 3. Use keypair functions that handle cleanup */
quac_kem_keypair_free(keypair);  /* Securely zeroizes */

/* 4. Lock memory to prevent swapping (Linux) */
mlock(secret_key, sizeof(secret_key));
/* ... use key ... */
munlock(secret_key, sizeof(secret_key));
```

### Side-Channel Protection

The QUAC 100 hardware implements constant-time operations. For software-side protection:

```c
/* Use constant-time comparison */
int constant_time_compare(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}
```

### FIPS Mode

```c
/* Initialize in FIPS mode */
quac_init_options_t options = {0};
options.struct_size = sizeof(options);
options.flags = QUAC_INIT_FIPS_MODE;

result = quac_init(&options);

/* FIPS mode enforces:
 * - Mandatory self-tests at startup
 * - Approved algorithms only
 * - Minimum key sizes
 * - Continuous entropy testing
 */
```

---

## Next Steps

- **[Simulator Guide](simulator_guide.md)** - Development without hardware
- **[Cloudflare Integration](cloudflare_integration.md)** - Deploy at scale
- **[API Reference](../api/README.md)** - Complete function documentation
- **Examples** - See `examples/` directory

---

*Document Version: 1.0.0*
*Last Updated: 2025*
*Copyright © 2025 Dyber, Inc. All Rights Reserved.*
