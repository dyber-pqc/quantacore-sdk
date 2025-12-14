# Simulator Guide

## QuantaCore SDK - Development Without Hardware

The QuantaCore SDK includes a full-featured software simulator that allows you to develop, test, and prototype applications without requiring physical QUAC 100 hardware.

---

## Table of Contents

1. [Overview](#overview)
2. [Enabling the Simulator](#enabling-the-simulator)
3. [Simulator Configuration](#simulator-configuration)
4. [Behavioral Accuracy](#behavioral-accuracy)
5. [Performance Characteristics](#performance-characteristics)
6. [Testing Strategies](#testing-strategies)
7. [Limitations](#limitations)
8. [Transitioning to Hardware](#transitioning-to-hardware)

---

## Overview

The simulator provides a complete software implementation of the QUAC 100 APIs, enabling:

- **Development** without hardware investment
- **Testing** in CI/CD pipelines
- **Debugging** with full source-level access
- **Prototyping** new applications
- **Education** and learning the APIs

### What's Simulated

| Feature | Simulated | Notes |
|---------|-----------|-------|
| ML-KEM (Kyber) | ✅ Yes | All security levels |
| ML-DSA (Dilithium) | ✅ Yes | All security levels |
| SLH-DSA (SPHINCS+) | ✅ Yes | All variants |
| QRNG | ✅ Yes | Uses OS CSPRNG |
| Key Storage | ✅ Yes | In-memory only |
| Async Operations | ✅ Yes | Thread pool |
| Batch Operations | ✅ Yes | Serial or parallel |
| DMA | ❌ No | Memory copies |
| PCIe Interface | ❌ No | N/A |
| FIPS Mode | ⚠️ Partial | Tests pass, no certification |
| Temperature Sensors | ⚠️ Synthetic | Returns fixed values |

---

## Enabling the Simulator

### Method 1: Runtime Configuration

Enable the simulator programmatically before initialization:

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
    
    /* Now initialize normally */
    result = quac_init(NULL);
    if (QUAC_FAILED(result)) {
        return 1;
    }
    
    /* Verify we're in simulator mode */
    if (quac_is_simulator()) {
        printf("Running in simulator mode\n");
    }
    
    /* Rest of your application... */
    
    quac_shutdown();
    return 0;
}
```

### Method 2: Initialization Options

Use init options for more control:

```c
#include <quac100.h>
#include <string.h>

int main(void)
{
    quac_result_t result;
    quac_init_options_t options;
    
    memset(&options, 0, sizeof(options));
    options.struct_size = sizeof(options);
    
    /* Use simulator if no hardware found */
    options.flags = QUAC_INIT_SIMULATOR;
    
    /* Or force simulator even if hardware is present */
    options.flags = QUAC_INIT_FORCE_SIMULATOR;
    
    result = quac_init(&options);
    
    /* ... */
}
```

### Method 3: Environment Variable

Set an environment variable before running your application:

```bash
# Linux/macOS
export QUAC_USE_SIMULATOR=1
./my_application

# Windows
set QUAC_USE_SIMULATOR=1
my_application.exe
```

### Method 4: Automatic Fallback

The SDK can automatically fall back to the simulator when no hardware is detected:

```c
quac_init_options_t options = {0};
options.struct_size = sizeof(options);
options.flags = QUAC_INIT_SIMULATOR;  /* Fallback only */

result = quac_init(&options);

/* Check what we got */
quac_device_t device;
quac_open(0, &device);

quac_device_info_t info;
info.struct_size = sizeof(info);
quac_get_info(device, &info);

if (info.capabilities & QUAC_CAP_SIMULATOR) {
    printf("Using simulator (no hardware found)\n");
} else {
    printf("Using real QUAC 100 hardware\n");
}
```

---

## Simulator Configuration

### Performance Tuning

Configure simulated latency and throughput to match your target hardware:

```c
/* Set simulated operation latency (microseconds) */
/* and throughput (operations per second) */
result = quac_simulator_config(
    100,     /* latency_us: 100µs per operation */
    10000    /* throughput_ops: 10,000 ops/second */
);
```

### Realistic Hardware Modeling

Match the simulator to QUAC 100 hardware performance:

```c
/* QUAC 100 typical performance characteristics */
typedef struct {
    uint32_t latency_us;
    uint32_t throughput_ops;
} perf_config_t;

/* Kyber768 on QUAC 100 */
perf_config_t kyber768_perf = {
    .latency_us = 50,        /* ~50µs per operation */
    .throughput_ops = 20000  /* ~20K ops/sec */
};

/* Dilithium3 on QUAC 100 */
perf_config_t dilithium3_perf = {
    .latency_us = 100,       /* ~100µs per operation */
    .throughput_ops = 10000  /* ~10K ops/sec */
};

/* Configure for your primary workload */
quac_simulator_config(kyber768_perf.latency_us, 
                      kyber768_perf.throughput_ops);
```

### Entropy Configuration

The simulator uses the operating system's CSPRNG for random number generation:

```c
/* Simulator entropy always appears available */
uint32_t entropy_bits;
quac_random_available(device, &entropy_bits);
printf("Simulated entropy: %u bits\n", entropy_bits);

/* You can still call reseed (no-op in simulator) */
quac_random_reseed(device, NULL, 0);
```

---

## Behavioral Accuracy

### Cryptographic Correctness

The simulator implements the exact same cryptographic algorithms as the hardware:

```c
/* These operations are cryptographically identical to hardware */

/* ML-KEM (Kyber) - FIPS 203 compliant */
quac_kem_keygen(device, QUAC_ALGORITHM_KYBER768, pk, pk_size, sk, sk_size);
quac_kem_encaps(device, QUAC_ALGORITHM_KYBER768, pk, pk_size, ct, ct_size, ss, ss_size);
quac_kem_decaps(device, QUAC_ALGORITHM_KYBER768, ct, ct_size, sk, sk_size, ss, ss_size);

/* ML-DSA (Dilithium) - FIPS 204 compliant */
quac_sign_keygen(device, QUAC_ALGORITHM_DILITHIUM3, pk, pk_size, sk, sk_size);
quac_sign(device, QUAC_ALGORITHM_DILITHIUM3, sk, sk_size, msg, msg_len, sig, sig_size, &sig_len);
quac_verify(device, QUAC_ALGORITHM_DILITHIUM3, pk, pk_size, msg, msg_len, sig, sig_len);
```

**Guarantee**: Keys and signatures generated by the simulator are interoperable with hardware and vice versa.

### Error Handling

The simulator returns the same error codes as hardware:

```c
/* These error conditions are simulated accurately */

/* Buffer too small */
uint8_t small_buffer[10];
result = quac_kem_keygen(device, QUAC_ALGORITHM_KYBER768,
                         small_buffer, sizeof(small_buffer),  /* Too small! */
                         sk, sizeof(sk));
assert(result == QUAC_ERROR_BUFFER_TOO_SMALL);

/* Invalid algorithm */
result = quac_kem_keygen(device, QUAC_ALGORITHM_DILITHIUM3,  /* Not a KEM! */
                         pk, sizeof(pk), sk, sizeof(sk));
assert(result == QUAC_ERROR_INVALID_ALGORITHM);

/* Invalid ciphertext */
uint8_t corrupted_ct[QUAC_KYBER768_CIPHERTEXT_SIZE] = {0};
result = quac_kem_decaps(device, QUAC_ALGORITHM_KYBER768,
                         corrupted_ct, sizeof(corrupted_ct),
                         sk, sizeof(sk), ss, sizeof(ss));
/* Note: Kyber decaps always succeeds but returns garbage on invalid CT */
/* This is correct implicit rejection behavior per FIPS 203 */
```

### Async and Batch Behavior

The simulator accurately models async job lifecycle:

```c
quac_job_id_t job_id;

/* Submit job */
result = quac_async_kem_keygen(device, QUAC_ALGORITHM_KYBER768,
                               pk, pk_size, sk, sk_size,
                               NULL, &job_id);
assert(result == QUAC_SUCCESS);

/* Job goes through proper lifecycle */
quac_job_info_t info;
info.struct_size = sizeof(info);
quac_async_get_info(device, job_id, &info);

/* Initially PENDING or RUNNING */
assert(info.status == QUAC_JOB_STATUS_PENDING || 
       info.status == QUAC_JOB_STATUS_RUNNING);

/* Wait for completion */
quac_async_wait(device, job_id, 5000);

/* Now COMPLETED */
quac_async_get_info(device, job_id, &info);
assert(info.status == QUAC_JOB_STATUS_COMPLETED);
```

---

## Performance Characteristics

### Simulated vs Hardware Performance

| Operation | Hardware (QUAC 100) | Simulator | Ratio |
|-----------|--------------------:|----------:|------:|
| Kyber768 Keygen | ~50 µs | ~500 µs | 10x slower |
| Kyber768 Encaps | ~30 µs | ~400 µs | 13x slower |
| Kyber768 Decaps | ~40 µs | ~450 µs | 11x slower |
| Dilithium3 Keygen | ~100 µs | ~2,000 µs | 20x slower |
| Dilithium3 Sign | ~150 µs | ~3,000 µs | 20x slower |
| Dilithium3 Verify | ~100 µs | ~1,500 µs | 15x slower |
| SPHINCS+-128s Sign | ~50 ms | ~200 ms | 4x slower |
| QRNG (32 bytes) | ~1 µs | ~10 µs | 10x slower |

**Note**: Actual simulator performance depends on your CPU.

### Batch Processing

The simulator supports parallel batch execution using threads:

```c
/* Batch operations use thread pool in simulator */
quac_batch_options_t options = {0};
options.struct_size = sizeof(options);
options.max_parallel = 8;  /* Use up to 8 threads */

quac_batch_execute(device, items, count, &options, &result);
```

### Profiling

The simulator records accurate timing information:

```c
quac_job_info_t info;
info.struct_size = sizeof(info);
quac_async_get_info(device, job_id, &info);

printf("Queue time: %u µs\n", info.queue_time_us);
printf("Execution time: %u µs\n", info.exec_time_us);
printf("Total time: %u µs\n", info.total_time_us);
```

---

## Testing Strategies

### Unit Testing

Use the simulator in unit tests:

```c
/* test_kem.c */
#include <quac100.h>
#include <assert.h>
#include <string.h>

void test_kyber768_roundtrip(void)
{
    quac_device_t device;
    quac_result_t result;
    
    /* Setup */
    quac_set_simulator_mode(true);
    quac_init(NULL);
    quac_open(0, &device);
    
    /* Generate key pair */
    uint8_t pk[QUAC_KYBER768_PUBLIC_KEY_SIZE];
    uint8_t sk[QUAC_KYBER768_SECRET_KEY_SIZE];
    result = quac_kem_keygen(device, QUAC_ALGORITHM_KYBER768,
                             pk, sizeof(pk), sk, sizeof(sk));
    assert(result == QUAC_SUCCESS);
    
    /* Encapsulate */
    uint8_t ct[QUAC_KYBER768_CIPHERTEXT_SIZE];
    uint8_t ss1[QUAC_KYBER768_SHARED_SECRET_SIZE];
    result = quac_kem_encaps(device, QUAC_ALGORITHM_KYBER768,
                             pk, sizeof(pk), ct, sizeof(ct),
                             ss1, sizeof(ss1));
    assert(result == QUAC_SUCCESS);
    
    /* Decapsulate */
    uint8_t ss2[QUAC_KYBER768_SHARED_SECRET_SIZE];
    result = quac_kem_decaps(device, QUAC_ALGORITHM_KYBER768,
                             ct, sizeof(ct), sk, sizeof(sk),
                             ss2, sizeof(ss2));
    assert(result == QUAC_SUCCESS);
    
    /* Verify shared secrets match */
    assert(memcmp(ss1, ss2, QUAC_KYBER768_SHARED_SECRET_SIZE) == 0);
    
    /* Cleanup */
    quac_close(device);
    quac_shutdown();
    
    printf("test_kyber768_roundtrip PASSED\n");
}

int main(void)
{
    test_kyber768_roundtrip();
    return 0;
}
```

### Integration Testing

```c
/* test_tls_handshake.c */
void test_simulated_tls_handshake(void)
{
    quac_set_simulator_mode(true);
    quac_init(NULL);
    quac_device_t device;
    quac_open(0, &device);
    
    /* Simulate server key pair generation */
    uint8_t server_pk[QUAC_KYBER768_PUBLIC_KEY_SIZE];
    uint8_t server_sk[QUAC_KYBER768_SECRET_KEY_SIZE];
    quac_kem_keygen(device, QUAC_ALGORITHM_KYBER768,
                    server_pk, sizeof(server_pk),
                    server_sk, sizeof(server_sk));
    
    /* Simulate client encapsulation (client sends ct to server) */
    uint8_t ciphertext[QUAC_KYBER768_CIPHERTEXT_SIZE];
    uint8_t client_secret[QUAC_KYBER768_SHARED_SECRET_SIZE];
    quac_kem_encaps(device, QUAC_ALGORITHM_KYBER768,
                    server_pk, sizeof(server_pk),
                    ciphertext, sizeof(ciphertext),
                    client_secret, sizeof(client_secret));
    
    /* Simulate server decapsulation */
    uint8_t server_secret[QUAC_KYBER768_SHARED_SECRET_SIZE];
    quac_kem_decaps(device, QUAC_ALGORITHM_KYBER768,
                    ciphertext, sizeof(ciphertext),
                    server_sk, sizeof(server_sk),
                    server_secret, sizeof(server_secret));
    
    /* Both parties now have the same shared secret */
    assert(memcmp(client_secret, server_secret, 
                  QUAC_KYBER768_SHARED_SECRET_SIZE) == 0);
    
    /* Derive session keys using HKDF... */
    
    quac_close(device);
    quac_shutdown();
}
```

### CI/CD Integration

Example GitHub Actions workflow:

```yaml
# .github/workflows/test.yml
name: Test

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Install dependencies
      run: |
        sudo apt-get update
        sudo apt-get install -y cmake build-essential
    
    - name: Build SDK
      run: |
        mkdir build && cd build
        cmake .. -DENABLE_SIMULATOR=ON -DBUILD_TESTS=ON
        make -j$(nproc)
    
    - name: Run tests (simulator mode)
      run: |
        cd build
        export QUAC_USE_SIMULATOR=1
        ctest --output-on-failure
    
    - name: Run example programs
      run: |
        cd build/examples
        export QUAC_USE_SIMULATOR=1
        ./basic_example
        ./kem_example
        ./sign_example
```

### Fuzz Testing

```c
/* fuzz_kyber_decaps.c - libFuzzer harness */
#include <quac100.h>
#include <stdint.h>
#include <stddef.h>

static quac_device_t g_device;
static uint8_t g_sk[QUAC_KYBER768_SECRET_KEY_SIZE];
static int g_initialized = 0;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    quac_set_simulator_mode(true);
    quac_init(NULL);
    quac_open(0, &g_device);
    
    /* Generate a fixed key pair for fuzzing */
    uint8_t pk[QUAC_KYBER768_PUBLIC_KEY_SIZE];
    quac_kem_keygen(g_device, QUAC_ALGORITHM_KYBER768,
                    pk, sizeof(pk), g_sk, sizeof(g_sk));
    
    g_initialized = 1;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!g_initialized) return 0;
    
    /* Fuzz with arbitrary ciphertext data */
    if (size < QUAC_KYBER768_CIPHERTEXT_SIZE) return 0;
    
    uint8_t ss[QUAC_KYBER768_SHARED_SECRET_SIZE];
    
    /* This should never crash, even with malformed input */
    quac_kem_decaps(g_device, QUAC_ALGORITHM_KYBER768,
                    data, QUAC_KYBER768_CIPHERTEXT_SIZE,
                    g_sk, sizeof(g_sk),
                    ss, sizeof(ss));
    
    return 0;
}
```

---

## Limitations

### What's NOT Simulated

1. **DMA Performance**
   - Hardware uses zero-copy DMA
   - Simulator uses memory copies
   - No accurate DMA timing

2. **PCIe Interface**
   - No BAR mapping
   - No MSI-X interrupts
   - No SR-IOV

3. **Hardware Security**
   - No tamper detection
   - No secure key storage (keys in regular memory)
   - No hardware random number source

4. **Real-Time Characteristics**
   - Jitter differs from hardware
   - No deterministic timing guarantees

5. **Resource Limits**
   - Key slot limits may differ
   - Entropy pool behavior differs

### Behavioral Differences

```c
/* Temperature always returns fixed value */
int32_t temp;
quac_diag_get_temperature(device, &temp);
/* Returns 45°C in simulator */

/* Health status always OK */
quac_health_status_t health;
quac_diag_get_health(device, &health);
/* state is always QUAC_HEALTH_OK in simulator */

/* Device info shows simulator */
quac_device_info_t info;
quac_get_info(device, &info);
assert(info.capabilities & QUAC_CAP_SIMULATOR);
/* device_name will be "QUAC 100 Simulator" */
```

---

## Transitioning to Hardware

### Code Compatibility

Code developed with the simulator requires **zero changes** to run on hardware:

```c
/* This code works on both simulator and hardware */
#include <quac100.h>

int main(void)
{
    quac_result_t result;
    
    /* Initialize SDK - will use hardware if available */
    result = quac_init(NULL);
    if (QUAC_FAILED(result)) {
        fprintf(stderr, "Init failed: %s\n", quac_error_string(result));
        return 1;
    }
    
    /* Open device */
    quac_device_t device;
    result = quac_open(0, &device);
    
    /* Optional: Check what we're running on */
    quac_device_info_t info;
    info.struct_size = sizeof(info);
    quac_get_info(device, &info);
    
    if (info.capabilities & QUAC_CAP_SIMULATOR) {
        printf("Note: Running on simulator\n");
    } else {
        printf("Running on QUAC 100 hardware\n");
        printf("Serial: %s\n", info.serial_number);
    }
    
    /* Your application code - works on both */
    uint8_t pk[QUAC_KYBER768_PUBLIC_KEY_SIZE];
    uint8_t sk[QUAC_KYBER768_SECRET_KEY_SIZE];
    quac_kem_keygen(device, QUAC_ALGORITHM_KYBER768,
                    pk, sizeof(pk), sk, sizeof(sk));
    
    quac_close(device);
    quac_shutdown();
    return 0;
}
```

### Testing on Hardware

1. **Install Hardware**: Follow [Installation Guide](installation.md)

2. **Remove Simulator Flag**:
```c
/* Don't enable simulator */
// quac_set_simulator_mode(true);  /* Remove this */

/* Use default init */
quac_init(NULL);
```

3. **Run Tests**:
```bash
# Unset environment variable
unset QUAC_USE_SIMULATOR

# Run tests on hardware
./my_test_suite
```

### Performance Validation

Compare simulator vs hardware performance:

```c
#include <quac100.h>
#include <time.h>

void benchmark_keygen(quac_device_t device, int iterations)
{
    uint8_t pk[QUAC_KYBER768_PUBLIC_KEY_SIZE];
    uint8_t sk[QUAC_KYBER768_SECRET_KEY_SIZE];
    
    clock_t start = clock();
    
    for (int i = 0; i < iterations; i++) {
        quac_kem_keygen(device, QUAC_ALGORITHM_KYBER768,
                        pk, sizeof(pk), sk, sizeof(sk));
    }
    
    clock_t end = clock();
    double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
    double ops_per_sec = iterations / elapsed;
    
    printf("Kyber768 Keygen: %.2f ops/sec (%.2f µs/op)\n",
           ops_per_sec, (elapsed * 1000000) / iterations);
}

int main(void)
{
    /* Test on simulator */
    quac_set_simulator_mode(true);
    quac_init(NULL);
    quac_device_t sim_device;
    quac_open(0, &sim_device);
    
    printf("Simulator:\n");
    benchmark_keygen(sim_device, 1000);
    
    quac_close(sim_device);
    quac_shutdown();
    
    /* Test on hardware (if available) */
    quac_init(NULL);  /* Will fail if no hardware */
    quac_device_t hw_device;
    if (QUAC_SUCCEEDED(quac_open(0, &hw_device))) {
        quac_device_info_t info;
        info.struct_size = sizeof(info);
        quac_get_info(hw_device, &info);
        
        if (!(info.capabilities & QUAC_CAP_SIMULATOR)) {
            printf("\nHardware:\n");
            benchmark_keygen(hw_device, 10000);
        }
        quac_close(hw_device);
    }
    quac_shutdown();
    
    return 0;
}
```

---

## Summary

The QuantaCore SDK simulator enables:

- ✅ Full API compatibility with hardware
- ✅ Cryptographically correct operations
- ✅ Unit and integration testing
- ✅ CI/CD pipeline integration
- ✅ Development without hardware investment
- ✅ Zero code changes when transitioning to hardware

Use the simulator for development and testing, then deploy confidently on QUAC 100 hardware.

---

*Document Version: 1.0.0*
*Last Updated: 2025*
*Copyright © 2025 Dyber, Inc. All Rights Reserved.*
