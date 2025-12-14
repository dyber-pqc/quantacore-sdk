# QUAC 100 Java SDK

[![Java](https://img.shields.io/badge/Java-11%2B-orange.svg)](https://openjdk.org/)
[![Maven](https://img.shields.io/badge/Maven-3.6%2B-blue.svg)](https://maven.apache.org/)
[![License](https://img.shields.io/badge/License-Proprietary-red.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-28%2F29%20Passing-brightgreen.svg)]()

Java bindings for the **QUAC 100** Post-Quantum Cryptographic Accelerator.

## Overview

The QUAC 100 Java SDK provides a comprehensive Java interface to the QUAC 100 hardware accelerator, enabling high-performance post-quantum cryptographic operations from Java applications.

### Features

- **ML-KEM (Kyber)** - Post-quantum key encapsulation (ML-KEM-512/768/1024)
- **ML-DSA (Dilithium)** - Post-quantum digital signatures (ML-DSA-44/65/87)
- **QRNG** - Quantum random number generation
- **Hardware-accelerated hashing** - SHA-2, SHA-3, SHAKE, HMAC, HKDF
- **HSM Key Storage** - Secure key management with 256 key slots
- **JNI-based** - Direct native library access for maximum performance
- **Thread-safe** - Safe for concurrent access
- **AutoCloseable** - Proper resource management with try-with-resources

## Requirements

- **Java 11** or later (LTS versions recommended: 11, 17, 21)
- **Maven 3.6** or later
- **QUAC 100 C library** (must be built first)
- **CMake 3.16+** (for building native JNI library)

### Platform Support

| Platform | Architecture | Status |
|----------|--------------|--------|
| Windows  | x64          | ✅ Supported |
| Linux    | x64          | ✅ Supported |
| macOS    | x64/arm64    | ✅ Supported |

## Installation

### Option 1: Maven Dependency (Recommended)

Add to your `pom.xml`:

```xml
<dependency>
    <groupId>com.dyber</groupId>
    <artifactId>quac100</artifactId>
    <version>1.0.0</version>
</dependency>
```

### Option 2: Build from Source

```bash
# Clone the repository
git clone https://github.com/dyber-pqc/quantacore-sdk.git
cd quantacore-sdk/bindings/java

# Build the C library first (if not already done)
cd ../c
mkdir build && cd build
cmake .. && cmake --build . --config Release
cd ../../java

# Build native JNI library
# Windows:
build-native.bat

# Linux/macOS:
./build-native.sh

# Build the Java SDK
mvn clean install
```

### Native Library Setup

The Java SDK requires the native JNI library (`quac100_jni.dll`/`.so`/`.dylib`) and the QUAC 100 C library.

**Option A: Bundled in JAR** (automatic if using Maven build)

The native libraries are automatically bundled in the JAR under `native/{platform}-x64/`.

**Option B: java.library.path**
```bash
java -Djava.library.path=/path/to/native/libs -jar your-app.jar
```

**Option C: System Library Path**
```bash
# Windows: Add to PATH or copy to application directory
# Linux: /usr/local/lib or set LD_LIBRARY_PATH
# macOS: /usr/local/lib or set DYLD_LIBRARY_PATH
```

## Quick Start

```java
import com.dyber.quac100.*;

public class QuickStart {
    public static void main(String[] args) throws QuacException {
        // Initialize library
        Library.initialize();
        
        try {
            // Open device
            Device device = Library.openFirstDevice();
            
            // ML-KEM-768 key exchange
            Kem kem = device.kem();
            try (KeyPair keys = kem.generateKeyPair(KemAlgorithm.ML_KEM_768)) {
                try (EncapsulationResult encap = kem.encapsulate(
                        KemAlgorithm.ML_KEM_768, keys.getPublicKey())) {
                    
                    byte[] sharedSecret = kem.decapsulate(
                        KemAlgorithm.ML_KEM_768,
                        keys.getSecretKey(), 
                        encap.getCiphertext());
                    
                    System.out.println("Shared secret: " + Utils.toHex(sharedSecret));
                }
            }
            
            device.close();
        } finally {
            Library.cleanup();
        }
    }
}
```

## API Reference

### Library Management

```java
// Initialize with default flags
Library.initialize();

// Initialize with flags
Library.initialize(Library.FLAG_HARDWARE_ACCEL | Library.FLAG_FIPS_MODE);

// Check initialization
boolean ready = Library.isInitialized();

// Get version info
String version = Library.getVersion();
String buildInfo = Library.getBuildInfo();

// Enumerate devices
int count = Library.getDeviceCount();
DeviceInfo[] devices = Library.enumerateDevices();

// Open device
Device device = Library.openDevice(0);
Device device = Library.openFirstDevice();

// Clean up
Library.cleanup();
```

### Initialization Flags

| Flag | Description |
|------|-------------|
| `FLAG_DEFAULT` | Default settings (0x0F) |
| `FLAG_HARDWARE_ACCEL` | Enable hardware acceleration |
| `FLAG_SIDE_CHANNEL_PROTECT` | Enable side-channel protection |
| `FLAG_CONSTANT_TIME` | Force constant-time operations |
| `FLAG_AUTO_ZEROIZE` | Auto-zeroize sensitive data |
| `FLAG_FIPS_MODE` | FIPS 140-3 compliant mode |
| `FLAG_DEBUG` | Enable debug output |
| `FLAG_SOFTWARE_FALLBACK` | Allow software fallback |

### Device Operations

```java
Device device = Library.openFirstDevice();

// Get device info
DeviceInfo info = device.getInfo();
System.out.println("Model: " + info.getModel());
System.out.println("Serial: " + info.getSerialNumber());
System.out.println("Firmware: " + info.getFirmwareVersion());
System.out.println("Key Slots: " + info.getKeySlots());

// Get device status
DeviceStatus status = device.getStatus();
System.out.println("Temperature: " + status.getTemperature() + "°C");
System.out.println("Entropy: " + status.getEntropyLevel() + "%");
System.out.println("Operations: " + status.getOperationCount());
System.out.println("Healthy: " + status.isHealthy());

// Run self-test
device.selfTest();

// Reset device
device.reset();

// Check if open
boolean open = device.isOpen();

// Close device
device.close();
```

### Key Encapsulation (ML-KEM/Kyber)

```java
Kem kem = device.kem();

// Generate key pair
KeyPair keys = kem.generateKeyPair(KemAlgorithm.ML_KEM_512);  // 128-bit security
KeyPair keys = kem.generateKeyPair(KemAlgorithm.ML_KEM_768);  // 192-bit security
KeyPair keys = kem.generateKeyPair(KemAlgorithm.ML_KEM_1024); // 256-bit security

// Key sizes (ML-KEM-768)
// Public key: 1184 bytes
// Secret key: 2400 bytes
// Ciphertext: 1088 bytes
// Shared secret: 32 bytes

// Encapsulate (sender side)
EncapsulationResult result = kem.encapsulate(
    KemAlgorithm.ML_KEM_768, recipientPublicKey);
byte[] ciphertext = result.getCiphertext();     // Send to recipient
byte[] sharedSecret = result.getSharedSecret(); // Use for encryption

// Decapsulate (recipient side)
byte[] sharedSecret = kem.decapsulate(
    KemAlgorithm.ML_KEM_768, mySecretKey, ciphertext);

// Clean up (important for security!)
keys.close();
result.close();
```

### Digital Signatures (ML-DSA/Dilithium)

```java
Sign sign = device.sign();

// Generate signing key pair
KeyPair keys = sign.generateKeyPair(SignAlgorithm.ML_DSA_44); // 128-bit security
KeyPair keys = sign.generateKeyPair(SignAlgorithm.ML_DSA_65); // 192-bit security
KeyPair keys = sign.generateKeyPair(SignAlgorithm.ML_DSA_87); // 256-bit security

// Key/signature sizes (ML-DSA-65)
// Public key: 1952 bytes
// Secret key: 4032 bytes
// Signature: 3309 bytes

// Sign a message
byte[] message = "Important document".getBytes(StandardCharsets.UTF_8);
byte[] signature = sign.sign(SignAlgorithm.ML_DSA_65, keys.getSecretKey(), message);

// Verify signature (returns boolean)
boolean valid = sign.verify(
    SignAlgorithm.ML_DSA_65, keys.getPublicKey(), message, signature);

// Clean up
keys.close();
```

### Random Number Generation (QRNG)

```java
Random random = device.random();

// Check entropy status
EntropyStatus status = random.getEntropyStatus();
System.out.println("Level: " + status.getLevel() + "%");
System.out.println("Healthy: " + status.isHealthOk());
System.out.println("Generated: " + status.getTotalGenerated() + " bytes");

// Generate random bytes
byte[] bytes = random.bytes(32);

// Fill existing buffer
byte[] buffer = new byte[64];
random.nextBytes(buffer);

// Random integers
int value = random.nextInt();            // Full range
int bounded = random.nextInt(100);       // [0, 100)
int range = random.nextInt(10, 20);      // [10, 20)

// Random longs
long longVal = random.nextLong();
long boundedLong = random.nextLong(1000000);

// Random doubles/floats
double d = random.nextDouble();          // [0.0, 1.0)
double rangeD = random.nextDouble(10, 20); // [10.0, 20.0)
float f = random.nextFloat();

// Random boolean
boolean b = random.nextBoolean();

// Generate UUID
String uuid = random.uuid();
UUID uuidObj = random.nextUUID();

// Shuffle array
Integer[] array = {1, 2, 3, 4, 5};
random.shuffle(array);
```

### Hashing

```java
Hash hash = device.hash();

// One-shot hashing with algorithm enum
byte[] digest = hash.hash(HashAlgorithm.SHA3_256, data);

// Convenience methods
byte[] sha256 = hash.sha256(data);
byte[] sha384 = hash.sha384(data);
byte[] sha512 = hash.sha512(data);
byte[] sha3_256 = hash.sha3_256(data);
byte[] sha3_512 = hash.sha3_512(data);

// String input
byte[] digest = hash.sha256("Hello, World!");

// SHAKE (variable output length)
byte[] shake128 = hash.shake128(data, 64);  // 64 bytes output
byte[] shake256 = hash.shake256(data, 128); // 128 bytes output

// Incremental hashing
try (Hash.HashContext ctx = hash.createContext(HashAlgorithm.SHA256)) {
    ctx.update("part1");
    ctx.update("part2".getBytes());
    byte[] result = ctx.digest();
    // Or: byte[] result = ctx.doFinal();
}

// HMAC
byte[] hmac = hash.hmacSha256(key, data);
byte[] hmac512 = hash.hmacSha512(key, data);
byte[] hmac = hash.hmac(HashAlgorithm.SHA256, key, data);

// HKDF key derivation
byte[] derived = hash.hkdf(HashAlgorithm.SHA256, ikm, salt, info, 32);
```

### HSM Key Storage

```java
Keys keys = device.keys();

// Key management operations available through keys() subsystem
// See Keys class documentation for full API
```

### Utility Functions

```java
// Hex encoding/decoding
String hex = Utils.toHex(bytes);
byte[] data = Utils.fromHex("deadbeef");

// Base64 encoding/decoding
String b64 = Utils.toBase64(bytes);
byte[] data = Utils.fromBase64(b64);

// URL-safe Base64
String b64url = Utils.toBase64Url(bytes);
byte[] data = Utils.fromBase64Url(b64url);

// Secure operations
Utils.secureZero(sensitiveData);        // Zero memory
boolean eq = Utils.secureCompare(a, b); // Constant-time compare

// Byte array operations
byte[] combined = Utils.concat(a, b, c);
byte[] copy = Utils.copy(original);
byte[] slice = Utils.slice(data, offset, length);
```

## Exception Handling

All SDK methods throw `QuacException` or its subclasses:

```java
try {
    device.selfTest();
} catch (DeviceException e) {
    // Device-related errors
    System.err.println("Device error: " + e.getErrorCode());
} catch (CryptoException e) {
    // Cryptographic operation errors
    System.err.println("Crypto error: " + e.getMessage());
} catch (VerificationException e) {
    // Signature verification failed
    System.err.println("Signature invalid");
} catch (QuacException e) {
    // General errors
    ErrorCode code = e.getErrorCodeEnum();
    System.err.println("Error [" + code + "]: " + e.getMessage());
}
```

### Error Codes

| Code | Constant | Description |
|------|----------|-------------|
| 0 | `SUCCESS` | Operation completed successfully |
| -1 | `ERROR` | Generic error |
| -2 | `INVALID_PARAM` | Invalid parameter |
| -4 | `DEVICE_NOT_FOUND` | Device not found |
| -6 | `DEVICE_ERROR` | Device error |
| -13 | `VERIFICATION_FAILED` | Signature verification failed |
| -14 | `DECAPS_FAILED` | Decapsulation failed |
| -26 | `INVALID_ALGORITHM` | Invalid algorithm |
| -27 | `CRYPTO_ERROR` | Cryptographic operation error |
| -99 | `INTERNAL_ERROR` | Internal error |

## Resource Management

The SDK uses `AutoCloseable` for proper resource management:

```java
// Recommended: try-with-resources
try (KeyPair kp = kem.generateKeyPair(KemAlgorithm.ML_KEM_768)) {
    // Use key pair
    byte[] pk = kp.getPublicKey();
    byte[] sk = kp.getSecretKey();
} // Automatically zeroed and closed

// Manual cleanup
KeyPair kp = kem.generateKeyPair(KemAlgorithm.ML_KEM_768);
try {
    // Use key pair
} finally {
    kp.close(); // Zero sensitive memory
}
```

## Thread Safety

The SDK is thread-safe with the following considerations:

- **Library**: Static methods, safe for concurrent access
- **Device**: Each device instance should be used by one thread, or synchronized
- **Operations**: Individual cryptographic operations are atomic
- **KeyPair/EncapsulationResult**: Not thread-safe, use per-thread instances

## Performance

Typical performance on QUAC 100 hardware:

| Operation | Performance |
|-----------|------------|
| ML-KEM-768 KeyGen | ~1,000,000 ops/sec |
| ML-KEM-768 Encaps | ~1,700,000 ops/sec |
| ML-KEM-768 Decaps | ~8,000,000 ops/sec |
| ML-DSA-65 Sign | ~900,000 ops/sec |
| ML-DSA-65 Verify | ~4,000,000 ops/sec |
| SHA3-256 | ~500 MB/sec |
| QRNG | ~2,000 MB/sec |

## Examples

See the `examples/` directory for complete examples:

- `BasicExample.java` - Device enumeration and status
- `KemExample.java` - Key encapsulation
- `SignExample.java` - Digital signatures
- `HashExample.java` - Hashing and key derivation
- `RandomExample.java` - Random number generation

Run examples:
```bash
# With Maven
mvn exec:java -Dexec.mainClass="BasicExample" \
    -Dexec.args="" \
    -Djava.library.path=native/build/Release

# Direct execution
java -Djava.library.path=native/build/Release \
    -cp target/classes:examples BasicExample
```

## Testing

```bash
# Run all tests
mvn test -DargLine="-Djava.library.path=native/build/Release"

# Run specific test class
mvn test -Dtest=Quac100Test -DargLine="-Djava.library.path=native/build/Release"

# Skip tests
mvn install -DskipTests
```

### Test Results

Current test status: **28/29 passing** (1 skipped)

```
Tests run: 29, Failures: 0, Errors: 0, Skipped: 1
BUILD SUCCESS
```

## Troubleshooting

### UnsatisfiedLinkError

```
java.lang.UnsatisfiedLinkError: no quac100_jni in java.library.path
```

**Solution**: Ensure the native library is in the library path:
```bash
java -Djava.library.path=native/build/Release -jar app.jar
```

### Device Not Found

```
DeviceException: No QUAC 100 devices found
```

**Solution**: 
1. Check device is connected and powered on
2. Verify USB/PCIe drivers are installed
3. The SDK includes simulation mode for testing without hardware

### Library Not Initialized

```
IllegalStateException: QUAC 100 library not initialized
```

**Solution**: Call `Library.initialize()` before using other SDK functions.

## Building Native Library

If you need to rebuild the native JNI library:

### Windows
```powershell
cd native
mkdir build
cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

### Linux/macOS
```bash
cd native
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .
```

## Project Structure

```
java/
├── pom.xml                          # Maven build configuration
├── build-native.bat                 # Windows native build script
├── build-native.sh                  # Unix native build script
├── README.md                        # This file
├── native/
│   ├── CMakeLists.txt              # Native library build
│   ├── quac100_jni.c               # JNI implementation
│   └── build/
│       └── Release/
│           ├── quac100.dll         # C library
│           └── quac100_jni.dll     # JNI bridge
├── src/
│   ├── main/java/com/dyber/quac100/
│   │   ├── Library.java            # Main entry point
│   │   ├── Device.java             # Device handle
│   │   ├── Kem.java                # Key encapsulation
│   │   ├── Sign.java               # Digital signatures
│   │   ├── Hash.java               # Hashing
│   │   ├── Random.java             # QRNG
│   │   ├── Keys.java               # Key storage
│   │   └── *.java                  # Supporting classes
│   └── test/java/com/dyber/quac100/
│       └── Quac100Test.java        # Unit tests
└── examples/
    ├── BasicExample.java
    ├── KemExample.java
    ├── SignExample.java
    ├── HashExample.java
    └── RandomExample.java
```

## License

Copyright © 2025 Dyber, Inc. All Rights Reserved.

This software is proprietary and confidential. Unauthorized copying, distribution, or use is strictly prohibited.

## Support

- **Documentation**: https://docs.dyber.org/quac100/java
- **Issues**: https://github.com/dyber-pqc/quantacore-sdk/issues
- **Email**: support@dyber.org
- **Website**: https://dyber.org