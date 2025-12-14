# QUAC 100 Go SDK

[![Go Reference](https://pkg.go.dev/badge/github.com/dyber-pqc/quac100-go.svg)](https://pkg.go.dev/github.com/dyber-pqc/quac100-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/dyber-pqc/quac100-go)](https://goreportcard.com/report/github.com/dyber-pqc/quac100-go)
[![License](https://img.shields.io/badge/license-Proprietary-blue.svg)](LICENSE)

Go bindings for the **QUAC 100 Post-Quantum Cryptographic Accelerator** by Dyber, Inc.

## Features

- **ML-KEM (Kyber)** - Key Encapsulation Mechanism (512/768/1024 variants)
- **ML-DSA (Dilithium)** - Digital Signatures (44/65/87 variants)
- **SLH-DSA (SPHINCS+)** - Hash-based Signatures
- **Quantum Random Number Generation** - Hardware QRNG with io.Reader interface
- **Device Pool** - Connection pooling for high-throughput applications
- **Thread-Safe** - Safe for concurrent use from multiple goroutines

## Installation

```bash
go get github.com/dyber-pqc/quac100-go
```

### Prerequisites

1. **QUAC 100 Hardware** - PCIe accelerator card installed
2. **Native Library** - `libquac100.so` (Linux), `quac100.dll` (Windows), or `libquac100.dylib` (macOS)
3. **Go 1.21+** - Required for generics support
4. **CGO** - Must be enabled (`CGO_ENABLED=1`)

### Native Library Installation

#### Linux
```bash
# Copy library to system path
sudo cp libquac100.so /usr/local/lib/
sudo ldconfig

# Or set LD_LIBRARY_PATH
export LD_LIBRARY_PATH=/path/to/quac100/lib:$LD_LIBRARY_PATH
```

#### Windows
```powershell
# Copy DLL to PATH or application directory
copy quac100.dll C:\Windows\System32\

# Or add to PATH
$env:PATH += ";C:\path\to\quac100\lib"
```

#### macOS
```bash
# Copy library to system path
sudo cp libquac100.dylib /usr/local/lib/

# Or set DYLD_LIBRARY_PATH
export DYLD_LIBRARY_PATH=/path/to/quac100/lib:$DYLD_LIBRARY_PATH
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"

    quac "github.com/dyber-pqc/quac100-go"
)

func main() {
    // Open device
    device, err := quac.Open()
    if err != nil {
        log.Fatal(err)
    }
    defer device.Close()

    // Generate ML-KEM key pair
    keyPair, err := device.KemGenerateKeyPair(quac.MlKem768)
    if err != nil {
        log.Fatal(err)
    }
    defer keyPair.Zeroize() // Secure cleanup

    // Encapsulate (sender side)
    result, err := device.KemEncapsulate(keyPair.PublicKey, quac.MlKem768)
    if err != nil {
        log.Fatal(err)
    }
    defer result.Zeroize()

    // Decapsulate (recipient side)
    sharedSecret, err := device.KemDecapsulate(keyPair.SecretKey, result.Ciphertext, quac.MlKem768)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Shared secret: %x\n", sharedSecret)
}
```

## Usage Examples

### ML-KEM Key Exchange

```go
device, _ := quac.Open()
defer device.Close()

kem := device.Kem()

// Alice generates key pair
aliceKeys, _ := kem.GenerateKeyPair(quac.MlKem768)
defer aliceKeys.Zeroize()

// Bob encapsulates to Alice's public key
encap, _ := kem.Encapsulate(aliceKeys.PublicKey, quac.MlKem768)
defer encap.Zeroize()

// Alice decapsulates
sharedSecret, _ := kem.DecapsulateKeyPair(aliceKeys, encap.Ciphertext)

// Both parties now have the same shared secret
```

### ML-DSA Digital Signatures

```go
device, _ := quac.Open()
defer device.Close()

signer := device.Signer()

// Generate signing key pair
keyPair, _ := signer.GenerateKeyPair(quac.MlDsa65)
defer keyPair.Zeroize()

// Sign a message
message := []byte("Important document")
signature, _ := signer.SignKeyPair(keyPair, message)

// Verify the signature
valid, _ := signer.VerifyKeyPair(keyPair, message, signature)
fmt.Printf("Signature valid: %v\n", valid)
```

### Quantum Random Numbers

```go
device, _ := quac.Open()
defer device.Close()

random := device.Random()

// Generate random bytes
bytes, _ := random.Bytes(32)

// Generate random integers
n, _ := random.Int32Range(1, 100)

// Generate random UUID
uuid, _ := random.UUID()

// Use as io.Reader
buffer := make([]byte, 1024)
random.Read(buffer)

// Shuffle a slice
items := []string{"a", "b", "c", "d", "e"}
random.ShuffleStrings(items)
```

### Device Pool for High Throughput

```go
// Create pool with 4 connections
pool, _ := quac.NewDevicePool(4, quac.FlagDefault)
defer pool.Close()

// Use pooled operations
ctx := context.Background()
var wg sync.WaitGroup

for i := 0; i < 100; i++ {
    wg.Add(1)
    go func() {
        defer wg.Done()
        
        pool.PooledOperation(ctx, func(device *quac.Device) error {
            keyPair, err := device.KemGenerateKeyPair(quac.MlKem768)
            if err != nil {
                return err
            }
            keyPair.Zeroize()
            return nil
        })
    }()
}

wg.Wait()
```

### Context API (Unified Interface)

```go
ctx, _ := quac.NewDefaultContext()
defer ctx.Close()

// All operations through context
keyPair, _ := ctx.GenerateKemKeyPair(quac.MlKem768)
randomBytes, _ := ctx.RandomBytes(32)
hash, _ := ctx.SHA256([]byte("data"))
```

## API Reference

### Algorithms

| Algorithm | Type | Security Level | Public Key | Secret Key |
|-----------|------|----------------|------------|------------|
| ML-KEM-512 | KEM | Level 1 | 800 B | 1632 B |
| ML-KEM-768 | KEM | Level 3 | 1184 B | 2400 B |
| ML-KEM-1024 | KEM | Level 5 | 1568 B | 3168 B |
| ML-DSA-44 | Signature | Level 2 | 1312 B | 2528 B |
| ML-DSA-65 | Signature | Level 3 | 1952 B | 4000 B |
| ML-DSA-87 | Signature | Level 5 | 2592 B | 4864 B |

### Error Handling

```go
device, err := quac.Open()
if err != nil {
    if quac.IsDeviceNotFound(err) {
        // No QUAC 100 device found
    } else if quac.IsHardwareNotAvailable(err) {
        // Hardware unavailable
    }
    log.Fatal(err)
}
```

## Testing

```bash
# Run all tests
go test ./...

# Run with verbose output
go test -v ./...

# Run benchmarks
go test -bench=. ./...

# Run specific test
go test -run TestKemKeyGeneration ./...
```

## Benchmarks

Example output on QUAC 100 hardware:

```
BenchmarkKemKeyGen768-8      100000    10500 ns/op    0 B/op    0 allocs/op
BenchmarkKemEncaps768-8      150000     7200 ns/op    0 B/op    0 allocs/op
BenchmarkSign65-8             50000    25000 ns/op    0 B/op    0 allocs/op
BenchmarkVerify65-8           80000    14000 ns/op    0 B/op    0 allocs/op
BenchmarkRandomBytes1K-8     500000     2500 ns/op    0 B/op    0 allocs/op
```

## Documentation

- [SDK Documentation](https://docs.dyber.io/quac100)
- [API Reference](https://pkg.go.dev/github.com/dyber-pqc/quac100-go)
- [Examples](./examples/)

## Support

- **Issues**: [GitHub Issues](https://github.com/dyber-pqc/quac100-go/issues)
- **Email**: support@dyber.org

## License

Copyright © 2025 Dyber, Inc. All Rights Reserved.

This software is proprietary and requires a valid license for use. See [LICENSE](LICENSE) for details.
