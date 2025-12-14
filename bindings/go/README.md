# QUAC 100 Go SDK

[![Go Reference](https://pkg.go.dev/badge/github.com/dyber-io/quac100-go.svg)](https://pkg.go.dev/github.com/dyber-io/quac100-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/dyber-io/quac100-go)](https://goreportcard.com/report/github.com/dyber-io/quac100-go)
[![License](https://img.shields.io/badge/license-Proprietary-blue.svg)](LICENSE)

Go bindings for the **QUAC 100 Post-Quantum Cryptographic Accelerator** by Dyber, Inc.

## Features

- **ML-KEM (Kyber)** - Key Encapsulation Mechanism (512/768/1024 variants)
- **ML-DSA (Dilithium)** - Digital Signatures (44/65/87 variants)
- **SLH-DSA (SPHINCS+)** - Hash-based Signatures
- **Quantum Random Number Generation** - Hardware QRNG with io.Reader interface
- **Hardware-Accelerated Hashing** - SHA-2, SHA-3, SHAKE
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

    quac100 "github.com/dyber-io/quac100-go"
)

func main() {
    // Open device
    device, err := quac100.Open()
    if err != nil {
        log.Fatal(err)
    }
    defer device.Close()

    // Generate ML-KEM key pair
    keyPair, err := device.KemGenerateKeyPair(quac100.MlKem768)
    if err != nil {
        log.Fatal(err)
    }
    defer keyPair.Zeroize() // Secure cleanup

    // Encapsulate (sender side)
    result, err := device.KemEncapsulate(keyPair.PublicKey, quac100.MlKem768)
    if err != nil {
        log.Fatal(err)
    }
    defer result.Zeroize()

    // Decapsulate (recipient side)
    sharedSecret, err := device.KemDecapsulate(keyPair.SecretKey, result.Ciphertext, quac100.MlKem768)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Shared secret: %x\n", sharedSecret)
}
```

## Usage Examples

### ML-KEM Key Exchange

```go
device, _ := quac100.Open()
defer device.Close()

kem := device.Kem()

// Alice generates key pair
aliceKeys, _ := kem.GenerateKeyPair(quac100.MlKem768)
defer aliceKeys.Zeroize()

// Bob encapsulates to Alice's public key
encap, _ := kem.Encapsulate(aliceKeys.PublicKey, quac100.MlKem768)
defer encap.Zeroize()

// Alice decapsulates
sharedSecret, _ := kem.DecapsulateKeyPair(aliceKeys, encap.Ciphertext)

// Both parties now have the same shared secret
```

### ML-DSA Digital Signatures

```go
device, _ := quac100.Open()
defer device.Close()

signer := device.Signer()

// Generate signing key pair
keyPair, _ := signer.GenerateKeyPair(quac100.MlDsa65)
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
device, _ := quac100.Open()
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
pool, _ := quac100.NewDevicePool(4, quac100.FlagDefault)
defer pool.Close()

// Use pooled operations
ctx := context.Background()
var wg sync.WaitGroup

for i := 0; i < 100; i++ {
    wg.Add(1)
    go func() {
        defer wg.Done()
        
        pool.PooledOperation(ctx, func(device *quac100.Device) error {
            keyPair, err := device.KemGenerateKeyPair(quac100.MlKem768)
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
ctx, _ := quac100.NewDefaultContext()
defer ctx.Close()

// All operations through context
keyPair, _ := ctx.GenerateKemKeyPair(quac100.MlKem768)
randomBytes, _ := ctx.RandomBytes(32)
hash, _ := ctx.SHA256([]byte("data"))
```

## API Reference

### Algorithms

| Algorithm | Type | Security Level | Key Sizes |
|-----------|------|----------------|-----------|
| ML-KEM-512 | KEM | Level 1 | PK: 800, SK: 1632 |
| ML-KEM-768 | KEM | Level 3 | PK: 1184, SK: 2400 |
| ML-KEM-1024 | KEM | Level 5 | PK: 1568, SK: 3168 |
| ML-DSA-44 | Signature | Level 2 | PK: 1312, SK: 2560 |
| ML-DSA-65 | Signature | Level 3 | PK: 1952, SK: 4032 |
| ML-DSA-87 | Signature | Level 5 | PK: 2592, SK: 4896 |

### Error Handling

```go
device, err := quac100.Open()
if err != nil {
    if quac100.IsDeviceNotFound(err) {
        // Handle no device
    } else if quac100.IsHardwareNotAvailable(err) {
        // Handle hardware unavailable
    }
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

Run benchmarks on your hardware:

```bash
go test -bench=. -benchmem ./tests/
```

Example output (QUAC 100 hardware):

```
BenchmarkKemKeyGen768-8      100000    10500 ns/op    0 B/op    0 allocs/op
BenchmarkKemEncaps768-8      150000     7200 ns/op    0 B/op    0 allocs/op
BenchmarkSign65-8             50000    25000 ns/op    0 B/op    0 allocs/op
BenchmarkVerify65-8           80000    14000 ns/op    0 B/op    0 allocs/op
BenchmarkRandomBytes1K-8     500000     2500 ns/op    0 B/op    0 allocs/op
```

---

## Publishing the Go Module

Follow these steps to publish the QUAC 100 Go module to make it publicly available via `go get`.

### Step 1: Create GitHub Repository

1. Create a new repository on GitHub named `quac100-go` under the `dyber-io` organization
2. Initialize with this README and appropriate license

```bash
# Clone the empty repository
git clone https://github.com/dyber-io/quac100-go.git
cd quac100-go

# Copy all Go binding files
cp -r /path/to/quantacore-sdk/bindings/go/* .
```

### Step 2: Verify Module Structure

Ensure the following structure:

```
quac100-go/
├── go.mod
├── go.sum
├── README.md
├── LICENSE
├── cgo_bridge.go
├── device.go
├── errors.go
├── kem.go
├── quac100.go
├── random.go
├── sign.go
├── types.go
├── examples/
│   └── main.go
├── tests/
│   └── quac100_test.go
├── include/           # C header files
│   └── quac100.h
└── lib/               # Native libraries (optional, for development)
    ├── libquac100.so
    └── quac100.dll
```

### Step 3: Update go.mod

Ensure `go.mod` has the correct module path:

```go
module github.com/dyber-io/quac100-go

go 1.21

require (
    golang.org/x/crypto v0.28.0
    golang.org/x/sys v0.26.0
)
```

### Step 4: Generate go.sum

```bash
go mod tidy
```

### Step 5: Commit and Push

```bash
git add .
git commit -m "Initial release of QUAC 100 Go SDK"
git push origin main
```

### Step 6: Create Version Tag

Go modules use semantic versioning via git tags:

```bash
# Create initial release tag
git tag v1.0.0
git push origin v1.0.0
```

### Step 7: Verify on pkg.go.dev

After pushing the tag, the module will be automatically indexed by pkg.go.dev. Visit:

```
https://pkg.go.dev/github.com/dyber-io/quac100-go
```

To force immediate indexing:

```bash
# Request the module (triggers indexing)
curl "https://proxy.golang.org/github.com/dyber-io/quac100-go/@v/v1.0.0.info"
```

### Step 8: Users Can Now Install

```bash
go get github.com/dyber-io/quac100-go@v1.0.0
```

### Releasing New Versions

```bash
# Make changes
git add .
git commit -m "Add new feature X"
git push origin main

# Tag new version
git tag v1.1.0
git push origin v1.1.0
```

### Version Guidelines

- **v1.0.0** - Initial stable release
- **v1.0.x** - Bug fixes (patch)
- **v1.x.0** - New features, backward compatible (minor)
- **v2.0.0** - Breaking changes (major) - requires new module path `github.com/dyber-io/quac100-go/v2`

### Private Module (Optional)

For private/enterprise distribution:

1. **GOPRIVATE** - Set for private repos:
   ```bash
   go env -w GOPRIVATE=github.com/dyber-io/*
   ```

2. **Authentication** - Configure git credentials:
   ```bash
   git config --global url."https://${GITHUB_TOKEN}@github.com/".insteadOf "https://github.com/"
   ```

3. **Private Proxy** - Use Athens or similar for internal caching

---

## Support

- **Documentation**: https://docs.dyber.org/quac100
- **Issues**: https://github.com/dyber-io/quac100-go/issues
- **Email**: support@dyber.io

## License

Copyright © 2025 Dyber, Inc. All Rights Reserved.

This software is proprietary and requires a valid license for use. Contact sales@dyber.io for licensing information.