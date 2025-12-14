# QUAC 100 Go Examples

Go bindings and examples for the QUAC 100 post-quantum cryptographic accelerator.

## Requirements

- Go 1.21+
- QUAC 100 SDK installed
- CGO enabled

## Installation

```bash
go get github.com/dyber/quac100-go
```

## Examples

| File | Description |
|------|-------------|
| `hello_quac.go` | Basic initialization and random generation |
| `kem_demo.go` | ML-KEM key exchange demonstration |
| `sign_demo.go` | ML-DSA digital signature demonstration |
| `concurrent.go` | Concurrent operations with goroutines |

## Quick Start

```go
package main

import (
    "fmt"
    "github.com/dyber/quac100-go"
)

func main() {
    // Initialize
    ctx, err := quac100.NewContext()
    if err != nil {
        panic(err)
    }
    defer ctx.Close()

    // Open device
    device, err := ctx.OpenDevice(0)
    if err != nil {
        device, _ = ctx.OpenSimulator()
    }
    defer device.Close()

    // Generate random bytes
    random, _ := device.Random(32)
    fmt.Printf("Random: %x\n", random)

    // ML-KEM key exchange
    pk, sk, _ := device.KEMKeygen(quac100.AlgMLKEM768)
    ct, ssSender, _ := device.KEMEncaps(quac100.AlgMLKEM768, pk)
    ssReceiver, _ := device.KEMDecaps(quac100.AlgMLKEM768, ct, sk)
    
    fmt.Printf("Shared secrets match: %v\n", 
        bytes.Equal(ssSender, ssReceiver))
}
```

## Running Examples

```bash
go run hello_quac.go
go run kem_demo.go
go run sign_demo.go
go run concurrent.go
```

## License

Copyright 2025 Dyber, Inc. All Rights Reserved.