# QUAC 100 OpenSSL Provider

OpenSSL 3.x provider for transparent post-quantum cryptographic acceleration using QUAC 100 hardware.

## Features

- **ML-KEM** (FIPS 203): ML-KEM-512, ML-KEM-768, ML-KEM-1024
- **ML-DSA** (FIPS 204): ML-DSA-44, ML-DSA-65, ML-DSA-87
- **QRNG**: Hardware quantum random number generation
- **Automatic Fallback**: Software simulation when hardware unavailable

## Requirements

- OpenSSL 3.0 or later
- CMake 3.16+
- C11 compiler (GCC, Clang, or MSVC)
- QUAC 100 SDK (optional - enables hardware acceleration)

## Building

### Quick Build (Simulator Only)

```bash
mkdir build && cd build
cmake ..
make
```

### Build with Hardware Support

```bash
mkdir build && cd build
cmake -DQUAC100_ROOT=/path/to/quantacore-sdk ..
make
```

### Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `QUAC_PROVIDER_SHARED` | ON | Build as shared library |
| `QUAC_PROVIDER_INSTALL` | ON | Enable installation |
| `QUAC_PROVIDER_TESTS` | ON | Build tests |

## Installation

```bash
sudo make install
```

Default installation paths:
- Linux: `/usr/local/lib/ossl-modules/quac100.so`
- macOS: `/usr/local/lib/ossl-modules/quac100.dylib`
- Windows: `C:\Program Files\QUAC100\bin\quac100.dll`

## Configuration

### Method 1: Environment Variable

```bash
export OPENSSL_MODULES=/usr/local/lib/ossl-modules
openssl list -providers -provider quac100
```

### Method 2: OpenSSL Configuration File

Copy `openssl.cnf.example` to your OpenSSL config directory:

```bash
sudo cp openssl.cnf.example /etc/ssl/openssl-quac100.cnf
export OPENSSL_CONF=/etc/ssl/openssl-quac100.cnf
```

### Method 3: Per-Command Loading

```bash
openssl -provider-path /usr/local/lib/ossl-modules -provider quac100 ...
```

## Usage Examples

### List Available Algorithms

```bash
# List all providers
openssl list -providers -provider quac100

# List KEM algorithms
openssl list -kem-algorithms -provider quac100

# List signature algorithms  
openssl list -signature-algorithms -provider quac100
```

### Key Generation

```bash
# Generate ML-KEM-768 keypair
openssl genpkey -provider quac100 -algorithm ML-KEM-768 -out mlkem768.pem

# Generate ML-DSA-65 keypair
openssl genpkey -provider quac100 -algorithm ML-DSA-65 -out mldsa65.pem

# Extract public key
openssl pkey -provider quac100 -in mldsa65.pem -pubout -out mldsa65_pub.pem
```

### Digital Signatures (ML-DSA)

```bash
# Sign a file
openssl pkeyutl -provider quac100 -sign \
    -inkey mldsa65.pem \
    -in message.txt \
    -out message.sig

# Verify signature
openssl pkeyutl -provider quac100 -verify \
    -pubin -inkey mldsa65_pub.pem \
    -in message.txt \
    -sigfile message.sig
```

### Key Encapsulation (ML-KEM)

```bash
# Generate keypair
openssl genpkey -provider quac100 -algorithm ML-KEM-768 -out mlkem.pem
openssl pkey -provider quac100 -in mlkem.pem -pubout -out mlkem_pub.pem

# Encapsulate (creates ciphertext and shared secret)
openssl pkeyutl -provider quac100 -encapsulate \
    -pubin -inkey mlkem_pub.pem \
    -out ciphertext.bin \
    -secret shared_secret.bin

# Decapsulate (recovers shared secret)
openssl pkeyutl -provider quac100 -decapsulate \
    -inkey mlkem.pem \
    -in ciphertext.bin \
    -secret recovered_secret.bin
```

### Random Number Generation (QRNG)

```bash
# Generate random bytes
openssl rand -provider quac100 -hex 32

# Generate random file
openssl rand -provider quac100 -out random.bin 1024
```

### Certificate Operations

```bash
# Create self-signed certificate with ML-DSA-65
openssl req -provider quac100 -x509 -new \
    -key mldsa65.pem \
    -out cert.pem \
    -days 365 \
    -subj "/CN=example.com"

# View certificate
openssl x509 -provider quac100 -in cert.pem -text -noout
```

### Benchmarking

```bash
# Benchmark ML-KEM operations
openssl speed -provider quac100 -seconds 5 mlkem512 mlkem768 mlkem1024

# Benchmark ML-DSA operations
openssl speed -provider quac100 -seconds 5 mldsa44 mldsa65 mldsa87
```

## Programmatic Usage (C)

```c
#include <openssl/evp.h>
#include <openssl/provider.h>

int main() {
    // Load QUAC 100 provider
    OSSL_PROVIDER *quac = OSSL_PROVIDER_load(NULL, "quac100");
    if (!quac) {
        fprintf(stderr, "Failed to load provider\n");
        return 1;
    }
    
    // Generate ML-KEM-768 keypair
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", "provider=quac100");
    EVP_PKEY_keygen_init(ctx);
    
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_generate(ctx, &pkey);
    
    // Use the key...
    
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PROVIDER_unload(quac);
    
    return 0;
}
```

Compile with:
```bash
gcc -o example example.c -lssl -lcrypto
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `OPENSSL_MODULES` | Directory containing provider modules |
| `OPENSSL_CONF` | Path to OpenSSL configuration file |
| `QUAC_DEVICE` | Device index (0-N) or "simulator" |
| `QUAC_LOG_LEVEL` | 0=off, 1=error, 2=warn, 3=info, 4=debug |
| `QUAC_FIPS_MODE` | Enable FIPS mode (1/0) |

## Troubleshooting

### Provider fails to load

```bash
# Check if module exists
ls -la /usr/local/lib/ossl-modules/quac100.so

# Check library dependencies
ldd /usr/local/lib/ossl-modules/quac100.so

# Verbose loading
QUAC_LOG_LEVEL=4 openssl list -providers -provider quac100
```

### Hardware not detected

```bash
# Check PCIe device
lspci | grep -i quac

# Check device node
ls -la /dev/quac*

# Check permissions
groups $USER
```

### Algorithm not found

Ensure you're specifying the provider:
```bash
# Wrong
openssl genpkey -algorithm ML-KEM-768 ...

# Correct
openssl genpkey -provider quac100 -algorithm ML-KEM-768 ...
```

## Testing

```bash
# Run CMake tests
cd build
ctest --output-on-failure

# Run test script
./test_provider.sh

# Run test program
./test_provider
```

## Performance

Expected performance with QUAC 100 hardware:

| Algorithm | Operation | Throughput |
|-----------|-----------|------------|
| ML-KEM-768 | Keygen | 1,400,000 ops/sec |
| ML-KEM-768 | Encaps | 1,200,000 ops/sec |
| ML-KEM-768 | Decaps | 1,000,000 ops/sec |
| ML-DSA-65 | Sign | 800,000 ops/sec |
| ML-DSA-65 | Verify | 900,000 ops/sec |
| QRNG | Generate | 1 Gbps |

## License

Copyright 2025 Dyber, Inc. All Rights Reserved.

## See Also

- [QuantaCore SDK Documentation](../../docs/)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [OpenSSL Provider Documentation](https://www.openssl.org/docs/man3.0/man7/provider.html)