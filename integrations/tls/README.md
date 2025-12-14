# QUAC 100 TLS Integration

Post-quantum TLS library for hardware-accelerated cryptographic operations using the QUAC 100 accelerator.

## Overview

The QUAC TLS library provides drop-in post-quantum cryptography support for TLS 1.3 with:

| Feature | Description |
|---------|-------------|
| **ML-KEM Key Exchange** | Quantum-resistant key encapsulation (512, 768, 1024) |
| **ML-DSA Authentication** | Post-quantum digital signatures (44, 65, 87) |
| **Hybrid Modes** | Combined classical + PQC for defense-in-depth |
| **Hardware Acceleration** | QUAC 100 offload with sub-microsecond latency |
| **Proxy Integrations** | Nginx, HAProxy, Envoy support |

## Performance

| Operation | Software | QUAC 100 Hardware | Speedup |
|-----------|----------|-------------------|---------|
| ML-KEM-768 Keygen | 0.15 ms | 0.7 µs | **214x** |
| ML-KEM-768 Encaps | 0.10 ms | 0.5 µs | **200x** |
| ML-KEM-768 Decaps | 0.12 ms | 0.5 µs | **240x** |
| ML-DSA-65 Sign | 0.45 ms | 2.5 µs | **180x** |
| ML-DSA-65 Verify | 0.15 ms | 1.0 µs | **150x** |
| TLS Handshake | 5 ms | 20 µs | **250x** |
| Handshakes/sec | 200 | 50,000 | **250x** |

## Quick Start

### Build

```bash
# Standard build (software fallback)
make

# With QUAC 100 hardware acceleration
make QUAC_SDK_PATH=/opt/quac-sdk

# Debug build
make DEBUG=1

# Install
sudo make install PREFIX=/usr/local
```

### CMake Build

```bash
mkdir build && cd build
cmake -DQUAC_SDK_PATH=/opt/quac-sdk ..
cmake --build .
ctest
sudo cmake --install .
```

### Generate Certificates

```bash
# Generate ML-DSA-65 self-signed certificate
./build/bin/quac-tls-keygen \
    --algorithm mldsa65 \
    --subject "CN=example.com" \
    --days 365 \
    --cert server.pem \
    --key server-key.pem
```

### Example Server

```bash
# Run example TLS server with auto-generated cert
./build/bin/example_tls_server -g -p 8443

# Test with curl
curl -k https://localhost:8443
```

## API Usage

### Basic TLS Server

```c
#include <quac_tls.h>

int main() {
    // Initialize library
    quac_tls_init();
    
    // Create server context with PQC
    quac_tls_config_t config;
    quac_tls_config_default(&config);
    config.kex_algorithms = QUAC_TLS_KEX_X25519_ML_KEM_768;
    config.sig_algorithms = QUAC_TLS_SIG_ML_DSA_65;
    
    quac_tls_ctx_t *ctx = quac_tls_ctx_new_config(1, &config);
    
    // Load certificate and key
    quac_tls_ctx_use_certificate_file(ctx, "server.pem");
    quac_tls_ctx_use_private_key_file(ctx, "server-key.pem");
    
    // Accept connections
    quac_tls_conn_t *conn = quac_tls_conn_new(ctx);
    quac_tls_conn_set_fd(conn, client_fd);
    quac_tls_accept(conn);
    
    // Read/write data
    char buf[4096];
    int n = quac_tls_read(conn, buf, sizeof(buf));
    quac_tls_write(conn, response, response_len);
    
    // Cleanup
    quac_tls_shutdown(conn);
    quac_tls_conn_free(conn);
    quac_tls_ctx_free(ctx);
    quac_tls_cleanup();
    
    return 0;
}
```

### Key Generation

```c
#include <quac_tls.h>

// Generate ML-DSA-65 keypair
uint8_t *pub_key, *priv_key;
size_t pub_len, priv_len;

quac_tls_generate_mldsa_keypair(65, &pub_key, &pub_len,
                                 &priv_key, &priv_len);

// Generate self-signed certificate
char *cert_pem, *key_pem;
quac_tls_generate_self_signed_mldsa(65, "CN=example.com", 365,
                                     &cert_pem, &key_pem);
```

## Algorithm Support

### Key Exchange (KEX)

| Algorithm | Flag | Description |
|-----------|------|-------------|
| X25519+ML-KEM-768 | `QUAC_TLS_KEX_X25519_ML_KEM_768` | Hybrid (recommended) |
| P-256+ML-KEM-768 | `QUAC_TLS_KEX_P256_ML_KEM_768` | Hybrid with P-256 |
| P-384+ML-KEM-1024 | `QUAC_TLS_KEX_P384_ML_KEM_1024` | Hybrid high-security |
| ML-KEM-512 | `QUAC_TLS_KEX_ML_KEM_512` | Pure PQC Level 1 |
| ML-KEM-768 | `QUAC_TLS_KEX_ML_KEM_768` | Pure PQC Level 3 |
| ML-KEM-1024 | `QUAC_TLS_KEX_ML_KEM_1024` | Pure PQC Level 5 |
| X25519 | `QUAC_TLS_KEX_X25519` | Classical fallback |

### Signatures

| Algorithm | Flag | Public Key | Signature |
|-----------|------|------------|-----------|
| ML-DSA-44 | `QUAC_TLS_SIG_ML_DSA_44` | 1,312 B | 2,420 B |
| ML-DSA-65 | `QUAC_TLS_SIG_ML_DSA_65` | 1,952 B | 3,309 B |
| ML-DSA-87 | `QUAC_TLS_SIG_ML_DSA_87` | 2,592 B | 4,627 B |
| Ed25519 | `QUAC_TLS_SIG_ED25519` | 32 B | 64 B |
| ECDSA P-256 | `QUAC_TLS_SIG_ECDSA_P256` | 64 B | ~72 B |

## Proxy Integrations

### Nginx

```nginx
server {
    listen 443 ssl http2;
    
    quac_tls on;
    quac_tls_certificate /etc/nginx/ssl/mldsa65-cert.pem;
    quac_tls_certificate_key /etc/nginx/ssl/mldsa65-key.pem;
    quac_tls_kex X25519_ML_KEM_768;
    quac_tls_sigalgs ML_DSA_65;
    quac_tls_hardware on;
}
```

See [nginx/README.md](nginx/README.md) for full documentation.

### HAProxy

```haproxy
frontend https
    bind *:443 ssl crt /etc/haproxy/certs/combined.pem
    quac-tls-engine /usr/lib/libquac_tls.so
    quac-tls-kex x25519_mlkem768
    quac-tls-sigalgs mldsa65
```

See [haproxy/README.md](haproxy/README.md) for full documentation.

### Envoy

```yaml
- name: envoy.filters.network.quac_tls
  typed_config:
    certificate_path: /etc/envoy/certs/server.pem
    private_key_path: /etc/envoy/certs/server-key.pem
    kex_algorithms: [X25519_ML_KEM_768]
    sig_algorithms: [ML_DSA_65]
    hardware_acceleration: true
```

See [envoy/README.md](envoy/README.md) for full documentation.

## Directory Structure

```
tls/
├── quac_tls.h              # Public API header
├── quac_tls_internal.h     # Internal structures
├── quac_tls.c              # Core implementation
├── quac_tls_pqc.c          # PQC algorithm support
├── quac_tls.def            # Windows DLL exports
├── Makefile                # GNU Make build
├── CMakeLists.txt          # CMake build
├── README.md               # This file
├── tests/
│   ├── test_quac_tls.c     # Test suite
│   └── bench_quac_tls.c    # Benchmarks
├── examples/
│   ├── example_tls_server.c
│   └── example_tls_client.c
├── tools/
│   └── quac_tls_keygen.c   # Certificate generator
├── cmake/
│   └── quac_tls-config.cmake.in
├── nginx/
│   ├── ngx_http_quac_module.c
│   ├── nginx-pqc.conf
│   └── README.md
├── haproxy/
│   ├── quac_haproxy_engine.c
│   ├── haproxy-pqc.cfg
│   └── README.md
└── envoy/
    ├── quac_envoy_filter.cc
    ├── envoy-pqc.yaml
    └── README.md
```

## Build Options

### Makefile

| Option | Description |
|--------|-------------|
| `DEBUG=1` | Enable debug symbols and assertions |
| `QUAC_SDK_PATH=/path` | Enable hardware acceleration |
| `OPENSSL_PATH=/path` | Custom OpenSSL location |
| `PREFIX=/path` | Installation prefix |

### CMake

| Option | Default | Description |
|--------|---------|-------------|
| `BUILD_TESTS` | ON | Build test suite |
| `BUILD_EXAMPLES` | ON | Build examples |
| `BUILD_TOOLS` | ON | Build keygen tool |
| `BUILD_SHARED_LIBS` | ON | Build shared library |
| `QUAC_SDK_PATH` | - | Path to QUAC SDK |

## Testing

```bash
# Run test suite
make test

# Run benchmarks
make bench

# Run with verbose output
./build/bin/test_quac_tls

# Run specific benchmark iterations
./build/bin/bench_quac_tls -n 1000
```

## Requirements

- **Compiler**: GCC 9+ or Clang 10+
- **OpenSSL**: 3.0+ (with OQS provider for full PQC support)
- **CMake**: 3.16+ (for CMake build)
- **QUAC SDK**: Optional, for hardware acceleration

## License

Copyright 2025 Dyber, Inc. All Rights Reserved.

## See Also

- [QuantaCore SDK Overview](../../README.md)
- [PKCS#11 Integration](../pkcs11/README.md)
- [OpenSSL Engine](../openssl/README.md)