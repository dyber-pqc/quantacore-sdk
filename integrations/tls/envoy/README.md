# QUAC 100 Envoy Proxy Integration

Hardware-accelerated post-quantum TLS termination for Envoy Proxy using the QUAC 100 cryptographic accelerator.

## Overview

The QUAC Envoy integration provides:

- **ML-KEM Key Exchange**: Quantum-resistant key encapsulation (512, 768, 1024)
- **ML-DSA Authentication**: Post-quantum digital signatures (44, 65, 87)
- **Hybrid Modes**: Combined classical + PQC for defense in depth
- **Hardware Acceleration**: QUAC 100 offload for high-performance TLS
- **Native Envoy Filter**: Seamless integration with Envoy's filter chain

## Performance

| Metric | Software Only | QUAC 100 Hardware |
|--------|---------------|-------------------|
| TLS Handshakes/sec | ~8,000 | ~300,000 |
| P99 Latency | ~5ms | ~50µs |
| ML-KEM-768 KEX | ~0.15ms | ~0.7µs |
| ML-DSA-65 Verify | ~0.15ms | ~1.0µs |
| Concurrent Connections | ~20,000 | ~200,000+ |

## Quick Start

### 1. Build QUAC TLS Library

```bash
cd /path/to/quantacore-sdk/integrations/tls
make && sudo make install
```

### 2. Build Envoy with QUAC Filter

```bash
# Clone Envoy
git clone https://github.com/envoyproxy/envoy.git
cd envoy

# Copy QUAC filter
cp /path/to/quantacore-sdk/integrations/tls/envoy/quac_envoy_filter.cc \
   source/extensions/filters/network/quac_tls/

# Add to BUILD file and build
bazel build //source/exe:envoy-static \
    --define quac_tls=enabled
```

### 3. Generate ML-DSA Certificates

```bash
# Generate self-signed ML-DSA-65 certificate
quac-tls-keygen --algorithm mldsa65 \
    --subject "CN=envoy.example.com" \
    --days 365 \
    --cert /etc/envoy/certs/mldsa65-cert.pem \
    --key /etc/envoy/certs/mldsa65-key.pem
```

### 4. Configure Envoy

```yaml
# envoy-pqc.yaml
static_resources:
  listeners:
  - name: pqc_listener
    address:
      socket_address:
        address: 0.0.0.0
        port_value: 8443
    filter_chains:
    - filters:
      - name: envoy.filters.network.quac_tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.quac_tls.v3.QuacTls
          certificate_path: /etc/envoy/certs/mldsa65-cert.pem
          private_key_path: /etc/envoy/certs/mldsa65-key.pem
          kex_algorithms:
          - X25519_ML_KEM_768
          - ML_KEM_768
          sig_algorithms:
          - ML_DSA_65
          hardware_acceleration: true
```

### 5. Run Envoy

```bash
envoy -c /etc/envoy/envoy-pqc.yaml
```

## Configuration Reference

### Filter Configuration

```yaml
name: envoy.filters.network.quac_tls
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.network.quac_tls.v3.QuacTls
  
  # Certificate and key
  certificate_path: /path/to/cert.pem
  private_key_path: /path/to/key.pem
  ca_certificate_path: /path/to/ca.pem  # Optional, for client verification
  
  # TLS version (only TLS 1.3 supported for PQC)
  min_tls_version: TLSv1_3
  max_tls_version: TLSv1_3
  
  # Key exchange algorithms (in preference order)
  kex_algorithms:
  - X25519_ML_KEM_768    # Hybrid (recommended)
  - P256_ML_KEM_768      # Hybrid with P-256
  - P384_ML_KEM_1024     # Hybrid with P-384
  - ML_KEM_768           # Pure PQC
  - X25519               # Classical fallback
  
  # Signature algorithms (in preference order)  
  sig_algorithms:
  - ML_DSA_65            # ML-DSA Level 3 (recommended)
  - ML_DSA_87            # ML-DSA Level 5
  - ML_DSA_44            # ML-DSA Level 2
  - ECDSA_P256           # Classical fallback
  
  # Client verification
  require_client_cert: false
  verify_depth: 4
  
  # Session management
  session_timeout: 300
  session_ticket_keys:
    filename: /etc/envoy/ticket-keys.bin
  
  # Hardware acceleration
  hardware_acceleration: true
  hardware_slot: 0
  
  # ALPN
  alpn_protocols:
  - h2
  - http/1.1
  
  # Performance tuning
  max_concurrent_streams: 100
  initial_stream_window_size: 65536
```

### Available Key Exchange Algorithms

| Algorithm | Description | Security Level |
|-----------|-------------|----------------|
| `X25519_ML_KEM_768` | Hybrid X25519 + ML-KEM-768 | 128-bit + NIST Level 3 |
| `P256_ML_KEM_768` | Hybrid P-256 + ML-KEM-768 | 128-bit + NIST Level 3 |
| `P384_ML_KEM_1024` | Hybrid P-384 + ML-KEM-1024 | 192-bit + NIST Level 5 |
| `ML_KEM_512` | Pure ML-KEM-512 | NIST Level 1 |
| `ML_KEM_768` | Pure ML-KEM-768 | NIST Level 3 |
| `ML_KEM_1024` | Pure ML-KEM-1024 | NIST Level 5 |
| `X25519` | Classical X25519 | 128-bit classical |
| `P256` | Classical P-256 | 128-bit classical |

### Available Signature Algorithms

| Algorithm | Description | Key Size | Signature Size |
|-----------|-------------|----------|----------------|
| `ML_DSA_44` | ML-DSA Level 2 | 1312 B | 2420 B |
| `ML_DSA_65` | ML-DSA Level 3 | 1952 B | 3309 B |
| `ML_DSA_87` | ML-DSA Level 5 | 2592 B | 4627 B |
| `ED25519` | Classical Ed25519 | 32 B | 64 B |
| `ECDSA_P256` | Classical P-256 | 64 B | ~72 B |

## Example Configurations

### Basic HTTPS Termination

```yaml
static_resources:
  listeners:
  - name: https_listener
    address:
      socket_address:
        address: 0.0.0.0
        port_value: 443
    filter_chains:
    - filters:
      - name: envoy.filters.network.quac_tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.quac_tls.v3.QuacTls
          certificate_path: /etc/envoy/certs/server.pem
          private_key_path: /etc/envoy/certs/server-key.pem
          kex_algorithms: [X25519_ML_KEM_768]
          sig_algorithms: [ML_DSA_65]
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: ingress_http
          route_config:
            name: local_route
            virtual_hosts:
            - name: backend
              domains: ["*"]
              routes:
              - match: {prefix: "/"}
                route: {cluster: backend_cluster}
          http_filters:
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
  
  clusters:
  - name: backend_cluster
    connect_timeout: 5s
    type: STRICT_DNS
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: backend_cluster
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: backend
                port_value: 8080
```

### Mutual TLS (mTLS)

```yaml
- name: envoy.filters.network.quac_tls
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.network.quac_tls.v3.QuacTls
    certificate_path: /etc/envoy/certs/server.pem
    private_key_path: /etc/envoy/certs/server-key.pem
    ca_certificate_path: /etc/envoy/certs/client-ca.pem
    require_client_cert: true
    verify_depth: 2
    kex_algorithms: [P384_ML_KEM_1024]
    sig_algorithms: [ML_DSA_87]
```

### High-Performance Configuration

```yaml
- name: envoy.filters.network.quac_tls
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.network.quac_tls.v3.QuacTls
    certificate_path: /etc/envoy/certs/server.pem
    private_key_path: /etc/envoy/certs/server-key.pem
    kex_algorithms: [X25519_ML_KEM_768]
    sig_algorithms: [ML_DSA_65]
    hardware_acceleration: true
    hardware_slot: 0
    session_timeout: 3600
    max_concurrent_streams: 256
    initial_stream_window_size: 1048576
```

## Monitoring & Metrics

### Prometheus Metrics

The QUAC filter exposes metrics compatible with Envoy's stats system:

```
# TLS handshake metrics
quac_tls_handshakes_total{result="success"}
quac_tls_handshakes_total{result="failed"}
quac_tls_handshake_duration_seconds{quantile="0.5"}
quac_tls_handshake_duration_seconds{quantile="0.99"}

# PQC operation metrics
quac_tls_mlkem_encaps_total
quac_tls_mlkem_decaps_total
quac_tls_mldsa_sign_total
quac_tls_mldsa_verify_total

# Hardware acceleration metrics
quac_tls_hw_operations_total
quac_tls_sw_fallback_total

# Connection metrics
quac_tls_active_connections
quac_tls_session_resumptions_total
```

### Admin Interface

```yaml
admin:
  address:
    socket_address:
      address: 127.0.0.1
      port_value: 9901

# Access metrics at:
# http://127.0.0.1:9901/stats/prometheus
# http://127.0.0.1:9901/stats?filter=quac_tls
```

### Logging

```yaml
- name: envoy.filters.network.quac_tls
  typed_config:
    # ... other config ...
    access_log:
    - name: envoy.access_loggers.file
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog
        path: /var/log/envoy/pqc-tls.log
        log_format:
          text_format: |
            [%START_TIME%] %DOWNSTREAM_REMOTE_ADDRESS% 
            kex=%QUAC_TLS_KEX% cipher=%QUAC_TLS_CIPHER% 
            handshake_ms=%QUAC_TLS_HANDSHAKE_MS%
```

## Troubleshooting

### Filter Not Loading

```bash
# Check Envoy build includes QUAC filter
envoy --version

# Verify library is installed
ldconfig -p | grep quac_tls

# Check Envoy logs
envoy -c config.yaml --log-level debug 2>&1 | grep -i quac
```

### Handshake Failures

```bash
# Test with OpenSSL (PQC-enabled build required)
openssl s_client -connect localhost:8443 \
    -groups x25519_kyber768

# Check certificate validity
openssl x509 -in /etc/envoy/certs/server.pem -text -noout
```

### Hardware Not Detected

```bash
# Check QUAC device
lspci | grep -i quac

# Verify driver loaded
lsmod | grep quac

# Check permissions
ls -la /dev/quac*
```

### Performance Issues

```bash
# Check hardware utilization
quac-stats --device 0

# Monitor Envoy stats
curl -s http://localhost:9901/stats | grep quac_tls

# Profile with perf
perf record -g envoy -c config.yaml
perf report
```

## Files

| File | Description |
|------|-------------|
| `quac_envoy_filter.cc` | Envoy network filter implementation |
| `envoy-pqc.yaml` | Example Envoy configuration |
| `README.md` | This documentation |

## Building from Source

### Prerequisites

- Envoy source code
- Bazel build system
- QUAC TLS library installed
- OpenSSL 3.0+ with OQS provider (optional)

### Build Steps

```bash
# 1. Clone Envoy
git clone https://github.com/envoyproxy/envoy.git
cd envoy

# 2. Create filter directory
mkdir -p source/extensions/filters/network/quac_tls

# 3. Copy filter source
cp /path/to/quac_envoy_filter.cc source/extensions/filters/network/quac_tls/

# 4. Create BUILD file
cat > source/extensions/filters/network/quac_tls/BUILD << 'EOF'
load("//bazel:envoy_build_system.bzl", "envoy_cc_extension")

envoy_cc_extension(
    name = "quac_tls",
    srcs = ["quac_envoy_filter.cc"],
    deps = [
        "//envoy/network:filter_interface",
        "//source/common/network:utility_lib",
        "@quac_tls//:quac_tls",
    ],
)
EOF

# 5. Add to extensions list
echo 'EXTENSIONS["envoy.filters.network.quac_tls"] = "//source/extensions/filters/network/quac_tls:quac_tls"' \
    >> source/extensions/extensions_build_config.bzl

# 6. Build Envoy
bazel build //source/exe:envoy-static -c opt
```

## See Also

- [QUAC TLS Library](../README.md)
- [Nginx Integration](../nginx/README.md)
- [HAProxy Integration](../haproxy/README.md)
- [Envoy Documentation](https://www.envoyproxy.io/docs/envoy/latest/)