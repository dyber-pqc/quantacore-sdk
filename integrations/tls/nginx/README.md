# QUAC 100 Nginx Integration

Hardware-accelerated post-quantum TLS termination for Nginx using the QUAC 100 cryptographic accelerator.

## Overview

The `ngx_http_quac_module` provides:

- **ML-KEM Key Exchange**: Quantum-resistant key encapsulation (512, 768, 1024)
- **ML-DSA Authentication**: Post-quantum digital signatures (44, 65, 87)
- **Hybrid Modes**: Combined classical + PQC for defense in depth
- **Hardware Acceleration**: QUAC 100 offload for high-performance TLS
- **Seamless Integration**: Drop-in replacement for standard SSL/TLS

## Performance

| Operation | Software | QUAC 100 Hardware |
|-----------|----------|-------------------|
| TLS Handshakes/sec | ~5,000 | ~250,000 |
| ML-KEM-768 KEX | ~2ms | ~0.7µs |
| ML-DSA-65 Sign | ~5ms | ~2.5µs |
| Concurrent Connections | ~10,000 | ~100,000+ |

## Quick Start

### 1. Install Dependencies

```bash
# Install QUAC TLS library
cd /path/to/quantacore-sdk/integrations/tls
make && sudo make install

# Verify installation
ldconfig -p | grep quac_tls
```

### 2. Build Nginx with Module

```bash
# Download Nginx source
wget https://nginx.org/download/nginx-1.26.0.tar.gz
tar xzf nginx-1.26.0.tar.gz
cd nginx-1.26.0

# Configure with QUAC module
./configure \
    --prefix=/etc/nginx \
    --sbin-path=/usr/sbin/nginx \
    --modules-path=/usr/lib64/nginx/modules \
    --conf-path=/etc/nginx/nginx.conf \
    --error-log-path=/var/log/nginx/error.log \
    --http-log-path=/var/log/nginx/access.log \
    --pid-path=/var/run/nginx.pid \
    --with-http_ssl_module \
    --with-http_v2_module \
    --with-threads \
    --add-module=/path/to/quantacore-sdk/integrations/tls/nginx

# Build and install
make -j$(nproc)
sudo make install
```

### 3. Generate ML-DSA Certificates

```bash
# Generate self-signed ML-DSA-65 certificate
quac-tls-keygen --algorithm mldsa65 \
    --subject "CN=pqc.example.com" \
    --days 365 \
    --cert /etc/nginx/ssl/mldsa65-cert.pem \
    --key /etc/nginx/ssl/mldsa65-key.pem

# Or use the library directly
./generate_mldsa_cert 65 "CN=pqc.example.com" 365 \
    /etc/nginx/ssl/mldsa65-cert.pem \
    /etc/nginx/ssl/mldsa65-key.pem
```

### 4. Configure Nginx

```nginx
server {
    listen 443 ssl http2;
    server_name pqc.example.com;

    # Enable QUAC PQC TLS
    quac_tls on;
    quac_tls_certificate /etc/nginx/ssl/mldsa65-cert.pem;
    quac_tls_certificate_key /etc/nginx/ssl/mldsa65-key.pem;
    quac_tls_protocols TLSv1.3;
    quac_tls_kex X25519_ML_KEM_768 ML_KEM_768;
    quac_tls_sigalgs ML_DSA_65;
    quac_tls_hardware on;

    root /var/www/html;
}
```

### 5. Start Nginx

```bash
# Test configuration
sudo nginx -t

# Start Nginx
sudo systemctl start nginx

# Check status
sudo systemctl status nginx
```

### 6. Verify PQC TLS

```bash
# Test with OpenSSL (requires PQC-enabled build)
openssl s_client -connect pqc.example.com:443 \
    -groups x25519_kyber768 \
    -sigalgs mldsa65

# Check negotiated parameters
curl -v https://pqc.example.com 2>&1 | grep -E "(SSL|cipher|kex)"
```

## Configuration Directives

### Core Settings

| Directive | Default | Description |
|-----------|---------|-------------|
| `quac_tls` | off | Enable/disable QUAC TLS module |
| `quac_tls_certificate` | - | Path to certificate file |
| `quac_tls_certificate_key` | - | Path to private key file |
| `quac_tls_protocols` | TLSv1.3 | Allowed TLS protocol versions |

### Key Exchange

| Directive | Default | Description |
|-----------|---------|-------------|
| `quac_tls_kex` | X25519_ML_KEM_768 | Key exchange algorithms (space-separated) |

Available algorithms:
- `X25519_ML_KEM_768` - Hybrid X25519 + ML-KEM-768 (recommended)
- `P256_ML_KEM_768` - Hybrid P-256 + ML-KEM-768
- `P384_ML_KEM_1024` - Hybrid P-384 + ML-KEM-1024
- `ML_KEM_512` - Pure ML-KEM-512
- `ML_KEM_768` - Pure ML-KEM-768
- `ML_KEM_1024` - Pure ML-KEM-1024
- `X25519` - Classical X25519 (fallback)
- `P256` - Classical P-256 (fallback)

### Signature Algorithms

| Directive | Default | Description |
|-----------|---------|-------------|
| `quac_tls_sigalgs` | ML_DSA_65 | Signature algorithms (space-separated) |

Available algorithms:
- `ML_DSA_44` - ML-DSA Level 2 (NIST security level 2)
- `ML_DSA_65` - ML-DSA Level 3 (recommended)
- `ML_DSA_87` - ML-DSA Level 5 (highest security)
- `ED25519` - Classical Ed25519 (fallback)
- `ECDSA_P256` - Classical ECDSA P-256 (fallback)

### Session Management

| Directive | Default | Description |
|-----------|---------|-------------|
| `quac_tls_session_tickets` | on | Enable session tickets |
| `quac_tls_session_timeout` | 300 | Session cache timeout (seconds) |

### Client Verification

| Directive | Default | Description |
|-----------|---------|-------------|
| `quac_tls_verify_client` | off | Require client certificate |
| `quac_tls_verify_depth` | 4 | Maximum certificate chain depth |
| `quac_tls_ca_certificate` | - | CA certificate for client verification |

### Hardware Settings

| Directive | Default | Description |
|-----------|---------|-------------|
| `quac_tls_hardware` | on | Enable QUAC hardware acceleration |
| `quac_tls_hardware_slot` | 0 | QUAC device slot number |

### Additional Settings

| Directive | Default | Description |
|-----------|---------|-------------|
| `quac_tls_alpn` | h2,http/1.1 | ALPN protocols |
| `quac_tls_ocsp_stapling` | on | Enable OCSP stapling |

## Example Configurations

### Basic HTTPS Server

```nginx
server {
    listen 443 ssl http2;
    server_name www.example.com;

    quac_tls on;
    quac_tls_certificate /etc/nginx/ssl/cert.pem;
    quac_tls_certificate_key /etc/nginx/ssl/key.pem;

    root /var/www/html;
}
```

### High-Security Configuration

```nginx
server {
    listen 443 ssl http2;
    server_name secure.example.com;

    quac_tls on;
    quac_tls_certificate /etc/nginx/ssl/mldsa87-cert.pem;
    quac_tls_certificate_key /etc/nginx/ssl/mldsa87-key.pem;
    quac_tls_protocols TLSv1.3;
    quac_tls_kex P384_ML_KEM_1024;
    quac_tls_sigalgs ML_DSA_87;
    quac_tls_hardware on;

    # Strict security headers
    add_header Strict-Transport-Security "max-age=63072000" always;

    root /var/www/secure;
}
```

### Mutual TLS (mTLS)

```nginx
server {
    listen 443 ssl http2;
    server_name mtls.example.com;

    quac_tls on;
    quac_tls_certificate /etc/nginx/ssl/server.pem;
    quac_tls_certificate_key /etc/nginx/ssl/server-key.pem;
    quac_tls_ca_certificate /etc/nginx/ssl/client-ca.pem;
    quac_tls_verify_client on;
    quac_tls_verify_depth 2;

    location / {
        if ($ssl_client_verify != SUCCESS) {
            return 403;
        }
        proxy_pass http://backend;
    }
}
```

### Load Balancer with PQC Termination

```nginx
upstream backends {
    least_conn;
    server 10.0.0.1:8080;
    server 10.0.0.2:8080;
    server 10.0.0.3:8080;
}

server {
    listen 443 ssl http2;
    server_name lb.example.com;

    quac_tls on;
    quac_tls_certificate /etc/nginx/ssl/lb.pem;
    quac_tls_certificate_key /etc/nginx/ssl/lb-key.pem;
    quac_tls_session_tickets on;
    quac_tls_hardware on;

    location / {
        proxy_pass http://backends;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }
}
```

## Monitoring

### Log Format with PQC Info

```nginx
log_format pqc '$remote_addr - [$time_local] "$request" $status '
               'kex=$sent_http_x_pqc_kex cipher=$sent_http_x_pqc_cipher';

access_log /var/log/nginx/pqc_access.log pqc;
```

### Status Endpoint

```nginx
location /pqc-status {
    return 200 '{"pqc": true, "kex": "$sent_http_x_pqc_kex"}';
    add_header Content-Type application/json;
}
```

## Troubleshooting

### Module Not Loading

```bash
# Check library dependencies
ldd /usr/sbin/nginx | grep quac

# Verify library path
ldconfig -p | grep quac_tls

# Check Nginx error log
tail -f /var/log/nginx/error.log
```

### Hardware Not Detected

```bash
# Check QUAC device
lspci | grep -i quac

# Verify driver loaded
lsmod | grep quac

# Check device permissions
ls -la /dev/quac*
```

### Handshake Failures

```bash
# Enable debug logging
error_log /var/log/nginx/error.log debug;

# Test with verbose OpenSSL
openssl s_client -connect localhost:443 -debug
```

## Files

| File | Description |
|------|-------------|
| `ngx_http_quac_module.c` | Nginx module source code |
| `config` | Nginx module build configuration |
| `nginx-pqc.conf` | Example Nginx configuration |
| `README.md` | This documentation |

## See Also

- [QUAC TLS Library](../core/README.md)
- [HAProxy Integration](../haproxy/README.md)
- [Envoy Integration](../envoy/README.md)