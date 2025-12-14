# QUAC 100 HAProxy Integration

Hardware-accelerated post-quantum TLS termination for HAProxy using the QUAC 100 cryptographic accelerator via OpenSSL engine.

## Overview

The QUAC HAProxy engine provides:

- **OpenSSL Engine Integration**: Seamless hardware acceleration via standard OpenSSL API
- **ML-KEM Key Exchange**: Quantum-resistant key encapsulation
- **ML-DSA Authentication**: Post-quantum digital signatures
- **QRNG Integration**: Hardware random number generation
- **Statistics Tracking**: Real-time performance monitoring

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        HAProxy                               │
├─────────────────────────────────────────────────────────────┤
│                    OpenSSL 3.x                               │
├─────────────────────────────────────────────────────────────┤
│              QUAC OpenSSL Engine (quac_pqc)                 │
├─────────────────────────────────────────────────────────────┤
│              QUAC TLS Library (libquac_tls)                 │
├─────────────────────────────────────────────────────────────┤
│              QUAC 100 Hardware / Software Fallback          │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Build and Install Engine

```bash
# Build QUAC TLS library and HAProxy engine
cd /path/to/quantacore-sdk/integrations/tls
make
sudo make install

# Verify engine installation
openssl engine -t quac_pqc
```

### 2. Configure HAProxy

Add to `haproxy.cfg`:

```
global
    ssl-engine quac_pqc
    ssl-default-bind-curves X25519:x25519_kyber768:kyber768
```

### 3. Generate Certificates

```bash
# Generate ML-DSA-65 certificate
quac-tls-keygen --algorithm mldsa65 \
    --subject "CN=haproxy.example.com" \
    --days 365 \
    --cert /etc/haproxy/certs/mldsa65-cert.pem \
    --key /etc/haproxy/certs/mldsa65-key.pem

# Create bundle
cat mldsa65-cert.pem mldsa65-key.pem > pqc-bundle.pem
```

### 4. Start HAProxy

```bash
haproxy -f haproxy-pqc.cfg
```

## Configuration Reference

### Global SSL Settings

```
global
    # Load QUAC engine
    ssl-engine quac_pqc
    
    # TLS 1.3 cipher suites
    ssl-default-bind-ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    
    # Key exchange groups (hybrid PQC)
    ssl-default-bind-curves X25519:x25519_kyber768:kyber768:P-256:p256_kyber768
    
    # Minimum TLS version
    ssl-default-bind-options ssl-min-ver TLSv1.2
    
    # SSL cache tuning
    tune.ssl.cachesize 100000
    tune.ssl.lifetime 300
```

### Frontend Configuration

```
frontend https_pqc
    bind *:443 ssl crt /etc/haproxy/certs/pqc-bundle.pem alpn h2,http/1.1
    
    # Add PQC headers
    http-response set-header X-PQC-Enabled true
    
    default_backend be_web
```

### Mutual TLS (mTLS)

```
frontend https_mtls
    bind *:8443 ssl crt /etc/haproxy/certs/server.pem verify required ca-file /etc/haproxy/certs/ca.pem
    
    # Require valid client certificate
    http-request deny unless { ssl_c_verify 0 }
    
    # Pass client info to backend
    http-request set-header X-SSL-Client-CN %[ssl_c_s_dn(cn)]
```

## Engine Commands

The QUAC engine supports runtime control via OpenSSL:

```bash
# Get statistics
openssl engine quac_pqc -c -t

# Set device (if multiple QUAC cards)
openssl engine quac_pqc -pre SET_DEVICE:1
```

### Available Commands

| Command | Description |
|---------|-------------|
| `GET_STATS` | Return engine statistics |
| `RESET_STATS` | Reset statistics counters |
| `SET_DEVICE` | Select QUAC device slot |
| `GET_VERSION` | Get engine version |

## Performance Tuning

### Thread Configuration

```
global
    nbthread 8              # Match CPU cores
    cpu-map auto:1/1-8 0-7  # Pin to cores
```

### SSL Cache

```
global
    tune.ssl.cachesize 100000    # Sessions to cache
    tune.ssl.lifetime 300        # Session lifetime (seconds)
    tune.ssl.ssl-ctx-cache-size 1000
```

### Connection Limits

```
global
    maxconn 100000
    
frontend https
    maxconn 50000
    
backend web
    server s1 10.0.0.1:8080 maxconn 1000
```

## Monitoring

### Stats Socket

```
global
    stats socket /var/run/haproxy.sock mode 660 level admin
```

```bash
# Query stats
echo "show stat" | socat stdio /var/run/haproxy.sock
```

### Stats Page

```
listen stats
    bind 127.0.0.1:8404
    stats enable
    stats uri /stats
```

### Prometheus Metrics

```bash
# HAProxy Exporter
haproxy_exporter --haproxy.scrape-uri="unix:/var/run/haproxy.sock"
```

### PQC Statistics JSON

Access via stats backend:

```json
{
  "engine": "quac_pqc",
  "version": "1.0.0",
  "mlkem_encaps": 125432,
  "mlkem_decaps": 125430,
  "mldsa_signs": 63210,
  "mldsa_verifies": 63208,
  "hw_operations": 377280,
  "sw_fallback": 0
}
```

## Certificate Management

### Certificate Bundle Format

HAProxy expects certificates in a single PEM bundle:

```bash
# Server certificate + key + chain
cat server-cert.pem server-key.pem ca-cert.pem > bundle.pem

# Set permissions
chmod 600 bundle.pem
```

### Hybrid Certificates

For maximum compatibility, use hybrid certificates:

```bash
# Classical + PQC in same bundle
cat ecdsa-cert.pem mldsa65-cert.pem ecdsa-key.pem mldsa65-key.pem > hybrid.pem
```

### Certificate Renewal

```bash
#!/bin/bash
# Automated renewal script

# Generate new certificate
quac-tls-keygen --algorithm mldsa65 \
    --subject "CN=haproxy.example.com" \
    --days 90 \
    --cert /tmp/new-cert.pem \
    --key /tmp/new-key.pem

# Create bundle
cat /tmp/new-cert.pem /tmp/new-key.pem > /tmp/new-bundle.pem

# Atomic swap
mv /tmp/new-bundle.pem /etc/haproxy/certs/pqc-bundle.pem

# Reload HAProxy
systemctl reload haproxy
```

## Troubleshooting

### Engine Not Loading

```bash
# Check engine availability
openssl engine -t quac_pqc

# Check library path
ldconfig -p | grep quac

# Verify OpenSSL version
openssl version
```

### Hardware Not Detected

```bash
# Check QUAC device
lspci | grep -i quac
ls -la /dev/quac*

# Check driver
lsmod | grep quac
dmesg | grep -i quac
```

### Connection Failures

```bash
# Test SSL connection
openssl s_client -connect localhost:443 -groups x25519_kyber768

# Check HAProxy logs
tail -f /var/log/haproxy.log

# Debug mode
haproxy -f haproxy-pqc.cfg -d
```

### Performance Issues

```bash
# Check thread utilization
echo "show threads" | socat stdio /var/run/haproxy.sock

# Monitor SSL stats
echo "show ssl sess" | socat stdio /var/run/haproxy.sock
```

## Files

| File | Description |
|------|-------------|
| `quac_haproxy_engine.c` | OpenSSL engine source code |
| `haproxy-pqc.cfg` | Example HAProxy configuration |
| `README.md` | This documentation |

## Security Considerations

1. **Key Protection**: Store private keys with restricted permissions (600)
2. **Certificate Pinning**: Consider HPKP for critical applications
3. **Session Security**: Use short session lifetimes for sensitive data
4. **mTLS**: Require client certificates for high-security endpoints
5. **Rate Limiting**: Implement connection limits to prevent DoS

## See Also

- [QUAC TLS Library](../core/README.md)
- [Nginx Integration](../nginx/README.md)
- [Envoy Integration](../envoy/README.md)