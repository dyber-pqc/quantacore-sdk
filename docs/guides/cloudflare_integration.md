# Cloudflare Integration Guide

## QuantaCore SDK - Deploying Post-Quantum Cryptography at Scale

This guide covers integrating the QUAC 100 Post-Quantum Cryptographic Accelerator with Cloudflare infrastructure for high-performance, quantum-resistant security at the edge.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Cloudflare Workers Integration](#cloudflare-workers-integration)
4. [TLS 1.3 with Post-Quantum Key Exchange](#tls-13-with-post-quantum-key-exchange)
5. [Certificate Signing with ML-DSA](#certificate-signing-with-ml-dsa)
6. [Edge Key Management](#edge-key-management)
7. [Performance Optimization](#performance-optimization)
8. [Monitoring and Observability](#monitoring-and-observability)
9. [Security Best Practices](#security-best-practices)
10. [Deployment Checklist](#deployment-checklist)

---

## Overview

The QuantaCore QUAC 100 accelerator enables Cloudflare deployments to achieve:

- **Post-Quantum TLS**: ML-KEM (Kyber) key exchange resistant to quantum attacks
- **Post-Quantum Signatures**: ML-DSA (Dilithium) for certificate chains
- **High Throughput**: 20,000+ key exchanges per second per device
- **Low Latency**: Sub-millisecond cryptographic operations
- **Hardware Security**: Tamper-resistant key storage

### Use Cases

| Use Case | Algorithms | Benefit |
|----------|-----------|---------|
| TLS Handshakes | ML-KEM-768 | Quantum-resistant key exchange |
| Certificate Signing | ML-DSA-65 | Post-quantum certificate chains |
| Token Signing | ML-DSA-44 | Fast JWT/PASETO signatures |
| Key Wrapping | ML-KEM-1024 | Protected key distribution |
| Session Tickets | ML-KEM-512 | Lightweight session resumption |

---

## Architecture

### Cloudflare Edge with QUAC 100

```
                    Internet
                       │
                       ▼
┌──────────────────────────────────────────┐
│           Cloudflare Edge PoP            │
│                                          │
│  ┌────────────────────────────────────┐  │
│  │        Cloudflare Workers          │  │
│  │                                    │  │
│  │  ┌─────────┐    ┌─────────┐       │  │
│  │  │ Worker  │    │ Worker  │  ...  │  │
│  │  └────┬────┘    └────┬────┘       │  │
│  │       │              │            │  │
│  └───────┼──────────────┼────────────┘  │
│          │              │               │
│  ┌───────▼──────────────▼────────────┐  │
│  │      QuantaCore SDK (Rust/C)      │  │
│  └───────────────┬───────────────────┘  │
│                  │                      │
│  ┌───────────────▼───────────────────┐  │
│  │      QUAC 100 Accelerator         │  │
│  │  ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐  │  │
│  │  │ KEM │ │Sign │ │QRNG │ │Keys │  │  │
│  │  └─────┘ └─────┘ └─────┘ └─────┘  │  │
│  └───────────────────────────────────┘  │
│                                          │
└──────────────────────────────────────────┘
```

### Multi-Accelerator Configuration

For high-traffic PoPs, deploy multiple QUAC 100 devices:

```c
#include <quac100.h>

#define MAX_DEVICES 4

typedef struct {
    quac_device_t devices[MAX_DEVICES];
    uint32_t device_count;
    uint32_t next_device;  /* Round-robin counter */
    pthread_mutex_t lock;
} device_pool_t;

device_pool_t g_pool;

/* Initialize device pool */
int init_device_pool(void)
{
    quac_result_t result = quac_init(NULL);
    if (QUAC_FAILED(result)) {
        return -1;
    }
    
    result = quac_device_count(&g_pool.device_count);
    if (QUAC_FAILED(result) || g_pool.device_count == 0) {
        quac_shutdown();
        return -1;
    }
    
    if (g_pool.device_count > MAX_DEVICES) {
        g_pool.device_count = MAX_DEVICES;
    }
    
    for (uint32_t i = 0; i < g_pool.device_count; i++) {
        result = quac_open(i, &g_pool.devices[i]);
        if (QUAC_FAILED(result)) {
            /* Cleanup already opened devices */
            for (uint32_t j = 0; j < i; j++) {
                quac_close(g_pool.devices[j]);
            }
            quac_shutdown();
            return -1;
        }
    }
    
    pthread_mutex_init(&g_pool.lock, NULL);
    return 0;
}

/* Get next device (round-robin) */
quac_device_t get_device(void)
{
    pthread_mutex_lock(&g_pool.lock);
    quac_device_t device = g_pool.devices[g_pool.next_device];
    g_pool.next_device = (g_pool.next_device + 1) % g_pool.device_count;
    pthread_mutex_unlock(&g_pool.lock);
    return device;
}
```

---

## Cloudflare Workers Integration

### Rust Bindings for Workers

Create Rust bindings for use in Cloudflare Workers:

```rust
// quac100-rs/src/lib.rs

use std::ffi::c_void;

#[repr(C)]
pub struct QuacDevice {
    _private: [u8; 0],
}

pub type QuacDeviceHandle = *mut QuacDevice;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuacResult(pub i32);

impl QuacResult {
    pub const SUCCESS: Self = Self(0);
    
    pub fn is_ok(&self) -> bool {
        self.0 == 0
    }
    
    pub fn is_err(&self) -> bool {
        self.0 != 0
    }
}

#[link(name = "quac100")]
extern "C" {
    pub fn quac_init(options: *const c_void) -> QuacResult;
    pub fn quac_shutdown();
    pub fn quac_open(index: u32, device: *mut QuacDeviceHandle) -> QuacResult;
    pub fn quac_close(device: QuacDeviceHandle) -> QuacResult;
    
    pub fn quac_kem_keygen(
        device: QuacDeviceHandle,
        algorithm: u32,
        public_key: *mut u8,
        pk_size: usize,
        secret_key: *mut u8,
        sk_size: usize,
    ) -> QuacResult;
    
    pub fn quac_kem_encaps(
        device: QuacDeviceHandle,
        algorithm: u32,
        public_key: *const u8,
        pk_size: usize,
        ciphertext: *mut u8,
        ct_size: usize,
        shared_secret: *mut u8,
        ss_size: usize,
    ) -> QuacResult;
    
    pub fn quac_kem_decaps(
        device: QuacDeviceHandle,
        algorithm: u32,
        ciphertext: *const u8,
        ct_size: usize,
        secret_key: *const u8,
        sk_size: usize,
        shared_secret: *mut u8,
        ss_size: usize,
    ) -> QuacResult;
}

// Safe Rust wrapper
pub struct Device {
    handle: QuacDeviceHandle,
}

impl Device {
    pub fn open(index: u32) -> Result<Self, QuacResult> {
        let mut handle: QuacDeviceHandle = std::ptr::null_mut();
        let result = unsafe { quac_open(index, &mut handle) };
        if result.is_ok() {
            Ok(Device { handle })
        } else {
            Err(result)
        }
    }
    
    pub fn kyber768_keygen(&self) -> Result<(Vec<u8>, Vec<u8>), QuacResult> {
        const PK_SIZE: usize = 1184;
        const SK_SIZE: usize = 2400;
        const ALGORITHM: u32 = 0x1101;  // QUAC_ALGORITHM_KYBER768
        
        let mut pk = vec![0u8; PK_SIZE];
        let mut sk = vec![0u8; SK_SIZE];
        
        let result = unsafe {
            quac_kem_keygen(
                self.handle,
                ALGORITHM,
                pk.as_mut_ptr(),
                PK_SIZE,
                sk.as_mut_ptr(),
                SK_SIZE,
            )
        };
        
        if result.is_ok() {
            Ok((pk, sk))
        } else {
            Err(result)
        }
    }
    
    pub fn kyber768_encaps(&self, public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), QuacResult> {
        const CT_SIZE: usize = 1088;
        const SS_SIZE: usize = 32;
        const ALGORITHM: u32 = 0x1101;
        
        let mut ct = vec![0u8; CT_SIZE];
        let mut ss = vec![0u8; SS_SIZE];
        
        let result = unsafe {
            quac_kem_encaps(
                self.handle,
                ALGORITHM,
                public_key.as_ptr(),
                public_key.len(),
                ct.as_mut_ptr(),
                CT_SIZE,
                ss.as_mut_ptr(),
                SS_SIZE,
            )
        };
        
        if result.is_ok() {
            Ok((ct, ss))
        } else {
            Err(result)
        }
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        unsafe { quac_close(self.handle) };
    }
}

// Initialize SDK
pub fn init() -> Result<(), QuacResult> {
    let result = unsafe { quac_init(std::ptr::null()) };
    if result.is_ok() {
        Ok(())
    } else {
        Err(result)
    }
}
```

### Worker Implementation

```rust
// src/worker.rs

use worker::*;
use quac100_rs::{Device, init};
use std::sync::OnceLock;

static DEVICE: OnceLock<Device> = OnceLock::new();

fn get_device() -> &'static Device {
    DEVICE.get_or_init(|| {
        init().expect("Failed to initialize QUAC SDK");
        Device::open(0).expect("Failed to open QUAC device")
    })
}

#[event(fetch)]
async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let router = Router::new();
    
    router
        .post_async("/api/pq-keygen", |_req, _ctx| async {
            let device = get_device();
            
            match device.kyber768_keygen() {
                Ok((pk, _sk)) => {
                    // Return public key (don't expose secret key!)
                    let pk_base64 = base64::encode(&pk);
                    Response::ok(format!(r#"{{"public_key": "{}"}}"#, pk_base64))
                }
                Err(e) => {
                    Response::error(format!("Key generation failed: {:?}", e), 500)
                }
            }
        })
        .post_async("/api/pq-encapsulate", |mut req, _ctx| async {
            let body: serde_json::Value = req.json().await?;
            let pk_base64 = body["public_key"].as_str()
                .ok_or("Missing public_key")?;
            let pk = base64::decode(pk_base64)
                .map_err(|_| "Invalid base64")?;
            
            let device = get_device();
            
            match device.kyber768_encaps(&pk) {
                Ok((ct, ss)) => {
                    let response = serde_json::json!({
                        "ciphertext": base64::encode(&ct),
                        "shared_secret_hash": hex::encode(&sha256(&ss))
                    });
                    Response::from_json(&response)
                }
                Err(e) => {
                    Response::error(format!("Encapsulation failed: {:?}", e), 500)
                }
            }
        })
        .run(req, env)
        .await
}
```

---

## TLS 1.3 with Post-Quantum Key Exchange

### Hybrid Key Exchange

Implement hybrid classical + post-quantum key exchange for TLS 1.3:

```c
/* hybrid_keyex.c */
#include <quac100.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

typedef struct {
    /* Classical (X25519) */
    uint8_t x25519_public[32];
    uint8_t x25519_private[32];
    
    /* Post-Quantum (Kyber768) */
    uint8_t kyber_public[QUAC_KYBER768_PUBLIC_KEY_SIZE];
    uint8_t kyber_secret[QUAC_KYBER768_SECRET_KEY_SIZE];
} hybrid_keypair_t;

typedef struct {
    /* Classical */
    uint8_t x25519_ciphertext[32];  /* Actually peer's public key */
    
    /* Post-Quantum */
    uint8_t kyber_ciphertext[QUAC_KYBER768_CIPHERTEXT_SIZE];
} hybrid_ciphertext_t;

/* Generate hybrid key pair */
int hybrid_keygen(quac_device_t device, hybrid_keypair_t *kp)
{
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey = NULL;
    size_t len;
    
    /* Generate X25519 key pair */
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_keygen(ctx, &pkey);
    
    len = 32;
    EVP_PKEY_get_raw_public_key(pkey, kp->x25519_public, &len);
    len = 32;
    EVP_PKEY_get_raw_private_key(pkey, kp->x25519_private, &len);
    
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    
    /* Generate Kyber768 key pair using QUAC 100 */
    quac_result_t result = quac_kem_keygen(
        device, QUAC_ALGORITHM_KYBER768,
        kp->kyber_public, sizeof(kp->kyber_public),
        kp->kyber_secret, sizeof(kp->kyber_secret)
    );
    
    return QUAC_SUCCEEDED(result) ? 0 : -1;
}

/* Client: Encapsulate to server's public key */
int hybrid_encaps(quac_device_t device,
                  const uint8_t *server_x25519_pk,
                  const uint8_t *server_kyber_pk,
                  hybrid_ciphertext_t *ct,
                  uint8_t *shared_secret,
                  size_t ss_len)
{
    uint8_t x25519_shared[32];
    uint8_t kyber_shared[32];
    uint8_t combined[64];
    
    /* X25519 key exchange */
    EVP_PKEY *client_key, *server_key;
    EVP_PKEY_CTX *ctx;
    
    /* Generate ephemeral X25519 key */
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_keygen(ctx, &client_key);
    EVP_PKEY_CTX_free(ctx);
    
    /* Export client public key as "ciphertext" */
    size_t len = 32;
    EVP_PKEY_get_raw_public_key(client_key, ct->x25519_ciphertext, &len);
    
    /* Import server public key and derive shared secret */
    server_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
                                              server_x25519_pk, 32);
    
    ctx = EVP_PKEY_CTX_new(client_key, NULL);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, server_key);
    len = 32;
    EVP_PKEY_derive(ctx, x25519_shared, &len);
    
    EVP_PKEY_free(client_key);
    EVP_PKEY_free(server_key);
    EVP_PKEY_CTX_free(ctx);
    
    /* Kyber encapsulation using QUAC 100 */
    quac_result_t result = quac_kem_encaps(
        device, QUAC_ALGORITHM_KYBER768,
        server_kyber_pk, QUAC_KYBER768_PUBLIC_KEY_SIZE,
        ct->kyber_ciphertext, sizeof(ct->kyber_ciphertext),
        kyber_shared, sizeof(kyber_shared)
    );
    
    if (QUAC_FAILED(result)) {
        return -1;
    }
    
    /* Combine shared secrets: HKDF(X25519 || Kyber) */
    memcpy(combined, x25519_shared, 32);
    memcpy(combined + 32, kyber_shared, 32);
    
    /* Derive final shared secret using HKDF */
    EVP_PKEY_CTX *hkdf_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    EVP_PKEY_derive_init(hkdf_ctx);
    EVP_PKEY_CTX_set_hkdf_md(hkdf_ctx, EVP_sha256());
    EVP_PKEY_CTX_set1_hkdf_key(hkdf_ctx, combined, 64);
    EVP_PKEY_CTX_set1_hkdf_salt(hkdf_ctx, (uint8_t*)"tls13 pq hybrid", 15);
    EVP_PKEY_CTX_add1_hkdf_info(hkdf_ctx, (uint8_t*)"derived", 7);
    
    len = ss_len;
    EVP_PKEY_derive(hkdf_ctx, shared_secret, &len);
    EVP_PKEY_CTX_free(hkdf_ctx);
    
    /* Zeroize intermediate values */
    OPENSSL_cleanse(x25519_shared, 32);
    OPENSSL_cleanse(kyber_shared, 32);
    OPENSSL_cleanse(combined, 64);
    
    return 0;
}

/* Server: Decapsulate client's ciphertext */
int hybrid_decaps(quac_device_t device,
                  const hybrid_keypair_t *server_kp,
                  const hybrid_ciphertext_t *ct,
                  uint8_t *shared_secret,
                  size_t ss_len)
{
    uint8_t x25519_shared[32];
    uint8_t kyber_shared[32];
    uint8_t combined[64];
    
    /* X25519 key exchange */
    EVP_PKEY *server_key, *client_key;
    EVP_PKEY_CTX *ctx;
    
    server_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
                                               server_kp->x25519_private, 32);
    client_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
                                              ct->x25519_ciphertext, 32);
    
    ctx = EVP_PKEY_CTX_new(server_key, NULL);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, client_key);
    size_t len = 32;
    EVP_PKEY_derive(ctx, x25519_shared, &len);
    
    EVP_PKEY_free(server_key);
    EVP_PKEY_free(client_key);
    EVP_PKEY_CTX_free(ctx);
    
    /* Kyber decapsulation using QUAC 100 */
    quac_result_t result = quac_kem_decaps(
        device, QUAC_ALGORITHM_KYBER768,
        ct->kyber_ciphertext, sizeof(ct->kyber_ciphertext),
        server_kp->kyber_secret, sizeof(server_kp->kyber_secret),
        kyber_shared, sizeof(kyber_shared)
    );
    
    if (QUAC_FAILED(result)) {
        return -1;
    }
    
    /* Combine and derive (same as encaps) */
    memcpy(combined, x25519_shared, 32);
    memcpy(combined + 32, kyber_shared, 32);
    
    EVP_PKEY_CTX *hkdf_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    EVP_PKEY_derive_init(hkdf_ctx);
    EVP_PKEY_CTX_set_hkdf_md(hkdf_ctx, EVP_sha256());
    EVP_PKEY_CTX_set1_hkdf_key(hkdf_ctx, combined, 64);
    EVP_PKEY_CTX_set1_hkdf_salt(hkdf_ctx, (uint8_t*)"tls13 pq hybrid", 15);
    EVP_PKEY_CTX_add1_hkdf_info(hkdf_ctx, (uint8_t*)"derived", 7);
    
    len = ss_len;
    EVP_PKEY_derive(hkdf_ctx, shared_secret, &len);
    EVP_PKEY_CTX_free(hkdf_ctx);
    
    OPENSSL_cleanse(x25519_shared, 32);
    OPENSSL_cleanse(kyber_shared, 32);
    OPENSSL_cleanse(combined, 64);
    
    return 0;
}
```

---

## Certificate Signing with ML-DSA

### Issuing Post-Quantum Certificates

```c
/* pq_cert.c */
#include <quac100.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

/* Custom OIDs for ML-DSA (placeholder - use NIST-assigned OIDs when available) */
#define OID_ML_DSA_44 "2.16.840.1.101.3.4.3.17"
#define OID_ML_DSA_65 "2.16.840.1.101.3.4.3.18"
#define OID_ML_DSA_87 "2.16.840.1.101.3.4.3.19"

typedef struct {
    uint8_t public_key[QUAC_DILITHIUM3_PUBLIC_KEY_SIZE];
    uint8_t secret_key[QUAC_DILITHIUM3_SECRET_KEY_SIZE];
    quac_key_handle_t hw_handle;  /* Hardware-protected key */
} pq_ca_key_t;

/* Generate CA key pair (stored in hardware) */
int pq_ca_keygen(quac_device_t device, pq_ca_key_t *ca_key)
{
    quac_result_t result;
    
    /* Generate key pair and store in hardware */
    result = quac_sign_keygen_stored(
        device,
        QUAC_ALGORITHM_DILITHIUM3,
        "cloudflare-pq-ca",  /* Label */
        true,                 /* Persistent */
        &ca_key->hw_handle,
        ca_key->public_key,
        sizeof(ca_key->public_key)
    );
    
    return QUAC_SUCCEEDED(result) ? 0 : -1;
}

/* Sign certificate using hardware-protected key */
int pq_sign_certificate(quac_device_t device,
                        quac_key_handle_t ca_key_handle,
                        X509 *cert)
{
    /* Get TBS (to-be-signed) certificate data */
    unsigned char *tbs_data = NULL;
    int tbs_len = i2d_re_X509_tbs(cert, &tbs_data);
    if (tbs_len <= 0) {
        return -1;
    }
    
    /* Sign using QUAC 100 with hardware-protected key */
    uint8_t signature[QUAC_DILITHIUM3_SIGNATURE_SIZE];
    size_t sig_len;
    
    quac_result_t result = quac_sign_stored(
        device,
        ca_key_handle,
        tbs_data, tbs_len,
        NULL,  /* No options */
        signature, sizeof(signature),
        &sig_len
    );
    
    OPENSSL_free(tbs_data);
    
    if (QUAC_FAILED(result)) {
        return -1;
    }
    
    /* Set signature algorithm */
    X509_ALGOR *sig_alg;
    const ASN1_BIT_STRING *sig_data;
    X509_get0_signature(&sig_data, &sig_alg, cert);
    
    /* Set ML-DSA-65 OID */
    ASN1_OBJECT *obj = OBJ_txt2obj(OID_ML_DSA_65, 1);
    X509_ALGOR_set0(sig_alg, obj, V_ASN1_UNDEF, NULL);
    
    /* Set signature value */
    ASN1_BIT_STRING *sig_str = ASN1_BIT_STRING_new();
    ASN1_BIT_STRING_set(sig_str, signature, sig_len);
    /* Note: Actually setting signature requires internal API access */
    
    return 0;
}

/* Create and sign a new certificate */
X509* pq_issue_certificate(quac_device_t device,
                           quac_key_handle_t ca_key_handle,
                           const char *common_name,
                           const uint8_t *subject_pk,
                           size_t subject_pk_len,
                           int days_valid)
{
    X509 *cert = X509_new();
    
    /* Set version (v3) */
    X509_set_version(cert, 2);
    
    /* Set serial number */
    ASN1_INTEGER *serial = ASN1_INTEGER_new();
    uint8_t rand_serial[16];
    quac_random_bytes(device, rand_serial, sizeof(rand_serial));
    ASN1_INTEGER_set_uint64(serial, *(uint64_t*)rand_serial);
    X509_set_serialNumber(cert, serial);
    ASN1_INTEGER_free(serial);
    
    /* Set subject */
    X509_NAME *name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (unsigned char*)common_name, -1, -1, 0);
    X509_set_subject_name(cert, name);
    X509_NAME_free(name);
    
    /* Set validity */
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), days_valid * 24 * 60 * 60);
    
    /* Set public key (using custom extension for PQ key) */
    /* In practice, you'd encode the PQ public key properly */
    
    /* Sign the certificate */
    if (pq_sign_certificate(device, ca_key_handle, cert) != 0) {
        X509_free(cert);
        return NULL;
    }
    
    return cert;
}
```

---

## Edge Key Management

### Distributed Key Generation

```c
/* edge_keymgmt.c */
#include <quac100.h>

typedef struct {
    char pop_id[32];           /* PoP identifier */
    quac_key_handle_t kem_key; /* KEM key for this PoP */
    quac_key_handle_t sig_key; /* Signing key for this PoP */
    uint64_t key_version;      /* Key rotation version */
    time_t created_at;
    time_t expires_at;
} edge_keys_t;

/* Initialize edge keys at PoP */
int edge_init_keys(quac_device_t device, const char *pop_id, edge_keys_t *keys)
{
    quac_result_t result;
    
    strncpy(keys->pop_id, pop_id, sizeof(keys->pop_id) - 1);
    keys->created_at = time(NULL);
    keys->expires_at = keys->created_at + (30 * 24 * 60 * 60);  /* 30 days */
    keys->key_version = 1;
    
    /* Generate KEM key pair (hardware-protected) */
    char kem_label[64];
    snprintf(kem_label, sizeof(kem_label), "%s-kem-v%lu", pop_id, keys->key_version);
    
    uint8_t kem_pk[QUAC_KYBER768_PUBLIC_KEY_SIZE];
    result = quac_kem_keygen_stored(
        device,
        QUAC_ALGORITHM_KYBER768,
        kem_label,
        true,  /* Persistent */
        &keys->kem_key,
        kem_pk, sizeof(kem_pk)
    );
    
    if (QUAC_FAILED(result)) {
        return -1;
    }
    
    /* Generate signing key pair (hardware-protected) */
    char sig_label[64];
    snprintf(sig_label, sizeof(sig_label), "%s-sig-v%lu", pop_id, keys->key_version);
    
    uint8_t sig_pk[QUAC_DILITHIUM3_PUBLIC_KEY_SIZE];
    result = quac_sign_keygen_stored(
        device,
        QUAC_ALGORITHM_DILITHIUM3,
        sig_label,
        true,
        &keys->sig_key,
        sig_pk, sizeof(sig_pk)
    );
    
    if (QUAC_FAILED(result)) {
        quac_key_destroy(device, keys->kem_key);
        return -1;
    }
    
    /* Register public keys with central management */
    /* ... publish kem_pk and sig_pk to key management service ... */
    
    return 0;
}

/* Rotate keys */
int edge_rotate_keys(quac_device_t device, edge_keys_t *keys)
{
    edge_keys_t new_keys;
    char pop_id_copy[32];
    strncpy(pop_id_copy, keys->pop_id, sizeof(pop_id_copy));
    
    /* Keep old version for reference */
    uint64_t old_version = keys->key_version;
    quac_key_handle_t old_kem = keys->kem_key;
    quac_key_handle_t old_sig = keys->sig_key;
    
    /* Generate new keys with incremented version */
    new_keys.key_version = old_version + 1;
    if (edge_init_keys(device, pop_id_copy, &new_keys) != 0) {
        return -1;
    }
    
    /* Transition period: keep old keys active for ongoing connections */
    /* ... application-specific transition logic ... */
    
    /* After transition period, destroy old keys */
    quac_key_destroy(device, old_kem);
    quac_key_destroy(device, old_sig);
    
    /* Update keys structure */
    *keys = new_keys;
    
    return 0;
}
```

---

## Performance Optimization

### Batch TLS Handshakes

Process multiple handshakes in parallel:

```c
/* batch_handshake.c */
#include <quac100.h>

#define BATCH_SIZE 64

typedef struct {
    uint8_t client_ciphertext[QUAC_KYBER768_CIPHERTEXT_SIZE];
    uint8_t shared_secret[QUAC_KYBER768_SHARED_SECRET_SIZE];
    void *connection_ctx;
} handshake_item_t;

/* Process batch of incoming handshakes */
int batch_process_handshakes(quac_device_t device,
                             const uint8_t *server_sk,
                             handshake_item_t *items,
                             size_t count)
{
    quac_batch_kem_decaps_t batch_items[BATCH_SIZE];
    
    /* Setup batch */
    for (size_t i = 0; i < count && i < BATCH_SIZE; i++) {
        batch_items[i].operation = QUAC_BATCH_OP_KEM_DECAPS;
        batch_items[i].algorithm = QUAC_ALGORITHM_KYBER768;
        batch_items[i].ciphertext = items[i].client_ciphertext;
        batch_items[i].ct_size = QUAC_KYBER768_CIPHERTEXT_SIZE;
        batch_items[i].secret_key = server_sk;
        batch_items[i].sk_size = QUAC_KYBER768_SECRET_KEY_SIZE;
        batch_items[i].shared_secret = items[i].shared_secret;
        batch_items[i].ss_size = QUAC_KYBER768_SHARED_SECRET_SIZE;
        batch_items[i].user_data = items[i].connection_ctx;
    }
    
    /* Execute batch */
    quac_batch_result_t result;
    quac_batch_execute(device, (quac_batch_item_t*)batch_items,
                       count, NULL, &result);
    
    printf("Processed %u handshakes in %lu µs (%.1f/sec)\n",
           result.completed, result.total_time_us,
           (double)result.completed * 1000000.0 / result.total_time_us);
    
    /* Handle individual results */
    int failures = 0;
    for (size_t i = 0; i < count; i++) {
        if (QUAC_FAILED(batch_items[i].result)) {
            /* Mark connection as failed */
            failures++;
        }
    }
    
    return failures;
}
```

### Pre-generation Pool

Maintain a pool of pre-generated key pairs:

```c
/* key_pool.c */
#include <quac100.h>
#include <pthread.h>

#define POOL_SIZE 1024
#define REFILL_THRESHOLD 256

typedef struct {
    uint8_t public_key[QUAC_KYBER768_PUBLIC_KEY_SIZE];
    uint8_t secret_key[QUAC_KYBER768_SECRET_KEY_SIZE];
} keypair_t;

typedef struct {
    keypair_t pairs[POOL_SIZE];
    size_t read_idx;
    size_t write_idx;
    size_t count;
    pthread_mutex_t lock;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
    quac_device_t device;
    volatile int shutdown;
} key_pool_t;

key_pool_t g_key_pool;

/* Background thread to refill pool */
void* pool_refill_thread(void *arg)
{
    key_pool_t *pool = (key_pool_t*)arg;
    
    while (!pool->shutdown) {
        pthread_mutex_lock(&pool->lock);
        
        /* Wait until pool needs refilling */
        while (pool->count >= POOL_SIZE - REFILL_THRESHOLD && !pool->shutdown) {
            pthread_cond_wait(&pool->not_full, &pool->lock);
        }
        
        if (pool->shutdown) {
            pthread_mutex_unlock(&pool->lock);
            break;
        }
        
        pthread_mutex_unlock(&pool->lock);
        
        /* Generate keys in batch */
        keypair_t new_pairs[64];
        uint8_t *pk_ptrs[64];
        uint8_t *sk_ptrs[64];
        
        for (int i = 0; i < 64; i++) {
            pk_ptrs[i] = new_pairs[i].public_key;
            sk_ptrs[i] = new_pairs[i].secret_key;
        }
        
        quac_batch_kem_keygen(pool->device, QUAC_ALGORITHM_KYBER768,
                              pk_ptrs, QUAC_KYBER768_PUBLIC_KEY_SIZE,
                              sk_ptrs, QUAC_KYBER768_SECRET_KEY_SIZE,
                              NULL, 64);
        
        /* Add to pool */
        pthread_mutex_lock(&pool->lock);
        for (int i = 0; i < 64 && pool->count < POOL_SIZE; i++) {
            pool->pairs[pool->write_idx] = new_pairs[i];
            pool->write_idx = (pool->write_idx + 1) % POOL_SIZE;
            pool->count++;
        }
        pthread_cond_broadcast(&pool->not_empty);
        pthread_mutex_unlock(&pool->lock);
    }
    
    return NULL;
}

/* Get a key pair from pool (fast path) */
int pool_get_keypair(keypair_t *kp)
{
    pthread_mutex_lock(&g_key_pool.lock);
    
    while (g_key_pool.count == 0) {
        /* Pool empty - wait for refill */
        pthread_cond_wait(&g_key_pool.not_empty, &g_key_pool.lock);
    }
    
    *kp = g_key_pool.pairs[g_key_pool.read_idx];
    g_key_pool.read_idx = (g_key_pool.read_idx + 1) % POOL_SIZE;
    g_key_pool.count--;
    
    pthread_cond_signal(&g_key_pool.not_full);
    pthread_mutex_unlock(&g_key_pool.lock);
    
    return 0;
}
```

---

## Monitoring and Observability

### Prometheus Metrics

```c
/* metrics.c */
#include <quac100.h>
#include <prometheus/prometheus.h>

/* Metric definitions */
static prom_counter_t *kem_operations_total;
static prom_counter_t *sign_operations_total;
static prom_histogram_t *kem_latency_seconds;
static prom_histogram_t *sign_latency_seconds;
static prom_gauge_t *device_temperature;
static prom_gauge_t *entropy_available;
static prom_gauge_t *operations_in_flight;

void init_metrics(void)
{
    kem_operations_total = prom_counter_new(
        "quac_kem_operations_total",
        "Total KEM operations",
        2, (const char*[]){"operation", "algorithm"}
    );
    
    sign_operations_total = prom_counter_new(
        "quac_sign_operations_total",
        "Total signature operations",
        2, (const char*[]){"operation", "algorithm"}
    );
    
    kem_latency_seconds = prom_histogram_new(
        "quac_kem_latency_seconds",
        "KEM operation latency",
        prom_histogram_buckets_default,
        1, (const char*[]){"operation"}
    );
    
    device_temperature = prom_gauge_new(
        "quac_device_temperature_celsius",
        "Device temperature",
        1, (const char*[]){"device"}
    );
    
    entropy_available = prom_gauge_new(
        "quac_entropy_available_bits",
        "Available entropy",
        1, (const char*[]){"device"}
    );
}

/* Update metrics from device health */
void update_device_metrics(quac_device_t device, const char *device_id)
{
    quac_health_status_t health;
    health.struct_size = sizeof(health);
    
    if (QUAC_SUCCEEDED(quac_diag_get_health(device, &health))) {
        prom_gauge_set(device_temperature, health.temp_core,
                      (const char*[]){device_id});
        prom_gauge_set(entropy_available, health.entropy_available,
                      (const char*[]){device_id});
    }
}

/* Instrumented KEM operation */
quac_result_t instrumented_kem_decaps(quac_device_t device,
                                       const uint8_t *ct, size_t ct_size,
                                       const uint8_t *sk, size_t sk_size,
                                       uint8_t *ss, size_t ss_size)
{
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    quac_result_t result = quac_kem_decaps(
        device, QUAC_ALGORITHM_KYBER768,
        ct, ct_size, sk, sk_size, ss, ss_size
    );
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double latency = (end.tv_sec - start.tv_sec) +
                     (end.tv_nsec - start.tv_nsec) / 1e9;
    
    prom_histogram_observe(kem_latency_seconds, latency,
                          (const char*[]){"decaps"});
    prom_counter_inc(kem_operations_total,
                    (const char*[]){"decaps", "kyber768"});
    
    return result;
}
```

### Alerting Rules

```yaml
# prometheus-alerts.yml
groups:
  - name: quac100-alerts
    rules:
      - alert: QuacDeviceTemperatureHigh
        expr: quac_device_temperature_celsius > 75
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "QUAC 100 temperature high on {{ $labels.device }}"
          
      - alert: QuacDeviceTemperatureCritical
        expr: quac_device_temperature_celsius > 85
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "QUAC 100 temperature critical on {{ $labels.device }}"
          
      - alert: QuacEntropyLow
        expr: quac_entropy_available_bits < 10000
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "QUAC 100 entropy pool low on {{ $labels.device }}"
          
      - alert: QuacOperationLatencyHigh
        expr: histogram_quantile(0.99, quac_kem_latency_seconds_bucket) > 0.005
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "QUAC 100 KEM latency high (p99 > 5ms)"
```

---

## Security Best Practices

### Key Protection

1. **Use Hardware Key Storage**
```c
/* Keys never leave the QUAC 100 */
quac_key_attr_t attr = {
    .extractable = false,
    .persistent = true,
};
quac_key_generate(device, &attr, &handle);
```

2. **Enable FIPS Mode**
```c
quac_init_options_t options = {
    .flags = QUAC_INIT_FIPS_MODE,
};
quac_init(&options);
```

3. **Regular Key Rotation**
```c
/* Rotate keys every 30 days */
if (time(NULL) > keys->expires_at) {
    edge_rotate_keys(device, keys);
}
```

### Access Control

1. **Restrict Device Access**
```bash
# Linux: udev rules
SUBSYSTEM=="quac100", MODE="0660", GROUP="pq-crypto"
```

2. **Audit Logging**
```c
void audit_log(const char *operation, const char *key_id, bool success)
{
    syslog(LOG_INFO, "QUAC100: op=%s key=%s result=%s",
           operation, key_id, success ? "success" : "failure");
}
```

---

## Deployment Checklist

### Pre-Deployment

- [ ] Install QUAC 100 hardware in all target PoPs
- [ ] Install and verify drivers on all hosts
- [ ] Run self-tests: `quac-verify --fips`
- [ ] Generate and distribute CA keys
- [ ] Configure monitoring and alerting
- [ ] Test hybrid TLS handshake with test clients

### Deployment

- [ ] Deploy SDK to edge workers
- [ ] Initialize device pools
- [ ] Generate per-PoP key pairs
- [ ] Register public keys with central management
- [ ] Enable post-quantum TLS for test traffic
- [ ] Gradually increase PQ traffic percentage

### Post-Deployment

- [ ] Monitor latency metrics
- [ ] Monitor error rates
- [ ] Verify entropy pool health
- [ ] Schedule key rotation jobs
- [ ] Review security audit logs

---

## Summary

The QuantaCore QUAC 100 enables Cloudflare to deploy post-quantum cryptography at scale:

- **Performance**: 20K+ key exchanges/second per device
- **Security**: Hardware-protected keys, FIPS 140-3 certified
- **Integration**: Native C/Rust bindings for Workers
- **Operations**: Full observability and automated key rotation

For support, contact: support@dyber.com

---

*Document Version: 1.0.0*
*Last Updated: 2025*
*Copyright © 2025 Dyber, Inc. All Rights Reserved.*
