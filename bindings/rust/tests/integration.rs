//! Integration tests for QUAC 100 SDK.
//!
//! These tests require a QUAC 100 device to be connected.
//! Run with: cargo test --test integration -- --ignored

use quantacore::{
    initialize, cleanup, is_initialized, get_version, get_device_count,
    enumerate_devices, open_first_device,
    KemAlgorithm, SignAlgorithm, HashAlgorithm,
    KeyType, KeyUsage,
};

// ============================================================================
// Library Tests
// ============================================================================

#[test]
#[ignore = "requires QUAC 100 hardware"]
fn test_library_init_cleanup() {
    assert!(!is_initialized());
    initialize().expect("Failed to initialize");
    assert!(is_initialized());
    cleanup().expect("Failed to cleanup");
    assert!(!is_initialized());
}

#[test]
#[ignore = "requires QUAC 100 hardware"]
fn test_library_double_init() {
    initialize().expect("First init failed");
    initialize().expect("Second init should succeed (idempotent)");
    cleanup().unwrap();
}

#[test]
fn test_get_version() {
    let version = get_version();
    assert!(!version.is_empty());
}

// ============================================================================
// Device Tests
// ============================================================================

#[test]
#[ignore = "requires QUAC 100 hardware"]
fn test_device_enumeration() {
    initialize().unwrap();
    
    let count = get_device_count();
    assert!(count > 0, "No QUAC 100 devices found");
    
    let devices = enumerate_devices();
    assert_eq!(devices.len(), count);
    
    for device in &devices {
        assert!(!device.model.is_empty());
        assert!(!device.serial_number.is_empty());
    }
    
    cleanup().unwrap();
}

#[test]
#[ignore = "requires QUAC 100 hardware"]
fn test_device_open_close() {
    initialize().unwrap();
    
    let device = open_first_device().expect("Failed to open device");
    let info = device.get_info().expect("Failed to get info");
    
    assert!(!info.model.is_empty());
    assert!(info.key_slots > 0);
    
    drop(device);
    cleanup().unwrap();
}

#[test]
#[ignore = "requires QUAC 100 hardware"]
fn test_device_status() {
    initialize().unwrap();
    let device = open_first_device().unwrap();
    
    let status = device.get_status().expect("Failed to get status");
    
    // Temperature should be reasonable
    assert!(status.temperature > -50 && status.temperature < 150);
    // Entropy level 0-100
    assert!(status.entropy_level <= 100);
    
    drop(device);
    cleanup().unwrap();
}

#[test]
#[ignore = "requires QUAC 100 hardware"]
fn test_device_self_test() {
    initialize().unwrap();
    let device = open_first_device().unwrap();
    
    device.self_test().expect("Self-test failed");
    
    drop(device);
    cleanup().unwrap();
}

// ============================================================================
// KEM Tests
// ============================================================================

#[test]
#[ignore = "requires QUAC 100 hardware"]
fn test_kem_keygen_512() {
    initialize().unwrap();
    let device = open_first_device().unwrap();
    let kem = device.kem();
    
    let keypair = kem.generate_keypair(KemAlgorithm::MlKem512).unwrap();
    
    assert_eq!(keypair.public_key().len(), KemAlgorithm::MlKem512.public_key_size());
    assert_eq!(keypair.secret_key().len(), KemAlgorithm::MlKem512.secret_key_size());
    
    drop(device);
    cleanup().unwrap();
}

#[test]
#[ignore = "requires QUAC 100 hardware"]
fn test_kem_keygen_768() {
    initialize().unwrap();
    let device = open_first_device().unwrap();
    let kem = device.kem();
    
    let keypair = kem.generate_keypair_768().unwrap();
    
    assert_eq!(keypair.public_key().len(), 1184);
    assert_eq!(keypair.secret_key().len(), 2400);
    
    drop(device);
    cleanup().unwrap();
}

#[test]
#[ignore = "requires QUAC 100 hardware"]
fn test_kem_keygen_1024() {
    initialize().unwrap();
    let device = open_first_device().unwrap();
    let kem = device.kem();
    
    let keypair = kem.generate_keypair_1024().unwrap();
    
    assert_eq!(keypair.public_key().len(), 1568);
    assert_eq!(keypair.secret_key().len(), 3168);
    
    drop(device);
    cleanup().unwrap();
}

#[test]
#[ignore = "requires QUAC 100 hardware"]
fn test_kem_encapsulate_decapsulate() {
    initialize().unwrap();
    let device = open_first_device().unwrap();
    let kem = device.kem();
    
    for algo in [KemAlgorithm::MlKem512, KemAlgorithm::MlKem768, KemAlgorithm::MlKem1024] {
        let keypair = kem.generate_keypair(algo).unwrap();
        
        let (ciphertext, shared_secret1) = kem.encapsulate(keypair.public_key(), algo).unwrap();
        
        assert_eq!(ciphertext.len(), algo.ciphertext_size());
        assert_eq!(shared_secret1.len(), 32);
        
        let shared_secret2 = kem.decapsulate(keypair.secret_key(), &ciphertext, algo).unwrap();
        
        assert_eq!(shared_secret1, shared_secret2);
    }
    
    drop(device);
    cleanup().unwrap();
}

#[test]
#[ignore = "requires QUAC 100 hardware"]
fn test_kem_convenience_methods() {
    initialize().unwrap();
    let device = open_first_device().unwrap();
    let kem = device.kem();
    
    // 768 variant
    let keypair = kem.generate_keypair_768().unwrap();
    let (ct, ss1) = kem.encapsulate_768(keypair.public_key()).unwrap();
    let ss2 = kem.decapsulate_768(keypair.secret_key(), &ct).unwrap();
    assert_eq!(ss1, ss2);
    
    drop(device);
    cleanup().unwrap();
}

// ============================================================================
// Signature Tests
// ============================================================================

#[test]
#[ignore = "requires QUAC 100 hardware"]
fn test_sign_keygen() {
    initialize().unwrap();
    let device = open_first_device().unwrap();
    let sign = device.sign();
    
    for algo in [SignAlgorithm::MlDsa44, SignAlgorithm::MlDsa65, SignAlgorithm::MlDsa87] {
        let keypair = sign.generate_keypair(algo).unwrap();
        
        assert_eq!(keypair.public_key().len(), algo.public_key_size());
        assert_eq!(keypair.secret_key().len(), algo.secret_key_size());
    }
    
    drop(device);
    cleanup().unwrap();
}

#[test]
#[ignore = "requires QUAC 100 hardware"]
fn test_sign_verify() {
    initialize().unwrap();
    let device = open_first_device().unwrap();
    let sign = device.sign();
    
    let message = b"Test message for signing";
    
    for algo in [SignAlgorithm::MlDsa44, SignAlgorithm::MlDsa65, SignAlgorithm::MlDsa87] {
        let keypair = sign.generate_keypair(algo).unwrap();
        
        let signature = sign.sign(keypair.secret_key(), message, algo).unwrap();
        assert!(signature.len() <= algo.signature_size());
        
        let valid = sign.verify(keypair.public_key(), message, &signature, algo).unwrap();
        assert!(valid, "Signature verification failed for {:?}", algo);
        
        // Verify with wrong message should fail
        let invalid = sign.verify(keypair.public_key(), b"wrong", &signature, algo).unwrap();
        assert!(!invalid);
    }
    
    drop(device);
    cleanup().unwrap();
}

#[test]
#[ignore = "requires QUAC 100 hardware"]
fn test_sign_verify_or_error() {
    initialize().unwrap();
    let device = open_first_device().unwrap();
    let sign = device.sign();
    
    let keypair = sign.generate_keypair_65().unwrap();
    let message = b"Test message";
    let signature = sign.sign_65(keypair.secret_key(), message).unwrap();
    
    // Should succeed
    sign.verify_or_error(keypair.public_key(), message, &signature, SignAlgorithm::MlDsa65).unwrap();
    
    // Should fail
    let result = sign.verify_or_error(keypair.public_key(), b"wrong", &signature, SignAlgorithm::MlDsa65);
    assert!(result.is_err());
    
    drop(device);
    cleanup().unwrap();
}

// ============================================================================
// Hash Tests
// ============================================================================

#[test]
#[ignore = "requires QUAC 100 hardware"]
fn test_hash_sha2() {
    initialize().unwrap();
    let device = open_first_device().unwrap();
    let hash = device.hash();
    
    let data = b"Hello, World!";
    
    let digest256 = hash.sha256(data).unwrap();
    assert_eq!(digest256.len(), 32);
    
    let digest384 = hash.sha384(data).unwrap();
    assert_eq!(digest384.len(), 48);
    
    let digest512 = hash.sha512(data).unwrap();
    assert_eq!(digest512.len(), 64);
    
    drop(device);
    cleanup().unwrap();
}

#[test]
#[ignore = "requires QUAC 100 hardware"]
fn test_hash_sha3() {
    initialize().unwrap();
    let device = open_first_device().unwrap();
    let hash = device.hash();
    
    let data = b"Hello, World!";
    
    let digest256 = hash.sha3_256(data).unwrap();
    assert_eq!(digest256.len(), 32);
    
    let digest384 = hash.sha3_384(data).unwrap();
    assert_eq!(digest384.len(), 48);
    
    let digest512 = hash.sha3_512(data).unwrap();
    assert_eq!(digest512.len(), 64);
    
    drop(device);
    cleanup().unwrap();
}

#[test]
#[ignore = "requires QUAC 100 hardware"]
fn test_hash_shake() {
    initialize().unwrap();
    let device = open_first_device().unwrap();
    let hash = device.hash();
    
    let data = b"Hello, World!";
    
    let output32 = hash.shake128(data, 32).unwrap();
    assert_eq!(output32.len(), 32);
    
    let output64 = hash.shake128(data, 64).unwrap();
    assert_eq!(output64.len(), 64);
    
    let output128 = hash.shake256(data, 128).unwrap();
    assert_eq!(output128.len(), 128);
    
    drop(device);
    cleanup().unwrap();
}

#[test]
#[ignore = "requires QUAC 100 hardware"]
fn test_hash_incremental() {
    initialize().unwrap();
    let device = open_first_device().unwrap();
    let hash = device.hash();
    
    // Incremental
    let mut ctx = hash.create_context(HashAlgorithm::Sha256).unwrap();
    ctx.update(b"Hello, ").unwrap();
    ctx.update(b"World!").unwrap();
    let incremental = ctx.finalize().unwrap();
    
    // One-shot
    let oneshot = hash.sha256(b"Hello, World!").unwrap();
    
    assert_eq!(incremental, oneshot);
    
    drop(device);
    cleanup().unwrap();
}

#[test]
#[ignore = "requires QUAC 100 hardware"]
fn test_hash_hmac() {
    initialize().unwrap();
    let device = open_first_device().unwrap();
    let hash = device.hash();
    
    let key = b"secret key";
    let data = b"message";
    
    let mac = hash.hmac_sha256(key, data).unwrap();
    assert_eq!(mac.len(), 32);
    
    // Same inputs should produce same output
    let mac2 = hash.hmac_sha256(key, data).unwrap();
    assert_eq!(mac, mac2);
    
    // Different key should produce different output
    let mac3 = hash.hmac_sha256(b"other key", data).unwrap();
    assert_ne!(mac, mac3);
    
    drop(device);
    cleanup().unwrap();
}

#[test]
#[ignore = "requires QUAC 100 hardware"]
fn test_hash_hkdf() {
    initialize().unwrap();
    let device = open_first_device().unwrap();
    let hash = device.hash();
    
    let ikm = b"input keying material";
    let salt = b"salt";
    let info = b"context";
    
    let key32 = hash.hkdf_sha256(ikm, salt, info, 32).unwrap();
    assert_eq!(key32.len(), 32);
    
    let key64 = hash.hkdf_sha256(ikm, salt, info, 64).unwrap();
    assert_eq!(key64.len(), 64);
    
    // First 32 bytes should match
    assert_eq!(&key64[..32], &key32[..]);
    
    drop(device);
    cleanup().unwrap();
}

// ============================================================================
// Random Tests
// ============================================================================

#[test]
#[ignore = "requires QUAC 100 hardware"]
fn test_random_bytes() {
    initialize().unwrap();
    let device = open_first_device().unwrap();
    let random = device.random();
    
    let bytes16 = random.bytes(16).unwrap();
    assert_eq!(bytes16.len(), 16);
    
    let bytes32 = random.bytes(32).unwrap();
    assert_eq!(bytes32.len(), 32);
    
    // Should be different
    let bytes32_2 = random.bytes(32).unwrap();
    assert_ne!(bytes32, bytes32_2);
    
    drop(device);
    cleanup().unwrap();
}

#[test]
#[ignore = "requires QUAC 100 hardware"]
fn test_random_integers() {
    initialize().unwrap();
    let device = open_first_device().unwrap();
    let random = device.random();
    
    // Just verify they don't error
    let _ = random.next_u8().unwrap();
    let _ = random.next_u16().unwrap();
    let _ = random.next_u32().unwrap();
    let _ = random.next_u64().unwrap();
    let _ = random.next_i32().unwrap();
    let _ = random.next_i64().unwrap();
    
    drop(device);
    cleanup().unwrap();
}

#[test]
#[ignore = "requires QUAC 100 hardware"]
fn test_random_bounded() {
    initialize().unwrap();
    let device = open_first_device().unwrap();
    let random = device.random();
    
    for _ in 0..100 {
        let val = random.next_u32_bound(100).unwrap();
        assert!(val < 100);
        
        let val = random.randint(10, 20).unwrap();
        assert!(val >= 10 && val <= 20);
    }
    
    drop(device);
    cleanup().unwrap();
}

#[test]
#[ignore = "requires QUAC 100 hardware"]
fn test_random_float() {
    initialize().unwrap();
    let device = open_first_device().unwrap();
    let random = device.random();
    
    for _ in 0..100 {
        let f = random.next_f64().unwrap();
        assert!(f >= 0.0 && f < 1.0);
        
        let u = random.uniform(10.0, 20.0).unwrap();
        assert!(u >= 10.0 && u < 20.0);
    }
    
    drop(device);
    cleanup().unwrap();
}

#[test]
#[ignore = "requires QUAC 100 hardware"]
fn test_random_uuid() {
    initialize().unwrap();
    let device = open_first_device().unwrap();
    let random = device.random();
    
    let uuid = random.uuid().unwrap();
    
    // Check format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
    assert_eq!(uuid.len(), 36);
    assert_eq!(&uuid[8..9], "-");
    assert_eq!(&uuid[13..14], "-");
    assert_eq!(&uuid[14..15], "4"); // Version 4
    assert_eq!(&uuid[18..19], "-");
    assert_eq!(&uuid[23..24], "-");
    
    // Two UUIDs should be different
    let uuid2 = random.uuid().unwrap();
    assert_ne!(uuid, uuid2);
    
    drop(device);
    cleanup().unwrap();
}

#[test]
#[ignore = "requires QUAC 100 hardware"]
fn test_random_selection() {
    initialize().unwrap();
    let device = open_first_device().unwrap();
    let random = device.random();
    
    let items = vec![1, 2, 3, 4, 5];
    
    // Choice
    let choice = random.choice(&items).unwrap();
    assert!(choice.is_some());
    assert!(items.contains(choice.unwrap()));
    
    // Sample
    let sample = random.sample(&items, 3).unwrap();
    assert_eq!(sample.len(), 3);
    
    // Shuffle
    let shuffled = random.shuffled(&items).unwrap();
    assert_eq!(shuffled.len(), 5);
    
    drop(device);
    cleanup().unwrap();
}

#[test]
#[ignore = "requires QUAC 100 hardware"]
fn test_random_entropy_status() {
    initialize().unwrap();
    let device = open_first_device().unwrap();
    let random = device.random();
    
    let status = random.get_entropy_status().unwrap();
    
    assert!(status.level <= 100);
    // Should generally be healthy
    assert!(status.is_healthy);
    
    drop(device);
    cleanup().unwrap();
}

// ============================================================================
// Key Storage Tests
// ============================================================================

#[test]
#[ignore = "requires QUAC 100 hardware"]
fn test_keys_slot_count() {
    initialize().unwrap();
    let device = open_first_device().unwrap();
    let keys = device.keys();
    
    let count = keys.get_slot_count().unwrap();
    assert!(count > 0);
    
    drop(device);
    cleanup().unwrap();
}

#[test]
#[ignore = "requires QUAC 100 hardware"]
fn test_keys_store_load_delete() {
    initialize().unwrap();
    let device = open_first_device().unwrap();
    let keys = device.keys();
    
    // Find a free slot
    let slot = keys.get_free_slot().unwrap();
    
    // Store a key
    let key_data = vec![0x42u8; 32];
    keys.store(
        slot,
        KeyType::Secret,
        0,
        KeyUsage::ENCRYPT | KeyUsage::DECRYPT,
        "test-key",
        &key_data,
    ).unwrap();
    
    // Check it exists
    assert!(keys.is_slot_occupied(slot).unwrap());
    
    // Get info
    let info = keys.get_info(slot).unwrap();
    assert_eq!(info.label, "test-key");
    assert_eq!(info.key_type, KeyType::Secret);
    
    // Load it back
    let loaded = keys.load(slot).unwrap();
    assert_eq!(loaded, key_data);
    
    // Delete it
    keys.delete(slot).unwrap();
    assert!(!keys.is_slot_occupied(slot).unwrap());
    
    drop(device);
    cleanup().unwrap();
}

#[test]
#[ignore = "requires QUAC 100 hardware"]
fn test_keys_list() {
    initialize().unwrap();
    let device = open_first_device().unwrap();
    let keys = device.keys();
    
    let slots = keys.list().unwrap();
    // Just verify it doesn't error
    let _ = slots;
    
    drop(device);
    cleanup().unwrap();
}

// ============================================================================
// Thread Safety Tests
// ============================================================================

#[test]
#[ignore = "requires QUAC 100 hardware"]
fn test_device_thread_safety() {
    use std::thread;
    
    initialize().unwrap();
    let device = open_first_device().unwrap();
    
    let handles: Vec<_> = (0..4).map(|i| {
        let dev = device.clone();
        thread::spawn(move || {
            let hash = dev.hash();
            for _ in 0..10 {
                let data = format!("Thread {} data", i);
                hash.sha256(data.as_bytes()).unwrap();
            }
        })
    }).collect();
    
    for h in handles {
        h.join().unwrap();
    }
    
    drop(device);
    cleanup().unwrap();
}