//! Unit tests for types and enums.
//!
//! These tests do not require QUAC 100 hardware.

use quantacore::{
    KemAlgorithm, SignAlgorithm, HashAlgorithm,
    KeyType, KeyUsage, InitFlags,
    ErrorCode,
};

// ============================================================================
// KemAlgorithm Tests
// ============================================================================

#[test]
fn test_kem_algorithm_values() {
    assert_eq!(KemAlgorithm::MlKem512 as i32, 0);
    assert_eq!(KemAlgorithm::MlKem768 as i32, 1);
    assert_eq!(KemAlgorithm::MlKem1024 as i32, 2);
}

#[test]
fn test_kem_algorithm_aliases() {
    assert_eq!(KemAlgorithm::KYBER_512, KemAlgorithm::MlKem512);
    assert_eq!(KemAlgorithm::KYBER_768, KemAlgorithm::MlKem768);
    assert_eq!(KemAlgorithm::KYBER_1024, KemAlgorithm::MlKem1024);
}

#[test]
fn test_kem_algorithm_sizes() {
    // ML-KEM-512
    assert_eq!(KemAlgorithm::MlKem512.public_key_size(), 800);
    assert_eq!(KemAlgorithm::MlKem512.secret_key_size(), 1632);
    assert_eq!(KemAlgorithm::MlKem512.ciphertext_size(), 768);
    assert_eq!(KemAlgorithm::MlKem512.shared_secret_size(), 32);

    // ML-KEM-768
    assert_eq!(KemAlgorithm::MlKem768.public_key_size(), 1184);
    assert_eq!(KemAlgorithm::MlKem768.secret_key_size(), 2400);
    assert_eq!(KemAlgorithm::MlKem768.ciphertext_size(), 1088);
    assert_eq!(KemAlgorithm::MlKem768.shared_secret_size(), 32);

    // ML-KEM-1024
    assert_eq!(KemAlgorithm::MlKem1024.public_key_size(), 1568);
    assert_eq!(KemAlgorithm::MlKem1024.secret_key_size(), 3168);
    assert_eq!(KemAlgorithm::MlKem1024.ciphertext_size(), 1568);
    assert_eq!(KemAlgorithm::MlKem1024.shared_secret_size(), 32);
}

#[test]
fn test_kem_algorithm_from_raw() {
    assert_eq!(KemAlgorithm::from_raw(0), Some(KemAlgorithm::MlKem512));
    assert_eq!(KemAlgorithm::from_raw(1), Some(KemAlgorithm::MlKem768));
    assert_eq!(KemAlgorithm::from_raw(2), Some(KemAlgorithm::MlKem1024));
    assert_eq!(KemAlgorithm::from_raw(99), None);
}

#[test]
fn test_kem_algorithm_display() {
    assert_eq!(format!("{}", KemAlgorithm::MlKem512), "ML-KEM-512");
    assert_eq!(format!("{}", KemAlgorithm::MlKem768), "ML-KEM-768");
    assert_eq!(format!("{}", KemAlgorithm::MlKem1024), "ML-KEM-1024");
}

// ============================================================================
// SignAlgorithm Tests
// ============================================================================

#[test]
fn test_sign_algorithm_values() {
    assert_eq!(SignAlgorithm::MlDsa44 as i32, 0);
    assert_eq!(SignAlgorithm::MlDsa65 as i32, 1);
    assert_eq!(SignAlgorithm::MlDsa87 as i32, 2);
}

#[test]
fn test_sign_algorithm_aliases() {
    assert_eq!(SignAlgorithm::DILITHIUM_2, SignAlgorithm::MlDsa44);
    assert_eq!(SignAlgorithm::DILITHIUM_3, SignAlgorithm::MlDsa65);
    assert_eq!(SignAlgorithm::DILITHIUM_5, SignAlgorithm::MlDsa87);
}

#[test]
fn test_sign_algorithm_sizes() {
    // ML-DSA-44
    assert_eq!(SignAlgorithm::MlDsa44.public_key_size(), 1312);
    assert_eq!(SignAlgorithm::MlDsa44.secret_key_size(), 2560);
    assert_eq!(SignAlgorithm::MlDsa44.signature_size(), 2420);

    // ML-DSA-65
    assert_eq!(SignAlgorithm::MlDsa65.public_key_size(), 1952);
    assert_eq!(SignAlgorithm::MlDsa65.secret_key_size(), 4032);
    assert_eq!(SignAlgorithm::MlDsa65.signature_size(), 3309);

    // ML-DSA-87
    assert_eq!(SignAlgorithm::MlDsa87.public_key_size(), 2592);
    assert_eq!(SignAlgorithm::MlDsa87.secret_key_size(), 4896);
    assert_eq!(SignAlgorithm::MlDsa87.signature_size(), 4627);
}

#[test]
fn test_sign_algorithm_display() {
    assert_eq!(format!("{}", SignAlgorithm::MlDsa44), "ML-DSA-44");
    assert_eq!(format!("{}", SignAlgorithm::MlDsa65), "ML-DSA-65");
    assert_eq!(format!("{}", SignAlgorithm::MlDsa87), "ML-DSA-87");
}

// ============================================================================
// HashAlgorithm Tests
// ============================================================================

#[test]
fn test_hash_algorithm_values() {
    assert_eq!(HashAlgorithm::Sha256 as i32, 0);
    assert_eq!(HashAlgorithm::Sha384 as i32, 1);
    assert_eq!(HashAlgorithm::Sha512 as i32, 2);
    assert_eq!(HashAlgorithm::Sha3_256 as i32, 3);
    assert_eq!(HashAlgorithm::Sha3_384 as i32, 4);
    assert_eq!(HashAlgorithm::Sha3_512 as i32, 5);
    assert_eq!(HashAlgorithm::Shake128 as i32, 6);
    assert_eq!(HashAlgorithm::Shake256 as i32, 7);
}

#[test]
fn test_hash_algorithm_digest_sizes() {
    assert_eq!(HashAlgorithm::Sha256.digest_size(), Some(32));
    assert_eq!(HashAlgorithm::Sha384.digest_size(), Some(48));
    assert_eq!(HashAlgorithm::Sha512.digest_size(), Some(64));
    assert_eq!(HashAlgorithm::Sha3_256.digest_size(), Some(32));
    assert_eq!(HashAlgorithm::Sha3_384.digest_size(), Some(48));
    assert_eq!(HashAlgorithm::Sha3_512.digest_size(), Some(64));
    assert_eq!(HashAlgorithm::Shake128.digest_size(), None);
    assert_eq!(HashAlgorithm::Shake256.digest_size(), None);
}

#[test]
fn test_hash_algorithm_is_xof() {
    assert!(!HashAlgorithm::Sha256.is_xof());
    assert!(!HashAlgorithm::Sha3_256.is_xof());
    assert!(HashAlgorithm::Shake128.is_xof());
    assert!(HashAlgorithm::Shake256.is_xof());
}

// ============================================================================
// KeyType Tests
// ============================================================================

#[test]
fn test_key_type_values() {
    assert_eq!(KeyType::Secret as i32, 0);
    assert_eq!(KeyType::Public as i32, 1);
    assert_eq!(KeyType::Private as i32, 2);
    assert_eq!(KeyType::KeyPair as i32, 3);
}

#[test]
fn test_key_type_from_raw() {
    assert_eq!(KeyType::from_raw(0), Some(KeyType::Secret));
    assert_eq!(KeyType::from_raw(1), Some(KeyType::Public));
    assert_eq!(KeyType::from_raw(2), Some(KeyType::Private));
    assert_eq!(KeyType::from_raw(3), Some(KeyType::KeyPair));
    assert_eq!(KeyType::from_raw(99), None);
}

// ============================================================================
// KeyUsage Tests
// ============================================================================

#[test]
fn test_key_usage_values() {
    assert_eq!(KeyUsage::ENCRYPT.bits(), 0x01);
    assert_eq!(KeyUsage::DECRYPT.bits(), 0x02);
    assert_eq!(KeyUsage::SIGN.bits(), 0x04);
    assert_eq!(KeyUsage::VERIFY.bits(), 0x08);
    assert_eq!(KeyUsage::DERIVE.bits(), 0x10);
    assert_eq!(KeyUsage::WRAP.bits(), 0x20);
    assert_eq!(KeyUsage::UNWRAP.bits(), 0x40);
}

#[test]
fn test_key_usage_combinations() {
    assert_eq!(KeyUsage::ENCRYPTION, KeyUsage::ENCRYPT | KeyUsage::DECRYPT);
    assert_eq!(KeyUsage::SIGNING, KeyUsage::SIGN | KeyUsage::VERIFY);
}

#[test]
fn test_key_usage_contains() {
    let usage = KeyUsage::ENCRYPT | KeyUsage::SIGN;
    assert!(usage.contains(KeyUsage::ENCRYPT));
    assert!(usage.contains(KeyUsage::SIGN));
    assert!(!usage.contains(KeyUsage::DECRYPT));
}

// ============================================================================
// InitFlags Tests
// ============================================================================

#[test]
fn test_init_flags_values() {
    assert_eq!(InitFlags::HARDWARE_ACCEL.bits(), 0x01);
    assert_eq!(InitFlags::SIDE_CHANNEL_PROTECT.bits(), 0x02);
    assert_eq!(InitFlags::CONSTANT_TIME.bits(), 0x04);
    assert_eq!(InitFlags::AUTO_ZEROIZE.bits(), 0x08);
    assert_eq!(InitFlags::FIPS_MODE.bits(), 0x10);
    assert_eq!(InitFlags::DEBUG.bits(), 0x20);
    assert_eq!(InitFlags::SOFTWARE_FALLBACK.bits(), 0x40);
}

#[test]
fn test_init_flags_default() {
    assert_eq!(InitFlags::DEFAULT.bits(), 0x0F);
    assert!(InitFlags::DEFAULT.contains(InitFlags::HARDWARE_ACCEL));
    assert!(InitFlags::DEFAULT.contains(InitFlags::SIDE_CHANNEL_PROTECT));
    assert!(InitFlags::DEFAULT.contains(InitFlags::CONSTANT_TIME));
    assert!(InitFlags::DEFAULT.contains(InitFlags::AUTO_ZEROIZE));
}

#[test]
fn test_init_flags_combination() {
    let flags = InitFlags::HARDWARE_ACCEL | InitFlags::DEBUG;
    assert_eq!(flags.bits(), 0x21);
}

// ============================================================================
// ErrorCode Tests
// ============================================================================

#[test]
fn test_error_code_values() {
    assert_eq!(ErrorCode::Success as i32, 0);
    assert_eq!(ErrorCode::Error as i32, -1);
    assert_eq!(ErrorCode::InvalidParam as i32, -2);
    assert_eq!(ErrorCode::DeviceNotFound as i32, -4);
    assert_eq!(ErrorCode::NotInitialized as i32, -17);
}

#[test]
fn test_error_code_from_raw() {
    assert_eq!(ErrorCode::from_raw(0), ErrorCode::Success);
    assert_eq!(ErrorCode::from_raw(-2), ErrorCode::InvalidParam);
    assert_eq!(ErrorCode::from_raw(-17), ErrorCode::NotInitialized);
    assert_eq!(ErrorCode::from_raw(-999), ErrorCode::InternalError);
}

#[test]
fn test_error_code_message() {
    assert!(ErrorCode::Success.message().contains("success"));
    assert!(ErrorCode::InvalidParam.message().contains("Invalid"));
    assert!(ErrorCode::DeviceNotFound.message().contains("device"));
}

#[test]
fn test_error_code_is_success() {
    assert!(ErrorCode::Success.is_success());
    assert!(!ErrorCode::Error.is_success());
    assert!(!ErrorCode::InvalidParam.is_success());
}