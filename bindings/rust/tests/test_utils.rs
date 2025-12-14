//! Unit tests for utility functions.
//!
//! These tests do not require QUAC 100 hardware.

use quantacore::utils::*;

#[test]
fn test_hex_encode() {
    assert_eq!(to_hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    assert_eq!(to_hex(&[]), "");
    assert_eq!(to_hex(&[0x00, 0x01, 0x02]), "000102");
}

#[test]
fn test_hex_decode() {
    assert_eq!(from_hex("deadbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(from_hex("DEADBEEF").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(from_hex("").unwrap(), vec![]);
}

#[test]
fn test_hex_roundtrip() {
    let data: Vec<u8> = (0..=255).collect();
    let hex = to_hex(&data);
    let decoded = from_hex(&hex).unwrap();
    assert_eq!(decoded, data);
}

#[test]
fn test_base64_encode() {
    assert_eq!(to_base64(b"Hello"), "SGVsbG8=");
    assert_eq!(to_base64(b""), "");
}

#[test]
fn test_base64_decode() {
    assert_eq!(from_base64("SGVsbG8=").unwrap(), b"Hello");
    assert_eq!(from_base64("").unwrap(), b"");
}

#[test]
fn test_base64_roundtrip() {
    let data: Vec<u8> = (0..=255).collect();
    let b64 = to_base64(&data);
    let decoded = from_base64(&b64).unwrap();
    assert_eq!(decoded, data);
}

#[test]
fn test_base64url() {
    // Data that produces + and / in standard base64
    let data = vec![0xfb, 0xff, 0xfe];
    let b64url = to_base64url(&data);
    assert!(!b64url.contains('+'));
    assert!(!b64url.contains('/'));
    assert!(!b64url.contains('='));
    
    let decoded = from_base64url(&b64url).unwrap();
    assert_eq!(decoded, data);
}

#[test]
fn test_secure_zero() {
    let mut data = vec![0x42u8; 32];
    secure_zero(&mut data);
    assert!(data.iter().all(|&b| b == 0));
}

#[test]
fn test_secure_clear() {
    let mut data = vec![0x42u8; 32];
    secure_clear(&mut data);
    assert!(data.is_empty());
}

#[test]
fn test_secure_compare_equal() {
    assert!(secure_compare(b"hello", b"hello"));
    assert!(secure_compare(&[], &[]));
    
    let a: Vec<u8> = (0..100).collect();
    let b: Vec<u8> = (0..100).collect();
    assert!(secure_compare(&a, &b));
}

#[test]
fn test_secure_compare_not_equal() {
    assert!(!secure_compare(b"hello", b"world"));
    assert!(!secure_compare(b"hello", b"Hello")); // Case sensitive
    assert!(!secure_compare(b"hello", b"hello!")); // Different length
    assert!(!secure_compare(b"", b"a"));
}

#[test]
fn test_concat() {
    assert_eq!(concat(&[b"hello", b" ", b"world"]), b"hello world");
    assert_eq!(concat(&[b""]), b"");
    assert_eq!(concat(&[]), Vec::<u8>::new());
}

#[test]
fn test_xor_bytes() {
    let a = [0x00, 0xFF, 0x00, 0xFF];
    let b = [0xFF, 0x00, 0xFF, 0x00];
    assert_eq!(xor_bytes(&a, &b), vec![0xFF, 0xFF, 0xFF, 0xFF]);
    
    // XOR with self should be all zeros
    let c = [0x12, 0x34, 0x56, 0x78];
    assert_eq!(xor_bytes(&c, &c), vec![0x00, 0x00, 0x00, 0x00]);
}

#[test]
fn test_try_xor_bytes_length_mismatch() {
    let result = try_xor_bytes(&[0, 0], &[0, 0, 0]);
    assert!(result.is_err());
}

#[test]
fn test_pkcs7_padding() {
    // Block size 16
    let padded = pad_pkcs7(b"hello", 16);
    assert_eq!(padded.len(), 16);
    assert_eq!(padded[5..], vec![11u8; 11]);
    
    // Exact block size needs full block of padding
    let padded = pad_pkcs7(b"0123456789abcdef", 16);
    assert_eq!(padded.len(), 32);
    assert_eq!(padded[16..], vec![16u8; 16]);
}

#[test]
fn test_pkcs7_unpadding() {
    let padded = pad_pkcs7(b"hello", 16);
    let unpadded = unpad_pkcs7(&padded).unwrap();
    assert_eq!(unpadded, b"hello");
}

#[test]
fn test_pkcs7_unpadding_invalid() {
    // Invalid padding byte
    assert!(unpad_pkcs7(&[1, 2, 3, 0]).is_err());
    
    // Padding length > data length
    assert!(unpad_pkcs7(&[0x10]).is_err());
    
    // Empty data
    assert!(unpad_pkcs7(&[]).is_err());
    
    // Inconsistent padding bytes
    assert!(unpad_pkcs7(&[1, 2, 3, 3, 2]).is_err());
}

#[test]
fn test_int_to_bytes_be() {
    assert_eq!(int_to_bytes_be(0x0102, 2), vec![0x01, 0x02]);
    assert_eq!(int_to_bytes_be(256, 4), vec![0x00, 0x00, 0x01, 0x00]);
    assert_eq!(int_to_bytes_be(0xFFFF, 1), vec![0xFF]); // Truncation
}

#[test]
fn test_int_to_bytes_le() {
    assert_eq!(int_to_bytes_le(0x0102, 2), vec![0x02, 0x01]);
    assert_eq!(int_to_bytes_le(256, 4), vec![0x00, 0x01, 0x00, 0x00]);
}

#[test]
fn test_bytes_to_int_be() {
    assert_eq!(bytes_to_int_be(&[0x01, 0x02]), 0x0102);
    assert_eq!(bytes_to_int_be(&[0x00, 0x00, 0x01, 0x00]), 256);
    assert_eq!(bytes_to_int_be(&[]), 0);
}

#[test]
fn test_bytes_to_int_le() {
    assert_eq!(bytes_to_int_le(&[0x02, 0x01]), 0x0102);
    assert_eq!(bytes_to_int_le(&[0x00, 0x01, 0x00, 0x00]), 256);
}

#[test]
fn test_int_bytes_roundtrip() {
    for value in [0u64, 1, 255, 256, 65535, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF] {
        let bytes_be = int_to_bytes_be(value, 8);
        assert_eq!(bytes_to_int_be(&bytes_be), value);
        
        let bytes_le = int_to_bytes_le(value, 8);
        assert_eq!(bytes_to_int_le(&bytes_le), value);
    }
}
