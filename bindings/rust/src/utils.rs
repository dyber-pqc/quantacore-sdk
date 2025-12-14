//! Utility functions for data manipulation.
//!
//! This module provides helper functions for encoding, decoding,
//! and secure memory operations.

use zeroize::Zeroize;

/// Convert bytes to hexadecimal string.
///
/// # Example
///
/// ```
/// use quantacore::utils::to_hex;
///
/// let hex = to_hex(&[0xde, 0xad, 0xbe, 0xef]);
/// assert_eq!(hex, "deadbeef");
/// ```
pub fn to_hex(data: &[u8]) -> String {
    hex::encode(data)
}

/// Convert bytes to uppercase hexadecimal string.
pub fn to_hex_upper(data: &[u8]) -> String {
    hex::encode_upper(data)
}

/// Convert hexadecimal string to bytes.
///
/// # Example
///
/// ```
/// use quantacore::utils::from_hex;
///
/// let bytes = from_hex("deadbeef").unwrap();
/// assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
/// ```
pub fn from_hex(s: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(s)
}

/// Convert bytes to base64 string.
///
/// # Example
///
/// ```
/// use quantacore::utils::to_base64;
///
/// let b64 = to_base64(b"Hello");
/// assert_eq!(b64, "SGVsbG8=");
/// ```
pub fn to_base64(data: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::STANDARD};
    STANDARD.encode(data)
}

/// Convert base64 string to bytes.
///
/// # Example
///
/// ```
/// use quantacore::utils::from_base64;
///
/// let bytes = from_base64("SGVsbG8=").unwrap();
/// assert_eq!(bytes, b"Hello");
/// ```
pub fn from_base64(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    STANDARD.decode(s)
}

/// Convert bytes to URL-safe base64 string (no padding).
pub fn to_base64url(data: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.encode(data)
}

/// Convert URL-safe base64 string to bytes.
pub fn from_base64url(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.decode(s)
}

/// Securely zero a byte slice.
///
/// This uses the `zeroize` crate to ensure the memory is actually zeroed
/// and not optimized away by the compiler.
///
/// # Example
///
/// ```
/// use quantacore::utils::secure_zero;
///
/// let mut secret = vec![0x42u8; 32];
/// secure_zero(&mut secret);
/// assert!(secret.iter().all(|&b| b == 0));
/// ```
pub fn secure_zero(data: &mut [u8]) {
    data.zeroize();
}

/// Securely zero a vector and clear it.
pub fn secure_clear(data: &mut Vec<u8>) {
    data.zeroize();
    data.clear();
}

/// Constant-time comparison of two byte slices.
///
/// Returns `true` if the slices are equal, `false` otherwise.
/// The comparison time is constant regardless of where (or if) the
/// slices differ.
///
/// # Example
///
/// ```
/// use quantacore::utils::secure_compare;
///
/// assert!(secure_compare(b"hello", b"hello"));
/// assert!(!secure_compare(b"hello", b"world"));
/// ```
pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Concatenate multiple byte slices.
///
/// # Example
///
/// ```
/// use quantacore::utils::concat;
///
/// let result = concat(&[b"hello", b" ", b"world"]);
/// assert_eq!(result, b"hello world");
/// ```
pub fn concat(slices: &[&[u8]]) -> Vec<u8> {
    let total_len: usize = slices.iter().map(|s| s.len()).sum();
    let mut result = Vec::with_capacity(total_len);
    for slice in slices {
        result.extend_from_slice(slice);
    }
    result
}

/// XOR two byte slices of equal length.
///
/// # Panics
///
/// Panics if the slices have different lengths.
///
/// # Example
///
/// ```
/// use quantacore::utils::xor_bytes;
///
/// let a = [0x00, 0xFF, 0x00, 0xFF];
/// let b = [0xFF, 0x00, 0xFF, 0x00];
/// let result = xor_bytes(&a, &b);
/// assert_eq!(result, vec![0xFF, 0xFF, 0xFF, 0xFF]);
/// ```
pub fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len(), "Byte slices must have equal length");
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

/// Try to XOR two byte slices, returning an error if lengths differ.
pub fn try_xor_bytes(a: &[u8], b: &[u8]) -> Result<Vec<u8>, &'static str> {
    if a.len() != b.len() {
        return Err("Byte slices must have equal length");
    }
    Ok(xor_bytes(a, b))
}

/// Apply PKCS#7 padding.
///
/// # Arguments
///
/// * `data` - The data to pad
/// * `block_size` - The block size (typically 16 for AES)
///
/// # Example
///
/// ```
/// use quantacore::utils::pad_pkcs7;
///
/// let padded = pad_pkcs7(b"hello", 16);
/// assert_eq!(padded.len(), 16);
/// assert_eq!(padded[5..], vec![11u8; 11]);
/// ```
pub fn pad_pkcs7(data: &[u8], block_size: usize) -> Vec<u8> {
    let padding_len = block_size - (data.len() % block_size);
    let mut result = Vec::with_capacity(data.len() + padding_len);
    result.extend_from_slice(data);
    result.extend(std::iter::repeat(padding_len as u8).take(padding_len));
    result
}

/// Remove PKCS#7 padding.
///
/// # Returns
///
/// The unpadded data, or an error if the padding is invalid.
///
/// # Example
///
/// ```
/// use quantacore::utils::{pad_pkcs7, unpad_pkcs7};
///
/// let padded = pad_pkcs7(b"hello", 16);
/// let unpadded = unpad_pkcs7(&padded).unwrap();
/// assert_eq!(unpadded, b"hello");
/// ```
pub fn unpad_pkcs7(data: &[u8]) -> Result<Vec<u8>, &'static str> {
    if data.is_empty() {
        return Err("Data is empty");
    }

    let padding_len = *data.last().unwrap() as usize;
    if padding_len == 0 || padding_len > data.len() {
        return Err("Invalid padding length");
    }

    // Verify padding bytes
    for &byte in &data[data.len() - padding_len..] {
        if byte as usize != padding_len {
            return Err("Invalid padding bytes");
        }
    }

    Ok(data[..data.len() - padding_len].to_vec())
}

/// Convert an integer to big-endian bytes.
pub fn int_to_bytes_be(value: u64, length: usize) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    if length >= 8 {
        let mut result = vec![0u8; length - 8];
        result.extend_from_slice(&bytes);
        result
    } else {
        bytes[8 - length..].to_vec()
    }
}

/// Convert an integer to little-endian bytes.
pub fn int_to_bytes_le(value: u64, length: usize) -> Vec<u8> {
    let bytes = value.to_le_bytes();
    let mut result = bytes[..length.min(8)].to_vec();
    result.resize(length, 0);
    result
}

/// Convert big-endian bytes to an integer.
pub fn bytes_to_int_be(data: &[u8]) -> u64 {
    let mut bytes = [0u8; 8];
    let start = 8usize.saturating_sub(data.len());
    let copy_len = data.len().min(8);
    bytes[start..start + copy_len].copy_from_slice(&data[..copy_len]);
    u64::from_be_bytes(bytes)
}

/// Convert little-endian bytes to an integer.
pub fn bytes_to_int_le(data: &[u8]) -> u64 {
    let mut bytes = [0u8; 8];
    let copy_len = data.len().min(8);
    bytes[..copy_len].copy_from_slice(&data[..copy_len]);
    u64::from_le_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_roundtrip() {
        let data = vec![0xde, 0xad, 0xbe, 0xef];
        let hex = to_hex(&data);
        assert_eq!(hex, "deadbeef");
        let decoded = from_hex(&hex).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base64_roundtrip() {
        let data = b"Hello, World!";
        let b64 = to_base64(data);
        let decoded = from_base64(&b64).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base64url_roundtrip() {
        let data = vec![0xff, 0xfe, 0xfd];
        let b64 = to_base64url(&data);
        assert!(!b64.contains('+'));
        assert!(!b64.contains('/'));
        let decoded = from_base64url(&b64).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_secure_zero() {
        let mut data = vec![0x42u8; 32];
        secure_zero(&mut data);
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_secure_compare() {
        assert!(secure_compare(b"hello", b"hello"));
        assert!(!secure_compare(b"hello", b"world"));
        assert!(!secure_compare(b"hello", b"helloworld"));
    }

    #[test]
    fn test_concat() {
        let result = concat(&[b"hello", b" ", b"world"]);
        assert_eq!(result, b"hello world");
    }

    #[test]
    fn test_xor_bytes() {
        let a = [0x00, 0xFF, 0x00, 0xFF];
        let b = [0xFF, 0x00, 0xFF, 0x00];
        let result = xor_bytes(&a, &b);
        assert_eq!(result, vec![0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_pkcs7_padding() {
        let padded = pad_pkcs7(b"hello", 16);
        assert_eq!(padded.len(), 16);
        assert_eq!(padded[5..], vec![11u8; 11]);

        let unpadded = unpad_pkcs7(&padded).unwrap();
        assert_eq!(unpadded, b"hello");
    }

    #[test]
    fn test_int_bytes_conversion() {
        let value = 0x0102u64;
        let bytes = int_to_bytes_be(value, 2);
        assert_eq!(bytes, vec![0x01, 0x02]);
        assert_eq!(bytes_to_int_be(&bytes), value);

        let bytes_le = int_to_bytes_le(value, 2);
        assert_eq!(bytes_le, vec![0x02, 0x01]);
        assert_eq!(bytes_to_int_le(&bytes_le), value);
    }
}