//! Type definitions for QUAC 100 SDK.
//!
//! This module contains enums and type aliases used throughout the SDK.

use bitflags::bitflags;

/// Key Encapsulation Mechanism algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum KemAlgorithm {
    /// ML-KEM-512 (128-bit security)
    MlKem512 = 0,
    /// ML-KEM-768 (192-bit security)
    MlKem768 = 1,
    /// ML-KEM-1024 (256-bit security)
    MlKem1024 = 2,
}

impl KemAlgorithm {
    /// Alias for ML-KEM-512 (NIST naming)
    pub const KYBER_512: Self = Self::MlKem512;
    /// Alias for ML-KEM-768 (NIST naming)
    pub const KYBER_768: Self = Self::MlKem768;
    /// Alias for ML-KEM-1024 (NIST naming)
    pub const KYBER_1024: Self = Self::MlKem1024;

    /// Get public key size in bytes.
    pub const fn public_key_size(self) -> usize {
        match self {
            Self::MlKem512 => 800,
            Self::MlKem768 => 1184,
            Self::MlKem1024 => 1568,
        }
    }

    /// Get secret key size in bytes.
    pub const fn secret_key_size(self) -> usize {
        match self {
            Self::MlKem512 => 1632,
            Self::MlKem768 => 2400,
            Self::MlKem1024 => 3168,
        }
    }

    /// Get ciphertext size in bytes.
    pub const fn ciphertext_size(self) -> usize {
        match self {
            Self::MlKem512 => 768,
            Self::MlKem768 => 1088,
            Self::MlKem1024 => 1568,
        }
    }

    /// Get shared secret size in bytes (always 32).
    pub const fn shared_secret_size(self) -> usize {
        32
    }

    /// Get raw value for FFI.
    pub const fn to_raw(self) -> i32 {
        self as i32
    }

    /// Create from raw FFI value.
    pub fn from_raw(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::MlKem512),
            1 => Some(Self::MlKem768),
            2 => Some(Self::MlKem1024),
            _ => None,
        }
    }
}

impl std::fmt::Display for KemAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MlKem512 => write!(f, "ML-KEM-512"),
            Self::MlKem768 => write!(f, "ML-KEM-768"),
            Self::MlKem1024 => write!(f, "ML-KEM-1024"),
        }
    }
}

/// Digital Signature algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum SignAlgorithm {
    /// ML-DSA-44 (128-bit security)
    MlDsa44 = 0,
    /// ML-DSA-65 (192-bit security)
    MlDsa65 = 1,
    /// ML-DSA-87 (256-bit security)
    MlDsa87 = 2,
}

impl SignAlgorithm {
    /// Alias for ML-DSA-44 (NIST naming)
    pub const DILITHIUM_2: Self = Self::MlDsa44;
    /// Alias for ML-DSA-65 (NIST naming)
    pub const DILITHIUM_3: Self = Self::MlDsa65;
    /// Alias for ML-DSA-87 (NIST naming)
    pub const DILITHIUM_5: Self = Self::MlDsa87;

    /// Get public key size in bytes.
    pub const fn public_key_size(self) -> usize {
        match self {
            Self::MlDsa44 => 1312,
            Self::MlDsa65 => 1952,
            Self::MlDsa87 => 2592,
        }
    }

    /// Get secret key size in bytes.
    pub const fn secret_key_size(self) -> usize {
        match self {
            Self::MlDsa44 => 2560,
            Self::MlDsa65 => 4032,
            Self::MlDsa87 => 4896,
        }
    }

    /// Get maximum signature size in bytes.
    pub const fn signature_size(self) -> usize {
        match self {
            Self::MlDsa44 => 2420,
            Self::MlDsa65 => 3309,
            Self::MlDsa87 => 4627,
        }
    }

    /// Get raw value for FFI.
    pub const fn to_raw(self) -> i32 {
        self as i32
    }

    /// Create from raw FFI value.
    pub fn from_raw(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::MlDsa44),
            1 => Some(Self::MlDsa65),
            2 => Some(Self::MlDsa87),
            _ => None,
        }
    }
}

impl std::fmt::Display for SignAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MlDsa44 => write!(f, "ML-DSA-44"),
            Self::MlDsa65 => write!(f, "ML-DSA-65"),
            Self::MlDsa87 => write!(f, "ML-DSA-87"),
        }
    }
}

/// Hash algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum HashAlgorithm {
    /// SHA-256
    Sha256 = 0,
    /// SHA-384
    Sha384 = 1,
    /// SHA-512
    Sha512 = 2,
    /// SHA3-256
    Sha3_256 = 3,
    /// SHA3-384
    Sha3_384 = 4,
    /// SHA3-512
    Sha3_512 = 5,
    /// SHAKE128 (variable output)
    Shake128 = 6,
    /// SHAKE256 (variable output)
    Shake256 = 7,
}

impl HashAlgorithm {
    /// Get digest size in bytes, or None for variable-length (SHAKE).
    pub const fn digest_size(self) -> Option<usize> {
        match self {
            Self::Sha256 | Self::Sha3_256 => Some(32),
            Self::Sha384 | Self::Sha3_384 => Some(48),
            Self::Sha512 | Self::Sha3_512 => Some(64),
            Self::Shake128 | Self::Shake256 => None,
        }
    }

    /// Check if this is a SHAKE algorithm (variable output).
    pub const fn is_xof(self) -> bool {
        matches!(self, Self::Shake128 | Self::Shake256)
    }

    /// Get raw value for FFI.
    pub const fn to_raw(self) -> i32 {
        self as i32
    }

    /// Create from raw FFI value.
    pub fn from_raw(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::Sha256),
            1 => Some(Self::Sha384),
            2 => Some(Self::Sha512),
            3 => Some(Self::Sha3_256),
            4 => Some(Self::Sha3_384),
            5 => Some(Self::Sha3_512),
            6 => Some(Self::Shake128),
            7 => Some(Self::Shake256),
            _ => None,
        }
    }
}

impl std::fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sha256 => write!(f, "SHA-256"),
            Self::Sha384 => write!(f, "SHA-384"),
            Self::Sha512 => write!(f, "SHA-512"),
            Self::Sha3_256 => write!(f, "SHA3-256"),
            Self::Sha3_384 => write!(f, "SHA3-384"),
            Self::Sha3_512 => write!(f, "SHA3-512"),
            Self::Shake128 => write!(f, "SHAKE128"),
            Self::Shake256 => write!(f, "SHAKE256"),
        }
    }
}

/// Key types for HSM storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum KeyType {
    /// Symmetric key
    Secret = 0,
    /// Public key only
    Public = 1,
    /// Private key only
    Private = 2,
    /// Full key pair
    KeyPair = 3,
}

impl KeyType {
    /// Get raw value for FFI.
    pub const fn to_raw(self) -> i32 {
        self as i32
    }

    /// Create from raw FFI value.
    pub fn from_raw(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::Secret),
            1 => Some(Self::Public),
            2 => Some(Self::Private),
            3 => Some(Self::KeyPair),
            _ => None,
        }
    }
}

bitflags! {
    /// Key usage flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct KeyUsage: u32 {
        /// Key can be used for encryption
        const ENCRYPT = 0x01;
        /// Key can be used for decryption
        const DECRYPT = 0x02;
        /// Key can be used for signing
        const SIGN = 0x04;
        /// Key can be used for verification
        const VERIFY = 0x08;
        /// Key can be used for key derivation
        const DERIVE = 0x10;
        /// Key can be used to wrap other keys
        const WRAP = 0x20;
        /// Key can be used to unwrap other keys
        const UNWRAP = 0x40;

        /// Encryption and decryption
        const ENCRYPTION = Self::ENCRYPT.bits() | Self::DECRYPT.bits();
        /// Signing and verification
        const SIGNING = Self::SIGN.bits() | Self::VERIFY.bits();
        /// All usages
        const ALL = Self::ENCRYPT.bits() | Self::DECRYPT.bits() | Self::SIGN.bits()
                  | Self::VERIFY.bits() | Self::DERIVE.bits() | Self::WRAP.bits()
                  | Self::UNWRAP.bits();
    }
}

bitflags! {
    /// Library initialization flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct InitFlags: u32 {
        /// Use hardware acceleration
        const HARDWARE_ACCEL = 0x01;
        /// Enable side-channel protection
        const SIDE_CHANNEL_PROTECT = 0x02;
        /// Use constant-time operations
        const CONSTANT_TIME = 0x04;
        /// Auto-zeroize sensitive data
        const AUTO_ZEROIZE = 0x08;
        /// Enable FIPS 140-3 mode
        const FIPS_MODE = 0x10;
        /// Enable debug output
        const DEBUG = 0x20;
        /// Allow software fallback
        const SOFTWARE_FALLBACK = 0x40;

        /// Default flags (hardware + protection + constant time + auto zeroize)
        const DEFAULT = Self::HARDWARE_ACCEL.bits() | Self::SIDE_CHANNEL_PROTECT.bits()
                      | Self::CONSTANT_TIME.bits() | Self::AUTO_ZEROIZE.bits();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kem_algorithm_sizes() {
        assert_eq!(KemAlgorithm::MlKem512.public_key_size(), 800);
        assert_eq!(KemAlgorithm::MlKem768.public_key_size(), 1184);
        assert_eq!(KemAlgorithm::MlKem1024.public_key_size(), 1568);
        assert_eq!(KemAlgorithm::MlKem768.shared_secret_size(), 32);
    }

    #[test]
    fn test_sign_algorithm_sizes() {
        assert_eq!(SignAlgorithm::MlDsa44.public_key_size(), 1312);
        assert_eq!(SignAlgorithm::MlDsa65.signature_size(), 3309);
    }

    #[test]
    fn test_hash_algorithm_digest_size() {
        assert_eq!(HashAlgorithm::Sha256.digest_size(), Some(32));
        assert_eq!(HashAlgorithm::Sha512.digest_size(), Some(64));
        assert_eq!(HashAlgorithm::Shake128.digest_size(), None);
    }

    #[test]
    fn test_key_usage_flags() {
        let usage = KeyUsage::ENCRYPT | KeyUsage::DECRYPT;
        assert_eq!(usage, KeyUsage::ENCRYPTION);
    }

    #[test]
    fn test_init_flags() {
        assert_eq!(InitFlags::DEFAULT.bits(), 0x0F);
    }
}