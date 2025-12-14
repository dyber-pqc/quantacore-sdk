//! Error types for QUAC 100 SDK.
//!
//! This module provides error handling through the `QuacError` type and
//! the `ErrorCode` enum which maps to the native library's error codes.

use std::fmt;
use thiserror::Error;

/// Result type alias for QUAC 100 operations.
pub type Result<T> = std::result::Result<T, QuacError>;

/// Error codes returned by QUAC 100 operations.
///
/// These map directly to the native library's error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum ErrorCode {
    /// Operation completed successfully
    Success = 0,
    /// Generic error
    Error = -1,
    /// Invalid parameter
    InvalidParam = -2,
    /// Output buffer too small
    BufferSmall = -3,
    /// No QUAC 100 device found
    DeviceNotFound = -4,
    /// Device is busy
    DeviceBusy = -5,
    /// Device error
    DeviceError = -6,
    /// Memory allocation failed
    OutOfMemory = -7,
    /// Operation not supported
    NotSupported = -8,
    /// Authentication required
    AuthRequired = -9,
    /// Authentication failed
    AuthFailed = -10,
    /// Key not found
    KeyNotFound = -11,
    /// Invalid key
    InvalidKey = -12,
    /// Signature verification failed
    VerificationFailed = -13,
    /// Decapsulation failed
    DecapsFailed = -14,
    /// Hardware acceleration unavailable
    HardwareUnavail = -15,
    /// Operation timed out
    Timeout = -16,
    /// Library not initialized
    NotInitialized = -17,
    /// Library already initialized
    AlreadyInit = -18,
    /// Invalid handle
    InvalidHandle = -19,
    /// Operation cancelled
    Cancelled = -20,
    /// Entropy pool depleted
    EntropyDepleted = -21,
    /// Self-test failed
    SelfTestFailed = -22,
    /// Tamper detected
    TamperDetected = -23,
    /// Temperature error
    Temperature = -24,
    /// Power supply error
    Power = -25,
    /// Invalid algorithm
    InvalidAlgorithm = -26,
    /// Cryptographic operation error
    CryptoError = -27,
    /// Internal error
    InternalError = -99,
}

impl ErrorCode {
    /// Get human-readable message for this error code.
    pub fn message(&self) -> &'static str {
        match self {
            Self::Success => "Operation completed successfully",
            Self::Error => "Generic error",
            Self::InvalidParam => "Invalid parameter",
            Self::BufferSmall => "Output buffer too small",
            Self::DeviceNotFound => "No QUAC 100 device found",
            Self::DeviceBusy => "Device is busy",
            Self::DeviceError => "Device error",
            Self::OutOfMemory => "Memory allocation failed",
            Self::NotSupported => "Operation not supported",
            Self::AuthRequired => "Authentication required",
            Self::AuthFailed => "Authentication failed",
            Self::KeyNotFound => "Key not found",
            Self::InvalidKey => "Invalid key",
            Self::VerificationFailed => "Signature verification failed",
            Self::DecapsFailed => "Decapsulation failed",
            Self::HardwareUnavail => "Hardware acceleration unavailable",
            Self::Timeout => "Operation timed out",
            Self::NotInitialized => "Library not initialized",
            Self::AlreadyInit => "Library already initialized",
            Self::InvalidHandle => "Invalid handle",
            Self::Cancelled => "Operation cancelled",
            Self::EntropyDepleted => "Entropy pool depleted",
            Self::SelfTestFailed => "Self-test failed",
            Self::TamperDetected => "Tamper detected",
            Self::Temperature => "Temperature error",
            Self::Power => "Power supply error",
            Self::InvalidAlgorithm => "Invalid algorithm",
            Self::CryptoError => "Cryptographic operation error",
            Self::InternalError => "Internal error",
        }
    }

    /// Create from raw i32 value.
    pub fn from_raw(code: i32) -> Self {
        match code {
            0 => Self::Success,
            -1 => Self::Error,
            -2 => Self::InvalidParam,
            -3 => Self::BufferSmall,
            -4 => Self::DeviceNotFound,
            -5 => Self::DeviceBusy,
            -6 => Self::DeviceError,
            -7 => Self::OutOfMemory,
            -8 => Self::NotSupported,
            -9 => Self::AuthRequired,
            -10 => Self::AuthFailed,
            -11 => Self::KeyNotFound,
            -12 => Self::InvalidKey,
            -13 => Self::VerificationFailed,
            -14 => Self::DecapsFailed,
            -15 => Self::HardwareUnavail,
            -16 => Self::Timeout,
            -17 => Self::NotInitialized,
            -18 => Self::AlreadyInit,
            -19 => Self::InvalidHandle,
            -20 => Self::Cancelled,
            -21 => Self::EntropyDepleted,
            -22 => Self::SelfTestFailed,
            -23 => Self::TamperDetected,
            -24 => Self::Temperature,
            -25 => Self::Power,
            -26 => Self::InvalidAlgorithm,
            -27 => Self::CryptoError,
            _ => Self::InternalError,
        }
    }

    /// Convert to raw i32 value.
    pub fn to_raw(self) -> i32 {
        self as i32
    }

    /// Check if this is a success code.
    pub fn is_success(self) -> bool {
        self == Self::Success
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message())
    }
}

/// Main error type for QUAC 100 operations.
#[derive(Error, Debug)]
pub enum QuacError {
    /// Error from the native library
    #[error("QUAC 100 error ({code:?}): {message}")]
    Native {
        /// The error code
        code: ErrorCode,
        /// Human-readable message
        message: String,
    },

    /// Device not found
    #[error("Device not found: {0}")]
    DeviceNotFound(String),

    /// Invalid parameter
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    /// Verification failed
    #[error("Verification failed")]
    VerificationFailed,

    /// Decapsulation failed
    #[error("Decapsulation failed")]
    DecapsulationFailed,

    /// Library not initialized
    #[error("Library not initialized")]
    NotInitialized,

    /// Buffer too small
    #[error("Buffer too small: need {needed} bytes, got {got}")]
    BufferTooSmall {
        /// Bytes needed
        needed: usize,
        /// Bytes provided
        got: usize,
    },

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// UTF-8 conversion error
    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    /// Null pointer error
    #[error("Null pointer encountered")]
    NullPointer,

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl QuacError {
    /// Create a new native error from an error code.
    pub fn from_code(code: ErrorCode) -> Self {
        Self::Native {
            message: code.message().to_string(),
            code,
        }
    }

    /// Create a new native error from a raw error code.
    pub fn from_raw(code: i32) -> Self {
        Self::from_code(ErrorCode::from_raw(code))
    }

    /// Get the error code if this is a native error.
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            Self::Native { code, .. } => Some(*code),
            Self::DeviceNotFound(_) => Some(ErrorCode::DeviceNotFound),
            Self::InvalidParameter(_) => Some(ErrorCode::InvalidParam),
            Self::VerificationFailed => Some(ErrorCode::VerificationFailed),
            Self::DecapsulationFailed => Some(ErrorCode::DecapsFailed),
            Self::NotInitialized => Some(ErrorCode::NotInitialized),
            Self::BufferTooSmall { .. } => Some(ErrorCode::BufferSmall),
            _ => None,
        }
    }

    /// Check if this is a verification error.
    pub fn is_verification_error(&self) -> bool {
        matches!(
            self,
            Self::VerificationFailed | Self::Native { code: ErrorCode::VerificationFailed, .. }
        )
    }
}

/// Check a raw return code and convert to Result.
pub(crate) fn check_error(code: i32) -> Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(QuacError::from_raw(code))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_from_raw() {
        assert_eq!(ErrorCode::from_raw(0), ErrorCode::Success);
        assert_eq!(ErrorCode::from_raw(-2), ErrorCode::InvalidParam);
        assert_eq!(ErrorCode::from_raw(-17), ErrorCode::NotInitialized);
        assert_eq!(ErrorCode::from_raw(-999), ErrorCode::InternalError);
    }

    #[test]
    fn test_error_code_message() {
        assert_eq!(ErrorCode::Success.message(), "Operation completed successfully");
        assert!(ErrorCode::InvalidParam.message().contains("Invalid"));
    }

    #[test]
    fn test_quac_error_from_code() {
        let err = QuacError::from_code(ErrorCode::DeviceNotFound);
        assert_eq!(err.code(), Some(ErrorCode::DeviceNotFound));
    }

    #[test]
    fn test_check_error() {
        assert!(check_error(0).is_ok());
        assert!(check_error(-1).is_err());
    }
}