//! Raw C FFI bindings for QUAC 100 native library.
//!
//! This module contains unsafe raw bindings to the C library.
//! Users should prefer the safe wrappers in other modules.

#![allow(non_camel_case_types)]
#![allow(dead_code)]

use std::os::raw::{c_char, c_int, c_uint, c_uchar, c_void};

/// Opaque device handle
pub type quac_device_t = *mut c_void;

/// Opaque hash context handle
pub type quac_hash_ctx_t = *mut c_void;

/// Device information structure
#[repr(C)]
#[derive(Debug, Clone)]
pub struct quac_device_info_t {
    pub index: c_uint,
    pub model: [c_char; 64],
    pub serial_number: [c_char; 32],
    pub firmware_version: [c_char; 32],
    pub driver_version: [c_char; 32],
    pub key_slots: c_uint,
    pub max_key_size: c_uint,
    pub features: c_uint,
}

impl Default for quac_device_info_t {
    fn default() -> Self {
        Self {
            index: 0,
            model: [0; 64],
            serial_number: [0; 32],
            firmware_version: [0; 32],
            driver_version: [0; 32],
            key_slots: 0,
            max_key_size: 0,
            features: 0,
        }
    }
}

/// Device status structure
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct quac_device_status_t {
    pub temperature: c_int,
    pub entropy_level: c_uint,
    pub operation_count: u64,
    pub error_count: u64,
    pub uptime_seconds: u64,
    pub flags: c_uint,
}

/// Entropy status structure
#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct quac_entropy_status_t {
    pub level: c_uint,
    pub is_healthy: c_int,
    pub total_generated: u64,
    pub generation_rate: f64,
}

/// Key information structure
#[repr(C)]
#[derive(Debug, Clone)]
pub struct quac_key_info_t {
    pub slot: c_uint,
    pub key_type: c_int,
    pub algorithm: c_int,
    pub usage: c_uint,
    pub label: [c_char; 64],
    pub created: u64,
    pub exportable: c_int,
}

impl Default for quac_key_info_t {
    fn default() -> Self {
        Self {
            slot: 0,
            key_type: 0,
            algorithm: 0,
            usage: 0,
            label: [0; 64],
            created: 0,
            exportable: 0,
        }
    }
}

// Link to native library
#[link(name = "quac100")]
extern "C" {
    // ========================================================================
    // Library Management
    // ========================================================================

    /// Initialize the library
    pub fn quac_init(flags: c_uint) -> c_int;

    /// Clean up the library
    pub fn quac_cleanup() -> c_int;

    /// Check if library is initialized
    pub fn quac_is_initialized() -> c_int;

    /// Get library version string
    pub fn quac_get_version() -> *const c_char;

    /// Get library build info
    pub fn quac_get_build_info() -> *const c_char;

    // ========================================================================
    // Device Management
    // ========================================================================

    /// Get number of available devices
    pub fn quac_get_device_count() -> c_int;

    /// Get device information by index
    pub fn quac_get_device_info(index: c_uint, info: *mut quac_device_info_t) -> c_int;

    /// Open a device by index
    pub fn quac_open_device(index: c_uint, device: *mut quac_device_t) -> c_int;

    /// Close a device
    pub fn quac_close_device(device: quac_device_t) -> c_int;

    /// Get device status
    pub fn quac_device_get_status(device: quac_device_t, status: *mut quac_device_status_t) -> c_int;

    /// Run device self-test
    pub fn quac_device_self_test(device: quac_device_t) -> c_int;

    /// Reset device
    pub fn quac_device_reset(device: quac_device_t) -> c_int;

    // ========================================================================
    // KEM Operations
    // ========================================================================

    /// Generate KEM key pair
    pub fn quac_kem_keygen(
        device: quac_device_t,
        algorithm: c_int,
        public_key: *mut c_uchar,
        public_key_len: *mut usize,
        secret_key: *mut c_uchar,
        secret_key_len: *mut usize,
    ) -> c_int;

    /// Encapsulate - generate shared secret and ciphertext
    pub fn quac_kem_encapsulate(
        device: quac_device_t,
        algorithm: c_int,
        public_key: *const c_uchar,
        public_key_len: usize,
        ciphertext: *mut c_uchar,
        ciphertext_len: *mut usize,
        shared_secret: *mut c_uchar,
        shared_secret_len: *mut usize,
    ) -> c_int;

    /// Decapsulate - recover shared secret from ciphertext
    pub fn quac_kem_decapsulate(
        device: quac_device_t,
        algorithm: c_int,
        secret_key: *const c_uchar,
        secret_key_len: usize,
        ciphertext: *const c_uchar,
        ciphertext_len: usize,
        shared_secret: *mut c_uchar,
        shared_secret_len: *mut usize,
    ) -> c_int;

    // ========================================================================
    // Signature Operations
    // ========================================================================

    /// Generate signature key pair
    pub fn quac_sign_keygen(
        device: quac_device_t,
        algorithm: c_int,
        public_key: *mut c_uchar,
        public_key_len: *mut usize,
        secret_key: *mut c_uchar,
        secret_key_len: *mut usize,
    ) -> c_int;

    /// Sign a message
    pub fn quac_sign(
        device: quac_device_t,
        algorithm: c_int,
        secret_key: *const c_uchar,
        secret_key_len: usize,
        message: *const c_uchar,
        message_len: usize,
        signature: *mut c_uchar,
        signature_len: *mut usize,
    ) -> c_int;

    /// Verify a signature
    pub fn quac_verify(
        device: quac_device_t,
        algorithm: c_int,
        public_key: *const c_uchar,
        public_key_len: usize,
        message: *const c_uchar,
        message_len: usize,
        signature: *const c_uchar,
        signature_len: usize,
    ) -> c_int;

    // ========================================================================
    // Hash Operations
    // ========================================================================

    /// One-shot hash
    pub fn quac_hash(
        device: quac_device_t,
        algorithm: c_int,
        data: *const c_uchar,
        data_len: usize,
        digest: *mut c_uchar,
        digest_len: *mut usize,
    ) -> c_int;

    /// Create hash context for incremental hashing
    pub fn quac_hash_init(
        device: quac_device_t,
        algorithm: c_int,
        ctx: *mut quac_hash_ctx_t,
    ) -> c_int;

    /// Update hash context with data
    pub fn quac_hash_update(
        ctx: quac_hash_ctx_t,
        data: *const c_uchar,
        data_len: usize,
    ) -> c_int;

    /// Finalize hash and get digest
    pub fn quac_hash_final(
        ctx: quac_hash_ctx_t,
        digest: *mut c_uchar,
        digest_len: *mut usize,
    ) -> c_int;

    /// Free hash context
    pub fn quac_hash_free(ctx: quac_hash_ctx_t) -> c_int;

    /// HMAC operation
    pub fn quac_hmac(
        device: quac_device_t,
        algorithm: c_int,
        key: *const c_uchar,
        key_len: usize,
        data: *const c_uchar,
        data_len: usize,
        mac: *mut c_uchar,
        mac_len: *mut usize,
    ) -> c_int;

    /// HKDF key derivation
    pub fn quac_hkdf(
        device: quac_device_t,
        algorithm: c_int,
        ikm: *const c_uchar,
        ikm_len: usize,
        salt: *const c_uchar,
        salt_len: usize,
        info: *const c_uchar,
        info_len: usize,
        okm: *mut c_uchar,
        okm_len: usize,
    ) -> c_int;

    // ========================================================================
    // Random Number Generation
    // ========================================================================

    /// Generate random bytes
    pub fn quac_random_bytes(
        device: quac_device_t,
        buffer: *mut c_uchar,
        length: usize,
    ) -> c_int;

    /// Get entropy status
    pub fn quac_get_entropy_status(
        device: quac_device_t,
        status: *mut quac_entropy_status_t,
    ) -> c_int;

    // ========================================================================
    // Key Storage (HSM)
    // ========================================================================

    /// Store a key in HSM
    pub fn quac_key_store(
        device: quac_device_t,
        slot: c_uint,
        key_type: c_int,
        algorithm: c_int,
        usage: c_uint,
        label: *const c_char,
        key_data: *const c_uchar,
        key_len: usize,
    ) -> c_int;

    /// Load a key from HSM
    pub fn quac_key_load(
        device: quac_device_t,
        slot: c_uint,
        key_data: *mut c_uchar,
        key_len: *mut usize,
    ) -> c_int;

    /// Get key information
    pub fn quac_key_get_info(
        device: quac_device_t,
        slot: c_uint,
        info: *mut quac_key_info_t,
    ) -> c_int;

    /// Delete a key from HSM
    pub fn quac_key_delete(
        device: quac_device_t,
        slot: c_uint,
    ) -> c_int;

    /// List all keys
    pub fn quac_key_list(
        device: quac_device_t,
        slots: *mut c_uint,
        count: *mut usize,
    ) -> c_int;

    /// Get number of key slots
    pub fn quac_key_get_slot_count(device: quac_device_t) -> c_int;

    /// Find first free slot
    pub fn quac_key_get_free_slot(device: quac_device_t) -> c_int;

    /// Clear all keys
    pub fn quac_key_clear_all(device: quac_device_t) -> c_int;
}