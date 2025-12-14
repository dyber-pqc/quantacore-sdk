//! Hash and MAC operations.
//!
//! This module provides hardware-accelerated hashing, HMAC, and HKDF.

use crate::device::Device;
use crate::error::{check_error, Result};
use crate::ffi;
use crate::types::HashAlgorithm;

/// Hash context for incremental hashing.
///
/// Use this for hashing data that arrives in chunks.
pub struct HashContext {
    handle: ffi::quac_hash_ctx_t,
    algorithm: HashAlgorithm,
}

impl HashContext {
    /// Create a new hash context.
    fn new(handle: ffi::quac_hash_ctx_t, algorithm: HashAlgorithm) -> Self {
        Self { handle, algorithm }
    }

    /// Update the hash with additional data.
    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        let result = unsafe { ffi::quac_hash_update(self.handle, data.as_ptr(), data.len()) };
        check_error(result)
    }

    /// Finalize and get the digest.
    ///
    /// The context is consumed and cannot be used after this.
    pub fn finalize(self) -> Result<Vec<u8>> {
        let size = self.algorithm.digest_size().unwrap_or(64);
        let mut digest = vec![0u8; size];
        let mut digest_len = size;

        let result = unsafe {
            ffi::quac_hash_final(self.handle, digest.as_mut_ptr(), &mut digest_len)
        };

        // Don't run drop since finalize already cleans up
        std::mem::forget(self);

        check_error(result)?;
        digest.truncate(digest_len);

        Ok(digest)
    }

    /// Get the algorithm.
    pub fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }
}

impl Drop for HashContext {
    fn drop(&mut self) {
        unsafe {
            ffi::quac_hash_free(self.handle);
        }
    }
}

// Safety: Hash context is thread-safe
unsafe impl Send for HashContext {}

impl std::fmt::Debug for HashContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HashContext")
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

/// Hash subsystem.
///
/// Provides hardware-accelerated hash functions including
/// SHA-2, SHA-3, SHAKE, HMAC, and HKDF.
///
/// # Example
///
/// ```no_run
/// use quantacore::{initialize, open_first_device, HashAlgorithm};
///
/// initialize().unwrap();
/// let device = open_first_device().unwrap();
/// let hash = device.hash();
///
/// // One-shot hashing
/// let digest = hash.sha256(b"Hello, World!").unwrap();
/// println!("SHA-256: {}", hex::encode(&digest));
///
/// // Incremental hashing
/// let mut ctx = hash.create_context(HashAlgorithm::Sha3_256).unwrap();
/// ctx.update(b"Hello, ").unwrap();
/// ctx.update(b"World!").unwrap();
/// let digest = ctx.finalize().unwrap();
/// ```
#[derive(Clone)]
pub struct Hash {
    device: Device,
}

impl Hash {
    /// Create a new hash subsystem handle.
    pub(crate) fn new(device: Device) -> Self {
        Self { device }
    }

    /// Compute a hash digest.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The hash algorithm to use
    /// * `data` - The data to hash
    ///
    /// # Returns
    ///
    /// The hash digest.
    pub fn hash(&self, algorithm: HashAlgorithm, data: &[u8]) -> Result<Vec<u8>> {
        let size = algorithm.digest_size().unwrap_or(64);
        let mut digest = vec![0u8; size];
        let mut digest_len = size;

        let result = unsafe {
            ffi::quac_hash(
                self.device.handle(),
                algorithm.to_raw(),
                data.as_ptr(),
                data.len(),
                digest.as_mut_ptr(),
                &mut digest_len,
            )
        };

        check_error(result)?;
        digest.truncate(digest_len);

        Ok(digest)
    }

    /// Compute SHA-256 digest.
    pub fn sha256(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.hash(HashAlgorithm::Sha256, data)
    }

    /// Compute SHA-384 digest.
    pub fn sha384(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.hash(HashAlgorithm::Sha384, data)
    }

    /// Compute SHA-512 digest.
    pub fn sha512(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.hash(HashAlgorithm::Sha512, data)
    }

    /// Compute SHA3-256 digest.
    pub fn sha3_256(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.hash(HashAlgorithm::Sha3_256, data)
    }

    /// Compute SHA3-384 digest.
    pub fn sha3_384(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.hash(HashAlgorithm::Sha3_384, data)
    }

    /// Compute SHA3-512 digest.
    pub fn sha3_512(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.hash(HashAlgorithm::Sha3_512, data)
    }

    /// Compute SHAKE128 output.
    ///
    /// # Arguments
    ///
    /// * `data` - The input data
    /// * `output_len` - The desired output length in bytes
    pub fn shake128(&self, data: &[u8], output_len: usize) -> Result<Vec<u8>> {
        self.shake(HashAlgorithm::Shake128, data, output_len)
    }

    /// Compute SHAKE256 output.
    ///
    /// # Arguments
    ///
    /// * `data` - The input data
    /// * `output_len` - The desired output length in bytes
    pub fn shake256(&self, data: &[u8], output_len: usize) -> Result<Vec<u8>> {
        self.shake(HashAlgorithm::Shake256, data, output_len)
    }

    /// Compute SHAKE output.
    fn shake(&self, algorithm: HashAlgorithm, data: &[u8], output_len: usize) -> Result<Vec<u8>> {
        let mut output = vec![0u8; output_len];
        let mut len = output_len;

        let result = unsafe {
            ffi::quac_hash(
                self.device.handle(),
                algorithm.to_raw(),
                data.as_ptr(),
                data.len(),
                output.as_mut_ptr(),
                &mut len,
            )
        };

        check_error(result)?;
        output.truncate(len);

        Ok(output)
    }

    /// Create a hash context for incremental hashing.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use quantacore::{initialize, open_first_device, HashAlgorithm};
    /// # initialize().unwrap();
    /// # let device = open_first_device().unwrap();
    /// # let hash = device.hash();
    /// let mut ctx = hash.create_context(HashAlgorithm::Sha256).unwrap();
    /// ctx.update(b"part 1").unwrap();
    /// ctx.update(b"part 2").unwrap();
    /// let digest = ctx.finalize().unwrap();
    /// ```
    pub fn create_context(&self, algorithm: HashAlgorithm) -> Result<HashContext> {
        let mut handle = std::ptr::null_mut();
        let result = unsafe {
            ffi::quac_hash_init(self.device.handle(), algorithm.to_raw(), &mut handle)
        };
        check_error(result)?;
        Ok(HashContext::new(handle, algorithm))
    }

    /// Compute HMAC.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The hash algorithm to use
    /// * `key` - The HMAC key
    /// * `data` - The data to authenticate
    ///
    /// # Returns
    ///
    /// The MAC tag.
    pub fn hmac(&self, algorithm: HashAlgorithm, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let size = algorithm.digest_size().unwrap_or(64);
        let mut mac = vec![0u8; size];
        let mut mac_len = size;

        let result = unsafe {
            ffi::quac_hmac(
                self.device.handle(),
                algorithm.to_raw(),
                key.as_ptr(),
                key.len(),
                data.as_ptr(),
                data.len(),
                mac.as_mut_ptr(),
                &mut mac_len,
            )
        };

        check_error(result)?;
        mac.truncate(mac_len);

        Ok(mac)
    }

    /// Compute HMAC-SHA256.
    pub fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        self.hmac(HashAlgorithm::Sha256, key, data)
    }

    /// Compute HMAC-SHA384.
    pub fn hmac_sha384(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        self.hmac(HashAlgorithm::Sha384, key, data)
    }

    /// Compute HMAC-SHA512.
    pub fn hmac_sha512(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        self.hmac(HashAlgorithm::Sha512, key, data)
    }

    /// Derive a key using HKDF.
    ///
    /// # Arguments
    ///
    /// * `algorithm` - The hash algorithm to use
    /// * `ikm` - Input keying material
    /// * `salt` - Optional salt (can be empty)
    /// * `info` - Optional context info (can be empty)
    /// * `output_len` - Desired output length
    ///
    /// # Returns
    ///
    /// The derived key material.
    pub fn hkdf(
        &self,
        algorithm: HashAlgorithm,
        ikm: &[u8],
        salt: &[u8],
        info: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>> {
        let mut okm = vec![0u8; output_len];

        let result = unsafe {
            ffi::quac_hkdf(
                self.device.handle(),
                algorithm.to_raw(),
                ikm.as_ptr(),
                ikm.len(),
                salt.as_ptr(),
                salt.len(),
                info.as_ptr(),
                info.len(),
                okm.as_mut_ptr(),
                output_len,
            )
        };

        check_error(result)?;
        Ok(okm)
    }

    /// Derive a key using HKDF-SHA256.
    pub fn hkdf_sha256(
        &self,
        ikm: &[u8],
        salt: &[u8],
        info: &[u8],
        output_len: usize,
    ) -> Result<Vec<u8>> {
        self.hkdf(HashAlgorithm::Sha256, ikm, salt, info, output_len)
    }
}

impl std::fmt::Debug for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hash").finish()
    }
}