//! HSM Key Storage operations.
//!
//! This module provides secure key storage in the hardware HSM.

use crate::device::Device;
use crate::error::{check_error, Result, QuacError, ErrorCode};
use crate::ffi;
use crate::types::{KeyType, KeyUsage};

use std::ffi::CString;

/// Information about a stored key.
#[derive(Debug, Clone)]
pub struct KeyInfo {
    /// Slot number
    pub slot: u32,
    /// Key type
    pub key_type: KeyType,
    /// Algorithm identifier
    pub algorithm: i32,
    /// Usage flags
    pub usage: KeyUsage,
    /// Key label
    pub label: String,
    /// Creation timestamp (Unix epoch)
    pub created: u64,
    /// Whether the key can be exported
    pub exportable: bool,
}

impl KeyInfo {
    pub(crate) fn from_ffi(info: &ffi::quac_key_info_t) -> Self {
        use std::ffi::CStr;
        
        Self {
            slot: info.slot,
            key_type: KeyType::from_raw(info.key_type).unwrap_or(KeyType::Secret),
            algorithm: info.algorithm,
            usage: KeyUsage::from_bits_truncate(info.usage),
            label: unsafe {
                CStr::from_ptr(info.label.as_ptr())
                    .to_string_lossy()
                    .into_owned()
            },
            created: info.created,
            exportable: info.exportable != 0,
        }
    }
}

/// Key storage (HSM) subsystem.
///
/// Provides secure key storage in the hardware security module.
///
/// # Example
///
/// ```no_run
/// use quantacore::{initialize, open_first_device, KeyType, KeyUsage};
///
/// initialize().unwrap();
/// let device = open_first_device().unwrap();
/// let keys = device.keys();
///
/// // Store a key
/// let key_data = vec![0u8; 32]; // Your key material
/// keys.store(
///     0,  // slot
///     KeyType::Secret,
///     0,  // algorithm
///     KeyUsage::ENCRYPT | KeyUsage::DECRYPT,
///     "my-key",
///     &key_data,
/// ).unwrap();
///
/// // Load the key
/// let loaded = keys.load(0).unwrap();
///
/// // Get key info
/// let info = keys.get_info(0).unwrap();
/// println!("Key label: {}", info.label);
///
/// // Delete the key
/// keys.delete(0).unwrap();
/// ```
#[derive(Clone)]
pub struct Keys {
    device: Device,
}

impl Keys {
    /// Create a new keys subsystem handle.
    pub(crate) fn new(device: Device) -> Self {
        Self { device }
    }

    /// Store a key in the HSM.
    ///
    /// # Arguments
    ///
    /// * `slot` - The slot number to store the key in
    /// * `key_type` - The type of key
    /// * `algorithm` - The algorithm identifier
    /// * `usage` - Allowed usage flags
    /// * `label` - A human-readable label (max 63 chars)
    /// * `key_data` - The raw key material
    pub fn store(
        &self,
        slot: u32,
        key_type: KeyType,
        algorithm: i32,
        usage: KeyUsage,
        label: &str,
        key_data: &[u8],
    ) -> Result<()> {
        let c_label = CString::new(label).map_err(|_| {
            QuacError::InvalidParameter("Label contains null bytes".into())
        })?;

        let result = unsafe {
            ffi::quac_key_store(
                self.device.handle(),
                slot,
                key_type.to_raw(),
                algorithm,
                usage.bits(),
                c_label.as_ptr(),
                key_data.as_ptr(),
                key_data.len(),
            )
        };

        check_error(result)
    }

    /// Load a key from the HSM.
    ///
    /// # Arguments
    ///
    /// * `slot` - The slot number to load from
    ///
    /// # Returns
    ///
    /// The raw key material.
    pub fn load(&self, slot: u32) -> Result<Vec<u8>> {
        // First get info to determine key size
        let _info = self.get_info(slot)?;
        let max_size = 8192; // Maximum reasonable key size

        let mut key_data = vec![0u8; max_size];
        let mut key_len = max_size;

        let result = unsafe {
            ffi::quac_key_load(
                self.device.handle(),
                slot,
                key_data.as_mut_ptr(),
                &mut key_len,
            )
        };

        check_error(result)?;
        key_data.truncate(key_len);

        Ok(key_data)
    }

    /// Get information about a stored key.
    ///
    /// # Arguments
    ///
    /// * `slot` - The slot number
    ///
    /// # Returns
    ///
    /// Information about the key in that slot.
    pub fn get_info(&self, slot: u32) -> Result<KeyInfo> {
        let mut info = ffi::quac_key_info_t::default();
        let result = unsafe {
            ffi::quac_key_get_info(self.device.handle(), slot, &mut info)
        };
        check_error(result)?;
        Ok(KeyInfo::from_ffi(&info))
    }

    /// Delete a key from the HSM.
    ///
    /// # Arguments
    ///
    /// * `slot` - The slot number to delete
    pub fn delete(&self, slot: u32) -> Result<()> {
        let result = unsafe { ffi::quac_key_delete(self.device.handle(), slot) };
        check_error(result)
    }

    /// List all occupied key slots.
    ///
    /// # Returns
    ///
    /// A vector of slot numbers that contain keys.
    pub fn list(&self) -> Result<Vec<u32>> {
        let capacity = self.get_slot_count()? as usize;
        let mut slots = vec![0u32; capacity];
        let mut count = capacity;

        let result = unsafe {
            ffi::quac_key_list(
                self.device.handle(),
                slots.as_mut_ptr(),
                &mut count,
            )
        };

        check_error(result)?;
        slots.truncate(count);

        Ok(slots)
    }

    /// Get the total number of key slots.
    pub fn get_slot_count(&self) -> Result<u32> {
        let result = unsafe { ffi::quac_key_get_slot_count(self.device.handle()) };
        if result < 0 {
            check_error(result)?;
        }
        Ok(result as u32)
    }

    /// Find the first free slot.
    ///
    /// # Returns
    ///
    /// The slot number, or an error if no free slots.
    pub fn get_free_slot(&self) -> Result<u32> {
        let result = unsafe { ffi::quac_key_get_free_slot(self.device.handle()) };
        if result < 0 {
            return Err(QuacError::from_code(ErrorCode::KeyNotFound));
        }
        Ok(result as u32)
    }

    /// Clear all keys from the HSM.
    ///
    /// **WARNING**: This permanently deletes all stored keys!
    pub fn clear_all(&self) -> Result<()> {
        let result = unsafe { ffi::quac_key_clear_all(self.device.handle()) };
        check_error(result)
    }

    /// Check if a slot is occupied.
    pub fn is_slot_occupied(&self, slot: u32) -> Result<bool> {
        match self.get_info(slot) {
            Ok(_) => Ok(true),
            Err(QuacError::Native { code: ErrorCode::KeyNotFound, .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Store a key pair (public + secret).
    ///
    /// This is a convenience method that stores both keys in adjacent slots.
    ///
    /// # Arguments
    ///
    /// * `slot` - The base slot (public key goes here, secret at slot+1)
    /// * `algorithm` - Algorithm identifier
    /// * `label` - Label prefix
    /// * `public_key` - Public key bytes
    /// * `secret_key` - Secret key bytes
    pub fn store_keypair(
        &self,
        slot: u32,
        algorithm: i32,
        label: &str,
        public_key: &[u8],
        secret_key: &[u8],
    ) -> Result<()> {
        self.store(
            slot,
            KeyType::Public,
            algorithm,
            KeyUsage::VERIFY,
            &format!("{}-pub", label),
            public_key,
        )?;

        self.store(
            slot + 1,
            KeyType::Private,
            algorithm,
            KeyUsage::SIGN,
            &format!("{}-priv", label),
            secret_key,
        )?;

        Ok(())
    }
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keys").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_usage_flags() {
        let usage = KeyUsage::ENCRYPT | KeyUsage::DECRYPT;
        assert!(usage.contains(KeyUsage::ENCRYPT));
        assert!(usage.contains(KeyUsage::DECRYPT));
        assert!(!usage.contains(KeyUsage::SIGN));
    }
}
