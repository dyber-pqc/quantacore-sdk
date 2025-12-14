//! QUAC 100 device management.
//!
//! This module provides the `Device` struct which represents an open
//! connection to a QUAC 100 hardware device.

use crate::error::{check_error, Result};
use crate::ffi;
use crate::hash::Hash;
use crate::kem::Kem;
use crate::keys::Keys;
use crate::random::Random;
use crate::sign::Sign;

use std::ffi::CStr;
use std::sync::Arc;

/// Device information.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    /// Device index
    pub index: u32,
    /// Device model name
    pub model: String,
    /// Serial number
    pub serial_number: String,
    /// Firmware version
    pub firmware_version: String,
    /// Driver version
    pub driver_version: String,
    /// Number of key slots
    pub key_slots: u32,
    /// Maximum key size
    pub max_key_size: u32,
    /// Feature flags
    pub features: u32,
}

impl DeviceInfo {
    /// Create from FFI structure.
    pub(crate) fn from_ffi(info: &ffi::quac_device_info_t) -> Self {
        Self {
            index: info.index,
            model: c_array_to_string(&info.model),
            serial_number: c_array_to_string(&info.serial_number),
            firmware_version: c_array_to_string(&info.firmware_version),
            driver_version: c_array_to_string(&info.driver_version),
            key_slots: info.key_slots,
            max_key_size: info.max_key_size,
            features: info.features,
        }
    }
}

/// Device status.
#[derive(Debug, Clone)]
pub struct DeviceStatus {
    /// Temperature in Celsius
    pub temperature: i32,
    /// Entropy pool level (0-100)
    pub entropy_level: u32,
    /// Total operations performed
    pub operation_count: u64,
    /// Total errors encountered
    pub error_count: u64,
    /// Uptime in seconds
    pub uptime_seconds: u64,
    /// Status flags
    pub flags: u32,
}

impl DeviceStatus {
    /// Check if the device is healthy.
    pub fn is_healthy(&self) -> bool {
        // Check temperature range (-10 to 85°C for typical FPGA)
        let temp_ok = (-10..=85).contains(&self.temperature);
        // Check entropy level
        let entropy_ok = self.entropy_level >= 10;
        // Check no critical flags
        let flags_ok = (self.flags & 0x80000000) == 0; // MSB = critical error

        temp_ok && entropy_ok && flags_ok
    }

    pub(crate) fn from_ffi(status: &ffi::quac_device_status_t) -> Self {
        Self {
            temperature: status.temperature,
            entropy_level: status.entropy_level,
            operation_count: status.operation_count,
            error_count: status.error_count,
            uptime_seconds: status.uptime_seconds,
            flags: status.flags,
        }
    }
}

/// Inner device state (shared via Arc).
struct DeviceInner {
    handle: ffi::quac_device_t,
    index: u32,
}

impl Drop for DeviceInner {
    fn drop(&mut self) {
        unsafe {
            ffi::quac_close_device(self.handle);
        }
    }
}

// Safety: The device handle is thread-safe per the native library spec
unsafe impl Send for DeviceInner {}
unsafe impl Sync for DeviceInner {}

/// Handle to an open QUAC 100 device.
///
/// This struct provides access to all device functionality including
/// KEM, signatures, hashing, random number generation, and key storage.
///
/// The device is automatically closed when this struct is dropped.
///
/// # Thread Safety
///
/// `Device` is `Send` and `Sync`, allowing it to be shared across threads.
/// The underlying hardware operations are serialized by the device.
///
/// # Example
///
/// ```no_run
/// use quantacore::{initialize, open_first_device};
///
/// initialize().unwrap();
/// let device = open_first_device().unwrap();
///
/// let info = device.get_info().unwrap();
/// println!("Connected to: {}", info.model);
///
/// // Access subsystems
/// let kem = device.kem();
/// let sign = device.sign();
/// let hash = device.hash();
/// let random = device.random();
/// ```
#[derive(Clone)]
pub struct Device {
    inner: Arc<DeviceInner>,
}

impl Device {
    /// Create a Device from a raw FFI handle.
    pub(crate) fn from_raw(handle: ffi::quac_device_t, index: u32) -> Self {
        Self {
            inner: Arc::new(DeviceInner { handle, index }),
        }
    }

    /// Get the raw FFI handle.
    pub(crate) fn handle(&self) -> ffi::quac_device_t {
        self.inner.handle
    }

    /// Get device index.
    pub fn index(&self) -> u32 {
        self.inner.index
    }

    /// Get device information.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use quantacore::{initialize, open_first_device};
    /// # initialize().unwrap();
    /// let device = open_first_device().unwrap();
    /// let info = device.get_info().unwrap();
    /// println!("Model: {}", info.model);
    /// println!("Serial: {}", info.serial_number);
    /// println!("Firmware: {}", info.firmware_version);
    /// ```
    pub fn get_info(&self) -> Result<DeviceInfo> {
        let mut info = ffi::quac_device_info_t::default();
        let result = unsafe { ffi::quac_get_device_info(self.inner.index, &mut info) };
        check_error(result)?;
        Ok(DeviceInfo::from_ffi(&info))
    }

    /// Get device status.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use quantacore::{initialize, open_first_device};
    /// # initialize().unwrap();
    /// let device = open_first_device().unwrap();
    /// let status = device.get_status().unwrap();
    /// println!("Temperature: {}°C", status.temperature);
    /// println!("Entropy: {}%", status.entropy_level);
    /// println!("Healthy: {}", status.is_healthy());
    /// ```
    pub fn get_status(&self) -> Result<DeviceStatus> {
        let mut status = ffi::quac_device_status_t::default();
        let result = unsafe { ffi::quac_device_get_status(self.inner.handle, &mut status) };
        check_error(result)?;
        Ok(DeviceStatus::from_ffi(&status))
    }

    /// Run device self-test.
    ///
    /// This performs a comprehensive self-test of the device hardware
    /// and cryptographic implementations.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use quantacore::{initialize, open_first_device};
    /// # initialize().unwrap();
    /// let device = open_first_device().unwrap();
    /// device.self_test().expect("Self-test failed");
    /// println!("Device self-test passed");
    /// ```
    pub fn self_test(&self) -> Result<()> {
        let result = unsafe { ffi::quac_device_self_test(self.inner.handle) };
        check_error(result)
    }

    /// Reset the device.
    ///
    /// This performs a soft reset of the device. All ongoing operations
    /// will be cancelled.
    pub fn reset(&self) -> Result<()> {
        let result = unsafe { ffi::quac_device_reset(self.inner.handle) };
        check_error(result)
    }

    /// Get the KEM (Key Encapsulation Mechanism) subsystem.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use quantacore::{initialize, open_first_device, KemAlgorithm};
    /// # initialize().unwrap();
    /// let device = open_first_device().unwrap();
    /// let kem = device.kem();
    /// let keypair = kem.generate_keypair(KemAlgorithm::MlKem768).unwrap();
    /// ```
    pub fn kem(&self) -> Kem {
        Kem::new(self.clone())
    }

    /// Get the signature subsystem.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use quantacore::{initialize, open_first_device, SignAlgorithm};
    /// # initialize().unwrap();
    /// let device = open_first_device().unwrap();
    /// let sign = device.sign();
    /// let keypair = sign.generate_keypair(SignAlgorithm::MlDsa65).unwrap();
    /// ```
    pub fn sign(&self) -> Sign {
        Sign::new(self.clone())
    }

    /// Get the hash subsystem.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use quantacore::{initialize, open_first_device};
    /// # initialize().unwrap();
    /// let device = open_first_device().unwrap();
    /// let hash = device.hash();
    /// let digest = hash.sha256(b"Hello, World!").unwrap();
    /// ```
    pub fn hash(&self) -> Hash {
        Hash::new(self.clone())
    }

    /// Get the random number generator subsystem.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use quantacore::{initialize, open_first_device};
    /// # initialize().unwrap();
    /// let device = open_first_device().unwrap();
    /// let random = device.random();
    /// let bytes = random.bytes(32).unwrap();
    /// ```
    pub fn random(&self) -> Random {
        Random::new(self.clone())
    }

    /// Get the key storage (HSM) subsystem.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use quantacore::{initialize, open_first_device};
    /// # initialize().unwrap();
    /// let device = open_first_device().unwrap();
    /// let keys = device.keys();
    /// let slots = keys.list().unwrap();
    /// ```
    pub fn keys(&self) -> Keys {
        Keys::new(self.clone())
    }

    /// Close the device explicitly.
    ///
    /// This is optional; the device will be closed automatically when dropped.
    pub fn close(self) {
        drop(self);
    }
}

impl std::fmt::Debug for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Device")
            .field("index", &self.inner.index)
            .finish()
    }
}

/// Convert a C char array to a Rust String.
fn c_array_to_string(arr: &[std::os::raw::c_char]) -> String {
    unsafe {
        CStr::from_ptr(arr.as_ptr())
            .to_string_lossy()
            .into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_status_is_healthy() {
        let status = DeviceStatus {
            temperature: 45,
            entropy_level: 80,
            operation_count: 1000,
            error_count: 0,
            uptime_seconds: 3600,
            flags: 0,
        };
        assert!(status.is_healthy());

        let hot_status = DeviceStatus {
            temperature: 100,
            ..status.clone()
        };
        assert!(!hot_status.is_healthy());

        let low_entropy = DeviceStatus {
            entropy_level: 5,
            ..status
        };
        assert!(!low_entropy.is_healthy());
    }
}