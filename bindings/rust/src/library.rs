//! Library initialization and management.
//!
//! This module provides functions to initialize and clean up the library,
//! enumerate devices, and open device handles.

use crate::device::{Device, DeviceInfo};
use crate::error::{check_error, QuacError, Result};
use crate::ffi;
use crate::types::InitFlags;

use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use std::ffi::CStr;
use std::sync::atomic::{AtomicBool, Ordering};

/// Global initialization state
static INITIALIZED: AtomicBool = AtomicBool::new(false);
static INIT_LOCK: OnceCell<Mutex<()>> = OnceCell::new();

fn init_lock() -> &'static Mutex<()> {
    INIT_LOCK.get_or_init(|| Mutex::new(()))
}

/// Initialize the QUAC 100 library with default flags.
///
/// This must be called before any other library functions.
/// The library can only be initialized once.
pub fn initialize() -> Result<()> {
    initialize_with_flags(InitFlags::DEFAULT)
}

/// Initialize the QUAC 100 library with custom flags.
pub fn initialize_with_flags(flags: InitFlags) -> Result<()> {
    let _guard = init_lock().lock();

    if INITIALIZED.load(Ordering::SeqCst) {
        return Ok(()); // Already initialized
    }

    let result = unsafe { ffi::quac_init(flags.bits()) };
    check_error(result)?;

    INITIALIZED.store(true, Ordering::SeqCst);
    Ok(())
}

/// Clean up the QUAC 100 library.
pub fn cleanup() -> Result<()> {
    let _guard = init_lock().lock();

    if !INITIALIZED.load(Ordering::SeqCst) {
        return Ok(()); // Not initialized
    }

    let result = unsafe { ffi::quac_cleanup() };
    check_error(result)?;

    INITIALIZED.store(false, Ordering::SeqCst);
    Ok(())
}

/// Check if the library is initialized.
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::SeqCst)
}

/// Get the library version string.
pub fn get_version() -> String {
    unsafe {
        let ptr = ffi::quac_get_version();
        if ptr.is_null() {
            return String::from("unknown");
        }
        CStr::from_ptr(ptr)
            .to_string_lossy()
            .into_owned()
    }
}

/// Get the library build information.
pub fn get_build_info() -> String {
    unsafe {
        let ptr = ffi::quac_get_build_info();
        if ptr.is_null() {
            return String::from("unknown");
        }
        CStr::from_ptr(ptr)
            .to_string_lossy()
            .into_owned()
    }
}

/// Get the number of available QUAC 100 devices.
pub fn get_device_count() -> usize {
    let count = unsafe { ffi::quac_get_device_count() };
    if count < 0 {
        0
    } else {
        count as usize
    }
}

/// Enumerate all available QUAC 100 devices.
pub fn enumerate_devices() -> Vec<DeviceInfo> {
    let count = get_device_count();
    let mut devices = Vec::with_capacity(count);

    for i in 0..count {
        if let Ok(info) = get_device_info(i as u32) {
            devices.push(info);
        }
    }

    devices
}

/// Get information about a specific device.
fn get_device_info(index: u32) -> Result<DeviceInfo> {
    let mut info = ffi::quac_device_info_t::default();
    let result = unsafe { ffi::quac_get_device_info(index, &mut info) };
    check_error(result)?;
    Ok(DeviceInfo::from_ffi(&info))
}

/// Open a QUAC 100 device by index.
pub fn open_device(index: u32) -> Result<Device> {
    if !is_initialized() {
        return Err(QuacError::NotInitialized);
    }

    let mut handle = std::ptr::null_mut();
    let result = unsafe { ffi::quac_open_device(index, &mut handle) };
    check_error(result)?;

    if handle.is_null() {
        return Err(QuacError::NullPointer);
    }

    Ok(Device::from_raw(handle, index))
}

/// Open the first available QUAC 100 device.
pub fn open_first_device() -> Result<Device> {
    if get_device_count() == 0 {
        return Err(QuacError::DeviceNotFound("No QUAC 100 devices found".into()));
    }
    open_device(0)
}

/// RAII guard for library initialization.
pub struct LibraryContext {
    _private: (),
}

impl LibraryContext {
    /// Create a new library context with default flags.
    pub fn new() -> Result<Self> {
        initialize()?;
        Ok(Self { _private: () })
    }

    /// Create a new library context with custom flags.
    pub fn with_flags(flags: InitFlags) -> Result<Self> {
        initialize_with_flags(flags)?;
        Ok(Self { _private: () })
    }
}

impl Drop for LibraryContext {
    fn drop(&mut self) {
        let _ = cleanup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_version() {
        let version = get_version();
        assert!(!version.is_empty());
    }
}