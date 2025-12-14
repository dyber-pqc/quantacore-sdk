//! Quantum Random Number Generation (QRNG).
//!
//! This module provides access to the hardware quantum random number generator.

use crate::device::Device;
use crate::error::{check_error, Result};
use crate::ffi;

/// Entropy pool status.
#[derive(Debug, Clone)]
pub struct EntropyStatus {
    /// Current entropy level (0-100%)
    pub level: u32,
    /// Whether the entropy source is healthy
    pub is_healthy: bool,
    /// Total bytes generated
    pub total_generated: u64,
    /// Current generation rate (bytes/second)
    pub generation_rate: f64,
}

impl EntropyStatus {
    pub(crate) fn from_ffi(status: &ffi::quac_entropy_status_t) -> Self {
        Self {
            level: status.level,
            is_healthy: status.is_healthy != 0,
            total_generated: status.total_generated,
            generation_rate: status.generation_rate,
        }
    }
}

/// Random number generator subsystem.
///
/// Provides access to the hardware Quantum Random Number Generator (QRNG)
/// for generating cryptographically secure random data.
///
/// # Example
///
/// ```no_run
/// use quantacore::{initialize, open_first_device};
///
/// initialize().unwrap();
/// let device = open_first_device().unwrap();
/// let random = device.random();
///
/// // Generate random bytes
/// let bytes = random.bytes(32).unwrap();
/// println!("Random: {}", hex::encode(&bytes));
///
/// // Generate random integer
/// let value = random.next_u64().unwrap();
///
/// // Generate random float in [0, 1)
/// let f = random.next_f64().unwrap();
///
/// // Check entropy status
/// let status = random.get_entropy_status().unwrap();
/// println!("Entropy level: {}%", status.level);
/// ```
#[derive(Clone)]
pub struct Random {
    device: Device,
}

impl Random {
    /// Create a new random subsystem handle.
    pub(crate) fn new(device: Device) -> Self {
        Self { device }
    }

    /// Get the current entropy status.
    pub fn get_entropy_status(&self) -> Result<EntropyStatus> {
        let mut status = ffi::quac_entropy_status_t::default();
        let result = unsafe { ffi::quac_get_entropy_status(self.device.handle(), &mut status) };
        check_error(result)?;
        Ok(EntropyStatus::from_ffi(&status))
    }

    /// Generate random bytes.
    ///
    /// # Arguments
    ///
    /// * `length` - Number of bytes to generate
    ///
    /// # Returns
    ///
    /// A vector of random bytes.
    pub fn bytes(&self, length: usize) -> Result<Vec<u8>> {
        let mut buffer = vec![0u8; length];
        self.fill(&mut buffer)?;
        Ok(buffer)
    }

    /// Fill a buffer with random bytes.
    ///
    /// # Arguments
    ///
    /// * `buffer` - The buffer to fill
    pub fn fill(&self, buffer: &mut [u8]) -> Result<()> {
        let result = unsafe {
            ffi::quac_random_bytes(self.device.handle(), buffer.as_mut_ptr(), buffer.len())
        };
        check_error(result)
    }

    /// Generate a random u8.
    pub fn next_u8(&self) -> Result<u8> {
        let mut buf = [0u8; 1];
        self.fill(&mut buf)?;
        Ok(buf[0])
    }

    /// Generate a random u16.
    pub fn next_u16(&self) -> Result<u16> {
        let mut buf = [0u8; 2];
        self.fill(&mut buf)?;
        Ok(u16::from_le_bytes(buf))
    }

    /// Generate a random u32.
    pub fn next_u32(&self) -> Result<u32> {
        let mut buf = [0u8; 4];
        self.fill(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    /// Generate a random u64.
    pub fn next_u64(&self) -> Result<u64> {
        let mut buf = [0u8; 8];
        self.fill(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    /// Generate a random i32.
    pub fn next_i32(&self) -> Result<i32> {
        let mut buf = [0u8; 4];
        self.fill(&mut buf)?;
        Ok(i32::from_le_bytes(buf))
    }

    /// Generate a random i64.
    pub fn next_i64(&self) -> Result<i64> {
        let mut buf = [0u8; 8];
        self.fill(&mut buf)?;
        Ok(i64::from_le_bytes(buf))
    }

    /// Generate a random u32 in range [0, bound).
    ///
    /// Uses rejection sampling to ensure uniform distribution.
    pub fn next_u32_bound(&self, bound: u32) -> Result<u32> {
        if bound == 0 {
            return Ok(0);
        }
        if bound.is_power_of_two() {
            return Ok(self.next_u32()? & (bound - 1));
        }

        let threshold = bound.wrapping_neg() % bound;
        loop {
            let r = self.next_u32()?;
            if r >= threshold {
                return Ok(r % bound);
            }
        }
    }

    /// Generate a random u64 in range [0, bound).
    pub fn next_u64_bound(&self, bound: u64) -> Result<u64> {
        if bound == 0 {
            return Ok(0);
        }
        if bound.is_power_of_two() {
            return Ok(self.next_u64()? & (bound - 1));
        }

        let threshold = bound.wrapping_neg() % bound;
        loop {
            let r = self.next_u64()?;
            if r >= threshold {
                return Ok(r % bound);
            }
        }
    }

    /// Generate a random integer in range [min, max].
    pub fn randint(&self, min: i64, max: i64) -> Result<i64> {
        if min > max {
            return Ok(min);
        }
        let range = (max - min) as u64 + 1;
        let r = self.next_u64_bound(range)?;
        Ok(min + r as i64)
    }

    /// Generate a random f32 in range [0.0, 1.0).
    pub fn next_f32(&self) -> Result<f32> {
        // Use 24 bits for f32 mantissa
        let r = self.next_u32()? >> 8;
        Ok(r as f32 / (1u32 << 24) as f32)
    }

    /// Generate a random f64 in range [0.0, 1.0).
    pub fn next_f64(&self) -> Result<f64> {
        // Use 53 bits for f64 mantissa
        let r = self.next_u64()? >> 11;
        Ok(r as f64 / (1u64 << 53) as f64)
    }

    /// Generate a random f64 in range [min, max).
    pub fn uniform(&self, min: f64, max: f64) -> Result<f64> {
        let r = self.next_f64()?;
        Ok(min + (max - min) * r)
    }

    /// Generate a random boolean.
    pub fn next_bool(&self) -> Result<bool> {
        Ok((self.next_u8()? & 1) != 0)
    }

    /// Generate a random boolean with given probability of being true.
    pub fn next_bool_with_probability(&self, p: f64) -> Result<bool> {
        Ok(self.next_f64()? < p)
    }

    /// Generate a UUID v4 string.
    ///
    /// Returns a string in the format `xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx`
    /// where x is any hexadecimal digit and y is one of 8, 9, a, or b.
    pub fn uuid(&self) -> Result<String> {
        let mut bytes = [0u8; 16];
        self.fill(&mut bytes)?;

        // Set version to 4
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        // Set variant to 10xx
        bytes[8] = (bytes[8] & 0x3f) | 0x80;

        Ok(format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5],
            bytes[6], bytes[7],
            bytes[8], bytes[9],
            bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
        ))
    }

    /// Select a random element from a slice.
    pub fn choice<'a, T>(&self, items: &'a [T]) -> Result<Option<&'a T>> {
        if items.is_empty() {
            return Ok(None);
        }
        let idx = self.next_u64_bound(items.len() as u64)? as usize;
        Ok(Some(&items[idx]))
    }

    /// Sample n unique elements from a slice without replacement.
    pub fn sample<T: Clone>(&self, items: &[T], n: usize) -> Result<Vec<T>> {
        if n >= items.len() {
            return Ok(items.to_vec());
        }

        let mut pool: Vec<usize> = (0..items.len()).collect();
        let mut result = Vec::with_capacity(n);

        for _ in 0..n {
            let idx = self.next_u64_bound(pool.len() as u64)? as usize;
            result.push(items[pool[idx]].clone());
            pool.swap_remove(idx);
        }

        Ok(result)
    }

    /// Shuffle a slice in place using Fisher-Yates algorithm.
    pub fn shuffle<T>(&self, items: &mut [T]) -> Result<()> {
        for i in (1..items.len()).rev() {
            let j = self.next_u64_bound((i + 1) as u64)? as usize;
            items.swap(i, j);
        }
        Ok(())
    }

    /// Return a shuffled copy of a slice.
    pub fn shuffled<T: Clone>(&self, items: &[T]) -> Result<Vec<T>> {
        let mut result = items.to_vec();
        self.shuffle(&mut result)?;
        Ok(result)
    }
}

impl std::fmt::Debug for Random {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Random").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_status() {
        let status = EntropyStatus {
            level: 80,
            is_healthy: true,
            total_generated: 1000000,
            generation_rate: 1000.0,
        };
        assert!(status.is_healthy);
        assert_eq!(status.level, 80);
    }
}