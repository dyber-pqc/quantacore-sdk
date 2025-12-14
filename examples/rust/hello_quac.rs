//! QUAC 100 Hello World Example (Rust)
//!
//! Basic example demonstrating device initialization and random generation.
//!
//! Run: cargo run --example hello_quac
//!
//! Copyright 2025 Dyber, Inc. All Rights Reserved.

use rand::RngCore;
use zeroize::Zeroize;

// =============================================================================
// Simulated QUAC Types (would be imported from quac100 crate)
// =============================================================================

#[derive(Debug, Clone, Copy)]
pub enum Algorithm {
    MlKem512,
    MlKem768,
    MlKem1024,
}

#[derive(Debug)]
pub struct DeviceInfo {
    pub name: String,
    pub serial: String,
    pub firmware: String,
}

pub struct Device {
    info: DeviceInfo,
    _is_simulator: bool,
}

impl Device {
    pub fn get_info(&self) -> &DeviceInfo {
        &self.info
    }

    pub fn random(&self, length: usize) -> Vec<u8> {
        let mut buf = vec![0u8; length];
        rand::thread_rng().fill_bytes(&mut buf);
        buf
    }

    pub fn kem_keygen(&self, algorithm: Algorithm) -> (Vec<u8>, Vec<u8>) {
        let (pk_size, sk_size) = match algorithm {
            Algorithm::MlKem512 => (800, 1632),
            Algorithm::MlKem768 => (1184, 2400),
            Algorithm::MlKem1024 => (1568, 3168),
        };

        let mut pk = vec![0u8; pk_size];
        let mut sk = vec![0u8; sk_size];
        rand::thread_rng().fill_bytes(&mut pk);
        rand::thread_rng().fill_bytes(&mut sk);
        (pk, sk)
    }
}

pub struct Context;

impl Context {
    pub fn new() -> Result<Self, &'static str> {
        Ok(Context)
    }

    pub fn get_device_count(&self) -> usize {
        1 // Simulator always available
    }

    pub fn open_device(&self, _index: usize) -> Result<Device, &'static str> {
        Err("No hardware available")
    }

    pub fn open_simulator(&self) -> Result<Device, &'static str> {
        Ok(Device {
            info: DeviceInfo {
                name: "QUAC 100 Simulator".to_string(),
                serial: "SIM-00000000".to_string(),
                firmware: "1.0.0-sim".to_string(),
            },
            _is_simulator: true,
        })
    }
}

// =============================================================================
// Main
// =============================================================================

fn main() {
    println!("==============================================");
    println!("  QUAC 100 Hello World Example (Rust)");
    println!("==============================================");
    println!();

    // Step 1: Initialize SDK
    println!("1. Initializing QUAC SDK...");
    let ctx = Context::new().expect("Failed to initialize SDK");
    println!("   SDK initialized successfully.");
    println!();

    // Step 2: Query devices
    println!("2. Querying devices...");
    let count = ctx.get_device_count();
    println!("   Found {} device(s)", count);
    println!();

    // Step 3: Open device
    println!("3. Opening device...");
    let device = match ctx.open_device(0) {
        Ok(d) => d,
        Err(_) => {
            println!("   No hardware found, using simulator...");
            ctx.open_simulator().expect("Failed to open simulator")
        }
    };
    println!("   Device opened successfully.");
    println!();

    // Step 4: Get device info
    println!("4. Device Information:");
    let info = device.get_info();
    println!("   Name:     {}", info.name);
    println!("   Serial:   {}", info.serial);
    println!("   Firmware: {}", info.firmware);
    println!();

    // Step 5: Generate random bytes
    println!("5. Generating random bytes with QRNG...");
    let random_bytes = device.random(32);
    println!("   Random: {}", hex::encode(&random_bytes));
    println!();

    // Step 6: Quick ML-KEM-768 demo
    println!("6. Quick ML-KEM-768 demonstration...");
    let (pk, mut sk) = device.kem_keygen(Algorithm::MlKem768);
    println!("   Public key:  {} bytes", pk.len());
    println!("   Secret key:  {} bytes", sk.len());
    println!("   PK (first 16 bytes): {}...", hex::encode(&pk[..16]));

    // Secure cleanup
    sk.zeroize();
    println!();

    // Step 7: Cleanup
    println!("7. Cleaning up...");
    println!("   Done!");
    println!();

    println!("==============================================");
    println!("  Hello World Complete!");
    println!("==============================================");
}