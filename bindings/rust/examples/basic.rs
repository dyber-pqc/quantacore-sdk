//! Basic usage example for QUAC 100 SDK.
//!
//! This example demonstrates library initialization, device enumeration,
//! and basic operations.

use quantacore::{
    initialize, cleanup, get_version, get_device_count,
    enumerate_devices, open_first_device,
};

fn main() -> quantacore::Result<()> {
    println!("QUAC 100 SDK Basic Example");
    println!("==========================\n");

    // Print version
    println!("SDK Version: {}", get_version());
    println!();

    // Initialize the library
    println!("Initializing library...");
    initialize()?;
    println!("Library initialized successfully.\n");

    // Enumerate devices
    let device_count = get_device_count();
    println!("Found {} QUAC 100 device(s).\n", device_count);

    if device_count == 0 {
        println!("No devices found. Please ensure a QUAC 100 is connected.");
        cleanup()?;
        return Ok(());
    }

    // List all devices
    for device_info in enumerate_devices() {
        println!("Device {}:", device_info.index);
        println!("  Model: {}", device_info.model);
        println!("  Serial: {}", device_info.serial_number);
        println!("  Firmware: {}", device_info.firmware_version);
        println!("  Key Slots: {}", device_info.key_slots);
        println!();
    }

    // Open the first device
    println!("Opening first device...");
    let device = open_first_device()?;
    println!("Device opened successfully.\n");

    // Get device status
    let status = device.get_status()?;
    println!("Device Status:");
    println!("  Temperature: {}°C", status.temperature);
    println!("  Entropy Level: {}%", status.entropy_level);
    println!("  Operations: {}", status.operation_count);
    println!("  Uptime: {} seconds", status.uptime_seconds);
    println!("  Healthy: {}", status.is_healthy());
    println!();

    // Run self-test
    println!("Running self-test...");
    device.self_test()?;
    println!("Self-test passed.\n");

    // Close device and cleanup
    drop(device);
    cleanup()?;
    println!("Cleanup complete.");

    Ok(())
}