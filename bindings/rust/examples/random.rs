//! Quantum Random Number Generator (QRNG) example.
//!
//! This example demonstrates random number generation.

use quantacore::{initialize, cleanup, open_first_device};
use quantacore::utils::to_hex;

fn main() -> quantacore::Result<()> {
    println!("QUAC 100 SDK - QRNG Example");
    println!("============================\n");

    // Initialize
    initialize()?;
    let device = open_first_device()?;
    let random = device.random();

    // Check entropy status
    let status = random.get_entropy_status()?;
    println!("Entropy Status:");
    println!("  Level: {}%", status.level);
    println!("  Healthy: {}", status.is_healthy);
    println!("  Total Generated: {} bytes", status.total_generated);
    println!("  Generation Rate: {:.2} bytes/sec", status.generation_rate);
    println!();

    // Generate random bytes
    println!("Random Bytes:");
    println!("  16 bytes: {}", to_hex(&random.bytes(16)?));
    println!("  32 bytes: {}", to_hex(&random.bytes(32)?));
    println!();

    // Generate integers
    println!("Random Integers:");
    println!("  u8:  {}", random.next_u8()?);
    println!("  u16: {}", random.next_u16()?);
    println!("  u32: {}", random.next_u32()?);
    println!("  u64: {}", random.next_u64()?);
    println!("  i32: {}", random.next_i32()?);
    println!("  i64: {}", random.next_i64()?);
    println!();

    // Bounded integers
    println!("Bounded Integers:");
    println!("  u32 in [0, 100): {}", random.next_u32_bound(100)?);
    println!("  u64 in [0, 1000): {}", random.next_u64_bound(1000)?);
    println!("  randint(1, 6): {} (dice roll)", random.randint(1, 6)?);
    println!("  randint(1, 100): {}", random.randint(1, 100)?);
    println!();

    // Floating point
    println!("Floating Point:");
    println!("  f32 in [0, 1): {:.6}", random.next_f32()?);
    println!("  f64 in [0, 1): {:.15}", random.next_f64()?);
    println!("  uniform(0, 100): {:.6}", random.uniform(0.0, 100.0)?);
    println!();

    // Boolean
    println!("Boolean:");
    let mut true_count = 0;
    for _ in 0..1000 {
        if random.next_bool()? {
            true_count += 1;
        }
    }
    println!("  1000 random bools: {} true, {} false", true_count, 1000 - true_count);
    println!("  bool with p=0.7: {}", random.next_bool_with_probability(0.7)?);
    println!();

    // UUID
    println!("UUID v4:");
    println!("  {}", random.uuid()?);
    println!("  {}", random.uuid()?);
    println!("  {}", random.uuid()?);
    println!();

    // Selection operations
    let items = vec!["apple", "banana", "cherry", "date", "elderberry"];
    println!("Selection Operations:");
    println!("  Items: {:?}", items);
    println!("  Random choice: {:?}", random.choice(&items)?);
    println!("  Sample(3): {:?}", random.sample(&items, 3)?);
    println!("  Shuffled: {:?}", random.shuffled(&items)?);
    println!();

    // Shuffle in place
    let mut numbers: Vec<i32> = (1..=10).collect();
    println!("Shuffle in place:");
    println!("  Before: {:?}", numbers);
    random.shuffle(&mut numbers)?;
    println!("  After:  {:?}", numbers);
    println!();

    // Cleanup
    drop(device);
    cleanup()?;

    println!("Done.");
    Ok(())
}