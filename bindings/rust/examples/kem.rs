//! Key Encapsulation Mechanism (KEM) example.
//!
//! This example demonstrates ML-KEM key exchange between two parties.

use quantacore::{initialize, cleanup, open_first_device, KemAlgorithm};
use quantacore::utils::to_hex;

fn main() -> quantacore::Result<()> {
    println!("QUAC 100 SDK - ML-KEM Example");
    println!("==============================\n");

    // Initialize
    initialize()?;
    let device = open_first_device()?;
    let kem = device.kem();

    // Test all algorithm variants
    for algo in [
        KemAlgorithm::MlKem512,
        KemAlgorithm::MlKem768,
        KemAlgorithm::MlKem1024,
    ] {
        println!("Testing {}:", algo);
        println!("  Public key size: {} bytes", algo.public_key_size());
        println!("  Secret key size: {} bytes", algo.secret_key_size());
        println!("  Ciphertext size: {} bytes", algo.ciphertext_size());
        println!();

        // Alice generates a key pair
        println!("  Alice: Generating key pair...");
        let alice_keypair = kem.generate_keypair(algo)?;
        println!("    Public key: {}...", &to_hex(alice_keypair.public_key())[..32]);

        // Bob encapsulates using Alice's public key
        println!("  Bob: Encapsulating...");
        let (ciphertext, bob_secret) = kem.encapsulate(
            alice_keypair.public_key(),
            algo,
        )?;
        println!("    Ciphertext: {}...", &to_hex(&ciphertext)[..32]);
        println!("    Shared secret: {}", to_hex(&bob_secret));

        // Alice decapsulates using her secret key
        println!("  Alice: Decapsulating...");
        let alice_secret = kem.decapsulate(
            alice_keypair.secret_key(),
            &ciphertext,
            algo,
        )?;
        println!("    Shared secret: {}", to_hex(&alice_secret));

        // Verify they match
        assert_eq!(alice_secret, bob_secret);
        println!("  ✓ Shared secrets match!\n");
    }

    // Using convenience methods
    println!("Using convenience methods (ML-KEM-768):");
    let keypair = kem.generate_keypair_768()?;
    let (ct, sender_ss) = kem.encapsulate_768(keypair.public_key())?;
    let receiver_ss = kem.decapsulate_768(keypair.secret_key(), &ct)?;
    assert_eq!(sender_ss, receiver_ss);
    println!("  ✓ Key exchange successful!\n");

    // Cleanup
    drop(device);
    cleanup()?;

    println!("Done.");
    Ok(())
}