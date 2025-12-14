//! Digital Signature example.
//!
//! This example demonstrates ML-DSA digital signatures.

use quantacore::{initialize, cleanup, open_first_device, SignAlgorithm};
use quantacore::utils::to_hex;

fn main() -> quantacore::Result<()> {
    println!("QUAC 100 SDK - ML-DSA Signature Example");
    println!("========================================\n");

    // Initialize
    initialize()?;
    let device = open_first_device()?;
    let sign = device.sign();

    // Message to sign
    let message = b"Hello, quantum-safe world!";
    println!("Message: {:?}\n", std::str::from_utf8(message).unwrap());

    // Test all algorithm variants
    for algo in [
        SignAlgorithm::MlDsa44,
        SignAlgorithm::MlDsa65,
        SignAlgorithm::MlDsa87,
    ] {
        println!("Testing {}:", algo);
        println!("  Public key size: {} bytes", algo.public_key_size());
        println!("  Secret key size: {} bytes", algo.secret_key_size());
        println!("  Signature size: {} bytes", algo.signature_size());
        println!();

        // Generate key pair
        println!("  Generating key pair...");
        let keypair = sign.generate_keypair(algo)?;
        println!("    Public key: {}...", &to_hex(keypair.public_key())[..32]);

        // Sign the message
        println!("  Signing message...");
        let signature = sign.sign(keypair.secret_key(), message, algo)?;
        println!("    Signature: {}...", &to_hex(&signature)[..32]);
        println!("    Signature size: {} bytes", signature.len());

        // Verify the signature
        println!("  Verifying signature...");
        let valid = sign.verify(keypair.public_key(), message, &signature, algo)?;
        assert!(valid);
        println!("    ✓ Signature valid!\n");

        // Test with wrong message
        let wrong_message = b"Tampered message!";
        let invalid = sign.verify(keypair.public_key(), wrong_message, &signature, algo)?;
        assert!(!invalid);
        println!("    ✓ Correctly rejected tampered message\n");
    }

    // Using convenience methods
    println!("Using convenience methods (ML-DSA-65):");
    let keypair = sign.generate_keypair_65()?;
    let sig = sign.sign_65(keypair.secret_key(), message)?;
    let valid = sign.verify_65(keypair.public_key(), message, &sig)?;
    assert!(valid);
    println!("  ✓ Signature verification successful!\n");

    // Using verify_or_error
    println!("Using verify_or_error:");
    sign.verify_or_error(keypair.public_key(), message, &sig, SignAlgorithm::MlDsa65)?;
    println!("  ✓ No error thrown - signature valid\n");

    // Cleanup
    drop(device);
    cleanup()?;

    println!("Done.");
    Ok(())
}