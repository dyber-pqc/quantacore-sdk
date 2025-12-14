//! Hash operations example.
//!
//! This example demonstrates SHA-2, SHA-3, HMAC, and HKDF.

use quantacore::{initialize, cleanup, open_first_device, HashAlgorithm};
use quantacore::utils::to_hex;

fn main() -> quantacore::Result<()> {
    println!("QUAC 100 SDK - Hash Example");
    println!("============================\n");

    // Initialize
    initialize()?;
    let device = open_first_device()?;
    let hash = device.hash();

    let data = b"Hello, World!";
    println!("Input data: {:?}\n", std::str::from_utf8(data).unwrap());

    // SHA-2 family
    println!("SHA-2 Family:");
    println!("  SHA-256: {}", to_hex(&hash.sha256(data)?));
    println!("  SHA-384: {}", to_hex(&hash.sha384(data)?));
    println!("  SHA-512: {}", to_hex(&hash.sha512(data)?));
    println!();

    // SHA-3 family
    println!("SHA-3 Family:");
    println!("  SHA3-256: {}", to_hex(&hash.sha3_256(data)?));
    println!("  SHA3-384: {}", to_hex(&hash.sha3_384(data)?));
    println!("  SHA3-512: {}", to_hex(&hash.sha3_512(data)?));
    println!();

    // SHAKE (extendable output)
    println!("SHAKE (XOF):");
    println!("  SHAKE128 (32 bytes): {}", to_hex(&hash.shake128(data, 32)?));
    println!("  SHAKE128 (64 bytes): {}", to_hex(&hash.shake128(data, 64)?));
    println!("  SHAKE256 (32 bytes): {}", to_hex(&hash.shake256(data, 32)?));
    println!();

    // Incremental hashing
    println!("Incremental Hashing:");
    let mut ctx = hash.create_context(HashAlgorithm::Sha256)?;
    ctx.update(b"Hello, ")?;
    ctx.update(b"World!")?;
    let incremental = ctx.finalize()?;
    let oneshot = hash.sha256(b"Hello, World!")?;
    assert_eq!(incremental, oneshot);
    println!("  Incremental SHA-256: {}", to_hex(&incremental));
    println!("  ✓ Matches one-shot hash\n");

    // HMAC
    println!("HMAC:");
    let key = b"secret key";
    let message = b"message to authenticate";
    println!("  Key: {:?}", std::str::from_utf8(key).unwrap());
    println!("  Message: {:?}", std::str::from_utf8(message).unwrap());
    println!("  HMAC-SHA256: {}", to_hex(&hash.hmac_sha256(key, message)?));
    println!("  HMAC-SHA384: {}", to_hex(&hash.hmac_sha384(key, message)?));
    println!("  HMAC-SHA512: {}", to_hex(&hash.hmac_sha512(key, message)?));
    println!();

    // HKDF
    println!("HKDF Key Derivation:");
    let ikm = b"input keying material";
    let salt = b"random salt";
    let info = b"application context";
    
    println!("  IKM: {:?}", std::str::from_utf8(ikm).unwrap());
    println!("  Salt: {:?}", std::str::from_utf8(salt).unwrap());
    println!("  Info: {:?}", std::str::from_utf8(info).unwrap());
    
    let derived_32 = hash.hkdf_sha256(ikm, salt, info, 32)?;
    let derived_64 = hash.hkdf_sha256(ikm, salt, info, 64)?;
    
    println!("  Derived (32 bytes): {}", to_hex(&derived_32));
    println!("  Derived (64 bytes): {}", to_hex(&derived_64));
    println!();

    // Cleanup
    drop(device);
    cleanup()?;

    println!("Done.");
    Ok(())
}