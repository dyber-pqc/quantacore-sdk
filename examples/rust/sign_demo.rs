//! QUAC 100 ML-DSA (Dilithium) Digital Signature Demo (Rust)
//!
//! Demonstrates complete digital signature workflow:
//! - Key generation
//! - Message signing
//! - Signature verification
//! - Tamper detection
//!
//! Run: cargo run --example sign_demo -- [44|65|87]
//!
//! Copyright 2025 Dyber, Inc. All Rights Reserved.

use std::collections::HashMap;
use std::env;

// Simulated types
struct SignParams {
    name: &'static str,
    security: &'static str,
    pk_size: usize,
    sk_size: usize,
    sig_size: usize,
}

impl SignParams {
    fn get(level: u32) -> Self {
        match level {
            44 => SignParams {
                name: "ML-DSA-44",
                security: "NIST Level 2 (128-bit)",
                pk_size: 1312,
                sk_size: 2560,
                sig_size: 2420,
            },
            65 => SignParams {
                name: "ML-DSA-65",
                security: "NIST Level 3 (192-bit)",
                pk_size: 1952,
                sk_size: 4032,
                sig_size: 3309,
            },
            87 => SignParams {
                name: "ML-DSA-87",
                security: "NIST Level 5 (256-bit)",
                pk_size: 2592,
                sk_size: 4896,
                sig_size: 4627,
            },
            _ => Self::get(65),
        }
    }
}

/// Simple hash function for simulation
fn simple_hash(data: &[u8]) -> [u8; 32] {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut result = [0u8; 32];
    for (i, chunk) in data.chunks(8).enumerate() {
        let mut hasher = DefaultHasher::new();
        chunk.hash(&mut hasher);
        i.hash(&mut hasher);
        let h = hasher.finish();
        for j in 0..8 {
            if i * 8 + j < 32 {
                result[i * 8 + j] ^= ((h >> (j * 8)) & 0xFF) as u8;
            }
        }
    }
    result
}

/// Simulated signature scheme
struct SimulatedSign {
    params: SignParams,
    keypairs: HashMap<Vec<u8>, Vec<u8>>, // pk -> sk
}

impl SimulatedSign {
    fn new(params: SignParams) -> Self {
        Self {
            params,
            keypairs: HashMap::new(),
        }
    }

    fn keygen(&mut self) -> (Vec<u8>, Vec<u8>) {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        use std::time::{SystemTime, UNIX_EPOCH};

        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let pk: Vec<u8> = (0..self.params.pk_size)
            .map(|i| {
                let mut h = DefaultHasher::new();
                (seed + i as u128).hash(&mut h);
                (h.finish() & 0xFF) as u8
            })
            .collect();

        let sk: Vec<u8> = (0..self.params.sk_size)
            .map(|i| {
                let mut h = DefaultHasher::new();
                (seed + i as u128 + 1000000).hash(&mut h);
                (h.finish() & 0xFF) as u8
            })
            .collect();

        // Store for verification
        self.keypairs.insert(pk[..32].to_vec(), sk.clone());

        (pk, sk)
    }

    fn sign(&self, message: &[u8], sk: &[u8]) -> Vec<u8> {
        // Create deterministic signature
        let mut to_hash = message.to_vec();
        to_hash.extend_from_slice(sk);
        let hash = simple_hash(&to_hash);

        let mut sig = vec![0u8; self.params.sig_size];
        sig[..32].copy_from_slice(&hash);

        // Fill rest with deterministic data
        for i in 32..self.params.sig_size {
            sig[i] = ((hash[i % 32] as usize + i) & 0xFF) as u8;
        }

        sig
    }

    fn verify(&self, message: &[u8], signature: &[u8], pk: &[u8]) -> bool {
        // Look up secret key
        let sk = match self.keypairs.get(&pk[..32]) {
            Some(sk) => sk,
            None => return false,
        };

        // Recompute expected signature
        let mut to_hash = message.to_vec();
        to_hash.extend_from_slice(sk);
        let expected_hash = simple_hash(&to_hash);

        // Compare first 32 bytes
        signature.len() >= 32 && signature[..32] == expected_hash
    }
}

fn print_hex_short(label: &str, data: &[u8], max_bytes: usize) {
    let show = data.len().min(max_bytes);
    let hex: String = data[..show].iter().map(|b| format!("{:02x}", b)).collect();
    let suffix = if data.len() > max_bytes { "..." } else { "" };
    println!("{} ({} bytes): {}{}", label, data.len(), hex, suffix);
}

fn main() {
    // Parse command line
    let args: Vec<String> = env::args().collect();
    let level: u32 = args.get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(65);

    if ![44, 65, 87].contains(&level) {
        eprintln!("Error: Invalid level. Use 44, 65, or 87.");
        std::process::exit(1);
    }

    let params = SignParams::get(level);

    println!("================================================================");
    println!("  QUAC 100 ML-DSA Digital Signature Demo (Rust)");
    println!("  Algorithm: {} (FIPS 204)", params.name);
    println!("  Security:  {}", params.security);
    println!("================================================================");
    println!();

    // Initialize
    let mut signer = SimulatedSign::new(params);
    println!("Using software simulator.");
    println!();

    // Sample message
    let message = b"This is a critical financial transaction: \
        Transfer $1,000,000 from Account A to Account B. \
        Transaction ID: TXN-2025-001-PQC";

    // =========================================================================
    // Step 1: Key Generation
    // =========================================================================
    println!("Step 1: Key Generation");
    println!("-----------------------");
    println!("Generating a signing keypair...");
    println!();

    let (pk, sk) = signer.keygen();

    print_hex_short("Public Key (verification key)", &pk, 32);
    println!("Secret Key (signing key): {} bytes (kept private)", sk.len());
    println!();

    // =========================================================================
    // Step 2: Sign Message
    // =========================================================================
    println!("Step 2: Sign Message");
    println!("--------------------");
    println!("Message to sign:");
    println!("  \"{}\"", String::from_utf8_lossy(message));
    println!();

    let signature = signer.sign(message, &sk);

    print_hex_short("Signature", &signature, 32);
    println!();

    // =========================================================================
    // Step 3: Verify Original Signature
    // =========================================================================
    println!("Step 3: Verify Original Signature");
    println!("----------------------------------");

    if signer.verify(message, &signature, &pk) {
        println!("✓ VALID: Signature verification succeeded.");
        println!("  → The message is authentic and unmodified.");
        println!("  → It was signed by the holder of the corresponding secret key.");
        println!();
    } else {
        println!("✗ INVALID: Signature verification failed.");
        std::process::exit(1);
    }

    // =========================================================================
    // Step 4: Detect Tampering
    // =========================================================================
    println!("Step 4: Tamper Detection Test");
    println!("-----------------------------");
    println!("Simulating message tampering (changing $1,000,000 to $10,000,000)...");
    println!();

    let tampered_message = String::from_utf8_lossy(message)
        .replace("$1,000,000", "$10,000,000");

    if !signer.verify(tampered_message.as_bytes(), &signature, &pk) {
        println!("✓ DETECTED: Signature verification FAILED for tampered message.");
        println!("  → The tampering was successfully detected!");
        println!("  → Any modification to the message invalidates the signature.");
        println!();
    } else {
        println!("✗ ERROR: Tampered message was incorrectly accepted!");
        std::process::exit(1);
    }

    // =========================================================================
    // Step 5: Wrong Key Test
    // =========================================================================
    println!("Step 5: Wrong Key Detection Test");
    println!("---------------------------------");
    println!("Generating a different keypair and trying to verify...");
    println!();

    let (wrong_pk, _wrong_sk) = signer.keygen();

    if !signer.verify(message, &signature, &wrong_pk) {
        println!("✓ DETECTED: Signature verification FAILED with wrong key.");
        println!("  → Only the correct public key can verify the signature.");
        println!();
    } else {
        println!("✗ ERROR: Wrong key was incorrectly accepted!");
    }

    // =========================================================================
    // Summary
    // =========================================================================
    let params = SignParams::get(level); // Get fresh params for summary
    println!("================================================================");
    println!("  Digital Signature Demo Complete");
    println!("================================================================");
    println!("Algorithm:      {}", params.name);
    println!("Security Level: {}", params.security);
    println!("Public Key:     {} bytes", pk.len());
    println!("Signature:      {} bytes", signature.len());
    println!();
    println!("ML-DSA provides:");
    println!("  • Post-quantum security (resistant to Shor's algorithm)");
    println!("  • EUF-CMA security (existential unforgeability)");
    println!("  • Deterministic signatures (no random number needed)");
    println!("  • Fast verification suitable for certificate checking");
    println!("================================================================");
}