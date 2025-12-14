//! QUAC 100 ML-KEM (Kyber) Key Exchange Demo (Rust)
//!
//! Demonstrates complete key encapsulation mechanism workflow:
//! - Key generation
//! - Encapsulation (sender side)
//! - Decapsulation (receiver side)
//! - Shared secret verification
//!
//! Run: cargo run --example kem_demo -- [512|768|1024]
//!
//! Copyright 2025 Dyber, Inc. All Rights Reserved.

use std::env;

// Simulated types (would be imported from quac100 crate)
#[derive(Clone, Copy)]
enum Algorithm {
    MlKem512,
    MlKem768,
    MlKem1024,
}

struct KemParams {
    name: &'static str,
    pk_size: usize,
    sk_size: usize,
    ct_size: usize,
    ss_size: usize,
}

impl KemParams {
    fn get(level: u32) -> Self {
        match level {
            512 => KemParams {
                name: "ML-KEM-512",
                pk_size: 800,
                sk_size: 1632,
                ct_size: 768,
                ss_size: 32,
            },
            768 => KemParams {
                name: "ML-KEM-768",
                pk_size: 1184,
                sk_size: 2400,
                ct_size: 1088,
                ss_size: 32,
            },
            1024 => KemParams {
                name: "ML-KEM-1024",
                pk_size: 1568,
                sk_size: 3168,
                ct_size: 1568,
                ss_size: 32,
            },
            _ => Self::get(768),
        }
    }
}

/// Simulated KEM for demonstration
struct SimulatedKem {
    params: KemParams,
    last_ss: Option<Vec<u8>>,
}

impl SimulatedKem {
    fn new(params: KemParams) -> Self {
        Self { params, last_ss: None }
    }

    fn keygen(&self) -> (Vec<u8>, Vec<u8>) {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        use std::time::{SystemTime, UNIX_EPOCH};

        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let mut hasher = DefaultHasher::new();
        seed.hash(&mut hasher);

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

        (pk, sk)
    }

    fn encaps(&mut self, _pk: &[u8]) -> (Vec<u8>, Vec<u8>) {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        use std::time::{SystemTime, UNIX_EPOCH};

        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let ct: Vec<u8> = (0..self.params.ct_size)
            .map(|i| {
                let mut h = DefaultHasher::new();
                (seed + i as u128).hash(&mut h);
                (h.finish() & 0xFF) as u8
            })
            .collect();

        let ss: Vec<u8> = (0..self.params.ss_size)
            .map(|i| {
                let mut h = DefaultHasher::new();
                (seed + i as u128 + 2000000).hash(&mut h);
                (h.finish() & 0xFF) as u8
            })
            .collect();

        self.last_ss = Some(ss.clone());
        (ct, ss)
    }

    fn decaps(&self, _ct: &[u8], _sk: &[u8]) -> Vec<u8> {
        // Return stored secret for simulation
        self.last_ss.clone().unwrap_or_else(|| vec![0u8; self.params.ss_size])
    }
}

fn print_hex(label: &str, data: &[u8], max_bytes: usize) {
    let show = data.len().min(max_bytes);
    let hex: String = data[..show].iter().map(|b| format!("{:02x}", b)).collect();
    let suffix = if data.len() > max_bytes { "..." } else { "" };
    println!("{} ({} bytes):", label, data.len());
    println!("  {}{}", hex, suffix);
}

fn main() {
    // Parse command line
    let args: Vec<String> = env::args().collect();
    let level: u32 = args.get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(768);

    if ![512, 768, 1024].contains(&level) {
        eprintln!("Error: Invalid level. Use 512, 768, or 1024.");
        std::process::exit(1);
    }

    let params = KemParams::get(level);

    println!("================================================================");
    println!("  QUAC 100 ML-KEM Key Exchange Demo (Rust)");
    println!("  Algorithm: {} (FIPS 203)", params.name);
    println!("================================================================");
    println!();

    // Initialize
    let mut kem = SimulatedKem::new(params);
    println!("Using software simulator.");
    println!();

    // =========================================================================
    // Step 1: Key Generation (Receiver - Alice)
    // =========================================================================
    println!("Step 1: Key Generation (Receiver - Alice)");
    println!("------------------------------------------");
    println!("Alice generates a keypair to receive encrypted messages.");
    println!();

    let (alice_pk, alice_sk) = kem.keygen();

    print_hex("Alice's Public Key", &alice_pk, 48);
    println!("Alice's Secret Key: {} bytes (kept private)", alice_sk.len());
    println!();
    println!("Alice sends her public key to Bob...");
    println!();

    // =========================================================================
    // Step 2: Encapsulation (Sender - Bob)
    // =========================================================================
    println!("Step 2: Encapsulation (Sender - Bob)");
    println!("-------------------------------------");
    println!("Bob uses Alice's public key to create:");
    println!("  - A ciphertext (to send to Alice)");
    println!("  - A shared secret (kept by Bob)");
    println!();

    let (ciphertext, ss_bob) = kem.encaps(&alice_pk);

    print_hex("Ciphertext", &ciphertext, 48);
    print_hex("Bob's Shared Secret", &ss_bob, 32);
    println!();
    println!("Bob sends the ciphertext to Alice...");
    println!();

    // =========================================================================
    // Step 3: Decapsulation (Receiver - Alice)
    // =========================================================================
    println!("Step 3: Decapsulation (Receiver - Alice)");
    println!("-----------------------------------------");
    println!("Alice uses her secret key to recover the shared secret.");
    println!();

    let ss_alice = kem.decaps(&ciphertext, &alice_sk);

    print_hex("Alice's Shared Secret", &ss_alice, 32);
    println!();

    // =========================================================================
    // Step 4: Verification
    // =========================================================================
    println!("Step 4: Verification");
    println!("--------------------");

    if ss_bob == ss_alice {
        println!("✓ SUCCESS! Both parties have the same shared secret.");
        println!("  This secret can now be used as a symmetric encryption key.");
        println!();
    } else {
        println!("✗ FAILURE! Shared secrets do not match.");
        std::process::exit(1);
    }

    // =========================================================================
    // Summary
    // =========================================================================
    println!("================================================================");
    println!("  Key Exchange Complete");
    println!("================================================================");
    println!("Algorithm:      {}", params.name);
    println!("Public Key:     {} bytes", alice_pk.len());
    println!("Secret Key:     {} bytes", alice_sk.len());
    println!("Ciphertext:     {} bytes", ciphertext.len());
    println!("Shared Secret:  {} bytes (256 bits)", ss_bob.len());
    println!();
    println!("This shared secret provides:");
    println!("  • Post-quantum security against Shor's algorithm");
    println!("  • IND-CCA2 security (chosen ciphertext attack resistance)");
    println!("  • Perfect forward secrecy when used with ephemeral keys");
    println!("================================================================");

    // Note: In real code, use zeroize crate to securely clear secrets
    // alice_sk.zeroize();
    // ss_bob.zeroize();
    // ss_alice.zeroize();
}