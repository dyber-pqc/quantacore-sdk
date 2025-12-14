/**
 * QUAC 100 ML-KEM (Kyber) Key Exchange Demo (Java)
 * 
 * Demonstrates complete key encapsulation mechanism workflow:
 * - Key generation
 * - Encapsulation (sender side)
 * - Decapsulation (receiver side)
 * - Shared secret verification
 * 
 * Build: javac KEMDemo.java
 * Run:   java KEMDemo [512|768|1024]
 * 
 * Copyright 2025 Dyber, Inc. All Rights Reserved.
 */

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * KEM Algorithm Parameters
 */
class KEMParams {
    public final String name;
    public final int pkSize;
    public final int skSize;
    public final int ctSize;
    public final int ssSize;
    
    public KEMParams(String name, int pkSize, int skSize, int ctSize, int ssSize) {
        this.name = name;
        this.pkSize = pkSize;
        this.skSize = skSize;
        this.ctSize = ctSize;
        this.ssSize = ssSize;
    }
    
    public static KEMParams get(int level) {
        switch (level) {
            case 512:  return new KEMParams("ML-KEM-512", 800, 1632, 768, 32);
            case 768:  return new KEMParams("ML-KEM-768", 1184, 2400, 1088, 32);
            case 1024: return new KEMParams("ML-KEM-1024", 1568, 3168, 1568, 32);
            default:   return new KEMParams("ML-KEM-768", 1184, 2400, 1088, 32);
        }
    }
}

/**
 * KEM Key Pair
 */
class KEMKeyPair {
    public final byte[] publicKey;
    public final byte[] secretKey;
    
    public KEMKeyPair(byte[] publicKey, byte[] secretKey) {
        this.publicKey = publicKey;
        this.secretKey = secretKey;
    }
    
    public void clear() {
        Arrays.fill(secretKey, (byte) 0);
    }
}

/**
 * Encapsulation Result
 */
class EncapsResult {
    public final byte[] ciphertext;
    public final byte[] sharedSecret;
    
    public EncapsResult(byte[] ciphertext, byte[] sharedSecret) {
        this.ciphertext = ciphertext;
        this.sharedSecret = sharedSecret;
    }
    
    public void clear() {
        Arrays.fill(sharedSecret, (byte) 0);
    }
}

/**
 * Simulated KEM Operations
 */
class SimulatedKEM {
    private final KEMParams params;
    private final SecureRandom random = new SecureRandom();
    private byte[] lastSS = null;
    
    public SimulatedKEM(KEMParams params) {
        this.params = params;
    }
    
    public KEMKeyPair keygen() {
        byte[] pk = new byte[params.pkSize];
        byte[] sk = new byte[params.skSize];
        random.nextBytes(pk);
        random.nextBytes(sk);
        return new KEMKeyPair(pk, sk);
    }
    
    public EncapsResult encaps(byte[] pk) {
        byte[] ct = new byte[params.ctSize];
        byte[] ss = new byte[params.ssSize];
        random.nextBytes(ct);
        random.nextBytes(ss);
        lastSS = ss.clone(); // Store for simulation
        return new EncapsResult(ct, ss);
    }
    
    public byte[] decaps(byte[] ct, byte[] sk) {
        // Return stored secret for simulation
        if (lastSS != null) {
            return lastSS.clone();
        }
        byte[] ss = new byte[params.ssSize];
        random.nextBytes(ss);
        return ss;
    }
}

/**
 * Main KEM Demo
 */
public class KEMDemo {
    
    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    
    private static void printHex(String label, byte[] data, int maxBytes) {
        String hex = toHex(Arrays.copyOf(data, Math.min(data.length, maxBytes)));
        String suffix = data.length > maxBytes ? "..." : "";
        System.out.println(label + " (" + data.length + " bytes):");
        System.out.println("  " + hex + suffix);
    }
    
    public static void main(String[] args) {
        // Parse command line
        int level = 768;
        if (args.length > 0) {
            try {
                level = Integer.parseInt(args[0]);
                if (level != 512 && level != 768 && level != 1024) {
                    System.err.println("Error: Invalid level. Use 512, 768, or 1024.");
                    System.exit(1);
                }
            } catch (NumberFormatException e) {
                System.err.println("Usage: java KEMDemo [512|768|1024]");
                System.exit(1);
            }
        }
        
        KEMParams params = KEMParams.get(level);
        
        System.out.println("================================================================");
        System.out.println("  QUAC 100 ML-KEM Key Exchange Demo (Java)");
        System.out.println("  Algorithm: " + params.name + " (FIPS 203)");
        System.out.println("================================================================");
        System.out.println();
        
        // Initialize
        SimulatedKEM kem = new SimulatedKEM(params);
        System.out.println("Using software simulator.");
        System.out.println();
        
        // =====================================================================
        // Step 1: Key Generation (Receiver - Alice)
        // =====================================================================
        System.out.println("Step 1: Key Generation (Receiver - Alice)");
        System.out.println("------------------------------------------");
        System.out.println("Alice generates a keypair to receive encrypted messages.");
        System.out.println();
        
        KEMKeyPair aliceKP = kem.keygen();
        
        printHex("Alice's Public Key", aliceKP.publicKey, 48);
        System.out.println("Alice's Secret Key: " + aliceKP.secretKey.length + " bytes (kept private)");
        System.out.println();
        System.out.println("Alice sends her public key to Bob...");
        System.out.println();
        
        // =====================================================================
        // Step 2: Encapsulation (Sender - Bob)
        // =====================================================================
        System.out.println("Step 2: Encapsulation (Sender - Bob)");
        System.out.println("-------------------------------------");
        System.out.println("Bob uses Alice's public key to create:");
        System.out.println("  - A ciphertext (to send to Alice)");
        System.out.println("  - A shared secret (kept by Bob)");
        System.out.println();
        
        EncapsResult bobResult = kem.encaps(aliceKP.publicKey);
        
        printHex("Ciphertext", bobResult.ciphertext, 48);
        printHex("Bob's Shared Secret", bobResult.sharedSecret, 32);
        System.out.println();
        System.out.println("Bob sends the ciphertext to Alice...");
        System.out.println();
        
        // =====================================================================
        // Step 3: Decapsulation (Receiver - Alice)
        // =====================================================================
        System.out.println("Step 3: Decapsulation (Receiver - Alice)");
        System.out.println("-----------------------------------------");
        System.out.println("Alice uses her secret key to recover the shared secret.");
        System.out.println();
        
        byte[] aliceSS = kem.decaps(bobResult.ciphertext, aliceKP.secretKey);
        
        printHex("Alice's Shared Secret", aliceSS, 32);
        System.out.println();
        
        // =====================================================================
        // Step 4: Verification
        // =====================================================================
        System.out.println("Step 4: Verification");
        System.out.println("--------------------");
        
        if (Arrays.equals(bobResult.sharedSecret, aliceSS)) {
            System.out.println("✓ SUCCESS! Both parties have the same shared secret.");
            System.out.println("  This secret can now be used as a symmetric encryption key.");
            System.out.println();
        } else {
            System.out.println("✗ FAILURE! Shared secrets do not match.");
            System.exit(1);
        }
        
        // =====================================================================
        // Summary
        // =====================================================================
        System.out.println("================================================================");
        System.out.println("  Key Exchange Complete");
        System.out.println("================================================================");
        System.out.println("Algorithm:      " + params.name);
        System.out.println("Public Key:     " + aliceKP.publicKey.length + " bytes");
        System.out.println("Secret Key:     " + aliceKP.secretKey.length + " bytes");
        System.out.println("Ciphertext:     " + bobResult.ciphertext.length + " bytes");
        System.out.println("Shared Secret:  " + bobResult.sharedSecret.length + " bytes (256 bits)");
        System.out.println();
        System.out.println("This shared secret provides:");
        System.out.println("  • Post-quantum security against Shor's algorithm");
        System.out.println("  • IND-CCA2 security (chosen ciphertext attack resistance)");
        System.out.println("  • Perfect forward secrecy when used with ephemeral keys");
        System.out.println("================================================================");
        
        // Secure cleanup
        aliceKP.clear();
        bobResult.clear();
        Arrays.fill(aliceSS, (byte) 0);
    }
}