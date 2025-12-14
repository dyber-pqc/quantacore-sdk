
/**
 * QUAC 100 ML-DSA (Dilithium) Digital Signature Demo (Java)
 * 
 * Demonstrates complete digital signature workflow:
 * - Key generation
 * - Message signing
 * - Signature verification
 * - Tamper detection
 * 
 * Build: javac SignDemo.java
 * Run:   java SignDemo [44|65|87]
 * 
 * Copyright 2025 Dyber, Inc. All Rights Reserved.
 */

import java.security.SecureRandom;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Signature Algorithm Parameters
 */
class SignParams {
    public final String name;
    public final String security;
    public final int pkSize;
    public final int skSize;
    public final int sigSize;

    public SignParams(String name, String security, int pkSize, int skSize, int sigSize) {
        this.name = name;
        this.security = security;
        this.pkSize = pkSize;
        this.skSize = skSize;
        this.sigSize = sigSize;
    }

    public static SignParams get(int level) {
        switch (level) {
            case 44:
                return new SignParams("ML-DSA-44", "NIST Level 2 (128-bit)", 1312, 2560, 2420);
            case 65:
                return new SignParams("ML-DSA-65", "NIST Level 3 (192-bit)", 1952, 4032, 3309);
            case 87:
                return new SignParams("ML-DSA-87", "NIST Level 5 (256-bit)", 2592, 4896, 4627);
            default:
                return new SignParams("ML-DSA-65", "NIST Level 3 (192-bit)", 1952, 4032, 3309);
        }
    }
}

/**
 * Signature Key Pair
 */
class SignKeyPair {
    public final byte[] publicKey;
    public final byte[] secretKey;

    public SignKeyPair(byte[] publicKey, byte[] secretKey) {
        this.publicKey = publicKey;
        this.secretKey = secretKey;
    }

    public void clear() {
        Arrays.fill(secretKey, (byte) 0);
    }
}

/**
 * Simulated Signature Operations
 */
class SimulatedSign {
    private final SignParams params;
    private final SecureRandom random = new SecureRandom();
    private final Map<String, byte[]> keypairs = new HashMap<>();

    public SimulatedSign(SignParams params) {
        this.params = params;
    }

    private String bytesToKey(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(32, bytes.length); i++) {
            sb.append(String.format("%02x", bytes[i]));
        }
        return sb.toString();
    }

    public SignKeyPair keygen() {
        byte[] pk = new byte[params.pkSize];
        byte[] sk = new byte[params.skSize];
        random.nextBytes(pk);
        random.nextBytes(sk);
        // Store for verification simulation
        keypairs.put(bytesToKey(pk), sk.clone());
        return new SignKeyPair(pk, sk);
    }

    public byte[] sign(byte[] message, byte[] sk) {
        try {
            // Create deterministic signature using hash
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(message);
            md.update(sk);
            byte[] hash = md.digest();

            byte[] sig = new byte[params.sigSize];
            System.arraycopy(hash, 0, sig, 0, hash.length);
            random.nextBytes(Arrays.copyOfRange(sig, 32, sig.length));
            return sig;
        } catch (Exception e) {
            throw new RuntimeException("Signing failed", e);
        }
    }

    public boolean verify(byte[] message, byte[] signature, byte[] pk) {
        try {
            // Check if we have the secret key for this public key
            byte[] sk = keypairs.get(bytesToKey(pk));
            if (sk == null) {
                return false;
            }

            // Recompute expected signature hash
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(message);
            md.update(sk);
            byte[] expectedHash = md.digest();

            // Compare first 32 bytes
            for (int i = 0; i < 32; i++) {
                if (signature[i] != expectedHash[i]) {
                    return false;
                }
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}

/**
 * Main Signature Demo
 */
public class SignDemo {

    private static String toHex(byte[] bytes, int maxBytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(bytes.length, maxBytes); i++) {
            sb.append(String.format("%02x", bytes[i]));
        }
        if (bytes.length > maxBytes) {
            sb.append("...");
        }
        return sb.toString();
    }

    public static void main(String[] args) {
        // Parse command line
        int level = 65;
        if (args.length > 0) {
            try {
                level = Integer.parseInt(args[0]);
                if (level != 44 && level != 65 && level != 87) {
                    System.err.println("Error: Invalid level. Use 44, 65, or 87.");
                    System.exit(1);
                }
            } catch (NumberFormatException e) {
                System.err.println("Usage: java SignDemo [44|65|87]");
                System.exit(1);
            }
        }

        SignParams params = SignParams.get(level);

        System.out.println("================================================================");
        System.out.println("  QUAC 100 ML-DSA Digital Signature Demo (Java)");
        System.out.println("  Algorithm: " + params.name + " (FIPS 204)");
        System.out.println("  Security:  " + params.security);
        System.out.println("================================================================");
        System.out.println();

        // Initialize
        SimulatedSign signer = new SimulatedSign(params);
        System.out.println("Using software simulator.");
        System.out.println();

        // Sample message
        byte[] message = ("This is a critical financial transaction: " +
                "Transfer $1,000,000 from Account A to Account B. " +
                "Transaction ID: TXN-2025-001-PQC").getBytes();

        // =====================================================================
        // Step 1: Key Generation
        // =====================================================================
        System.out.println("Step 1: Key Generation");
        System.out.println("-----------------------");
        System.out.println("Generating a signing keypair...");
        System.out.println();

        SignKeyPair kp = signer.keygen();

        System.out.println("Public Key (verification key) (" + kp.publicKey.length + " bytes): " +
                toHex(kp.publicKey, 32));
        System.out.println("Secret Key (signing key): " + kp.secretKey.length + " bytes (kept private)");
        System.out.println();

        // =====================================================================
        // Step 2: Sign Message
        // =====================================================================
        System.out.println("Step 2: Sign Message");
        System.out.println("--------------------");
        System.out.println("Message to sign:");
        System.out.println("  \"" + new String(message) + "\"");
        System.out.println();

        byte[] signature = signer.sign(message, kp.secretKey);

        System.out.println("Signature (" + signature.length + " bytes): " + toHex(signature, 32));
        System.out.println();

        // =====================================================================
        // Step 3: Verify Original Signature
        // =====================================================================
        System.out.println("Step 3: Verify Original Signature");
        System.out.println("----------------------------------");

        if (signer.verify(message, signature, kp.publicKey)) {
            System.out.println("✓ VALID: Signature verification succeeded.");
            System.out.println("  → The message is authentic and unmodified.");
            System.out.println("  → It was signed by the holder of the corresponding secret key.");
            System.out.println();
        } else {
            System.out.println("✗ INVALID: Signature verification failed.");
            System.exit(1);
        }

        // =====================================================================
        // Step 4: Detect Tampering
        // =====================================================================
        System.out.println("Step 4: Tamper Detection Test");
        System.out.println("-----------------------------");
        System.out.println("Simulating message tampering (changing $1,000,000 to $10,000,000)...");
        System.out.println();

        byte[] tamperedMessage = new String(message).replace("$1,000,000", "$10,000,000").getBytes();

        if (!signer.verify(tamperedMessage, signature, kp.publicKey)) {
            System.out.println("✓ DETECTED: Signature verification FAILED for tampered message.");
            System.out.println("  → The tampering was successfully detected!");
            System.out.println("  → Any modification to the message invalidates the signature.");
            System.out.println();
        } else {
            System.out.println("✗ ERROR: Tampered message was incorrectly accepted!");
            System.exit(1);
        }

        // =====================================================================
        // Step 5: Wrong Key Test
        // =====================================================================
        System.out.println("Step 5: Wrong Key Detection Test");
        System.out.println("---------------------------------");
        System.out.println("Generating a different keypair and trying to verify...");
        System.out.println();

        SignKeyPair wrongKP = signer.keygen();

        if (!signer.verify(message, signature, wrongKP.publicKey)) {
            System.out.println("✓ DETECTED: Signature verification FAILED with wrong key.");
            System.out.println("  → Only the correct public key can verify the signature.");
            System.out.println();
        } else {
            System.out.println("✗ ERROR: Wrong key was incorrectly accepted!");
        }

        // Secure cleanup
        kp.clear();
        wrongKP.clear();

        // =====================================================================
        // Summary
        // =====================================================================
        System.out.println("================================================================");
        System.out.println("  Digital Signature Demo Complete");
        System.out.println("================================================================");
        System.out.println("Algorithm:      " + params.name);
        System.out.println("Security Level: " + params.security);
        System.out.println("Public Key:     " + params.pkSize + " bytes");
        System.out.println("Signature:      " + params.sigSize + " bytes");
        System.out.println();
        System.out.println("ML-DSA provides:");
        System.out.println("  • Post-quantum security (resistant to Shor's algorithm)");
        System.out.println("  • EUF-CMA security (existential unforgeability)");
        System.out.println("  • Deterministic signatures (no random number needed)");
        System.out.println("  • Fast verification suitable for certificate checking");
        System.out.println("================================================================");
    }
}