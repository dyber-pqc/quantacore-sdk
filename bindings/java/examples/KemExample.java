/*
 * Copyright © 2025 Dyber, Inc. All Rights Reserved.
 * QUAC 100 Post-Quantum Cryptographic Accelerator - Java SDK
 * 
 * KEM Example - Key Encapsulation Mechanism operations
 */
package com.dyber.quac100.examples;

import com.dyber.quac100.*;
import java.util.Arrays;

/**
 * Example demonstrating ML-KEM (Kyber) key encapsulation mechanism.
 */
public class KemExample {

    public static void main(String[] args) {
        System.out.println("=== QUAC 100 Java SDK KEM Example ===\n");

        try (Library lib = Library.getInstance()) {
            Device device = lib.openFirstDevice();
            Kem kem = device.kem();

            // Print algorithm parameters
            System.out.println("ML-KEM Algorithm Parameters:\n");
            for (KemAlgorithm alg : KemAlgorithm.values()) {
                KemParams params = kem.getParams(alg);
                System.out.println("  " + params.getName() + ":");
                System.out.println("    Public Key:    " + params.getPublicKeySize() + " bytes");
                System.out.println("    Secret Key:    " + params.getSecretKeySize() + " bytes");
                System.out.println("    Ciphertext:    " + params.getCiphertextSize() + " bytes");
                System.out.println("    Shared Secret: " + params.getSharedSecretSize() + " bytes");
                System.out.println("    Security:      Level " + params.getSecurityLevel());
                System.out.println();
            }

            // Demonstrate key exchange with ML-KEM-768 (recommended)
            System.out.println("=== ML-KEM-768 Key Exchange Demo ===\n");

            // Alice generates a key pair
            System.out.println("Alice: Generating key pair...");
            long startTime = System.nanoTime();
            KeyPair aliceKeys = kem.generateKeyPair768();
            long keyGenTime = System.nanoTime() - startTime;

            System.out.println("  Public key:  " + aliceKeys.getPublicKeySize() + " bytes");
            System.out.println("  Secret key:  " + aliceKeys.getSecretKeySize() + " bytes");
            System.out.println("  Time:        " + (keyGenTime / 1000.0) + " µs");
            System.out.println();

            // Bob receives Alice's public key and encapsulates a shared secret
            System.out.println("Bob: Encapsulating shared secret...");
            startTime = System.nanoTime();
            EncapsulationResult bobResult = kem.encapsulate768(aliceKeys.getPublicKey());
            long encapTime = System.nanoTime() - startTime;

            System.out.println("  Ciphertext:    " + bobResult.getCiphertextSize() + " bytes");
            System.out.println("  Shared secret: " + Utils.toHex(bobResult.getSharedSecret()));
            System.out.println("  Time:          " + (encapTime / 1000.0) + " µs");
            System.out.println();

            // Alice decapsulates to recover the shared secret
            System.out.println("Alice: Decapsulating shared secret...");
            startTime = System.nanoTime();
            byte[] aliceSecret = kem.decapsulate768(aliceKeys.getSecretKey(), bobResult.getCiphertext());
            long decapTime = System.nanoTime() - startTime;

            System.out.println("  Shared secret: " + Utils.toHex(aliceSecret));
            System.out.println("  Time:          " + (decapTime / 1000.0) + " µs");
            System.out.println();

            // Verify both parties have the same shared secret
            boolean match = Arrays.equals(bobResult.getSharedSecret(), aliceSecret);
            System.out.println("Shared secrets match: " + (match ? "YES ✓" : "NO ✗"));

            if (!match) {
                System.err.println("ERROR: Shared secrets do not match!");
                System.exit(1);
            }

            // Performance benchmark
            System.out.println("\n=== Performance Benchmark (100 iterations) ===\n");

            int iterations = 100;
            long totalKeyGen = 0, totalEncap = 0, totalDecap = 0;

            for (int i = 0; i < iterations; i++) {
                startTime = System.nanoTime();
                KeyPair kp = kem.generateKeyPair768();
                totalKeyGen += System.nanoTime() - startTime;

                startTime = System.nanoTime();
                EncapsulationResult enc = kem.encapsulate768(kp.getPublicKey());
                totalEncap += System.nanoTime() - startTime;

                startTime = System.nanoTime();
                kem.decapsulate768(kp.getSecretKey(), enc.getCiphertext());
                totalDecap += System.nanoTime() - startTime;

                // Clean up
                kp.destroy();
                enc.destroy();
            }

            System.out.printf("KeyGen:  %.2f µs/op (%.0f ops/sec)%n",
                    totalKeyGen / 1000.0 / iterations,
                    iterations * 1_000_000_000.0 / totalKeyGen);
            System.out.printf("Encap:   %.2f µs/op (%.0f ops/sec)%n",
                    totalEncap / 1000.0 / iterations,
                    iterations * 1_000_000_000.0 / totalEncap);
            System.out.printf("Decap:   %.2f µs/op (%.0f ops/sec)%n",
                    totalDecap / 1000.0 / iterations,
                    iterations * 1_000_000_000.0 / totalDecap);

            // Clean up
            aliceKeys.destroy();
            bobResult.destroy();
            device.close();

        } catch (QuacException e) {
            System.err.println("QUAC Error [" + e.getErrorCode() + "]: " + e.getMessage());
            e.printStackTrace();
        }

        System.out.println("\n=== Example Complete ===");
    }
}