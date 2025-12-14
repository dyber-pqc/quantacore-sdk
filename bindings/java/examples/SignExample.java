/*
 * Copyright © 2025 Dyber, Inc. All Rights Reserved.
 * QUAC 100 Post-Quantum Cryptographic Accelerator - Java SDK
 * 
 * Sign Example - Digital Signature operations
 */
package com.dyber.quac100.examples;

import com.dyber.quac100.*;
import java.nio.charset.StandardCharsets;

/**
 * Example demonstrating ML-DSA (Dilithium) digital signatures.
 */
public class SignExample {

    public static void main(String[] args) {
        System.out.println("=== QUAC 100 Java SDK Signature Example ===\n");

        try (Library lib = Library.getInstance()) {
            Device device = lib.openFirstDevice();
            Sign sign = device.sign();

            // Print algorithm parameters
            System.out.println("ML-DSA Algorithm Parameters:\n");
            for (SignAlgorithm alg : SignAlgorithm.values()) {
                SignParams params = sign.getParams(alg);
                System.out.println("  " + params.getName() + ":");
                System.out.println("    Public Key:  " + params.getPublicKeySize() + " bytes");
                System.out.println("    Secret Key:  " + params.getSecretKeySize() + " bytes");
                System.out.println("    Signature:   " + params.getSignatureSize() + " bytes (max)");
                System.out.println("    Security:    Level " + params.getSecurityLevel());
                System.out.println();
            }

            // Demonstrate signing with ML-DSA-65 (recommended)
            System.out.println("=== ML-DSA-65 Signature Demo ===\n");

            // Generate signing key pair
            System.out.println("Generating signing key pair...");
            long startTime = System.nanoTime();
            KeyPair keys = sign.generateKeyPair65();
            long keyGenTime = System.nanoTime() - startTime;

            System.out.println("  Public key:  " + keys.getPublicKeySize() + " bytes");
            System.out.println("  Secret key:  " + keys.getSecretKeySize() + " bytes");
            System.out.println("  Time:        " + (keyGenTime / 1000.0) + " µs");
            System.out.println();

            // Sign a message
            String message = "This is an important document that needs to be signed.";
            byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);

            System.out.println("Signing message: \"" + message + "\"");
            startTime = System.nanoTime();
            byte[] signature = sign.sign65(keys.getSecretKey(), messageBytes);
            long signTime = System.nanoTime() - startTime;

            System.out.println("  Signature size: " + signature.length + " bytes");
            System.out.println("  Signature (first 64 bytes): " +
                    Utils.toHex(java.util.Arrays.copyOf(signature, 64)) + "...");
            System.out.println("  Time:           " + (signTime / 1000.0) + " µs");
            System.out.println();

            // Verify the signature
            System.out.println("Verifying signature...");
            startTime = System.nanoTime();
            boolean valid = sign.verify65(keys.getPublicKey(), messageBytes, signature);
            long verifyTime = System.nanoTime() - startTime;

            System.out.println("  Valid:  " + (valid ? "YES ✓" : "NO ✗"));
            System.out.println("  Time:   " + (verifyTime / 1000.0) + " µs");
            System.out.println();

            // Verify tamper detection
            System.out.println("Testing tamper detection...");
            byte[] tamperedMessage = "This is a TAMPERED document that needs to be signed."
                    .getBytes(StandardCharsets.UTF_8);

            boolean tamperedValid = sign.verify65(keys.getPublicKey(), tamperedMessage, signature);
            System.out.println("  Tampered message verification: " +
                    (tamperedValid ? "VALID (BAD!)" : "REJECTED ✓"));

            if (tamperedValid) {
                System.err.println("ERROR: Tampered message should have been rejected!");
                System.exit(1);
            }
            System.out.println();

            // Batch signing demo
            System.out.println("=== Batch Signing Demo ===\n");
            String[] documents = {
                    "Contract Agreement v1.0",
                    "Purchase Order #12345",
                    "Invoice 2025-001",
                    "Shipping Manifest",
                    "Quality Certificate"
            };

            System.out.println("Signing " + documents.length + " documents:\n");
            for (String doc : documents) {
                byte[] docBytes = doc.getBytes(StandardCharsets.UTF_8);
                byte[] docSig = sign.sign65(keys.getSecretKey(), docBytes);
                boolean docValid = sign.verify65(keys.getPublicKey(), docBytes, docSig);
                System.out.println("  \"" + doc + "\"");
                System.out.println("    Sig: " + Utils.toHex(java.util.Arrays.copyOf(docSig, 16)) + "...");
                System.out.println("    Valid: " + (docValid ? "✓" : "✗"));
            }
            System.out.println();

            // Performance benchmark
            System.out.println("=== Performance Benchmark (100 iterations) ===\n");

            int iterations = 100;
            byte[] benchMsg = "Benchmark message for performance testing".getBytes(StandardCharsets.UTF_8);
            long totalKeyGen = 0, totalSign = 0, totalVerify = 0;

            for (int i = 0; i < iterations; i++) {
                startTime = System.nanoTime();
                KeyPair kp = sign.generateKeyPair65();
                totalKeyGen += System.nanoTime() - startTime;

                startTime = System.nanoTime();
                byte[] sig = sign.sign65(kp.getSecretKey(), benchMsg);
                totalSign += System.nanoTime() - startTime;

                startTime = System.nanoTime();
                sign.verify65(kp.getPublicKey(), benchMsg, sig);
                totalVerify += System.nanoTime() - startTime;

                kp.destroy();
            }

            System.out.printf("KeyGen:  %.2f µs/op (%.0f ops/sec)%n",
                    totalKeyGen / 1000.0 / iterations,
                    iterations * 1_000_000_000.0 / totalKeyGen);
            System.out.printf("Sign:    %.2f µs/op (%.0f ops/sec)%n",
                    totalSign / 1000.0 / iterations,
                    iterations * 1_000_000_000.0 / totalSign);
            System.out.printf("Verify:  %.2f µs/op (%.0f ops/sec)%n",
                    totalVerify / 1000.0 / iterations,
                    iterations * 1_000_000_000.0 / totalVerify);

            // Clean up
            keys.destroy();
            device.close();

        } catch (QuacException e) {
            System.err.println("QUAC Error [" + e.getErrorCode() + "]: " + e.getMessage());
            e.printStackTrace();
        }

        System.out.println("\n=== Example Complete ===");
    }
}