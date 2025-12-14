/*
 * Copyright © 2025 Dyber, Inc. All Rights Reserved.
 * QUAC 100 Post-Quantum Cryptographic Accelerator - Java SDK
 * 
 * Hash Example - Hashing, HMAC, and key derivation operations
 */
package com.dyber.quac100.examples;

import com.dyber.quac100.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Example demonstrating hardware-accelerated hashing operations.
 */
public class HashExample {

    public static void main(String[] args) {
        System.out.println("=== QUAC 100 Java SDK Hash Example ===\n");

        try (Library lib = Library.getInstance()) {
            Device device = lib.openFirstDevice();
            Hash hash = device.hash();

            String testData = "Hello, World!";
            byte[] testBytes = testData.getBytes(StandardCharsets.UTF_8);

            // SHA-2 Family
            System.out.println("=== SHA-2 Family ===\n");

            byte[] sha256 = hash.sha256(testBytes);
            System.out.println("SHA-256:  " + Utils.toHex(sha256));

            byte[] sha384 = hash.sha384(testBytes);
            System.out.println("SHA-384:  " + Utils.toHex(sha384));

            byte[] sha512 = hash.sha512(testBytes);
            System.out.println("SHA-512:  " + Utils.toHex(sha512));
            System.out.println();

            // SHA-3 Family
            System.out.println("=== SHA-3 Family ===\n");

            byte[] sha3_256 = hash.sha3_256(testBytes);
            System.out.println("SHA3-256: " + Utils.toHex(sha3_256));

            byte[] sha3_512 = hash.sha3_512(testBytes);
            System.out.println("SHA3-512: " + Utils.toHex(sha3_512));
            System.out.println();

            // SHAKE Extendable Output Functions
            System.out.println("=== SHAKE (Extendable Output) ===\n");

            byte[] shake128_32 = hash.shake128(testBytes, 32);
            System.out.println("SHAKE128 (32 bytes): " + Utils.toHex(shake128_32));

            byte[] shake128_64 = hash.shake128(testBytes, 64);
            System.out.println("SHAKE128 (64 bytes): " + Utils.toHex(shake128_64));

            byte[] shake256_32 = hash.shake256(testBytes, 32);
            System.out.println("SHAKE256 (32 bytes): " + Utils.toHex(shake256_32));

            byte[] shake256_128 = hash.shake256(testBytes, 128);
            System.out.println("SHAKE256 (128 bytes): " +
                    Utils.toHex(Arrays.copyOf(shake256_128, 32)) + "...");
            System.out.println();

            // Incremental hashing
            System.out.println("=== Incremental Hashing ===\n");

            System.out.println("One-shot: hash(\"Hello, World!\")");
            byte[] oneshot = hash.sha256("Hello, World!");
            System.out.println("  Result: " + Utils.toHex(oneshot));

            System.out.println("\nIncremental: update(\"Hello, \") + update(\"World!\")");
            try (Hash.HashContext ctx = hash.createContext(HashAlgorithm.SHA256)) {
                ctx.update("Hello, ");
                ctx.update("World!");
                byte[] incremental = ctx.digest(); // Changed from finalize() to digest()
                System.out.println("  Result: " + Utils.toHex(incremental));

                System.out.println("\nMatches: " +
                        (Arrays.equals(oneshot, incremental) ? "YES ✓" : "NO ✗"));
            }
            System.out.println();

            // HMAC
            System.out.println("=== HMAC (Message Authentication) ===\n");

            byte[] hmacKey = "secret-key-for-hmac".getBytes(StandardCharsets.UTF_8);
            byte[] hmacData = "Data to authenticate".getBytes(StandardCharsets.UTF_8);

            byte[] hmac256 = hash.hmacSha256(hmacKey, hmacData);
            System.out.println("HMAC-SHA256: " + Utils.toHex(hmac256));

            byte[] hmac512 = hash.hmacSha512(hmacKey, hmacData);
            System.out.println("HMAC-SHA512: " + Utils.toHex(hmac512));
            System.out.println();

            // HKDF Key Derivation
            System.out.println("=== HKDF Key Derivation ===\n");

            byte[] ikm = "input-keying-material".getBytes(StandardCharsets.UTF_8);
            byte[] salt = "optional-salt".getBytes(StandardCharsets.UTF_8);
            byte[] info = "context-info".getBytes(StandardCharsets.UTF_8);

            byte[] derived32 = hash.hkdf(HashAlgorithm.SHA256, ikm, salt, info, 32);
            System.out.println("HKDF-SHA256 (32 bytes): " + Utils.toHex(derived32));

            byte[] derived64 = hash.hkdf(HashAlgorithm.SHA256, ikm, salt, info, 64);
            System.out.println("HKDF-SHA256 (64 bytes): " + Utils.toHex(derived64));

            // Derive multiple keys from same material
            System.out.println("\nDeriving encryption and MAC keys:");
            byte[] encKey = hash.hkdf(HashAlgorithm.SHA256, ikm, salt,
                    "encryption".getBytes(), 32);
            byte[] macKey = hash.hkdf(HashAlgorithm.SHA256, ikm, salt,
                    "authentication".getBytes(), 32);
            System.out.println("  Encryption key: " + Utils.toHex(encKey));
            System.out.println("  MAC key:        " + Utils.toHex(macKey));
            System.out.println();

            // Password verification example
            System.out.println("=== Password Verification Example ===\n");

            String password = "MySecurePassword123!";
            byte[] passwordSalt = device.random().bytes(16);

            // Store: hash the password
            byte[] storedHash = hash.hkdf(HashAlgorithm.SHA256,
                    password.getBytes(StandardCharsets.UTF_8),
                    passwordSalt,
                    "password-hash".getBytes(),
                    32);

            System.out.println("Stored salt: " + Utils.toHex(passwordSalt));
            System.out.println("Stored hash: " + Utils.toHex(storedHash));

            // Verify: check entered password
            String enteredPassword = "MySecurePassword123!";
            byte[] verifyHash = hash.hkdf(HashAlgorithm.SHA256,
                    enteredPassword.getBytes(StandardCharsets.UTF_8),
                    passwordSalt,
                    "password-hash".getBytes(),
                    32);

            boolean passwordMatch = Utils.secureCompare(storedHash, verifyHash);
            System.out.println("\nPassword verification: " +
                    (passwordMatch ? "SUCCESS ✓" : "FAILED ✗"));
            System.out.println();

            // Performance benchmark
            System.out.println("=== Performance Benchmark ===\n");

            byte[] benchData = new byte[1024 * 1024]; // 1 MB
            device.random().nextBytes(benchData);

            int iterations = 100;
            long startTime, elapsed;

            // SHA-256
            startTime = System.nanoTime();
            for (int i = 0; i < iterations; i++) {
                hash.sha256(benchData);
            }
            elapsed = System.nanoTime() - startTime;
            double sha256Rate = (iterations * benchData.length) / (elapsed / 1_000_000_000.0) / (1024 * 1024);
            System.out.printf("SHA-256:  %.2f MB/sec%n", sha256Rate);

            // SHA3-256
            startTime = System.nanoTime();
            for (int i = 0; i < iterations; i++) {
                hash.sha3_256(benchData);
            }
            elapsed = System.nanoTime() - startTime;
            double sha3Rate = (iterations * benchData.length) / (elapsed / 1_000_000_000.0) / (1024 * 1024);
            System.out.printf("SHA3-256: %.2f MB/sec%n", sha3Rate);

            device.close();

        } catch (QuacException e) {
            System.err.println("QUAC Error [" + e.getErrorCode() + "]: " + e.getMessage());
            e.printStackTrace();
        }

        System.out.println("\n=== Example Complete ===");
    }
}