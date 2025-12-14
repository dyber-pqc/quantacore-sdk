/*
 * Copyright © 2025 Dyber, Inc. All Rights Reserved.
 * QUAC 100 Post-Quantum Cryptographic Accelerator - Java SDK
 * 
 * Random Example - Quantum Random Number Generation operations
 */
package com.dyber.quac100.examples;

import com.dyber.quac100.*;
import java.util.Arrays;

/**
 * Example demonstrating quantum random number generation.
 */
public class RandomExample {

    public static void main(String[] args) {
        System.out.println("=== QUAC 100 Java SDK Random Example ===\n");

        try (Library lib = Library.getInstance()) {
            Device device = lib.openFirstDevice();
            Random random = device.random();

            // Check entropy status
            System.out.println("=== Entropy Status ===\n");
            EntropyStatus status = random.getEntropyStatus();
            System.out.println("  Level:           " + status.getLevel() + "%");
            System.out.println("  Health OK:       " + status.isHealthOk());
            System.out.println("  Bytes Generated: " + status.getBytesGenerated());
            System.out.println("  Bit Rate:        " + String.format("%.2f", status.getBitRate()) + " bps");
            System.out.println();

            // Generate random bytes
            System.out.println("=== Random Bytes ===\n");

            byte[] bytes16 = random.bytes(16);
            System.out.println("16 bytes:  " + Utils.toHex(bytes16));

            byte[] bytes32 = random.bytes(32);
            System.out.println("32 bytes:  " + Utils.toHex(bytes32));

            byte[] bytes64 = random.bytes(64);
            System.out.println("64 bytes:  " + Utils.toHex(bytes64));
            System.out.println();

            // Generate random integers
            System.out.println("=== Random Integers ===\n");

            System.out.println("10 random integers (full range):");
            System.out.print("  ");
            for (int i = 0; i < 10; i++) {
                System.out.print(random.nextInt() + " ");
            }
            System.out.println("\n");

            System.out.println("10 random integers [0, 100):");
            System.out.print("  ");
            for (int i = 0; i < 10; i++) {
                System.out.print(random.nextInt(100) + " ");
            }
            System.out.println("\n");

            System.out.println("10 random integers [50, 60):");
            System.out.print("  ");
            for (int i = 0; i < 10; i++) {
                System.out.print(random.nextInt(50, 60) + " ");
            }
            System.out.println("\n");

            // Generate random longs
            System.out.println("=== Random Longs ===\n");

            System.out.println("5 random longs:");
            for (int i = 0; i < 5; i++) {
                System.out.println("  " + random.nextLong());
            }
            System.out.println();

            // Generate random doubles
            System.out.println("=== Random Doubles ===\n");

            System.out.println("10 random doubles [0.0, 1.0):");
            System.out.print("  ");
            for (int i = 0; i < 10; i++) {
                System.out.printf("%.4f ", random.nextDouble());
            }
            System.out.println("\n");

            System.out.println("5 random doubles [10.0, 20.0):");
            System.out.print("  ");
            for (int i = 0; i < 5; i++) {
                System.out.printf("%.4f ", random.nextDouble(10.0, 20.0));
            }
            System.out.println("\n");

            // Generate random booleans
            System.out.println("=== Random Booleans ===\n");

            System.out.println("20 random booleans:");
            System.out.print("  ");
            for (int i = 0; i < 20; i++) {
                System.out.print(random.nextBoolean() ? "T" : "F");
            }
            System.out.println("\n");

            // Generate UUIDs
            System.out.println("=== Random UUIDs ===\n");

            for (int i = 0; i < 5; i++) {
                System.out.println("  " + random.uuid());
            }
            System.out.println();

            // Shuffle demonstration
            System.out.println("=== Fisher-Yates Shuffle ===\n");

            Integer[] cards = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
            System.out.println("Original: " + Arrays.toString(cards));

            random.shuffle(cards);
            System.out.println("Shuffled: " + Arrays.toString(cards));

            random.shuffle(cards);
            System.out.println("Shuffled: " + Arrays.toString(cards));
            System.out.println();

            // Random selection
            System.out.println("=== Random Selection ===\n");

            String[] options = { "Apple", "Banana", "Cherry", "Date", "Elderberry" };
            System.out.println("Options: " + Arrays.toString(options));
            System.out.println("5 random selections:");
            for (int i = 0; i < 5; i++) {
                int idx = random.nextInt(options.length);
                System.out.println("  " + (i + 1) + ". " + options[idx]);
            }
            System.out.println();

            // Distribution test
            System.out.println("=== Distribution Test (10,000 samples, 10 buckets) ===\n");

            int[] buckets = new int[10];
            int samples = 10000;

            for (int i = 0; i < samples; i++) {
                int bucket = random.nextInt(10);
                buckets[bucket]++;
            }

            System.out.println("Expected: ~" + (samples / 10) + " per bucket");
            System.out.println("Results:");
            for (int i = 0; i < 10; i++) {
                int bars = buckets[i] / 50;
                System.out.printf("  [%d]: %4d ", i, buckets[i]);
                for (int j = 0; j < bars; j++) {
                    System.out.print("█");
                }
                System.out.println();
            }

            // Calculate chi-square statistic
            double expected = samples / 10.0;
            double chiSquare = 0;
            for (int bucket : buckets) {
                chiSquare += Math.pow(bucket - expected, 2) / expected;
            }
            System.out.printf("\nChi-square statistic: %.2f (should be < 16.92 for p=0.05)%n", chiSquare);
            System.out.println();

            // Performance benchmark
            System.out.println("=== Performance Benchmark ===\n");

            int iterations = 10000;
            long startTime, elapsed;

            // Bytes
            startTime = System.nanoTime();
            for (int i = 0; i < iterations; i++) {
                random.bytes(256);
            }
            elapsed = System.nanoTime() - startTime;
            double bytesRate = (iterations * 256.0) / (elapsed / 1_000_000_000.0) / (1024 * 1024);
            System.out.printf("Random bytes:    %.2f MB/sec%n", bytesRate);

            // Integers
            startTime = System.nanoTime();
            for (int i = 0; i < iterations; i++) {
                random.nextInt();
            }
            elapsed = System.nanoTime() - startTime;
            double intRate = iterations * 1_000_000_000.0 / elapsed;
            System.out.printf("Random integers: %.0f ops/sec%n", intRate);

            // UUIDs
            startTime = System.nanoTime();
            for (int i = 0; i < iterations; i++) {
                random.uuid();
            }
            elapsed = System.nanoTime() - startTime;
            double uuidRate = iterations * 1_000_000_000.0 / elapsed;
            System.out.printf("Random UUIDs:    %.0f ops/sec%n", uuidRate);

            device.close();

        } catch (QuacException e) {
            System.err.println("QUAC Error [" + e.getErrorCode() + "]: " + e.getMessage());
            e.printStackTrace();
        }

        System.out.println("\n=== Example Complete ===");
    }
}