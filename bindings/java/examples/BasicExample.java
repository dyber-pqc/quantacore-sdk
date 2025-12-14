/*
 * Copyright © 2025 Dyber, Inc. All Rights Reserved.
 * QUAC 100 Post-Quantum Cryptographic Accelerator - Java SDK
 * 
 * Basic Example - Device enumeration and status
 */
package com.dyber.quac100.examples;

import com.dyber.quac100.*;
import java.util.List;

/**
 * Basic example demonstrating library initialization, device enumeration,
 * and status checking.
 */
public class BasicExample {

    public static void main(String[] args) {
        System.out.println("=== QUAC 100 Java SDK Basic Example ===\n");

        try (Library lib = Library.getInstance()) {
            // Print library version
            System.out.println("Library Version: " + Library.version());
            System.out.println("Build Info:\n" + Library.buildInfo());
            System.out.println();

            // Enumerate devices
            List<DeviceInfo> devices = lib.enumerateDevices();
            System.out.println("Found " + devices.size() + " device(s):\n");

            for (DeviceInfo info : devices) {
                System.out.println("  Device " + info.getIndex() + ":");
                System.out.println("    Model:    " + info.getModelName());
                System.out.println("    Serial:   " + info.getSerialNumber());
                System.out.println("    Firmware: " + info.getFirmwareVersion());
                System.out.println("    Slots:    " + info.getKeySlots());
                System.out.println();
            }

            if (devices.isEmpty()) {
                System.out.println("No devices found. Exiting.");
                return;
            }

            // Open first device
            Device device = lib.openFirstDevice();
            System.out.println("Opened device: " + device.getInfo().getSerialNumber());

            // Get device status
            DeviceStatus status = device.getStatus();
            System.out.println("\nDevice Status:");
            System.out.println("  Temperature:    " + status.getTemperature() + "°C");
            System.out.println("  Entropy Level:  " + status.getEntropyLevel() + "%");
            System.out.println("  Total Ops:      " + status.getTotalOperations());
            System.out.println("  Healthy:        " + status.isHealthy());
            System.out.println("  Error Count:    " + status.getErrorCount());

            // Run self-test
            System.out.println("\nRunning self-test...");
            device.selfTest();
            System.out.println("Self-test PASSED");

            // Generate some random data
            System.out.println("\nGenerating random data:");
            byte[] randomBytes = device.random().bytes(32);
            System.out.println("  32 random bytes: " + Utils.toHex(randomBytes));

            String uuid = device.random().uuid();
            System.out.println("  Random UUID:     " + uuid);

            // Close device
            device.close();
            System.out.println("\nDevice closed successfully.");

        } catch (QuacException e) {
            System.err.println("QUAC Error [" + e.getErrorCode() + "]: " + e.getMessage());
            e.printStackTrace();
        }

        System.out.println("\n=== Example Complete ===");
    }
}