/**
 * QUAC 100 Hello World Example (Java)
 * 
 * Basic example demonstrating device initialization and random generation.
 * 
 * Build: javac HelloQUAC.java
 * Run:   java HelloQUAC
 * 
 * Copyright 2025 Dyber, Inc. All Rights Reserved.
 */

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Simulated QUAC Algorithm enum
 */
enum Algorithm {
    ML_KEM_512,
    ML_KEM_768,
    ML_KEM_1024,
    ML_DSA_44,
    ML_DSA_65,
    ML_DSA_87
}

/**
 * Simulated Device Info
 */
class DeviceInfo {
    public final String name;
    public final String serial;
    public final String firmware;
    
    public DeviceInfo(String name, String serial, String firmware) {
        this.name = name;
        this.serial = serial;
        this.firmware = firmware;
    }
}

/**
 * Simulated Key Pair
 */
class KeyPair {
    public final byte[] publicKey;
    public final byte[] secretKey;
    
    public KeyPair(byte[] publicKey, byte[] secretKey) {
        this.publicKey = publicKey;
        this.secretKey = secretKey;
    }
    
    public void clear() {
        Arrays.fill(secretKey, (byte) 0);
    }
}

/**
 * Simulated Device
 */
class Device implements AutoCloseable {
    private final DeviceInfo info;
    private final SecureRandom random = new SecureRandom();
    private boolean closed = false;
    
    public Device(DeviceInfo info) {
        this.info = info;
    }
    
    public DeviceInfo getInfo() {
        return info;
    }
    
    public byte[] random(int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }
    
    public KeyPair kemKeygen(Algorithm algorithm) {
        int pkSize, skSize;
        switch (algorithm) {
            case ML_KEM_512:  pkSize = 800;  skSize = 1632; break;
            case ML_KEM_768:  pkSize = 1184; skSize = 2400; break;
            case ML_KEM_1024: pkSize = 1568; skSize = 3168; break;
            default: throw new IllegalArgumentException("Invalid algorithm");
        }
        byte[] pk = new byte[pkSize];
        byte[] sk = new byte[skSize];
        random.nextBytes(pk);
        random.nextBytes(sk);
        return new KeyPair(pk, sk);
    }
    
    @Override
    public void close() {
        closed = true;
    }
    
    public boolean isClosed() {
        return closed;
    }
}

/**
 * Simulated Context
 */
class Context implements AutoCloseable {
    private boolean closed = false;
    
    public int getDeviceCount() {
        return 1;
    }
    
    public Device openDevice(int index) throws Exception {
        throw new Exception("No hardware available");
    }
    
    public Device openSimulator() {
        return new Device(new DeviceInfo(
            "QUAC 100 Simulator",
            "SIM-00000000",
            "1.0.0-sim"
        ));
    }
    
    @Override
    public void close() {
        closed = true;
    }
}

/**
 * Main Hello World Example
 */
public class HelloQUAC {
    
    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    
    public static void main(String[] args) {
        System.out.println("==============================================");
        System.out.println("  QUAC 100 Hello World Example (Java)");
        System.out.println("==============================================");
        System.out.println();
        
        // Step 1: Initialize SDK
        System.out.println("1. Initializing QUAC SDK...");
        try (Context ctx = new Context()) {
            System.out.println("   SDK initialized successfully.");
            System.out.println();
            
            // Step 2: Query devices
            System.out.println("2. Querying devices...");
            int count = ctx.getDeviceCount();
            System.out.println("   Found " + count + " device(s)");
            System.out.println();
            
            // Step 3: Open device
            System.out.println("3. Opening device...");
            Device device;
            try {
                device = ctx.openDevice(0);
            } catch (Exception e) {
                System.out.println("   No hardware found, using simulator...");
                device = ctx.openSimulator();
            }
            
            try {
                System.out.println("   Device opened successfully.");
                System.out.println();
                
                // Step 4: Get device info
                System.out.println("4. Device Information:");
                DeviceInfo info = device.getInfo();
                System.out.println("   Name:     " + info.name);
                System.out.println("   Serial:   " + info.serial);
                System.out.println("   Firmware: " + info.firmware);
                System.out.println();
                
                // Step 5: Generate random bytes
                System.out.println("5. Generating random bytes with QRNG...");
                byte[] randomBytes = device.random(32);
                System.out.println("   Random: " + toHex(randomBytes));
                System.out.println();
                
                // Step 6: Quick ML-KEM-768 demo
                System.out.println("6. Quick ML-KEM-768 demonstration...");
                KeyPair kp = device.kemKeygen(Algorithm.ML_KEM_768);
                System.out.println("   Public key:  " + kp.publicKey.length + " bytes");
                System.out.println("   Secret key:  " + kp.secretKey.length + " bytes");
                System.out.println("   PK (first 16 bytes): " + 
                    toHex(Arrays.copyOf(kp.publicKey, 16)) + "...");
                
                // Secure cleanup
                kp.clear();
                System.out.println();
                
                // Step 7: Cleanup
                System.out.println("7. Cleaning up...");
                
            } finally {
                device.close();
            }
            
            System.out.println("   Done!");
            System.out.println();
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
        
        System.out.println("==============================================");
        System.out.println("  Hello World Complete!");
        System.out.println("==============================================");
    }
}