/*
 * Copyright © 2025 Dyber, Inc. All Rights Reserved.
 * QUAC 100 Post-Quantum Cryptographic Accelerator - Java SDK
 */
package com.dyber.quac100;

/**
 * Represents an open QUAC 100 device.
 * 
 * <p>
 * Device instances provide access to all cryptographic operations including
 * key encapsulation, digital signatures, random number generation, and hashing.
 * </p>
 * 
 * <h2>Example Usage:</h2>
 * 
 * <pre>{@code
 * try (Library lib = Library.getInstance()) {
 *     Device device = lib.openFirstDevice();
 * 
 *     // Check device status
 *     DeviceStatus status = device.getStatus();
 *     System.out.println("Temperature: " + status.getTemperature() + "°C");
 *     System.out.println("Entropy: " + status.getEntropyLevel() + "%");
 * 
 *     // Run self-test
 *     device.selfTest();
 * 
 *     // Access subsystems
 *     Kem kem = device.kem();
 *     Sign sign = device.sign();
 *     Random random = device.random();
 *     Hash hash = device.hash();
 * }
 * }</pre>
 * 
 * @author Dyber, Inc.
 * @version 1.0.0
 */
public class Device implements AutoCloseable {

    private long handle;
    private final int index;
    private boolean closed = false;

    // Subsystem instances (lazy initialization)
    private Kem kem;
    private Sign sign;
    private Random random;
    private Hash hash;
    private Keys keys;

    // Native methods
    private static native DeviceInfo nativeGetInfo(long handle);

    private static native DeviceStatus nativeGetStatus(long handle);

    private static native int nativeSelfTest(long handle);

    private static native int nativeReset(long handle);

    private static native void nativeCloseDevice(long handle);

    /**
     * Package-private constructor - devices are created by Library.
     */
    Device(long handle, int index) {
        this.handle = handle;
        this.index = index;
    }

    /**
     * Gets the native handle for this device.
     * 
     * @return native handle
     */
    long getHandle() {
        return handle;
    }

    /**
     * Gets the device index.
     * 
     * @return device index (0-based)
     */
    public int getIndex() {
        return index;
    }

    /**
     * Gets device information.
     * 
     * @return DeviceInfo containing model, serial number, firmware version, etc.
     * @throws QuacException if operation fails
     */
    public DeviceInfo getInfo() throws QuacException {
        checkOpen();
        DeviceInfo info = nativeGetInfo(handle);
        if (info == null) {
            throw new DeviceException(ErrorCode.DEVICE_ERROR,
                    "Failed to get device info");
        }
        return info;
    }

    /**
     * Gets current device status.
     * 
     * @return DeviceStatus containing temperature, entropy level, health status,
     *         etc.
     * @throws QuacException if operation fails
     */
    public DeviceStatus getStatus() throws QuacException {
        checkOpen();
        DeviceStatus status = nativeGetStatus(handle);
        if (status == null) {
            throw new DeviceException(ErrorCode.DEVICE_ERROR,
                    "Failed to get device status");
        }
        return status;
    }

    /**
     * Runs device self-test.
     * 
     * <p>
     * Performs comprehensive hardware and cryptographic self-test.
     * </p>
     * 
     * @throws QuacException if self-test fails
     */
    public void selfTest() throws QuacException {
        checkOpen();
        int result = nativeSelfTest(handle);
        if (result != 0) {
            throw new DeviceException(ErrorCode.fromCode(result),
                    "Device self-test failed");
        }
    }

    /**
     * Resets the device to initial state.
     * 
     * <p>
     * Clears all temporary state and reinitializes the device.
     * </p>
     * 
     * @throws QuacException if reset fails
     */
    public void reset() throws QuacException {
        checkOpen();
        int result = nativeReset(handle);
        if (result != 0) {
            throw new DeviceException(ErrorCode.fromCode(result),
                    "Device reset failed");
        }
    }

    /**
     * Gets the Key Encapsulation Mechanism (KEM) subsystem.
     * 
     * @return Kem instance for ML-KEM operations
     */
    public Kem kem() {
        if (kem == null) {
            kem = new Kem(this);
        }
        return kem;
    }

    /**
     * Gets the Digital Signature subsystem.
     * 
     * @return Sign instance for ML-DSA operations
     */
    public Sign sign() {
        if (sign == null) {
            sign = new Sign(this);
        }
        return sign;
    }

    /**
     * Gets the Random Number Generation subsystem.
     * 
     * @return Random instance for QRNG operations
     */
    public Random random() {
        if (random == null) {
            random = new Random(this);
        }
        return random;
    }

    /**
     * Gets the Hash subsystem.
     * 
     * @return Hash instance for SHA-2, SHA-3, and SHAKE operations
     */
    public Hash hash() {
        if (hash == null) {
            hash = new Hash(this);
        }
        return hash;
    }

    /**
     * Gets the HSM Key Storage subsystem.
     * 
     * @return Keys instance for key management operations
     */
    public Keys keys() {
        if (keys == null) {
            keys = new Keys(this);
        }
        return keys;
    }

    /**
     * Checks if the device is still open.
     * 
     * @return true if device is open
     */
    public boolean isOpen() {
        return !closed && handle != 0;
    }

    private void checkOpen() throws QuacException {
        if (closed || handle == 0) {
            throw new DeviceException(ErrorCode.DEVICE_ERROR,
                    "Device is closed");
        }
    }

    /**
     * Closes the device and releases resources.
     */
    @Override
    public void close() {
        if (!closed && handle != 0) {
            nativeCloseDevice(handle);
            handle = 0;
            closed = true;

            // Notify library
            Library.deviceClosed(this);
        }
    }
}
