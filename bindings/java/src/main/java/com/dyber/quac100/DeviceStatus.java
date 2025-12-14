/*
 * Copyright © 2025 Dyber, Inc. All Rights Reserved.
 * QUAC 100 Post-Quantum Cryptographic Accelerator - Java SDK
 */

package com.dyber.quac100;

/**
 * Current status of a QUAC 100 device.
 * 
 * @since 1.0.0
 */
public final class DeviceStatus {

    private final float temperature;
    private final int entropyLevel;
    private final long totalOperations;
    private final boolean healthy;
    private final int lastError;

    /**
     * Construct DeviceStatus (called from JNI).
     */
    public DeviceStatus(float temperature, int entropyLevel, long totalOperations,
            boolean healthy, int lastError) {
        this.temperature = temperature;
        this.entropyLevel = entropyLevel;
        this.totalOperations = totalOperations;
        this.healthy = healthy;
        this.lastError = lastError;
    }

    /** Get the device temperature in Celsius */
    public float getTemperature() {
        return temperature;
    }

    /** Get the entropy pool level (0-100) */
    public int getEntropyLevel() {
        return entropyLevel;
    }

    /** Get the total number of operations performed */
    public long getTotalOperations() {
        return totalOperations;
    }

    /** Check if the device is healthy */
    public boolean isHealthy() {
        return healthy;
    }

    /** Get the last error code */
    public int getLastError() {
        return lastError;
    }

    /** Get the last error as ErrorCode enum */
    public ErrorCode getLastErrorCode() {
        return ErrorCode.fromCode(lastError);
    }

    @Override
    public String toString() {
        return String.format(
                "DeviceStatus{temp=%.1f°C, entropy=%d%%, ops=%d, healthy=%b, lastError=%d}",
                temperature, entropyLevel, totalOperations, healthy, lastError);
    }
}