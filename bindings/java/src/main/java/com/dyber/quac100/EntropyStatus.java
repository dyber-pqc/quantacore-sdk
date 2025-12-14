/*
 * Copyright © 2025 Dyber, Inc. All Rights Reserved.
 * QUAC 100 Post-Quantum Cryptographic Accelerator - Java SDK
 */
package com.dyber.quac100;

/**
 * Entropy source status information.
 */
public class EntropyStatus {
    private final int level;
    private final boolean healthOk;
    private final long bytesGenerated;
    private final double bitRate;

    /**
     * Constructs new EntropyStatus (called by native code).
     */
    public EntropyStatus(int level, boolean healthOk, long bytesGenerated, double bitRate) {
        this.level = level;
        this.healthOk = healthOk;
        this.bytesGenerated = bytesGenerated;
        this.bitRate = bitRate;
    }

    /** Gets the entropy level (0-100%). */
    public int getLevel() {
        return level;
    }

    /** Returns true if entropy source is healthy. */
    public boolean isHealthOk() {
        return healthOk;
    }

    /** Gets total bytes generated since device startup. */
    public long getBytesGenerated() {
        return bytesGenerated;
    }

    /** Gets current generation rate in bits per second. */
    public double getBitRate() {
        return bitRate;
    }

    @Override
    public String toString() {
        return String.format("EntropyStatus{level=%d%%, healthy=%s, generated=%d bytes, rate=%.2f bps}",
                level, healthOk, bytesGenerated, bitRate);
    }
}