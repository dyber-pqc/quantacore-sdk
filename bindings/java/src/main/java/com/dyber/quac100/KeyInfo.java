/*
 * Copyright © 2025 Dyber, Inc. All Rights Reserved.
 * QUAC 100 Post-Quantum Cryptographic Accelerator - Java SDK
 */

package com.dyber.quac100;

/**
 * Information about a stored key.
 * 
 * @since 1.0.0
 */
public final class KeyInfo {

    private final int slot;
    private final String label;
    private final int type;
    private final int algorithm;
    private final int usage;
    private final boolean extractable;
    private final long createdTime;

    /**
     * Construct KeyInfo (called from JNI).
     */
    public KeyInfo(int slot, String label, int type, int algorithm,
            int usage, boolean extractable, long createdTime) {
        this.slot = slot;
        this.label = label;
        this.type = type;
        this.algorithm = algorithm;
        this.usage = usage;
        this.extractable = extractable;
        this.createdTime = createdTime;
    }

    /** Get the key slot number */
    public int getSlot() {
        return slot;
    }

    /** Get the key label */
    public String getLabel() {
        return label;
    }

    /** Get the key type */
    public int getType() {
        return type;
    }

    /** Get the algorithm ID */
    public int getAlgorithm() {
        return algorithm;
    }

    /** Get the usage flags */
    public int getUsage() {
        return usage;
    }

    /** Check if the key can be extracted */
    public boolean isExtractable() {
        return extractable;
    }

    /** Get the creation timestamp (Unix epoch milliseconds) */
    public long getCreatedTime() {
        return createdTime;
    }

    @Override
    public String toString() {
        return String.format("KeyInfo{slot=%d, label='%s', type=%d, extractable=%b}",
                slot, label, type, extractable);
    }
}