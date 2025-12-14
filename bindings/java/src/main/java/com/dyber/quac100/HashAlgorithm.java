/*
 * Copyright © 2025 Dyber, Inc. All Rights Reserved.
 * QUAC 100 Post-Quantum Cryptographic Accelerator - Java SDK
 */
package com.dyber.quac100;

/**
 * Hash algorithms supported by the QUAC 100.
 */
public enum HashAlgorithm {
    /** SHA-256 (32-byte output) */
    SHA256(1),

    /** SHA-384 (48-byte output) */
    SHA384(2),

    /** SHA-512 (64-byte output) */
    SHA512(3),

    /** SHA3-256 (32-byte output) */
    SHA3_256(4),

    /** SHA3-384 (48-byte output) */
    SHA3_384(5),

    /** SHA3-512 (64-byte output) */
    SHA3_512(6),

    /** SHAKE128 (variable output) */
    SHAKE128(7),

    /** SHAKE256 (variable output) */
    SHAKE256(8);

    private final int value;

    HashAlgorithm(int value) {
        this.value = value;
    }

    /**
     * Gets the native value for this algorithm.
     * 
     * @return native enum value
     */
    public int getValue() {
        return value;
    }

    /**
     * Gets the default output size in bytes for this algorithm.
     * 
     * @return output size in bytes (0 for SHAKE which is variable)
     */
    public int getOutputSize() {
        switch (this) {
            case SHA256:
            case SHA3_256:
                return 32;
            case SHA384:
            case SHA3_384:
                return 48;
            case SHA512:
            case SHA3_512:
                return 64;
            default:
                return 0; // Variable for SHAKE
        }
    }

    /**
     * Converts a native value to the corresponding enum.
     * 
     * @param value native value
     * @return corresponding enum value
     * @throws IllegalArgumentException if value is invalid
     */
    public static HashAlgorithm fromValue(int value) {
        for (HashAlgorithm alg : values()) {
            if (alg.value == value) {
                return alg;
            }
        }
        throw new IllegalArgumentException("Unknown HashAlgorithm value: " + value);
    }
}