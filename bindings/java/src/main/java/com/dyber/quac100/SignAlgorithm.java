/*
 * Copyright © 2025 Dyber, Inc. All Rights Reserved.
 * QUAC 100 Post-Quantum Cryptographic Accelerator - Java SDK
 */
package com.dyber.quac100;

/**
 * Digital Signature algorithms.
 * 
 * <p>
 * ML-DSA (previously known as CRYSTALS-Dilithium) is the NIST standardized
 * lattice-based digital signature algorithm.
 * </p>
 */
public enum SignAlgorithm {
    /** ML-DSA-44 - NIST Security Level 2 */
    ML_DSA_44(1),

    /** ML-DSA-65 - NIST Security Level 3 (Recommended) */
    ML_DSA_65(2),

    /** ML-DSA-87 - NIST Security Level 5 */
    ML_DSA_87(3);

    private final int value;

    SignAlgorithm(int value) {
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
     * Converts a native value to the corresponding enum.
     * 
     * @param value native value
     * @return corresponding enum value
     * @throws IllegalArgumentException if value is invalid
     */
    public static SignAlgorithm fromValue(int value) {
        for (SignAlgorithm alg : values()) {
            if (alg.value == value) {
                return alg;
            }
        }
        throw new IllegalArgumentException("Unknown SignAlgorithm value: " + value);
    }
}