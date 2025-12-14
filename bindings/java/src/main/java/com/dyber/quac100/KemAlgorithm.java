/*
 * Copyright © 2025 Dyber, Inc. All Rights Reserved.
 * QUAC 100 Post-Quantum Cryptographic Accelerator - Java SDK
 */
package com.dyber.quac100;

/**
 * Key Encapsulation Mechanism algorithms.
 * 
 * <p>
 * ML-KEM (previously known as CRYSTALS-Kyber) is the NIST standardized
 * lattice-based key encapsulation mechanism.
 * </p>
 */
public enum KemAlgorithm {
    /** ML-KEM-512 - NIST Security Level 1 */
    ML_KEM_512(1),

    /** ML-KEM-768 - NIST Security Level 3 (Recommended) */
    ML_KEM_768(2),

    /** ML-KEM-1024 - NIST Security Level 5 */
    ML_KEM_1024(3);

    private final int value;

    KemAlgorithm(int value) {
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
    public static KemAlgorithm fromValue(int value) {
        for (KemAlgorithm alg : values()) {
            if (alg.value == value) {
                return alg;
            }
        }
        throw new IllegalArgumentException("Unknown KemAlgorithm value: " + value);
    }
}