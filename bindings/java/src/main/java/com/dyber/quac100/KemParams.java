/*
 * Copyright © 2025 Dyber, Inc. All Rights Reserved.
 * QUAC 100 Post-Quantum Cryptographic Accelerator - Java SDK
 */

package com.dyber.quac100;

/**
 * Parameters for a KEM (Key Encapsulation Mechanism) algorithm.
 * 
 * @since 1.0.0
 */
public final class KemParams {

    private final String name;
    private final int publicKeySize;
    private final int secretKeySize;
    private final int ciphertextSize;
    private final int sharedSecretSize;
    private final int securityLevel;
    private final int algorithm;

    /**
     * Construct KemParams (called from JNI).
     */
    public KemParams(String name, int publicKeySize, int secretKeySize,
            int ciphertextSize, int sharedSecretSize, int securityLevel, int algorithm) {
        this.name = name;
        this.publicKeySize = publicKeySize;
        this.secretKeySize = secretKeySize;
        this.ciphertextSize = ciphertextSize;
        this.sharedSecretSize = sharedSecretSize;
        this.securityLevel = securityLevel;
        this.algorithm = algorithm;
    }

    public String getName() {
        return name;
    }

    public int getPublicKeySize() {
        return publicKeySize;
    }

    public int getSecretKeySize() {
        return secretKeySize;
    }

    public int getCiphertextSize() {
        return ciphertextSize;
    }

    public int getSharedSecretSize() {
        return sharedSecretSize;
    }

    public int getSecurityLevel() {
        return securityLevel;
    }

    public int getAlgorithm() {
        return algorithm;
    }

    @Override
    public String toString() {
        return String.format("KemParams{name='%s', pk=%d, sk=%d, ct=%d, ss=%d, level=%d}",
                name, publicKeySize, secretKeySize, ciphertextSize, sharedSecretSize, securityLevel);
    }
}