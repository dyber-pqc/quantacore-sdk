/*
 * Copyright © 2025 Dyber, Inc. All Rights Reserved.
 * QUAC 100 Post-Quantum Cryptographic Accelerator - Java SDK
 */

package com.dyber.quac100;

/**
 * Parameters for a digital signature algorithm.
 * 
 * @since 1.0.0
 */
public final class SignParams {

    private final String name;
    private final int publicKeySize;
    private final int secretKeySize;
    private final int signatureSize;
    private final int securityLevel;
    private final int algorithm;

    /**
     * Construct SignParams (called from JNI).
     */
    public SignParams(String name, int publicKeySize, int secretKeySize,
            int signatureSize, int securityLevel, int algorithm) {
        this.name = name;
        this.publicKeySize = publicKeySize;
        this.secretKeySize = secretKeySize;
        this.signatureSize = signatureSize;
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

    public int getSignatureSize() {
        return signatureSize;
    }

    public int getSecurityLevel() {
        return securityLevel;
    }

    public int getAlgorithm() {
        return algorithm;
    }

    @Override
    public String toString() {
        return String.format("SignParams{name='%s', pk=%d, sk=%d, sig=%d, level=%d}",
                name, publicKeySize, secretKeySize, signatureSize, securityLevel);
    }
}