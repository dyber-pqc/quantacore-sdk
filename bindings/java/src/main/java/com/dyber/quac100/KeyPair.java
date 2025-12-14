/*
 * Copyright © 2025 Dyber, Inc. All Rights Reserved.
 * QUAC 100 Post-Quantum Cryptographic Accelerator - Java SDK
 */

package com.dyber.quac100;

import java.util.Arrays;

/**
 * A cryptographic key pair (public key + secret key).
 * 
 * <p>
 * This class implements AutoCloseable to ensure sensitive key material
 * is securely zeroed when no longer needed.
 * </p>
 * 
 * @since 1.0.0
 */
public final class KeyPair implements AutoCloseable {

    private byte[] publicKey;
    private byte[] secretKey;
    private boolean closed = false;

    /**
     * Construct KeyPair.
     *
     * @param publicKey The public key bytes
     * @param secretKey The secret key bytes
     */
    public KeyPair(byte[] publicKey, byte[] secretKey) {
        this.publicKey = publicKey != null ? publicKey.clone() : null;
        this.secretKey = secretKey != null ? secretKey.clone() : null;
    }

    /**
     * Get the public key.
     * 
     * @return Copy of public key bytes
     * @throws IllegalStateException if key pair has been closed
     */
    public byte[] getPublicKey() {
        checkNotClosed();
        return publicKey != null ? publicKey.clone() : null;
    }

    /**
     * Get the secret key.
     * 
     * <p>
     * <b>Security Note:</b> The returned array contains sensitive data.
     * Clear it when done.
     * </p>
     * 
     * @return Copy of secret key bytes
     * @throws IllegalStateException if key pair has been closed
     */
    public byte[] getSecretKey() {
        checkNotClosed();
        return secretKey != null ? secretKey.clone() : null;
    }

    /**
     * Get the public key size in bytes.
     * 
     * @return Public key size
     */
    public int getPublicKeySize() {
        return publicKey != null ? publicKey.length : 0;
    }

    /**
     * Get the secret key size in bytes.
     * 
     * @return Secret key size
     */
    public int getSecretKeySize() {
        return secretKey != null ? secretKey.length : 0;
    }

    /**
     * Securely clear the key material.
     */
    @Override
    public void close() {
        if (!closed) {
            if (secretKey != null) {
                Arrays.fill(secretKey, (byte) 0);
                secretKey = null;
            }
            if (publicKey != null) {
                Arrays.fill(publicKey, (byte) 0);
                publicKey = null;
            }
            closed = true;
        }
    }

    private void checkNotClosed() {
        if (closed) {
            throw new IllegalStateException("KeyPair has been closed");
        }
    }

    @Override
    public String toString() {
        if (closed) {
            return "KeyPair{closed}";
        }
        return String.format("KeyPair{publicKey=%d bytes, secretKey=%d bytes}",
                getPublicKeySize(), getSecretKeySize());
    }
}