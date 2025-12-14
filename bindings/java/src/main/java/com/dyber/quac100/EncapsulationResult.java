/*
 * Copyright © 2025 Dyber, Inc. All Rights Reserved.
 * QUAC 100 Post-Quantum Cryptographic Accelerator - Java SDK
 */

package com.dyber.quac100;

import java.util.Arrays;

/**
 * Result of a KEM encapsulation operation.
 * 
 * <p>
 * Contains the ciphertext (to send to the recipient) and the shared secret
 * (for key derivation).
 * </p>
 * 
 * @since 1.0.0
 */
public final class EncapsulationResult implements AutoCloseable {

    private byte[] ciphertext;
    private byte[] sharedSecret;
    private boolean closed = false;

    /**
     * Construct EncapsulationResult.
     *
     * @param ciphertext   The encapsulated ciphertext
     * @param sharedSecret The derived shared secret
     */
    public EncapsulationResult(byte[] ciphertext, byte[] sharedSecret) {
        this.ciphertext = ciphertext != null ? ciphertext.clone() : null;
        this.sharedSecret = sharedSecret != null ? sharedSecret.clone() : null;
    }

    /**
     * Get the ciphertext to send to the recipient.
     * 
     * @return Copy of ciphertext bytes
     * @throws IllegalStateException if result has been closed
     */
    public byte[] getCiphertext() {
        checkNotClosed();
        return ciphertext != null ? ciphertext.clone() : null;
    }

    /**
     * Get the shared secret for key derivation.
     * 
     * @return Copy of shared secret bytes
     * @throws IllegalStateException if result has been closed
     */
    public byte[] getSharedSecret() {
        checkNotClosed();
        return sharedSecret != null ? sharedSecret.clone() : null;
    }

    /**
     * Get the ciphertext size in bytes.
     * 
     * @return Ciphertext size
     */
    public int getCiphertextSize() {
        return ciphertext != null ? ciphertext.length : 0;
    }

    /**
     * Get the shared secret size in bytes.
     * 
     * @return Shared secret size
     */
    public int getSharedSecretSize() {
        return sharedSecret != null ? sharedSecret.length : 0;
    }

    /**
     * Securely clear the sensitive data.
     */
    @Override
    public void close() {
        if (!closed) {
            if (sharedSecret != null) {
                Arrays.fill(sharedSecret, (byte) 0);
                sharedSecret = null;
            }
            if (ciphertext != null) {
                ciphertext = null;
            }
            closed = true;
        }
    }

    private void checkNotClosed() {
        if (closed) {
            throw new IllegalStateException("EncapsulationResult has been closed");
        }
    }

    @Override
    public String toString() {
        if (closed) {
            return "EncapsulationResult{closed}";
        }
        return String.format("EncapsulationResult{ciphertext=%d bytes, sharedSecret=%d bytes}",
                getCiphertextSize(), getSharedSecretSize());
    }
}