/*
 * Copyright © 2025 Dyber, Inc. All Rights Reserved.
 * QUAC 100 Post-Quantum Cryptographic Accelerator - Java SDK
 */
package com.dyber.quac100;

/**
 * Exception thrown when signature verification fails.
 */
public class VerificationException extends CryptoException {

    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new VerificationException.
     * 
     * @param message the detail message
     */
    public VerificationException(String message) {
        super(ErrorCode.VERIFICATION_FAILED, message);
    }

    /**
     * Constructs a new VerificationException with a cause.
     * 
     * @param message the detail message
     * @param cause   the cause
     */
    public VerificationException(String message, Throwable cause) {
        super(ErrorCode.VERIFICATION_FAILED, message, cause);
    }
}