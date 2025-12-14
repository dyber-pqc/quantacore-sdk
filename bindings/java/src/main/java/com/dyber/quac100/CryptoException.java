/*
 * Copyright © 2025 Dyber, Inc. All Rights Reserved.
 * QUAC 100 Post-Quantum Cryptographic Accelerator - Java SDK
 */

package com.dyber.quac100;

/**
 * Exception thrown for cryptographic operation errors.
 * 
 * @since 1.0.0
 */
public class CryptoException extends QuacException {

    private static final long serialVersionUID = 1L;

    /**
     * Construct a CryptoException with error code and message.
     *
     * @param errorCode The error code
     * @param message   The error message
     */
    public CryptoException(int errorCode, String message) {
        super(errorCode, message);
    }

    /**
     * Construct a CryptoException with ErrorCode enum and message.
     *
     * @param errorCode The error code enum
     * @param message   The error message
     */
    public CryptoException(ErrorCode errorCode, String message) {
        super(errorCode.getCode(), message);
    }

    /**
     * Construct a CryptoException with error code only.
     *
     * @param errorCode The error code
     */
    public CryptoException(int errorCode) {
        super(errorCode);
    }

    /**
     * Construct a CryptoException with ErrorCode enum only.
     *
     * @param errorCode The error code enum
     */
    public CryptoException(ErrorCode errorCode) {
        super(errorCode.getCode());
    }

    /**
     * Construct a CryptoException with error code, message, and cause.
     *
     * @param errorCode The error code
     * @param message   The error message
     * @param cause     The underlying cause
     */
    public CryptoException(int errorCode, String message, Throwable cause) {
        super(errorCode, message, cause);
    }

    /**
     * Construct a CryptoException with ErrorCode enum, message, and cause.
     *
     * @param errorCode The error code enum
     * @param message   The error message
     * @param cause     The underlying cause
     */
    public CryptoException(ErrorCode errorCode, String message, Throwable cause) {
        super(errorCode.getCode(), message, cause);
    }

    /**
     * Create a generic cryptographic error exception.
     *
     * @param message Error details
     * @return CryptoException for crypto error
     */
    public static CryptoException cryptoError(String message) {
        return new CryptoException(ErrorCode.CRYPTO_ERROR, message);
    }

    /**
     * Create an invalid algorithm exception.
     *
     * @param algorithm The invalid algorithm name
     * @return CryptoException for invalid algorithm
     */
    public static CryptoException invalidAlgorithm(String algorithm) {
        return new CryptoException(ErrorCode.INVALID_ALGORITHM, "Invalid algorithm: " + algorithm);
    }

    /**
     * Create a verification failed exception.
     *
     * @return CryptoException for verification failure
     */
    public static CryptoException verificationFailed() {
        return new CryptoException(ErrorCode.VERIFICATION_FAILED, "Signature verification failed");
    }

    /**
     * Create a decapsulation failed exception.
     *
     * @return CryptoException for decapsulation failure
     */
    public static CryptoException decapsulationFailed() {
        return new CryptoException(ErrorCode.DECAPS_FAILED, "KEM decapsulation failed");
    }
}