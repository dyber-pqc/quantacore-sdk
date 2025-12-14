/*
 * Copyright © 2025 Dyber, Inc. All Rights Reserved.
 * QUAC 100 Post-Quantum Cryptographic Accelerator - Java SDK
 */

package com.dyber.quac100;

/**
 * Error codes returned by QUAC 100 operations.
 * 
 * @since 1.0.0
 */
public enum ErrorCode {

    /** Operation completed successfully */
    SUCCESS(0, "Operation completed successfully"),

    /** Generic error */
    ERROR(-1, "Generic error"),

    /** Invalid parameter */
    INVALID_PARAM(-2, "Invalid parameter"),

    /** Output buffer too small */
    BUFFER_SMALL(-3, "Output buffer too small"),

    /** No QUAC 100 device found */
    DEVICE_NOT_FOUND(-4, "No QUAC 100 device found"),

    /** Device is busy */
    DEVICE_BUSY(-5, "Device is busy"),

    /** Device error */
    DEVICE_ERROR(-6, "Device error"),

    /** Memory allocation failed */
    OUT_OF_MEMORY(-7, "Memory allocation failed"),

    /** Operation not supported */
    NOT_SUPPORTED(-8, "Operation not supported"),

    /** Authentication required */
    AUTH_REQUIRED(-9, "Authentication required"),

    /** Authentication failed */
    AUTH_FAILED(-10, "Authentication failed"),

    /** Key not found */
    KEY_NOT_FOUND(-11, "Key not found"),

    /** Invalid key */
    INVALID_KEY(-12, "Invalid key"),

    /** Signature verification failed */
    VERIFICATION_FAILED(-13, "Signature verification failed"),

    /** Decapsulation failed */
    DECAPS_FAILED(-14, "Decapsulation failed"),

    /** Hardware acceleration unavailable */
    HARDWARE_UNAVAIL(-15, "Hardware acceleration unavailable"),

    /** Operation timed out */
    TIMEOUT(-16, "Operation timed out"),

    /** Library not initialized */
    NOT_INITIALIZED(-17, "Library not initialized"),

    /** Library already initialized */
    ALREADY_INIT(-18, "Library already initialized"),

    /** Invalid handle */
    INVALID_HANDLE(-19, "Invalid handle"),

    /** Operation cancelled */
    CANCELLED(-20, "Operation cancelled"),

    /** Entropy pool depleted */
    ENTROPY_DEPLETED(-21, "Entropy pool depleted"),

    /** Self-test failed */
    SELF_TEST_FAILED(-22, "Self-test failed"),

    /** Tamper detected */
    TAMPER_DETECTED(-23, "Tamper detected"),

    /** Temperature error */
    TEMPERATURE(-24, "Temperature error"),

    /** Power supply error */
    POWER(-25, "Power supply error"),

    /** Invalid algorithm */
    INVALID_ALGORITHM(-26, "Invalid algorithm"),

    /** Cryptographic operation error */
    CRYPTO_ERROR(-27, "Cryptographic operation error"),

    /** Internal error */
    INTERNAL_ERROR(-99, "Internal error"),

    /** Internal error (alias) */
    INTERNAL(-99, "Internal error");

    private final int code;
    private final String description;

    ErrorCode(int code, String description) {
        this.code = code;
        this.description = description;
    }

    /**
     * Get the native error code value.
     * 
     * @return Error code integer
     */
    public int getCode() {
        return code;
    }

    /**
     * Get the error description.
     * 
     * @return Human-readable description
     */
    public String getDescription() {
        return description;
    }

    /**
     * Check if this code indicates success.
     * 
     * @return true if SUCCESS
     */
    public boolean isSuccess() {
        return this == SUCCESS;
    }

    /**
     * Check if this code indicates an error.
     * 
     * @return true if not SUCCESS
     */
    public boolean isError() {
        return this != SUCCESS;
    }

    /**
     * Look up ErrorCode by native code value.
     * 
     * @param code Native error code
     * @return Corresponding ErrorCode or null if unknown
     */
    public static ErrorCode fromCode(int code) {
        for (ErrorCode ec : values()) {
            if (ec.code == code) {
                return ec;
            }
        }
        return null;
    }

    /**
     * Check if a native code indicates success.
     * 
     * @param code Native error code
     * @return true if code == 0
     */
    public static boolean isSuccess(int code) {
        return code == 0;
    }

    /**
     * Throw QuacException if code indicates error.
     * 
     * @param code    Native error code
     * @param message Additional context
     * @throws QuacException if code != SUCCESS
     */
    public static void checkStatus(int code, String message) throws QuacException {
        if (code != 0) {
            throw new QuacException(code, message);
        }
    }

    /**
     * Throw QuacException if code indicates error.
     * 
     * @param code Native error code
     * @throws QuacException if code != SUCCESS
     */
    public static void checkStatus(int code) throws QuacException {
        checkStatus(code, null);
    }
}