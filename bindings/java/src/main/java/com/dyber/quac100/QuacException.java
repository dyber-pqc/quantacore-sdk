/*
 * Copyright © 2025 Dyber, Inc. All Rights Reserved.
 * QUAC 100 Post-Quantum Cryptographic Accelerator - Java SDK
 */

package com.dyber.quac100;

/**
 * Base exception for QUAC 100 operations.
 * 
 * <p>
 * This exception wraps error codes returned by the native library
 * and provides human-readable error messages.
 * </p>
 * 
 * @since 1.0.0
 */
public class QuacException extends Exception {

    private static final long serialVersionUID = 1L;

    private final int errorCode;

    /**
     * Construct a new QuacException with an error code and message.
     * 
     * @param errorCode Native error code
     * @param message   Error message
     */
    public QuacException(int errorCode, String message) {
        super(formatMessage(errorCode, message));
        this.errorCode = errorCode;
    }

    /**
     * Construct a new QuacException with an ErrorCode enum.
     * 
     * @param errorCode Error code enum
     * @param message   Additional error context
     */
    public QuacException(ErrorCode errorCode, String message) {
        this(errorCode.getCode(), message);
    }

    /**
     * Construct a new QuacException with just an error code.
     * 
     * @param errorCode Native error code
     */
    public QuacException(int errorCode) {
        this(errorCode, null);
    }

    /**
     * Construct a new QuacException with ErrorCode enum only.
     * 
     * @param errorCode Error code enum
     */
    public QuacException(ErrorCode errorCode) {
        this(errorCode.getCode(), null);
    }

    /**
     * Construct a new QuacException with error code, message, and cause.
     * 
     * @param errorCode Native error code
     * @param message   Error message
     * @param cause     Underlying cause
     */
    public QuacException(int errorCode, String message, Throwable cause) {
        super(formatMessage(errorCode, message), cause);
        this.errorCode = errorCode;
    }

    /**
     * Get the native error code.
     * 
     * @return Error code
     */
    public int getErrorCode() {
        return errorCode;
    }

    /**
     * Get the ErrorCode enum value, if known.
     * 
     * @return ErrorCode enum or null if code is unknown
     */
    public ErrorCode getErrorCodeEnum() {
        return ErrorCode.fromCode(errorCode);
    }

    /**
     * Check if this is a specific error type.
     * 
     * @param code Error code to check
     * @return true if this exception has the specified error code
     */
    public boolean isError(ErrorCode code) {
        return errorCode == code.getCode();
    }

    /**
     * Format the exception message.
     */
    private static String formatMessage(int errorCode, String message) {
        ErrorCode ec = ErrorCode.fromCode(errorCode);
        StringBuilder sb = new StringBuilder();

        if (ec != null) {
            sb.append(ec.name()).append(" (").append(errorCode).append(")");
        } else {
            sb.append("Error code ").append(errorCode);
        }

        if (message != null && !message.isEmpty()) {
            sb.append(": ").append(message);
        } else if (ec != null) {
            sb.append(": ").append(ec.getDescription());
        }

        return sb.toString();
    }
}