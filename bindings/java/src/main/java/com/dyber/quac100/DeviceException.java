/*
 * Copyright © 2025 Dyber, Inc. All Rights Reserved.
 * QUAC 100 Post-Quantum Cryptographic Accelerator - Java SDK
 */

package com.dyber.quac100;

/**
 * Exception thrown for device-related errors.
 * 
 * @since 1.0.0
 */
public class DeviceException extends QuacException {

    private static final long serialVersionUID = 1L;

    /**
     * Construct a DeviceException with error code and message.
     *
     * @param errorCode The error code
     * @param message   The error message
     */
    public DeviceException(int errorCode, String message) {
        super(errorCode, message);
    }

    /**
     * Construct a DeviceException with ErrorCode enum and message.
     *
     * @param errorCode The error code enum
     * @param message   The error message
     */
    public DeviceException(ErrorCode errorCode, String message) {
        super(errorCode.getCode(), message);
    }

    /**
     * Construct a DeviceException with error code only.
     *
     * @param errorCode The error code
     */
    public DeviceException(int errorCode) {
        super(errorCode);
    }

    /**
     * Construct a DeviceException with ErrorCode enum only.
     *
     * @param errorCode The error code enum
     */
    public DeviceException(ErrorCode errorCode) {
        super(errorCode.getCode());
    }

    /**
     * Create a device not found exception.
     *
     * @return DeviceException for device not found
     */
    public static DeviceException deviceNotFound() {
        return new DeviceException(ErrorCode.DEVICE_NOT_FOUND, "No QUAC 100 device found");
    }

    /**
     * Create a device busy exception.
     *
     * @return DeviceException for device busy
     */
    public static DeviceException deviceBusy() {
        return new DeviceException(ErrorCode.DEVICE_BUSY, "Device is busy");
    }

    /**
     * Create a device error exception.
     *
     * @param details Additional error details
     * @return DeviceException for device error
     */
    public static DeviceException deviceError(String details) {
        return new DeviceException(ErrorCode.DEVICE_ERROR, "Device error: " + details);
    }
}