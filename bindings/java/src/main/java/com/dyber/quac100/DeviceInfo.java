/*
 * Copyright © 2025 Dyber, Inc. All Rights Reserved.
 * QUAC 100 Post-Quantum Cryptographic Accelerator - Java SDK
 */

package com.dyber.quac100;

/**
 * Information about a QUAC 100 device.
 * 
 * @since 1.0.0
 */
public final class DeviceInfo {

    private final int deviceIndex;
    private final String modelName;
    private final String serialNumber;
    private final String firmwareVersion;
    private final int keySlots;

    /**
     * Construct DeviceInfo (called from JNI).
     */
    public DeviceInfo(int deviceIndex, String modelName, String serialNumber,
            String firmwareVersion, int keySlots) {
        this.deviceIndex = deviceIndex;
        this.modelName = modelName;
        this.serialNumber = serialNumber;
        this.firmwareVersion = firmwareVersion;
        this.keySlots = keySlots;
    }

    /** Get the device index */
    public int getDeviceIndex() {
        return deviceIndex;
    }

    /** Get the model name */
    public String getModelName() {
        return modelName;
    }

    /** Get the serial number */
    public String getSerialNumber() {
        return serialNumber;
    }

    /** Get the firmware version */
    public String getFirmwareVersion() {
        return firmwareVersion;
    }

    /** Get the number of key storage slots */
    public int getKeySlots() {
        return keySlots;
    }

    @Override
    public String toString() {
        return String.format("DeviceInfo{index=%d, model='%s', serial='%s', firmware='%s', keySlots=%d}",
                deviceIndex, modelName, serialNumber, firmwareVersion, keySlots);
    }
}