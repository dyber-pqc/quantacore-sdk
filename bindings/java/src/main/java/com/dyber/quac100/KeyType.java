/*
 * Copyright © 2025 Dyber, Inc. All Rights Reserved.
 * QUAC 100 Post-Quantum Cryptographic Accelerator - Java SDK
 */
package com.dyber.quac100;

/**
 * Types of keys that can be stored in the HSM.
 */
public enum KeyType {
    /** Secret/symmetric key */
    SECRET(1),

    /** Public key (asymmetric) */
    PUBLIC(2),

    /** Private key (asymmetric) */
    PRIVATE(3),

    /** Key pair (public + private) */
    KEY_PAIR(4);

    private final int value;

    KeyType(int value) {
        this.value = value;
    }

    /**
     * Gets the native value for this key type.
     * 
     * @return native enum value
     */
    public int getValue() {
        return value;
    }

    /**
     * Converts a native value to the corresponding enum.
     * 
     * @param value native value
     * @return corresponding enum value
     * @throws IllegalArgumentException if value is invalid
     */
    public static KeyType fromValue(int value) {
        for (KeyType type : values()) {
            if (type.value == value) {
                return type;
            }
        }
        throw new IllegalArgumentException("Unknown KeyType value: " + value);
    }
}