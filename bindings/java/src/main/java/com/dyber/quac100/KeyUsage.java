/*
 * Copyright © 2025 Dyber, Inc. All Rights Reserved.
 * QUAC 100 Post-Quantum Cryptographic Accelerator - Java SDK
 */
package com.dyber.quac100;

/**
 * Permitted usage for HSM-stored keys.
 */
public enum KeyUsage {
    /** Key can be used for signing */
    SIGN(1),
    
    /** Key can be used for signature verification */
    VERIFY(2),
    
    /** Key can be used for encryption */
    ENCRYPT(3),
    
    /** Key can be used for decryption */
    DECRYPT(4),
    
    /** Key can be used for key encapsulation */
    ENCAPSULATE(5),
    
    /** Key can be used for key decapsulation */
    DECAPSULATE(6),
    
    /** Key can be used for key derivation */
    DERIVE(7),
    
    /** Key can be used for key wrapping */
    WRAP(8),
    
    /** Key can be used for key unwrapping */
    UNWRAP(9),
    
    /** Key can be used for any purpose */
    ANY(0xFF);
    
    private final int value;
    
    KeyUsage(int value) {
        this.value = value;
    }
    
    /**
     * Gets the native value for this key usage.
     * @return native enum value
     */
    public int getValue() {
        return value;
    }
    
    /**
     * Converts a native value to the corresponding enum.
     * @param value native value
     * @return corresponding enum value
     * @throws IllegalArgumentException if value is invalid
     */
    public static KeyUsage fromValue(int value) {
        for (KeyUsage usage : values()) {
            if (usage.value == value) {
                return usage;
            }
        }
        throw new IllegalArgumentException("Unknown KeyUsage value: " + value);
    }
}