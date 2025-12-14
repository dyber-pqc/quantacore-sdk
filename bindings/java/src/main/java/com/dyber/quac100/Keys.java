/*
 * Copyright © 2025 Dyber, Inc. All Rights Reserved.
 * QUAC 100 Post-Quantum Cryptographic Accelerator - Java SDK
 */
package com.dyber.quac100;

import java.util.ArrayList;
import java.util.List;

/**
 * HSM Key Storage operations.
 * 
 * <p>
 * Provides secure key storage and management using the QUAC 100's
 * integrated Hardware Security Module (HSM). Keys stored in the HSM
 * are protected against extraction and can be used for cryptographic
 * operations without exposing the key material.
 * </p>
 * 
 * <h2>Example Usage:</h2>
 * 
 * <pre>{@code
 * Device device = lib.openFirstDevice();
 * Keys keys = device.keys();
 * 
 * // Store a key
 * keys.store(0, "my-signing-key", KeyType.SECRET,
 *         SignAlgorithm.ML_DSA_65.getValue(), keyData,
 *         KeyUsage.SIGN, false);
 * 
 * // Find key by label
 * int slot = keys.findByLabel("my-signing-key");
 * if (slot >= 0) {
 *     KeyInfo info = keys.getInfo(slot);
 *     System.out.println("Found key: " + info.getLabel());
 * }
 * 
 * // List all keys
 * List<KeyInfo> allKeys = keys.list();
 * for (KeyInfo key : allKeys) {
 *     System.out.println("Slot " + key.getSlot() + ": " + key.getLabel());
 * }
 * }</pre>
 * 
 * @author Dyber, Inc.
 * @version 1.0.0
 */
public class Keys {

    private final Device device;

    // Native methods
    private static native int nativeStore(long handle, int slot, String label,
            int type, int algorithm, byte[] keyData, int usage, boolean exportable);

    private static native int nativeGenerate(long handle, int slot, String label,
            int type, int algorithm, int usage, boolean exportable);

    private static native KeyInfo nativeGetInfo(long handle, int slot);

    private static native int nativeDelete(long handle, int slot);

    private static native byte[] nativeExport(long handle, int slot);

    private static native int nativeFindByLabel(long handle, String label);

    private static native int nativeGetSlotCount(long handle);

    /**
     * Package-private constructor - instances are created by Device.
     */
    Keys(Device device) {
        this.device = device;
    }

    /**
     * Stores a key in the HSM.
     * 
     * @param slot       the slot number (0-based)
     * @param label      human-readable label for the key
     * @param type       the key type
     * @param algorithm  algorithm identifier
     * @param keyData    the key material
     * @param usage      intended usage for the key
     * @param exportable whether the key can be exported
     * @throws QuacException if storage fails
     */
    public void store(int slot, String label, KeyType type, int algorithm,
            byte[] keyData, KeyUsage usage, boolean exportable) throws QuacException {
        if (slot < 0) {
            throw new IllegalArgumentException("Slot must be non-negative");
        }
        if (label == null || label.isEmpty()) {
            throw new IllegalArgumentException("Label cannot be null or empty");
        }
        if (keyData == null || keyData.length == 0) {
            throw new IllegalArgumentException("Key data cannot be null or empty");
        }

        int result = nativeStore(device.getHandle(), slot, label, type.getValue(),
                algorithm, keyData, usage.getValue(), exportable);
        if (result != 0) {
            throw new QuacException(ErrorCode.fromCode(result),
                    "Failed to store key in slot " + slot);
        }
    }

    /**
     * Generates a key directly in the HSM.
     * 
     * @param slot       the slot number (0-based)
     * @param label      human-readable label for the key
     * @param type       the key type
     * @param algorithm  algorithm identifier
     * @param usage      intended usage for the key
     * @param exportable whether the key can be exported
     * @throws QuacException if generation fails
     */
    public void generate(int slot, String label, KeyType type, int algorithm,
            KeyUsage usage, boolean exportable) throws QuacException {
        if (slot < 0) {
            throw new IllegalArgumentException("Slot must be non-negative");
        }
        if (label == null || label.isEmpty()) {
            throw new IllegalArgumentException("Label cannot be null or empty");
        }

        int result = nativeGenerate(device.getHandle(), slot, label, type.getValue(),
                algorithm, usage.getValue(), exportable);
        if (result != 0) {
            throw new QuacException(ErrorCode.fromCode(result),
                    "Failed to generate key in slot " + slot);
        }
    }

    /**
     * Gets information about a key in a slot.
     * 
     * @param slot the slot number
     * @return KeyInfo describing the key, or null if slot is empty
     * @throws QuacException if operation fails
     */
    public KeyInfo getInfo(int slot) throws QuacException {
        if (slot < 0) {
            throw new IllegalArgumentException("Slot must be non-negative");
        }
        return nativeGetInfo(device.getHandle(), slot);
    }

    /**
     * Deletes a key from a slot.
     * 
     * @param slot the slot number
     * @throws QuacException if deletion fails
     */
    public void delete(int slot) throws QuacException {
        if (slot < 0) {
            throw new IllegalArgumentException("Slot must be non-negative");
        }

        int result = nativeDelete(device.getHandle(), slot);
        if (result != 0) {
            throw new QuacException(ErrorCode.fromCode(result),
                    "Failed to delete key in slot " + slot);
        }
    }

    /**
     * Alias for delete().
     * 
     * @param slot the slot number
     * @throws QuacException if deletion fails
     */
    public void remove(int slot) throws QuacException {
        delete(slot);
    }

    /**
     * Exports a key from a slot.
     * 
     * <p>
     * Only keys marked as exportable can be exported.
     * </p>
     * 
     * @param slot the slot number
     * @return key material, or null if key is not exportable
     * @throws QuacException if export fails
     */
    public byte[] export(int slot) throws QuacException {
        if (slot < 0) {
            throw new IllegalArgumentException("Slot must be non-negative");
        }
        return nativeExport(device.getHandle(), slot);
    }

    /**
     * Finds a key by its label.
     * 
     * @param label the key label to search for
     * @return slot number containing the key, or -1 if not found
     * @throws QuacException if operation fails
     */
    public int findByLabel(String label) throws QuacException {
        if (label == null || label.isEmpty()) {
            throw new IllegalArgumentException("Label cannot be null or empty");
        }
        return nativeFindByLabel(device.getHandle(), label);
    }

    /**
     * Gets the total number of key slots available.
     * 
     * @return number of slots
     * @throws QuacException if operation fails
     */
    public int getSlotCount() throws QuacException {
        return nativeGetSlotCount(device.getHandle());
    }

    /**
     * Lists all stored keys.
     * 
     * @return list of KeyInfo for all occupied slots
     * @throws QuacException if operation fails
     */
    public List<KeyInfo> list() throws QuacException {
        int count = getSlotCount();
        List<KeyInfo> keys = new ArrayList<>();

        for (int i = 0; i < count; i++) {
            KeyInfo info = getInfo(i);
            if (info != null) {
                keys.add(info);
            }
        }

        return keys;
    }

    /**
     * Checks if a slot contains a key.
     * 
     * @param slot the slot number
     * @return true if slot contains a key
     * @throws QuacException if operation fails
     */
    public boolean isOccupied(int slot) throws QuacException {
        return getInfo(slot) != null;
    }

    /**
     * Finds the first empty slot.
     * 
     * @return slot number of first empty slot, or -1 if all slots are full
     * @throws QuacException if operation fails
     */
    public int findEmptySlot() throws QuacException {
        int count = getSlotCount();
        for (int i = 0; i < count; i++) {
            if (!isOccupied(i)) {
                return i;
            }
        }
        return -1;
    }

    /**
     * Clears all keys from the HSM.
     * 
     * <p>
     * <strong>Warning:</strong> This permanently deletes all stored keys!
     * </p>
     * 
     * @throws QuacException if operation fails
     */
    public void clearAll() throws QuacException {
        int count = getSlotCount();
        for (int i = 0; i < count; i++) {
            if (isOccupied(i)) {
                delete(i);
            }
        }
    }
}