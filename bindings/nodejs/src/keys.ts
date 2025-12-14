/**
 * HSM Key Storage operations
 * @module keys
 */

import { getLib, createSizeT, readSizeT } from './ffi';
import { checkError, QuacError, ErrorCode } from './errors';
import { KeyType, KeyUsage, KeyInfo } from './types';
import type { Device } from './device';

/**
 * HSM Key Storage interface
 *
 * Provides secure key storage operations on the hardware.
 *
 * @example
 * ```typescript
 * const keys = device.keys;
 *
 * // Store a key
 * const keyData = crypto.randomBytes(32);
 * keys.store(0, KeyType.Secret, 0, KeyUsage.Encrypt | KeyUsage.Decrypt, 'my-key', keyData);
 *
 * // Load a key
 * const loaded = keys.load(0);
 *
 * // Get key info
 * const info = keys.getInfo(0);
 * console.log(`Key: ${info.label}`);
 *
 * // Delete a key
 * keys.delete(0);
 * ```
 */
export class Keys {
    private readonly device: Device;

    constructor(device: Device) {
        this.device = device;
    }

    /**
     * Store a key in the HSM
     * @param slot - Slot number
     * @param keyType - Type of key
     * @param algorithm - Algorithm identifier
     * @param usage - Allowed key usages
     * @param label - Human-readable label
     * @param keyData - Key data
     */
    store(
        slot: number,
        keyType: KeyType,
        algorithm: number,
        usage: KeyUsage,
        label: string,
        keyData: Buffer
    ): void {
        const lib = getLib();
        const handle = this.device.getHandle();

        const result = lib.quac_key_store(
            handle,
            slot,
            keyType,
            algorithm,
            usage,
            label,
            keyData,
            keyData.length
        );
        checkError(result);
    }

    /**
     * Load a key from the HSM
     * @param slot - Slot number
     * @returns Key data
     */
    load(slot: number): Buffer {
        const lib = getLib();
        const handle = this.device.getHandle();

        // Allocate max possible key size
        const keyData = Buffer.alloc(8192);
        const keyDataLen = createSizeT(keyData.length);

        const result = lib.quac_key_load(handle, slot, keyData, keyDataLen);
        checkError(result);

        return keyData.subarray(0, readSizeT(keyDataLen));
    }

    /**
     * Get information about a stored key
     * @param slot - Slot number
     * @returns Key information
     */
    getInfo(slot: number): KeyInfo {
        const lib = getLib();
        const handle = this.device.getHandle();

        const infoBuffer = Buffer.alloc(256);
        const result = lib.quac_key_get_info(handle, slot, infoBuffer);
        checkError(result);

        return {
            slot: infoBuffer.readUInt32LE(0),
            keyType: infoBuffer.readInt32LE(4) as KeyType,
            algorithm: infoBuffer.readInt32LE(8),
            usage: infoBuffer.readUInt32LE(12) as KeyUsage,
            label: infoBuffer.toString('utf8', 16, 80).replace(/\0/g, '').trim(),
            size: infoBuffer.readUInt32LE(80),
            createdAt: new Date(infoBuffer.readUInt32LE(84) * 1000),
        };
    }

    /**
     * Delete a key from the HSM
     * @param slot - Slot number
     */
    delete(slot: number): void {
        const lib = getLib();
        const handle = this.device.getHandle();

        const result = lib.quac_key_delete(handle, slot);
        checkError(result);
    }

    /**
     * List all occupied slots
     * @returns Array of slot numbers
     */
    list(): number[] {
        const lib = getLib();
        const handle = this.device.getHandle();

        // Get slot count first
        const slotCount = this.getSlotCount();
        const slots = Buffer.alloc(slotCount * 4);
        const count = createSizeT(slotCount);

        const result = lib.quac_key_list(handle, slots, count);
        checkError(result);

        const actualCount = readSizeT(count);
        const slotNumbers: number[] = [];
        for (let i = 0; i < actualCount; i++) {
            slotNumbers.push(slots.readUInt32LE(i * 4));
        }

        return slotNumbers;
    }

    /**
     * Get total number of key slots
     */
    getSlotCount(): number {
        const lib = getLib();
        const handle = this.device.getHandle();

        const count = lib.quac_key_get_slot_count(handle);
        if (count < 0) {
            throw QuacError.fromCode(count);
        }
        return count;
    }

    /**
     * Get the first free slot
     * @returns Free slot number, or -1 if no slots available
     */
    getFreeSlot(): number {
        const lib = getLib();
        const handle = this.device.getHandle();

        const slot = lib.quac_key_get_free_slot(handle);
        return slot;
    }

    /**
     * Check if a slot is occupied
     * @param slot - Slot number
     */
    isSlotOccupied(slot: number): boolean {
        try {
            this.getInfo(slot);
            return true;
        } catch (e) {
            if (e instanceof QuacError && e.code === ErrorCode.SlotEmpty) {
                return false;
            }
            throw e;
        }
    }

    /**
     * Clear all keys from the HSM
     * @warning This permanently deletes all stored keys!
     */
    clearAll(): void {
        const lib = getLib();
        const handle = this.device.getHandle();

        const result = lib.quac_key_clear_all(handle);
        checkError(result);
    }

    /**
     * Store a KEM key pair
     * @param publicKeySlot - Slot for public key
     * @param secretKeySlot - Slot for secret key
     * @param algorithm - Algorithm identifier
     * @param label - Label prefix
     * @param publicKey - Public key data
     * @param secretKey - Secret key data
     */
    storeKemKeypair(
        publicKeySlot: number,
        secretKeySlot: number,
        algorithm: number,
        label: string,
        publicKey: Buffer,
        secretKey: Buffer
    ): void {
        this.store(
            publicKeySlot,
            KeyType.Public,
            algorithm,
            KeyUsage.Encrypt,
            `${label}-pub`,
            publicKey
        );
        this.store(
            secretKeySlot,
            KeyType.Private,
            algorithm,
            KeyUsage.Decrypt,
            `${label}-sec`,
            secretKey
        );
    }

    /**
     * Store a signature key pair
     * @param publicKeySlot - Slot for public key
     * @param secretKeySlot - Slot for secret key
     * @param algorithm - Algorithm identifier
     * @param label - Label prefix
     * @param publicKey - Public key data
     * @param secretKey - Secret key data
     */
    storeSignKeypair(
        publicKeySlot: number,
        secretKeySlot: number,
        algorithm: number,
        label: string,
        publicKey: Buffer,
        secretKey: Buffer
    ): void {
        this.store(
            publicKeySlot,
            KeyType.Public,
            algorithm,
            KeyUsage.Verify,
            `${label}-pub`,
            publicKey
        );
        this.store(
            secretKeySlot,
            KeyType.Private,
            algorithm,
            KeyUsage.Sign,
            `${label}-sec`,
            secretKey
        );
    }
}