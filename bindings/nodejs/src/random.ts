/**
 * Random number generation using QRNG
 * @module random
 */

import { getLib } from './ffi';
import { checkError } from './errors';
import { EntropyStatus } from './types';
import type { Device } from './device';

/**
 * Random number generator interface
 *
 * Provides quantum random number generation using hardware QRNG.
 *
 * @example
 * ```typescript
 * const random = device.random;
 *
 * // Generate random bytes
 * const bytes = random.bytes(32);
 *
 * // Generate random integer
 * const num = random.int(1, 100);
 *
 * // Generate UUID
 * const uuid = random.uuid();
 *
 * // Shuffle array
 * const items = [1, 2, 3, 4, 5];
 * random.shuffle(items);
 * ```
 */
export class Random {
    private readonly device: Device;

    constructor(device: Device) {
        this.device = device;
    }

    /**
     * Generate random bytes
     * @param length - Number of bytes to generate
     * @returns Buffer containing random bytes
     */
    bytes(length: number): Buffer {
        const lib = getLib();
        const handle = this.device.getHandle();

        const buffer = Buffer.alloc(length);
        const result = lib.quac_random_bytes(handle, buffer, length);
        checkError(result);

        return buffer;
    }

    /**
     * Fill a buffer with random bytes
     * @param buffer - Buffer to fill
     */
    fill(buffer: Buffer): void {
        const lib = getLib();
        const handle = this.device.getHandle();

        const result = lib.quac_random_bytes(handle, buffer, buffer.length);
        checkError(result);
    }

    /**
     * Generate a random unsigned 8-bit integer
     */
    uint8(): number {
        return this.bytes(1).readUInt8(0);
    }

    /**
     * Generate a random unsigned 16-bit integer
     */
    uint16(): number {
        return this.bytes(2).readUInt16LE(0);
    }

    /**
     * Generate a random unsigned 32-bit integer
     */
    uint32(): number {
        return this.bytes(4).readUInt32LE(0);
    }

    /**
     * Generate a random unsigned 64-bit integer as BigInt
     */
    uint64(): bigint {
        return this.bytes(8).readBigUInt64LE(0);
    }

    /**
     * Generate a random signed 32-bit integer
     */
    int32(): number {
        return this.bytes(4).readInt32LE(0);
    }

    /**
     * Generate a random signed 64-bit integer as BigInt
     */
    int64(): bigint {
        return this.bytes(8).readBigInt64LE(0);
    }

    /**
     * Generate a random integer in range [0, max)
     * @param max - Exclusive upper bound
     */
    uint32Bounded(max: number): number {
        if (max <= 0) {
            throw new Error('max must be positive');
        }
        // Use rejection sampling to avoid bias
        const threshold = (0x100000000 - max) % max;
        let value: number;
        do {
            value = this.uint32();
        } while (value < threshold);
        return value % max;
    }

    /**
     * Generate a random integer in range [min, max]
     * @param min - Inclusive lower bound
     * @param max - Inclusive upper bound
     */
    int(min: number, max: number): number {
        if (min > max) {
            throw new Error('min must be <= max');
        }
        const range = max - min + 1;
        return min + this.uint32Bounded(range);
    }

    /**
     * Generate a random float in range [0, 1)
     */
    float(): number {
        return this.uint32() / 0x100000000;
    }

    /**
     * Generate a random double in range [0, 1)
     */
    double(): number {
        const high = this.uint32() * 0x100000000;
        const low = this.uint32();
        return (high + low) / 0x10000000000000000;
    }

    /**
     * Generate a random float in range [min, max)
     * @param min - Inclusive lower bound
     * @param max - Exclusive upper bound
     */
    uniform(min: number, max: number): number {
        return min + this.float() * (max - min);
    }

    /**
     * Generate a random boolean
     * @param probability - Probability of true (default 0.5)
     */
    bool(probability: number = 0.5): boolean {
        return this.float() < probability;
    }

    /**
     * Generate a random UUID v4
     */
    uuid(): string {
        const bytes = this.bytes(16);

        // Set version (4) and variant (10xx)
        bytes[6] = (bytes[6]! & 0x0f) | 0x40;
        bytes[8] = (bytes[8]! & 0x3f) | 0x80;

        const hex = bytes.toString('hex');
        return [
            hex.slice(0, 8),
            hex.slice(8, 12),
            hex.slice(12, 16),
            hex.slice(16, 20),
            hex.slice(20, 32),
        ].join('-');
    }

    /**
     * Select a random element from an array
     * @param array - Array to choose from
     * @returns Random element, or undefined if array is empty
     */
    choice<T>(array: readonly T[]): T | undefined {
        if (array.length === 0) {
            return undefined;
        }
        const index = this.uint32Bounded(array.length);
        return array[index];
    }

    /**
     * Select multiple random elements from an array (without replacement)
     * @param array - Array to choose from
     * @param count - Number of elements to select
     * @returns Array of selected elements
     */
    sample<T>(array: readonly T[], count: number): T[] {
        if (count > array.length) {
            throw new Error('count must be <= array length');
        }
        if (count <= 0) {
            return [];
        }

        // Fisher-Yates shuffle on a copy, then take first n
        const copy = [...array];
        for (let i = copy.length - 1; i > copy.length - count - 1 && i > 0; i--) {
            const j = this.uint32Bounded(i + 1);
            [copy[i], copy[j]] = [copy[j]!, copy[i]!];
        }
        return copy.slice(-count);
    }

    /**
     * Shuffle an array in place
     * @param array - Array to shuffle
     * @returns The same array, shuffled
     */
    shuffle<T>(array: T[]): T[] {
        for (let i = array.length - 1; i > 0; i--) {
            const j = this.uint32Bounded(i + 1);
            [array[i], array[j]] = [array[j]!, array[i]!];
        }
        return array;
    }

    /**
     * Create a shuffled copy of an array
     * @param array - Array to shuffle
     * @returns New shuffled array
     */
    shuffled<T>(array: readonly T[]): T[] {
        return this.shuffle([...array]);
    }

    /**
     * Generate a random hex string
     * @param length - Number of hex characters (must be even)
     */
    hex(length: number): string {
        if (length % 2 !== 0) {
            throw new Error('length must be even');
        }
        return this.bytes(length / 2).toString('hex');
    }

    /**
     * Generate a random base64 string
     * @param length - Number of random bytes to encode
     */
    base64(length: number): string {
        return this.bytes(length).toString('base64');
    }

    /**
     * Generate a random alphanumeric string
     * @param length - Length of string
     */
    alphanumeric(length: number): string {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        let result = '';
        for (let i = 0; i < length; i++) {
            result += chars[this.uint32Bounded(chars.length)];
        }
        return result;
    }

    /**
     * Get entropy status
     * @returns Entropy status information
     */
    getEntropyStatus(): EntropyStatus {
        const lib = getLib();
        const handle = this.device.getHandle();

        const statusBuffer = Buffer.alloc(16);
        const result = lib.quac_get_entropy_status(handle, statusBuffer);
        checkError(result);

        return {
            level: statusBuffer.readUInt32LE(0),
            isHealthy: statusBuffer.readUInt8(4) !== 0,
            bytesAvailable: statusBuffer.readUInt32LE(8),
        };
    }
}