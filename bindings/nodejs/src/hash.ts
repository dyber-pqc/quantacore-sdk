/**
 * Hash operations
 * @module hash
 */

import { getLib, createSizeT, readSizeT, createPointer, derefPointer } from './ffi';
import { checkError } from './errors';
import { HashAlgorithm, HASH_SIZES } from './types';
import type { Device } from './device';

/**
 * Incremental hash context
 */
export class HashContext {
    private ctx: Buffer | null;
    private readonly algorithm: HashAlgorithm;

    constructor(ctx: Buffer, algorithm: HashAlgorithm) {
        this.ctx = ctx;
        this.algorithm = algorithm;
    }

    /**
     * Update the hash with additional data
     * @param data - Data to hash
     * @returns This context for chaining
     */
    update(data: Buffer | string): HashContext {
        if (!this.ctx) {
            throw new Error('Hash context is already finalized');
        }

        const lib = getLib();
        const buf = typeof data === 'string' ? Buffer.from(data) : data;
        const result = lib.quac_hash_update(this.ctx, buf, buf.length);
        checkError(result);

        return this;
    }

    /**
     * Finalize the hash and return the digest
     * @param outputLength - Output length for XOF algorithms (SHAKE)
     * @returns Hash digest
     */
    finalize(outputLength?: number): Buffer {
        if (!this.ctx) {
            throw new Error('Hash context is already finalized');
        }

        const lib = getLib();
        const size = HASH_SIZES[this.algorithm];
        const digestSize = size ?? outputLength ?? 32;

        const digest = Buffer.alloc(digestSize);
        const digestLen = createSizeT(digestSize);

        const result = lib.quac_hash_final(this.ctx, digest, digestLen);
        checkError(result);

        // Free the context
        lib.quac_hash_free(this.ctx);
        this.ctx = null;

        return digest.subarray(0, readSizeT(digestLen));
    }

    /**
     * Check if context is still valid
     */
    get isValid(): boolean {
        return this.ctx !== null;
    }
}

/**
 * Hash operations interface
 *
 * Provides SHA-2, SHA-3, SHAKE, HMAC, and HKDF operations.
 *
 * @example
 * ```typescript
 * const hash = device.hash;
 *
 * // One-shot hash
 * const digest = hash.sha256(Buffer.from('Hello, World!'));
 *
 * // Incremental hash
 * const ctx = hash.createContext(HashAlgorithm.Sha3_256);
 * ctx.update('Hello, ');
 * ctx.update('World!');
 * const digest2 = ctx.finalize();
 *
 * // HMAC
 * const mac = hash.hmac(HashAlgorithm.Sha256, key, message);
 *
 * // HKDF
 * const derivedKey = hash.hkdf(HashAlgorithm.Sha256, ikm, salt, info, 32);
 * ```
 */
export class Hash {
    private readonly device: Device;

    constructor(device: Device) {
        this.device = device;
    }

    /**
     * Compute a hash in one shot
     * @param algorithm - Hash algorithm to use
     * @param data - Data to hash
     * @param outputLength - Output length for XOF algorithms
     * @returns Hash digest
     */
    hash(algorithm: HashAlgorithm, data: Buffer | string, outputLength?: number): Buffer {
        const lib = getLib();
        const handle = this.device.getHandle();

        const buf = typeof data === 'string' ? Buffer.from(data) : data;
        const size = HASH_SIZES[algorithm];
        const digestSize = size ?? outputLength ?? 32;

        const digest = Buffer.alloc(digestSize);
        const digestLen = createSizeT(digestSize);

        const result = lib.quac_hash(handle, algorithm, buf, buf.length, digest, digestLen);
        checkError(result);

        return digest.subarray(0, readSizeT(digestLen));
    }

    /**
     * Create an incremental hash context
     * @param algorithm - Hash algorithm to use
     * @returns Hash context
     */
    createContext(algorithm: HashAlgorithm): HashContext {
        const lib = getLib();
        const handle = this.device.getHandle();

        const ctxPtr = createPointer();
        const result = lib.quac_hash_init(handle, algorithm, ctxPtr);
        checkError(result);

        const ctx = derefPointer(ctxPtr);
        return new HashContext(ctx, algorithm);
    }

    // Convenience methods for SHA-2

    /**
     * Compute SHA-256 hash
     */
    sha256(data: Buffer | string): Buffer {
        return this.hash(HashAlgorithm.Sha256, data);
    }

    /**
     * Compute SHA-384 hash
     */
    sha384(data: Buffer | string): Buffer {
        return this.hash(HashAlgorithm.Sha384, data);
    }

    /**
     * Compute SHA-512 hash
     */
    sha512(data: Buffer | string): Buffer {
        return this.hash(HashAlgorithm.Sha512, data);
    }

    // Convenience methods for SHA-3

    /**
     * Compute SHA3-256 hash
     */
    sha3_256(data: Buffer | string): Buffer {
        return this.hash(HashAlgorithm.Sha3_256, data);
    }

    /**
     * Compute SHA3-384 hash
     */
    sha3_384(data: Buffer | string): Buffer {
        return this.hash(HashAlgorithm.Sha3_384, data);
    }

    /**
     * Compute SHA3-512 hash
     */
    sha3_512(data: Buffer | string): Buffer {
        return this.hash(HashAlgorithm.Sha3_512, data);
    }

    // Convenience methods for SHAKE

    /**
     * Compute SHAKE128 hash
     * @param data - Data to hash
     * @param outputLength - Desired output length in bytes
     */
    shake128(data: Buffer | string, outputLength: number): Buffer {
        return this.hash(HashAlgorithm.Shake128, data, outputLength);
    }

    /**
     * Compute SHAKE256 hash
     * @param data - Data to hash
     * @param outputLength - Desired output length in bytes
     */
    shake256(data: Buffer | string, outputLength: number): Buffer {
        return this.hash(HashAlgorithm.Shake256, data, outputLength);
    }

    /**
     * Compute HMAC
     * @param algorithm - Hash algorithm to use
     * @param key - HMAC key
     * @param data - Data to authenticate
     * @returns MAC
     */
    hmac(algorithm: HashAlgorithm, key: Buffer, data: Buffer | string): Buffer {
        const lib = getLib();
        const handle = this.device.getHandle();

        const buf = typeof data === 'string' ? Buffer.from(data) : data;
        const size = HASH_SIZES[algorithm] ?? 32;

        const mac = Buffer.alloc(size);
        const macLen = createSizeT(size);

        const result = lib.quac_hmac(
            handle,
            algorithm,
            key,
            key.length,
            buf,
            buf.length,
            mac,
            macLen
        );
        checkError(result);

        return mac.subarray(0, readSizeT(macLen));
    }

    /**
     * Compute HMAC-SHA256
     */
    hmacSha256(key: Buffer, data: Buffer | string): Buffer {
        return this.hmac(HashAlgorithm.Sha256, key, data);
    }

    /**
     * Compute HMAC-SHA384
     */
    hmacSha384(key: Buffer, data: Buffer | string): Buffer {
        return this.hmac(HashAlgorithm.Sha384, key, data);
    }

    /**
     * Compute HMAC-SHA512
     */
    hmacSha512(key: Buffer, data: Buffer | string): Buffer {
        return this.hmac(HashAlgorithm.Sha512, key, data);
    }

    /**
     * Derive key using HKDF
     * @param algorithm - Hash algorithm to use
     * @param ikm - Input keying material
     * @param salt - Salt (can be empty)
     * @param info - Context info (can be empty)
     * @param length - Output length in bytes
     * @returns Derived key
     */
    hkdf(
        algorithm: HashAlgorithm,
        ikm: Buffer,
        salt: Buffer,
        info: Buffer,
        length: number
    ): Buffer {
        const lib = getLib();
        const handle = this.device.getHandle();

        const output = Buffer.alloc(length);

        const result = lib.quac_hkdf(
            handle,
            algorithm,
            ikm,
            ikm.length,
            salt,
            salt.length,
            info,
            info.length,
            output,
            length
        );
        checkError(result);

        return output;
    }

    /**
     * Derive key using HKDF-SHA256
     */
    hkdfSha256(ikm: Buffer, salt: Buffer, info: Buffer, length: number): Buffer {
        return this.hkdf(HashAlgorithm.Sha256, ikm, salt, info, length);
    }

    /**
     * Derive key using HKDF-SHA384
     */
    hkdfSha384(ikm: Buffer, salt: Buffer, info: Buffer, length: number): Buffer {
        return this.hkdf(HashAlgorithm.Sha384, ikm, salt, info, length);
    }

    /**
     * Derive key using HKDF-SHA512
     */
    hkdfSha512(ikm: Buffer, salt: Buffer, info: Buffer, length: number): Buffer {
        return this.hkdf(HashAlgorithm.Sha512, ikm, salt, info, length);
    }

    /**
     * Get the digest size for an algorithm
     * @returns Digest size in bytes, or null for XOF algorithms
     */
    getDigestSize(algorithm: HashAlgorithm): number | null {
        return HASH_SIZES[algorithm];
    }
}