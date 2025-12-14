/**
 * Key Encapsulation Mechanism operations
 * @module kem
 */

import { getLib, createSizeT, readSizeT } from './ffi';
import { checkError } from './errors';
import { KemAlgorithm, KemKeyPair, EncapsulationResult, KEM_SIZES } from './types';
import type { Device } from './device';

/**
 * KEM operations interface
 *
 * Provides ML-KEM (Kyber) key encapsulation operations.
 *
 * @example
 * ```typescript
 * const kem = device.kem;
 *
 * // Generate key pair
 * const keypair = kem.generateKeypair(KemAlgorithm.MlKem768);
 *
 * // Encapsulate (sender)
 * const { ciphertext, sharedSecret } = kem.encapsulate(keypair.publicKey, KemAlgorithm.MlKem768);
 *
 * // Decapsulate (receiver)
 * const decapSecret = kem.decapsulate(keypair.secretKey, ciphertext, KemAlgorithm.MlKem768);
 *
 * // sharedSecret and decapSecret are equal
 * ```
 */
export class Kem {
    private readonly device: Device;

    constructor(device: Device) {
        this.device = device;
    }

    /**
     * Generate a KEM key pair
     * @param algorithm - KEM algorithm to use
     * @returns Key pair containing public and secret keys
     */
    generateKeypair(algorithm: KemAlgorithm): KemKeyPair {
        const lib = getLib();
        const handle = this.device.getHandle();
        const sizes = KEM_SIZES[algorithm];

        const publicKey = Buffer.alloc(sizes.publicKey);
        const secretKey = Buffer.alloc(sizes.secretKey);
        const publicKeyLen = createSizeT(sizes.publicKey);
        const secretKeyLen = createSizeT(sizes.secretKey);

        const result = lib.quac_kem_keygen(
            handle,
            algorithm,
            publicKey,
            publicKeyLen,
            secretKey,
            secretKeyLen
        );
        checkError(result);

        return {
            publicKey: publicKey.subarray(0, readSizeT(publicKeyLen)),
            secretKey: secretKey.subarray(0, readSizeT(secretKeyLen)),
        };
    }

    /**
     * Generate ML-KEM-512 key pair
     */
    generateKeypair512(): KemKeyPair {
        return this.generateKeypair(KemAlgorithm.MlKem512);
    }

    /**
     * Generate ML-KEM-768 key pair
     */
    generateKeypair768(): KemKeyPair {
        return this.generateKeypair(KemAlgorithm.MlKem768);
    }

    /**
     * Generate ML-KEM-1024 key pair
     */
    generateKeypair1024(): KemKeyPair {
        return this.generateKeypair(KemAlgorithm.MlKem1024);
    }

    /**
     * Encapsulate a shared secret using a public key
     * @param publicKey - Recipient's public key
     * @param algorithm - KEM algorithm to use
     * @returns Ciphertext and shared secret
     */
    encapsulate(publicKey: Buffer, algorithm: KemAlgorithm): EncapsulationResult {
        const lib = getLib();
        const handle = this.device.getHandle();
        const sizes = KEM_SIZES[algorithm];

        const ciphertext = Buffer.alloc(sizes.ciphertext);
        const sharedSecret = Buffer.alloc(sizes.sharedSecret);
        const ciphertextLen = createSizeT(sizes.ciphertext);
        const sharedSecretLen = createSizeT(sizes.sharedSecret);

        const result = lib.quac_kem_encapsulate(
            handle,
            algorithm,
            publicKey,
            publicKey.length,
            ciphertext,
            ciphertextLen,
            sharedSecret,
            sharedSecretLen
        );
        checkError(result);

        return {
            ciphertext: ciphertext.subarray(0, readSizeT(ciphertextLen)),
            sharedSecret: sharedSecret.subarray(0, readSizeT(sharedSecretLen)),
        };
    }

    /**
     * Encapsulate using ML-KEM-512
     */
    encapsulate512(publicKey: Buffer): EncapsulationResult {
        return this.encapsulate(publicKey, KemAlgorithm.MlKem512);
    }

    /**
     * Encapsulate using ML-KEM-768
     */
    encapsulate768(publicKey: Buffer): EncapsulationResult {
        return this.encapsulate(publicKey, KemAlgorithm.MlKem768);
    }

    /**
     * Encapsulate using ML-KEM-1024
     */
    encapsulate1024(publicKey: Buffer): EncapsulationResult {
        return this.encapsulate(publicKey, KemAlgorithm.MlKem1024);
    }

    /**
     * Decapsulate a ciphertext using a secret key
     * @param secretKey - Recipient's secret key
     * @param ciphertext - Ciphertext from encapsulation
     * @param algorithm - KEM algorithm to use
     * @returns Shared secret
     */
    decapsulate(secretKey: Buffer, ciphertext: Buffer, algorithm: KemAlgorithm): Buffer {
        const lib = getLib();
        const handle = this.device.getHandle();
        const sizes = KEM_SIZES[algorithm];

        const sharedSecret = Buffer.alloc(sizes.sharedSecret);
        const sharedSecretLen = createSizeT(sizes.sharedSecret);

        const result = lib.quac_kem_decapsulate(
            handle,
            algorithm,
            secretKey,
            secretKey.length,
            ciphertext,
            ciphertext.length,
            sharedSecret,
            sharedSecretLen
        );
        checkError(result);

        return sharedSecret.subarray(0, readSizeT(sharedSecretLen));
    }

    /**
     * Decapsulate using ML-KEM-512
     */
    decapsulate512(secretKey: Buffer, ciphertext: Buffer): Buffer {
        return this.decapsulate(secretKey, ciphertext, KemAlgorithm.MlKem512);
    }

    /**
     * Decapsulate using ML-KEM-768
     */
    decapsulate768(secretKey: Buffer, ciphertext: Buffer): Buffer {
        return this.decapsulate(secretKey, ciphertext, KemAlgorithm.MlKem768);
    }

    /**
     * Decapsulate using ML-KEM-1024
     */
    decapsulate1024(secretKey: Buffer, ciphertext: Buffer): Buffer {
        return this.decapsulate(secretKey, ciphertext, KemAlgorithm.MlKem1024);
    }

    /**
     * Get the public key size for an algorithm
     */
    getPublicKeySize(algorithm: KemAlgorithm): number {
        return KEM_SIZES[algorithm].publicKey;
    }

    /**
     * Get the secret key size for an algorithm
     */
    getSecretKeySize(algorithm: KemAlgorithm): number {
        return KEM_SIZES[algorithm].secretKey;
    }

    /**
     * Get the ciphertext size for an algorithm
     */
    getCiphertextSize(algorithm: KemAlgorithm): number {
        return KEM_SIZES[algorithm].ciphertext;
    }

    /**
     * Get the shared secret size (always 32 bytes)
     */
    getSharedSecretSize(): number {
        return 32;
    }
}