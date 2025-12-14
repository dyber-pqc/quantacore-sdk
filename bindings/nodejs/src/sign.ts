/**
 * Digital Signature operations
 * @module sign
 */

import { getLib, createSizeT, readSizeT } from './ffi';
import { checkError, QuacError, ErrorCode } from './errors';
import { SignAlgorithm, SignKeyPair, SIGN_SIZES } from './types';
import type { Device } from './device';

/**
 * Digital signature operations interface
 *
 * Provides ML-DSA (Dilithium) signature operations.
 *
 * @example
 * ```typescript
 * const sign = device.sign;
 *
 * // Generate key pair
 * const keypair = sign.generateKeypair(SignAlgorithm.MlDsa65);
 *
 * // Sign a message
 * const message = Buffer.from('Hello, World!');
 * const signature = sign.sign(keypair.secretKey, message, SignAlgorithm.MlDsa65);
 *
 * // Verify the signature
 * const isValid = sign.verify(keypair.publicKey, message, signature, SignAlgorithm.MlDsa65);
 * ```
 */
export class Sign {
    private readonly device: Device;

    constructor(device: Device) {
        this.device = device;
    }

    /**
     * Generate a signature key pair
     * @param algorithm - Signature algorithm to use
     * @returns Key pair containing public and secret keys
     */
    generateKeypair(algorithm: SignAlgorithm): SignKeyPair {
        const lib = getLib();
        const handle = this.device.getHandle();
        const sizes = SIGN_SIZES[algorithm];

        const publicKey = Buffer.alloc(sizes.publicKey);
        const secretKey = Buffer.alloc(sizes.secretKey);
        const publicKeyLen = createSizeT(sizes.publicKey);
        const secretKeyLen = createSizeT(sizes.secretKey);

        const result = lib.quac_sign_keygen(
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
     * Generate ML-DSA-44 key pair
     */
    generateKeypair44(): SignKeyPair {
        return this.generateKeypair(SignAlgorithm.MlDsa44);
    }

    /**
     * Generate ML-DSA-65 key pair
     */
    generateKeypair65(): SignKeyPair {
        return this.generateKeypair(SignAlgorithm.MlDsa65);
    }

    /**
     * Generate ML-DSA-87 key pair
     */
    generateKeypair87(): SignKeyPair {
        return this.generateKeypair(SignAlgorithm.MlDsa87);
    }

    /**
     * Sign a message
     * @param secretKey - Signer's secret key
     * @param message - Message to sign
     * @param algorithm - Signature algorithm to use
     * @returns Signature
     */
    sign(secretKey: Buffer, message: Buffer, algorithm: SignAlgorithm): Buffer {
        const lib = getLib();
        const handle = this.device.getHandle();
        const sizes = SIGN_SIZES[algorithm];

        const signature = Buffer.alloc(sizes.signature);
        const signatureLen = createSizeT(sizes.signature);

        const result = lib.quac_sign(
            handle,
            algorithm,
            secretKey,
            secretKey.length,
            message,
            message.length,
            signature,
            signatureLen
        );
        checkError(result);

        return signature.subarray(0, readSizeT(signatureLen));
    }

    /**
     * Sign using ML-DSA-44
     */
    sign44(secretKey: Buffer, message: Buffer): Buffer {
        return this.sign(secretKey, message, SignAlgorithm.MlDsa44);
    }

    /**
     * Sign using ML-DSA-65
     */
    sign65(secretKey: Buffer, message: Buffer): Buffer {
        return this.sign(secretKey, message, SignAlgorithm.MlDsa65);
    }

    /**
     * Sign using ML-DSA-87
     */
    sign87(secretKey: Buffer, message: Buffer): Buffer {
        return this.sign(secretKey, message, SignAlgorithm.MlDsa87);
    }

    /**
     * Verify a signature
     * @param publicKey - Signer's public key
     * @param message - Original message
     * @param signature - Signature to verify
     * @param algorithm - Signature algorithm to use
     * @returns True if signature is valid
     */
    verify(
        publicKey: Buffer,
        message: Buffer,
        signature: Buffer,
        algorithm: SignAlgorithm
    ): boolean {
        const lib = getLib();
        const handle = this.device.getHandle();

        const result = lib.quac_verify(
            handle,
            algorithm,
            publicKey,
            publicKey.length,
            message,
            message.length,
            signature,
            signature.length
        );

        return result === 0;
    }

    /**
     * Verify using ML-DSA-44
     */
    verify44(publicKey: Buffer, message: Buffer, signature: Buffer): boolean {
        return this.verify(publicKey, message, signature, SignAlgorithm.MlDsa44);
    }

    /**
     * Verify using ML-DSA-65
     */
    verify65(publicKey: Buffer, message: Buffer, signature: Buffer): boolean {
        return this.verify(publicKey, message, signature, SignAlgorithm.MlDsa65);
    }

    /**
     * Verify using ML-DSA-87
     */
    verify87(publicKey: Buffer, message: Buffer, signature: Buffer): boolean {
        return this.verify(publicKey, message, signature, SignAlgorithm.MlDsa87);
    }

    /**
     * Verify a signature, throwing if invalid
     * @throws {QuacError} If signature is invalid
     */
    verifyOrThrow(
        publicKey: Buffer,
        message: Buffer,
        signature: Buffer,
        algorithm: SignAlgorithm
    ): void {
        if (!this.verify(publicKey, message, signature, algorithm)) {
            throw new QuacError(ErrorCode.VerificationFailed, 'Signature verification failed');
        }
    }

    /**
     * Get the public key size for an algorithm
     */
    getPublicKeySize(algorithm: SignAlgorithm): number {
        return SIGN_SIZES[algorithm].publicKey;
    }

    /**
     * Get the secret key size for an algorithm
     */
    getSecretKeySize(algorithm: SignAlgorithm): number {
        return SIGN_SIZES[algorithm].secretKey;
    }

    /**
     * Get the maximum signature size for an algorithm
     */
    getSignatureSize(algorithm: SignAlgorithm): number {
        return SIGN_SIZES[algorithm].signature;
    }
}