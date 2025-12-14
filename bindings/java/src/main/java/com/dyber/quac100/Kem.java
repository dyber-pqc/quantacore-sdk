/*
 * Copyright © 2025 Dyber, Inc. All Rights Reserved.
 * QUAC 100 Post-Quantum Cryptographic Accelerator - Java SDK
 */
package com.dyber.quac100;

/**
 * Key Encapsulation Mechanism (KEM) operations.
 * 
 * <p>
 * Provides ML-KEM (Kyber) post-quantum key exchange functionality.
 * ML-KEM is NIST's standardized lattice-based key encapsulation mechanism.
 * </p>
 * 
 * <h2>Example Usage:</h2>
 * 
 * <pre>{@code
 * Device device = lib.openFirstDevice();
 * Kem kem = device.kem();
 * 
 * // Get algorithm parameters
 * KemParams params = kem.getParams(KemAlgorithm.ML_KEM_768);
 * System.out.println("Public key size: " + params.getPublicKeySize());
 * 
 * // Alice generates a key pair
 * KeyPair aliceKeys = kem.generateKeyPair(KemAlgorithm.ML_KEM_768);
 * 
 * // Alice sends her public key to Bob...
 * 
 * // Bob encapsulates a shared secret
 * EncapsulationResult bobResult = kem.encapsulate(
 *         KemAlgorithm.ML_KEM_768, aliceKeys.getPublicKey());
 * 
 * // Bob sends ciphertext to Alice...
 * 
 * // Alice decapsulates to get the same shared secret
 * byte[] aliceSecret = kem.decapsulate(
 *         KemAlgorithm.ML_KEM_768, aliceKeys.getSecretKey(), bobResult.getCiphertext());
 * 
 * // Both parties now have the same 32-byte shared secret
 * assert Arrays.equals(bobResult.getSharedSecret(), aliceSecret);
 * }</pre>
 * 
 * @author Dyber, Inc.
 * @version 1.0.0
 */
public class Kem {

    private final Device device;

    // Native methods
    private static native KemParams nativeGetParams(long handle, int algorithm);

    private static native KeyPair nativeGenerateKeyPair(long handle, int algorithm);

    private static native EncapsulationResult nativeEncapsulate(long handle, int algorithm, byte[] publicKey);

    private static native byte[] nativeDecapsulate(long handle, int algorithm, byte[] secretKey, byte[] ciphertext);

    /**
     * Package-private constructor - instances are created by Device.
     */
    Kem(Device device) {
        this.device = device;
    }

    /**
     * Gets algorithm parameters for the specified KEM algorithm.
     * 
     * @param algorithm the KEM algorithm
     * @return KemParams containing key sizes, ciphertext size, etc.
     * @throws QuacException if operation fails
     */
    public KemParams getParams(KemAlgorithm algorithm) throws QuacException {
        KemParams params = nativeGetParams(device.getHandle(), algorithm.getValue());
        if (params == null) {
            throw new CryptoException(ErrorCode.INVALID_ALGORITHM,
                    "Failed to get parameters for " + algorithm);
        }
        return params;
    }

    /**
     * Generates a new key pair for the specified algorithm.
     * 
     * @param algorithm the KEM algorithm
     * @return KeyPair containing public and secret keys
     * @throws QuacException if key generation fails
     */
    public KeyPair generateKeyPair(KemAlgorithm algorithm) throws QuacException {
        KeyPair kp = nativeGenerateKeyPair(device.getHandle(), algorithm.getValue());
        if (kp == null) {
            throw new CryptoException(ErrorCode.CRYPTO_ERROR,
                    "Failed to generate key pair for " + algorithm);
        }
        return kp;
    }

    /**
     * Generates a new ML-KEM-512 key pair.
     * 
     * @return KeyPair containing public and secret keys
     * @throws QuacException if key generation fails
     */
    public KeyPair generateKeyPair512() throws QuacException {
        return generateKeyPair(KemAlgorithm.ML_KEM_512);
    }

    /**
     * Generates a new ML-KEM-768 key pair.
     * 
     * @return KeyPair containing public and secret keys
     * @throws QuacException if key generation fails
     */
    public KeyPair generateKeyPair768() throws QuacException {
        return generateKeyPair(KemAlgorithm.ML_KEM_768);
    }

    /**
     * Generates a new ML-KEM-1024 key pair.
     * 
     * @return KeyPair containing public and secret keys
     * @throws QuacException if key generation fails
     */
    public KeyPair generateKeyPair1024() throws QuacException {
        return generateKeyPair(KemAlgorithm.ML_KEM_1024);
    }

    /**
     * Encapsulates a shared secret using the recipient's public key.
     * 
     * @param algorithm the KEM algorithm
     * @param publicKey recipient's public key
     * @return EncapsulationResult containing ciphertext and shared secret
     * @throws QuacException if encapsulation fails
     */
    public EncapsulationResult encapsulate(KemAlgorithm algorithm, byte[] publicKey)
            throws QuacException {
        if (publicKey == null || publicKey.length == 0) {
            throw new IllegalArgumentException("Public key cannot be null or empty");
        }

        EncapsulationResult result = nativeEncapsulate(
                device.getHandle(), algorithm.getValue(), publicKey);
        if (result == null) {
            throw new CryptoException(ErrorCode.CRYPTO_ERROR,
                    "Encapsulation failed for " + algorithm);
        }
        return result;
    }

    /**
     * Encapsulates using ML-KEM-512.
     * 
     * @param publicKey recipient's public key
     * @return EncapsulationResult containing ciphertext and shared secret
     * @throws QuacException if encapsulation fails
     */
    public EncapsulationResult encapsulate512(byte[] publicKey) throws QuacException {
        return encapsulate(KemAlgorithm.ML_KEM_512, publicKey);
    }

    /**
     * Encapsulates using ML-KEM-768.
     * 
     * @param publicKey recipient's public key
     * @return EncapsulationResult containing ciphertext and shared secret
     * @throws QuacException if encapsulation fails
     */
    public EncapsulationResult encapsulate768(byte[] publicKey) throws QuacException {
        return encapsulate(KemAlgorithm.ML_KEM_768, publicKey);
    }

    /**
     * Encapsulates using ML-KEM-1024.
     * 
     * @param publicKey recipient's public key
     * @return EncapsulationResult containing ciphertext and shared secret
     * @throws QuacException if encapsulation fails
     */
    public EncapsulationResult encapsulate1024(byte[] publicKey) throws QuacException {
        return encapsulate(KemAlgorithm.ML_KEM_1024, publicKey);
    }

    /**
     * Decapsulates to recover the shared secret.
     * 
     * @param algorithm  the KEM algorithm
     * @param secretKey  recipient's secret key
     * @param ciphertext the encapsulated ciphertext
     * @return shared secret bytes
     * @throws QuacException if decapsulation fails
     */
    public byte[] decapsulate(KemAlgorithm algorithm, byte[] secretKey, byte[] ciphertext)
            throws QuacException {
        if (secretKey == null || secretKey.length == 0) {
            throw new IllegalArgumentException("Secret key cannot be null or empty");
        }
        if (ciphertext == null || ciphertext.length == 0) {
            throw new IllegalArgumentException("Ciphertext cannot be null or empty");
        }

        byte[] secret = nativeDecapsulate(
                device.getHandle(), algorithm.getValue(), secretKey, ciphertext);
        if (secret == null) {
            throw new CryptoException(ErrorCode.CRYPTO_ERROR,
                    "Decapsulation failed for " + algorithm);
        }
        return secret;
    }

    /**
     * Decapsulates using ML-KEM-512.
     * 
     * @param secretKey  recipient's secret key
     * @param ciphertext the encapsulated ciphertext
     * @return shared secret bytes
     * @throws QuacException if decapsulation fails
     */
    public byte[] decapsulate512(byte[] secretKey, byte[] ciphertext) throws QuacException {
        return decapsulate(KemAlgorithm.ML_KEM_512, secretKey, ciphertext);
    }

    /**
     * Decapsulates using ML-KEM-768.
     * 
     * @param secretKey  recipient's secret key
     * @param ciphertext the encapsulated ciphertext
     * @return shared secret bytes
     * @throws QuacException if decapsulation fails
     */
    public byte[] decapsulate768(byte[] secretKey, byte[] ciphertext) throws QuacException {
        return decapsulate(KemAlgorithm.ML_KEM_768, secretKey, ciphertext);
    }

    /**
     * Decapsulates using ML-KEM-1024.
     * 
     * @param secretKey  recipient's secret key
     * @param ciphertext the encapsulated ciphertext
     * @return shared secret bytes
     * @throws QuacException if decapsulation fails
     */
    public byte[] decapsulate1024(byte[] secretKey, byte[] ciphertext) throws QuacException {
        return decapsulate(KemAlgorithm.ML_KEM_1024, secretKey, ciphertext);
    }
}