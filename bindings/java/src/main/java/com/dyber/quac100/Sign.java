/*
 * Copyright © 2025 Dyber, Inc. All Rights Reserved.
 * QUAC 100 Post-Quantum Cryptographic Accelerator - Java SDK
 */
package com.dyber.quac100;

/**
 * Digital Signature operations.
 * 
 * <p>
 * Provides ML-DSA (Dilithium) post-quantum digital signature functionality.
 * ML-DSA is NIST's standardized lattice-based digital signature algorithm.
 * </p>
 * 
 * <h2>Example Usage:</h2>
 * 
 * <pre>{@code
 * Device device = lib.openFirstDevice();
 * Sign sign = device.sign();
 * 
 * // Generate signing key pair
 * KeyPair keys = sign.generateKeyPair(SignAlgorithm.ML_DSA_65);
 * 
 * // Sign a message
 * byte[] message = "Important document".getBytes(StandardCharsets.UTF_8);
 * byte[] signature = sign.sign(SignAlgorithm.ML_DSA_65, keys.getSecretKey(), message);
 * 
 * // Verify the signature
 * boolean valid = sign.verify(
 *         SignAlgorithm.ML_DSA_65, keys.getPublicKey(), message, signature);
 * System.out.println("Signature valid: " + valid);
 * }</pre>
 * 
 * @author Dyber, Inc.
 * @version 1.0.0
 */
public class Sign {

    private final Device device;

    // Native methods
    private static native SignParams nativeGetParams(long handle, int algorithm);

    private static native KeyPair nativeGenerateKeyPair(long handle, int algorithm);

    private static native byte[] nativeSign(long handle, int algorithm, byte[] secretKey, byte[] message);

    private static native boolean nativeVerify(long handle, int algorithm, byte[] publicKey, byte[] message,
            byte[] signature);

    /**
     * Package-private constructor - instances are created by Device.
     */
    Sign(Device device) {
        this.device = device;
    }

    /**
     * Gets algorithm parameters for the specified signature algorithm.
     * 
     * @param algorithm the signature algorithm
     * @return SignParams containing key sizes, signature size, etc.
     * @throws QuacException if operation fails
     */
    public SignParams getParams(SignAlgorithm algorithm) throws QuacException {
        SignParams params = nativeGetParams(device.getHandle(), algorithm.getValue());
        if (params == null) {
            throw new CryptoException(ErrorCode.INVALID_ALGORITHM,
                    "Failed to get parameters for " + algorithm);
        }
        return params;
    }

    /**
     * Generates a new signing key pair for the specified algorithm.
     * 
     * @param algorithm the signature algorithm
     * @return KeyPair containing public and secret keys
     * @throws QuacException if key generation fails
     */
    public KeyPair generateKeyPair(SignAlgorithm algorithm) throws QuacException {
        KeyPair kp = nativeGenerateKeyPair(device.getHandle(), algorithm.getValue());
        if (kp == null) {
            throw new CryptoException(ErrorCode.CRYPTO_ERROR,
                    "Failed to generate key pair for " + algorithm);
        }
        return kp;
    }

    /**
     * Generates a new ML-DSA-44 signing key pair.
     * 
     * @return KeyPair containing public and secret keys
     * @throws QuacException if key generation fails
     */
    public KeyPair generateKeyPair44() throws QuacException {
        return generateKeyPair(SignAlgorithm.ML_DSA_44);
    }

    /**
     * Generates a new ML-DSA-65 signing key pair.
     * 
     * @return KeyPair containing public and secret keys
     * @throws QuacException if key generation fails
     */
    public KeyPair generateKeyPair65() throws QuacException {
        return generateKeyPair(SignAlgorithm.ML_DSA_65);
    }

    /**
     * Generates a new ML-DSA-87 signing key pair.
     * 
     * @return KeyPair containing public and secret keys
     * @throws QuacException if key generation fails
     */
    public KeyPair generateKeyPair87() throws QuacException {
        return generateKeyPair(SignAlgorithm.ML_DSA_87);
    }

    /**
     * Signs a message.
     * 
     * @param algorithm the signature algorithm
     * @param secretKey the signing secret key
     * @param message   the message to sign
     * @return signature bytes
     * @throws QuacException if signing fails
     */
    public byte[] sign(SignAlgorithm algorithm, byte[] secretKey, byte[] message)
            throws QuacException {
        if (secretKey == null || secretKey.length == 0) {
            throw new IllegalArgumentException("Secret key cannot be null or empty");
        }
        if (message == null) {
            throw new IllegalArgumentException("Message cannot be null");
        }

        byte[] signature = nativeSign(
                device.getHandle(), algorithm.getValue(), secretKey, message);
        if (signature == null) {
            throw new CryptoException(ErrorCode.CRYPTO_ERROR,
                    "Signing failed for " + algorithm);
        }
        return signature;
    }

    /**
     * Signs a message using ML-DSA-44.
     * 
     * @param secretKey the signing secret key
     * @param message   the message to sign
     * @return signature bytes
     * @throws QuacException if signing fails
     */
    public byte[] sign44(byte[] secretKey, byte[] message) throws QuacException {
        return sign(SignAlgorithm.ML_DSA_44, secretKey, message);
    }

    /**
     * Signs a message using ML-DSA-65.
     * 
     * @param secretKey the signing secret key
     * @param message   the message to sign
     * @return signature bytes
     * @throws QuacException if signing fails
     */
    public byte[] sign65(byte[] secretKey, byte[] message) throws QuacException {
        return sign(SignAlgorithm.ML_DSA_65, secretKey, message);
    }

    /**
     * Signs a message using ML-DSA-87.
     * 
     * @param secretKey the signing secret key
     * @param message   the message to sign
     * @return signature bytes
     * @throws QuacException if signing fails
     */
    public byte[] sign87(byte[] secretKey, byte[] message) throws QuacException {
        return sign(SignAlgorithm.ML_DSA_87, secretKey, message);
    }

    /**
     * Verifies a signature.
     * 
     * @param algorithm the signature algorithm
     * @param publicKey the verification public key
     * @param message   the original message
     * @param signature the signature to verify
     * @return true if signature is valid
     * @throws QuacException if verification operation fails
     */
    public boolean verify(SignAlgorithm algorithm, byte[] publicKey, byte[] message,
            byte[] signature) throws QuacException {
        if (publicKey == null || publicKey.length == 0) {
            throw new IllegalArgumentException("Public key cannot be null or empty");
        }
        if (message == null) {
            throw new IllegalArgumentException("Message cannot be null");
        }
        if (signature == null || signature.length == 0) {
            throw new IllegalArgumentException("Signature cannot be null or empty");
        }

        return nativeVerify(
                device.getHandle(), algorithm.getValue(), publicKey, message, signature);
    }

    /**
     * Verifies a signature, throwing an exception if invalid.
     * 
     * @param algorithm the signature algorithm
     * @param publicKey the verification public key
     * @param message   the original message
     * @param signature the signature to verify
     * @throws VerificationException if signature is invalid
     * @throws QuacException         if verification operation fails
     */
    public void verifyOrThrow(SignAlgorithm algorithm, byte[] publicKey, byte[] message,
            byte[] signature) throws QuacException {
        if (!verify(algorithm, publicKey, message, signature)) {
            throw new VerificationException("Signature verification failed");
        }
    }

    /**
     * Verifies using ML-DSA-44.
     * 
     * @param publicKey the verification public key
     * @param message   the original message
     * @param signature the signature to verify
     * @return true if signature is valid
     * @throws QuacException if verification operation fails
     */
    public boolean verify44(byte[] publicKey, byte[] message, byte[] signature)
            throws QuacException {
        return verify(SignAlgorithm.ML_DSA_44, publicKey, message, signature);
    }

    /**
     * Verifies using ML-DSA-65.
     * 
     * @param publicKey the verification public key
     * @param message   the original message
     * @param signature the signature to verify
     * @return true if signature is valid
     * @throws QuacException if verification operation fails
     */
    public boolean verify65(byte[] publicKey, byte[] message, byte[] signature)
            throws QuacException {
        return verify(SignAlgorithm.ML_DSA_65, publicKey, message, signature);
    }

    /**
     * Verifies using ML-DSA-87.
     * 
     * @param publicKey the verification public key
     * @param message   the original message
     * @param signature the signature to verify
     * @return true if signature is valid
     * @throws QuacException if verification operation fails
     */
    public boolean verify87(byte[] publicKey, byte[] message, byte[] signature)
            throws QuacException {
        return verify(SignAlgorithm.ML_DSA_87, publicKey, message, signature);
    }
}