/*
 * Copyright © 2025 Dyber, Inc. All Rights Reserved.
 * QUAC 100 Post-Quantum Cryptographic Accelerator - Java SDK
 */
package com.dyber.quac100;

import java.nio.charset.StandardCharsets;

/**
 * Hardware-accelerated hash operations.
 * 
 * <p>
 * Provides SHA-2, SHA-3, SHAKE, HMAC, and HKDF operations using
 * the QUAC 100's dedicated hash acceleration engine.
 * </p>
 * 
 * <h2>Example Usage:</h2>
 * 
 * <pre>{@code
 * Device device = lib.openFirstDevice();
 * Hash hash = device.hash();
 * 
 * // One-shot hashing
 * byte[] sha256 = hash.sha256("Hello, World!".getBytes());
 * byte[] sha3_256 = hash.sha3_256("Hello, World!".getBytes());
 * 
 * // Variable-length SHAKE output
 * byte[] shake = hash.shake256("data".getBytes(), 64);
 * 
 * // Incremental hashing
 * HashContext ctx = hash.createContext(HashAlgorithm.SHA256);
 * ctx.update("chunk1".getBytes());
 * ctx.update("chunk2".getBytes());
 * byte[] result = ctx.digest();
 * 
 * // HMAC
 * byte[] mac = hash.hmac(HashAlgorithm.SHA256, key, data);
 * 
 * // Key derivation
 * byte[] derivedKey = hash.hkdf(HashAlgorithm.SHA256, ikm, salt, info, 32);
 * }</pre>
 * 
 * @author Dyber, Inc.
 * @version 1.0.0
 */
public class Hash {

    private final Device device;

    // Native methods
    private static native byte[] nativeHash(long handle, int algorithm, byte[] data);

    private static native byte[] nativeShake(long handle, int algorithm, byte[] data, int outputLen);

    private static native byte[] nativeHmac(long handle, int algorithm, byte[] key, byte[] data);

    private static native byte[] nativeHkdf(long handle, int algorithm, byte[] ikm, byte[] salt, byte[] info,
            int outputLen);

    private static native long nativeCreateContext(long handle, int algorithm);

    private static native int nativeContextUpdate(long contextHandle, byte[] data);

    private static native byte[] nativeContextFinalize(long contextHandle);

    private static native void nativeContextFree(long contextHandle);

    /**
     * Package-private constructor - instances are created by Device.
     */
    Hash(Device device) {
        this.device = device;
    }

    /**
     * Computes a hash using the specified algorithm.
     * 
     * @param algorithm the hash algorithm
     * @param data      the data to hash
     * @return hash digest
     * @throws QuacException if operation fails
     */
    public byte[] hash(HashAlgorithm algorithm, byte[] data) throws QuacException {
        if (data == null) {
            throw new IllegalArgumentException("Data cannot be null");
        }

        byte[] result = nativeHash(device.getHandle(), algorithm.getValue(), data);
        if (result == null) {
            throw new QuacException(ErrorCode.CRYPTO_ERROR,
                    "Hash operation failed for " + algorithm);
        }
        return result;
    }

    /**
     * Computes SHA-256 hash.
     * 
     * @param data the data to hash
     * @return 32-byte hash digest
     * @throws QuacException if operation fails
     */
    public byte[] sha256(byte[] data) throws QuacException {
        return hash(HashAlgorithm.SHA256, data);
    }

    /**
     * Computes SHA-256 hash of a string.
     * 
     * @param data the string to hash (UTF-8 encoded)
     * @return 32-byte hash digest
     * @throws QuacException if operation fails
     */
    public byte[] sha256(String data) throws QuacException {
        return sha256(data.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Computes SHA-384 hash.
     * 
     * @param data the data to hash
     * @return 48-byte hash digest
     * @throws QuacException if operation fails
     */
    public byte[] sha384(byte[] data) throws QuacException {
        return hash(HashAlgorithm.SHA384, data);
    }

    /**
     * Computes SHA-512 hash.
     * 
     * @param data the data to hash
     * @return 64-byte hash digest
     * @throws QuacException if operation fails
     */
    public byte[] sha512(byte[] data) throws QuacException {
        return hash(HashAlgorithm.SHA512, data);
    }

    /**
     * Computes SHA3-256 hash.
     * 
     * @param data the data to hash
     * @return 32-byte hash digest
     * @throws QuacException if operation fails
     */
    public byte[] sha3_256(byte[] data) throws QuacException {
        return hash(HashAlgorithm.SHA3_256, data);
    }

    /**
     * Computes SHA3-512 hash.
     * 
     * @param data the data to hash
     * @return 64-byte hash digest
     * @throws QuacException if operation fails
     */
    public byte[] sha3_512(byte[] data) throws QuacException {
        return hash(HashAlgorithm.SHA3_512, data);
    }

    /**
     * Computes SHAKE128 extendable output.
     * 
     * @param data         the data to hash
     * @param outputLength desired output length in bytes
     * @return hash output of specified length
     * @throws QuacException if operation fails
     */
    public byte[] shake128(byte[] data, int outputLength) throws QuacException {
        if (data == null) {
            throw new IllegalArgumentException("Data cannot be null");
        }
        if (outputLength <= 0) {
            throw new IllegalArgumentException("Output length must be positive");
        }

        byte[] result = nativeShake(device.getHandle(), HashAlgorithm.SHAKE128.getValue(),
                data, outputLength);
        if (result == null) {
            throw new QuacException(ErrorCode.CRYPTO_ERROR, "SHAKE128 operation failed");
        }
        return result;
    }

    /**
     * Computes SHAKE256 extendable output.
     * 
     * @param data         the data to hash
     * @param outputLength desired output length in bytes
     * @return hash output of specified length
     * @throws QuacException if operation fails
     */
    public byte[] shake256(byte[] data, int outputLength) throws QuacException {
        if (data == null) {
            throw new IllegalArgumentException("Data cannot be null");
        }
        if (outputLength <= 0) {
            throw new IllegalArgumentException("Output length must be positive");
        }

        byte[] result = nativeShake(device.getHandle(), HashAlgorithm.SHAKE256.getValue(),
                data, outputLength);
        if (result == null) {
            throw new QuacException(ErrorCode.CRYPTO_ERROR, "SHAKE256 operation failed");
        }
        return result;
    }

    /**
     * Computes HMAC using the specified hash algorithm.
     * 
     * @param algorithm the hash algorithm
     * @param key       the HMAC key
     * @param data      the data to authenticate
     * @return HMAC value
     * @throws QuacException if operation fails
     */
    public byte[] hmac(HashAlgorithm algorithm, byte[] key, byte[] data) throws QuacException {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException("Key cannot be null or empty");
        }
        if (data == null) {
            throw new IllegalArgumentException("Data cannot be null");
        }

        byte[] result = nativeHmac(device.getHandle(), algorithm.getValue(), key, data);
        if (result == null) {
            throw new QuacException(ErrorCode.CRYPTO_ERROR,
                    "HMAC operation failed for " + algorithm);
        }
        return result;
    }

    /**
     * Computes HMAC-SHA256.
     * 
     * @param key  the HMAC key
     * @param data the data to authenticate
     * @return 32-byte HMAC value
     * @throws QuacException if operation fails
     */
    public byte[] hmacSha256(byte[] key, byte[] data) throws QuacException {
        return hmac(HashAlgorithm.SHA256, key, data);
    }

    /**
     * Computes HMAC-SHA512.
     * 
     * @param key  the HMAC key
     * @param data the data to authenticate
     * @return 64-byte HMAC value
     * @throws QuacException if operation fails
     */
    public byte[] hmacSha512(byte[] key, byte[] data) throws QuacException {
        return hmac(HashAlgorithm.SHA512, key, data);
    }

    /**
     * Derives a key using HKDF (RFC 5869).
     * 
     * @param algorithm    the hash algorithm to use
     * @param ikm          input keying material
     * @param salt         optional salt (can be null)
     * @param info         optional context/application info (can be null)
     * @param outputLength desired output length in bytes
     * @return derived key material
     * @throws QuacException if operation fails
     */
    public byte[] hkdf(HashAlgorithm algorithm, byte[] ikm, byte[] salt, byte[] info,
            int outputLength) throws QuacException {
        if (ikm == null || ikm.length == 0) {
            throw new IllegalArgumentException("IKM cannot be null or empty");
        }
        if (outputLength <= 0) {
            throw new IllegalArgumentException("Output length must be positive");
        }

        // Use empty byte arrays for null salt/info
        if (salt == null)
            salt = new byte[0];
        if (info == null)
            info = new byte[0];

        byte[] result = nativeHkdf(device.getHandle(), algorithm.getValue(),
                ikm, salt, info, outputLength);
        if (result == null) {
            throw new QuacException(ErrorCode.CRYPTO_ERROR,
                    "HKDF operation failed for " + algorithm);
        }
        return result;
    }

    /**
     * Creates an incremental hash context.
     * 
     * @param algorithm the hash algorithm
     * @return HashContext for incremental hashing
     * @throws QuacException if creation fails
     */
    public HashContext createContext(HashAlgorithm algorithm) throws QuacException {
        long contextHandle = nativeCreateContext(device.getHandle(), algorithm.getValue());
        if (contextHandle == 0) {
            throw new QuacException(ErrorCode.CRYPTO_ERROR,
                    "Failed to create hash context for " + algorithm);
        }
        return new HashContext(contextHandle, algorithm);
    }

    /**
     * Incremental hash context for processing data in chunks.
     */
    public static class HashContext implements AutoCloseable {

        private long handle;
        private final HashAlgorithm algorithm;
        private boolean finalized = false;

        HashContext(long handle, HashAlgorithm algorithm) {
            this.handle = handle;
            this.algorithm = algorithm;
        }

        /**
         * Gets the algorithm used by this context.
         * 
         * @return the hash algorithm
         */
        public HashAlgorithm getAlgorithm() {
            return algorithm;
        }

        /**
         * Updates the hash with additional data.
         * 
         * @param data the data to add
         * @throws QuacException if update fails
         */
        public void update(byte[] data) throws QuacException {
            if (finalized) {
                throw new IllegalStateException("Context has been finalized");
            }
            if (data == null) {
                throw new IllegalArgumentException("Data cannot be null");
            }

            int result = nativeContextUpdate(handle, data);
            if (result != 0) {
                throw new QuacException(ErrorCode.fromCode(result),
                        "Hash context update failed");
            }
        }

        /**
         * Updates the hash with a string (UTF-8 encoded).
         * 
         * @param data the string to add
         * @throws QuacException if update fails
         */
        public void update(String data) throws QuacException {
            update(data.getBytes(StandardCharsets.UTF_8));
        }

        /**
         * Finalizes the hash and returns the digest.
         * 
         * <p>
         * After calling this method, the context cannot be used again.
         * </p>
         * 
         * @return the hash digest
         * @throws QuacException if finalization fails
         */
        public byte[] digest() throws QuacException {
            if (finalized) {
                throw new IllegalStateException("Context has already been finalized");
            }

            byte[] result = nativeContextFinalize(handle);
            finalized = true;

            if (result == null) {
                throw new QuacException(ErrorCode.CRYPTO_ERROR,
                        "Hash context finalization failed");
            }
            return result;
        }

        /**
         * Alias for digest() - finalizes the hash and returns the result.
         * 
         * @return the hash digest
         * @throws QuacException if finalization fails
         */
        public byte[] doFinal() throws QuacException {
            return digest();
        }

        /**
         * Releases resources associated with this context.
         */
        @Override
        public void close() {
            if (handle != 0) {
                nativeContextFree(handle);
                handle = 0;
            }
        }
    }
}

