/*
 * Copyright © 2025 Dyber, Inc. All Rights Reserved.
 * QUAC 100 Post-Quantum Cryptographic Accelerator - Java SDK
 */
package com.dyber.quac100;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.UUID;

/**
 * Quantum Random Number Generation (QRNG) operations.
 * 
 * <p>
 * Provides true quantum random number generation using the QUAC 100's
 * integrated quantum entropy source. Random numbers generated are
 * cryptographically secure and suitable for key generation and nonces.
 * </p>
 * 
 * <h2>Example Usage:</h2>
 * 
 * <pre>{@code
 * Device device = lib.openFirstDevice();
 * Random random = device.random();
 * 
 * // Check entropy status
 * EntropyStatus status = random.getEntropyStatus();
 * System.out.println("Entropy level: " + status.getLevel() + "%");
 * 
 * // Generate random bytes
 * byte[] key = random.bytes(32);
 * 
 * // Generate random integers
 * int value = random.nextInt();
 * int inRange = random.nextInt(100); // [0, 100)
 * 
 * // Generate UUID
 * String uuid = random.uuid();
 * }</pre>
 * 
 * @author Dyber, Inc.
 * @version 1.0.0
 */
public class Random {

    private final Device device;

    // Native methods
    private static native EntropyStatus nativeGetEntropyStatus(long handle);

    private static native byte[] nativeGetBytes(long handle, int count);

    private static native int nativeGetUint32(long handle);

    private static native long nativeGetUint64(long handle);

    /**
     * Package-private constructor - instances are created by Device.
     */
    Random(Device device) {
        this.device = device;
    }

    /**
     * Gets the current entropy status.
     * 
     * @return EntropyStatus containing level, health status, etc.
     * @throws QuacException if operation fails
     */
    public EntropyStatus getEntropyStatus() throws QuacException {
        EntropyStatus status = nativeGetEntropyStatus(device.getHandle());
        if (status == null) {
            throw new QuacException(ErrorCode.INTERNAL_ERROR,
                    "Failed to get entropy status");
        }
        return status;
    }

    /**
     * Generates random bytes.
     * 
     * @param count number of bytes to generate
     * @return random byte array
     * @throws QuacException if generation fails
     */
    public byte[] bytes(int count) throws QuacException {
        if (count <= 0) {
            throw new IllegalArgumentException("Count must be positive");
        }

        byte[] result = nativeGetBytes(device.getHandle(), count);
        if (result == null || result.length != count) {
            throw new QuacException(ErrorCode.INTERNAL_ERROR,
                    "Failed to generate random bytes");
        }
        return result;
    }

    /**
     * Fills a byte array with random bytes.
     * 
     * @param buffer the buffer to fill
     * @throws QuacException if generation fails
     */
    public void nextBytes(byte[] buffer) throws QuacException {
        if (buffer == null || buffer.length == 0) {
            throw new IllegalArgumentException("Buffer cannot be null or empty");
        }

        byte[] random = bytes(buffer.length);
        System.arraycopy(random, 0, buffer, 0, buffer.length);
    }

    /**
     * Generates a random unsigned 32-bit integer.
     * 
     * @return random integer (full 32-bit range, may be negative in Java)
     * @throws QuacException if generation fails
     */
    public int nextUint32() throws QuacException {
        return nativeGetUint32(device.getHandle());
    }

    /**
     * Generates a random unsigned 64-bit integer.
     * 
     * @return random long (full 64-bit range, may be negative in Java)
     * @throws QuacException if generation fails
     */
    public long nextUint64() throws QuacException {
        return nativeGetUint64(device.getHandle());
    }

    /**
     * Generates a random non-negative integer.
     * 
     * @return random non-negative integer
     * @throws QuacException if generation fails
     */
    public int nextInt() throws QuacException {
        return nextUint32() & Integer.MAX_VALUE;
    }

    /**
     * Generates a random integer in the range [0, bound).
     * 
     * @param bound upper bound (exclusive)
     * @return random integer in [0, bound)
     * @throws QuacException if generation fails
     */
    public int nextInt(int bound) throws QuacException {
        if (bound <= 0) {
            throw new IllegalArgumentException("Bound must be positive");
        }

        // Use rejection sampling to avoid modulo bias
        int mask = bound - 1;
        if ((bound & mask) == 0) {
            // Power of 2
            return nextUint32() & mask;
        }

        // General case with rejection sampling
        int threshold = (0x80000000 - (0x80000000 % bound)) & 0x7FFFFFFF;
        while (true) {
            int r = nextUint32() & 0x7FFFFFFF;
            if (r >= threshold || (r % bound) < bound) {
                return r % bound;
            }
        }
    }

    /**
     * Generates a random integer in the range [min, max).
     * 
     * @param min lower bound (inclusive)
     * @param max upper bound (exclusive)
     * @return random integer in [min, max)
     * @throws QuacException if generation fails
     */
    public int nextInt(int min, int max) throws QuacException {
        if (min >= max) {
            throw new IllegalArgumentException("min must be less than max");
        }
        return min + nextInt(max - min);
    }

    /**
     * Generates a random non-negative long.
     * 
     * @return random non-negative long
     * @throws QuacException if generation fails
     */
    public long nextLong() throws QuacException {
        return nextUint64() & Long.MAX_VALUE;
    }

    /**
     * Generates a random long in the range [0, bound).
     * 
     * @param bound upper bound (exclusive)
     * @return random long in [0, bound)
     * @throws QuacException if generation fails
     */
    public long nextLong(long bound) throws QuacException {
        if (bound <= 0) {
            throw new IllegalArgumentException("Bound must be positive");
        }

        long mask = bound - 1;
        if ((bound & mask) == 0) {
            return nextUint64() & mask;
        }

        while (true) {
            long r = nextUint64() & Long.MAX_VALUE;
            if (r - (r % bound) + mask >= 0) {
                return r % bound;
            }
        }
    }

    /**
     * Generates a random double in the range [0.0, 1.0).
     * 
     * @return random double in [0.0, 1.0)
     * @throws QuacException if generation fails
     */
    public double nextDouble() throws QuacException {
        // Use 53 bits for double precision
        return (nextUint64() >>> 11) * (1.0 / (1L << 53));
    }

    /**
     * Generates a random double in the range [min, max).
     * 
     * @param min lower bound (inclusive)
     * @param max upper bound (exclusive)
     * @return random double in [min, max)
     * @throws QuacException if generation fails
     */
    public double nextDouble(double min, double max) throws QuacException {
        if (min >= max) {
            throw new IllegalArgumentException("min must be less than max");
        }
        return min + nextDouble() * (max - min);
    }

    /**
     * Generates a random float in the range [0.0f, 1.0f).
     * 
     * @return random float in [0.0f, 1.0f)
     * @throws QuacException if generation fails
     */
    public float nextFloat() throws QuacException {
        // Use 24 bits for float precision
        return (nextUint32() >>> 8) * (1.0f / (1 << 24));
    }

    /**
     * Generates a random boolean.
     * 
     * @return random boolean
     * @throws QuacException if generation fails
     */
    public boolean nextBoolean() throws QuacException {
        return (nextUint32() & 1) == 1;
    }

    /**
     * Generates a random UUID (version 4).
     * 
     * @return random UUID string (e.g., "550e8400-e29b-41d4-a716-446655440000")
     * @throws QuacException if generation fails
     */
    public String uuid() throws QuacException {
        byte[] randomBytes = bytes(16);

        // Set version to 4 (random UUID)
        randomBytes[6] = (byte) ((randomBytes[6] & 0x0F) | 0x40);
        // Set variant to RFC 4122
        randomBytes[8] = (byte) ((randomBytes[8] & 0x3F) | 0x80);

        // Convert to UUID format
        StringBuilder sb = new StringBuilder(36);
        for (int i = 0; i < 16; i++) {
            if (i == 4 || i == 6 || i == 8 || i == 10) {
                sb.append('-');
            }
            sb.append(String.format("%02x", randomBytes[i] & 0xFF));
        }
        return sb.toString();
    }

    /**
     * Generates a random UUID object (version 4).
     * 
     * @return random UUID
     * @throws QuacException if generation fails
     */
    public UUID nextUUID() throws QuacException {
        byte[] randomBytes = bytes(16);

        // Set version to 4 (random UUID)
        randomBytes[6] = (byte) ((randomBytes[6] & 0x0F) | 0x40);
        // Set variant to RFC 4122
        randomBytes[8] = (byte) ((randomBytes[8] & 0x3F) | 0x80);

        ByteBuffer bb = ByteBuffer.wrap(randomBytes);
        bb.order(ByteOrder.BIG_ENDIAN);
        return new UUID(bb.getLong(), bb.getLong());
    }

    /**
     * Shuffles an array in place using Fisher-Yates algorithm.
     * 
     * @param array the array to shuffle
     * @param <T>   element type
     * @throws QuacException if generation fails
     */
    public <T> void shuffle(T[] array) throws QuacException {
        if (array == null || array.length <= 1) {
            return;
        }

        for (int i = array.length - 1; i > 0; i--) {
            int j = nextInt(i + 1);
            T temp = array[i];
            array[i] = array[j];
            array[j] = temp;
        }
    }

    /**
     * Shuffles an int array in place using Fisher-Yates algorithm.
     * 
     * @param array the array to shuffle
     * @throws QuacException if generation fails
     */
    public void shuffle(int[] array) throws QuacException {
        if (array == null || array.length <= 1) {
            return;
        }

        for (int i = array.length - 1; i > 0; i--) {
            int j = nextInt(i + 1);
            int temp = array[i];
            array[i] = array[j];
            array[j] = temp;
        }
    }

    /**
     * Shuffles a byte array in place.
     * 
     * @param array the array to shuffle
     * @throws QuacException if generation fails
     */
    public void shuffle(byte[] array) throws QuacException {
        if (array == null || array.length <= 1) {
            return;
        }

        for (int i = array.length - 1; i > 0; i--) {
            int j = nextInt(i + 1);
            byte temp = array[i];
            array[i] = array[j];
            array[j] = temp;
        }
    }
}