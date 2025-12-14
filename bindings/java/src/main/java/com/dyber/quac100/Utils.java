/*
 * Copyright © 2025 Dyber, Inc. All Rights Reserved.
 * QUAC 100 Post-Quantum Cryptographic Accelerator - Java SDK
 */
package com.dyber.quac100;

import java.util.Arrays;
import java.util.Base64;

/**
 * Utility methods for the QUAC 100 SDK.
 */
public final class Utils {

    private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();

    private Utils() {
        // Utility class - no instantiation
    }

    /**
     * Converts a byte array to a hexadecimal string.
     * 
     * @param data the byte array
     * @return hexadecimal string representation
     */
    public static String toHex(byte[] data) {
        if (data == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(HEX_CHARS[(b >> 4) & 0x0F]);
            sb.append(HEX_CHARS[b & 0x0F]);
        }
        return sb.toString();
    }

    /**
     * Converts a hexadecimal string to a byte array.
     * 
     * @param hex the hexadecimal string
     * @return byte array
     * @throws IllegalArgumentException if the string is not valid hex
     */
    public static byte[] fromHex(String hex) {
        if (hex == null) {
            return null;
        }

        // Remove common prefixes
        if (hex.startsWith("0x") || hex.startsWith("0X")) {
            hex = hex.substring(2);
        }

        // Remove whitespace
        hex = hex.replaceAll("\\s", "");

        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string must have even length");
        }

        byte[] result = new byte[hex.length() / 2];
        for (int i = 0; i < result.length; i++) {
            int hi = Character.digit(hex.charAt(i * 2), 16);
            int lo = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("Invalid hex character at position " + (i * 2));
            }
            result[i] = (byte) ((hi << 4) | lo);
        }
        return result;
    }

    /**
     * Converts a byte array to a Base64 string.
     * 
     * @param data the byte array
     * @return Base64 encoded string
     */
    public static String toBase64(byte[] data) {
        if (data == null) {
            return null;
        }
        return Base64.getEncoder().encodeToString(data);
    }

    /**
     * Converts a Base64 string to a byte array.
     * 
     * @param base64 the Base64 string
     * @return byte array
     * @throws IllegalArgumentException if the string is not valid Base64
     */
    public static byte[] fromBase64(String base64) {
        if (base64 == null) {
            return null;
        }
        return Base64.getDecoder().decode(base64);
    }

    /**
     * Converts a byte array to a Base64 URL-safe string.
     * 
     * @param data the byte array
     * @return Base64 URL-safe encoded string
     */
    public static String toBase64Url(byte[] data) {
        if (data == null) {
            return null;
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    /**
     * Converts a Base64 URL-safe string to a byte array.
     * 
     * @param base64 the Base64 URL-safe string
     * @return byte array
     */
    public static byte[] fromBase64Url(String base64) {
        if (base64 == null) {
            return null;
        }
        return Base64.getUrlDecoder().decode(base64);
    }

    /**
     * Securely zeros a byte array.
     * 
     * @param data the array to zero
     */
    public static void secureZero(byte[] data) {
        if (data != null) {
            Arrays.fill(data, (byte) 0);
        }
    }

    /**
     * Performs a constant-time comparison of two byte arrays.
     * 
     * <p>
     * This method takes the same amount of time regardless of where
     * the arrays differ, which helps prevent timing attacks.
     * </p>
     * 
     * @param a first array
     * @param b second array
     * @return true if arrays are equal
     */
    public static boolean secureCompare(byte[] a, byte[] b) {
        if (a == null || b == null) {
            return a == b;
        }
        if (a.length != b.length) {
            return false;
        }

        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }

    /**
     * Concatenates multiple byte arrays.
     * 
     * @param arrays the arrays to concatenate
     * @return concatenated array
     */
    public static byte[] concat(byte[]... arrays) {
        int totalLength = 0;
        for (byte[] array : arrays) {
            if (array != null) {
                totalLength += array.length;
            }
        }

        byte[] result = new byte[totalLength];
        int offset = 0;
        for (byte[] array : arrays) {
            if (array != null) {
                System.arraycopy(array, 0, result, offset, array.length);
                offset += array.length;
            }
        }
        return result;
    }

    /**
     * Creates a copy of a byte array.
     * 
     * @param data the array to copy
     * @return copy of the array, or null if input is null
     */
    public static byte[] copy(byte[] data) {
        if (data == null) {
            return null;
        }
        return Arrays.copyOf(data, data.length);
    }

    /**
     * Creates a substring of a byte array.
     * 
     * @param data   the source array
     * @param offset starting offset
     * @param length number of bytes to copy
     * @return new array containing the substring
     */
    public static byte[] slice(byte[] data, int offset, int length) {
        if (data == null) {
            return null;
        }
        return Arrays.copyOfRange(data, offset, offset + length);
    }
}