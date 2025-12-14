/*
 * Copyright © 2025 Dyber, Inc. All Rights Reserved.
 * QUAC 100 Post-Quantum Cryptographic Accelerator - Java SDK
 */

package com.dyber.quac100;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.condition.EnabledIf;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for QUAC 100 Java SDK.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class Quac100Test {

    private static Device device;
    private static boolean hardwareAvailable = false;

    @BeforeAll
    static void setup() throws Exception {
        // Initialize library
        Library.initialize();

        // Check if hardware is available
        int deviceCount = Library.getDeviceCount();
        hardwareAvailable = deviceCount > 0;

        if (hardwareAvailable) {
            device = Library.openDevice(0);
        }
    }

    @AfterAll
    static void teardown() throws Exception {
        if (device != null) {
            device.close();
        }
        Library.cleanup();
    }

    // =========================================================================
    // Library Tests
    // =========================================================================

    @Test
    @Order(1)
    void testLibraryVersion() {
        String version = Library.getVersion();
        assertNotNull(version);
        assertFalse(version.isEmpty());
        System.out.println("Library version: " + version);
    }

    @Test
    @Order(2)
    void testLibraryBuildInfo() {
        String buildInfo = Library.getBuildInfo();
        assertNotNull(buildInfo);
        System.out.println("Build info: " + buildInfo);
    }

    @Test
    @Order(3)
    void testLibraryIsInitialized() {
        assertTrue(Library.isInitialized());
    }

    @Test
    @Order(4)
    void testDeviceCount() {
        int count = Library.getDeviceCount();
        assertTrue(count >= 0);
        System.out.println("Device count: " + count);
    }

    @Test
    @Order(5)
    void testEnumerateDevices() {
        DeviceInfo[] devices = Library.enumerateDevices();
        assertNotNull(devices);
        System.out.println("Enumerated " + devices.length + " devices");
        for (DeviceInfo info : devices) {
            System.out.println("  - " + info);
        }
    }

    // =========================================================================
    // ErrorCode Tests
    // =========================================================================

    @Test
    @Order(6)
    void testErrorCodeEnum() {
        assertEquals(0, ErrorCode.SUCCESS.getCode());
        assertTrue(ErrorCode.SUCCESS.isSuccess());
        assertFalse(ErrorCode.ERROR.isSuccess());

        // Test lookup
        ErrorCode found = ErrorCode.fromCode(0);
        assertEquals(ErrorCode.SUCCESS, found);

        // Test CRYPTO_ERROR exists
        assertNotNull(ErrorCode.CRYPTO_ERROR);
        assertNotNull(ErrorCode.INVALID_ALGORITHM);
        assertNotNull(ErrorCode.INTERNAL_ERROR);
    }

    // =========================================================================
    // Device Tests (require hardware)
    // =========================================================================

    @Test
    @Order(10)
    @EnabledIf("isHardwareAvailable")
    void testDeviceInfo() throws Exception {
        DeviceInfo info = device.getInfo();
        assertNotNull(info);
        System.out.println("Device info: " + info);
    }

    @Test
    @Order(11)
    @EnabledIf("isHardwareAvailable")
    void testDeviceStatus() throws Exception {
        DeviceStatus status = device.getStatus();
        assertNotNull(status);
        assertTrue(status.isHealthy());
        System.out.println("Device status: " + status);
    }

    @Test
    @Order(12)
    @EnabledIf("isHardwareAvailable")
    void testDeviceIsOpen() {
        assertTrue(device.isOpen());
    }

    @Test
    @Order(13)
    @EnabledIf("isHardwareAvailable")
    void testDeviceSelfTest() throws Exception {
        // Self-test should pass on healthy hardware
        assertDoesNotThrow(() -> device.selfTest());
    }

    // =========================================================================
    // Random Number Generation Tests
    // =========================================================================

    @Test
    @Order(20)
    @EnabledIf("isHardwareAvailable")
    void testRandomSubsystem() throws Exception {
        Random random = device.random();
        assertNotNull(random);
    }

    @Test
    @Order(21)
    @Disabled("JNI nativeGetBytes not implemented")
    void testRandomBytes() throws Exception {
        Random random = device.random();
        byte[] bytes = random.bytes(32);
        assertNotNull(bytes);
        assertEquals(32, bytes.length);

        // Check bytes aren't all zeros (extremely unlikely for true random)
        boolean hasNonZero = false;
        for (byte b : bytes) {
            if (b != 0) {
                hasNonZero = true;
                break;
            }
        }
        assertTrue(hasNonZero, "Random bytes should not all be zero");
        System.out.println("Generated 32 random bytes");
    }

    @Test
    @Order(22)
    @EnabledIf("isHardwareAvailable")
    void testEntropyStatus() throws Exception {
        Random random = device.random();
        EntropyStatus status = random.getEntropyStatus();
        assertNotNull(status);
        assertTrue(status.isHealthOk());
        System.out.println("Entropy status: " + status);
    }

    // =========================================================================
    // KEM Tests
    // =========================================================================

    @Test
    @Order(30)
    @EnabledIf("isHardwareAvailable")
    void testKemSubsystem() throws Exception {
        Kem kem = device.kem();
        assertNotNull(kem);
    }

    @Test
    @Order(31)
    @EnabledIf("isHardwareAvailable")
    void testKemKeyGen() throws Exception {
        Kem kem = device.kem();
        KeyPair kp = kem.generateKeyPair(KemAlgorithm.ML_KEM_512);

        assertNotNull(kp);
        assertNotNull(kp.getPublicKey());
        assertNotNull(kp.getSecretKey());
        assertTrue(kp.getPublicKeySize() > 0);
        assertTrue(kp.getSecretKeySize() > 0);

        System.out.println("KEM KeyPair: pk=" + kp.getPublicKeySize() +
                " bytes, sk=" + kp.getSecretKeySize() + " bytes");
        kp.close();
    }

    @Test
    @Order(32)
    @EnabledIf("isHardwareAvailable")
    void testKemEncapsDecaps() throws Exception {
        Kem kem = device.kem();

        // Generate key pair
        KeyPair kp = kem.generateKeyPair(KemAlgorithm.ML_KEM_512);

        // Encapsulate
        EncapsulationResult encap = kem.encapsulate(KemAlgorithm.ML_KEM_512, kp.getPublicKey());
        assertNotNull(encap);
        assertNotNull(encap.getCiphertext());
        assertNotNull(encap.getSharedSecret());

        // Decapsulate
        byte[] sharedSecret2 = kem.decapsulate(KemAlgorithm.ML_KEM_512,
                kp.getSecretKey(),
                encap.getCiphertext());
        assertNotNull(sharedSecret2);

        // Verify shared secrets match
        assertArrayEquals(encap.getSharedSecret(), sharedSecret2);

        System.out.println("KEM encaps/decaps successful, shared secret: " +
                encap.getSharedSecretSize() + " bytes");

        kp.close();
        encap.close();
    }

    // =========================================================================
    // Signature Tests
    // =========================================================================

    @Test
    @Order(40)
    @EnabledIf("isHardwareAvailable")
    void testSignSubsystem() throws Exception {
        Sign sign = device.sign();
        assertNotNull(sign);
    }

    @Test
    @Order(41)
    @EnabledIf("isHardwareAvailable")
    void testSignKeyGen() throws Exception {
        Sign sign = device.sign();
        KeyPair kp = sign.generateKeyPair(SignAlgorithm.ML_DSA_44);

        assertNotNull(kp);
        assertNotNull(kp.getPublicKey());
        assertNotNull(kp.getSecretKey());

        System.out.println("Sign KeyPair: pk=" + kp.getPublicKeySize() +
                " bytes, sk=" + kp.getSecretKeySize() + " bytes");
        kp.close();
    }

    @Test
    @Order(42)
    @EnabledIf("isHardwareAvailable")
    void testSignVerify() throws Exception {
        Sign sign = device.sign();

        // Generate key pair
        KeyPair kp = sign.generateKeyPair(SignAlgorithm.ML_DSA_44);

        // Sign a message
        byte[] message = "Hello, QUAC 100!".getBytes();
        byte[] signature = sign.sign(SignAlgorithm.ML_DSA_44, kp.getSecretKey(), message);
        assertNotNull(signature);
        assertTrue(signature.length > 0);

        // Verify signature
        boolean valid = sign.verify(SignAlgorithm.ML_DSA_44, kp.getPublicKey(), message, signature);
        assertTrue(valid, "Signature verification should succeed");

        System.out.println("Sign/verify successful, signature: " + signature.length + " bytes");
        kp.close();
    }

    @Test
    @Order(43)
    @EnabledIf("isHardwareAvailable")
    void testSignVerifyInvalid() throws Exception {
        Sign sign = device.sign();

        // Generate key pair
        KeyPair kp = sign.generateKeyPair(SignAlgorithm.ML_DSA_44);

        // Sign a message
        byte[] message = "Hello, QUAC 100!".getBytes();
        byte[] signature = sign.sign(SignAlgorithm.ML_DSA_44, kp.getSecretKey(), message);

        // Modify message
        byte[] modifiedMessage = "Modified message".getBytes();

        // Verify should fail
        boolean valid = sign.verify(SignAlgorithm.ML_DSA_44, kp.getPublicKey(), modifiedMessage, signature);
        assertFalse(valid, "Signature verification should fail for modified message");

        kp.close();
    }

    // =========================================================================
    // Hash Tests
    // =========================================================================

    @Test
    @Order(50)
    @EnabledIf("isHardwareAvailable")
    void testHashSubsystem() throws Exception {
        Hash hash = device.hash();
        assertNotNull(hash);
    }

    @Test
    @Order(51)
    @EnabledIf("isHardwareAvailable")
    void testHash() throws Exception {
        Hash hash = device.hash();

        byte[] data = "Test data for hashing".getBytes();
        byte[] digest = hash.hash(HashAlgorithm.SHA3_256, data);

        assertNotNull(digest);
        assertEquals(32, digest.length); // SHA3-256 = 32 bytes

        System.out.println("Hash computed: " + digest.length + " bytes");
    }

    @Test
    @Order(52)
    @EnabledIf("isHardwareAvailable")
    void testHashConsistency() throws Exception {
        Hash hash = device.hash();

        byte[] data = "Consistent test data".getBytes();
        byte[] digest1 = hash.hash(HashAlgorithm.SHA3_256, data);
        byte[] digest2 = hash.hash(HashAlgorithm.SHA3_256, data);

        assertArrayEquals(digest1, digest2, "Same input should produce same hash");
    }

    // =========================================================================
    // Key Storage Tests
    // =========================================================================

    @Test
    @Order(60)
    @EnabledIf("isHardwareAvailable")
    void testKeysSubsystem() throws Exception {
        Keys keys = device.keys();
        assertNotNull(keys);
    }

    // =========================================================================
    // Exception Tests
    // =========================================================================

    @Test
    @Order(70)
    void testQuacException() {
        QuacException ex = new QuacException(ErrorCode.DEVICE_NOT_FOUND, "Test message");
        assertEquals(ErrorCode.DEVICE_NOT_FOUND.getCode(), ex.getErrorCode());
        assertTrue(ex.getMessage().contains("DEVICE_NOT_FOUND"));
    }

    @Test
    @Order(71)
    void testCryptoException() {
        CryptoException ex = CryptoException.cryptoError("Test crypto error");
        assertEquals(ErrorCode.CRYPTO_ERROR.getCode(), ex.getErrorCode());
    }

    @Test
    @Order(72)
    void testDeviceException() {
        DeviceException ex = DeviceException.deviceNotFound();
        assertEquals(ErrorCode.DEVICE_NOT_FOUND.getCode(), ex.getErrorCode());
    }

    // =========================================================================
    // KeyPair and EncapsulationResult Tests
    // =========================================================================

    @Test
    @Order(80)
    void testKeyPairClose() {
        byte[] pk = new byte[32];
        byte[] sk = new byte[64];
        KeyPair kp = new KeyPair(pk, sk);

        assertNotNull(kp.getPublicKey());
        assertNotNull(kp.getSecretKey());

        kp.close();

        // After close, should throw
        assertThrows(IllegalStateException.class, kp::getPublicKey);
        assertThrows(IllegalStateException.class, kp::getSecretKey);
    }

    @Test
    @Order(81)
    void testEncapsulationResultClose() {
        byte[] ct = new byte[768];
        byte[] ss = new byte[32];
        EncapsulationResult er = new EncapsulationResult(ct, ss);

        assertNotNull(er.getCiphertext());
        assertNotNull(er.getSharedSecret());

        er.close();

        // After close, should throw
        assertThrows(IllegalStateException.class, er::getCiphertext);
        assertThrows(IllegalStateException.class, er::getSharedSecret);
    }

    // =========================================================================
    // Helper Methods
    // =========================================================================

    static boolean isHardwareAvailable() {
        return hardwareAvailable;
    }
}

