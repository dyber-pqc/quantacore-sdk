/*
 * Copyright © 2025 Dyber, Inc. All Rights Reserved.
 * QUAC 100 Post-Quantum Cryptographic Accelerator - Java SDK
 */

package com.dyber.quac100;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Main entry point for the QUAC 100 SDK.
 * 
 * <p>
 * This class manages library initialization, cleanup, and device enumeration.
 * It must be initialized before any other QUAC 100 operations can be performed.
 * </p>
 * 
 * @since 1.0.0
 */
public final class Library {

    /** Library version string */
    public static final String SDK_VERSION = "1.0.0";

    /** Default initialization flags */
    public static final int FLAG_DEFAULT = 0x0F;

    /** Enable hardware acceleration */
    public static final int FLAG_HARDWARE_ACCEL = 0x01;

    /** Enable side-channel protection */
    public static final int FLAG_SIDE_CHANNEL_PROTECT = 0x02;

    /** Force constant-time operations */
    public static final int FLAG_CONSTANT_TIME = 0x04;

    /** Auto-zeroize sensitive data */
    public static final int FLAG_AUTO_ZEROIZE = 0x08;

    /** FIPS 140-3 compliant mode */
    public static final int FLAG_FIPS_MODE = 0x10;

    /** Enable debug output */
    public static final int FLAG_DEBUG = 0x20;

    /** Allow software fallback */
    public static final int FLAG_SOFTWARE_FALLBACK = 0x40;

    private static final AtomicBoolean initialized = new AtomicBoolean(false);
    private static final AtomicBoolean nativeLoaded = new AtomicBoolean(false);

    // Singleton instance for backward compatibility
    private static final Library INSTANCE = new Library();

    // Native library names
    private static final String JNI_LIB_NAME = "quac100_jni";
    private static final String C_LIB_NAME = "quac100";

    static {
        loadNativeLibraries();
    }

    private Library() {
        // Private constructor for singleton
    }

    /**
     * Get the Library singleton instance.
     * 
     * @return Library instance
     */
    public static Library getInstance() {
        return INSTANCE;
    }

    /**
     * Load native libraries with platform-specific handling.
     */
    private static void loadNativeLibraries() {
        if (nativeLoaded.get()) {
            return;
        }

        synchronized (Library.class) {
            if (nativeLoaded.get()) {
                return;
            }

            try {
                loadFromLibraryPath();
            } catch (UnsatisfiedLinkError e1) {
                try {
                    loadFromResources();
                } catch (Exception e2) {
                    throw new UnsatisfiedLinkError(
                            "Failed to load QUAC 100 native libraries. " +
                                    "Ensure the native libraries are in java.library.path or bundled in the JAR.\n" +
                                    "java.library.path: " + System.getProperty("java.library.path") + "\n" +
                                    "Primary error: " + e1.getMessage() + "\n" +
                                    "Secondary error: " + e2.getMessage());
                }
            }

            nativeLoaded.set(true);
        }
    }

    private static void loadFromLibraryPath() {
        if (isWindows()) {
            try {
                System.loadLibrary(C_LIB_NAME);
            } catch (UnsatisfiedLinkError e) {
                // C library might be loaded as dependency of JNI library
            }
        }
        System.loadLibrary(JNI_LIB_NAME);
    }

    private static void loadFromResources() throws IOException {
        String platform = getPlatformIdentifier();
        Path tempDir = Files.createTempDirectory("quac100-native-");
        tempDir.toFile().deleteOnExit();

        if (isWindows()) {
            String cLibResource = "/native/" + platform + "/" + C_LIB_NAME + ".dll";
            extractAndLoadLibrary(cLibResource, tempDir, C_LIB_NAME + ".dll");
        }

        String jniLibResource = "/native/" + platform + "/" + getLibraryFileName(JNI_LIB_NAME);
        extractAndLoadLibrary(jniLibResource, tempDir, getLibraryFileName(JNI_LIB_NAME));
    }

    private static void extractAndLoadLibrary(String resourcePath, Path tempDir, String fileName)
            throws IOException {
        try (InputStream is = Library.class.getResourceAsStream(resourcePath)) {
            if (is == null) {
                throw new IOException("Native library not found in JAR: " + resourcePath);
            }

            Path libPath = tempDir.resolve(fileName);
            Files.copy(is, libPath, StandardCopyOption.REPLACE_EXISTING);
            libPath.toFile().deleteOnExit();

            System.load(libPath.toAbsolutePath().toString());
        }
    }

    private static String getPlatformIdentifier() {
        String os = System.getProperty("os.name").toLowerCase();
        String arch = System.getProperty("os.arch").toLowerCase();

        String osName;
        if (os.contains("win")) {
            osName = "windows";
        } else if (os.contains("mac") || os.contains("darwin")) {
            osName = "macos";
        } else {
            osName = "linux";
        }

        String archName;
        if (arch.contains("amd64") || arch.contains("x86_64")) {
            archName = "x64";
        } else if (arch.contains("aarch64") || arch.contains("arm64")) {
            archName = "arm64";
        } else {
            archName = "x86";
        }

        return osName + "-" + archName;
    }

    private static String getLibraryFileName(String baseName) {
        if (isWindows()) {
            return baseName + ".dll";
        } else if (isMacOS()) {
            return "lib" + baseName + ".dylib";
        } else {
            return "lib" + baseName + ".so";
        }
    }

    private static boolean isWindows() {
        return System.getProperty("os.name").toLowerCase().contains("win");
    }

    private static boolean isMacOS() {
        String os = System.getProperty("os.name").toLowerCase();
        return os.contains("mac") || os.contains("darwin");
    }

    // =========================================================================
    // Public API - Static Methods
    // =========================================================================

    /**
     * Initialize the QUAC 100 library with default flags.
     * 
     * @throws QuacException if initialization fails
     */
    public static void initialize() throws QuacException {
        initialize(FLAG_DEFAULT);
    }

    /**
     * Initialize the QUAC 100 library with specified flags.
     * 
     * @param flags Initialization flags (FLAG_*)
     * @throws QuacException if initialization fails
     */
    public static void initialize(int flags) throws QuacException {
        if (initialized.compareAndSet(false, true)) {
            int status = nativeInit(flags);
            if (status != 0) {
                initialized.set(false);
                throw new QuacException(status, "Failed to initialize library");
            }
        }
    }

    /**
     * Clean up the QUAC 100 library.
     * 
     * @throws QuacException if cleanup fails
     */
    public static void cleanup() throws QuacException {
        if (initialized.compareAndSet(true, false)) {
            int status = nativeCleanup();
            if (status != 0) {
                throw new QuacException(status, "Failed to cleanup library");
            }
        }
    }

    /**
     * Check if the library is initialized.
     * 
     * @return true if initialized
     */
    public static boolean isInitialized() {
        return initialized.get() && nativeIsInitialized();
    }

    /**
     * Get the native library version string.
     * 
     * @return Version string
     */
    public static String getVersion() {
        return nativeVersion();
    }

    /**
     * Get build information string.
     * 
     * @return Build information
     */
    public static String getBuildInfo() {
        return nativeBuildInfo();
    }

    /**
     * Get the number of available QUAC 100 devices.
     * 
     * @return Number of devices
     */
    public static int getDeviceCount() {
        ensureInitialized();
        return nativeDeviceCount();
    }

    /**
     * Enumerate available QUAC 100 devices.
     * 
     * @return Array of device information
     */
    public static DeviceInfo[] enumerateDevices() {
        ensureInitialized();
        return nativeEnumerateDevices();
    }

    /**
     * Open a QUAC 100 device.
     * 
     * @param index Device index (0 for first device)
     * @return Device handle
     * @throws QuacException if device cannot be opened
     */
    public static Device openDevice(int index) throws QuacException {
        return openDevice(index, FLAG_DEFAULT);
    }

    /**
     * Open a QUAC 100 device with specified flags.
     * 
     * @param index Device index
     * @param flags Device flags
     * @return Device handle
     * @throws QuacException if device cannot be opened
     */
    public static Device openDevice(int index, int flags) throws QuacException {
        ensureInitialized();
        long handle = nativeOpenDevice(index, flags);
        if (handle == 0) {
            throw new QuacException(ErrorCode.DEVICE_NOT_FOUND.getCode(),
                    "Failed to open device " + index);
        }
        return new Device(handle, index);
    }

    /**
     * Open the first available device.
     * 
     * @return Device handle
     * @throws QuacException if no device is available
     */
    public static Device openFirstDevice() throws QuacException {
        return openDevice(0);
    }

    /**
     * Notify library that a device has been closed.
     * Called internally by Device.close().
     * 
     * @param device The device that was closed
     */
    static void deviceClosed(Device device) {
        // Internal bookkeeping for device tracking
        // Could be used for resource management, logging, etc.
    }

    // =========================================================================
    // Instance Methods (for backward compatibility)
    // =========================================================================

    /**
     * Initialize via instance method.
     * 
     * @throws QuacException if initialization fails
     */
    public void init() throws QuacException {
        initialize();
    }

    /**
     * Initialize via instance method with flags.
     * 
     * @param flags Initialization flags
     * @throws QuacException if initialization fails
     */
    public void init(int flags) throws QuacException {
        initialize(flags);
    }

    /**
     * Shutdown the library via instance method.
     * 
     * @throws QuacException if cleanup fails
     */
    public void shutdown() throws QuacException {
        cleanup();
    }

    /**
     * Get device count via instance method.
     * 
     * @return Number of devices
     */
    public int deviceCount() {
        return getDeviceCount();
    }

    /**
     * Ensure library is initialized.
     */
    private static void ensureInitialized() {
        if (!initialized.get()) {
            throw new IllegalStateException(
                    "QUAC 100 library not initialized. Call Library.initialize() first.");
        }
    }

    // =========================================================================
    // Native Methods
    // =========================================================================

    private static native int nativeInit(int flags);

    private static native int nativeCleanup();

    private static native boolean nativeIsInitialized();

    private static native String nativeVersion();

    private static native String nativeBuildInfo();

    private static native int nativeDeviceCount();

    private static native DeviceInfo[] nativeEnumerateDevices();

    static native long nativeOpenDevice(int index, int flags);
}