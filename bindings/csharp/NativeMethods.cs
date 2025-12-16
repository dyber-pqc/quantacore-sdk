// D:\quantacore-sdk\bindings\csharp\NativeMethods.cs
// QUAC 100 SDK - Native P/Invoke Declarations
// Copyright © 2025 Dyber, Inc. All Rights Reserved.

using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace Dyber.Quac100;

/// <summary>
/// Native method imports for QUAC 100 library
/// </summary>
[SuppressUnmanagedCodeSecurity]
internal static partial class NativeMethods
{
    #region Library Loading

    private const string LibraryName = "quac100";

    // Platform-specific library resolution
    static NativeMethods()
    {
        NativeLibrary.SetDllImportResolver(typeof(NativeMethods).Assembly, ImportResolver);
    }

    private static IntPtr ImportResolver(string libraryName, System.Reflection.Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (libraryName != LibraryName)
            return IntPtr.Zero;

        IntPtr handle = IntPtr.Zero;

        // Try platform-specific paths
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            NativeLibrary.TryLoad("quac100.dll", assembly, searchPath, out handle);
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            NativeLibrary.TryLoad("libquac100.so", assembly, searchPath, out handle);
            if (handle == IntPtr.Zero)
                NativeLibrary.TryLoad("libquac100.so.1", assembly, searchPath, out handle);
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            NativeLibrary.TryLoad("libquac100.dylib", assembly, searchPath, out handle);
        }

        return handle;
    }

    #endregion

    #region Native Structures

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    internal struct NativeDeviceInfo
    {
        public int device_index;
        public ushort vendor_id;
        public ushort product_id;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string serial_number;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string firmware_version;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string hardware_version;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string model_name;
        public uint capabilities;
        public int max_concurrent_ops;
        public int key_slots;
        public byte fips_mode;
        public byte hardware_available;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct NativeDeviceStatus
    {
        public float temperature;
        public uint power_mw;
        public ulong uptime_seconds;
        public ulong total_operations;
        public uint ops_per_second;
        public int entropy_level;
        public int active_sessions;
        public int used_key_slots;
        public int last_error;
        public int tamper_status;
    }

    #endregion

    #region Library Initialization

    /// <summary>Initialize the QUAC 100 library</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_init(uint flags);

    /// <summary>Cleanup the QUAC 100 library</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_cleanup();

    /// <summary>Get library version string</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr quac_version();

    /// <summary>Get library version numbers</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_version_info(out int major, out int minor, out int patch);

    #endregion

    #region Device Management

    /// <summary>Enumerate available devices</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_enumerate_devices(
        [Out] NativeDeviceInfo[] devices,
        int max_devices,
        out int device_count);

    /// <summary>Open a device handle</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_open_device(
        int device_index,
        uint flags,
        out IntPtr handle);

    /// <summary>Close a device handle</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_close_device(IntPtr handle);

    /// <summary>Get device information</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_get_device_info(
        IntPtr handle,
        out NativeDeviceInfo info);

    /// <summary>Get device status</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_get_device_status(
        IntPtr handle,
        out NativeDeviceStatus status);

    /// <summary>Reset device</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_reset_device(IntPtr handle);

    /// <summary>Run device self-test</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_self_test(IntPtr handle);

    #endregion

    #region ML-KEM (Key Encapsulation)

    /// <summary>Generate ML-KEM key pair</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_kem_keygen(
        IntPtr handle,
        int algorithm,
        [Out] byte[] public_key,
        ref int public_key_len,
        [Out] byte[] secret_key,
        ref int secret_key_len);

    /// <summary>ML-KEM encapsulation</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_kem_encaps(
        IntPtr handle,
        int algorithm,
        [In] byte[] public_key,
        int public_key_len,
        [Out] byte[] ciphertext,
        ref int ciphertext_len,
        [Out] byte[] shared_secret,
        ref int shared_secret_len);

    /// <summary>ML-KEM decapsulation</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_kem_decaps(
        IntPtr handle,
        int algorithm,
        [In] byte[] secret_key,
        int secret_key_len,
        [In] byte[] ciphertext,
        int ciphertext_len,
        [Out] byte[] shared_secret,
        ref int shared_secret_len);

    /// <summary>Get ML-KEM parameters</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_kem_get_params(
        int algorithm,
        out int public_key_len,
        out int secret_key_len,
        out int ciphertext_len,
        out int shared_secret_len);

    /// <summary>Batch ML-KEM encapsulation</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_kem_encaps_batch(
        IntPtr handle,
        int algorithm,
        [In] IntPtr[] public_keys,
        [In] int[] public_key_lens,
        [Out] IntPtr[] ciphertexts,
        [In, Out] int[] ciphertext_lens,
        [Out] IntPtr[] shared_secrets,
        [In, Out] int[] shared_secret_lens,
        int count,
        [Out] int[] results);

    #endregion

    #region ML-DSA (Digital Signatures)

    /// <summary>Generate ML-DSA key pair</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_sign_keygen(
        IntPtr handle,
        int algorithm,
        [Out] byte[] public_key,
        ref int public_key_len,
        [Out] byte[] secret_key,
        ref int secret_key_len);

    /// <summary>ML-DSA sign message</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_sign(
        IntPtr handle,
        int algorithm,
        [In] byte[] secret_key,
        int secret_key_len,
        [In] byte[] message,
        int message_len,
        [Out] byte[] signature,
        ref int signature_len);

    /// <summary>ML-DSA verify signature</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_verify(
        IntPtr handle,
        int algorithm,
        [In] byte[] public_key,
        int public_key_len,
        [In] byte[] message,
        int message_len,
        [In] byte[] signature,
        int signature_len);

    /// <summary>Get ML-DSA parameters</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_sign_get_params(
        int algorithm,
        out int public_key_len,
        out int secret_key_len,
        out int signature_len);

    /// <summary>Batch signing</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_sign_batch(
        IntPtr handle,
        int algorithm,
        [In] byte[] secret_key,
        int secret_key_len,
        [In] IntPtr[] messages,
        [In] int[] message_lens,
        [Out] IntPtr[] signatures,
        [In, Out] int[] signature_lens,
        int count,
        [Out] int[] results);

    /// <summary>Batch verification</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_verify_batch(
        IntPtr handle,
        int algorithm,
        [In] byte[] public_key,
        int public_key_len,
        [In] IntPtr[] messages,
        [In] int[] message_lens,
        [In] IntPtr[] signatures,
        [In] int[] signature_lens,
        int count,
        [Out] int[] results);

    #endregion

    #region Random Number Generation

    /// <summary>Generate random bytes</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_random_bytes(
        IntPtr handle,
        [Out] byte[] buffer,
        int length);

    /// <summary>Generate random bytes with specific entropy source</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_random_bytes_ex(
        IntPtr handle,
        [Out] byte[] buffer,
        int length,
        int entropy_source);

    /// <summary>Get entropy pool status</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_random_entropy_status(
        IntPtr handle,
        out int level,
        out int source);

    /// <summary>Seed the random number generator</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_random_seed(
        IntPtr handle,
        [In] byte[] seed,
        int seed_len);

    /// <summary>Reseed from hardware entropy</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_random_reseed(IntPtr handle);

    #endregion

    #region Key Storage

    /// <summary>Store key in hardware</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_key_store(
        IntPtr handle,
        [In] byte[] key,
        int key_len,
        int key_type,
        [MarshalAs(UnmanagedType.LPStr)] string label,
        uint usage,
        out int slot);

    /// <summary>Load key from hardware</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_key_load(
        IntPtr handle,
        int slot,
        [Out] byte[] key,
        ref int key_len);

    /// <summary>Delete key from hardware</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_key_delete(
        IntPtr handle,
        int slot);

    /// <summary>List stored keys</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_key_list(
        IntPtr handle,
        [Out] int[] slots,
        int max_slots,
        out int count);

    /// <summary>Get key information</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_key_info(
        IntPtr handle,
        int slot,
        out int key_type,
        out int key_len,
        out uint usage,
        [MarshalAs(UnmanagedType.LPStr)] StringBuilder label,
        int label_max);

    #endregion

    #region Hash Functions

    /// <summary>Compute hash</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_hash(
        IntPtr handle,
        int algorithm,
        [In] byte[] data,
        int data_len,
        [Out] byte[] hash,
        ref int hash_len);

    /// <summary>Initialize hash context</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_hash_init(
        IntPtr handle,
        int algorithm,
        out IntPtr context);

    /// <summary>Update hash context</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_hash_update(
        IntPtr context,
        [In] byte[] data,
        int data_len);

    /// <summary>Finalize hash</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_hash_final(
        IntPtr context,
        [Out] byte[] hash,
        ref int hash_len);

    /// <summary>Free hash context</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_hash_free(IntPtr context);

    #endregion

    #region Utility Functions

    /// <summary>Get error message</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr quac_error_string(int error_code);

    /// <summary>Secure memory zeroization</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void quac_secure_zero(
        [In, Out] byte[] buffer,
        int length);

    /// <summary>Constant-time comparison</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_secure_compare(
        [In] byte[] a,
        [In] byte[] b,
        int length);

    /// <summary>Set log callback</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_set_log_callback(
        LogCallback callback,
        int level);

    /// <summary>Log callback delegate</summary>
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate void LogCallback(int level, IntPtr message);

    #endregion

    #region Async Operations (if available)

    /// <summary>Async operation callback</summary>
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate void AsyncCallback(int status, IntPtr result, IntPtr user_data);

    /// <summary>Async KEM encapsulation</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_kem_encaps_async(
        IntPtr handle,
        int algorithm,
        [In] byte[] public_key,
        int public_key_len,
        AsyncCallback callback,
        IntPtr user_data);

    /// <summary>Async sign</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_sign_async(
        IntPtr handle,
        int algorithm,
        [In] byte[] secret_key,
        int secret_key_len,
        [In] byte[] message,
        int message_len,
        AsyncCallback callback,
        IntPtr user_data);

    /// <summary>Cancel async operation</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_async_cancel(IntPtr handle, int operation_id);

    /// <summary>Wait for async operation</summary>
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int quac_async_wait(IntPtr handle, int operation_id, int timeout_ms);

    #endregion
}