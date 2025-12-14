// D:\quantacore-sdk\bindings\csharp\Types.cs
// QUAC 100 SDK - Type Definitions
// Copyright © 2025 Dyber, Inc. All Rights Reserved.

using System.Runtime.InteropServices;

namespace Dyber.Quac100;

#region Enumerations

/// <summary>
/// QUAC 100 operation result codes
/// </summary>
public enum Quac100Status
{
    /// <summary>Operation completed successfully</summary>
    Success = 0,

    /// <summary>Generic error</summary>
    Error = -1,

    /// <summary>Invalid parameter provided</summary>
    InvalidParameter = -2,

    /// <summary>Buffer too small for output</summary>
    BufferTooSmall = -3,

    /// <summary>Device not found</summary>
    DeviceNotFound = -4,

    /// <summary>Device busy</summary>
    DeviceBusy = -5,

    /// <summary>Device error</summary>
    DeviceError = -6,

    /// <summary>Memory allocation failed</summary>
    OutOfMemory = -7,

    /// <summary>Operation not supported</summary>
    NotSupported = -8,

    /// <summary>Authentication required</summary>
    AuthRequired = -9,

    /// <summary>Authentication failed</summary>
    AuthFailed = -10,

    /// <summary>Key not found</summary>
    KeyNotFound = -11,

    /// <summary>Invalid key</summary>
    InvalidKey = -12,

    /// <summary>Signature verification failed</summary>
    VerifyFailed = -13,

    /// <summary>Decapsulation failed</summary>
    DecapsFailed = -14,

    /// <summary>Hardware not available</summary>
    HardwareNotAvailable = -15,

    /// <summary>Operation timeout</summary>
    Timeout = -16,

    /// <summary>Library not initialized</summary>
    NotInitialized = -17,

    /// <summary>Already initialized</summary>
    AlreadyInitialized = -18,

    /// <summary>Invalid handle</summary>
    InvalidHandle = -19,

    /// <summary>Operation cancelled</summary>
    Cancelled = -20,

    /// <summary>Entropy source depleted</summary>
    EntropyDepleted = -21,

    /// <summary>Self-test failed</summary>
    SelfTestFailed = -22,

    /// <summary>Tamper detected</summary>
    TamperDetected = -23,

    /// <summary>Temperature out of range</summary>
    TemperatureError = -24,

    /// <summary>Power supply issue</summary>
    PowerError = -25,
}

/// <summary>
/// ML-KEM (Kyber) algorithm variants
/// </summary>
public enum KemAlgorithm
{
    /// <summary>ML-KEM-512 (NIST Security Level 1)</summary>
    MlKem512 = 1,

    /// <summary>ML-KEM-768 (NIST Security Level 3) - Recommended</summary>
    MlKem768 = 2,

    /// <summary>ML-KEM-1024 (NIST Security Level 5)</summary>
    MlKem1024 = 3,
}

/// <summary>
/// ML-DSA (Dilithium) algorithm variants
/// </summary>
public enum SignatureAlgorithm
{
    /// <summary>ML-DSA-44 (NIST Security Level 2)</summary>
    MlDsa44 = 1,

    /// <summary>ML-DSA-65 (NIST Security Level 3) - Recommended</summary>
    MlDsa65 = 2,

    /// <summary>ML-DSA-87 (NIST Security Level 5)</summary>
    MlDsa87 = 3,

    /// <summary>SLH-DSA-SHA2-128s (SPHINCS+)</summary>
    SlhDsaSha2_128s = 10,

    /// <summary>SLH-DSA-SHA2-128f (SPHINCS+)</summary>
    SlhDsaSha2_128f = 11,

    /// <summary>SLH-DSA-SHA2-192s (SPHINCS+)</summary>
    SlhDsaSha2_192s = 12,

    /// <summary>SLH-DSA-SHA2-192f (SPHINCS+)</summary>
    SlhDsaSha2_192f = 13,

    /// <summary>SLH-DSA-SHA2-256s (SPHINCS+)</summary>
    SlhDsaSha2_256s = 14,

    /// <summary>SLH-DSA-SHA2-256f (SPHINCS+)</summary>
    SlhDsaSha2_256f = 15,

    /// <summary>SLH-DSA-SHAKE-128s (SPHINCS+)</summary>
    SlhDsaShake_128s = 20,

    /// <summary>SLH-DSA-SHAKE-128f (SPHINCS+)</summary>
    SlhDsaShake_128f = 21,

    /// <summary>SLH-DSA-SHAKE-192s (SPHINCS+)</summary>
    SlhDsaShake_192s = 22,

    /// <summary>SLH-DSA-SHAKE-192f (SPHINCS+)</summary>
    SlhDsaShake_192f = 23,

    /// <summary>SLH-DSA-SHAKE-256s (SPHINCS+)</summary>
    SlhDsaShake_256s = 24,

    /// <summary>SLH-DSA-SHAKE-256f (SPHINCS+)</summary>
    SlhDsaShake_256f = 25,
}

/// <summary>
/// Hash algorithm for message digest
/// </summary>
public enum HashAlgorithm
{
    /// <summary>SHA-256</summary>
    Sha256 = 1,

    /// <summary>SHA-384</summary>
    Sha384 = 2,

    /// <summary>SHA-512</summary>
    Sha512 = 3,

    /// <summary>SHA3-256</summary>
    Sha3_256 = 4,

    /// <summary>SHA3-384</summary>
    Sha3_384 = 5,

    /// <summary>SHA3-512</summary>
    Sha3_512 = 6,

    /// <summary>SHAKE-128</summary>
    Shake128 = 7,

    /// <summary>SHAKE-256</summary>
    Shake256 = 8,
}

/// <summary>
/// Device operation flags
/// </summary>
[Flags]
public enum DeviceFlags : uint
{
    /// <summary>No special flags</summary>
    None = 0,

    /// <summary>Enable hardware acceleration</summary>
    HardwareAcceleration = 1 << 0,

    /// <summary>Enable side-channel countermeasures</summary>
    SideChannelProtection = 1 << 1,

    /// <summary>Enable constant-time operations</summary>
    ConstantTime = 1 << 2,

    /// <summary>Enable automatic key zeroization</summary>
    AutoZeroize = 1 << 3,

    /// <summary>Enable FIPS mode</summary>
    FipsMode = 1 << 4,

    /// <summary>Enable debug logging</summary>
    Debug = 1 << 5,

    /// <summary>Prefer software fallback</summary>
    SoftwareFallback = 1 << 6,

    /// <summary>Enable async operations</summary>
    AsyncOperations = 1 << 7,

    /// <summary>Enable batch processing</summary>
    BatchProcessing = 1 << 8,
}

/// <summary>
/// Key storage location
/// </summary>
public enum KeyStorage
{
    /// <summary>Key stored in volatile memory only</summary>
    Volatile = 0,

    /// <summary>Key stored in secure hardware</summary>
    Hardware = 1,

    /// <summary>Key stored in software with encryption</summary>
    Software = 2,
}

/// <summary>
/// Key usage restrictions
/// </summary>
[Flags]
public enum KeyUsage : uint
{
    /// <summary>No restrictions</summary>
    None = 0,

    /// <summary>Key can be used for signing</summary>
    Sign = 1 << 0,

    /// <summary>Key can be used for verification</summary>
    Verify = 1 << 1,

    /// <summary>Key can be used for encapsulation</summary>
    Encapsulate = 1 << 2,

    /// <summary>Key can be used for decapsulation</summary>
    Decapsulate = 1 << 3,

    /// <summary>Key can be exported</summary>
    Export = 1 << 4,

    /// <summary>Key can be wrapped</summary>
    Wrap = 1 << 5,

    /// <summary>Key can be unwrapped</summary>
    Unwrap = 1 << 6,

    /// <summary>Key can be used for key derivation</summary>
    Derive = 1 << 7,

    /// <summary>All signing operations</summary>
    AllSign = Sign | Verify,

    /// <summary>All KEM operations</summary>
    AllKem = Encapsulate | Decapsulate,

    /// <summary>All operations</summary>
    All = 0xFFFFFFFF,
}

/// <summary>
/// Entropy source type
/// </summary>
public enum EntropySource
{
    /// <summary>Hardware quantum random number generator</summary>
    Qrng = 0,

    /// <summary>Hardware true random number generator</summary>
    Trng = 1,

    /// <summary>Hybrid QRNG + TRNG</summary>
    Hybrid = 2,

    /// <summary>Software CSPRNG (fallback)</summary>
    Software = 3,
}

#endregion

#region Structures

/// <summary>
/// Device information structure
/// </summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct DeviceInfo
{
    /// <summary>Device index</summary>
    public int DeviceIndex;

    /// <summary>Vendor ID</summary>
    public ushort VendorId;

    /// <summary>Product ID</summary>
    public ushort ProductId;

    /// <summary>Device serial number</summary>
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string SerialNumber;

    /// <summary>Firmware version string</summary>
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
    public string FirmwareVersion;

    /// <summary>Hardware version string</summary>
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
    public string HardwareVersion;

    /// <summary>Device model name</summary>
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
    public string ModelName;

    /// <summary>Device capability flags</summary>
    public uint Capabilities;

    /// <summary>Maximum concurrent operations</summary>
    public int MaxConcurrentOps;

    /// <summary>Available key storage slots</summary>
    public int KeySlots;

    /// <summary>Device is in FIPS mode</summary>
    [MarshalAs(UnmanagedType.I1)]
    public bool FipsMode;

    /// <summary>Hardware acceleration available</summary>
    [MarshalAs(UnmanagedType.I1)]
    public bool HardwareAvailable;
}

/// <summary>
/// Device status information
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public struct DeviceStatus
{
    /// <summary>Device temperature in Celsius</summary>
    public float Temperature;

    /// <summary>Power consumption in milliwatts</summary>
    public uint PowerMilliwatts;

    /// <summary>Uptime in seconds</summary>
    public ulong UptimeSeconds;

    /// <summary>Total operations performed</summary>
    public ulong TotalOperations;

    /// <summary>Operations per second (current)</summary>
    public uint OpsPerSecond;

    /// <summary>Entropy pool level (0-100)</summary>
    public int EntropyLevel;

    /// <summary>Number of active sessions</summary>
    public int ActiveSessions;

    /// <summary>Used key storage slots</summary>
    public int UsedKeySlots;

    /// <summary>Last error code</summary>
    public Quac100Status LastError;

    /// <summary>Tamper status (0 = OK)</summary>
    public int TamperStatus;
}

/// <summary>
/// KEM algorithm parameters
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public readonly struct KemParameters
{
    /// <summary>Algorithm identifier</summary>
    public readonly KemAlgorithm Algorithm;

    /// <summary>Public key size in bytes</summary>
    public readonly int PublicKeySize;

    /// <summary>Secret key size in bytes</summary>
    public readonly int SecretKeySize;

    /// <summary>Ciphertext size in bytes</summary>
    public readonly int CiphertextSize;

    /// <summary>Shared secret size in bytes</summary>
    public readonly int SharedSecretSize;

    /// <summary>NIST security level (1, 3, or 5)</summary>
    public readonly int SecurityLevel;

    /// <summary>Algorithm name</summary>
    public readonly string Name;

    internal KemParameters(KemAlgorithm alg, int pk, int sk, int ct, int ss, int level, string name)
    {
        Algorithm = alg;
        PublicKeySize = pk;
        SecretKeySize = sk;
        CiphertextSize = ct;
        SharedSecretSize = ss;
        SecurityLevel = level;
        Name = name;
    }
}

/// <summary>
/// Signature algorithm parameters
/// </summary>
[StructLayout(LayoutKind.Sequential)]
public readonly struct SignatureParameters
{
    /// <summary>Algorithm identifier</summary>
    public readonly SignatureAlgorithm Algorithm;

    /// <summary>Public key size in bytes</summary>
    public readonly int PublicKeySize;

    /// <summary>Secret key size in bytes</summary>
    public readonly int SecretKeySize;

    /// <summary>Maximum signature size in bytes</summary>
    public readonly int SignatureSize;

    /// <summary>NIST security level (1-5)</summary>
    public readonly int SecurityLevel;

    /// <summary>Algorithm name</summary>
    public readonly string Name;

    internal SignatureParameters(SignatureAlgorithm alg, int pk, int sk, int sig, int level, string name)
    {
        Algorithm = alg;
        PublicKeySize = pk;
        SecretKeySize = sk;
        SignatureSize = sig;
        SecurityLevel = level;
        Name = name;
    }
}

/// <summary>
/// Key pair container
/// </summary>
public sealed class KeyPair : IDisposable
{
    private byte[]? _publicKey;
    private byte[]? _secretKey;
    private bool _disposed;

    /// <summary>Public key bytes</summary>
    public ReadOnlySpan<byte> PublicKey => _publicKey ?? ReadOnlySpan<byte>.Empty;

    /// <summary>Secret key bytes (sensitive)</summary>
    public ReadOnlySpan<byte> SecretKey => _secretKey ?? ReadOnlySpan<byte>.Empty;

    /// <summary>Key pair algorithm (KEM or Signature)</summary>
    public object Algorithm { get; }

    /// <summary>Key identifier/label</summary>
    public string? Label { get; set; }

    /// <summary>Key storage location</summary>
    public KeyStorage Storage { get; }

    /// <summary>Key usage restrictions</summary>
    public KeyUsage Usage { get; set; }

    /// <summary>Key creation timestamp</summary>
    public DateTimeOffset CreatedAt { get; }

    /// <summary>Hardware key handle (if stored in hardware)</summary>
    internal IntPtr HardwareHandle { get; set; }

    internal KeyPair(byte[] publicKey, byte[] secretKey, object algorithm, KeyStorage storage = KeyStorage.Volatile)
    {
        _publicKey = publicKey;
        _secretKey = secretKey;
        Algorithm = algorithm;
        Storage = storage;
        CreatedAt = DateTimeOffset.UtcNow;
        Usage = KeyUsage.All;
    }

    /// <summary>
    /// Export public key to byte array
    /// </summary>
    public byte[] ExportPublicKey()
    {
        ThrowIfDisposed();
        return _publicKey?.ToArray() ?? Array.Empty<byte>();
    }

    /// <summary>
    /// Export secret key to byte array (use with caution)
    /// </summary>
    public byte[] ExportSecretKey()
    {
        ThrowIfDisposed();
        if (!Usage.HasFlag(KeyUsage.Export))
            throw new InvalidOperationException("Key export not permitted");
        return _secretKey?.ToArray() ?? Array.Empty<byte>();
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(KeyPair));
    }

    /// <summary>
    /// Securely dispose of key material
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;

        // Secure zeroization
        if (_secretKey != null)
        {
            Array.Clear(_secretKey, 0, _secretKey.Length);
            _secretKey = null;
        }

        if (_publicKey != null)
        {
            Array.Clear(_publicKey, 0, _publicKey.Length);
            _publicKey = null;
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }

    ~KeyPair() => Dispose();
}

/// <summary>
/// Encapsulation result containing ciphertext and shared secret
/// </summary>
public sealed class EncapsulationResult : IDisposable
{
    private byte[]? _ciphertext;
    private byte[]? _sharedSecret;
    private bool _disposed;

    /// <summary>Ciphertext to send to recipient</summary>
    public ReadOnlySpan<byte> Ciphertext => _ciphertext ?? ReadOnlySpan<byte>.Empty;

    /// <summary>Shared secret (sensitive)</summary>
    public ReadOnlySpan<byte> SharedSecret => _sharedSecret ?? ReadOnlySpan<byte>.Empty;

    internal EncapsulationResult(byte[] ciphertext, byte[] sharedSecret)
    {
        _ciphertext = ciphertext;
        _sharedSecret = sharedSecret;
    }

    /// <summary>Export ciphertext to byte array</summary>
    public byte[] ExportCiphertext()
    {
        ThrowIfDisposed();
        return _ciphertext?.ToArray() ?? Array.Empty<byte>();
    }

    /// <summary>Export shared secret to byte array</summary>
    public byte[] ExportSharedSecret()
    {
        ThrowIfDisposed();
        return _sharedSecret?.ToArray() ?? Array.Empty<byte>();
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(EncapsulationResult));
    }

    public void Dispose()
    {
        if (_disposed) return;

        if (_sharedSecret != null)
        {
            Array.Clear(_sharedSecret, 0, _sharedSecret.Length);
            _sharedSecret = null;
        }

        _ciphertext = null;
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    ~EncapsulationResult() => Dispose();
}

/// <summary>
/// Batch operation item
/// </summary>
public readonly struct BatchItem<TInput, TOutput>
{
    /// <summary>Input data</summary>
    public readonly TInput Input;

    /// <summary>Output data (after processing)</summary>
    public readonly TOutput? Output;

    /// <summary>Operation status</summary>
    public readonly Quac100Status Status;

    /// <summary>Processing time in microseconds</summary>
    public readonly long ProcessingTimeMicros;

    internal BatchItem(TInput input, TOutput? output, Quac100Status status, long timeMicros)
    {
        Input = input;
        Output = output;
        Status = status;
        ProcessingTimeMicros = timeMicros;
    }
}

/// <summary>
/// Performance statistics
/// </summary>
public readonly struct PerformanceStats
{
    /// <summary>Operations per second</summary>
    public readonly double OpsPerSecond;

    /// <summary>Average latency in microseconds</summary>
    public readonly double AvgLatencyMicros;

    /// <summary>Minimum latency in microseconds</summary>
    public readonly long MinLatencyMicros;

    /// <summary>Maximum latency in microseconds</summary>
    public readonly long MaxLatencyMicros;

    /// <summary>99th percentile latency in microseconds</summary>
    public readonly long P99LatencyMicros;

    /// <summary>Total operations counted</summary>
    public readonly long TotalOperations;

    /// <summary>Total errors</summary>
    public readonly long TotalErrors;

    internal PerformanceStats(double ops, double avg, long min, long max, long p99, long total, long errors)
    {
        OpsPerSecond = ops;
        AvgLatencyMicros = avg;
        MinLatencyMicros = min;
        MaxLatencyMicros = max;
        P99LatencyMicros = p99;
        TotalOperations = total;
        TotalErrors = errors;
    }
}

#endregion