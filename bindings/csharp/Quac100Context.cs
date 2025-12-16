// D:\quantacore-sdk\bindings\csharp\Quac100Context.cs
// QUAC 100 SDK - Main API Context
// Copyright © 2025 Dyber, Inc. All Rights Reserved.

using System.Runtime.InteropServices;

namespace Dyber.Quac100;

/// <summary>
/// Main QUAC 100 SDK context providing unified access to all cryptographic operations
/// </summary>
public sealed class Quac100Context : IDisposable
{
    private static bool _initialized;
    private static readonly object _initLock = new();

    private readonly Device _device;
    private readonly Kem _kem;
    private readonly Signer _signer;
    private readonly QuantumRandom _random;
    private bool _disposed;

    /// <summary>Underlying device</summary>
    public Device Device => _device;

    /// <summary>KEM operations (ML-KEM)</summary>
    public Kem Kem => _kem;

    /// <summary>Signature operations (ML-DSA, SLH-DSA)</summary>
    public Signer Signer => _signer;

    /// <summary>Quantum random number generator</summary>
    public QuantumRandom Random => _random;

    /// <summary>SDK version string</summary>
    public static string Version
    {
        get
        {
            EnsureInitialized();
            var ptr = NativeMethods.quac_version();
            return Marshal.PtrToStringAnsi(ptr) ?? "unknown";
        }
    }

    /// <summary>SDK version numbers</summary>
    public static (int Major, int Minor, int Patch) VersionInfo
    {
        get
        {
            EnsureInitialized();
            NativeMethods.quac_version_info(out int major, out int minor, out int patch);
            return (major, minor, patch);
        }
    }

    /// <summary>
    /// Initialize the QUAC 100 SDK
    /// </summary>
    /// <param name="flags">Initialization flags</param>
    public static void Initialize(DeviceFlags flags = DeviceFlags.HardwareAcceleration)
    {
        lock (_initLock)
        {
            if (_initialized)
                return;

            var status = (Quac100Status)NativeMethods.quac_init((uint)flags);
            Quac100Exception.ThrowIfError(status, "SDK initialization failed");

            _initialized = true;
        }
    }

    /// <summary>
    /// Cleanup the QUAC 100 SDK
    /// </summary>
    public static void Cleanup()
    {
        lock (_initLock)
        {
            if (!_initialized)
                return;

            NativeMethods.quac_cleanup();
            _initialized = false;
        }
    }

    private static void EnsureInitialized()
    {
        if (!_initialized)
        {
            Initialize();
        }
    }

    /// <summary>
    /// Create a new QUAC 100 context
    /// </summary>
    /// <param name="deviceIndex">Device index (default 0)</param>
    /// <param name="flags">Device flags</param>
    public Quac100Context(int deviceIndex = 0, DeviceFlags flags = DeviceFlags.HardwareAcceleration)
    {
        EnsureInitialized();

        _device = new Device(deviceIndex, flags);
        _kem = new Kem(_device);
        _signer = new Signer(_device);
        _random = new QuantumRandom(_device);
    }

    /// <summary>
    /// Create context from existing device
    /// </summary>
    internal Quac100Context(Device device)
    {
        _device = device ?? throw new ArgumentNullException(nameof(device));
        _kem = new Kem(_device);
        _signer = new Signer(_device);
        _random = new QuantumRandom(_device);
    }

    /// <summary>
    /// Create context using the first available device
    /// </summary>
    public static Quac100Context Open(DeviceFlags flags = DeviceFlags.HardwareAcceleration)
    {
        return new Quac100Context(0, flags);
    }

    /// <summary>
    /// Try to create context, returns null if no device available
    /// </summary>
    public static Quac100Context? TryOpen(int deviceIndex = 0, DeviceFlags flags = DeviceFlags.HardwareAcceleration)
    {
        try
        {
            return new Quac100Context(deviceIndex, flags);
        }
        catch (DeviceNotFoundException)
        {
            return null;
        }
    }

    #region Convenience Methods

    /// <summary>
    /// Generate ML-KEM key pair (convenience method)
    /// </summary>
    public KeyPair GenerateKemKeyPair(KemAlgorithm algorithm = KemAlgorithm.MlKem768)
        => _kem.GenerateKeyPair(algorithm);

    /// <summary>
    /// Generate signature key pair (convenience method)
    /// </summary>
    public KeyPair GenerateSignatureKeyPair(SignatureAlgorithm algorithm = SignatureAlgorithm.MlDsa65)
        => _signer.GenerateKeyPair(algorithm);

    /// <summary>
    /// Encapsulate (convenience method)
    /// </summary>
    public EncapsulationResult Encapsulate(ReadOnlySpan<byte> publicKey, KemAlgorithm algorithm = KemAlgorithm.MlKem768)
        => _kem.Encapsulate(publicKey, algorithm);

    /// <summary>
    /// Decapsulate (convenience method)
    /// </summary>
    public byte[] Decapsulate(ReadOnlySpan<byte> secretKey, ReadOnlySpan<byte> ciphertext, KemAlgorithm algorithm = KemAlgorithm.MlKem768)
        => _kem.Decapsulate(secretKey, ciphertext, algorithm);

    /// <summary>
    /// Sign message (convenience method)
    /// </summary>
    public byte[] Sign(KeyPair keyPair, ReadOnlySpan<byte> message)
        => _signer.Sign(keyPair, message);

    /// <summary>
    /// Verify signature (convenience method)
    /// </summary>
    public bool Verify(KeyPair keyPair, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
        => _signer.Verify(keyPair, message, signature);

    /// <summary>
    /// Generate random bytes (convenience method)
    /// </summary>
    public byte[] GenerateRandom(int count)
        => _random.GetBytes(count);

    /// <summary>
    /// Fill buffer with random bytes (convenience method)
    /// </summary>
    public void FillRandom(Span<byte> buffer)
        => _random.GetBytes(buffer);

    #endregion

    #region Hash Operations

    /// <summary>
    /// Compute hash of data
    /// </summary>
    public byte[] Hash(ReadOnlySpan<byte> data, HashAlgorithm algorithm = HashAlgorithm.Sha256)
    {
        ThrowIfDisposed();

        int hashLen = algorithm switch
        {
            HashAlgorithm.Sha256 => 32,
            HashAlgorithm.Sha384 => 48,
            HashAlgorithm.Sha512 => 64,
            HashAlgorithm.Sha3_256 => 32,
            HashAlgorithm.Sha3_384 => 48,
            HashAlgorithm.Sha3_512 => 64,
            _ => 32
        };

        var hash = new byte[hashLen];
        int len = hash.Length;

        var status = (Quac100Status)NativeMethods.quac_hash(
            _device.Handle,
            (int)algorithm,
            data.ToArray(), data.Length,
            hash, ref len
        );

        Quac100Exception.ThrowIfError(status, "Hash computation failed");

        if (len < hash.Length)
            Array.Resize(ref hash, len);

        return hash;
    }

    /// <summary>
    /// Create incremental hash context
    /// </summary>
    public IncrementalHash CreateIncrementalHash(HashAlgorithm algorithm = HashAlgorithm.Sha256)
    {
        ThrowIfDisposed();
        return new IncrementalHash(_device, algorithm);
    }

    #endregion

    #region Key Storage

    /// <summary>
    /// Store key in hardware
    /// </summary>
    public int StoreKey(KeyPair keyPair, string? label = null)
    {
        ThrowIfDisposed();

        int keyType = keyPair.Algorithm switch
        {
            KemAlgorithm alg => (int)alg,
            SignatureAlgorithm alg => (int)alg + 100,
            _ => throw new ArgumentException("Unknown key type")
        };

        var key = keyPair.ExportSecretKey();

        var status = (Quac100Status)NativeMethods.quac_key_store(
            _device.Handle,
            key, key.Length,
            keyType,
            label ?? "",
            (uint)keyPair.Usage,
            out int slot
        );

        // Secure clear the exported key
        Array.Clear(key, 0, key.Length);

        Quac100Exception.ThrowIfError(status, "Key storage failed");

        keyPair.HardwareHandle = new IntPtr(slot);
        return slot;
    }

    /// <summary>
    /// Delete key from hardware storage
    /// </summary>
    public void DeleteKey(int slot)
    {
        ThrowIfDisposed();

        var status = (Quac100Status)NativeMethods.quac_key_delete(_device.Handle, slot);
        Quac100Exception.ThrowIfError(status, "Key deletion failed");
    }

    /// <summary>
    /// List stored keys
    /// </summary>
    public int[] ListKeys()
    {
        ThrowIfDisposed();

        var slots = new int[256];

        var status = (Quac100Status)NativeMethods.quac_key_list(
            _device.Handle, slots, slots.Length, out int count);

        Quac100Exception.ThrowIfError(status, "Key listing failed");

        return slots.Take(count).ToArray();
    }

    #endregion

    #region Utility Methods

    /// <summary>
    /// Securely zero memory
    /// </summary>
    public static void SecureZero(byte[] buffer)
    {
        if (buffer != null)
        {
            NativeMethods.quac_secure_zero(buffer, buffer.Length);
        }
    }

    /// <summary>
    /// Constant-time comparison
    /// </summary>
    public static bool SecureCompare(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        if (a.Length != b.Length)
            return false;

        return NativeMethods.quac_secure_compare(a.ToArray(), b.ToArray(), a.Length) == 0;
    }

    /// <summary>
    /// Get error message for status code
    /// </summary>
    public static string GetErrorMessage(Quac100Status status)
    {
        var ptr = NativeMethods.quac_error_string((int)status);
        return Marshal.PtrToStringAnsi(ptr) ?? "Unknown error";
    }

    #endregion

    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(Quac100Context));
    }

    /// <summary>
    /// Dispose all resources
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;

        _random?.Dispose();
        _device?.Dispose();

        _disposed = true;
        GC.SuppressFinalize(this);
    }

    ~Quac100Context() => Dispose();
}

/// <summary>
/// Incremental hash computation
/// </summary>
public sealed class IncrementalHash : IDisposable
{
    private IntPtr _context;
    private readonly HashAlgorithm _algorithm;
    private bool _disposed;
    private bool _finalized;

    internal IncrementalHash(Device device, HashAlgorithm algorithm)
    {
        _algorithm = algorithm;

        var status = (Quac100Status)NativeMethods.quac_hash_init(
            device.Handle, (int)algorithm, out _context);

        Quac100Exception.ThrowIfError(status, "Hash initialization failed");
    }

    /// <summary>
    /// Update hash with more data
    /// </summary>
    public void Update(ReadOnlySpan<byte> data)
    {
        ThrowIfDisposed();

        if (_finalized)
            throw new InvalidOperationException("Hash already finalized");

        var status = (Quac100Status)NativeMethods.quac_hash_update(
            _context, data.ToArray(), data.Length);

        Quac100Exception.ThrowIfError(status, "Hash update failed");
    }

    /// <summary>
    /// Finalize and get hash value
    /// </summary>
    public byte[] GetHashAndReset()
    {
        ThrowIfDisposed();

        if (_finalized)
            throw new InvalidOperationException("Hash already finalized");

        int hashLen = _algorithm switch
        {
            HashAlgorithm.Sha256 => 32,
            HashAlgorithm.Sha384 => 48,
            HashAlgorithm.Sha512 => 64,
            HashAlgorithm.Sha3_256 => 32,
            HashAlgorithm.Sha3_384 => 48,
            HashAlgorithm.Sha3_512 => 64,
            _ => 32
        };

        var hash = new byte[hashLen];
        int len = hash.Length;

        var status = (Quac100Status)NativeMethods.quac_hash_final(_context, hash, ref len);
        Quac100Exception.ThrowIfError(status, "Hash finalization failed");

        _finalized = true;

        if (len < hash.Length)
            Array.Resize(ref hash, len);

        return hash;
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(IncrementalHash));
    }

    public void Dispose()
    {
        if (_disposed) return;

        if (_context != IntPtr.Zero)
        {
            NativeMethods.quac_hash_free(_context);
            _context = IntPtr.Zero;
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }

    ~IncrementalHash() => Dispose();
}