// D:\quantacore-sdk\bindings\csharp\Random.cs
// QUAC 100 SDK - Quantum Random Number Generation
// Copyright © 2025 Dyber, Inc. All Rights Reserved.

using System.Buffers;
using System.Security.Cryptography;

namespace Dyber.Quac100;

/// <summary>
/// Quantum Random Number Generator operations
/// </summary>
public sealed class QuantumRandom : RandomNumberGenerator
{
    private readonly Device _device;
    private readonly EntropySource _preferredSource;
    private bool _disposed;

    /// <summary>Default chunk size for large requests</summary>
    public const int DefaultChunkSize = 65536; // 64KB

    /// <summary>
    /// Create QRNG operations context
    /// </summary>
    /// <param name="device">Device to use for operations</param>
    /// <param name="preferredSource">Preferred entropy source</param>
    public QuantumRandom(Device device, EntropySource preferredSource = EntropySource.Qrng)
    {
        _device = device ?? throw new ArgumentNullException(nameof(device));
        _preferredSource = preferredSource;
    }

    /// <summary>
    /// Generate random bytes
    /// </summary>
    /// <param name="count">Number of bytes to generate</param>
    /// <returns>Random byte array</returns>
    public new byte[] GetBytes(int count)
    {
        ThrowIfDisposed();

        if (count < 0)
            throw new ArgumentOutOfRangeException(nameof(count), "Count must be non-negative");

        if (count == 0)
            return Array.Empty<byte>();

        var buffer = new byte[count];
        GetBytes(buffer);
        return buffer;
    }

    /// <summary>
    /// Fill buffer with random bytes
    /// </summary>
    /// <param name="data">Buffer to fill</param>
    public override void GetBytes(byte[] data)
    {
        ThrowIfDisposed();

        if (data == null)
            throw new ArgumentNullException(nameof(data));

        GetBytes(data.AsSpan());
    }

    /// <summary>
    /// Fill span with random bytes
    /// </summary>
    public override void GetBytes(Span<byte> data)
    {
        ThrowIfDisposed();

        if (data.Length == 0)
            return;

        // For large requests, process in chunks
        if (data.Length > DefaultChunkSize)
        {
            int offset = 0;
            while (offset < data.Length)
            {
                int chunkSize = Math.Min(DefaultChunkSize, data.Length - offset);
                var chunk = data.Slice(offset, chunkSize);
                FillChunk(chunk);
                offset += chunkSize;
            }
        }
        else
        {
            FillChunk(data);
        }
    }

    private void FillChunk(Span<byte> chunk)
    {
        var buffer = chunk.ToArray();

        Quac100Status status;

        if (_preferredSource == EntropySource.Qrng)
        {
            status = (Quac100Status)NativeMethods.quac_random_bytes(
                _device.Handle, buffer, buffer.Length);
        }
        else
        {
            status = (Quac100Status)NativeMethods.quac_random_bytes_ex(
                _device.Handle, buffer, buffer.Length, (int)_preferredSource);
        }

        Quac100Exception.ThrowIfError(status, "Random byte generation failed");

        buffer.AsSpan().CopyTo(chunk);
    }

    /// <summary>
    /// Generate non-zero random bytes
    /// </summary>
    public override void GetNonZeroBytes(byte[] data)
    {
        ThrowIfDisposed();

        GetNonZeroBytes(data.AsSpan());
    }

    /// <summary>
    /// Fill span with non-zero random bytes
    /// </summary>
    public override void GetNonZeroBytes(Span<byte> data)
    {
        ThrowIfDisposed();

        // Generate random bytes and replace zeros
        GetBytes(data);

        for (int i = 0; i < data.Length; i++)
        {
            while (data[i] == 0)
            {
                var replacement = new byte[1];
                GetBytes(replacement);
                data[i] = replacement[0];
            }
        }
    }

    /// <summary>
    /// Generate a random 32-bit integer
    /// </summary>
    public int GetInt32()
    {
        Span<byte> buffer = stackalloc byte[4];
        GetBytes(buffer);
        return BitConverter.ToInt32(buffer);
    }

    /// <summary>
    /// Generate a random 32-bit integer in range [0, maxValue)
    /// </summary>
    public new int GetInt32(int maxValue)
    {
        if (maxValue <= 0)
            throw new ArgumentOutOfRangeException(nameof(maxValue), "Max value must be positive");

        return GetInt32(0, maxValue);
    }

    /// <summary>
    /// Generate a random 32-bit integer in range [minValue, maxValue)
    /// </summary>
    public new int GetInt32(int minValue, int maxValue)
    {
        if (minValue >= maxValue)
            throw new ArgumentException("minValue must be less than maxValue");

        long range = (long)maxValue - minValue;

        // Use rejection sampling for unbiased results
        long limit = uint.MaxValue - (uint.MaxValue % range);
        uint value;

        do
        {
            Span<byte> buffer = stackalloc byte[4];
            GetBytes(buffer);
            value = BitConverter.ToUInt32(buffer);
        }
        while (value >= limit);

        return (int)(minValue + (value % range));
    }

    /// <summary>
    /// Generate a random 64-bit integer
    /// </summary>
    public long GetInt64()
    {
        Span<byte> buffer = stackalloc byte[8];
        GetBytes(buffer);
        return BitConverter.ToInt64(buffer);
    }

    /// <summary>
    /// Generate a random 64-bit integer in range [0, maxValue)
    /// </summary>
    public long GetInt64(long maxValue)
    {
        if (maxValue <= 0)
            throw new ArgumentOutOfRangeException(nameof(maxValue), "Max value must be positive");

        return GetInt64(0, maxValue);
    }

    /// <summary>
    /// Generate a random 64-bit integer in range [minValue, maxValue)
    /// </summary>
    public long GetInt64(long minValue, long maxValue)
    {
        if (minValue >= maxValue)
            throw new ArgumentException("minValue must be less than maxValue");

        // Use BigInteger for large ranges if needed
        ulong range = (ulong)(maxValue - minValue);
        ulong limit = ulong.MaxValue - (ulong.MaxValue % range);
        ulong value;

        do
        {
            Span<byte> buffer = stackalloc byte[8];
            GetBytes(buffer);
            value = BitConverter.ToUInt64(buffer);
        }
        while (value >= limit);

        return minValue + (long)(value % range);
    }

    /// <summary>
    /// Generate a random double in range [0.0, 1.0)
    /// </summary>
    public double GetDouble()
    {
        // Generate 53 random bits for full double precision
        Span<byte> buffer = stackalloc byte[8];
        GetBytes(buffer);
        ulong value = BitConverter.ToUInt64(buffer);

        // Use only 53 bits for mantissa
        return (value >> 11) * (1.0 / (1UL << 53));
    }

    /// <summary>
    /// Generate a random float in range [0.0, 1.0)
    /// </summary>
    public float GetSingle()
    {
        Span<byte> buffer = stackalloc byte[4];
        GetBytes(buffer);
        uint value = BitConverter.ToUInt32(buffer);

        // Use only 24 bits for mantissa
        return (value >> 8) * (1.0f / (1U << 24));
    }

    /// <summary>
    /// Generate a random boolean
    /// </summary>
    public bool GetBoolean()
    {
        return (GetBytes(1)[0] & 1) == 1;
    }

    /// <summary>
    /// Generate a random GUID
    /// </summary>
    public Guid GetGuid()
    {
        var bytes = GetBytes(16);

        // Set version 4 (random) and variant bits
        bytes[6] = (byte)((bytes[6] & 0x0F) | 0x40); // Version 4
        bytes[8] = (byte)((bytes[8] & 0x3F) | 0x80); // Variant 1

        return new Guid(bytes);
    }

    /// <summary>
    /// Shuffle an array in place using Fisher-Yates algorithm
    /// </summary>
    public void Shuffle<T>(T[] array)
    {
        Shuffle(array.AsSpan());
    }

    /// <summary>
    /// Shuffle a span in place using Fisher-Yates algorithm
    /// </summary>
    public new void Shuffle<T>(Span<T> span)
    {
        for (int i = span.Length - 1; i > 0; i--)
        {
            int j = GetInt32(0, i + 1);
            (span[i], span[j]) = (span[j], span[i]);
        }
    }

    /// <summary>
    /// Select a random element from an array
    /// </summary>
    public T Choose<T>(T[] array)
    {
        if (array == null || array.Length == 0)
            throw new ArgumentException("Array cannot be null or empty", nameof(array));

        return array[GetInt32(0, array.Length)];
    }

    /// <summary>
    /// Select multiple random elements from an array (with replacement)
    /// </summary>
    public T[] ChooseMultiple<T>(T[] array, int count)
    {
        if (array == null || array.Length == 0)
            throw new ArgumentException("Array cannot be null or empty", nameof(array));

        var result = new T[count];
        for (int i = 0; i < count; i++)
        {
            result[i] = array[GetInt32(0, array.Length)];
        }

        return result;
    }

    /// <summary>
    /// Generate random string from character set
    /// </summary>
    public string GetString(int length, string charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
    {
        if (length < 0)
            throw new ArgumentOutOfRangeException(nameof(length));

        if (string.IsNullOrEmpty(charset))
            throw new ArgumentException("Charset cannot be null or empty", nameof(charset));

        if (length == 0)
            return string.Empty;

        var chars = new char[length];
        for (int i = 0; i < length; i++)
        {
            chars[i] = charset[GetInt32(0, charset.Length)];
        }

        return new string(chars);
    }

    /// <summary>
    /// Get entropy pool status
    /// </summary>
    public (int Level, EntropySource Source) GetEntropyStatus()
    {
        ThrowIfDisposed();

        var status = (Quac100Status)NativeMethods.quac_random_entropy_status(
            _device.Handle, out int level, out int source);

        Quac100Exception.ThrowIfError(status, "Failed to get entropy status");

        return (level, (EntropySource)source);
    }

    /// <summary>
    /// Seed the random number generator (may be ignored by hardware)
    /// </summary>
    public void Seed(ReadOnlySpan<byte> seed)
    {
        ThrowIfDisposed();

        var status = (Quac100Status)NativeMethods.quac_random_seed(
            _device.Handle, seed.ToArray(), seed.Length);

        Quac100Exception.ThrowIfError(status, "Failed to seed RNG");
    }

    /// <summary>
    /// Reseed from hardware entropy
    /// </summary>
    public void Reseed()
    {
        ThrowIfDisposed();

        var status = (Quac100Status)NativeMethods.quac_random_reseed(_device.Handle);
        Quac100Exception.ThrowIfError(status, "Failed to reseed RNG");
    }

    /// <summary>
    /// Generate random bytes asynchronously
    /// </summary>
    public Task<byte[]> GetBytesAsync(int count, CancellationToken cancellationToken = default)
    {
        return Task.Run(() => GetBytes(count), cancellationToken);
    }

    /// <summary>
    /// Benchmark random number generation
    /// </summary>
    /// <param name="bytesToGenerate">Total bytes to generate</param>
    /// <returns>Generation rate in MB/s</returns>
    public double Benchmark(int bytesToGenerate = 10 * 1024 * 1024)
    {
        ThrowIfDisposed();

        var buffer = new byte[DefaultChunkSize];
        int remaining = bytesToGenerate;

        var sw = System.Diagnostics.Stopwatch.StartNew();

        while (remaining > 0)
        {
            int toGenerate = Math.Min(buffer.Length, remaining);
            GetBytes(buffer.AsSpan(0, toGenerate));
            remaining -= toGenerate;
        }

        sw.Stop();

        return bytesToGenerate / (1024.0 * 1024.0) / sw.Elapsed.TotalSeconds;
    }

    /// <summary>
    /// Compute Shannon entropy estimate of generated bytes
    /// </summary>
    public double EstimateEntropy(int sampleSize = 100000)
    {
        ThrowIfDisposed();

        var bytes = GetBytes(sampleSize);
        var counts = new int[256];

        foreach (var b in bytes)
            counts[b]++;

        double entropy = 0;
        double n = sampleSize;

        for (int i = 0; i < 256; i++)
        {
            if (counts[i] > 0)
            {
                double p = counts[i] / n;
                entropy -= p * Math.Log2(p);
            }
        }

        return entropy;
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(QuantumRandom));
    }

    protected override void Dispose(bool disposing)
    {
        _disposed = true;
        base.Dispose(disposing);
    }
}

/// <summary>
/// Extension methods for random operations
/// </summary>
public static class QuantumRandomExtensions
{
    /// <summary>
    /// Create QuantumRandom from device
    /// </summary>
    public static QuantumRandom GetRandom(this Device device, EntropySource source = EntropySource.Qrng)
        => new(device, source);

    /// <summary>
    /// Fill buffer with quantum random bytes
    /// </summary>
    public static void FillRandom(this Device device, Span<byte> buffer)
    {
        using var rng = new QuantumRandom(device);
        rng.GetBytes(buffer);
    }

    /// <summary>
    /// Generate quantum random bytes
    /// </summary>
    public static byte[] GenerateRandom(this Device device, int count)
    {
        using var rng = new QuantumRandom(device);
        return rng.GetBytes(count);
    }
}