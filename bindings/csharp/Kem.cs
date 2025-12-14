// D:\quantacore-sdk\bindings\csharp\Kem.cs
// QUAC 100 SDK - Key Encapsulation Mechanism (ML-KEM)
// Copyright © 2025 Dyber, Inc. All Rights Reserved.

namespace Dyber.Quac100;

/// <summary>
/// ML-KEM (Kyber) Key Encapsulation Mechanism operations
/// </summary>
public sealed class Kem
{
    private readonly Device _device;

    /// <summary>ML-KEM-512 parameters</summary>
    public static readonly KemParameters MlKem512 = new(
        KemAlgorithm.MlKem512,
        publicKeySize: 800,
        secretKeySize: 1632,
        ciphertextSize: 768,
        sharedSecretSize: 32,
        securityLevel: 1,
        name: "ML-KEM-512"
    );

    /// <summary>ML-KEM-768 parameters (recommended)</summary>
    public static readonly KemParameters MlKem768 = new(
        KemAlgorithm.MlKem768,
        publicKeySize: 1184,
        secretKeySize: 2400,
        ciphertextSize: 1088,
        sharedSecretSize: 32,
        securityLevel: 3,
        name: "ML-KEM-768"
    );

    /// <summary>ML-KEM-1024 parameters</summary>
    public static readonly KemParameters MlKem1024 = new(
        KemAlgorithm.MlKem1024,
        publicKeySize: 1568,
        secretKeySize: 3168,
        ciphertextSize: 1568,
        sharedSecretSize: 32,
        securityLevel: 5,
        name: "ML-KEM-1024"
    );

    /// <summary>
    /// Create KEM operations context
    /// </summary>
    /// <param name="device">Device to use for operations</param>
    public Kem(Device device)
    {
        _device = device ?? throw new ArgumentNullException(nameof(device));
    }

    /// <summary>
    /// Get parameters for a KEM algorithm
    /// </summary>
    public static KemParameters GetParameters(KemAlgorithm algorithm)
    {
        return algorithm switch
        {
            KemAlgorithm.MlKem512 => MlKem512,
            KemAlgorithm.MlKem768 => MlKem768,
            KemAlgorithm.MlKem1024 => MlKem1024,
            _ => throw new ArgumentException($"Unknown algorithm: {algorithm}", nameof(algorithm))
        };
    }

    /// <summary>
    /// Generate a new ML-KEM key pair
    /// </summary>
    /// <param name="algorithm">ML-KEM variant</param>
    /// <returns>Generated key pair</returns>
    public KeyPair GenerateKeyPair(KemAlgorithm algorithm = KemAlgorithm.MlKem768)
    {
        var parameters = GetParameters(algorithm);

        var publicKey = new byte[parameters.PublicKeySize];
        var secretKey = new byte[parameters.SecretKeySize];
        int pkLen = publicKey.Length;
        int skLen = secretKey.Length;

        var status = (Quac100Status)NativeMethods.quac_kem_keygen(
            _device.Handle,
            (int)algorithm,
            publicKey, ref pkLen,
            secretKey, ref skLen
        );

        Quac100Exception.ThrowIfError(status, "Key generation failed");

        // Trim to actual size if needed
        if (pkLen < publicKey.Length)
            Array.Resize(ref publicKey, pkLen);
        if (skLen < secretKey.Length)
            Array.Resize(ref secretKey, skLen);

        var keyPair = new KeyPair(publicKey, secretKey, algorithm)
        {
            Usage = KeyUsage.AllKem
        };

        return keyPair;
    }

    /// <summary>
    /// Generate key pair asynchronously
    /// </summary>
    public Task<KeyPair> GenerateKeyPairAsync(
        KemAlgorithm algorithm = KemAlgorithm.MlKem768,
        CancellationToken cancellationToken = default)
    {
        return Task.Run(() => GenerateKeyPair(algorithm), cancellationToken);
    }

    /// <summary>
    /// Encapsulate - generate ciphertext and shared secret using recipient's public key
    /// </summary>
    /// <param name="publicKey">Recipient's public key</param>
    /// <param name="algorithm">ML-KEM variant</param>
    /// <returns>Encapsulation result with ciphertext and shared secret</returns>
    public EncapsulationResult Encapsulate(ReadOnlySpan<byte> publicKey, KemAlgorithm algorithm = KemAlgorithm.MlKem768)
    {
        var parameters = GetParameters(algorithm);

        if (publicKey.Length != parameters.PublicKeySize)
            throw new ArgumentException($"Invalid public key size. Expected {parameters.PublicKeySize}, got {publicKey.Length}", nameof(publicKey));

        var ciphertext = new byte[parameters.CiphertextSize];
        var sharedSecret = new byte[parameters.SharedSecretSize];
        int ctLen = ciphertext.Length;
        int ssLen = sharedSecret.Length;

        var status = (Quac100Status)NativeMethods.quac_kem_encaps(
            _device.Handle,
            (int)algorithm,
            publicKey.ToArray(), publicKey.Length,
            ciphertext, ref ctLen,
            sharedSecret, ref ssLen
        );

        Quac100Exception.ThrowIfError(status, "Encapsulation failed");

        // Trim to actual size if needed
        if (ctLen < ciphertext.Length)
            Array.Resize(ref ciphertext, ctLen);
        if (ssLen < sharedSecret.Length)
            Array.Resize(ref sharedSecret, ssLen);

        return new EncapsulationResult(ciphertext, sharedSecret);
    }

    /// <summary>
    /// Encapsulate using a key pair object
    /// </summary>
    public EncapsulationResult Encapsulate(KeyPair keyPair)
    {
        if (keyPair.Algorithm is not KemAlgorithm algorithm)
            throw new ArgumentException("Key pair is not a KEM key pair", nameof(keyPair));

        return Encapsulate(keyPair.PublicKey, algorithm);
    }

    /// <summary>
    /// Encapsulate asynchronously
    /// </summary>
    public Task<EncapsulationResult> EncapsulateAsync(
        ReadOnlyMemory<byte> publicKey,
        KemAlgorithm algorithm = KemAlgorithm.MlKem768,
        CancellationToken cancellationToken = default)
    {
        return Task.Run(() => Encapsulate(publicKey.Span, algorithm), cancellationToken);
    }

    /// <summary>
    /// Decapsulate - recover shared secret from ciphertext using secret key
    /// </summary>
    /// <param name="secretKey">Recipient's secret key</param>
    /// <param name="ciphertext">Ciphertext from encapsulation</param>
    /// <param name="algorithm">ML-KEM variant</param>
    /// <returns>Shared secret</returns>
    public byte[] Decapsulate(ReadOnlySpan<byte> secretKey, ReadOnlySpan<byte> ciphertext, KemAlgorithm algorithm = KemAlgorithm.MlKem768)
    {
        var parameters = GetParameters(algorithm);

        if (secretKey.Length != parameters.SecretKeySize)
            throw new ArgumentException($"Invalid secret key size. Expected {parameters.SecretKeySize}, got {secretKey.Length}", nameof(secretKey));

        if (ciphertext.Length != parameters.CiphertextSize)
            throw new ArgumentException($"Invalid ciphertext size. Expected {parameters.CiphertextSize}, got {ciphertext.Length}", nameof(ciphertext));

        var sharedSecret = new byte[parameters.SharedSecretSize];
        int ssLen = sharedSecret.Length;

        var status = (Quac100Status)NativeMethods.quac_kem_decaps(
            _device.Handle,
            (int)algorithm,
            secretKey.ToArray(), secretKey.Length,
            ciphertext.ToArray(), ciphertext.Length,
            sharedSecret, ref ssLen
        );

        Quac100Exception.ThrowIfError(status, "Decapsulation failed");

        if (ssLen < sharedSecret.Length)
            Array.Resize(ref sharedSecret, ssLen);

        return sharedSecret;
    }

    /// <summary>
    /// Decapsulate using key pair and encapsulation result
    /// </summary>
    public byte[] Decapsulate(KeyPair keyPair, EncapsulationResult encapsulation)
    {
        if (keyPair.Algorithm is not KemAlgorithm algorithm)
            throw new ArgumentException("Key pair is not a KEM key pair", nameof(keyPair));

        return Decapsulate(keyPair.SecretKey, encapsulation.Ciphertext, algorithm);
    }

    /// <summary>
    /// Decapsulate using key pair and raw ciphertext
    /// </summary>
    public byte[] Decapsulate(KeyPair keyPair, ReadOnlySpan<byte> ciphertext)
    {
        if (keyPair.Algorithm is not KemAlgorithm algorithm)
            throw new ArgumentException("Key pair is not a KEM key pair", nameof(keyPair));

        return Decapsulate(keyPair.SecretKey, ciphertext, algorithm);
    }

    /// <summary>
    /// Decapsulate asynchronously
    /// </summary>
    public Task<byte[]> DecapsulateAsync(
        ReadOnlyMemory<byte> secretKey,
        ReadOnlyMemory<byte> ciphertext,
        KemAlgorithm algorithm = KemAlgorithm.MlKem768,
        CancellationToken cancellationToken = default)
    {
        return Task.Run(() => Decapsulate(secretKey.Span, ciphertext.Span, algorithm), cancellationToken);
    }

    /// <summary>
    /// Perform a full key exchange (keygen + encaps + decaps) for testing/demo
    /// </summary>
    /// <param name="algorithm">ML-KEM variant</param>
    /// <returns>Tuple of (KeyPair, EncapsulationResult, SharedSecret)</returns>
    public (KeyPair KeyPair, EncapsulationResult Encapsulation, byte[] SharedSecret) DemoKeyExchange(
        KemAlgorithm algorithm = KemAlgorithm.MlKem768)
    {
        // Generate key pair
        var keyPair = GenerateKeyPair(algorithm);

        // Encapsulate to public key
        var encapsulation = Encapsulate(keyPair.PublicKey, algorithm);

        // Decapsulate with secret key
        var sharedSecret = Decapsulate(keyPair.SecretKey, encapsulation.Ciphertext, algorithm);

        // Verify shared secrets match
        if (!encapsulation.SharedSecret.SequenceEqual(sharedSecret))
            throw new Quac100Exception("Key exchange failed: shared secrets do not match");

        return (keyPair, encapsulation, sharedSecret);
    }

    /// <summary>
    /// Batch encapsulation for high throughput
    /// </summary>
    /// <param name="publicKeys">Array of public keys</param>
    /// <param name="algorithm">ML-KEM variant</param>
    /// <returns>Array of encapsulation results</returns>
    public EncapsulationResult[] EncapsulateBatch(
        ReadOnlySpan<byte>[] publicKeys,
        KemAlgorithm algorithm = KemAlgorithm.MlKem768)
    {
        var parameters = GetParameters(algorithm);
        var results = new EncapsulationResult[publicKeys.Length];

        // For now, sequential processing (native batch support can be added)
        for (int i = 0; i < publicKeys.Length; i++)
        {
            results[i] = Encapsulate(publicKeys[i], algorithm);
        }

        return results;
    }

    /// <summary>
    /// Parallel batch encapsulation
    /// </summary>
    public async Task<EncapsulationResult[]> EncapsulateBatchAsync(
        ReadOnlyMemory<byte>[] publicKeys,
        KemAlgorithm algorithm = KemAlgorithm.MlKem768,
        int maxParallelism = 4,
        CancellationToken cancellationToken = default)
    {
        var results = new EncapsulationResult[publicKeys.Length];
        var semaphore = new SemaphoreSlim(maxParallelism);

        var tasks = publicKeys.Select(async (pk, index) =>
        {
            await semaphore.WaitAsync(cancellationToken);
            try
            {
                results[index] = await EncapsulateAsync(pk, algorithm, cancellationToken);
            }
            finally
            {
                semaphore.Release();
            }
        });

        await Task.WhenAll(tasks);
        return results;
    }

    /// <summary>
    /// Import a public key from raw bytes
    /// </summary>
    public static (byte[] PublicKey, KemAlgorithm Algorithm) ImportPublicKey(ReadOnlySpan<byte> keyData)
    {
        // Determine algorithm from key size
        var algorithm = keyData.Length switch
        {
            800 => KemAlgorithm.MlKem512,
            1184 => KemAlgorithm.MlKem768,
            1568 => KemAlgorithm.MlKem1024,
            _ => throw new ArgumentException($"Unknown public key size: {keyData.Length}", nameof(keyData))
        };

        return (keyData.ToArray(), algorithm);
    }

    /// <summary>
    /// Import a secret key from raw bytes
    /// </summary>
    public static (byte[] SecretKey, KemAlgorithm Algorithm) ImportSecretKey(ReadOnlySpan<byte> keyData)
    {
        // Determine algorithm from key size
        var algorithm = keyData.Length switch
        {
            1632 => KemAlgorithm.MlKem512,
            2400 => KemAlgorithm.MlKem768,
            3168 => KemAlgorithm.MlKem1024,
            _ => throw new ArgumentException($"Unknown secret key size: {keyData.Length}", nameof(keyData))
        };

        return (keyData.ToArray(), algorithm);
    }
}

/// <summary>
/// Extension methods for KEM operations
/// </summary>
public static class KemExtensions
{
    /// <summary>
    /// Create KEM operations from device
    /// </summary>
    public static Kem GetKem(this Device device) => new(device);

    /// <summary>
    /// Check if key pair is a KEM key pair
    /// </summary>
    public static bool IsKemKeyPair(this KeyPair keyPair) => keyPair.Algorithm is KemAlgorithm;

    /// <summary>
    /// Get KEM algorithm from key pair
    /// </summary>
    public static KemAlgorithm? GetKemAlgorithm(this KeyPair keyPair) => keyPair.Algorithm as KemAlgorithm?;
}