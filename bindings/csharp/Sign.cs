// D:\quantacore-sdk\bindings\csharp\Sign.cs
// QUAC 100 SDK - Digital Signature Operations (ML-DSA, SLH-DSA)
// Copyright © 2025 Dyber, Inc. All Rights Reserved.

namespace Dyber.Quac100;

/// <summary>
/// ML-DSA and SLH-DSA Digital Signature operations
/// </summary>
public sealed class Signer
{
    private readonly Device _device;

    #region ML-DSA Parameters

    /// <summary>ML-DSA-44 parameters (NIST Level 2)</summary>
    public static readonly SignatureParameters MlDsa44 = new(
        SignatureAlgorithm.MlDsa44,
        publicKeySize: 1312,
        secretKeySize: 2560,
        signatureSize: 2420,
        securityLevel: 2,
        name: "ML-DSA-44"
    );

    /// <summary>ML-DSA-65 parameters (NIST Level 3, recommended)</summary>
    public static readonly SignatureParameters MlDsa65 = new(
        SignatureAlgorithm.MlDsa65,
        publicKeySize: 1952,
        secretKeySize: 4032,
        signatureSize: 3309,
        securityLevel: 3,
        name: "ML-DSA-65"
    );

    /// <summary>ML-DSA-87 parameters (NIST Level 5)</summary>
    public static readonly SignatureParameters MlDsa87 = new(
        SignatureAlgorithm.MlDsa87,
        publicKeySize: 2592,
        secretKeySize: 4896,
        signatureSize: 4627,
        securityLevel: 5,
        name: "ML-DSA-87"
    );

    #endregion

    #region SLH-DSA Parameters (SHA2)

    /// <summary>SLH-DSA-SHA2-128s parameters</summary>
    public static readonly SignatureParameters SlhDsaSha2_128s = new(
        SignatureAlgorithm.SlhDsaSha2_128s,
        publicKeySize: 32,
        secretKeySize: 64,
        signatureSize: 7856,
        securityLevel: 1,
        name: "SLH-DSA-SHA2-128s"
    );

    /// <summary>SLH-DSA-SHA2-128f parameters</summary>
    public static readonly SignatureParameters SlhDsaSha2_128f = new(
        SignatureAlgorithm.SlhDsaSha2_128f,
        publicKeySize: 32,
        secretKeySize: 64,
        signatureSize: 17088,
        securityLevel: 1,
        name: "SLH-DSA-SHA2-128f"
    );

    /// <summary>SLH-DSA-SHA2-192s parameters</summary>
    public static readonly SignatureParameters SlhDsaSha2_192s = new(
        SignatureAlgorithm.SlhDsaSha2_192s,
        publicKeySize: 48,
        secretKeySize: 96,
        signatureSize: 16224,
        securityLevel: 3,
        name: "SLH-DSA-SHA2-192s"
    );

    /// <summary>SLH-DSA-SHA2-192f parameters</summary>
    public static readonly SignatureParameters SlhDsaSha2_192f = new(
        SignatureAlgorithm.SlhDsaSha2_192f,
        publicKeySize: 48,
        secretKeySize: 96,
        signatureSize: 35664,
        securityLevel: 3,
        name: "SLH-DSA-SHA2-192f"
    );

    /// <summary>SLH-DSA-SHA2-256s parameters</summary>
    public static readonly SignatureParameters SlhDsaSha2_256s = new(
        SignatureAlgorithm.SlhDsaSha2_256s,
        publicKeySize: 64,
        secretKeySize: 128,
        signatureSize: 29792,
        securityLevel: 5,
        name: "SLH-DSA-SHA2-256s"
    );

    /// <summary>SLH-DSA-SHA2-256f parameters</summary>
    public static readonly SignatureParameters SlhDsaSha2_256f = new(
        SignatureAlgorithm.SlhDsaSha2_256f,
        publicKeySize: 64,
        secretKeySize: 128,
        signatureSize: 49856,
        securityLevel: 5,
        name: "SLH-DSA-SHA2-256f"
    );

    #endregion

    /// <summary>
    /// Create Signer operations context
    /// </summary>
    /// <param name="device">Device to use for operations</param>
    public Signer(Device device)
    {
        _device = device ?? throw new ArgumentNullException(nameof(device));
    }

    /// <summary>
    /// Get parameters for a signature algorithm
    /// </summary>
    public static SignatureParameters GetParameters(SignatureAlgorithm algorithm)
    {
        return algorithm switch
        {
            SignatureAlgorithm.MlDsa44 => MlDsa44,
            SignatureAlgorithm.MlDsa65 => MlDsa65,
            SignatureAlgorithm.MlDsa87 => MlDsa87,
            SignatureAlgorithm.SlhDsaSha2_128s => SlhDsaSha2_128s,
            SignatureAlgorithm.SlhDsaSha2_128f => SlhDsaSha2_128f,
            SignatureAlgorithm.SlhDsaSha2_192s => SlhDsaSha2_192s,
            SignatureAlgorithm.SlhDsaSha2_192f => SlhDsaSha2_192f,
            SignatureAlgorithm.SlhDsaSha2_256s => SlhDsaSha2_256s,
            SignatureAlgorithm.SlhDsaSha2_256f => SlhDsaSha2_256f,
            _ => throw new ArgumentException($"Unknown algorithm: {algorithm}", nameof(algorithm))
        };
    }

    /// <summary>
    /// Generate a new signature key pair
    /// </summary>
    /// <param name="algorithm">Signature algorithm variant</param>
    /// <returns>Generated key pair</returns>
    public KeyPair GenerateKeyPair(SignatureAlgorithm algorithm = SignatureAlgorithm.MlDsa65)
    {
        var parameters = GetParameters(algorithm);

        var publicKey = new byte[parameters.PublicKeySize];
        var secretKey = new byte[parameters.SecretKeySize];
        int pkLen = publicKey.Length;
        int skLen = secretKey.Length;

        var status = (Quac100Status)NativeMethods.quac_sign_keygen(
            _device.Handle,
            (int)algorithm,
            publicKey, ref pkLen,
            secretKey, ref skLen
        );

        Quac100Exception.ThrowIfError(status, "Key generation failed");

        if (pkLen < publicKey.Length)
            Array.Resize(ref publicKey, pkLen);
        if (skLen < secretKey.Length)
            Array.Resize(ref secretKey, skLen);

        var keyPair = new KeyPair(publicKey, secretKey, algorithm)
        {
            Usage = KeyUsage.AllSign
        };

        return keyPair;
    }

    /// <summary>
    /// Generate key pair asynchronously
    /// </summary>
    public Task<KeyPair> GenerateKeyPairAsync(
        SignatureAlgorithm algorithm = SignatureAlgorithm.MlDsa65,
        CancellationToken cancellationToken = default)
    {
        return Task.Run(() => GenerateKeyPair(algorithm), cancellationToken);
    }

    /// <summary>
    /// Sign a message
    /// </summary>
    /// <param name="secretKey">Signing key</param>
    /// <param name="message">Message to sign</param>
    /// <param name="algorithm">Signature algorithm</param>
    /// <returns>Signature bytes</returns>
    public byte[] Sign(ReadOnlySpan<byte> secretKey, ReadOnlySpan<byte> message, SignatureAlgorithm algorithm = SignatureAlgorithm.MlDsa65)
    {
        var parameters = GetParameters(algorithm);

        if (secretKey.Length != parameters.SecretKeySize)
            throw new ArgumentException($"Invalid secret key size. Expected {parameters.SecretKeySize}, got {secretKey.Length}", nameof(secretKey));

        var signature = new byte[parameters.SignatureSize];
        int sigLen = signature.Length;

        var status = (Quac100Status)NativeMethods.quac_sign(
            _device.Handle,
            (int)algorithm,
            secretKey.ToArray(), secretKey.Length,
            message.ToArray(), message.Length,
            signature, ref sigLen
        );

        Quac100Exception.ThrowIfError(status, "Signing failed");

        if (sigLen < signature.Length)
            Array.Resize(ref signature, sigLen);

        return signature;
    }

    /// <summary>
    /// Sign a message using key pair
    /// </summary>
    public byte[] Sign(KeyPair keyPair, ReadOnlySpan<byte> message)
    {
        if (keyPair.Algorithm is not SignatureAlgorithm algorithm)
            throw new ArgumentException("Key pair is not a signature key pair", nameof(keyPair));

        return Sign(keyPair.SecretKey, message, algorithm);
    }

    /// <summary>
    /// Sign a string message (UTF-8 encoded)
    /// </summary>
    public byte[] Sign(KeyPair keyPair, string message)
    {
        return Sign(keyPair, System.Text.Encoding.UTF8.GetBytes(message));
    }

    /// <summary>
    /// Sign asynchronously
    /// </summary>
    public Task<byte[]> SignAsync(
        ReadOnlyMemory<byte> secretKey,
        ReadOnlyMemory<byte> message,
        SignatureAlgorithm algorithm = SignatureAlgorithm.MlDsa65,
        CancellationToken cancellationToken = default)
    {
        return Task.Run(() => Sign(secretKey.Span, message.Span, algorithm), cancellationToken);
    }

    /// <summary>
    /// Verify a signature
    /// </summary>
    /// <param name="publicKey">Verification key</param>
    /// <param name="message">Original message</param>
    /// <param name="signature">Signature to verify</param>
    /// <param name="algorithm">Signature algorithm</param>
    /// <returns>True if signature is valid</returns>
    public bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature, SignatureAlgorithm algorithm = SignatureAlgorithm.MlDsa65)
    {
        var parameters = GetParameters(algorithm);

        if (publicKey.Length != parameters.PublicKeySize)
            throw new ArgumentException($"Invalid public key size. Expected {parameters.PublicKeySize}, got {publicKey.Length}", nameof(publicKey));

        var status = (Quac100Status)NativeMethods.quac_verify(
            _device.Handle,
            (int)algorithm,
            publicKey.ToArray(), publicKey.Length,
            message.ToArray(), message.Length,
            signature.ToArray(), signature.Length
        );

        if (status == Quac100Status.Success)
            return true;

        if (status == Quac100Status.VerifyFailed)
            return false;

        Quac100Exception.ThrowIfError(status, "Verification error");
        return false;
    }

    /// <summary>
    /// Verify a signature using key pair
    /// </summary>
    public bool Verify(KeyPair keyPair, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        if (keyPair.Algorithm is not SignatureAlgorithm algorithm)
            throw new ArgumentException("Key pair is not a signature key pair", nameof(keyPair));

        return Verify(keyPair.PublicKey, message, signature, algorithm);
    }

    /// <summary>
    /// Verify a signature (string message)
    /// </summary>
    public bool Verify(KeyPair keyPair, string message, ReadOnlySpan<byte> signature)
    {
        return Verify(keyPair, System.Text.Encoding.UTF8.GetBytes(message), signature);
    }

    /// <summary>
    /// Verify and throw if invalid
    /// </summary>
    public void VerifyOrThrow(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature, SignatureAlgorithm algorithm = SignatureAlgorithm.MlDsa65)
    {
        if (!Verify(publicKey, message, signature, algorithm))
            throw new SignatureVerificationException("Signature verification failed");
    }

    /// <summary>
    /// Verify and throw if invalid (using key pair)
    /// </summary>
    public void VerifyOrThrow(KeyPair keyPair, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        if (!Verify(keyPair, message, signature))
            throw new SignatureVerificationException("Signature verification failed");
    }

    /// <summary>
    /// Verify asynchronously
    /// </summary>
    public Task<bool> VerifyAsync(
        ReadOnlyMemory<byte> publicKey,
        ReadOnlyMemory<byte> message,
        ReadOnlyMemory<byte> signature,
        SignatureAlgorithm algorithm = SignatureAlgorithm.MlDsa65,
        CancellationToken cancellationToken = default)
    {
        return Task.Run(() => Verify(publicKey.Span, message.Span, signature.Span, algorithm), cancellationToken);
    }

    /// <summary>
    /// Perform a full sign/verify round-trip for testing
    /// </summary>
    public (KeyPair KeyPair, byte[] Signature, bool Verified) DemoSignVerify(
        string message = "Hello, Post-Quantum World!",
        SignatureAlgorithm algorithm = SignatureAlgorithm.MlDsa65)
    {
        var messageBytes = System.Text.Encoding.UTF8.GetBytes(message);

        // Generate key pair
        var keyPair = GenerateKeyPair(algorithm);

        // Sign message
        var signature = Sign(keyPair, messageBytes);

        // Verify signature
        var verified = Verify(keyPair, messageBytes, signature);

        return (keyPair, signature, verified);
    }

    /// <summary>
    /// Batch sign multiple messages
    /// </summary>
    public byte[][] SignBatch(KeyPair keyPair, ReadOnlySpan<byte>[] messages)
    {
        if (keyPair.Algorithm is not SignatureAlgorithm algorithm)
            throw new ArgumentException("Key pair is not a signature key pair", nameof(keyPair));

        var signatures = new byte[messages.Length][];

        for (int i = 0; i < messages.Length; i++)
        {
            signatures[i] = Sign(keyPair.SecretKey, messages[i], algorithm);
        }

        return signatures;
    }

    /// <summary>
    /// Batch verify multiple signatures
    /// </summary>
    public bool[] VerifyBatch(KeyPair keyPair, ReadOnlySpan<byte>[] messages, ReadOnlySpan<byte>[] signatures)
    {
        if (messages.Length != signatures.Length)
            throw new ArgumentException("Messages and signatures arrays must have the same length");

        if (keyPair.Algorithm is not SignatureAlgorithm algorithm)
            throw new ArgumentException("Key pair is not a signature key pair", nameof(keyPair));

        var results = new bool[messages.Length];

        for (int i = 0; i < messages.Length; i++)
        {
            results[i] = Verify(keyPair.PublicKey, messages[i], signatures[i], algorithm);
        }

        return results;
    }

    /// <summary>
    /// Parallel batch signing
    /// </summary>
    public async Task<byte[][]> SignBatchAsync(
        KeyPair keyPair,
        ReadOnlyMemory<byte>[] messages,
        int maxParallelism = 4,
        CancellationToken cancellationToken = default)
    {
        if (keyPair.Algorithm is not SignatureAlgorithm algorithm)
            throw new ArgumentException("Key pair is not a signature key pair", nameof(keyPair));

        var signatures = new byte[messages.Length][];
        var semaphore = new SemaphoreSlim(maxParallelism);

        var tasks = messages.Select(async (msg, index) =>
        {
            await semaphore.WaitAsync(cancellationToken);
            try
            {
                signatures[index] = await SignAsync(keyPair.SecretKey.ToArray(), msg, algorithm, cancellationToken);
            }
            finally
            {
                semaphore.Release();
            }
        });

        await Task.WhenAll(tasks);
        return signatures;
    }

    /// <summary>
    /// Detect algorithm from public key size
    /// </summary>
    public static SignatureAlgorithm? DetectAlgorithmFromPublicKey(int keySize)
    {
        return keySize switch
        {
            1312 => SignatureAlgorithm.MlDsa44,
            1952 => SignatureAlgorithm.MlDsa65,
            2592 => SignatureAlgorithm.MlDsa87,
            32 => SignatureAlgorithm.SlhDsaSha2_128s, // or 128f - need context
            48 => SignatureAlgorithm.SlhDsaSha2_192s, // or 192f
            64 => SignatureAlgorithm.SlhDsaSha2_256s, // or 256f
            _ => null
        };
    }

    /// <summary>
    /// Detect algorithm from secret key size
    /// </summary>
    public static SignatureAlgorithm? DetectAlgorithmFromSecretKey(int keySize)
    {
        return keySize switch
        {
            2560 => SignatureAlgorithm.MlDsa44,
            4032 => SignatureAlgorithm.MlDsa65,
            4896 => SignatureAlgorithm.MlDsa87,
            64 => SignatureAlgorithm.SlhDsaSha2_128s,
            96 => SignatureAlgorithm.SlhDsaSha2_192s,
            128 => SignatureAlgorithm.SlhDsaSha2_256s,
            _ => null
        };
    }
}

/// <summary>
/// Extension methods for signature operations
/// </summary>
public static class SignerExtensions
{
    /// <summary>
    /// Create Signer operations from device
    /// </summary>
    public static Signer GetSigner(this Device device) => new(device);

    /// <summary>
    /// Check if key pair is a signature key pair
    /// </summary>
    public static bool IsSignatureKeyPair(this KeyPair keyPair) => keyPair.Algorithm is SignatureAlgorithm;

    /// <summary>
    /// Get signature algorithm from key pair
    /// </summary>
    public static SignatureAlgorithm? GetSignatureAlgorithm(this KeyPair keyPair) => keyPair.Algorithm as SignatureAlgorithm?;
}