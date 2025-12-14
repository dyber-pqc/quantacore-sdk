// D:\quantacore-sdk\bindings\csharp\Examples\BasicUsage.cs
// QUAC 100 SDK - Usage Examples
// Copyright © 2025 Dyber, Inc. All Rights Reserved.

using System.Text;
using Dyber.Quac100;

namespace Dyber.Quac100.Examples;

/// <summary>
/// Basic usage examples for the QUAC 100 SDK
/// </summary>
public static class BasicUsage
{
    /// <summary>
    /// Example 1: Basic context usage
    /// </summary>
    public static void BasicContextExample()
    {
        Console.WriteLine("=== Basic Context Example ===\n");

        // Initialize SDK (done automatically, but can be explicit)
        Quac100Context.Initialize();

        // Open device and create context
        using var ctx = new Quac100Context();

        // Get device info
        var info = ctx.Device.GetInfo();
        Console.WriteLine($"Device: {info.ModelName}");
        Console.WriteLine($"Serial: {info.SerialNumber}");
        Console.WriteLine($"Firmware: {info.FirmwareVersion}");
        Console.WriteLine($"FIPS Mode: {info.FipsMode}");

        // Get device status
        var status = ctx.Device.GetStatus();
        Console.WriteLine($"Temperature: {status.Temperature}°C");
        Console.WriteLine($"Entropy Level: {status.EntropyLevel}%");
        Console.WriteLine($"Total Operations: {status.TotalOperations}");

        Console.WriteLine();
    }

    /// <summary>
    /// Example 2: ML-KEM key exchange
    /// </summary>
    public static void KemKeyExchangeExample()
    {
        Console.WriteLine("=== ML-KEM Key Exchange Example ===\n");

        using var ctx = new Quac100Context();

        // Alice generates a key pair
        Console.WriteLine("Alice: Generating ML-KEM-768 key pair...");
        using var aliceKeyPair = ctx.Kem.GenerateKeyPair(KemAlgorithm.MlKem768);
        Console.WriteLine($"  Public key: {aliceKeyPair.PublicKey.Length} bytes");
        Console.WriteLine($"  Secret key: {aliceKeyPair.SecretKey.Length} bytes");

        // Alice sends her public key to Bob
        var alicePublicKey = aliceKeyPair.ExportPublicKey();
        Console.WriteLine("Alice: Sending public key to Bob...\n");

        // Bob encapsulates to Alice's public key
        Console.WriteLine("Bob: Encapsulating shared secret...");
        using var encapsulation = ctx.Kem.Encapsulate(alicePublicKey, KemAlgorithm.MlKem768);
        Console.WriteLine($"  Ciphertext: {encapsulation.Ciphertext.Length} bytes");
        Console.WriteLine($"  Shared secret: {BitConverter.ToString(encapsulation.ExportSharedSecret()).Replace("-", "").Substring(0, 32)}...");

        // Bob sends ciphertext to Alice
        var ciphertext = encapsulation.ExportCiphertext();
        Console.WriteLine("Bob: Sending ciphertext to Alice...\n");

        // Alice decapsulates
        Console.WriteLine("Alice: Decapsulating shared secret...");
        var aliceSharedSecret = ctx.Kem.Decapsulate(aliceKeyPair, ciphertext);
        Console.WriteLine($"  Shared secret: {BitConverter.ToString(aliceSharedSecret).Replace("-", "").Substring(0, 32)}...");

        // Verify both parties have the same shared secret
        bool match = Quac100Context.SecureCompare(encapsulation.SharedSecret, aliceSharedSecret);
        Console.WriteLine($"\nShared secrets match: {match}");

        Console.WriteLine();
    }

    /// <summary>
    /// Example 3: ML-DSA signing and verification
    /// </summary>
    public static void SignatureExample()
    {
        Console.WriteLine("=== ML-DSA Signature Example ===\n");

        using var ctx = new Quac100Context();

        // Generate signing key pair
        Console.WriteLine("Generating ML-DSA-65 key pair...");
        using var keyPair = ctx.Signer.GenerateKeyPair(SignatureAlgorithm.MlDsa65);
        Console.WriteLine($"  Public key: {keyPair.PublicKey.Length} bytes");
        Console.WriteLine($"  Secret key: {keyPair.SecretKey.Length} bytes");

        // Message to sign
        string message = "Hello, Post-Quantum World!";
        var messageBytes = Encoding.UTF8.GetBytes(message);
        Console.WriteLine($"\nMessage: \"{message}\"");
        Console.WriteLine($"Message bytes: {messageBytes.Length}");

        // Sign the message
        Console.WriteLine("\nSigning message...");
        var signature = ctx.Signer.Sign(keyPair, messageBytes);
        Console.WriteLine($"  Signature: {signature.Length} bytes");
        Console.WriteLine($"  Signature (hex): {BitConverter.ToString(signature).Replace("-", "").Substring(0, 64)}...");

        // Verify the signature
        Console.WriteLine("\nVerifying signature...");
        bool valid = ctx.Signer.Verify(keyPair, messageBytes, signature);
        Console.WriteLine($"  Signature valid: {valid}");

        // Try with tampered message
        Console.WriteLine("\nVerifying with tampered message...");
        var tamperedMessage = Encoding.UTF8.GetBytes("Hello, Tampered World!");
        bool tamperedValid = ctx.Signer.Verify(keyPair, tamperedMessage, signature);
        Console.WriteLine($"  Signature valid: {tamperedValid}");

        Console.WriteLine();
    }

    /// <summary>
    /// Example 4: Quantum random number generation
    /// </summary>
    public static void RandomExample()
    {
        Console.WriteLine("=== Quantum Random Number Generation Example ===\n");

        using var ctx = new Quac100Context();

        // Get entropy status
        var (level, source) = ctx.Random.GetEntropyStatus();
        Console.WriteLine($"Entropy Level: {level}%");
        Console.WriteLine($"Entropy Source: {source}");

        // Generate random bytes
        Console.WriteLine("\nGenerating 32 random bytes...");
        var randomBytes = ctx.Random.GetBytes(32);
        Console.WriteLine($"  {BitConverter.ToString(randomBytes).Replace("-", "")}");

        // Generate random integers
        Console.WriteLine("\nGenerating random integers...");
        Console.WriteLine($"  Random Int32: {ctx.Random.GetInt32()}");
        Console.WriteLine($"  Random Int32 (0-100): {ctx.Random.GetInt32(100)}");
        Console.WriteLine($"  Random Int64: {ctx.Random.GetInt64()}");

        // Generate random double
        Console.WriteLine($"  Random Double: {ctx.Random.GetDouble():F16}");

        // Generate random GUID
        Console.WriteLine($"  Random GUID: {ctx.Random.GetGuid()}");

        // Generate random string
        Console.WriteLine($"  Random String (16): {ctx.Random.GetString(16)}");

        // Shuffle array
        var numbers = new[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
        ctx.Random.Shuffle(numbers);
        Console.WriteLine($"  Shuffled: [{string.Join(", ", numbers)}]");

        // Estimate entropy quality
        Console.WriteLine("\nEstimating entropy quality (100KB sample)...");
        double entropy = ctx.Random.EstimateEntropy(100000);
        Console.WriteLine($"  Shannon entropy: {entropy:F4} bits/byte (ideal: 8.0)");

        // Benchmark
        Console.WriteLine("\nBenchmarking (10MB)...");
        double mbps = ctx.Random.Benchmark(10 * 1024 * 1024);
        Console.WriteLine($"  Generation rate: {mbps:F2} MB/s");

        Console.WriteLine();
    }

    /// <summary>
    /// Example 5: Hash operations
    /// </summary>
    public static void HashExample()
    {
        Console.WriteLine("=== Hash Operations Example ===\n");

        using var ctx = new Quac100Context();

        var data = Encoding.UTF8.GetBytes("Hello, World!");

        // One-shot hash
        Console.WriteLine("One-shot hash:");
        var sha256 = ctx.Hash(data, HashAlgorithm.Sha256);
        Console.WriteLine($"  SHA-256: {BitConverter.ToString(sha256).Replace("-", "")}");

        var sha512 = ctx.Hash(data, HashAlgorithm.Sha512);
        Console.WriteLine($"  SHA-512: {BitConverter.ToString(sha512).Replace("-", "").Substring(0, 64)}...");

        // Incremental hash
        Console.WriteLine("\nIncremental hash:");
        using var hash = ctx.CreateIncrementalHash(HashAlgorithm.Sha256);
        hash.Update(Encoding.UTF8.GetBytes("Hello, "));
        hash.Update(Encoding.UTF8.GetBytes("World!"));
        var result = hash.Finalize();
        Console.WriteLine($"  Incremental SHA-256: {BitConverter.ToString(result).Replace("-", "")}");
        Console.WriteLine($"  Match one-shot: {Quac100Context.SecureCompare(sha256, result)}");

        Console.WriteLine();
    }

    /// <summary>
    /// Example 6: Async operations
    /// </summary>
    public static async Task AsyncOperationsExample()
    {
        Console.WriteLine("=== Async Operations Example ===\n");

        using var ctx = new Quac100Context();

        // Async key generation
        Console.WriteLine("Generating keys asynchronously...");
        var keyGenTasks = new[]
        {
            ctx.Kem.GenerateKeyPairAsync(KemAlgorithm.MlKem768),
            ctx.Kem.GenerateKeyPairAsync(KemAlgorithm.MlKem768),
            ctx.Kem.GenerateKeyPairAsync(KemAlgorithm.MlKem768),
        };

        var keyPairs = await Task.WhenAll(keyGenTasks);
        Console.WriteLine($"  Generated {keyPairs.Length} key pairs");

        // Async random bytes
        Console.WriteLine("\nGenerating random bytes asynchronously...");
        var random = await ctx.Random.GetBytesAsync(1024);
        Console.WriteLine($"  Generated {random.Length} bytes");

        // Cleanup
        foreach (var kp in keyPairs)
            kp.Dispose();

        Console.WriteLine();
    }

    /// <summary>
    /// Example 7: Error handling
    /// </summary>
    public static void ErrorHandlingExample()
    {
        Console.WriteLine("=== Error Handling Example ===\n");

        // Try to open non-existent device
        Console.WriteLine("Attempting to open non-existent device...");
        try
        {
            using var ctx = new Quac100Context(deviceIndex: 99);
        }
        catch (DeviceNotFoundException ex)
        {
            Console.WriteLine($"  Caught: {ex.GetType().Name}");
            Console.WriteLine($"  Status: {ex.Status}");
            Console.WriteLine($"  Message: {ex.Message}");
        }

        // Try invalid key size
        Console.WriteLine("\nAttempting operation with invalid key...");
        using var ctx2 = Quac100Context.TryOpen();
        if (ctx2 != null)
        {
            try
            {
                ctx2.Kem.Encapsulate(new byte[100], KemAlgorithm.MlKem768);
            }
            catch (ArgumentException ex)
            {
                Console.WriteLine($"  Caught: {ex.GetType().Name}");
                Console.WriteLine($"  Message: {ex.Message}");
            }
        }

        Console.WriteLine();
    }

    /// <summary>
    /// Example 8: Device pool for high throughput
    /// </summary>
    public static async Task DevicePoolExample()
    {
        Console.WriteLine("=== Device Pool Example ===\n");

        // Create a pool of 4 device connections
        using var pool = new DevicePool(poolSize: 4);
        Console.WriteLine($"Created pool with {pool.PoolSize} connections");

        // Simulate concurrent operations
        Console.WriteLine("\nRunning 10 concurrent operations...");
        var tasks = Enumerable.Range(0, 10).Select(async i =>
        {
            using var pooledDevice = await pool.AcquireAsync();
            var kem = pooledDevice.Device.GetKem();
            var keyPair = kem.GenerateKeyPair();
            Console.WriteLine($"  Task {i}: Generated key pair");
            keyPair.Dispose();
        });

        await Task.WhenAll(tasks);
        Console.WriteLine("All operations completed");

        Console.WriteLine();
    }

    /// <summary>
    /// Run all examples
    /// </summary>
    public static async Task RunAllExamples()
    {
        Console.WriteLine("╔═══════════════════════════════════════════════════════════╗");
        Console.WriteLine("║           QUAC 100 SDK - C# Binding Examples              ║");
        Console.WriteLine("╚═══════════════════════════════════════════════════════════╝\n");

        try
        {
            BasicContextExample();
            KemKeyExchangeExample();
            SignatureExample();
            RandomExample();
            HashExample();
            await AsyncOperationsExample();
            ErrorHandlingExample();
            await DevicePoolExample();

            Console.WriteLine("All examples completed successfully!");
        }
        catch (DeviceNotFoundException)
        {
            Console.WriteLine("\n⚠ QUAC 100 device not found.");
            Console.WriteLine("  These examples require a QUAC 100 hardware device.");
            Console.WriteLine("  In production, ensure the device is connected and drivers are installed.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"\n❌ Error: {ex.Message}");
        }
        finally
        {
            Quac100Context.Cleanup();
        }
    }
}

/// <summary>
/// Program entry point for running examples
/// </summary>
public static class Program
{
    public static async Task Main(string[] args)
    {
        if (args.Length > 0 && args[0] == "--version")
        {
            Console.WriteLine($"QUAC 100 SDK Version: {Quac100Context.Version}");
            var (major, minor, patch) = Quac100Context.VersionInfo;
            Console.WriteLine($"Version Numbers: {major}.{minor}.{patch}");
            return;
        }

        await BasicUsage.RunAllExamples();
    }
}