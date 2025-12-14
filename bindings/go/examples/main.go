// D:\quantacore-sdk\bindings\go\examples\main.go
// QUAC 100 SDK - Usage Examples
// Copyright © 2025 Dyber, Inc. All Rights Reserved.

package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"time"

	quac100 "github.com/dyber-io/quac100-go"
)

func main() {
	fmt.Println("╔═══════════════════════════════════════════════════════════╗")
	fmt.Println("║           QUAC 100 SDK - Go Binding Examples              ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Check for version flag
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		major, minor, patch := quac100.VersionInfo()
		fmt.Printf("QUAC 100 SDK Version: %s (%d.%d.%d)\n", quac100.Version(), major, minor, patch)
		return
	}

	// Run examples
	if err := runExamples(); err != nil {
		log.Fatalf("Error: %v\n", err)
	}

	fmt.Println("\nAll examples completed successfully!")
}

func runExamples() error {
	// Initialize SDK
	if err := quac100.InitDefault(); err != nil {
		return fmt.Errorf("failed to initialize SDK: %w", err)
	}
	defer quac100.Cleanup()

	// Example 1: Basic device usage
	if err := basicDeviceExample(); err != nil {
		if quac100.IsDeviceNotFound(err) {
			fmt.Println("\n⚠ QUAC 100 device not found.")
			fmt.Println("  These examples require a QUAC 100 hardware device.")
			return nil
		}
		return err
	}

	// Example 2: ML-KEM key exchange
	if err := kemKeyExchangeExample(); err != nil {
		return err
	}

	// Example 3: ML-DSA signatures
	if err := signatureExample(); err != nil {
		return err
	}

	// Example 4: Quantum random numbers
	if err := randomExample(); err != nil {
		return err
	}

	// Example 5: Hash operations
	if err := hashExample(); err != nil {
		return err
	}

	// Example 6: Context API
	if err := contextExample(); err != nil {
		return err
	}

	// Example 7: Device pool
	if err := devicePoolExample(); err != nil {
		return err
	}

	return nil
}

func basicDeviceExample() error {
	fmt.Println("=== Basic Device Example ===\n")

	// Enumerate devices
	devices, err := quac100.EnumerateDevices()
	if err != nil {
		return fmt.Errorf("enumerate devices: %w", err)
	}
	fmt.Printf("Found %d device(s)\n", len(devices))

	// Open first device
	device, err := quac100.Open()
	if err != nil {
		return err
	}
	defer device.Close()

	// Get device info
	info, err := device.Info()
	if err != nil {
		return fmt.Errorf("get device info: %w", err)
	}

	fmt.Printf("Device: %s\n", info.ModelName)
	fmt.Printf("Serial: %s\n", info.SerialNumber)
	fmt.Printf("Firmware: %s\n", info.FirmwareVersion)
	fmt.Printf("FIPS Mode: %v\n", info.FipsMode)

	// Get device status
	status, err := device.Status()
	if err != nil {
		return fmt.Errorf("get device status: %w", err)
	}

	fmt.Printf("Temperature: %.1f°C\n", status.Temperature)
	fmt.Printf("Entropy Level: %d%%\n", status.EntropyLevel)
	fmt.Printf("Total Operations: %d\n", status.TotalOperations)

	// Run self-test
	fmt.Println("\nRunning self-test...")
	passed, err := device.SelfTest()
	if err != nil {
		return fmt.Errorf("self-test: %w", err)
	}
	fmt.Printf("Self-test passed: %v\n", passed)

	fmt.Println()
	return nil
}

func kemKeyExchangeExample() error {
	fmt.Println("=== ML-KEM Key Exchange Example ===\n")

	device, err := quac100.Open()
	if err != nil {
		return err
	}
	defer device.Close()

	kem := device.Kem()

	// Alice generates a key pair
	fmt.Println("Alice: Generating ML-KEM-768 key pair...")
	aliceKeyPair, err := kem.GenerateKeyPair(quac100.MlKem768)
	if err != nil {
		return fmt.Errorf("keygen: %w", err)
	}
	defer aliceKeyPair.Zeroize()

	fmt.Printf("  Public key: %d bytes\n", len(aliceKeyPair.PublicKey))
	fmt.Printf("  Secret key: %d bytes\n", len(aliceKeyPair.SecretKey))

	// Bob encapsulates to Alice's public key
	fmt.Println("\nBob: Encapsulating shared secret...")
	encapsulation, err := kem.EncapsulateKeyPair(aliceKeyPair)
	if err != nil {
		return fmt.Errorf("encapsulation: %w", err)
	}
	defer encapsulation.Zeroize()

	fmt.Printf("  Ciphertext: %d bytes\n", len(encapsulation.Ciphertext))
	fmt.Printf("  Shared secret: %s...\n", hex.EncodeToString(encapsulation.SharedSecret[:16]))

	// Alice decapsulates
	fmt.Println("\nAlice: Decapsulating shared secret...")
	sharedSecret, err := kem.DecapsulateKeyPair(aliceKeyPair, encapsulation.Ciphertext)
	if err != nil {
		return fmt.Errorf("decapsulation: %w", err)
	}
	defer quac100.SecureZero(sharedSecret)

	fmt.Printf("  Shared secret: %s...\n", hex.EncodeToString(sharedSecret[:16]))

	// Verify match
	match := quac100.SecureCompare(encapsulation.SharedSecret, sharedSecret)
	fmt.Printf("\nShared secrets match: %v\n", match)

	fmt.Println()
	return nil
}

func signatureExample() error {
	fmt.Println("=== ML-DSA Signature Example ===\n")

	device, err := quac100.Open()
	if err != nil {
		return err
	}
	defer device.Close()

	signer := device.Signer()

	// Generate key pair
	fmt.Println("Generating ML-DSA-65 key pair...")
	keyPair, err := signer.GenerateKeyPair(quac100.MlDsa65)
	if err != nil {
		return fmt.Errorf("keygen: %w", err)
	}
	defer keyPair.Zeroize()

	fmt.Printf("  Public key: %d bytes\n", len(keyPair.PublicKey))
	fmt.Printf("  Secret key: %d bytes\n", len(keyPair.SecretKey))

	// Sign message
	message := "Hello, Post-Quantum World!"
	fmt.Printf("\nMessage: %q\n", message)
	fmt.Println("Signing message...")

	signature, err := signer.SignString(keyPair, message)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}

	fmt.Printf("  Signature: %d bytes\n", len(signature))
	fmt.Printf("  Signature (hex): %s...\n", hex.EncodeToString(signature[:32]))

	// Verify signature
	fmt.Println("\nVerifying signature...")
	valid, err := signer.VerifyString(keyPair, message, signature)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	fmt.Printf("  Signature valid: %v\n", valid)

	// Try with tampered message
	fmt.Println("\nVerifying with tampered message...")
	tamperedValid, _ := signer.VerifyString(keyPair, "Hello, Tampered World!", signature)
	fmt.Printf("  Signature valid: %v\n", tamperedValid)

	fmt.Println()
	return nil
}

func randomExample() error {
	fmt.Println("=== Quantum Random Number Generation Example ===\n")

	device, err := quac100.Open()
	if err != nil {
		return err
	}
	defer device.Close()

	random := device.Random()

	// Get entropy status
	status, err := random.EntropyStatus()
	if err != nil {
		return fmt.Errorf("entropy status: %w", err)
	}
	fmt.Printf("Entropy Level: %d%%\n", status.Level)
	fmt.Printf("Entropy Source: %d\n", status.Source)

	// Generate random bytes
	fmt.Println("\nGenerating 32 random bytes...")
	bytes, err := random.Bytes(32)
	if err != nil {
		return fmt.Errorf("random bytes: %w", err)
	}
	fmt.Printf("  %s\n", hex.EncodeToString(bytes))

	// Generate random integers
	fmt.Println("\nGenerating random integers...")
	int32Val, _ := random.Int32()
	fmt.Printf("  Random Int32: %d\n", int32Val)

	int32Range, _ := random.Int32Range(0, 100)
	fmt.Printf("  Random Int32 (0-100): %d\n", int32Range)

	int64Val, _ := random.Int64()
	fmt.Printf("  Random Int64: %d\n", int64Val)

	// Generate random float
	floatVal, _ := random.Float64()
	fmt.Printf("  Random Float64: %.16f\n", floatVal)

	// Generate UUID
	uuid, _ := random.UUID()
	fmt.Printf("  Random UUID: %s\n", uuid)

	// Generate random string
	str, _ := random.AlphanumericString(16)
	fmt.Printf("  Random String (16): %s\n", str)

	// Shuffle example
	numbers := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	random.ShuffleInts(numbers)
	fmt.Printf("  Shuffled: %v\n", numbers)

	// Estimate entropy quality
	fmt.Println("\nEstimating entropy quality (100KB sample)...")
	entropy, _ := random.EstimateEntropy(100000)
	fmt.Printf("  Shannon entropy: %.4f bits/byte (ideal: 8.0)\n", entropy)

	// Benchmark
	fmt.Println("\nBenchmarking (10MB)...")
	mbps, _ := random.Benchmark(10 * 1024 * 1024)
	fmt.Printf("  Generation rate: %.2f MB/s\n", mbps)

	fmt.Println()
	return nil
}

func hashExample() error {
	fmt.Println("=== Hash Operations Example ===\n")

	ctx, err := quac100.NewDefaultContext()
	if err != nil {
		return err
	}
	defer ctx.Close()

	data := []byte("Hello, World!")

	// SHA-256
	sha256, err := ctx.SHA256(data)
	if err != nil {
		return fmt.Errorf("sha256: %w", err)
	}
	fmt.Printf("SHA-256: %s\n", hex.EncodeToString(sha256))

	// SHA-512
	sha512, err := ctx.SHA512(data)
	if err != nil {
		return fmt.Errorf("sha512: %w", err)
	}
	fmt.Printf("SHA-512: %s...\n", hex.EncodeToString(sha512[:32]))

	// SHA3-256
	sha3_256, err := ctx.SHA3_256(data)
	if err != nil {
		return fmt.Errorf("sha3-256: %w", err)
	}
	fmt.Printf("SHA3-256: %s\n", hex.EncodeToString(sha3_256))

	fmt.Println()
	return nil
}

func contextExample() error {
	fmt.Println("=== Context API Example ===\n")

	ctx, err := quac100.NewDefaultContext()
	if err != nil {
		return err
	}
	defer ctx.Close()

	// Use convenience methods
	fmt.Println("Using Context convenience methods...")

	// Generate KEM key pair
	keyPair, err := ctx.GenerateKemKeyPair(quac100.MlKem768)
	if err != nil {
		return err
	}
	defer keyPair.Zeroize()
	fmt.Printf("Generated KEM key pair: %d byte public key\n", len(keyPair.PublicKey))

	// Generate random bytes
	randomBytes, err := ctx.RandomBytes(32)
	if err != nil {
		return err
	}
	fmt.Printf("Random bytes: %s...\n", hex.EncodeToString(randomBytes[:16]))

	fmt.Println()
	return nil
}

func devicePoolExample() error {
	fmt.Println("=== Device Pool Example ===\n")

	// Create pool with 4 connections
	pool, err := quac100.NewDevicePool(4, quac100.FlagDefault)
	if err != nil {
		return err
	}
	defer pool.Close()

	fmt.Printf("Created pool with %d connections\n", pool.Size())
	fmt.Printf("Available: %d\n", pool.Available())

	// Run concurrent operations
	fmt.Println("\nRunning 10 concurrent operations...")

	ctx := context.Background()
	done := make(chan struct{}, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() { done <- struct{}{} }()

			err := pool.PooledOperation(ctx, func(device *quac100.Device) error {
				keyPair, err := device.KemGenerateKeyPair(quac100.MlKem768)
				if err != nil {
					return err
				}
				keyPair.Zeroize()
				fmt.Printf("  Task %d: Generated key pair\n", id)
				return nil
			})

			if err != nil {
				fmt.Printf("  Task %d: Error: %v\n", id, err)
			}
		}(i)
	}

	// Wait for all tasks
	for i := 0; i < 10; i++ {
		<-done
	}

	fmt.Println("All operations completed")
	fmt.Println()
	return nil
}

// BenchmarkExample demonstrates benchmarking capabilities
func BenchmarkExample() error {
	fmt.Println("=== Benchmark Example ===\n")

	device, err := quac100.Open()
	if err != nil {
		return err
	}
	defer device.Close()

	kem := device.Kem()
	signer := device.Signer()

	// Benchmark KEM
	fmt.Println("Benchmarking ML-KEM-768...")
	start := time.Now()
	iterations := 1000

	for i := 0; i < iterations; i++ {
		kp, _ := kem.GenerateKeyPair(quac100.MlKem768)
		kp.Zeroize()
	}

	keygenDuration := time.Since(start)
	fmt.Printf("  KeyGen: %.2f ops/sec\n", float64(iterations)/keygenDuration.Seconds())

	// Benchmark signatures
	fmt.Println("\nBenchmarking ML-DSA-65...")
	kp, _ := signer.GenerateKeyPair(quac100.MlDsa65)
	defer kp.Zeroize()

	message := []byte("Benchmark message")
	start = time.Now()

	for i := 0; i < iterations; i++ {
		sig, _ := signer.SignKeyPair(kp, message)
		_ = sig
	}

	signDuration := time.Since(start)
	fmt.Printf("  Sign: %.2f ops/sec\n", float64(iterations)/signDuration.Seconds())

	fmt.Println()
	return nil
}