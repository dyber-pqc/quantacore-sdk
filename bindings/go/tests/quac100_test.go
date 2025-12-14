// D:\quantacore-sdk\bindings\go\tests\quac100_test.go
// QUAC 100 SDK - Unit Tests
// Copyright © 2025 Dyber, Inc. All Rights Reserved.

package quac100_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	quac100 "github.com/dyber-io/quac100-go"
)

// skipIfNoDevice skips the test if no device is available
func skipIfNoDevice(t *testing.T) *quac100.Device {
	t.Helper()
	
	device, err := quac100.Open()
	if err != nil {
		if quac100.IsDeviceNotFound(err) {
			t.Skip("QUAC 100 device not found")
		}
		t.Fatalf("Failed to open device: %v", err)
	}
	
	return device
}

func TestVersion(t *testing.T) {
	version := quac100.Version()
	if version == "" {
		t.Error("Version string is empty")
	}
	t.Logf("Version: %s", version)
	
	major, minor, patch := quac100.VersionInfo()
	t.Logf("Version info: %d.%d.%d", major, minor, patch)
}

func TestEnumerateDevices(t *testing.T) {
	devices, err := quac100.EnumerateDevices()
	if err != nil && !quac100.IsDeviceNotFound(err) {
		t.Fatalf("EnumerateDevices failed: %v", err)
	}
	t.Logf("Found %d devices", len(devices))
}

func TestDeviceInfo(t *testing.T) {
	device := skipIfNoDevice(t)
	defer device.Close()
	
	info, err := device.Info()
	if err != nil {
		t.Fatalf("Info failed: %v", err)
	}
	
	if info.ModelName == "" {
		t.Error("ModelName is empty")
	}
	t.Logf("Device: %s (Serial: %s)", info.ModelName, info.SerialNumber)
}

func TestDeviceStatus(t *testing.T) {
	device := skipIfNoDevice(t)
	defer device.Close()
	
	status, err := device.Status()
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}
	
	if status.EntropyLevel < 0 || status.EntropyLevel > 100 {
		t.Errorf("Invalid entropy level: %d", status.EntropyLevel)
	}
	t.Logf("Temperature: %.1f°C, Entropy: %d%%", status.Temperature, status.EntropyLevel)
}

func TestDeviceSelfTest(t *testing.T) {
	device := skipIfNoDevice(t)
	defer device.Close()
	
	passed, err := device.SelfTest()
	if err != nil {
		t.Fatalf("SelfTest failed: %v", err)
	}
	
	if !passed {
		t.Error("Self-test did not pass")
	}
}

func TestKemKeyGeneration(t *testing.T) {
	device := skipIfNoDevice(t)
	defer device.Close()
	
	kem := device.Kem()
	
	testCases := []struct {
		alg        quac100.KemAlgorithm
		pkSize     int
		skSize     int
	}{
		{quac100.MlKem512, 800, 1632},
		{quac100.MlKem768, 1184, 2400},
		{quac100.MlKem1024, 1568, 3168},
	}
	
	for _, tc := range testCases {
		t.Run(tc.alg.String(), func(t *testing.T) {
			keyPair, err := kem.GenerateKeyPair(tc.alg)
			if err != nil {
				t.Fatalf("GenerateKeyPair failed: %v", err)
			}
			defer keyPair.Zeroize()
			
			if len(keyPair.PublicKey) != tc.pkSize {
				t.Errorf("Public key size: got %d, want %d", len(keyPair.PublicKey), tc.pkSize)
			}
			if len(keyPair.SecretKey) != tc.skSize {
				t.Errorf("Secret key size: got %d, want %d", len(keyPair.SecretKey), tc.skSize)
			}
		})
	}
}

func TestKemEncapsDecaps(t *testing.T) {
	device := skipIfNoDevice(t)
	defer device.Close()
	
	kem := device.Kem()
	
	keyPair, err := kem.GenerateKeyPair(quac100.MlKem768)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	defer keyPair.Zeroize()
	
	// Encapsulate
	result, err := kem.EncapsulateKeyPair(keyPair)
	if err != nil {
		t.Fatalf("Encapsulate failed: %v", err)
	}
	defer result.Zeroize()
	
	// Decapsulate
	sharedSecret, err := kem.DecapsulateKeyPair(keyPair, result.Ciphertext)
	if err != nil {
		t.Fatalf("Decapsulate failed: %v", err)
	}
	
	// Verify shared secrets match
	if !bytes.Equal(result.SharedSecret, sharedSecret) {
		t.Error("Shared secrets do not match")
	}
}

func TestKemDemoKeyExchange(t *testing.T) {
	device := skipIfNoDevice(t)
	defer device.Close()
	
	kem := device.Kem()
	
	keyPair, encapsulation, sharedSecret, err := kem.DemoKeyExchange(quac100.MlKem768)
	if err != nil {
		t.Fatalf("DemoKeyExchange failed: %v", err)
	}
	defer keyPair.Zeroize()
	defer encapsulation.Zeroize()
	defer quac100.SecureZero(sharedSecret)
	
	if len(sharedSecret) != 32 {
		t.Errorf("Shared secret size: got %d, want 32", len(sharedSecret))
	}
}

func TestSignatureKeyGeneration(t *testing.T) {
	device := skipIfNoDevice(t)
	defer device.Close()
	
	signer := device.Signer()
	
	testCases := []struct {
		alg    quac100.SignatureAlgorithm
		pkSize int
		skSize int
	}{
		{quac100.MlDsa44, 1312, 2560},
		{quac100.MlDsa65, 1952, 4032},
		{quac100.MlDsa87, 2592, 4896},
	}
	
	for _, tc := range testCases {
		t.Run(tc.alg.String(), func(t *testing.T) {
			keyPair, err := signer.GenerateKeyPair(tc.alg)
			if err != nil {
				t.Fatalf("GenerateKeyPair failed: %v", err)
			}
			defer keyPair.Zeroize()
			
			if len(keyPair.PublicKey) != tc.pkSize {
				t.Errorf("Public key size: got %d, want %d", len(keyPair.PublicKey), tc.pkSize)
			}
			if len(keyPair.SecretKey) != tc.skSize {
				t.Errorf("Secret key size: got %d, want %d", len(keyPair.SecretKey), tc.skSize)
			}
		})
	}
}

func TestSignVerify(t *testing.T) {
	device := skipIfNoDevice(t)
	defer device.Close()
	
	signer := device.Signer()
	
	keyPair, err := signer.GenerateKeyPair(quac100.MlDsa65)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	defer keyPair.Zeroize()
	
	message := []byte("Test message for signing")
	
	// Sign
	signature, err := signer.SignKeyPair(keyPair, message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	
	// Verify
	valid, err := signer.VerifyKeyPair(keyPair, message, signature)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !valid {
		t.Error("Signature verification failed")
	}
	
	// Verify with tampered message should fail
	tamperedMessage := []byte("Tampered message")
	tamperedValid, _ := signer.VerifyKeyPair(keyPair, tamperedMessage, signature)
	if tamperedValid {
		t.Error("Tampered message verification should fail")
	}
}

func TestRandomBytes(t *testing.T) {
	device := skipIfNoDevice(t)
	defer device.Close()
	
	random := device.Random()
	
	// Generate bytes
	bytes1, err := random.Bytes(32)
	if err != nil {
		t.Fatalf("Bytes failed: %v", err)
	}
	
	if len(bytes1) != 32 {
		t.Errorf("Bytes length: got %d, want 32", len(bytes1))
	}
	
	// Generate more bytes - should be different
	bytes2, err := random.Bytes(32)
	if err != nil {
		t.Fatalf("Bytes failed: %v", err)
	}
	
	if bytes.Equal(bytes1, bytes2) {
		t.Error("Two random byte sequences should not be equal")
	}
}

func TestRandomIntegers(t *testing.T) {
	device := skipIfNoDevice(t)
	defer device.Close()
	
	random := device.Random()
	
	// Test Int32
	_, err := random.Int32()
	if err != nil {
		t.Fatalf("Int32 failed: %v", err)
	}
	
	// Test Int32N
	for i := 0; i < 100; i++ {
		val, err := random.Int32N(100)
		if err != nil {
			t.Fatalf("Int32N failed: %v", err)
		}
		if val < 0 || val >= 100 {
			t.Errorf("Int32N out of range: %d", val)
		}
	}
	
	// Test Int32Range
	for i := 0; i < 100; i++ {
		val, err := random.Int32Range(50, 100)
		if err != nil {
			t.Fatalf("Int32Range failed: %v", err)
		}
		if val < 50 || val >= 100 {
			t.Errorf("Int32Range out of range: %d", val)
		}
	}
}

func TestRandomFloat(t *testing.T) {
	device := skipIfNoDevice(t)
	defer device.Close()
	
	random := device.Random()
	
	for i := 0; i < 100; i++ {
		val, err := random.Float64()
		if err != nil {
			t.Fatalf("Float64 failed: %v", err)
		}
		if val < 0.0 || val >= 1.0 {
			t.Errorf("Float64 out of range: %f", val)
		}
	}
}

func TestRandomUUID(t *testing.T) {
	device := skipIfNoDevice(t)
	defer device.Close()
	
	random := device.Random()
	
	uuid, err := random.UUID()
	if err != nil {
		t.Fatalf("UUID failed: %v", err)
	}
	
	if len(uuid) != 36 {
		t.Errorf("UUID length: got %d, want 36", len(uuid))
	}
	
	// Check format
	if uuid[8] != '-' || uuid[13] != '-' || uuid[18] != '-' || uuid[23] != '-' {
		t.Errorf("UUID format invalid: %s", uuid)
	}
	
	// Check version (should be 4)
	if uuid[14] != '4' {
		t.Errorf("UUID version invalid: %s", uuid)
	}
}

func TestEntropyStatus(t *testing.T) {
	device := skipIfNoDevice(t)
	defer device.Close()
	
	random := device.Random()
	
	status, err := random.EntropyStatus()
	if err != nil {
		t.Fatalf("EntropyStatus failed: %v", err)
	}
	
	if status.Level < 0 || status.Level > 100 {
		t.Errorf("Entropy level out of range: %d", status.Level)
	}
}

func TestSecureZero(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	quac100.SecureZero(data)
	
	for i, b := range data {
		if b != 0 {
			t.Errorf("SecureZero: byte %d not zero", i)
		}
	}
}

func TestSecureCompare(t *testing.T) {
	a := []byte{1, 2, 3, 4, 5}
	b := []byte{1, 2, 3, 4, 5}
	c := []byte{1, 2, 3, 4, 6}
	d := []byte{1, 2, 3}
	
	if !quac100.SecureCompare(a, b) {
		t.Error("SecureCompare: equal slices should match")
	}
	
	if quac100.SecureCompare(a, c) {
		t.Error("SecureCompare: different slices should not match")
	}
	
	if quac100.SecureCompare(a, d) {
		t.Error("SecureCompare: different length slices should not match")
	}
}

func TestDevicePool(t *testing.T) {
	// Try to create a small pool
	pool, err := quac100.NewDevicePool(2, quac100.FlagDefault)
	if err != nil {
		if quac100.IsDeviceNotFound(err) {
			t.Skip("QUAC 100 device not found")
		}
		t.Fatalf("NewDevicePool failed: %v", err)
	}
	defer pool.Close()
	
	if pool.Size() != 2 {
		t.Errorf("Pool size: got %d, want 2", pool.Size())
	}
	
	// Acquire and release
	ctx := context.Background()
	device, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}
	
	// Check available count decreased
	if pool.Available() != 1 {
		t.Errorf("Available after acquire: got %d, want 1", pool.Available())
	}
	
	pool.Release(device)
	
	// Check available count increased
	if pool.Available() != 2 {
		t.Errorf("Available after release: got %d, want 2", pool.Available())
	}
}

func TestPooledOperation(t *testing.T) {
	pool, err := quac100.NewDevicePool(2, quac100.FlagDefault)
	if err != nil {
		if quac100.IsDeviceNotFound(err) {
			t.Skip("QUAC 100 device not found")
		}
		t.Fatalf("NewDevicePool failed: %v", err)
	}
	defer pool.Close()
	
	ctx := context.Background()
	
	err = pool.PooledOperation(ctx, func(device *quac100.Device) error {
		_, err := device.RandomBytes(32)
		return err
	})
	
	if err != nil {
		t.Fatalf("PooledOperation failed: %v", err)
	}
}

func TestContext(t *testing.T) {
	ctx, err := quac100.NewDefaultContext()
	if err != nil {
		if quac100.IsDeviceNotFound(err) {
			t.Skip("QUAC 100 device not found")
		}
		t.Fatalf("NewDefaultContext failed: %v", err)
	}
	defer ctx.Close()
	
	// Test convenience methods
	keyPair, err := ctx.GenerateKemKeyPair(quac100.MlKem768)
	if err != nil {
		t.Fatalf("GenerateKemKeyPair failed: %v", err)
	}
	keyPair.Zeroize()
	
	bytes, err := ctx.RandomBytes(32)
	if err != nil {
		t.Fatalf("RandomBytes failed: %v", err)
	}
	if len(bytes) != 32 {
		t.Errorf("RandomBytes length: got %d, want 32", len(bytes))
	}
}

// Benchmarks

func BenchmarkKemKeyGen768(b *testing.B) {
	device, err := quac100.Open()
	if err != nil {
		b.Skip("QUAC 100 device not found")
	}
	defer device.Close()
	
	kem := device.Kem()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		keyPair, _ := kem.GenerateKeyPair(quac100.MlKem768)
		keyPair.Zeroize()
	}
}

func BenchmarkKemEncaps768(b *testing.B) {
	device, err := quac100.Open()
	if err != nil {
		b.Skip("QUAC 100 device not found")
	}
	defer device.Close()
	
	kem := device.Kem()
	keyPair, _ := kem.GenerateKeyPair(quac100.MlKem768)
	defer keyPair.Zeroize()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, _ := kem.EncapsulateKeyPair(keyPair)
		result.Zeroize()
	}
}

func BenchmarkSign65(b *testing.B) {
	device, err := quac100.Open()
	if err != nil {
		b.Skip("QUAC 100 device not found")
	}
	defer device.Close()
	
	signer := device.Signer()
	keyPair, _ := signer.GenerateKeyPair(quac100.MlDsa65)
	defer keyPair.Zeroize()
	
	message := []byte("Benchmark message for signing")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = signer.SignKeyPair(keyPair, message)
	}
}

func BenchmarkVerify65(b *testing.B) {
	device, err := quac100.Open()
	if err != nil {
		b.Skip("QUAC 100 device not found")
	}
	defer device.Close()
	
	signer := device.Signer()
	keyPair, _ := signer.GenerateKeyPair(quac100.MlDsa65)
	defer keyPair.Zeroize()
	
	message := []byte("Benchmark message for signing")
	signature, _ := signer.SignKeyPair(keyPair, message)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = signer.VerifyKeyPair(keyPair, message, signature)
	}
}

func BenchmarkRandomBytes1K(b *testing.B) {
	device, err := quac100.Open()
	if err != nil {
		b.Skip("QUAC 100 device not found")
	}
	defer device.Close()
	
	random := device.Random()
	buffer := make([]byte, 1024)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = random.GetBytes(buffer)
	}
}

func BenchmarkRandomBytes64K(b *testing.B) {
	device, err := quac100.Open()
	if err != nil {
		b.Skip("QUAC 100 device not found")
	}
	defer device.Close()
	
	random := device.Random()
	buffer := make([]byte, 64*1024)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = random.GetBytes(buffer)
	}
}