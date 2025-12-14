// D:\quantacore-sdk\bindings\go\quac100.go
// QUAC 100 SDK - Main API
// Copyright © 2025 Dyber, Inc. All Rights Reserved.

// Package quac100 provides Go bindings for the QUAC 100 Post-Quantum
// Cryptographic Accelerator.
//
// The QUAC 100 provides hardware-accelerated implementations of:
//   - ML-KEM (Kyber) key encapsulation mechanism
//   - ML-DSA (Dilithium) digital signatures
//   - SLH-DSA (SPHINCS+) hash-based signatures
//   - Quantum random number generation
//
// Basic usage:
//
//	import "github.com/dyber-pqc/quac100-go"
//
//	func main() {
//	    // Open device
//	    device, err := quac100.Open()
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//	    defer device.Close()
//
//	    // Generate ML-KEM key pair
//	    keyPair, err := device.KemGenerateKeyPair(quac100.MlKem768)
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//	    defer keyPair.Zeroize()
//
//	    // Encapsulate
//	    result, err := device.KemEncapsulate(keyPair.PublicKey, quac100.MlKem768)
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//	    defer result.Zeroize()
//
//	    fmt.Printf("Shared secret: %x\n", result.SharedSecret)
//	}
package quac100

import (
	"unsafe"
)

// Context provides a unified interface to all QUAC 100 operations
type Context struct {
	device *Device
	kem    *Kem
	signer *Signer
	random *QuantumRandom
}

// NewContext creates a new QUAC 100 context
func NewContext(deviceIndex int, flags DeviceFlags) (*Context, error) {
	device, err := OpenDevice(deviceIndex, flags)
	if err != nil {
		return nil, err
	}
	
	return &Context{
		device: device,
		kem:    NewKem(device),
		signer: NewSigner(device),
		random: NewQuantumRandom(device, EntropyQRNG),
	}, nil
}

// NewDefaultContext creates a context with default settings
func NewDefaultContext() (*Context, error) {
	return NewContext(0, FlagDefault)
}

// TryNewContext attempts to create a context, returning nil if device not found
func TryNewContext(deviceIndex int, flags DeviceFlags) *Context {
	ctx, err := NewContext(deviceIndex, flags)
	if err != nil {
		return nil
	}
	return ctx
}

// Device returns the underlying device
func (c *Context) Device() *Device {
	return c.device
}

// Kem returns the KEM operations interface
func (c *Context) Kem() *Kem {
	return c.kem
}

// Signer returns the signature operations interface
func (c *Context) Signer() *Signer {
	return c.signer
}

// Random returns the random number generator
func (c *Context) Random() *QuantumRandom {
	return c.random
}

// Close closes the context and underlying device
func (c *Context) Close() error {
	return c.device.Close()
}

// Info returns device information
func (c *Context) Info() (*DeviceInfo, error) {
	return c.device.Info()
}

// Status returns device status
func (c *Context) Status() (*DeviceStatus, error) {
	return c.device.Status()
}

// Hash computes a hash of the given data
func (c *Context) Hash(data []byte, alg HashAlgorithm) ([]byte, error) {
	handle, err := c.device.getHandle()
	if err != nil {
		return nil, err
	}
	defer c.device.releaseHandle()
	
	return cgoHash(handle, alg, data)
}

// SHA256 computes SHA-256 hash
func (c *Context) SHA256(data []byte) ([]byte, error) {
	return c.Hash(data, HashSha256)
}

// SHA384 computes SHA-384 hash
func (c *Context) SHA384(data []byte) ([]byte, error) {
	return c.Hash(data, HashSha384)
}

// SHA512 computes SHA-512 hash
func (c *Context) SHA512(data []byte) ([]byte, error) {
	return c.Hash(data, HashSha512)
}

// SHA3_256 computes SHA3-256 hash
func (c *Context) SHA3_256(data []byte) ([]byte, error) {
	return c.Hash(data, HashSha3_256)
}

// SHA3_512 computes SHA3-512 hash
func (c *Context) SHA3_512(data []byte) ([]byte, error) {
	return c.Hash(data, HashSha3_512)
}

// Hasher provides incremental hash computation
type Hasher struct {
	context unsafe.Pointer
	alg     HashAlgorithm
	device  *Device
}

// NewHasher creates a new incremental hasher
func (c *Context) NewHasher(alg HashAlgorithm) (*Hasher, error) {
	handle, err := c.device.getHandle()
	if err != nil {
		return nil, err
	}
	defer c.device.releaseHandle()
	
	// Note: This would need the hash_init CGO function implemented
	// For now, return a placeholder error
	return nil, ErrNotSupported
}

// Convenience methods on Context

// GenerateKemKeyPair generates an ML-KEM key pair
func (c *Context) GenerateKemKeyPair(alg KemAlgorithm) (*KemKeyPair, error) {
	return c.kem.GenerateKeyPair(alg)
}

// Encapsulate performs ML-KEM encapsulation
func (c *Context) Encapsulate(publicKey []byte, alg KemAlgorithm) (*EncapsulationResult, error) {
	return c.kem.Encapsulate(publicKey, alg)
}

// Decapsulate performs ML-KEM decapsulation
func (c *Context) Decapsulate(secretKey, ciphertext []byte, alg KemAlgorithm) ([]byte, error) {
	return c.kem.Decapsulate(secretKey, ciphertext, alg)
}

// GenerateSignatureKeyPair generates a signature key pair
func (c *Context) GenerateSignatureKeyPair(alg SignatureAlgorithm) (*SignatureKeyPair, error) {
	return c.signer.GenerateKeyPair(alg)
}

// Sign signs a message
func (c *Context) Sign(secretKey, message []byte, alg SignatureAlgorithm) ([]byte, error) {
	return c.signer.Sign(secretKey, message, alg)
}

// Verify verifies a signature
func (c *Context) Verify(publicKey, message, signature []byte, alg SignatureAlgorithm) (bool, error) {
	return c.signer.Verify(publicKey, message, signature, alg)
}

// RandomBytes generates random bytes
func (c *Context) RandomBytes(count int) ([]byte, error) {
	return c.random.Bytes(count)
}

// FillRandom fills a buffer with random bytes
func (c *Context) FillRandom(buffer []byte) error {
	return c.random.GetBytes(buffer)
}

// Global convenience functions

// QuickKemKeyExchange performs a quick ML-KEM key exchange using default device
func QuickKemKeyExchange(alg KemAlgorithm) (*KemKeyPair, *EncapsulationResult, []byte, error) {
	ctx, err := NewDefaultContext()
	if err != nil {
		return nil, nil, nil, err
	}
	defer ctx.Close()
	
	return ctx.Kem().DemoKeyExchange(alg)
}

// QuickSignVerify performs a quick sign/verify cycle using default device
func QuickSignVerify(message string, alg SignatureAlgorithm) (*SignatureKeyPair, []byte, bool, error) {
	ctx, err := NewDefaultContext()
	if err != nil {
		return nil, nil, false, err
	}
	defer ctx.Close()
	
	return ctx.Signer().DemoSignVerify(message, alg)
}

// QuickRandomBytes generates random bytes using default device
func QuickRandomBytes(count int) ([]byte, error) {
	ctx, err := NewDefaultContext()
	if err != nil {
		return nil, err
	}
	defer ctx.Close()
	
	return ctx.RandomBytes(count)
}

// Init initializes the SDK with the specified flags
func Init(flags DeviceFlags) error {
	return cgoInit(flags)
}

// InitDefault initializes the SDK with default flags
func InitDefault() error {
	return cgoInit(FlagDefault)
}