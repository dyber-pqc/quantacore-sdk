// D:\quantacore-sdk\bindings\go\kem.go
// QUAC 100 SDK - Key Encapsulation Mechanism (ML-KEM)
// Copyright © 2025 Dyber, Inc. All Rights Reserved.

package quac100

import (
	"context"
	"fmt"
	"sync"
)

// Kem provides ML-KEM (Kyber) operations
type Kem struct {
	device *Device
}

// NewKem creates a new Kem instance
func NewKem(device *Device) *Kem {
	return &Kem{device: device}
}

// Kem returns a Kem instance for this device
func (d *Device) Kem() *Kem {
	return NewKem(d)
}

// GenerateKeyPair generates a new ML-KEM key pair
func (k *Kem) GenerateKeyPair(alg KemAlgorithm) (*KemKeyPair, error) {
	handle, err := k.device.getHandle()
	if err != nil {
		return nil, err
	}
	defer k.device.releaseHandle()
	
	publicKey, secretKey, err := cgoKemKeygen(handle, alg)
	if err != nil {
		return nil, err
	}
	
	return NewKemKeyPair(publicKey, secretKey, alg), nil
}

// GenerateKeyPairContext generates a key pair with context cancellation
func (k *Kem) GenerateKeyPairContext(ctx context.Context, alg KemAlgorithm) (*KemKeyPair, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return k.GenerateKeyPair(alg)
	}
}

// Encapsulate generates a shared secret and ciphertext from a public key
func (k *Kem) Encapsulate(publicKey []byte, alg KemAlgorithm) (*EncapsulationResult, error) {
	params := GetKemParams(alg)
	if len(publicKey) != params.PublicKeySize {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidKey, params.PublicKeySize, len(publicKey))
	}
	
	handle, err := k.device.getHandle()
	if err != nil {
		return nil, err
	}
	defer k.device.releaseHandle()
	
	ciphertext, sharedSecret, err := cgoKemEncaps(handle, alg, publicKey)
	if err != nil {
		return nil, err
	}
	
	return &EncapsulationResult{
		Ciphertext:   ciphertext,
		SharedSecret: sharedSecret,
	}, nil
}

// EncapsulateKeyPair encapsulates using a key pair's public key
func (k *Kem) EncapsulateKeyPair(keyPair *KemKeyPair) (*EncapsulationResult, error) {
	if keyPair.IsZeroized() {
		return nil, ErrKeyZeroized
	}
	return k.Encapsulate(keyPair.PublicKey, keyPair.Algorithm)
}

// Decapsulate recovers a shared secret from a ciphertext using a secret key
func (k *Kem) Decapsulate(secretKey, ciphertext []byte, alg KemAlgorithm) ([]byte, error) {
	params := GetKemParams(alg)
	if len(secretKey) != params.SecretKeySize {
		return nil, fmt.Errorf("%w: expected %d bytes secret key, got %d", ErrInvalidKey, params.SecretKeySize, len(secretKey))
	}
	if len(ciphertext) != params.CiphertextSize {
		return nil, fmt.Errorf("%w: expected %d bytes ciphertext, got %d", ErrInvalidParameter, params.CiphertextSize, len(ciphertext))
	}
	
	handle, err := k.device.getHandle()
	if err != nil {
		return nil, err
	}
	defer k.device.releaseHandle()
	
	return cgoKemDecaps(handle, alg, secretKey, ciphertext)
}

// DecapsulateKeyPair decapsulates using a key pair's secret key
func (k *Kem) DecapsulateKeyPair(keyPair *KemKeyPair, ciphertext []byte) ([]byte, error) {
	if keyPair.IsZeroized() {
		return nil, ErrKeyZeroized
	}
	return k.Decapsulate(keyPair.SecretKey, ciphertext, keyPair.Algorithm)
}

// DecapsulateResult decapsulates using an encapsulation result
func (k *Kem) DecapsulateResult(keyPair *KemKeyPair, result *EncapsulationResult) ([]byte, error) {
	return k.DecapsulateKeyPair(keyPair, result.Ciphertext)
}

// DemoKeyExchange performs a complete key exchange for testing
func (k *Kem) DemoKeyExchange(alg KemAlgorithm) (*KemKeyPair, *EncapsulationResult, []byte, error) {
	// Generate key pair
	keyPair, err := k.GenerateKeyPair(alg)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("keygen failed: %w", err)
	}
	
	// Encapsulate
	encapsulation, err := k.EncapsulateKeyPair(keyPair)
	if err != nil {
		keyPair.Zeroize()
		return nil, nil, nil, fmt.Errorf("encapsulation failed: %w", err)
	}
	
	// Decapsulate
	sharedSecret, err := k.DecapsulateKeyPair(keyPair, encapsulation.Ciphertext)
	if err != nil {
		keyPair.Zeroize()
		encapsulation.Zeroize()
		return nil, nil, nil, fmt.Errorf("decapsulation failed: %w", err)
	}
	
	// Verify shared secrets match
	if !SecureCompare(encapsulation.SharedSecret, sharedSecret) {
		keyPair.Zeroize()
		encapsulation.Zeroize()
		SecureZero(sharedSecret)
		return nil, nil, nil, fmt.Errorf("shared secrets do not match")
	}
	
	return keyPair, encapsulation, sharedSecret, nil
}

// BatchEncapsulate performs batch encapsulation
func (k *Kem) BatchEncapsulate(publicKeys [][]byte, alg KemAlgorithm) ([]*EncapsulationResult, []error) {
	results := make([]*EncapsulationResult, len(publicKeys))
	errors := make([]error, len(publicKeys))
	
	for i, pk := range publicKeys {
		results[i], errors[i] = k.Encapsulate(pk, alg)
	}
	
	return results, errors
}

// ParallelEncapsulate performs parallel encapsulation with limited concurrency
func (k *Kem) ParallelEncapsulate(ctx context.Context, publicKeys [][]byte, alg KemAlgorithm, maxWorkers int) ([]*EncapsulationResult, []error) {
	if maxWorkers < 1 {
		maxWorkers = 1
	}
	
	results := make([]*EncapsulationResult, len(publicKeys))
	errors := make([]error, len(publicKeys))
	
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxWorkers)
	
	for i, pk := range publicKeys {
		select {
		case <-ctx.Done():
			errors[i] = ctx.Err()
			continue
		default:
		}
		
		wg.Add(1)
		sem <- struct{}{}
		
		go func(idx int, publicKey []byte) {
			defer wg.Done()
			defer func() { <-sem }()
			
			select {
			case <-ctx.Done():
				errors[idx] = ctx.Err()
				return
			default:
			}
			
			results[idx], errors[idx] = k.Encapsulate(publicKey, alg)
		}(i, pk)
	}
	
	wg.Wait()
	return results, errors
}

// DetectAlgorithmFromPublicKey attempts to detect the algorithm from public key size
func DetectKemAlgorithmFromPublicKey(keySize int) (KemAlgorithm, bool) {
	switch keySize {
	case 800:
		return MlKem512, true
	case 1184:
		return MlKem768, true
	case 1568:
		return MlKem1024, true
	default:
		return 0, false
	}
}

// DetectAlgorithmFromSecretKey attempts to detect the algorithm from secret key size
func DetectKemAlgorithmFromSecretKey(keySize int) (KemAlgorithm, bool) {
	switch keySize {
	case 1632:
		return MlKem512, true
	case 2400:
		return MlKem768, true
	case 3168:
		return MlKem1024, true
	default:
		return 0, false
	}
}

// ImportKemPublicKey imports a public key and detects the algorithm
func ImportKemPublicKey(keyData []byte) (*KemKeyPair, error) {
	alg, ok := DetectKemAlgorithmFromPublicKey(len(keyData))
	if !ok {
		return nil, fmt.Errorf("%w: unknown public key size %d", ErrInvalidKey, len(keyData))
	}
	
	return &KemKeyPair{
		PublicKey: keyData,
		Algorithm: alg,
		Usage:     KeyUsageEncapsulate,
	}, nil
}

// Convenience functions for Device

// KemGenerateKeyPair generates an ML-KEM key pair using the device
func (d *Device) KemGenerateKeyPair(alg KemAlgorithm) (*KemKeyPair, error) {
	return d.Kem().GenerateKeyPair(alg)
}

// KemEncapsulate performs encapsulation using the device
func (d *Device) KemEncapsulate(publicKey []byte, alg KemAlgorithm) (*EncapsulationResult, error) {
	return d.Kem().Encapsulate(publicKey, alg)
}

// KemDecapsulate performs decapsulation using the device
func (d *Device) KemDecapsulate(secretKey, ciphertext []byte, alg KemAlgorithm) ([]byte, error) {
	return d.Kem().Decapsulate(secretKey, ciphertext, alg)
}