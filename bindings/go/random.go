// D:\quantacore-sdk\bindings\go\sign.go
// QUAC 100 SDK - Digital Signature Operations (ML-DSA, SLH-DSA)
// Copyright © 2025 Dyber, Inc. All Rights Reserved.

package quac100

import (
	"context"
	"fmt"
	"sync"
)

// Signer provides ML-DSA and SLH-DSA signature operations
type Signer struct {
	device *Device
}

// NewSigner creates a new Signer instance
func NewSigner(device *Device) *Signer {
	return &Signer{device: device}
}

// Signer returns a Signer instance for this device
func (d *Device) Signer() *Signer {
	return NewSigner(d)
}

// GenerateKeyPair generates a new signature key pair
func (s *Signer) GenerateKeyPair(alg SignatureAlgorithm) (*SignatureKeyPair, error) {
	handle, err := s.device.getHandle()
	if err != nil {
		return nil, err
	}
	defer s.device.releaseHandle()
	
	publicKey, secretKey, err := cgoSignKeygen(handle, alg)
	if err != nil {
		return nil, err
	}
	
	return NewSignatureKeyPair(publicKey, secretKey, alg), nil
}

// GenerateKeyPairContext generates a key pair with context cancellation
func (s *Signer) GenerateKeyPairContext(ctx context.Context, alg SignatureAlgorithm) (*SignatureKeyPair, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return s.GenerateKeyPair(alg)
	}
}

// Sign signs a message using a secret key
func (s *Signer) Sign(secretKey, message []byte, alg SignatureAlgorithm) ([]byte, error) {
	params := GetSignatureParams(alg)
	if len(secretKey) != params.SecretKeySize {
		return nil, fmt.Errorf("%w: expected %d bytes secret key, got %d", ErrInvalidKey, params.SecretKeySize, len(secretKey))
	}
	
	if len(message) == 0 {
		return nil, fmt.Errorf("%w: message cannot be empty", ErrInvalidParameter)
	}
	
	handle, err := s.device.getHandle()
	if err != nil {
		return nil, err
	}
	defer s.device.releaseHandle()
	
	return cgoSign(handle, alg, secretKey, message)
}

// SignKeyPair signs a message using a key pair's secret key
func (s *Signer) SignKeyPair(keyPair *SignatureKeyPair, message []byte) ([]byte, error) {
	if keyPair.IsZeroized() {
		return nil, ErrKeyZeroized
	}
	return s.Sign(keyPair.SecretKey, message, keyPair.Algorithm)
}

// SignString signs a string message (UTF-8 encoded)
func (s *Signer) SignString(keyPair *SignatureKeyPair, message string) ([]byte, error) {
	return s.SignKeyPair(keyPair, []byte(message))
}

// Verify verifies a signature
func (s *Signer) Verify(publicKey, message, signature []byte, alg SignatureAlgorithm) (bool, error) {
	params := GetSignatureParams(alg)
	if len(publicKey) != params.PublicKeySize {
		return false, fmt.Errorf("%w: expected %d bytes public key, got %d", ErrInvalidKey, params.PublicKeySize, len(publicKey))
	}
	
	if len(message) == 0 {
		return false, fmt.Errorf("%w: message cannot be empty", ErrInvalidParameter)
	}
	
	handle, err := s.device.getHandle()
	if err != nil {
		return false, err
	}
	defer s.device.releaseHandle()
	
	return cgoVerify(handle, alg, publicKey, message, signature)
}

// VerifyKeyPair verifies a signature using a key pair's public key
func (s *Signer) VerifyKeyPair(keyPair *SignatureKeyPair, message, signature []byte) (bool, error) {
	if keyPair.IsZeroized() {
		return false, ErrKeyZeroized
	}
	return s.Verify(keyPair.PublicKey, message, signature, keyPair.Algorithm)
}

// VerifyString verifies a signature for a string message
func (s *Signer) VerifyString(keyPair *SignatureKeyPair, message string, signature []byte) (bool, error) {
	return s.VerifyKeyPair(keyPair, []byte(message), signature)
}

// VerifyOrError returns an error if verification fails
func (s *Signer) VerifyOrError(publicKey, message, signature []byte, alg SignatureAlgorithm) error {
	valid, err := s.Verify(publicKey, message, signature, alg)
	if err != nil {
		return err
	}
	if !valid {
		return ErrVerifyFailed
	}
	return nil
}

// VerifyOrErrorKeyPair returns an error if verification fails using a key pair
func (s *Signer) VerifyOrErrorKeyPair(keyPair *SignatureKeyPair, message, signature []byte) error {
	valid, err := s.VerifyKeyPair(keyPair, message, signature)
	if err != nil {
		return err
	}
	if !valid {
		return ErrVerifyFailed
	}
	return nil
}

// DemoSignVerify performs a complete sign/verify cycle for testing
func (s *Signer) DemoSignVerify(message string, alg SignatureAlgorithm) (*SignatureKeyPair, []byte, bool, error) {
	// Generate key pair
	keyPair, err := s.GenerateKeyPair(alg)
	if err != nil {
		return nil, nil, false, fmt.Errorf("keygen failed: %w", err)
	}
	
	// Sign message
	messageBytes := []byte(message)
	signature, err := s.SignKeyPair(keyPair, messageBytes)
	if err != nil {
		keyPair.Zeroize()
		return nil, nil, false, fmt.Errorf("signing failed: %w", err)
	}
	
	// Verify signature
	valid, err := s.VerifyKeyPair(keyPair, messageBytes, signature)
	if err != nil {
		keyPair.Zeroize()
		return nil, nil, false, fmt.Errorf("verification failed: %w", err)
	}
	
	return keyPair, signature, valid, nil
}

// BatchSign signs multiple messages with the same key
func (s *Signer) BatchSign(keyPair *SignatureKeyPair, messages [][]byte) ([][]byte, []error) {
	signatures := make([][]byte, len(messages))
	errors := make([]error, len(messages))
	
	for i, msg := range messages {
		signatures[i], errors[i] = s.SignKeyPair(keyPair, msg)
	}
	
	return signatures, errors
}

// BatchVerify verifies multiple signatures with the same key
func (s *Signer) BatchVerify(keyPair *SignatureKeyPair, messages, signatures [][]byte) ([]bool, []error) {
	if len(messages) != len(signatures) {
		results := make([]bool, len(messages))
		errors := make([]error, len(messages))
		for i := range errors {
			errors[i] = ErrInvalidParameter
		}
		return results, errors
	}
	
	results := make([]bool, len(messages))
	errors := make([]error, len(messages))
	
	for i := range messages {
		results[i], errors[i] = s.VerifyKeyPair(keyPair, messages[i], signatures[i])
	}
	
	return results, errors
}

// ParallelSign signs multiple messages in parallel
func (s *Signer) ParallelSign(ctx context.Context, keyPair *SignatureKeyPair, messages [][]byte, maxWorkers int) ([][]byte, []error) {
	if maxWorkers < 1 {
		maxWorkers = 1
	}
	
	signatures := make([][]byte, len(messages))
	errors := make([]error, len(messages))
	
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxWorkers)
	
	for i, msg := range messages {
		select {
		case <-ctx.Done():
			errors[i] = ctx.Err()
			continue
		default:
		}
		
		wg.Add(1)
		sem <- struct{}{}
		
		go func(idx int, message []byte) {
			defer wg.Done()
			defer func() { <-sem }()
			
			select {
			case <-ctx.Done():
				errors[idx] = ctx.Err()
				return
			default:
			}
			
			signatures[idx], errors[idx] = s.SignKeyPair(keyPair, message)
		}(i, msg)
	}
	
	wg.Wait()
	return signatures, errors
}

// ParallelVerify verifies multiple signatures in parallel
func (s *Signer) ParallelVerify(ctx context.Context, keyPair *SignatureKeyPair, messages, signatures [][]byte, maxWorkers int) ([]bool, []error) {
	if len(messages) != len(signatures) {
		results := make([]bool, len(messages))
		errors := make([]error, len(messages))
		for i := range errors {
			errors[i] = ErrInvalidParameter
		}
		return results, errors
	}
	
	if maxWorkers < 1 {
		maxWorkers = 1
	}
	
	results := make([]bool, len(messages))
	errors := make([]error, len(messages))
	
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxWorkers)
	
	for i := range messages {
		select {
		case <-ctx.Done():
			errors[i] = ctx.Err()
			continue
		default:
		}
		
		wg.Add(1)
		sem <- struct{}{}
		
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()
			
			select {
			case <-ctx.Done():
				errors[idx] = ctx.Err()
				return
			default:
			}
			
			results[idx], errors[idx] = s.VerifyKeyPair(keyPair, messages[idx], signatures[idx])
		}(i)
	}
	
	wg.Wait()
	return results, errors
}

// DetectSignatureAlgorithmFromPublicKey attempts to detect the algorithm from public key size
func DetectSignatureAlgorithmFromPublicKey(keySize int) (SignatureAlgorithm, bool) {
	switch keySize {
	case 1312:
		return MlDsa44, true
	case 1952:
		return MlDsa65, true
	case 2592:
		return MlDsa87, true
	case 32:
		return SlhDsaSha2_128s, true // Could also be 128f
	case 48:
		return SlhDsaSha2_192s, true // Could also be 192f
	case 64:
		return SlhDsaSha2_256s, true // Could also be 256f
	default:
		return 0, false
	}
}

// DetectSignatureAlgorithmFromSecretKey attempts to detect the algorithm from secret key size
func DetectSignatureAlgorithmFromSecretKey(keySize int) (SignatureAlgorithm, bool) {
	switch keySize {
	case 2560:
		return MlDsa44, true
	case 4032:
		return MlDsa65, true
	case 4896:
		return MlDsa87, true
	case 64:
		return SlhDsaSha2_128s, true
	case 96:
		return SlhDsaSha2_192s, true
	case 128:
		return SlhDsaSha2_256s, true
	default:
		return 0, false
	}
}

// ImportSignaturePublicKey imports a public key and detects the algorithm
func ImportSignaturePublicKey(keyData []byte) (*SignatureKeyPair, error) {
	alg, ok := DetectSignatureAlgorithmFromPublicKey(len(keyData))
	if !ok {
		return nil, fmt.Errorf("%w: unknown public key size %d", ErrInvalidKey, len(keyData))
	}
	
	return &SignatureKeyPair{
		PublicKey: keyData,
		Algorithm: alg,
		Usage:     KeyUsageVerify,
	}, nil
}

// Convenience functions for Device

// SignGenerateKeyPair generates a signature key pair using the device
func (d *Device) SignGenerateKeyPair(alg SignatureAlgorithm) (*SignatureKeyPair, error) {
	return d.Signer().GenerateKeyPair(alg)
}

// Sign signs a message using the device
func (d *Device) Sign(secretKey, message []byte, alg SignatureAlgorithm) ([]byte, error) {
	return d.Signer().Sign(secretKey, message, alg)
}

// Verify verifies a signature using the device
func (d *Device) Verify(publicKey, message, signature []byte, alg SignatureAlgorithm) (bool, error) {
	return d.Signer().Verify(publicKey, message, signature, alg)
}