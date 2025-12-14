// QUAC 100 ML-DSA (Dilithium) Digital Signature Demo (Go)
//
// Demonstrates complete digital signature workflow:
// - Key generation
// - Message signing
// - Signature verification
// - Tamper detection
//
// Build: go build -o sign_demo sign_demo.go
// Run:   ./sign_demo [44|65|87]
//
// Copyright 2025 Dyber, Inc. All Rights Reserved.

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
)

// Algorithm represents signature algorithm variants
type SignAlgorithm int

const (
	AlgMLDSA44 SignAlgorithm = iota
	AlgMLDSA65
	AlgMLDSA87
)

// SignParams holds algorithm parameters
type SignParams struct {
	Algorithm SignAlgorithm
	Name      string
	Security  string
	PKSize    int
	SKSize    int
	SigSize   int
}

var signParams = map[int]SignParams{
	44: {AlgMLDSA44, "ML-DSA-44", "NIST Level 2 (128-bit)", 1312, 2560, 2420},
	65: {AlgMLDSA65, "ML-DSA-65", "NIST Level 3 (192-bit)", 1952, 4032, 3309},
	87: {AlgMLDSA87, "ML-DSA-87", "NIST Level 5 (256-bit)", 2592, 4896, 4627},
}

// SimulatedSign provides simulated signature operations
type SimulatedSign struct {
	params   SignParams
	keypairs map[string][]byte // pk -> sk mapping for simulation
}

func NewSimulatedSign(params SignParams) *SimulatedSign {
	return &SimulatedSign{
		params:   params,
		keypairs: make(map[string][]byte),
	}
}

func (s *SimulatedSign) Keygen() (pk, sk []byte, err error) {
	pk = make([]byte, s.params.PKSize)
	sk = make([]byte, s.params.SKSize)
	rand.Read(pk)
	rand.Read(sk)
	// Store for verification simulation
	s.keypairs[string(pk)] = sk
	return pk, sk, nil
}

func (s *SimulatedSign) Sign(message, sk []byte) (sig []byte, err error) {
	// Create deterministic signature using hash
	h := sha256.New()
	h.Write(message)
	h.Write(sk)
	hash := h.Sum(nil)
	
	sig = make([]byte, s.params.SigSize)
	copy(sig, hash)
	rand.Read(sig[32:])
	return sig, nil
}

func (s *SimulatedSign) Verify(message, sig, pk []byte) bool {
	// Check if we have the secret key for this public key
	sk, ok := s.keypairs[string(pk)]
	if !ok {
		return false
	}
	
	// Recompute expected signature hash
	h := sha256.New()
	h.Write(message)
	h.Write(sk)
	expectedHash := h.Sum(nil)
	
	return bytes.Equal(sig[:32], expectedHash)
}

func printHexShort(label string, data []byte, maxBytes int) {
	if maxBytes > len(data) {
		maxBytes = len(data)
	}
	suffix := ""
	if len(data) > maxBytes {
		suffix = "..."
	}
	fmt.Printf("%s (%d bytes): %s%s\n", label, len(data),
		hex.EncodeToString(data[:maxBytes]), suffix)
}

func main() {
	// Parse command line
	level := flag.Int("level", 65, "Security level: 44, 65, or 87")
	flag.Parse()

	// Get parameters
	params, ok := signParams[*level]
	if !ok {
		fmt.Fprintf(os.Stderr, "Error: Invalid level %d. Use 44, 65, or 87.\n", *level)
		os.Exit(1)
	}

	fmt.Println("================================================================")
	fmt.Println("  QUAC 100 ML-DSA Digital Signature Demo (Go)")
	fmt.Printf("  Algorithm: %s (FIPS 204)\n", params.Name)
	fmt.Printf("  Security:  %s\n", params.Security)
	fmt.Println("================================================================")
	fmt.Println()

	// Initialize
	signer := NewSimulatedSign(params)
	fmt.Println("Using software simulator.")
	fmt.Println()

	// Sample message
	message := []byte("This is a critical financial transaction: " +
		"Transfer $1,000,000 from Account A to Account B. " +
		"Transaction ID: TXN-2025-001-PQC")

	// =========================================================================
	// Step 1: Key Generation
	// =========================================================================
	fmt.Println("Step 1: Key Generation")
	fmt.Println("-----------------------")
	fmt.Println("Generating a signing keypair...")
	fmt.Println()

	pk, sk, err := signer.Keygen()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Key generation failed: %v\n", err)
		os.Exit(1)
	}

	printHexShort("Public Key (verification key)", pk, 32)
	fmt.Printf("Secret Key (signing key): %d bytes (kept private)\n\n", len(sk))

	// =========================================================================
	// Step 2: Sign Message
	// =========================================================================
	fmt.Println("Step 2: Sign Message")
	fmt.Println("--------------------")
	fmt.Printf("Message to sign:\n  \"%s\"\n\n", string(message))

	signature, err := signer.Sign(message, sk)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Signing failed: %v\n", err)
		os.Exit(1)
	}

	printHexShort("Signature", signature, 32)
	fmt.Println()

	// =========================================================================
	// Step 3: Verify Original Signature
	// =========================================================================
	fmt.Println("Step 3: Verify Original Signature")
	fmt.Println("----------------------------------")

	if signer.Verify(message, signature, pk) {
		fmt.Println("✓ VALID: Signature verification succeeded.")
		fmt.Println("  → The message is authentic and unmodified.")
		fmt.Println("  → It was signed by the holder of the corresponding secret key.")
		fmt.Println()
	} else {
		fmt.Println("✗ INVALID: Signature verification failed.")
		os.Exit(1)
	}

	// =========================================================================
	// Step 4: Detect Tampering
	// =========================================================================
	fmt.Println("Step 4: Tamper Detection Test")
	fmt.Println("-----------------------------")
	fmt.Println("Simulating message tampering (changing $1,000,000 to $10,000,000)...")
	fmt.Println()

	tamperedMessage := bytes.Replace(message, []byte("$1,000,000"), []byte("$10,000,000"), 1)

	if !signer.Verify(tamperedMessage, signature, pk) {
		fmt.Println("✓ DETECTED: Signature verification FAILED for tampered message.")
		fmt.Println("  → The tampering was successfully detected!")
		fmt.Println("  → Any modification to the message invalidates the signature.")
		fmt.Println()
	} else {
		fmt.Println("✗ ERROR: Tampered message was incorrectly accepted!")
		os.Exit(1)
	}

	// =========================================================================
	// Step 5: Wrong Key Test
	// =========================================================================
	fmt.Println("Step 5: Wrong Key Detection Test")
	fmt.Println("---------------------------------")
	fmt.Println("Generating a different keypair and trying to verify...")
	fmt.Println()

	wrongPK, wrongSK, _ := signer.Keygen()

	if !signer.Verify(message, signature, wrongPK) {
		fmt.Println("✓ DETECTED: Signature verification FAILED with wrong key.")
		fmt.Println("  → Only the correct public key can verify the signature.")
		fmt.Println()
	} else {
		fmt.Println("✗ ERROR: Wrong key was incorrectly accepted!")
	}

	// Secure cleanup
	for i := range sk {
		sk[i] = 0
	}
	for i := range wrongSK {
		wrongSK[i] = 0
	}
	_ = wrongPK // Used above

	// =========================================================================
	// Summary
	// =========================================================================
	fmt.Println("================================================================")
	fmt.Println("  Digital Signature Demo Complete")
	fmt.Println("================================================================")
	fmt.Printf("Algorithm:      %s\n", params.Name)
	fmt.Printf("Security Level: %s\n", params.Security)
	fmt.Printf("Public Key:     %d bytes\n", len(pk))
	fmt.Printf("Signature:      %d bytes\n", len(signature))
	fmt.Println()
	fmt.Println("ML-DSA provides:")
	fmt.Println("  • Post-quantum security (resistant to Shor's algorithm)")
	fmt.Println("  • EUF-CMA security (existential unforgeability)")
	fmt.Println("  • Deterministic signatures (no random number needed)")
	fmt.Println("  • Fast verification suitable for certificate checking")
	fmt.Println("================================================================")
}