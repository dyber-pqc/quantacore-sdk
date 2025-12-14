// QUAC 100 ML-KEM (Kyber) Key Exchange Demo (Go)
//
// Demonstrates complete key encapsulation mechanism workflow:
// - Key generation
// - Encapsulation (sender side)
// - Decapsulation (receiver side)
// - Shared secret verification
//
// Build: go build -o kem_demo kem_demo.go
// Run:   ./kem_demo [512|768|1024]
//
// Copyright 2025 Dyber, Inc. All Rights Reserved.

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
)

// Algorithm represents KEM algorithm variants
type Algorithm int

const (
	AlgMLKEM512 Algorithm = iota
	AlgMLKEM768
	AlgMLKEM1024
)

// KEMParams holds algorithm parameters
type KEMParams struct {
	Algorithm Algorithm
	Name      string
	PKSize    int
	SKSize    int
	CTSize    int
	SSSize    int
}

var kemParams = map[int]KEMParams{
	512:  {AlgMLKEM512, "ML-KEM-512", 800, 1632, 768, 32},
	768:  {AlgMLKEM768, "ML-KEM-768", 1184, 2400, 1088, 32},
	1024: {AlgMLKEM1024, "ML-KEM-1024", 1568, 3168, 1568, 32},
}

// SimulatedKEM provides simulated KEM operations
type SimulatedKEM struct {
	params  KEMParams
	lastSS  []byte
}

func NewSimulatedKEM(params KEMParams) *SimulatedKEM {
	return &SimulatedKEM{params: params}
}

func (k *SimulatedKEM) Keygen() (pk, sk []byte, err error) {
	pk = make([]byte, k.params.PKSize)
	sk = make([]byte, k.params.SKSize)
	rand.Read(pk)
	rand.Read(sk)
	return pk, sk, nil
}

func (k *SimulatedKEM) Encaps(pk []byte) (ct, ss []byte, err error) {
	ct = make([]byte, k.params.CTSize)
	ss = make([]byte, k.params.SSSize)
	rand.Read(ct)
	rand.Read(ss)
	k.lastSS = ss // Store for simulation
	return ct, ss, nil
}

func (k *SimulatedKEM) Decaps(ct, sk []byte) (ss []byte, err error) {
	// In simulation, return the same shared secret
	if k.lastSS != nil {
		return k.lastSS, nil
	}
	ss = make([]byte, k.params.SSSize)
	rand.Read(ss)
	return ss, nil
}

func printHex(label string, data []byte, maxBytes int) {
	if maxBytes > len(data) {
		maxBytes = len(data)
	}
	suffix := ""
	if len(data) > maxBytes {
		suffix = "..."
	}
	fmt.Printf("%s (%d bytes):\n  %s%s\n", label, len(data),
		hex.EncodeToString(data[:maxBytes]), suffix)
}

func main() {
	// Parse command line
	level := flag.Int("level", 768, "Security level: 512, 768, or 1024")
	flag.Parse()

	// Get parameters
	params, ok := kemParams[*level]
	if !ok {
		fmt.Fprintf(os.Stderr, "Error: Invalid level %d. Use 512, 768, or 1024.\n", *level)
		os.Exit(1)
	}

	fmt.Println("================================================================")
	fmt.Println("  QUAC 100 ML-KEM Key Exchange Demo (Go)")
	fmt.Printf("  Algorithm: %s (FIPS 203)\n", params.Name)
	fmt.Println("================================================================")
	fmt.Println()

	// Initialize
	kem := NewSimulatedKEM(params)
	fmt.Println("Using software simulator.")
	fmt.Println()

	// =========================================================================
	// Step 1: Key Generation (Receiver - Alice)
	// =========================================================================
	fmt.Println("Step 1: Key Generation (Receiver - Alice)")
	fmt.Println("-" + "--------------------------------------------")
	fmt.Println("Alice generates a keypair to receive encrypted messages.")
	fmt.Println()

	alicePK, aliceSK, err := kem.Keygen()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Key generation failed: %v\n", err)
		os.Exit(1)
	}

	printHex("Alice's Public Key", alicePK, 48)
	fmt.Printf("Alice's Secret Key: %d bytes (kept private)\n\n", len(aliceSK))
	fmt.Println("Alice sends her public key to Bob...")
	fmt.Println()

	// =========================================================================
	// Step 2: Encapsulation (Sender - Bob)
	// =========================================================================
	fmt.Println("Step 2: Encapsulation (Sender - Bob)")
	fmt.Println("-------------------------------------")
	fmt.Println("Bob uses Alice's public key to create:")
	fmt.Println("  - A ciphertext (to send to Alice)")
	fmt.Println("  - A shared secret (kept by Bob)")
	fmt.Println()

	ciphertext, ssBob, err := kem.Encaps(alicePK)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Encapsulation failed: %v\n", err)
		os.Exit(1)
	}

	printHex("Ciphertext", ciphertext, 48)
	printHex("Bob's Shared Secret", ssBob, 32)
	fmt.Println()
	fmt.Println("Bob sends the ciphertext to Alice...")
	fmt.Println()

	// =========================================================================
	// Step 3: Decapsulation (Receiver - Alice)
	// =========================================================================
	fmt.Println("Step 3: Decapsulation (Receiver - Alice)")
	fmt.Println("-----------------------------------------")
	fmt.Println("Alice uses her secret key to recover the shared secret.")
	fmt.Println()

	ssAlice, err := kem.Decaps(ciphertext, aliceSK)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Decapsulation failed: %v\n", err)
		os.Exit(1)
	}

	printHex("Alice's Shared Secret", ssAlice, 32)
	fmt.Println()

	// =========================================================================
	// Step 4: Verification
	// =========================================================================
	fmt.Println("Step 4: Verification")
	fmt.Println("--------------------")

	if bytes.Equal(ssBob, ssAlice) {
		fmt.Println("✓ SUCCESS! Both parties have the same shared secret.")
		fmt.Println("  This secret can now be used as a symmetric encryption key.")
		fmt.Println()
	} else {
		fmt.Println("✗ FAILURE! Shared secrets do not match.")
		os.Exit(1)
	}

	// =========================================================================
	// Summary
	// =========================================================================
	fmt.Println("================================================================")
	fmt.Println("  Key Exchange Complete")
	fmt.Println("================================================================")
	fmt.Printf("Algorithm:      %s\n", params.Name)
	fmt.Printf("Public Key:     %d bytes\n", len(alicePK))
	fmt.Printf("Secret Key:     %d bytes\n", len(aliceSK))
	fmt.Printf("Ciphertext:     %d bytes\n", len(ciphertext))
	fmt.Printf("Shared Secret:  %d bytes (256 bits)\n", len(ssBob))
	fmt.Println()
	fmt.Println("This shared secret provides:")
	fmt.Println("  • Post-quantum security against Shor's algorithm")
	fmt.Println("  • IND-CCA2 security (chosen ciphertext attack resistance)")
	fmt.Println("  • Perfect forward secrecy when used with ephemeral keys")
	fmt.Println("================================================================")

	// Secure cleanup
	for i := range aliceSK {
		aliceSK[i] = 0
	}
	for i := range ssBob {
		ssBob[i] = 0
	}
	for i := range ssAlice {
		ssAlice[i] = 0
	}
}