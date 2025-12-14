#!/usr/bin/env python3
"""
QUAC 100 Hybrid Encryption Example

Demonstrates hybrid encryption combining:
- ML-KEM for quantum-safe key encapsulation
- AES-256-GCM for symmetric encryption

This pattern is recommended for transitioning to post-quantum cryptography.

Usage:
    python hybrid_crypto.py

Copyright 2025 Dyber, Inc. All Rights Reserved.
"""

import sys
import os
import secrets
import hashlib
from typing import Tuple, Optional

# Try to import cryptography for AES
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False
    print("Note: 'cryptography' package not installed. Using simulation.\n")

try:
    from quac100 import QUAC, QUACError, Algorithm
    HAVE_QUAC = True
except ImportError:
    HAVE_QUAC = False


class HybridCrypto:
    """
    Hybrid encryption using ML-KEM + AES-256-GCM
    
    This provides:
    - Post-quantum security from ML-KEM
    - Efficient symmetric encryption from AES-GCM
    - Authenticated encryption (AEAD)
    """
    
    # Key sizes
    ML_KEM_768_PK_SIZE = 1184
    ML_KEM_768_SK_SIZE = 2400
    ML_KEM_768_CT_SIZE = 1088
    ML_KEM_768_SS_SIZE = 32
    
    AES_KEY_SIZE = 32  # 256 bits
    AES_NONCE_SIZE = 12
    AES_TAG_SIZE = 16
    
    def __init__(self, use_hardware: bool = False):
        """Initialize hybrid encryption system"""
        self.use_hardware = use_hardware and HAVE_QUAC
        
        if self.use_hardware:
            try:
                self.quac = QUAC()
                print("Using QUAC 100 hardware for KEM operations.")
            except:
                self.quac = None
                self.use_hardware = False
                print("Hardware not available, using simulation.")
        else:
            self.quac = None
            print("Using software simulation.")
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate ML-KEM-768 keypair"""
        if self.use_hardware and self.quac:
            return self.quac.kem_keygen(Algorithm.ML_KEM_768)
        else:
            # Simulation
            pk = secrets.token_bytes(self.ML_KEM_768_PK_SIZE)
            sk = secrets.token_bytes(self.ML_KEM_768_SK_SIZE)
            return pk, sk
    
    def _kem_encaps(self, pk: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate to get ciphertext and shared secret"""
        if self.use_hardware and self.quac:
            return self.quac.kem_encaps(Algorithm.ML_KEM_768, pk)
        else:
            ct = secrets.token_bytes(self.ML_KEM_768_CT_SIZE)
            ss = secrets.token_bytes(self.ML_KEM_768_SS_SIZE)
            # Store for simulation
            self._sim_ss = ss
            return ct, ss
    
    def _kem_decaps(self, ct: bytes, sk: bytes) -> bytes:
        """Decapsulate to recover shared secret"""
        if self.use_hardware and self.quac:
            return self.quac.kem_decaps(Algorithm.ML_KEM_768, ct, sk)
        else:
            # Return stored secret for simulation
            return getattr(self, '_sim_ss', secrets.token_bytes(self.ML_KEM_768_SS_SIZE))
    
    def _derive_aes_key(self, shared_secret: bytes, context: bytes = b"") -> bytes:
        """Derive AES key from shared secret using HKDF-like construction"""
        # Simple KDF: SHA-256(shared_secret || context)
        return hashlib.sha256(shared_secret + context).digest()
    
    def _aes_encrypt(self, key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
        """Encrypt with AES-256-GCM"""
        nonce = secrets.token_bytes(self.AES_NONCE_SIZE)
        
        if HAVE_CRYPTO:
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
        else:
            # Simulation: just XOR with key hash (NOT SECURE - for demo only)
            key_stream = hashlib.sha256(key + nonce).digest()
            ciphertext = bytes(p ^ k for p, k in zip(plaintext, key_stream * 100))
            ciphertext = ciphertext[:len(plaintext)] + secrets.token_bytes(self.AES_TAG_SIZE)
        
        return nonce + ciphertext
    
    def _aes_decrypt(self, key: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
        """Decrypt with AES-256-GCM"""
        nonce = ciphertext[:self.AES_NONCE_SIZE]
        ct = ciphertext[self.AES_NONCE_SIZE:]
        
        if HAVE_CRYPTO:
            aesgcm = AESGCM(key)
            return aesgcm.decrypt(nonce, ct, aad)
        else:
            # Simulation: reverse XOR
            key_stream = hashlib.sha256(key + nonce).digest()
            plaintext_len = len(ct) - self.AES_TAG_SIZE
            plaintext = bytes(c ^ k for c, k in zip(ct[:plaintext_len], key_stream * 100))
            return plaintext
    
    def encrypt(self, plaintext: bytes, recipient_pk: bytes, 
                aad: bytes = b"") -> bytes:
        """
        Hybrid encrypt a message
        
        Args:
            plaintext: Message to encrypt
            recipient_pk: Recipient's ML-KEM public key
            aad: Additional authenticated data
            
        Returns:
            Encrypted message: KEM_ciphertext || AES_nonce || AES_ciphertext || tag
        """
        # Step 1: Encapsulate to get shared secret
        kem_ct, shared_secret = self._kem_encaps(recipient_pk)
        
        # Step 2: Derive AES key
        aes_key = self._derive_aes_key(shared_secret, b"hybrid-encrypt-v1")
        
        # Step 3: Encrypt with AES-GCM
        aes_ct = self._aes_encrypt(aes_key, plaintext, aad)
        
        # Return: KEM ciphertext + AES ciphertext
        return kem_ct + aes_ct
    
    def decrypt(self, ciphertext: bytes, recipient_sk: bytes,
                aad: bytes = b"") -> bytes:
        """
        Hybrid decrypt a message
        
        Args:
            ciphertext: Encrypted message
            recipient_sk: Recipient's ML-KEM secret key
            aad: Additional authenticated data
            
        Returns:
            Decrypted plaintext
        """
        # Split ciphertext
        kem_ct = ciphertext[:self.ML_KEM_768_CT_SIZE]
        aes_ct = ciphertext[self.ML_KEM_768_CT_SIZE:]
        
        # Step 1: Decapsulate to get shared secret
        shared_secret = self._kem_decaps(kem_ct, recipient_sk)
        
        # Step 2: Derive AES key
        aes_key = self._derive_aes_key(shared_secret, b"hybrid-encrypt-v1")
        
        # Step 3: Decrypt with AES-GCM
        return self._aes_decrypt(aes_key, aes_ct, aad)


def main():
    print("=" * 64)
    print("  QUAC 100 Hybrid Encryption Demo")
    print("  ML-KEM-768 + AES-256-GCM")
    print("=" * 64)
    print()
    
    # Initialize hybrid crypto
    crypto = HybridCrypto(use_hardware=False)
    print()
    
    # =========================================================================
    # Step 1: Generate Recipient's Keypair
    # =========================================================================
    print("Step 1: Generate Recipient's Keypair")
    print("-" * 38)
    
    recipient_pk, recipient_sk = crypto.generate_keypair()
    print(f"  Public key:  {len(recipient_pk)} bytes")
    print(f"  Secret key:  {len(recipient_sk)} bytes")
    print()
    
    # =========================================================================
    # Step 2: Encrypt a Message
    # =========================================================================
    print("Step 2: Encrypt a Message")
    print("-" * 28)
    
    plaintext = b"This is a top-secret message protected by post-quantum cryptography!"
    aad = b"metadata:sender=alice,recipient=bob,timestamp=2025"
    
    print(f"  Plaintext: {plaintext.decode()}")
    print(f"  AAD: {aad.decode()}")
    print()
    
    ciphertext = crypto.encrypt(plaintext, recipient_pk, aad)
    
    print(f"  Ciphertext: {len(ciphertext)} bytes")
    print(f"    KEM ciphertext: {crypto.ML_KEM_768_CT_SIZE} bytes")
    print(f"    AES ciphertext: {len(ciphertext) - crypto.ML_KEM_768_CT_SIZE} bytes")
    print(f"  First 32 bytes: {ciphertext[:32].hex()}")
    print()
    
    # =========================================================================
    # Step 3: Decrypt the Message
    # =========================================================================
    print("Step 3: Decrypt the Message")
    print("-" * 30)
    
    decrypted = crypto.decrypt(ciphertext, recipient_sk, aad)
    
    print(f"  Decrypted: {decrypted.decode()}")
    print()
    
    if decrypted == plaintext:
        print("✓ SUCCESS! Message decrypted correctly.")
    else:
        print("✗ FAILURE! Decryption mismatch.")
        return 1
    print()
    
    # =========================================================================
    # Step 4: Demonstrate Authentication
    # =========================================================================
    print("Step 4: Demonstrate Authentication")
    print("-" * 37)
    print("Attempting to decrypt with wrong AAD...\n")
    
    try:
        wrong_aad = b"metadata:sender=eve,recipient=bob"
        crypto.decrypt(ciphertext, recipient_sk, wrong_aad)
        if not HAVE_CRYPTO:
            print("  (Simulation mode - authentication not fully simulated)")
        else:
            print("✗ ERROR: Should have failed with wrong AAD!")
    except Exception as e:
        print(f"✓ DETECTED: Decryption failed as expected.")
        print(f"  → Authenticated encryption ensures data integrity.")
    print()
    
    # =========================================================================
    # Summary
    # =========================================================================
    print("=" * 64)
    print("  Hybrid Encryption Summary")
    print("=" * 64)
    print()
    print("Message Size Overhead:")
    print(f"  Original plaintext:  {len(plaintext)} bytes")
    print(f"  Encrypted ciphertext: {len(ciphertext)} bytes")
    print(f"  Overhead: {len(ciphertext) - len(plaintext)} bytes")
    print(f"    - KEM ciphertext: {crypto.ML_KEM_768_CT_SIZE} bytes")
    print(f"    - AES nonce: {crypto.AES_NONCE_SIZE} bytes")
    print(f"    - AES tag: {crypto.AES_TAG_SIZE} bytes")
    print()
    print("Security Properties:")
    print("  • Post-quantum key exchange (ML-KEM-768)")
    print("  • Authenticated encryption (AES-256-GCM)")
    print("  • Forward secrecy (ephemeral KEM keys)")
    print("  • AAD integrity verification")
    print()
    print("Use Cases:")
    print("  • Secure file encryption")
    print("  • Encrypted email (like PGP)")
    print("  • Secure messaging protocols")
    print("  • Data-at-rest encryption")
    print("=" * 64)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())