#!/usr/bin/env python3
"""
QUAC 100 ML-KEM (Kyber) Key Exchange Demo

Demonstrates complete key encapsulation mechanism workflow:
- Key generation
- Encapsulation (sender side)
- Decapsulation (receiver side)
- Shared secret verification

Usage:
    python kem_demo.py [512|768|1024]

Copyright 2025 Dyber, Inc. All Rights Reserved.
"""

import sys
import argparse
import secrets
from dataclasses import dataclass
from typing import Tuple, Optional

try:
    from quac100 import QUAC, QUACError, Algorithm
    HAVE_QUAC = True
except ImportError:
    HAVE_QUAC = False
    print("Note: quac100 package not installed. Using simulation mode.\n")


@dataclass
class KEMParams:
    """KEM algorithm parameters"""
    algorithm: str
    name: str
    pk_size: int
    sk_size: int
    ct_size: int
    ss_size: int


# Algorithm parameters
KEM_PARAMS = {
    512: KEMParams("ML_KEM_512", "ML-KEM-512", 800, 1632, 768, 32),
    768: KEMParams("ML_KEM_768", "ML-KEM-768", 1184, 2400, 1088, 32),
    1024: KEMParams("ML_KEM_1024", "ML-KEM-1024", 1568, 3168, 1568, 32),
}


class SimulatedKEM:
    """Simulated KEM for demonstration without hardware"""
    
    def __init__(self, params: KEMParams):
        self.params = params
    
    def keygen(self) -> Tuple[bytes, bytes]:
        """Generate keypair"""
        pk = secrets.token_bytes(self.params.pk_size)
        sk = secrets.token_bytes(self.params.sk_size)
        return pk, sk
    
    def encaps(self, pk: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate to public key"""
        ct = secrets.token_bytes(self.params.ct_size)
        ss = secrets.token_bytes(self.params.ss_size)
        # Store for simulation
        self._last_ss = ss
        return ct, ss
    
    def decaps(self, ct: bytes, sk: bytes) -> bytes:
        """Decapsulate with secret key"""
        # In simulation, return the same shared secret
        return getattr(self, '_last_ss', secrets.token_bytes(self.params.ss_size))


def print_hex(label: str, data: bytes, max_bytes: int = 48):
    """Print data as hex with label"""
    hex_str = data[:max_bytes].hex()
    suffix = "..." if len(data) > max_bytes else ""
    print(f"{label} ({len(data)} bytes):")
    print(f"  {hex_str}{suffix}")


def run_demo(level: int, use_simulator: bool = True):
    """Run the KEM demonstration"""
    
    params = KEM_PARAMS.get(level)
    if not params:
        print(f"Error: Invalid level {level}. Use 512, 768, or 1024.")
        return 1
    
    print("=" * 64)
    print(f"  QUAC 100 ML-KEM Key Exchange Demo")
    print(f"  Algorithm: {params.name} (FIPS 203)")
    print("=" * 64)
    print()
    
    # Initialize
    if HAVE_QUAC and not use_simulator:
        try:
            quac = QUAC()
            kem = quac
            print("Using QUAC 100 hardware accelerator.\n")
        except QUACError:
            kem = SimulatedKEM(params)
            print("Hardware not available, using simulator.\n")
    else:
        kem = SimulatedKEM(params)
        print("Using software simulator.\n")
    
    # =========================================================================
    # Step 1: Key Generation (Receiver - Alice)
    # =========================================================================
    print("Step 1: Key Generation (Receiver - Alice)")
    print("-" * 45)
    print("Alice generates a keypair to receive encrypted messages.\n")
    
    if isinstance(kem, SimulatedKEM):
        alice_pk, alice_sk = kem.keygen()
    else:
        alice_pk, alice_sk = kem.kem_keygen(getattr(Algorithm, params.algorithm))
    
    print_hex("Alice's Public Key", alice_pk)
    print(f"Alice's Secret Key: {len(alice_sk)} bytes (kept private)\n")
    print("Alice sends her public key to Bob...\n")
    
    # =========================================================================
    # Step 2: Encapsulation (Sender - Bob)
    # =========================================================================
    print("Step 2: Encapsulation (Sender - Bob)")
    print("-" * 40)
    print("Bob uses Alice's public key to create:")
    print("  - A ciphertext (to send to Alice)")
    print("  - A shared secret (kept by Bob)\n")
    
    if isinstance(kem, SimulatedKEM):
        ciphertext, ss_bob = kem.encaps(alice_pk)
    else:
        ciphertext, ss_bob = kem.kem_encaps(
            getattr(Algorithm, params.algorithm), alice_pk
        )
    
    print_hex("Ciphertext", ciphertext)
    print_hex("Bob's Shared Secret", ss_bob)
    print("\nBob sends the ciphertext to Alice...\n")
    
    # =========================================================================
    # Step 3: Decapsulation (Receiver - Alice)
    # =========================================================================
    print("Step 3: Decapsulation (Receiver - Alice)")
    print("-" * 42)
    print("Alice uses her secret key to recover the shared secret.\n")
    
    if isinstance(kem, SimulatedKEM):
        ss_alice = kem.decaps(ciphertext, alice_sk)
    else:
        ss_alice = kem.kem_decaps(
            getattr(Algorithm, params.algorithm), ciphertext, alice_sk
        )
    
    print_hex("Alice's Shared Secret", ss_alice)
    print()
    
    # =========================================================================
    # Step 4: Verification
    # =========================================================================
    print("Step 4: Verification")
    print("-" * 22)
    
    if ss_bob == ss_alice:
        print("✓ SUCCESS! Both parties have the same shared secret.")
        print("  This secret can now be used as a symmetric encryption key.\n")
    else:
        print("✗ FAILURE! Shared secrets do not match.")
        return 1
    
    # =========================================================================
    # Summary
    # =========================================================================
    print("=" * 64)
    print("  Key Exchange Complete")
    print("=" * 64)
    print(f"Algorithm:      {params.name}")
    print(f"Public Key:     {len(alice_pk)} bytes")
    print(f"Secret Key:     {len(alice_sk)} bytes")
    print(f"Ciphertext:     {len(ciphertext)} bytes")
    print(f"Shared Secret:  {len(ss_bob)} bytes (256 bits)")
    print()
    print("This shared secret provides:")
    print("  • Post-quantum security against Shor's algorithm")
    print("  • IND-CCA2 security (chosen ciphertext attack resistance)")
    print("  • Perfect forward secrecy when used with ephemeral keys")
    print("=" * 64)
    
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="QUAC 100 ML-KEM Key Exchange Demo"
    )
    parser.add_argument(
        "level",
        nargs="?",
        type=int,
        default=768,
        choices=[512, 768, 1024],
        help="Security level: 512, 768, or 1024 (default: 768)"
    )
    parser.add_argument(
        "-s", "--simulator",
        action="store_true",
        help="Force use of software simulator"
    )
    
    args = parser.parse_args()
    return run_demo(args.level, args.simulator)


if __name__ == "__main__":
    sys.exit(main())