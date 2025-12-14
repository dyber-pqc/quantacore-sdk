#!/usr/bin/env python3
"""
QUAC 100 ML-DSA (Dilithium) Digital Signature Demo

Demonstrates complete digital signature workflow:
- Key generation
- Message signing
- Signature verification
- Tamper detection

Usage:
    python sign_demo.py [44|65|87]

Copyright 2025 Dyber, Inc. All Rights Reserved.
"""

import sys
import argparse
import secrets
from dataclasses import dataclass
from typing import Tuple

try:
    from quac100 import QUAC, QUACError, Algorithm
    HAVE_QUAC = True
except ImportError:
    HAVE_QUAC = False
    print("Note: quac100 package not installed. Using simulation mode.\n")


@dataclass
class SignParams:
    """Signature algorithm parameters"""
    algorithm: str
    name: str
    security: str
    pk_size: int
    sk_size: int
    sig_size: int


# Algorithm parameters
SIGN_PARAMS = {
    44: SignParams("ML_DSA_44", "ML-DSA-44", "NIST Level 2 (128-bit)", 1312, 2560, 2420),
    65: SignParams("ML_DSA_65", "ML-DSA-65", "NIST Level 3 (192-bit)", 1952, 4032, 3309),
    87: SignParams("ML_DSA_87", "ML-DSA-87", "NIST Level 5 (256-bit)", 2592, 4896, 4627),
}


class SimulatedSign:
    """Simulated signature scheme for demonstration"""
    
    def __init__(self, params: SignParams):
        self.params = params
        self._keypairs = {}
    
    def keygen(self) -> Tuple[bytes, bytes]:
        """Generate keypair"""
        pk = secrets.token_bytes(self.params.pk_size)
        sk = secrets.token_bytes(self.params.sk_size)
        # Store for verification simulation
        self._keypairs[pk] = sk
        return pk, sk
    
    def sign(self, message: bytes, sk: bytes) -> bytes:
        """Sign a message"""
        # Simulate deterministic signature
        import hashlib
        h = hashlib.sha3_256(message + sk).digest()
        sig = h + secrets.token_bytes(self.params.sig_size - 32)
        # Store for simulation
        self._last_sig_hash = h
        self._last_message = message
        return sig
    
    def verify(self, message: bytes, signature: bytes, pk: bytes) -> bool:
        """Verify a signature"""
        # In simulation, check if message matches
        import hashlib
        if pk in self._keypairs:
            sk = self._keypairs[pk]
            expected_h = hashlib.sha3_256(message + sk).digest()
            return signature[:32] == expected_h
        return False


def print_hex_short(label: str, data: bytes, max_bytes: int = 32):
    """Print data as hex with truncation"""
    hex_str = data[:max_bytes].hex()
    suffix = "..." if len(data) > max_bytes else ""
    print(f"{label} ({len(data)} bytes): {hex_str}{suffix}")


def run_demo(level: int, use_simulator: bool = True):
    """Run the signature demonstration"""
    
    params = SIGN_PARAMS.get(level)
    if not params:
        print(f"Error: Invalid level {level}. Use 44, 65, or 87.")
        return 1
    
    print("=" * 64)
    print(f"  QUAC 100 ML-DSA Digital Signature Demo")
    print(f"  Algorithm: {params.name} (FIPS 204)")
    print(f"  Security:  {params.security}")
    print("=" * 64)
    print()
    
    # Initialize
    if HAVE_QUAC and not use_simulator:
        try:
            quac = QUAC()
            signer = quac
            print("Using QUAC 100 hardware accelerator.\n")
        except QUACError:
            signer = SimulatedSign(params)
            print("Hardware not available, using simulator.\n")
    else:
        signer = SimulatedSign(params)
        print("Using software simulator.\n")
    
    # Sample message
    message = (
        b"This is a critical financial transaction: "
        b"Transfer $1,000,000 from Account A to Account B. "
        b"Transaction ID: TXN-2025-001-PQC"
    )
    
    # =========================================================================
    # Step 1: Key Generation
    # =========================================================================
    print("Step 1: Key Generation")
    print("-" * 25)
    print("Generating a signing keypair...\n")
    
    if isinstance(signer, SimulatedSign):
        pk, sk = signer.keygen()
    else:
        pk, sk = signer.sign_keygen(getattr(Algorithm, params.algorithm))
    
    print_hex_short("Public Key (verification key)", pk)
    print(f"Secret Key (signing key): {len(sk)} bytes (kept private)\n")
    
    # =========================================================================
    # Step 2: Sign Message
    # =========================================================================
    print("Step 2: Sign Message")
    print("-" * 22)
    print(f"Message to sign:\n  \"{message.decode()}\"\n")
    
    if isinstance(signer, SimulatedSign):
        signature = signer.sign(message, sk)
    else:
        signature = signer.sign(
            getattr(Algorithm, params.algorithm), message, sk
        )
    
    print_hex_short("Signature", signature)
    print()
    
    # =========================================================================
    # Step 3: Verify Original Signature
    # =========================================================================
    print("Step 3: Verify Original Signature")
    print("-" * 36)
    
    if isinstance(signer, SimulatedSign):
        valid = signer.verify(message, signature, pk)
    else:
        valid = signer.verify(
            getattr(Algorithm, params.algorithm), message, signature, pk
        )
    
    if valid:
        print("✓ VALID: Signature verification succeeded.")
        print("  → The message is authentic and unmodified.")
        print("  → It was signed by the holder of the corresponding secret key.\n")
    else:
        print("✗ INVALID: Signature verification failed.")
        return 1
    
    # =========================================================================
    # Step 4: Detect Tampering
    # =========================================================================
    print("Step 4: Tamper Detection Test")
    print("-" * 32)
    print("Simulating message tampering (changing $1,000,000 to $10,000,000)...\n")
    
    tampered_message = message.replace(b"$1,000,000", b"$10,000,000")
    
    if isinstance(signer, SimulatedSign):
        tampered_valid = signer.verify(tampered_message, signature, pk)
    else:
        tampered_valid = signer.verify(
            getattr(Algorithm, params.algorithm), tampered_message, signature, pk
        )
    
    if not tampered_valid:
        print("✓ DETECTED: Signature verification FAILED for tampered message.")
        print("  → The tampering was successfully detected!")
        print("  → Any modification to the message invalidates the signature.\n")
    else:
        print("✗ ERROR: Tampered message was incorrectly accepted!")
        return 1
    
    # =========================================================================
    # Step 5: Wrong Key Test
    # =========================================================================
    print("Step 5: Wrong Key Detection Test")
    print("-" * 35)
    print("Generating a different keypair and trying to verify...\n")
    
    if isinstance(signer, SimulatedSign):
        wrong_pk, wrong_sk = signer.keygen()
        wrong_key_valid = signer.verify(message, signature, wrong_pk)
    else:
        wrong_pk, wrong_sk = signer.sign_keygen(
            getattr(Algorithm, params.algorithm)
        )
        wrong_key_valid = signer.verify(
            getattr(Algorithm, params.algorithm), message, signature, wrong_pk
        )
    
    if not wrong_key_valid:
        print("✓ DETECTED: Signature verification FAILED with wrong key.")
        print("  → Only the correct public key can verify the signature.\n")
    else:
        print("✗ ERROR: Wrong key was incorrectly accepted!")
    
    # Secure cleanup
    del sk
    del wrong_sk
    
    # =========================================================================
    # Summary
    # =========================================================================
    print("=" * 64)
    print("  Digital Signature Demo Complete")
    print("=" * 64)
    print(f"Algorithm:      {params.name}")
    print(f"Security Level: {params.security}")
    print(f"Public Key:     {len(pk)} bytes")
    print(f"Signature:      {len(signature)} bytes")
    print()
    print("ML-DSA provides:")
    print("  • Post-quantum security (resistant to Shor's algorithm)")
    print("  • EUF-CMA security (existential unforgeability)")
    print("  • Deterministic signatures (no random number needed)")
    print("  • Fast verification suitable for certificate checking")
    print("=" * 64)
    
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="QUAC 100 ML-DSA Digital Signature Demo"
    )
    parser.add_argument(
        "level",
        nargs="?",
        type=int,
        default=65,
        choices=[44, 65, 87],
        help="Security level: 44, 65, or 87 (default: 65)"
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