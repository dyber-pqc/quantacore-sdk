#!/usr/bin/env python3
"""
Signature Example - QUAC 100 Python SDK

Demonstrates ML-DSA (Dilithium) digital signature operations.
"""

import quantacore
from quantacore import SignAlgorithm, to_hex


def main():
    print("=" * 60)
    print("QUAC 100 Python SDK - Digital Signature Example")
    print("=" * 60)
    
    quantacore.initialize()
    
    try:
        with quantacore.open_first_device() as device:
            sign = device.sign()
            
            # Test all ML-DSA variants
            algorithms = [
                (SignAlgorithm.ML_DSA_44, "ML-DSA-44 (128-bit security)"),
                (SignAlgorithm.ML_DSA_65, "ML-DSA-65 (192-bit security)"),
                (SignAlgorithm.ML_DSA_87, "ML-DSA-87 (256-bit security)"),
            ]
            
            for algo, name in algorithms:
                print(f"\n{'─' * 60}")
                print(f"Testing {name}")
                print(f"{'─' * 60}")
                
                # Key generation
                print("\n[1] Key Generation...")
                with sign.generate_keypair(algo) as keypair:
                    print(f"    Public key:  {len(keypair.public_key):>5} bytes")
                    print(f"    Secret key:  {len(keypair.secret_key):>5} bytes")
                    
                    # Sign a message
                    message = b"This is an important document that needs to be signed."
                    
                    print("\n[2] Signing...")
                    print(f"    Message: {message.decode()[:40]}...")
                    signature = sign.sign(keypair.secret_key, message, algo)
                    print(f"    Signature: {len(signature)} bytes")
                    print(f"    Sig preview: {to_hex(signature[:16])}...")
                    
                    # Verify signature
                    print("\n[3] Verification...")
                    valid = sign.verify(keypair.public_key, message, signature, algo)
                    if valid:
                        print("    ✓ Signature is VALID")
                    else:
                        print("    ✗ Signature is INVALID")
                    
                    # Test with wrong message
                    print("\n[4] Testing with modified message...")
                    modified = b"This message has been tampered with!"
                    valid = sign.verify(keypair.public_key, modified, signature, algo)
                    if not valid:
                        print("    ✓ Correctly rejected modified message")
                    else:
                        print("    ✗ ERROR: Should have rejected modified message")
            
            # Demonstrate string signing
            print(f"\n{'─' * 60}")
            print("Signing String Messages")
            print(f"{'─' * 60}")
            
            with sign.generate_keypair_65() as kp:
                # Sign string directly
                message = "Hello, Post-Quantum World! 🔐"
                print(f"\n[1] Message: {message}")
                
                sig = sign.sign_65(kp.secret_key, message)
                print(f"[2] Signature: {len(sig)} bytes")
                
                valid = sign.verify_65(kp.public_key, message, sig)
                print(f"[3] Valid: {valid}")
                
                # Test verify_or_raise
                print("\n[4] Testing verify_or_raise...")
                try:
                    sign.verify_or_raise(kp.public_key, message, sig, SignAlgorithm.ML_DSA_65)
                    print("    ✓ Verification passed")
                except quantacore.VerificationError:
                    print("    ✗ Verification failed")
                
                # Test with invalid signature
                print("\n[5] Testing verify_or_raise with invalid signature...")
                try:
                    sign.verify_or_raise(kp.public_key, "wrong message", sig, SignAlgorithm.ML_DSA_65)
                    print("    ✗ Should have raised VerificationError")
                except quantacore.VerificationError:
                    print("    ✓ Correctly raised VerificationError")
    
    finally:
        quantacore.cleanup()
    
    print("\n" + "=" * 60)
    print("Signature example completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()