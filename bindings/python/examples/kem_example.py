#!/usr/bin/env python3
"""
KEM Example - QUAC 100 Python SDK

Demonstrates ML-KEM (Kyber) key encapsulation operations.
"""

import quantacore
from quantacore import KemAlgorithm, to_hex


def main():
    print("=" * 60)
    print("QUAC 100 Python SDK - KEM Example")
    print("=" * 60)
    
    quantacore.initialize()
    
    try:
        with quantacore.open_first_device() as device:
            kem = device.kem()
            
            # Test all ML-KEM variants
            algorithms = [
                (KemAlgorithm.ML_KEM_512, "ML-KEM-512 (128-bit security)"),
                (KemAlgorithm.ML_KEM_768, "ML-KEM-768 (192-bit security)"),
                (KemAlgorithm.ML_KEM_1024, "ML-KEM-1024 (256-bit security)"),
            ]
            
            for algo, name in algorithms:
                print(f"\n{'─' * 60}")
                print(f"Testing {name}")
                print(f"{'─' * 60}")
                
                # Key generation
                print("\n[1] Key Generation...")
                with kem.generate_keypair(algo) as keypair:
                    print(f"    Public key:  {len(keypair.public_key):>5} bytes")
                    print(f"    Secret key:  {len(keypair.secret_key):>5} bytes")
                    
                    # Encapsulation (sender side)
                    print("\n[2] Encapsulation (Sender)...")
                    with kem.encapsulate(keypair.public_key, algo) as encap:
                        print(f"    Ciphertext:    {len(encap.ciphertext):>5} bytes")
                        print(f"    Shared secret: {len(encap.shared_secret):>5} bytes")
                        print(f"    Sender secret: {to_hex(encap.shared_secret[:16])}...")
                        
                        # Decapsulation (recipient side)
                        print("\n[3] Decapsulation (Recipient)...")
                        shared_secret = kem.decapsulate(
                            keypair.secret_key,
                            encap.ciphertext,
                            algo
                        )
                        print(f"    Recipient secret: {to_hex(shared_secret[:16])}...")
                        
                        # Verify secrets match
                        print("\n[4] Verification...")
                        if shared_secret == encap.shared_secret:
                            print("    ✓ Shared secrets match!")
                        else:
                            print("    ✗ ERROR: Shared secrets do not match!")
            
            # Demonstrate convenience methods
            print(f"\n{'─' * 60}")
            print("Using Convenience Methods")
            print(f"{'─' * 60}")
            
            print("\n[1] Generate ML-KEM-768 key pair...")
            with kem.generate_keypair_768() as kp:
                print(f"    Generated {len(kp.public_key)} byte public key")
                
                print("\n[2] Encapsulate...")
                with kem.encapsulate_768(kp.public_key) as enc:
                    print(f"    Ciphertext: {len(enc.ciphertext)} bytes")
                    
                    print("\n[3] Decapsulate...")
                    ss = kem.decapsulate_768(kp.secret_key, enc.ciphertext)
                    
                    print(f"\n    Final shared secret: {to_hex(ss)}")
    
    finally:
        quantacore.cleanup()
    
    print("\n" + "=" * 60)
    print("KEM example completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()