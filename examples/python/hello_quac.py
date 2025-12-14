#!/usr/bin/env python3
"""
QUAC 100 Hello World Example

Basic example demonstrating device initialization and random number generation.

Usage:
    python hello_quac.py

Copyright 2025 Dyber, Inc. All Rights Reserved.
"""

import sys

try:
    from quac100 import QUAC, QUACError, Algorithm
except ImportError:
    print("Note: quac100 package not installed. Using simulation mode.")
    # Simulation fallback for demonstration
    import secrets
    
    class Algorithm:
        ML_KEM_768 = "ML-KEM-768"
    
    class QUACError(Exception):
        pass
    
    class QUAC:
        def __init__(self, device_index=0, use_simulator=True):
            self.device_index = device_index
            self.is_simulator = use_simulator
            
        def get_device_count(self):
            return 1 if self.is_simulator else 0
            
        def get_device_info(self):
            return {
                "name": "QUAC 100 Simulator",
                "serial": "SIM-00000000",
                "firmware": "1.0.0-sim"
            }
        
        def random(self, length):
            return secrets.token_bytes(length)
        
        def kem_keygen(self, algorithm):
            return secrets.token_bytes(1184), secrets.token_bytes(2400)
        
        def close(self):
            pass
        
        def __enter__(self):
            return self
        
        def __exit__(self, *args):
            self.close()


def main():
    print("=" * 50)
    print("  QUAC 100 Hello World Example (Python)")
    print("=" * 50)
    print()
    
    # Step 1: Initialize
    print("1. Initializing QUAC SDK...")
    try:
        quac = QUAC(use_simulator=True)
        print("   SDK initialized successfully.")
    except QUACError as e:
        print(f"   Error: {e}")
        return 1
    print()
    
    # Step 2: Query devices
    print("2. Querying devices...")
    device_count = quac.get_device_count()
    print(f"   Found {device_count} device(s)")
    print()
    
    # Step 3: Get device info
    print("3. Device Information:")
    info = quac.get_device_info()
    print(f"   Name:     {info['name']}")
    print(f"   Serial:   {info['serial']}")
    print(f"   Firmware: {info['firmware']}")
    print()
    
    # Step 4: Generate random bytes
    print("4. Generating random bytes with QRNG...")
    random_bytes = quac.random(32)
    print(f"   Random (32 bytes): {random_bytes.hex()}")
    print()
    
    # Step 5: Quick ML-KEM demo
    print("5. Quick ML-KEM-768 demonstration...")
    pk, sk = quac.kem_keygen(Algorithm.ML_KEM_768)
    print(f"   Public key:  {len(pk)} bytes")
    print(f"   Secret key:  {len(sk)} bytes")
    print(f"   PK (first 16 bytes): {pk[:16].hex()}...")
    print()
    
    # Step 6: Cleanup
    print("6. Cleaning up...")
    quac.close()
    print("   Done!")
    print()
    
    print("=" * 50)
    print("  Hello World Complete!")
    print("=" * 50)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())