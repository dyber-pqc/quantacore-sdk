#!/usr/bin/env python3
"""
Hash Example - QUAC 100 Python SDK

Demonstrates hardware-accelerated hashing operations.
"""

import quantacore
from quantacore import HashAlgorithm, to_hex


def main():
    print("=" * 60)
    print("QUAC 100 Python SDK - Hash Example")
    print("=" * 60)
    
    quantacore.initialize()
    
    try:
        with quantacore.open_first_device() as device:
            hash_obj = device.hash()
            
            test_data = b"The quick brown fox jumps over the lazy dog"
            
            # SHA-2 Family
            print(f"\n{'─' * 60}")
            print("SHA-2 Family")
            print(f"{'─' * 60}")
            print(f"\nInput: {test_data.decode()}")
            
            print("\n[1] SHA-256:")
            digest = hash_obj.sha256(test_data)
            print(f"    {to_hex(digest)}")
            print(f"    ({len(digest)} bytes)")
            
            print("\n[2] SHA-384:")
            digest = hash_obj.sha384(test_data)
            print(f"    {to_hex(digest)}")
            print(f"    ({len(digest)} bytes)")
            
            print("\n[3] SHA-512:")
            digest = hash_obj.sha512(test_data)
            print(f"    {to_hex(digest)}")
            print(f"    ({len(digest)} bytes)")
            
            # SHA-3 Family
            print(f"\n{'─' * 60}")
            print("SHA-3 Family")
            print(f"{'─' * 60}")
            
            print("\n[1] SHA3-256:")
            digest = hash_obj.sha3_256(test_data)
            print(f"    {to_hex(digest)}")
            print(f"    ({len(digest)} bytes)")
            
            print("\n[2] SHA3-384:")
            digest = hash_obj.sha3_384(test_data)
            print(f"    {to_hex(digest)}")
            print(f"    ({len(digest)} bytes)")
            
            print("\n[3] SHA3-512:")
            digest = hash_obj.sha3_512(test_data)
            print(f"    {to_hex(digest)}")
            print(f"    ({len(digest)} bytes)")
            
            # SHAKE (Variable Output)
            print(f"\n{'─' * 60}")
            print("SHAKE (Variable Output Length)")
            print(f"{'─' * 60}")
            
            print("\n[1] SHAKE128 (32 bytes):")
            output = hash_obj.shake128(test_data, 32)
            print(f"    {to_hex(output)}")
            
            print("\n[2] SHAKE128 (64 bytes):")
            output = hash_obj.shake128(test_data, 64)
            print(f"    {to_hex(output)}")
            
            print("\n[3] SHAKE256 (64 bytes):")
            output = hash_obj.shake256(test_data, 64)
            print(f"    {to_hex(output)}")
            
            # Incremental Hashing
            print(f"\n{'─' * 60}")
            print("Incremental Hashing")
            print(f"{'─' * 60}")
            
            print("\n[1] Hashing in parts with SHA-256:")
            with hash_obj.create_context(HashAlgorithm.SHA256) as ctx:
                ctx.update(b"The quick brown ")
                ctx.update(b"fox jumps over ")
                ctx.update(b"the lazy dog")
                digest = ctx.digest()
            print(f"    {to_hex(digest)}")
            
            # Verify it matches one-shot hash
            one_shot = hash_obj.sha256(test_data)
            if digest == one_shot:
                print("    ✓ Matches one-shot hash")
            else:
                print("    ✗ Does not match!")
            
            # HMAC
            print(f"\n{'─' * 60}")
            print("HMAC (Hash-based Message Authentication)")
            print(f"{'─' * 60}")
            
            key = b"secret-key-12345"
            data = b"Message to authenticate"
            
            print(f"\nKey: {key.decode()}")
            print(f"Data: {data.decode()}")
            
            print("\n[1] HMAC-SHA256:")
            mac = hash_obj.hmac_sha256(key, data)
            print(f"    {to_hex(mac)}")
            
            print("\n[2] HMAC-SHA512:")
            mac = hash_obj.hmac_sha512(key, data)
            print(f"    {to_hex(mac)}")
            
            # HKDF
            print(f"\n{'─' * 60}")
            print("HKDF (Key Derivation)")
            print(f"{'─' * 60}")
            
            ikm = b"input key material"
            salt = b"random salt value"
            info = b"application context"
            
            print(f"\nIKM: {ikm.decode()}")
            print(f"Salt: {salt.decode()}")
            print(f"Info: {info.decode()}")
            
            print("\n[1] Derive 32-byte key:")
            derived = hash_obj.hkdf(HashAlgorithm.SHA256, ikm, salt, info, 32)
            print(f"    {to_hex(derived)}")
            
            print("\n[2] Derive 64-byte key:")
            derived = hash_obj.hkdf(HashAlgorithm.SHA256, ikm, salt, info, 64)
            print(f"    {to_hex(derived)}")
    
    finally:
        quantacore.cleanup()
    
    print("\n" + "=" * 60)
    print("Hash example completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()