#!/usr/bin/env python3
"""
Basic Example - QUAC 100 Python SDK

Demonstrates library initialization, device enumeration, and basic operations.
"""

import quantacore


def main():
    print("=" * 60)
    print("QUAC 100 Python SDK - Basic Example")
    print("=" * 60)
    
    # Initialize library
    print("\n[1] Initializing library...")
    quantacore.initialize()
    
    try:
        # Get version info
        print(f"\n[2] Library Information:")
        print(f"    Version: {quantacore.get_version()}")
        print(f"    Build: {quantacore.get_build_info()}")
        
        # Enumerate devices
        print(f"\n[3] Device Enumeration:")
        device_count = quantacore.get_device_count()
        print(f"    Found {device_count} device(s)")
        
        devices = quantacore.enumerate_devices()
        for dev in devices:
            print(f"    - Device {dev.index}: {dev.model}")
            print(f"      Serial: {dev.serial_number}")
            print(f"      Firmware: {dev.firmware_version}")
            print(f"      Key Slots: {dev.key_slots}")
        
        if device_count == 0:
            print("\n    No devices found. Exiting.")
            return
        
        # Open first device
        print(f"\n[4] Opening device...")
        device = quantacore.open_first_device()
        
        try:
            # Get device info
            info = device.get_info()
            print(f"    Connected to: {info.model}")
            
            # Get device status
            print(f"\n[5] Device Status:")
            status = device.get_status()
            print(f"    Temperature: {status.temperature}°C")
            print(f"    Entropy Level: {status.entropy_level}%")
            print(f"    Operation Count: {status.operation_count}")
            print(f"    Healthy: {status.is_healthy}")
            
            # Run self-test
            print(f"\n[6] Running self-test...")
            device.self_test()
            print("    Self-test passed!")
            
            # Check subsystems
            print(f"\n[7] Available Subsystems:")
            print(f"    - KEM (Key Encapsulation): {device.kem()}")
            print(f"    - Sign (Digital Signatures): {device.sign()}")
            print(f"    - Hash (Cryptographic Hashing): {device.hash()}")
            print(f"    - Random (QRNG): {device.random()}")
            print(f"    - Keys (HSM Storage): {device.keys()}")
            
        finally:
            device.close()
            print(f"\n[8] Device closed.")
    
    finally:
        quantacore.cleanup()
        print("\n[9] Library cleanup complete.")
    
    print("\n" + "=" * 60)
    print("Basic example completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()