#!/usr/bin/env python3
"""
Random Example - QUAC 100 Python SDK

Demonstrates Quantum Random Number Generation (QRNG) operations.
"""

import quantacore
from quantacore import to_hex


def main():
    print("=" * 60)
    print("QUAC 100 Python SDK - QRNG Example")
    print("=" * 60)
    
    quantacore.initialize()
    
    try:
        with quantacore.open_first_device() as device:
            random = device.random()
            
            # Entropy Status
            print(f"\n{'─' * 60}")
            print("Entropy Source Status")
            print(f"{'─' * 60}")
            
            status = random.get_entropy_status()
            print(f"\n    Level: {status.level}%")
            print(f"    Healthy: {status.is_healthy}")
            print(f"    Total Generated: {status.total_generated:,} bytes")
            print(f"    Generation Rate: {status.generation_rate:.2f} bytes/sec")
            
            # Random Bytes
            print(f"\n{'─' * 60}")
            print("Random Bytes")
            print(f"{'─' * 60}")
            
            print("\n[1] 16 random bytes:")
            data = random.bytes(16)
            print(f"    {to_hex(data)}")
            
            print("\n[2] 32 random bytes:")
            data = random.bytes(32)
            print(f"    {to_hex(data)}")
            
            print("\n[3] 64 random bytes:")
            data = random.bytes(64)
            print(f"    {to_hex(data[:32])}...")
            
            # Fill buffer
            print("\n[4] Fill existing buffer:")
            buffer = bytearray(16)
            random.next_bytes(buffer)
            print(f"    {to_hex(bytes(buffer))}")
            
            # Random Integers
            print(f"\n{'─' * 60}")
            print("Random Integers")
            print(f"{'─' * 60}")
            
            print("\n[1] 10 random 32-bit integers:")
            values = [random.next_int() for _ in range(10)]
            for i, v in enumerate(values):
                print(f"    [{i}] {v:>12}")
            
            print("\n[2] 10 random integers [0, 100):")
            values = [random.next_int(100) for _ in range(10)]
            print(f"    {values}")
            
            print("\n[3] 10 random integers [10, 20]:")
            values = [random.randint(10, 20) for _ in range(10)]
            print(f"    {values}")
            
            print("\n[4] 5 random 64-bit integers:")
            values = [random.next_long() for _ in range(5)]
            for i, v in enumerate(values):
                print(f"    [{i}] {v}")
            
            # Random Floats
            print(f"\n{'─' * 60}")
            print("Random Floats")
            print(f"{'─' * 60}")
            
            print("\n[1] 5 random floats [0.0, 1.0):")
            values = [random.next_float() for _ in range(5)]
            for i, v in enumerate(values):
                print(f"    [{i}] {v:.10f}")
            
            print("\n[2] 5 random doubles [0.0, 1.0):")
            values = [random.next_double() for _ in range(5)]
            for i, v in enumerate(values):
                print(f"    [{i}] {v:.15f}")
            
            print("\n[3] 5 random floats [10.0, 20.0):")
            values = [random.uniform(10.0, 20.0) for _ in range(5)]
            for i, v in enumerate(values):
                print(f"    [{i}] {v:.6f}")
            
            # Random Booleans
            print(f"\n{'─' * 60}")
            print("Random Booleans")
            print(f"{'─' * 60}")
            
            print("\n[1] 20 random booleans:")
            values = [random.next_bool() for _ in range(20)]
            print(f"    {values}")
            true_count = sum(values)
            print(f"    True: {true_count}, False: {20 - true_count}")
            
            # UUIDs
            print(f"\n{'─' * 60}")
            print("Random UUIDs")
            print(f"{'─' * 60}")
            
            print("\n[1] 5 random UUIDs:")
            for i in range(5):
                print(f"    [{i}] {random.uuid()}")
            
            # Choice and Sampling
            print(f"\n{'─' * 60}")
            print("Random Selection")
            print(f"{'─' * 60}")
            
            items = ['apple', 'banana', 'cherry', 'date', 'elderberry']
            print(f"\nItems: {items}")
            
            print("\n[1] Random choice (5 times):")
            choices = [random.choice(items) for _ in range(5)]
            print(f"    {choices}")
            
            print("\n[2] Random sample (3 items, no replacement):")
            sample = random.sample(items, 3)
            print(f"    {sample}")
            
            # Shuffling
            print(f"\n{'─' * 60}")
            print("Shuffling")
            print(f"{'─' * 60}")
            
            deck = list(range(1, 11))
            print(f"\nOriginal: {deck}")
            
            print("\n[1] Shuffle in-place:")
            random.shuffle(deck)
            print(f"    Shuffled: {deck}")
            
            print("\n[2] Get shuffled copy:")
            original = ['A', 'B', 'C', 'D', 'E']
            shuffled = random.shuffled(original)
            print(f"    Original: {original}")
            print(f"    Shuffled: {shuffled}")
            
            # Dice Simulation
            print(f"\n{'─' * 60}")
            print("Dice Simulation (Rolling 2d6, 10 times)")
            print(f"{'─' * 60}")
            
            print()
            for i in range(10):
                d1 = random.randint(1, 6)
                d2 = random.randint(1, 6)
                total = d1 + d2
                print(f"    Roll {i+1}: {d1} + {d2} = {total}")
    
    finally:
        quantacore.cleanup()
    
    print("\n" + "=" * 60)
    print("QRNG example completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()