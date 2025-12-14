#!/usr/bin/env python3
"""
QUAC 100 Performance Benchmark

Measures performance of cryptographic operations:
- ML-KEM key generation, encapsulation, decapsulation
- ML-DSA key generation, signing, verification
- QRNG random number generation

Usage:
    python benchmark.py [-i ITERATIONS] [-a ALGORITHM]

Copyright 2025 Dyber, Inc. All Rights Reserved.
"""

import sys
import time
import argparse
import statistics
import secrets
from dataclasses import dataclass
from typing import List, Callable, Any

try:
    from quac100 import QUAC, QUACError, Algorithm
    HAVE_QUAC = True
except ImportError:
    HAVE_QUAC = False


@dataclass
class BenchmarkResult:
    """Result of a benchmark run"""
    name: str
    iterations: int
    total_time_ms: float
    mean_time_us: float
    min_time_us: float
    max_time_us: float
    std_dev_us: float
    ops_per_sec: float


class Timer:
    """High-resolution timer"""
    
    def __init__(self):
        self.start_time = None
        self.times: List[float] = []
    
    def start(self):
        self.start_time = time.perf_counter()
    
    def stop(self) -> float:
        elapsed = (time.perf_counter() - self.start_time) * 1_000_000  # microseconds
        self.times.append(elapsed)
        return elapsed
    
    def reset(self):
        self.times = []
    
    def get_stats(self) -> dict:
        if not self.times:
            return {}
        return {
            "count": len(self.times),
            "total_ms": sum(self.times) / 1000,
            "mean_us": statistics.mean(self.times),
            "min_us": min(self.times),
            "max_us": max(self.times),
            "std_dev_us": statistics.stdev(self.times) if len(self.times) > 1 else 0,
            "ops_per_sec": len(self.times) / (sum(self.times) / 1_000_000) if sum(self.times) > 0 else 0
        }


class SimulatedQUAC:
    """Simulated QUAC for benchmarking without hardware"""
    
    def __init__(self):
        # Simulate ~65µs for ML-KEM-768 keygen
        self.kem_keygen_delay = 0.000065
        # Simulate ~35µs for ML-KEM-768 encaps
        self.kem_encaps_delay = 0.000035
        # Simulate ~38µs for ML-KEM-768 decaps
        self.kem_decaps_delay = 0.000038
        # Simulate ~130µs for ML-DSA-65 keygen
        self.sign_keygen_delay = 0.000130
        # Simulate ~180µs for ML-DSA-65 sign
        self.sign_delay = 0.000180
        # Simulate ~65µs for ML-DSA-65 verify
        self.verify_delay = 0.000065
        # Simulate ~5µs for 32 bytes random
        self.random_delay = 0.000005
    
    def kem_keygen(self, alg) -> tuple:
        time.sleep(self.kem_keygen_delay)
        return secrets.token_bytes(1184), secrets.token_bytes(2400)
    
    def kem_encaps(self, alg, pk) -> tuple:
        time.sleep(self.kem_encaps_delay)
        ct = secrets.token_bytes(1088)
        ss = secrets.token_bytes(32)
        self._last_ss = ss
        return ct, ss
    
    def kem_decaps(self, alg, ct, sk) -> bytes:
        time.sleep(self.kem_decaps_delay)
        return getattr(self, '_last_ss', secrets.token_bytes(32))
    
    def sign_keygen(self, alg) -> tuple:
        time.sleep(self.sign_keygen_delay)
        return secrets.token_bytes(1952), secrets.token_bytes(4032)
    
    def sign(self, alg, msg, sk) -> bytes:
        time.sleep(self.sign_delay)
        return secrets.token_bytes(3309)
    
    def verify(self, alg, msg, sig, pk) -> bool:
        time.sleep(self.verify_delay)
        return True
    
    def random(self, length) -> bytes:
        time.sleep(self.random_delay * length / 32)
        return secrets.token_bytes(length)


def run_benchmark(name: str, iterations: int, warmup: int,
                  func: Callable, *args) -> BenchmarkResult:
    """Run a benchmark"""
    timer = Timer()
    
    # Warmup
    for _ in range(warmup):
        func(*args)
    
    # Timed runs
    for _ in range(iterations):
        timer.start()
        func(*args)
        timer.stop()
    
    stats = timer.get_stats()
    
    return BenchmarkResult(
        name=name,
        iterations=iterations,
        total_time_ms=stats["total_ms"],
        mean_time_us=stats["mean_us"],
        min_time_us=stats["min_us"],
        max_time_us=stats["max_us"],
        std_dev_us=stats["std_dev_us"],
        ops_per_sec=stats["ops_per_sec"]
    )


def print_result(result: BenchmarkResult):
    """Print benchmark result"""
    print(f"  {result.name}:")
    print(f"    Iterations:   {result.iterations}")
    print(f"    Total time:   {result.total_time_ms:.2f} ms")
    print(f"    Mean latency: {result.mean_time_us:.2f} µs")
    print(f"    Min latency:  {result.min_time_us:.2f} µs")
    print(f"    Max latency:  {result.max_time_us:.2f} µs")
    print(f"    Std dev:      {result.std_dev_us:.2f} µs")
    print(f"    Throughput:   {result.ops_per_sec:,.0f} ops/sec")
    print()


def run_kem_benchmarks(quac, iterations: int, warmup: int) -> List[BenchmarkResult]:
    """Run KEM benchmarks"""
    results = []
    
    print("ML-KEM-768 Benchmarks")
    print("-" * 40)
    
    # Keygen
    result = run_benchmark(
        "Keygen", iterations, warmup,
        lambda: quac.kem_keygen("ML_KEM_768")
    )
    print_result(result)
    results.append(result)
    
    # Setup for encaps/decaps
    pk, sk = quac.kem_keygen("ML_KEM_768")
    
    # Encaps
    result = run_benchmark(
        "Encaps", iterations, warmup,
        lambda: quac.kem_encaps("ML_KEM_768", pk)
    )
    print_result(result)
    results.append(result)
    
    # Setup for decaps
    ct, _ = quac.kem_encaps("ML_KEM_768", pk)
    
    # Decaps
    result = run_benchmark(
        "Decaps", iterations, warmup,
        lambda: quac.kem_decaps("ML_KEM_768", ct, sk)
    )
    print_result(result)
    results.append(result)
    
    return results


def run_sign_benchmarks(quac, iterations: int, warmup: int) -> List[BenchmarkResult]:
    """Run signature benchmarks"""
    results = []
    
    print("ML-DSA-65 Benchmarks")
    print("-" * 40)
    
    # Keygen
    result = run_benchmark(
        "Keygen", iterations, warmup,
        lambda: quac.sign_keygen("ML_DSA_65")
    )
    print_result(result)
    results.append(result)
    
    # Setup for sign/verify
    pk, sk = quac.sign_keygen("ML_DSA_65")
    message = b"Test message for benchmarking digital signatures"
    
    # Sign
    result = run_benchmark(
        "Sign", iterations, warmup,
        lambda: quac.sign("ML_DSA_65", message, sk)
    )
    print_result(result)
    results.append(result)
    
    # Setup for verify
    signature = quac.sign("ML_DSA_65", message, sk)
    
    # Verify
    result = run_benchmark(
        "Verify", iterations, warmup,
        lambda: quac.verify("ML_DSA_65", message, signature, pk)
    )
    print_result(result)
    results.append(result)
    
    return results


def run_random_benchmarks(quac, iterations: int, warmup: int) -> List[BenchmarkResult]:
    """Run random number generation benchmarks"""
    results = []
    
    print("QRNG Benchmarks")
    print("-" * 40)
    
    for size in [32, 256, 1024]:
        result = run_benchmark(
            f"Random {size}B", iterations, warmup,
            lambda s=size: quac.random(s)
        )
        print_result(result)
        results.append(result)
    
    return results


def main():
    parser = argparse.ArgumentParser(
        description="QUAC 100 Performance Benchmark"
    )
    parser.add_argument(
        "-i", "--iterations",
        type=int,
        default=100,
        help="Number of iterations (default: 100)"
    )
    parser.add_argument(
        "-w", "--warmup",
        type=int,
        default=10,
        help="Warmup iterations (default: 10)"
    )
    parser.add_argument(
        "-a", "--algorithm",
        choices=["kem", "sign", "random", "all"],
        default="all",
        help="Algorithm to benchmark (default: all)"
    )
    parser.add_argument(
        "-s", "--simulator",
        action="store_true",
        help="Force use of simulator"
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("  QUAC 100 Performance Benchmark")
    print("=" * 60)
    print()
    
    # Initialize
    if HAVE_QUAC and not args.simulator:
        try:
            quac = QUAC()
            print("Using QUAC 100 hardware accelerator.")
        except:
            quac = SimulatedQUAC()
            print("Hardware not available, using simulator.")
    else:
        quac = SimulatedQUAC()
        print("Using software simulator.")
    
    print(f"Iterations: {args.iterations}")
    print(f"Warmup: {args.warmup}")
    print()
    
    all_results = []
    
    # Run benchmarks
    if args.algorithm in ["kem", "all"]:
        all_results.extend(run_kem_benchmarks(quac, args.iterations, args.warmup))
    
    if args.algorithm in ["sign", "all"]:
        all_results.extend(run_sign_benchmarks(quac, args.iterations, args.warmup))
    
    if args.algorithm in ["random", "all"]:
        all_results.extend(run_random_benchmarks(quac, args.iterations, args.warmup))
    
    # Summary
    print("=" * 60)
    print("  Summary")
    print("=" * 60)
    print()
    print(f"{'Operation':<20} {'Mean (µs)':<12} {'Ops/sec':<15}")
    print("-" * 50)
    
    for result in all_results:
        print(f"{result.name:<20} {result.mean_time_us:<12.2f} {result.ops_per_sec:>13,.0f}")
    
    print()
    print("Note: Simulated timings approximate QUAC 100 hardware performance.")
    print("=" * 60)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())