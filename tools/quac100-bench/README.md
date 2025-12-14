# QUAC 100 Benchmark Tool (quac100-bench)

A comprehensive benchmarking tool for the QUAC 100 post-quantum cryptographic accelerator. Measures performance across all supported algorithms, operations, and configurations.

## Features

- **Algorithm Benchmarks**: ML-KEM (512/768/1024), ML-DSA (44/65/87), SLH-DSA
- **Operation Profiling**: Keygen, encaps/decaps, sign/verify, random generation
- **Throughput Testing**: Single-threaded and multi-threaded performance
- **Latency Analysis**: Min/max/mean/median/percentile statistics
- **Batch Performance**: Batch processing efficiency and scaling
- **Comparison Mode**: Hardware vs. software implementation comparison
- **Export Formats**: JSON, CSV, Markdown for integration with analysis tools

## Usage

```bash
# Run full benchmark suite
quac100-bench

# Benchmark specific algorithm
quac100-bench --algorithm ml-kem-768

# Benchmark specific operation
quac100-bench --operation keygen

# Multi-threaded benchmark
quac100-bench --threads 8

# Quick benchmark (fewer iterations)
quac100-bench --quick

# Extended benchmark (more iterations, better statistics)
quac100-bench --extended

# Export results to JSON
quac100-bench --output results.json --format json

# Compare hardware vs software
quac100-bench --compare

# Specify device
quac100-bench --device 0
```

## Command Line Options

```
quac100-bench [OPTIONS]

Device Selection:
  -d, --device <INDEX>     Device index (default: 0)
  -s, --simulator          Use software simulator

Algorithm Selection:
  -a, --algorithm <ALG>    Specific algorithm to benchmark:
                           ml-kem-512, ml-kem-768, ml-kem-1024
                           ml-dsa-44, ml-dsa-65, ml-dsa-87
                           slh-dsa-128f, slh-dsa-128s, etc.
                           random, all (default: all)

Operation Selection:
  -o, --operation <OP>     Specific operation:
                           keygen, encaps, decaps, sign, verify
                           random, batch, all (default: all)

Benchmark Parameters:
  -i, --iterations <N>     Number of iterations (default: 1000)
  -w, --warmup <N>         Warmup iterations (default: 100)
  -t, --threads <N>        Number of threads (default: 1)
  -b, --batch-size <N>     Batch size for batch tests (default: 64)
  --quick                  Quick benchmark (100 iterations)
  --extended               Extended benchmark (10000 iterations)

Output Options:
  -O, --output <FILE>      Output file path
  -f, --format <FMT>       Output format: text, json, csv, markdown
  -v, --verbose            Verbose output
  -q, --quiet              Suppress progress output

Comparison:
  --compare                Compare hardware vs software implementation
  --baseline <FILE>        Load baseline results for comparison

Misc:
  --list-devices           List available devices
  --list-algorithms        List supported algorithms
  --version                Show version information
  -h, --help               Show this help message
```

## Benchmark Types

### Single Operation Latency
Measures the time for individual cryptographic operations:
- Key generation
- Encapsulation/Decapsulation
- Signing/Verification
- Random number generation

### Throughput
Measures operations per second under sustained load:
- Single-threaded throughput
- Multi-threaded scaling
- Maximum sustainable throughput

### Batch Processing
Measures efficiency of batch operations:
- Batch vs. individual operation comparison
- Optimal batch size determination
- Batch throughput scaling

### Statistical Analysis
For each benchmark, provides:
- Minimum, maximum, mean latency
- Median and standard deviation
- 95th/99th percentile latency
- Operations per second

## Output Formats

### Text (Default)
```
QUAC 100 Benchmark Results
==========================

Device: QUAC 100 PCIe (serial: ABC123)
Date: 2025-01-15 14:30:00

ML-KEM-768 Key Generation
-------------------------
Iterations: 1000
Latency (μs):
  Min:      45.2
  Max:      128.4
  Mean:     52.3
  Median:   50.1
  Std Dev:  8.7
  P95:      68.2
  P99:      95.4
Throughput: 19,120 ops/sec
```

### JSON
```json
{
  "device": {
    "name": "QUAC 100 PCIe",
    "serial": "ABC123"
  },
  "timestamp": "2025-01-15T14:30:00Z",
  "results": [
    {
      "algorithm": "ML-KEM-768",
      "operation": "keygen",
      "iterations": 1000,
      "latency_us": {
        "min": 45.2,
        "max": 128.4,
        "mean": 52.3,
        "median": 50.1,
        "stddev": 8.7,
        "p95": 68.2,
        "p99": 95.4
      },
      "throughput_ops": 19120
    }
  ]
}
```

### CSV
```csv
algorithm,operation,iterations,min_us,max_us,mean_us,median_us,stddev_us,p95_us,p99_us,throughput
ML-KEM-768,keygen,1000,45.2,128.4,52.3,50.1,8.7,68.2,95.4,19120
```

### Markdown
```markdown
| Algorithm | Operation | Iterations | Mean (μs) | P99 (μs) | Throughput |
|-----------|-----------|------------|-----------|----------|------------|
| ML-KEM-768 | keygen | 1000 | 52.3 | 95.4 | 19,120 ops/s |
```

## Performance Targets

| Algorithm | Operation | Target Latency | Target Throughput |
|-----------|-----------|----------------|-------------------|
| ML-KEM-768 | Keygen | < 100 μs | > 10,000 ops/s |
| ML-KEM-768 | Encaps | < 50 μs | > 20,000 ops/s |
| ML-KEM-768 | Decaps | < 50 μs | > 20,000 ops/s |
| ML-DSA-65 | Sign | < 200 μs | > 5,000 ops/s |
| ML-DSA-65 | Verify | < 100 μs | > 10,000 ops/s |
| QRNG | 32 bytes | < 10 μs | > 100,000 ops/s |

## Building

```bash
cd tools/quac100-bench
mkdir build && cd build
cmake ..
make
```

## Architecture

```
quac100-bench/
├── src/
│   ├── main.c              # Entry point, argument parsing
│   ├── benchmark.c         # Benchmark execution engine
│   ├── benchmark.h
│   ├── stats.c             # Statistical calculations
│   ├── stats.h
│   ├── output.c            # Output formatting
│   ├── output.h
│   └── config.h            # Configuration and defaults
├── CMakeLists.txt
└── README.md
```

## Example Results

```
$ quac100-bench --algorithm ml-kem-768 --iterations 10000

QUAC 100 Benchmark Tool v1.0.0
==============================

Initializing...
Device: QUAC 100 PCIe [0000:03:00.0]
Serial: QUAC-2025-001234

Running ML-KEM-768 benchmarks...

Key Generation:
  Warmup: 100 iterations
  Benchmark: 10000 iterations
  Progress: [####################] 100%
  
  Results:
    Min:      44.8 μs
    Max:      156.2 μs
    Mean:     51.2 μs
    Median:   49.5 μs
    Std Dev:  9.3 μs
    P95:      65.8 μs
    P99:      89.2 μs
    Throughput: 19,531 ops/sec

Encapsulation:
  ...

Decapsulation:
  ...

Summary:
  Total time: 45.2 seconds
  Operations: 30000
  Overall throughput: 663 ops/sec (combined)
```

## Integration

The benchmark tool can be integrated into CI/CD pipelines:

```bash
# Run benchmark and fail if below threshold
quac100-bench --algorithm ml-kem-768 --format json | \
  jq '.results[0].throughput_ops > 10000' | grep -q true
```

## License

Copyright 2025 Dyber, Inc. All Rights Reserved.
Proprietary and confidential.