# QUAC 100 Diagnostics Tool

Comprehensive hardware diagnostics and testing utility for the QUAC 100 post-quantum cryptographic accelerator.

## Features

- **Hardware Validation**: PCIe connectivity, register access, memory tests
- **Cryptographic Self-Tests**: Known Answer Tests (KAT) for all algorithms
- **Performance Tests**: Throughput and latency validation
- **Stress Testing**: Extended operation under load
- **QRNG Validation**: Entropy quality and statistical tests
- **Temperature Monitoring**: Thermal status and alerts
- **Report Generation**: Text, JSON, and HTML reports

## Building

```bash
cd tools/quac100-diag
mkdir build && cd build
cmake ..
cmake --build .
```

## Usage

```
quac100-diag [OPTIONS] [TEST...]

Options:
  -d, --device <index>    Select device by index (default: 0)
  -s, --simulator         Use software simulator
  -a, --all               Run all tests
  -q, --quick             Quick test suite (basic validation)
  -f, --full              Full test suite (comprehensive)
  -S, --stress            Stress test suite (extended)
  -l, --list-tests        List available tests
  -o, --output <file>     Output report to file
  -F, --format <fmt>      Report format: text, json, html
  -v, --verbose           Verbose output
  -c, --continuous        Run tests continuously
  -t, --timeout <sec>     Test timeout in seconds
  -h, --help              Show help
  -V, --version           Show version

Test Categories:
  hw                      Hardware tests
  kem                     KEM algorithm tests
  sign                    Signature algorithm tests
  random                  QRNG tests
  perf                    Performance tests
  stress                  Stress tests
```

## Test Categories

### Hardware Tests (`hw`)

| Test | Description |
|------|-------------|
| `hw.pcie` | PCIe link status and bandwidth |
| `hw.registers` | Register read/write validation |
| `hw.memory` | On-device memory test |
| `hw.dma` | DMA transfer test |
| `hw.interrupt` | Interrupt delivery test |
| `hw.temperature` | Temperature sensor validation |
| `hw.voltage` | Voltage rail monitoring |
| `hw.clock` | Clock frequency validation |

### KEM Tests (`kem`)

| Test | Description |
|------|-------------|
| `kem.mlkem512.kat` | ML-KEM-512 Known Answer Test |
| `kem.mlkem768.kat` | ML-KEM-768 Known Answer Test |
| `kem.mlkem1024.kat` | ML-KEM-1024 Known Answer Test |
| `kem.roundtrip` | Full KEM round-trip validation |
| `kem.invalid` | Invalid input handling |

### Signature Tests (`sign`)

| Test | Description |
|------|-------------|
| `sign.mldsa44.kat` | ML-DSA-44 Known Answer Test |
| `sign.mldsa65.kat` | ML-DSA-65 Known Answer Test |
| `sign.mldsa87.kat` | ML-DSA-87 Known Answer Test |
| `sign.slhdsa.kat` | SLH-DSA Known Answer Tests |
| `sign.roundtrip` | Full sign/verify round-trip |
| `sign.invalid` | Invalid signature detection |

### QRNG Tests (`random`)

| Test | Description |
|------|-------------|
| `random.basic` | Basic random generation |
| `random.monobit` | NIST SP 800-22 Monobit test |
| `random.runs` | NIST SP 800-22 Runs test |
| `random.entropy` | Min-entropy estimation |
| `random.repetition` | Repetition count test |
| `random.adaptive` | Adaptive proportion test |

### Performance Tests (`perf`)

| Test | Description |
|------|-------------|
| `perf.kem.throughput` | KEM throughput measurement |
| `perf.kem.latency` | KEM latency measurement |
| `perf.sign.throughput` | Signature throughput measurement |
| `perf.sign.latency` | Signature latency measurement |
| `perf.random.throughput` | QRNG throughput measurement |
| `perf.batch` | Batch operation efficiency |

### Stress Tests (`stress`)

| Test | Description |
|------|-------------|
| `stress.continuous` | Continuous operation (1 hour) |
| `stress.thermal` | Thermal stress test |
| `stress.memory` | Memory stress test |
| `stress.concurrent` | Concurrent operation test |

## Examples

### Run Quick Diagnostics

```bash
# Basic hardware check
quac100-diag -q

# Check specific device
quac100-diag -d 1 -q
```

### Run Full Test Suite

```bash
# Comprehensive testing
quac100-diag -f -o report.txt

# With JSON output
quac100-diag -f -F json -o report.json
```

### Run Specific Tests

```bash
# Hardware tests only
quac100-diag hw

# KEM Known Answer Tests
quac100-diag kem.mlkem768.kat

# All QRNG tests
quac100-diag random

# Multiple specific tests
quac100-diag hw.pcie kem.roundtrip random.entropy
```

### Stress Testing

```bash
# Run stress tests (long duration)
quac100-diag -S

# Continuous testing
quac100-diag -c stress.continuous

# With timeout
quac100-diag -t 3600 stress.thermal
```

### Generate Reports

```bash
# Text report
quac100-diag -a -o diagnostics.txt

# JSON report for automation
quac100-diag -a -F json -o diagnostics.json

# HTML report for documentation
quac100-diag -a -F html -o diagnostics.html
```

## Output Formats

### Text Format (Default)

```
QUAC 100 Diagnostics Report
===========================
Device: QUAC 100 PCIe
Serial: QC100-2025-00001
Date:   2025-01-15 10:30:00

Test Results
------------
[PASS] hw.pcie          PCIe Gen4 x4, 8 GT/s
[PASS] hw.registers     All registers accessible
[PASS] kem.mlkem768.kat Known answers verified
[FAIL] random.entropy   Min-entropy below threshold

Summary: 45/46 tests passed
```

### JSON Format

```json
{
  "device": {
    "name": "QUAC 100 PCIe",
    "serial": "QC100-2025-00001"
  },
  "timestamp": "2025-01-15T10:30:00Z",
  "results": [
    {
      "test": "hw.pcie",
      "status": "pass",
      "message": "PCIe Gen4 x4, 8 GT/s",
      "duration_ms": 50
    }
  ],
  "summary": {
    "total": 46,
    "passed": 45,
    "failed": 1,
    "skipped": 0
  }
}
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All tests passed |
| 1 | One or more tests failed |
| 2 | Invalid arguments |
| 3 | Device not found |
| 4 | Hardware error |
| 5 | Timeout |

## FIPS 140-3 Compliance

The diagnostics tool supports FIPS 140-3 compliance testing:

- **Power-On Self-Tests (POST)**: Run automatically on device initialization
- **Conditional Self-Tests**: Triggered by specific operations
- **Known Answer Tests (KAT)**: Verify algorithm correctness
- **Continuous Tests**: Monitor QRNG health

For FIPS compliance documentation, generate a report with:

```bash
quac100-diag -f -F json -o fips_compliance.json kem sign random
```

## Troubleshooting

### Device Not Found

```bash
# List available devices
quac100-diag --list-devices

# Use simulator for testing
quac100-diag -s -q
```

### Test Failures

1. Check device temperature: `quac100-diag hw.temperature`
2. Verify PCIe connection: `quac100-diag hw.pcie`
3. Run isolated test: `quac100-diag -v <test_name>`
4. Check firmware version: `quac100-diag hw.registers`

### Performance Issues

1. Ensure PCIe Gen4 link: `quac100-diag hw.pcie`
2. Check thermal throttling: `quac100-diag hw.temperature`
3. Run performance baseline: `quac100-diag perf`

## License

Copyright 2025 Dyber, Inc. All Rights Reserved.