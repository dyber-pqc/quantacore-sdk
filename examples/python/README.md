# QUAC 100 Python Examples

Python bindings and examples for the QUAC 100 post-quantum cryptographic accelerator.

## Requirements

- Python 3.8+
- QUAC 100 SDK installed
- quac100 Python package

## Installation

```bash
pip install quac100
# Or from source:
cd bindings/python
pip install -e .
```

## Examples

| File | Description |
|------|-------------|
| `hello_quac.py` | Basic initialization and random generation |
| `kem_demo.py` | ML-KEM key exchange demonstration |
| `sign_demo.py` | ML-DSA digital signature demonstration |
| `hybrid_crypto.py` | Hybrid classical/PQC encryption |
| `async_operations.py` | Asynchronous batch operations |
| `benchmark.py` | Performance benchmarking script |

## Quick Start

```python
from quac100 import QUAC, Algorithm

# Initialize
quac = QUAC()

# Generate random bytes
random_data = quac.random(32)
print(f"Random: {random_data.hex()}")

# ML-KEM key exchange
pk, sk = quac.kem_keygen(Algorithm.ML_KEM_768)
ct, ss_sender = quac.kem_encaps(Algorithm.ML_KEM_768, pk)
ss_receiver = quac.kem_decaps(Algorithm.ML_KEM_768, ct, sk)
assert ss_sender == ss_receiver
```

## Running Examples

```bash
python hello_quac.py
python kem_demo.py
python sign_demo.py
python benchmark.py
```

## License

Copyright 2025 Dyber, Inc. All Rights Reserved.