"""
QUAC 100 Python SDK Test Suite

Tests are organized into two categories:
- Pure Python tests (no hardware required): test_utils, test_types, test_exceptions
- Hardware tests (require QUAC 100 device): test_device, test_kem, test_sign, test_hash, test_random, test_library

Run pure Python tests only:
    pytest tests/ -v -m "not hardware"

Run all tests (requires hardware):
    pytest tests/ -v
"""