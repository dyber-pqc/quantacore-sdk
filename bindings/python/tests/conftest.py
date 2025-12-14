"""
Pytest configuration and fixtures for QUAC 100 Python SDK tests.
"""

import pytest


# Mark for tests that require hardware
def pytest_configure(config):
    config.addinivalue_line(
        "markers", "hardware: mark test as requiring QUAC 100 hardware"
    )


@pytest.fixture(scope="session")
def initialize_library():
    """Initialize the QUAC 100 library for hardware tests only."""
    import quantacore
    
    quantacore.initialize()
    yield
    quantacore.cleanup()


@pytest.fixture
def device(initialize_library):
    """Open a device for testing (requires hardware)."""
    import quantacore
    
    device = quantacore.open_first_device()
    yield device
    device.close()


@pytest.fixture
def kem(device):
    """Get KEM subsystem."""
    return device.kem()


@pytest.fixture
def sign(device):
    """Get signature subsystem."""
    return device.sign()


@pytest.fixture
def hash_obj(device):
    """Get hash subsystem."""
    return device.hash()


@pytest.fixture
def random(device):
    """Get random subsystem."""
    return device.random()