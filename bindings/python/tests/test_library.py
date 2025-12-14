"""
Tests for library management functions - REQUIRES HARDWARE.
"""

import pytest

# Mark all tests in this module as requiring hardware
pytestmark = pytest.mark.hardware


class TestLibrary:
    """Test library initialization and management."""

    def test_version(self, initialize_library):
        import quantacore
        version = quantacore.get_version()
        assert isinstance(version, str)
        assert len(version) > 0

    def test_build_info(self, initialize_library):
        import quantacore
        build = quantacore.get_build_info()
        assert isinstance(build, str)

    def test_is_initialized(self, initialize_library):
        import quantacore
        assert quantacore.is_initialized() is True

    def test_device_count(self, initialize_library):
        import quantacore
        count = quantacore.get_device_count()
        assert isinstance(count, int)
        assert count >= 0

    def test_enumerate_devices(self, initialize_library):
        import quantacore
        devices = quantacore.enumerate_devices()
        assert isinstance(devices, list)