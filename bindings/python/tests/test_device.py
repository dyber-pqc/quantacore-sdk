"""
Tests for device operations - REQUIRES HARDWARE.
"""

import pytest

# Mark all tests in this module as requiring hardware
pytestmark = pytest.mark.hardware


class TestDevice:
    """Test device operations."""

    def test_get_info(self, device):
        info = device.get_info()
        assert hasattr(info, 'model')
        assert hasattr(info, 'serial_number')
        assert hasattr(info, 'firmware_version')
        assert hasattr(info, 'driver_version')
        assert hasattr(info, 'key_slots')

    def test_get_status(self, device):
        status = device.get_status()
        assert hasattr(status, 'temperature')
        assert hasattr(status, 'entropy_level')
        assert hasattr(status, 'is_healthy')
        assert hasattr(status, 'operation_count')

    def test_status_values(self, device):
        status = device.get_status()
        assert isinstance(status.temperature, (int, float))
        assert 0 <= status.entropy_level <= 100
        assert isinstance(status.is_healthy, bool)
        assert isinstance(status.operation_count, int)

    def test_self_test(self, device):
        # Should not raise if hardware is working
        device.self_test()

    def test_subsystem_access(self, device):
        """Test that all subsystems are accessible."""
        kem = device.kem()
        assert kem is not None

        sign = device.sign()
        assert sign is not None

        hash_obj = device.hash()
        assert hash_obj is not None

        random = device.random()
        assert random is not None

        keys = device.keys()
        assert keys is not None


class TestDeviceInfo:
    """Test DeviceInfo dataclass."""

    def test_repr(self, device):
        info = device.get_info()
        r = repr(info)
        assert 'DeviceInfo' in r

    def test_model_not_empty(self, device):
        info = device.get_info()
        assert len(info.model) > 0

    def test_serial_not_empty(self, device):
        info = device.get_info()
        assert len(info.serial_number) > 0


class TestDeviceStatus:
    """Test DeviceStatus dataclass."""

    def test_repr(self, device):
        status = device.get_status()
        r = repr(status)
        assert 'DeviceStatus' in r

    def test_healthy_device(self, device):
        status = device.get_status()
        # A working device should generally be healthy
        assert status.is_healthy is True


class TestDeviceContextManager:
    """Test device as context manager."""

    def test_context_manager(self, initialize_library):
        import quantacore

        with quantacore.open_first_device() as dev:
            info = dev.get_info()
            assert info is not None
        # Device should be closed after context


class TestLibraryContext:
    """Test LibraryContext context manager."""

    def test_library_context(self):
        import quantacore

        with quantacore.LibraryContext() as ctx:
            assert quantacore.is_initialized() is True
        # Library should be cleaned up after context


class TestMultipleDevices:
    """Test multiple device handling."""

    def test_device_count(self, initialize_library):
        import quantacore

        count = quantacore.get_device_count()
        assert count >= 1  # At least one device for these tests

    def test_enumerate_devices(self, initialize_library):
        import quantacore

        devices = quantacore.enumerate_devices()
        assert len(devices) >= 1

    def test_open_by_index(self, initialize_library):
        import quantacore

        device = quantacore.open_device(0)
        assert device is not None
        device.close()