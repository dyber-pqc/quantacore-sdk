"""
Library management for QUAC 100 SDK.

This module provides functions for initializing and cleaning up the
QUAC 100 library, as well as device enumeration.
"""

import ctypes
from typing import List, Optional

from quantacore._native import get_library, DeviceInfoStruct
from quantacore.types import InitFlags, ErrorCode
from quantacore.exceptions import check_error, InitializationError
from quantacore.device import Device, DeviceInfo


_initialized = False


def initialize(flags: int = InitFlags.DEFAULT) -> None:
    """Initialize the QUAC 100 library.
    
    This must be called before any other SDK operations.
    
    Args:
        flags: Initialization flags (see InitFlags).
        
    Raises:
        InitializationError: If initialization fails.
        
    Example:
        >>> import quantacore
        >>> quantacore.initialize()
        >>> # ... use the library ...
        >>> quantacore.cleanup()
    """
    global _initialized
    
    if _initialized:
        return
    
    lib = get_library()
    result = lib.quac100_init(flags)
    
    if result != ErrorCode.SUCCESS:
        raise InitializationError(result, "Failed to initialize QUAC 100 library")
    
    _initialized = True


def cleanup() -> None:
    """Clean up the QUAC 100 library.
    
    This should be called when done using the library to release resources.
    
    Raises:
        QuacError: If cleanup fails.
    """
    global _initialized
    
    if not _initialized:
        return
    
    lib = get_library()
    result = lib.quac100_cleanup()
    check_error(result, "Failed to cleanup library")
    
    _initialized = False


def is_initialized() -> bool:
    """Check if the library is initialized.
    
    Returns:
        True if the library is initialized.
    """
    try:
        lib = get_library()
        return lib.quac100_is_initialized()
    except OSError:
        return False


def get_version() -> str:
    """Get the library version string.
    
    Returns:
        Version string (e.g., "1.0.0").
    """
    lib = get_library()
    result = lib.quac100_version()
    return result.decode("utf-8") if result else "unknown"


def get_build_info() -> str:
    """Get build information string.
    
    Returns:
        Build info including compiler, platform, and build date.
    """
    lib = get_library()
    result = lib.quac100_build_info()
    return result.decode("utf-8") if result else "unknown"


def get_device_count() -> int:
    """Get the number of available QUAC 100 devices.
    
    Returns:
        Number of devices found.
    """
    _ensure_initialized()
    lib = get_library()
    return lib.quac100_device_count()


def enumerate_devices() -> List[DeviceInfo]:
    """Enumerate all available QUAC 100 devices.
    
    Returns:
        List of DeviceInfo objects for each device.
        
    Example:
        >>> devices = quantacore.enumerate_devices()
        >>> for dev in devices:
        ...     print(f"Device {dev.index}: {dev.model}")
    """
    _ensure_initialized()
    lib = get_library()
    
    count = lib.quac100_device_count()
    devices = []
    
    # Get info for each device
    for i in range(count):
        info_struct = DeviceInfoStruct()
        if hasattr(lib, 'quac100_device_get_info_by_index'):
            result = lib.quac100_device_get_info_by_index(i, ctypes.byref(info_struct))
            if result == ErrorCode.SUCCESS:
                devices.append(DeviceInfo(
                    index=info_struct.index,
                    model=info_struct.model.decode("utf-8").rstrip('\x00'),
                    serial_number=info_struct.serial.decode("utf-8").rstrip('\x00'),
                    firmware_version=info_struct.firmware.decode("utf-8").rstrip('\x00'),
                    key_slots=info_struct.key_slots,
                ))
        else:
            # Fallback: create basic info
            devices.append(DeviceInfo(
                index=i,
                model="QUAC 100",
                serial_number=f"QUAC100-{i:05d}",
                firmware_version="1.0.0",
                key_slots=256,
            ))
    
    return devices


def open_device(index: int = 0, flags: int = InitFlags.DEFAULT) -> Device:
    """Open a QUAC 100 device.
    
    Args:
        index: Device index (0 for first device).
        flags: Device flags.
        
    Returns:
        Device instance.
        
    Raises:
        DeviceError: If the device cannot be opened.
        
    Example:
        >>> device = quantacore.open_device(0)
        >>> # ... use device ...
        >>> device.close()
    """
    _ensure_initialized()
    lib = get_library()
    
    handle = lib.quac100_device_open(index, flags)
    if not handle:
        from quantacore.exceptions import DeviceError
        raise DeviceError(ErrorCode.DEVICE_NOT_FOUND, f"Failed to open device {index}")
    
    return Device(handle, index)


def open_first_device(flags: int = InitFlags.DEFAULT) -> Device:
    """Open the first available QUAC 100 device.
    
    Args:
        flags: Device flags.
        
    Returns:
        Device instance.
        
    Raises:
        DeviceError: If no device is available.
    """
    return open_device(0, flags)


def _ensure_initialized() -> None:
    """Ensure the library is initialized."""
    if not _initialized:
        raise InitializationError(
            ErrorCode.NOT_INITIALIZED,
            "Library not initialized. Call quantacore.initialize() first."
        )


# Context manager for automatic initialization/cleanup
class LibraryContext:
    """Context manager for automatic library initialization and cleanup.
    
    Example:
        >>> with quantacore.LibraryContext() as lib:
        ...     device = quantacore.open_first_device()
        ...     # ... use device ...
        ...     device.close()
    """
    
    def __init__(self, flags: int = InitFlags.DEFAULT):
        self.flags = flags
    
    def __enter__(self) -> "LibraryContext":
        initialize(self.flags)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        cleanup()
        return False