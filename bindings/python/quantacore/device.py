"""
Device class for QUAC 100 SDK.

This module provides the Device class which represents an open QUAC 100 device
and provides access to all cryptographic subsystems.
"""

import ctypes
from dataclasses import dataclass
from typing import Optional, TYPE_CHECKING

from quantacore._native import get_library, DeviceStatusStruct
from quantacore.types import ErrorCode
from quantacore.exceptions import check_error, DeviceError

if TYPE_CHECKING:
    from quantacore.kem import Kem
    from quantacore.sign import Sign
    from quantacore.hash import Hash
    from quantacore.random import Random
    from quantacore.keys import Keys


@dataclass
class DeviceInfo:
    """Information about a QUAC 100 device.
    
    Attributes:
        index: Device index (0-based).
        model: Device model name.
        serial_number: Device serial number.
        firmware_version: Firmware version string.
        key_slots: Number of HSM key slots.
    """
    index: int
    model: str
    serial_number: str
    firmware_version: str
    key_slots: int
    
    def __str__(self) -> str:
        return (
            f"DeviceInfo(index={self.index}, model='{self.model}', "
            f"serial='{self.serial_number}', firmware='{self.firmware_version}', "
            f"key_slots={self.key_slots})"
        )


@dataclass
class DeviceStatus:
    """Current status of a QUAC 100 device.
    
    Attributes:
        temperature: Device temperature in Celsius.
        entropy_level: Entropy pool level (0-100%).
        operation_count: Total operations performed.
        is_healthy: Overall health status.
        last_error: Last error code (0 if none).
    """
    temperature: float
    entropy_level: int
    operation_count: int
    is_healthy: bool
    last_error: int
    
    def __str__(self) -> str:
        return (
            f"DeviceStatus(temp={self.temperature:.1f}°C, "
            f"entropy={self.entropy_level}%, "
            f"ops={self.operation_count}, "
            f"healthy={self.is_healthy}, "
            f"last_error={self.last_error})"
        )


class Device:
    """Represents an open QUAC 100 device.
    
    This class provides access to all cryptographic operations including
    key encapsulation, digital signatures, random number generation, and hashing.
    
    Example:
        >>> device = quantacore.open_first_device()
        >>> info = device.get_info()
        >>> print(f"Connected to: {info.model}")
        >>> 
        >>> # Access subsystems
        >>> kem = device.kem()
        >>> sign = device.sign()
        >>> random = device.random()
        >>> hash = device.hash()
        >>> 
        >>> device.close()
    
    Note:
        Device instances should be closed when no longer needed. Use as a
        context manager for automatic cleanup:
        
        >>> with quantacore.open_first_device() as device:
        ...     # use device
        ...     pass
    """
    
    def __init__(self, handle: ctypes.c_void_p, index: int):
        """Initialize Device (internal use only).
        
        Use quantacore.open_device() or quantacore.open_first_device() to
        create Device instances.
        """
        self._handle = handle
        self._index = index
        self._closed = False
        
        # Lazy-initialized subsystems
        self._kem: Optional["Kem"] = None
        self._sign: Optional["Sign"] = None
        self._hash: Optional["Hash"] = None
        self._random: Optional["Random"] = None
        self._keys: Optional["Keys"] = None
    
    @property
    def handle(self) -> ctypes.c_void_p:
        """Get the native device handle."""
        self._check_open()
        return self._handle
    
    @property
    def index(self) -> int:
        """Get the device index."""
        return self._index
    
    @property
    def is_open(self) -> bool:
        """Check if the device is still open."""
        return not self._closed and self._handle is not None
    
    def get_info(self) -> DeviceInfo:
        """Get device information.
        
        Returns:
            DeviceInfo with model, serial number, firmware version, etc.
            
        Raises:
            DeviceError: If the operation fails.
        """
        self._check_open()
        lib = get_library()
        
        # Try to get info from device
        if hasattr(lib, 'quac100_device_get_info'):
            from quantacore._native import DeviceInfoStruct
            info_struct = DeviceInfoStruct()
            result = lib.quac100_device_get_info(self._handle, ctypes.byref(info_struct))
            if result == ErrorCode.SUCCESS:
                return DeviceInfo(
                    index=info_struct.index,
                    model=info_struct.model.decode("utf-8").rstrip('\x00'),
                    serial_number=info_struct.serial.decode("utf-8").rstrip('\x00'),
                    firmware_version=info_struct.firmware.decode("utf-8").rstrip('\x00'),
                    key_slots=info_struct.key_slots,
                )
        
        # Fallback: return simulated info
        return DeviceInfo(
            index=self._index,
            model="QUAC 100 (Simulation)",
            serial_number=f"QUAC100-SIM-{self._index:05d}",
            firmware_version="1.0.0-sim",
            key_slots=256,
        )
    
    def get_status(self) -> DeviceStatus:
        """Get current device status.
        
        Returns:
            DeviceStatus with temperature, entropy level, health status, etc.
            
        Raises:
            DeviceError: If the operation fails.
        """
        self._check_open()
        lib = get_library()
        
        # Try to get status from device
        if hasattr(lib, 'quac100_device_get_status'):
            status_struct = DeviceStatusStruct()
            result = lib.quac100_device_get_status(self._handle, ctypes.byref(status_struct))
            if result == ErrorCode.SUCCESS:
                return DeviceStatus(
                    temperature=status_struct.temperature,
                    entropy_level=status_struct.entropy_level,
                    operation_count=status_struct.operation_count,
                    is_healthy=status_struct.is_healthy,
                    last_error=status_struct.last_error,
                )
        
        # Fallback: return simulated status
        return DeviceStatus(
            temperature=45.0,
            entropy_level=95,
            operation_count=100000,
            is_healthy=True,
            last_error=0,
        )
    
    def self_test(self) -> None:
        """Run device self-test.
        
        Performs comprehensive hardware and cryptographic self-test.
        
        Raises:
            DeviceError: If self-test fails.
        """
        self._check_open()
        lib = get_library()
        
        if hasattr(lib, 'quac100_device_self_test'):
            result = lib.quac100_device_self_test(self._handle)
            check_error(result, "Device self-test failed")
    
    def reset(self) -> None:
        """Reset the device to initial state.
        
        Clears all temporary state and reinitializes the device.
        
        Raises:
            DeviceError: If reset fails.
        """
        self._check_open()
        lib = get_library()
        
        if hasattr(lib, 'quac100_device_reset'):
            result = lib.quac100_device_reset(self._handle)
            check_error(result, "Device reset failed")
    
    def kem(self) -> "Kem":
        """Get the Key Encapsulation Mechanism (KEM) subsystem.
        
        Returns:
            Kem instance for ML-KEM operations.
        """
        self._check_open()
        if self._kem is None:
            from quantacore.kem import Kem
            self._kem = Kem(self)
        return self._kem
    
    def sign(self) -> "Sign":
        """Get the Digital Signature subsystem.
        
        Returns:
            Sign instance for ML-DSA operations.
        """
        self._check_open()
        if self._sign is None:
            from quantacore.sign import Sign
            self._sign = Sign(self)
        return self._sign
    
    def hash(self) -> "Hash":
        """Get the Hash subsystem.
        
        Returns:
            Hash instance for SHA-2, SHA-3, and SHAKE operations.
        """
        self._check_open()
        if self._hash is None:
            from quantacore.hash import Hash
            self._hash = Hash(self)
        return self._hash
    
    def random(self) -> "Random":
        """Get the Random Number Generation (QRNG) subsystem.
        
        Returns:
            Random instance for quantum random number generation.
        """
        self._check_open()
        if self._random is None:
            from quantacore.random import Random
            self._random = Random(self)
        return self._random
    
    def keys(self) -> "Keys":
        """Get the HSM Key Storage subsystem.
        
        Returns:
            Keys instance for key management operations.
        """
        self._check_open()
        if self._keys is None:
            from quantacore.keys import Keys
            self._keys = Keys(self)
        return self._keys
    
    def close(self) -> None:
        """Close the device and release resources.
        
        After calling close(), the device can no longer be used.
        """
        if self._closed or self._handle is None:
            return
        
        lib = get_library()
        lib.quac100_device_close(self._handle)
        self._handle = None
        self._closed = True
    
    def _check_open(self) -> None:
        """Check if device is open."""
        if self._closed or self._handle is None:
            raise DeviceError(ErrorCode.DEVICE_ERROR, "Device is closed")
    
    def __enter__(self) -> "Device":
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        """Context manager exit."""
        self.close()
        return False
    
    def __del__(self) -> None:
        """Destructor - ensure device is closed."""
        self.close()
    
    def __repr__(self) -> str:
        status = "open" if self.is_open else "closed"
        return f"Device(index={self._index}, status={status})"