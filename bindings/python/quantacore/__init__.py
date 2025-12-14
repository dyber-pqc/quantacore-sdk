"""
QUAC 100 Python SDK

Python bindings for the QUAC 100 Post-Quantum Cryptographic Accelerator.

Example:
    >>> import quantacore
    >>> quantacore.initialize()
    >>> device = quantacore.open_device()
    >>> 
    >>> # ML-KEM key exchange
    >>> kem = device.kem()
    >>> keypair = kem.generate_keypair(quantacore.KemAlgorithm.ML_KEM_768)
    >>> encap = kem.encapsulate(keypair.public_key)
    >>> shared_secret = kem.decapsulate(keypair.secret_key, encap.ciphertext)
    >>> 
    >>> device.close()
    >>> quantacore.cleanup()

Copyright © 2025 Dyber, Inc. All Rights Reserved.
"""

__version__ = "1.0.1"
__author__ = "Dyber, Inc."
__email__ = "support@dyber.org"
__license__ = "Proprietary"

# Core classes
from quantacore.library import (
    initialize,
    cleanup,
    is_initialized,
    get_version,
    get_build_info,
    get_device_count,
    enumerate_devices,
    open_device,
    open_first_device,
)
from quantacore.device import Device, DeviceInfo, DeviceStatus
from quantacore.kem import Kem, KemAlgorithm, KeyPair, EncapsulationResult
from quantacore.sign import Sign, SignAlgorithm
from quantacore.hash import Hash, HashAlgorithm, HashContext
from quantacore.random import Random, EntropyStatus
from quantacore.keys import Keys, KeyInfo, KeyType, KeyUsage

# Exceptions
from quantacore.exceptions import (
    QuacError,
    DeviceError,
    CryptoError,
    VerificationError,
    InitializationError,
    InvalidParameterError,
    NotFoundError,
)

# Utilities
from quantacore.utils import (
    to_hex,
    from_hex,
    to_base64,
    from_base64,
    to_base64url,
    from_base64url,
    secure_zero,
    secure_compare,
)

# Type definitions
from quantacore.types import ErrorCode, InitFlags

__all__ = [
    # Version info
    "__version__",
    "__author__",
    "__email__",
    
    # Library functions
    "initialize",
    "cleanup",
    "is_initialized",
    "get_version",
    "get_build_info",
    "get_device_count",
    "enumerate_devices",
    "open_device",
    "open_first_device",
    
    # Classes
    "Device",
    "DeviceInfo",
    "DeviceStatus",
    "Kem",
    "KemAlgorithm",
    "KeyPair",
    "EncapsulationResult",
    "Sign",
    "SignAlgorithm",
    "Hash",
    "HashAlgorithm",
    "HashContext",
    "Random",
    "EntropyStatus",
    "Keys",
    "KeyInfo",
    "KeyType",
    "KeyUsage",
    
    # Exceptions
    "QuacError",
    "DeviceError",
    "CryptoError",
    "VerificationError",
    "InitializationError",
    "InvalidParameterError",
    "NotFoundError",
    
    # Utilities
    "to_hex",
    "from_hex",
    "to_base64",
    "from_base64",
    "to_base64url",
    "from_base64url",
    "secure_zero",
    "secure_compare",
    
    # Types
    "ErrorCode",
    "InitFlags",
]
