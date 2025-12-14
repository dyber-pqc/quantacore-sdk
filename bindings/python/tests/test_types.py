"""
Type definitions for QUAC 100 SDK.

This module contains enums, type aliases, and dataclasses used throughout
the SDK.
"""

from enum import IntEnum, IntFlag
from dataclasses import dataclass
from typing import Optional


class ErrorCode(IntEnum):
    """Error codes returned by QUAC 100 operations."""
    
    SUCCESS = 0
    ERROR = -1
    INVALID_PARAM = -2
    BUFFER_SMALL = -3
    DEVICE_NOT_FOUND = -4
    DEVICE_BUSY = -5
    DEVICE_ERROR = -6
    OUT_OF_MEMORY = -7
    NOT_SUPPORTED = -8
    AUTH_REQUIRED = -9
    AUTH_FAILED = -10
    KEY_NOT_FOUND = -11
    INVALID_KEY = -12
    VERIFICATION_FAILED = -13
    DECAPS_FAILED = -14
    HARDWARE_UNAVAIL = -15
    TIMEOUT = -16
    NOT_INITIALIZED = -17
    ALREADY_INIT = -18
    INVALID_HANDLE = -19
    CANCELLED = -20
    ENTROPY_DEPLETED = -21
    SELF_TEST_FAILED = -22
    TAMPER_DETECTED = -23
    TEMPERATURE = -24
    POWER = -25
    INVALID_ALGORITHM = -26
    CRYPTO_ERROR = -27
    INTERNAL_ERROR = -99

    @classmethod
    def get_message(cls, code: int) -> str:
        """Get human-readable message for error code."""
        messages = {
            cls.SUCCESS: "Operation completed successfully",
            cls.ERROR: "Generic error",
            cls.INVALID_PARAM: "Invalid parameter",
            cls.BUFFER_SMALL: "Output buffer too small",
            cls.DEVICE_NOT_FOUND: "No QUAC 100 device found",
            cls.DEVICE_BUSY: "Device is busy",
            cls.DEVICE_ERROR: "Device error",
            cls.OUT_OF_MEMORY: "Memory allocation failed",
            cls.NOT_SUPPORTED: "Operation not supported",
            cls.AUTH_REQUIRED: "Authentication required",
            cls.AUTH_FAILED: "Authentication failed",
            cls.KEY_NOT_FOUND: "Key not found",
            cls.INVALID_KEY: "Invalid key",
            cls.VERIFICATION_FAILED: "Signature verification failed",
            cls.DECAPS_FAILED: "Decapsulation failed",
            cls.HARDWARE_UNAVAIL: "Hardware acceleration unavailable",
            cls.TIMEOUT: "Operation timed out",
            cls.NOT_INITIALIZED: "Library not initialized",
            cls.ALREADY_INIT: "Library already initialized",
            cls.INVALID_HANDLE: "Invalid handle",
            cls.CANCELLED: "Operation cancelled",
            cls.ENTROPY_DEPLETED: "Entropy pool depleted",
            cls.SELF_TEST_FAILED: "Self-test failed",
            cls.TAMPER_DETECTED: "Tamper detected",
            cls.TEMPERATURE: "Temperature error",
            cls.POWER: "Power supply error",
            cls.INVALID_ALGORITHM: "Invalid algorithm",
            cls.CRYPTO_ERROR: "Cryptographic operation error",
            cls.INTERNAL_ERROR: "Internal error",
        }
        return messages.get(code, f"Unknown error ({code})")


class InitFlags(IntFlag):
    """Initialization flags for the QUAC 100 library."""
    
    DEFAULT = 0x0F
    HARDWARE_ACCEL = 0x01
    SIDE_CHANNEL_PROTECT = 0x02
    CONSTANT_TIME = 0x04
    AUTO_ZEROIZE = 0x08
    FIPS_MODE = 0x10
    DEBUG = 0x20
    SOFTWARE_FALLBACK = 0x40


class KemAlgorithm(IntEnum):
    """Key Encapsulation Mechanism algorithms."""
    
    ML_KEM_512 = 0   # 128-bit security
    ML_KEM_768 = 1   # 192-bit security  
    ML_KEM_1024 = 2  # 256-bit security
    
    # Aliases for NIST naming
    KYBER_512 = 0
    KYBER_768 = 1
    KYBER_1024 = 2

    @property
    def public_key_size(self) -> int:
        """Get public key size in bytes."""
        sizes = {0: 800, 1: 1184, 2: 1568}
        return sizes[self.value]
    
    @property
    def secret_key_size(self) -> int:
        """Get secret key size in bytes."""
        sizes = {0: 1632, 1: 2400, 2: 3168}
        return sizes[self.value]
    
    @property
    def ciphertext_size(self) -> int:
        """Get ciphertext size in bytes."""
        sizes = {0: 768, 1: 1088, 2: 1568}
        return sizes[self.value]
    
    @property
    def shared_secret_size(self) -> int:
        """Get shared secret size in bytes."""
        return 32


class SignAlgorithm(IntEnum):
    """Digital Signature algorithms."""
    
    ML_DSA_44 = 0   # 128-bit security
    ML_DSA_65 = 1   # 192-bit security
    ML_DSA_87 = 2   # 256-bit security
    
    # Aliases for NIST naming
    DILITHIUM_2 = 0
    DILITHIUM_3 = 1
    DILITHIUM_5 = 2

    @property
    def public_key_size(self) -> int:
        """Get public key size in bytes."""
        sizes = {0: 1312, 1: 1952, 2: 2592}
        return sizes[self.value]
    
    @property
    def secret_key_size(self) -> int:
        """Get secret key size in bytes."""
        sizes = {0: 2560, 1: 4032, 2: 4896}
        return sizes[self.value]
    
    @property
    def signature_size(self) -> int:
        """Get maximum signature size in bytes."""
        sizes = {0: 2420, 1: 3309, 2: 4627}
        return sizes[self.value]


class HashAlgorithm(IntEnum):
    """Hash algorithms."""
    
    SHA256 = 0
    SHA384 = 1
    SHA512 = 2
    SHA3_256 = 3
    SHA3_384 = 4
    SHA3_512 = 5
    SHAKE128 = 6
    SHAKE256 = 7

    @property
    def digest_size(self) -> Optional[int]:
        """Get digest size in bytes (None for SHAKE)."""
        sizes = {
            0: 32,   # SHA256
            1: 48,   # SHA384
            2: 64,   # SHA512
            3: 32,   # SHA3-256
            4: 48,   # SHA3-384
            5: 64,   # SHA3-512
            6: None, # SHAKE128 (variable)
            7: None, # SHAKE256 (variable)
        }
        return sizes[self.value]


class KeyType(IntEnum):
    """Key types for HSM storage."""
    
    SECRET = 0      # Symmetric key
    PUBLIC = 1      # Public key only
    PRIVATE = 2     # Private key only
    KEY_PAIR = 3    # Full key pair


class KeyUsage(IntFlag):
    """Key usage flags."""
    
    ENCRYPT = 0x01
    DECRYPT = 0x02
    SIGN = 0x04
    VERIFY = 0x08
    DERIVE = 0x10
    WRAP = 0x20
    UNWRAP = 0x40
    
    # Common combinations
    ENCRYPTION = ENCRYPT | DECRYPT
    SIGNING = SIGN | VERIFY
    KEY_EXCHANGE = DERIVE
    ALL = ENCRYPT | DECRYPT | SIGN | VERIFY | DERIVE | WRAP | UNWRAP