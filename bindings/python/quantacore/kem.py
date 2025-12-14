"""
Key Encapsulation Mechanism (KEM) operations for QUAC 100 SDK.

This module provides ML-KEM (Kyber) key encapsulation operations.
"""

import ctypes
from dataclasses import dataclass
from typing import TYPE_CHECKING, Union

from quantacore._native import get_library
from quantacore.types import KemAlgorithm, ErrorCode
from quantacore.exceptions import check_error, CryptoError
from quantacore.utils import secure_zero

if TYPE_CHECKING:
    from quantacore.device import Device


@dataclass
class KeyPair:
    """A cryptographic key pair (public key + secret key).
    
    Attributes:
        public_key: The public key bytes.
        secret_key: The secret key bytes.
        algorithm: The KEM algorithm used.
    
    Note:
        Call close() or use as context manager to securely clear the secret key.
    """
    public_key: bytes
    secret_key: bytes
    algorithm: KemAlgorithm
    _closed: bool = False
    
    def close(self) -> None:
        """Securely clear the secret key material."""
        if not self._closed and self.secret_key:
            # Create mutable bytearray and zero it
            sk = bytearray(self.secret_key)
            secure_zero(sk)
            self.secret_key = bytes(sk)
            self._closed = True
    
    def __enter__(self) -> "KeyPair":
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        self.close()
        return False
    
    def __del__(self) -> None:
        self.close()
    
    @property
    def public_key_size(self) -> int:
        """Get the public key size in bytes."""
        return len(self.public_key)
    
    @property
    def secret_key_size(self) -> int:
        """Get the secret key size in bytes."""
        return len(self.secret_key)
    
    def __repr__(self) -> str:
        return (
            f"KeyPair(algorithm={self.algorithm.name}, "
            f"pk={self.public_key_size} bytes, "
            f"sk={self.secret_key_size} bytes)"
        )


@dataclass
class EncapsulationResult:
    """Result of a KEM encapsulation operation.
    
    Attributes:
        ciphertext: The encapsulated ciphertext (send to recipient).
        shared_secret: The derived shared secret (use for encryption).
    
    Note:
        Call close() or use as context manager to securely clear the shared secret.
    """
    ciphertext: bytes
    shared_secret: bytes
    _closed: bool = False
    
    def close(self) -> None:
        """Securely clear the shared secret."""
        if not self._closed and self.shared_secret:
            ss = bytearray(self.shared_secret)
            secure_zero(ss)
            self.shared_secret = bytes(ss)
            self._closed = True
    
    def __enter__(self) -> "EncapsulationResult":
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        self.close()
        return False
    
    def __del__(self) -> None:
        self.close()
    
    @property
    def ciphertext_size(self) -> int:
        """Get the ciphertext size in bytes."""
        return len(self.ciphertext)
    
    @property
    def shared_secret_size(self) -> int:
        """Get the shared secret size in bytes."""
        return len(self.shared_secret)
    
    def __repr__(self) -> str:
        return (
            f"EncapsulationResult(ciphertext={self.ciphertext_size} bytes, "
            f"shared_secret={self.shared_secret_size} bytes)"
        )


class Kem:
    """Key Encapsulation Mechanism (ML-KEM/Kyber) operations.
    
    This class provides post-quantum key encapsulation using ML-KEM
    (formerly known as CRYSTALS-Kyber).
    
    Example:
        >>> kem = device.kem()
        >>> 
        >>> # Generate key pair
        >>> with kem.generate_keypair(KemAlgorithm.ML_KEM_768) as kp:
        ...     # Encapsulate (sender side)
        ...     with kem.encapsulate(kp.public_key, KemAlgorithm.ML_KEM_768) as encap:
        ...         ciphertext = encap.ciphertext
        ...         sender_secret = encap.shared_secret
        ...         
        ...         # Decapsulate (recipient side)
        ...         recipient_secret = kem.decapsulate(
        ...             kp.secret_key, ciphertext, KemAlgorithm.ML_KEM_768)
        ...         
        ...         assert sender_secret == recipient_secret
    """
    
    def __init__(self, device: "Device"):
        """Initialize KEM subsystem.
        
        Args:
            device: Parent device instance.
        """
        self._device = device
    
    def generate_keypair(
        self, 
        algorithm: KemAlgorithm = KemAlgorithm.ML_KEM_768
    ) -> KeyPair:
        """Generate a new KEM key pair.
        
        Args:
            algorithm: KEM algorithm to use.
            
        Returns:
            KeyPair containing public and secret keys.
            
        Raises:
            CryptoError: If key generation fails.
        """
        lib = get_library()
        
        # Allocate output buffers
        pk_size = ctypes.c_size_t(algorithm.public_key_size)
        sk_size = ctypes.c_size_t(algorithm.secret_key_size)
        pk_buf = (ctypes.c_uint8 * algorithm.public_key_size)()
        sk_buf = (ctypes.c_uint8 * algorithm.secret_key_size)()
        
        result = lib.quac100_kem_keygen(
            self._device.handle,
            algorithm.value,
            pk_buf,
            ctypes.byref(pk_size),
            sk_buf,
            ctypes.byref(sk_size),
        )
        
        check_error(result, "KEM key generation failed")
        
        return KeyPair(
            public_key=bytes(pk_buf[:pk_size.value]),
            secret_key=bytes(sk_buf[:sk_size.value]),
            algorithm=algorithm,
        )
    
    def encapsulate(
        self,
        public_key: bytes,
        algorithm: KemAlgorithm = KemAlgorithm.ML_KEM_768,
    ) -> EncapsulationResult:
        """Encapsulate a shared secret using a public key.
        
        This is the sender's operation in a key exchange.
        
        Args:
            public_key: Recipient's public key.
            algorithm: KEM algorithm to use.
            
        Returns:
            EncapsulationResult containing ciphertext and shared secret.
            
        Raises:
            CryptoError: If encapsulation fails.
        """
        lib = get_library()
        
        # Allocate output buffers
        ct_size = ctypes.c_size_t(algorithm.ciphertext_size)
        ss_size = ctypes.c_size_t(algorithm.shared_secret_size)
        ct_buf = (ctypes.c_uint8 * algorithm.ciphertext_size)()
        ss_buf = (ctypes.c_uint8 * algorithm.shared_secret_size)()
        
        # Convert public key to ctypes array
        pk_buf = (ctypes.c_uint8 * len(public_key))(*public_key)
        
        result = lib.quac100_kem_encaps(
            self._device.handle,
            algorithm.value,
            pk_buf,
            len(public_key),
            ct_buf,
            ctypes.byref(ct_size),
            ss_buf,
            ctypes.byref(ss_size),
        )
        
        check_error(result, "KEM encapsulation failed")
        
        return EncapsulationResult(
            ciphertext=bytes(ct_buf[:ct_size.value]),
            shared_secret=bytes(ss_buf[:ss_size.value]),
        )
    
    def decapsulate(
        self,
        secret_key: bytes,
        ciphertext: bytes,
        algorithm: KemAlgorithm = KemAlgorithm.ML_KEM_768,
    ) -> bytes:
        """Decapsulate a ciphertext using a secret key.
        
        This is the recipient's operation in a key exchange.
        
        Args:
            secret_key: Recipient's secret key.
            ciphertext: Ciphertext from encapsulation.
            algorithm: KEM algorithm to use.
            
        Returns:
            Shared secret bytes.
            
        Raises:
            CryptoError: If decapsulation fails.
        """
        lib = get_library()
        
        # Allocate output buffer
        ss_size = ctypes.c_size_t(algorithm.shared_secret_size)
        ss_buf = (ctypes.c_uint8 * algorithm.shared_secret_size)()
        
        # Convert inputs to ctypes arrays
        sk_buf = (ctypes.c_uint8 * len(secret_key))(*secret_key)
        ct_buf = (ctypes.c_uint8 * len(ciphertext))(*ciphertext)
        
        result = lib.quac100_kem_decaps(
            self._device.handle,
            algorithm.value,
            sk_buf,
            len(secret_key),
            ct_buf,
            len(ciphertext),
            ss_buf,
            ctypes.byref(ss_size),
        )
        
        check_error(result, "KEM decapsulation failed")
        
        return bytes(ss_buf[:ss_size.value])
    
    # Convenience methods for specific security levels
    
    def generate_keypair_512(self) -> KeyPair:
        """Generate ML-KEM-512 key pair (128-bit security)."""
        return self.generate_keypair(KemAlgorithm.ML_KEM_512)
    
    def generate_keypair_768(self) -> KeyPair:
        """Generate ML-KEM-768 key pair (192-bit security)."""
        return self.generate_keypair(KemAlgorithm.ML_KEM_768)
    
    def generate_keypair_1024(self) -> KeyPair:
        """Generate ML-KEM-1024 key pair (256-bit security)."""
        return self.generate_keypair(KemAlgorithm.ML_KEM_1024)
    
    def encapsulate_512(self, public_key: bytes) -> EncapsulationResult:
        """Encapsulate using ML-KEM-512."""
        return self.encapsulate(public_key, KemAlgorithm.ML_KEM_512)
    
    def encapsulate_768(self, public_key: bytes) -> EncapsulationResult:
        """Encapsulate using ML-KEM-768."""
        return self.encapsulate(public_key, KemAlgorithm.ML_KEM_768)
    
    def encapsulate_1024(self, public_key: bytes) -> EncapsulationResult:
        """Encapsulate using ML-KEM-1024."""
        return self.encapsulate(public_key, KemAlgorithm.ML_KEM_1024)
    
    def decapsulate_512(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate using ML-KEM-512."""
        return self.decapsulate(secret_key, ciphertext, KemAlgorithm.ML_KEM_512)
    
    def decapsulate_768(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate using ML-KEM-768."""
        return self.decapsulate(secret_key, ciphertext, KemAlgorithm.ML_KEM_768)
    
    def decapsulate_1024(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate using ML-KEM-1024."""
        return self.decapsulate(secret_key, ciphertext, KemAlgorithm.ML_KEM_1024)