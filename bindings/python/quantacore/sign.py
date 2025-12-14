"""
Digital Signature operations for QUAC 100 SDK.

This module provides ML-DSA (Dilithium) digital signature operations.
"""

import ctypes
from typing import TYPE_CHECKING, Union

from quantacore._native import get_library
from quantacore.types import SignAlgorithm, ErrorCode
from quantacore.exceptions import check_error, CryptoError, VerificationError
from quantacore.kem import KeyPair  # Reuse KeyPair class
from quantacore.utils import secure_zero

if TYPE_CHECKING:
    from quantacore.device import Device


class Sign:
    """Digital Signature (ML-DSA/Dilithium) operations.
    
    This class provides post-quantum digital signatures using ML-DSA
    (formerly known as CRYSTALS-Dilithium).
    
    Example:
        >>> sign = device.sign()
        >>> 
        >>> # Generate signing key pair
        >>> with sign.generate_keypair(SignAlgorithm.ML_DSA_65) as kp:
        ...     message = b"Important document"
        ...     
        ...     # Sign message
        ...     signature = sign.sign(kp.secret_key, message, SignAlgorithm.ML_DSA_65)
        ...     
        ...     # Verify signature
        ...     valid = sign.verify(kp.public_key, message, signature, SignAlgorithm.ML_DSA_65)
        ...     assert valid
    """
    
    def __init__(self, device: "Device"):
        """Initialize Sign subsystem.
        
        Args:
            device: Parent device instance.
        """
        self._device = device
    
    def generate_keypair(
        self,
        algorithm: SignAlgorithm = SignAlgorithm.ML_DSA_65
    ) -> KeyPair:
        """Generate a new signing key pair.
        
        Args:
            algorithm: Signature algorithm to use.
            
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
        
        result = lib.quac100_sign_keygen(
            self._device.handle,
            algorithm.value,
            pk_buf,
            ctypes.byref(pk_size),
            sk_buf,
            ctypes.byref(sk_size),
        )
        
        check_error(result, "Signature key generation failed")
        
        return KeyPair(
            public_key=bytes(pk_buf[:pk_size.value]),
            secret_key=bytes(sk_buf[:sk_size.value]),
            algorithm=algorithm,
        )
    
    def sign(
        self,
        secret_key: bytes,
        message: Union[bytes, str],
        algorithm: SignAlgorithm = SignAlgorithm.ML_DSA_65,
    ) -> bytes:
        """Sign a message.
        
        Args:
            secret_key: Signer's secret key.
            message: Message to sign (bytes or string).
            algorithm: Signature algorithm to use.
            
        Returns:
            Signature bytes.
            
        Raises:
            CryptoError: If signing fails.
        """
        lib = get_library()
        
        # Convert message to bytes if string
        if isinstance(message, str):
            message = message.encode("utf-8")
        
        # Allocate output buffer
        sig_size = ctypes.c_size_t(algorithm.signature_size)
        sig_buf = (ctypes.c_uint8 * algorithm.signature_size)()
        
        # Convert inputs to ctypes arrays
        sk_buf = (ctypes.c_uint8 * len(secret_key))(*secret_key)
        msg_buf = (ctypes.c_uint8 * len(message))(*message)
        
        result = lib.quac100_sign(
            self._device.handle,
            algorithm.value,
            sk_buf,
            len(secret_key),
            msg_buf,
            len(message),
            sig_buf,
            ctypes.byref(sig_size),
        )
        
        check_error(result, "Message signing failed")
        
        return bytes(sig_buf[:sig_size.value])
    
    def verify(
        self,
        public_key: bytes,
        message: Union[bytes, str],
        signature: bytes,
        algorithm: SignAlgorithm = SignAlgorithm.ML_DSA_65,
    ) -> bool:
        """Verify a signature.
        
        Args:
            public_key: Signer's public key.
            message: Original message (bytes or string).
            signature: Signature to verify.
            algorithm: Signature algorithm to use.
            
        Returns:
            True if signature is valid, False otherwise.
        """
        lib = get_library()
        
        # Convert message to bytes if string
        if isinstance(message, str):
            message = message.encode("utf-8")
        
        # Convert inputs to ctypes arrays
        pk_buf = (ctypes.c_uint8 * len(public_key))(*public_key)
        msg_buf = (ctypes.c_uint8 * len(message))(*message)
        sig_buf = (ctypes.c_uint8 * len(signature))(*signature)
        
        result = lib.quac100_verify(
            self._device.handle,
            algorithm.value,
            pk_buf,
            len(public_key),
            msg_buf,
            len(message),
            sig_buf,
            len(signature),
        )
        
        # Return True for success, False for verification failure
        if result == ErrorCode.SUCCESS:
            return True
        elif result == ErrorCode.VERIFICATION_FAILED:
            return False
        else:
            check_error(result, "Signature verification error")
            return False
    
    def verify_or_raise(
        self,
        public_key: bytes,
        message: Union[bytes, str],
        signature: bytes,
        algorithm: SignAlgorithm = SignAlgorithm.ML_DSA_65,
    ) -> None:
        """Verify a signature and raise exception if invalid.
        
        Args:
            public_key: Signer's public key.
            message: Original message (bytes or string).
            signature: Signature to verify.
            algorithm: Signature algorithm to use.
            
        Raises:
            VerificationError: If signature is invalid.
        """
        if not self.verify(public_key, message, signature, algorithm):
            raise VerificationError()
    
    # Convenience methods for specific security levels
    
    def generate_keypair_44(self) -> KeyPair:
        """Generate ML-DSA-44 key pair (128-bit security)."""
        return self.generate_keypair(SignAlgorithm.ML_DSA_44)
    
    def generate_keypair_65(self) -> KeyPair:
        """Generate ML-DSA-65 key pair (192-bit security)."""
        return self.generate_keypair(SignAlgorithm.ML_DSA_65)
    
    def generate_keypair_87(self) -> KeyPair:
        """Generate ML-DSA-87 key pair (256-bit security)."""
        return self.generate_keypair(SignAlgorithm.ML_DSA_87)
    
    def sign_44(self, secret_key: bytes, message: Union[bytes, str]) -> bytes:
        """Sign using ML-DSA-44."""
        return self.sign(secret_key, message, SignAlgorithm.ML_DSA_44)
    
    def sign_65(self, secret_key: bytes, message: Union[bytes, str]) -> bytes:
        """Sign using ML-DSA-65."""
        return self.sign(secret_key, message, SignAlgorithm.ML_DSA_65)
    
    def sign_87(self, secret_key: bytes, message: Union[bytes, str]) -> bytes:
        """Sign using ML-DSA-87."""
        return self.sign(secret_key, message, SignAlgorithm.ML_DSA_87)
    
    def verify_44(
        self, public_key: bytes, message: Union[bytes, str], signature: bytes
    ) -> bool:
        """Verify using ML-DSA-44."""
        return self.verify(public_key, message, signature, SignAlgorithm.ML_DSA_44)
    
    def verify_65(
        self, public_key: bytes, message: Union[bytes, str], signature: bytes
    ) -> bool:
        """Verify using ML-DSA-65."""
        return self.verify(public_key, message, signature, SignAlgorithm.ML_DSA_65)
    
    def verify_87(
        self, public_key: bytes, message: Union[bytes, str], signature: bytes
    ) -> bool:
        """Verify using ML-DSA-87."""
        return self.verify(public_key, message, signature, SignAlgorithm.ML_DSA_87)