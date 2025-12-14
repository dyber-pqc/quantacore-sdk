"""
Exception classes for QUAC 100 SDK.

All exceptions inherit from QuacError, which provides the error code
and a human-readable message.
"""

from typing import Optional
from quantacore.types import ErrorCode


class QuacError(Exception):
    """Base exception for all QUAC 100 errors.
    
    Attributes:
        error_code: The numeric error code from the native library.
        message: Human-readable error message.
    """
    
    def __init__(
        self, 
        error_code: int = ErrorCode.ERROR, 
        message: Optional[str] = None
    ):
        self.error_code = error_code
        if message is None:
            message = ErrorCode.get_message(error_code)
        self.message = message
        super().__init__(f"[{error_code}] {message}")
    
    @classmethod
    def from_code(cls, code: int, context: Optional[str] = None) -> "QuacError":
        """Create appropriate exception subclass from error code.
        
        Args:
            code: Native error code.
            context: Optional additional context.
            
        Returns:
            Appropriate QuacError subclass.
        """
        message = ErrorCode.get_message(code)
        if context:
            message = f"{message}: {context}"
        
        # Map error codes to specific exception types
        if code == ErrorCode.DEVICE_NOT_FOUND:
            return NotFoundError(code, message)
        elif code == ErrorCode.DEVICE_ERROR:
            return DeviceError(code, message)
        elif code == ErrorCode.DEVICE_BUSY:
            return DeviceError(code, message)
        elif code == ErrorCode.INVALID_PARAM:
            return InvalidParameterError(code, message)
        elif code == ErrorCode.INVALID_ALGORITHM:
            return InvalidParameterError(code, message)
        elif code == ErrorCode.VERIFICATION_FAILED:
            return VerificationError(code, message)
        elif code == ErrorCode.DECAPS_FAILED:
            return CryptoError(code, message)
        elif code == ErrorCode.CRYPTO_ERROR:
            return CryptoError(code, message)
        elif code == ErrorCode.NOT_INITIALIZED:
            return InitializationError(code, message)
        elif code == ErrorCode.ALREADY_INIT:
            return InitializationError(code, message)
        else:
            return QuacError(code, message)


class DeviceError(QuacError):
    """Exception raised for device-related errors.
    
    This includes device not found, device busy, hardware failures,
    and communication errors.
    """
    pass


class CryptoError(QuacError):
    """Exception raised for cryptographic operation errors.
    
    This includes key generation failures, encryption/decryption errors,
    and algorithm-specific failures.
    """
    pass


class VerificationError(CryptoError):
    """Exception raised when signature verification fails.
    
    This is a subclass of CryptoError specifically for verification failures.
    """
    
    def __init__(
        self, 
        error_code: int = ErrorCode.VERIFICATION_FAILED,
        message: str = "Signature verification failed"
    ):
        super().__init__(error_code, message)


class InitializationError(QuacError):
    """Exception raised for library initialization errors.
    
    This includes failures during initialization, cleanup, or when
    operations are attempted before initialization.
    """
    pass


class InvalidParameterError(QuacError):
    """Exception raised for invalid parameter errors.
    
    This includes invalid algorithm selection, out-of-range values,
    and malformed input data.
    """
    pass


class NotFoundError(QuacError):
    """Exception raised when a resource is not found.
    
    This includes device not found, key not found, and similar errors.
    """
    pass


class TimeoutError(QuacError):
    """Exception raised when an operation times out."""
    
    def __init__(
        self,
        error_code: int = ErrorCode.TIMEOUT,
        message: str = "Operation timed out"
    ):
        super().__init__(error_code, message)


class SecurityError(QuacError):
    """Exception raised for security-related errors.
    
    This includes tamper detection, authentication failures, and
    entropy depletion.
    """
    pass


def check_error(code: int, context: Optional[str] = None) -> None:
    """Check error code and raise appropriate exception if not SUCCESS.
    
    Args:
        code: Native error code.
        context: Optional additional context for the error message.
        
    Raises:
        QuacError: If code indicates an error.
    """
    if code != ErrorCode.SUCCESS:
        raise QuacError.from_code(code, context)