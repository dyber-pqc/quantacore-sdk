"""
Utility functions for QUAC 100 SDK.

This module provides common utilities for encoding, secure operations,
and byte manipulation.
"""

import base64
import ctypes
from typing import Union


def to_hex(data: bytes) -> str:
    """Convert bytes to hexadecimal string.
    
    Args:
        data: Bytes to convert.
        
    Returns:
        Lowercase hexadecimal string.
        
    Example:
        >>> to_hex(b'\\xde\\xad\\xbe\\xef')
        'deadbeef'
    """
    return data.hex()


def from_hex(hex_str: str) -> bytes:
    """Convert hexadecimal string to bytes.
    
    Args:
        hex_str: Hexadecimal string (with or without spaces).
        
    Returns:
        Decoded bytes.
        
    Example:
        >>> from_hex('deadbeef')
        b'\\xde\\xad\\xbe\\xef'
    """
    # Remove spaces and convert
    hex_str = hex_str.replace(" ", "").replace(":", "")
    return bytes.fromhex(hex_str)


def to_base64(data: bytes) -> str:
    """Convert bytes to Base64 string.
    
    Args:
        data: Bytes to encode.
        
    Returns:
        Base64 encoded string.
    """
    return base64.b64encode(data).decode("ascii")


def from_base64(b64_str: str) -> bytes:
    """Convert Base64 string to bytes.
    
    Args:
        b64_str: Base64 encoded string.
        
    Returns:
        Decoded bytes.
    """
    return base64.b64decode(b64_str)


def to_base64url(data: bytes) -> str:
    """Convert bytes to URL-safe Base64 string.
    
    Args:
        data: Bytes to encode.
        
    Returns:
        URL-safe Base64 encoded string (no padding).
    """
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def from_base64url(b64_str: str) -> bytes:
    """Convert URL-safe Base64 string to bytes.
    
    Args:
        b64_str: URL-safe Base64 encoded string.
        
    Returns:
        Decoded bytes.
    """
    # Add padding if needed
    padding = 4 - len(b64_str) % 4
    if padding != 4:
        b64_str += "=" * padding
    return base64.urlsafe_b64decode(b64_str)


def secure_zero(buffer: Union[bytearray, ctypes.Array]) -> None:
    """Securely zero a buffer to clear sensitive data.
    
    This function attempts to prevent compiler optimizations from
    removing the zeroing operation.
    
    Args:
        buffer: Mutable buffer to zero (bytearray or ctypes array).
        
    Example:
        >>> secret = bytearray(b'sensitive data')
        >>> secure_zero(secret)
        >>> secret
        bytearray(b'\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00')
    """
    if isinstance(buffer, bytearray):
        for i in range(len(buffer)):
            buffer[i] = 0
    elif hasattr(buffer, '__len__'):
        # ctypes array or similar
        for i in range(len(buffer)):
            buffer[i] = 0
    
    # Try to use volatile-like semantics
    # This is best-effort; Python doesn't guarantee this
    try:
        import gc
        gc.collect()
    except:
        pass


def secure_compare(a: bytes, b: bytes) -> bool:
    """Compare two byte strings in constant time.
    
    This function is resistant to timing attacks.
    
    Args:
        a: First byte string.
        b: Second byte string.
        
    Returns:
        True if equal, False otherwise.
    """
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    
    return result == 0


def concat(*args: bytes) -> bytes:
    """Concatenate multiple byte strings.
    
    Args:
        *args: Byte strings to concatenate.
        
    Returns:
        Concatenated bytes.
    """
    return b"".join(args)


def copy(data: bytes) -> bytes:
    """Create a copy of a byte string.
    
    Args:
        data: Bytes to copy.
        
    Returns:
        Copy of the bytes.
    """
    return bytes(data)


def slice_bytes(data: bytes, offset: int, length: int) -> bytes:
    """Extract a slice from a byte string.
    
    Args:
        data: Source bytes.
        offset: Start offset.
        length: Number of bytes.
        
    Returns:
        Slice of bytes.
    """
    return data[offset:offset + length]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings.
    
    Args:
        a: First byte string.
        b: Second byte string.
        
    Returns:
        XOR of the two strings.
        
    Raises:
        ValueError: If lengths don't match.
    """
    if len(a) != len(b):
        raise ValueError("Byte strings must have equal length")
    
    return bytes(x ^ y for x, y in zip(a, b))


def pad_pkcs7(data: bytes, block_size: int) -> bytes:
    """Apply PKCS#7 padding.
    
    Args:
        data: Data to pad.
        block_size: Block size (1-255).
        
    Returns:
        Padded data.
    """
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)


def unpad_pkcs7(data: bytes) -> bytes:
    """Remove PKCS#7 padding.
    
    Args:
        data: Padded data.
        
    Returns:
        Unpadded data.
        
    Raises:
        ValueError: If padding is invalid.
    """
    if not data:
        raise ValueError("Empty data")
    
    padding_len = data[-1]
    if padding_len == 0 or padding_len > len(data):
        raise ValueError("Invalid padding")
    
    # Verify all padding bytes
    for i in range(1, padding_len + 1):
        if data[-i] != padding_len:
            raise ValueError("Invalid padding")
    
    return data[:-padding_len]


def int_to_bytes(value: int, length: int, byteorder: str = 'big') -> bytes:
    """Convert an integer to bytes.
    
    Args:
        value: Integer value.
        length: Output length in bytes.
        byteorder: 'big' or 'little'.
        
    Returns:
        Bytes representation.
    """
    return value.to_bytes(length, byteorder=byteorder)


def bytes_to_int(data: bytes, byteorder: str = 'big') -> int:
    """Convert bytes to an integer.
    
    Args:
        data: Bytes to convert.
        byteorder: 'big' or 'little'.
        
    Returns:
        Integer value.
    """
    return int.from_bytes(data, byteorder=byteorder)