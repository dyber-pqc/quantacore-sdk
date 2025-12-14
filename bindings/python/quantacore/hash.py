"""
Hash operations for QUAC 100 SDK.

This module provides hardware-accelerated hashing using SHA-2, SHA-3,
SHAKE, and HMAC algorithms.
"""

import ctypes
from typing import TYPE_CHECKING, Union, Optional

from quantacore._native import get_library
from quantacore.types import HashAlgorithm, ErrorCode
from quantacore.exceptions import check_error, CryptoError

if TYPE_CHECKING:
    from quantacore.device import Device


class HashContext:
    """Incremental hash context for streaming operations.
    
    Use for hashing large data in chunks.
    
    Example:
        >>> ctx = hash.create_context(HashAlgorithm.SHA3_256)
        >>> ctx.update(b"Part 1")
        >>> ctx.update(b"Part 2")
        >>> digest = ctx.digest()
    """
    
    def __init__(self, device: "Device", algorithm: HashAlgorithm):
        self._device = device
        self._algorithm = algorithm
        self._data = bytearray()
        self._finalized = False
    
    @property
    def algorithm(self) -> HashAlgorithm:
        """Get the hash algorithm."""
        return self._algorithm
    
    def update(self, data: Union[bytes, str]) -> "HashContext":
        """Add data to the hash.
        
        Args:
            data: Data to hash (bytes or string).
            
        Returns:
            Self for method chaining.
            
        Raises:
            ValueError: If digest() has already been called.
        """
        if self._finalized:
            raise ValueError("Cannot update after digest()")
        
        if isinstance(data, str):
            data = data.encode("utf-8")
        
        self._data.extend(data)
        return self
    
    def digest(self) -> bytes:
        """Finalize and return the hash digest.
        
        Returns:
            Hash digest bytes.
            
        Note:
            After calling digest(), update() cannot be called.
        """
        if self._finalized:
            raise ValueError("digest() already called")
        
        self._finalized = True
        
        # Compute hash of accumulated data
        from quantacore.hash import Hash
        hash_obj = Hash(self._device)
        return hash_obj.hash(self._algorithm, bytes(self._data))
    
    def do_final(self) -> bytes:
        """Alias for digest()."""
        return self.digest()
    
    def copy(self) -> "HashContext":
        """Create a copy of this context.
        
        Returns:
            New HashContext with same state.
        """
        if self._finalized:
            raise ValueError("Cannot copy finalized context")
        
        ctx = HashContext(self._device, self._algorithm)
        ctx._data = bytearray(self._data)
        return ctx
    
    def close(self) -> None:
        """Clear internal state."""
        self._data.clear()
        self._finalized = True
    
    def __enter__(self) -> "HashContext":
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        self.close()
        return False


class Hash:
    """Hardware-accelerated hash operations.
    
    This class provides hashing using SHA-2, SHA-3, SHAKE, and HMAC algorithms.
    
    Example:
        >>> hash = device.hash()
        >>> 
        >>> # One-shot hashing
        >>> digest = hash.sha256(b"Hello, World!")
        >>> 
        >>> # With algorithm enum
        >>> digest = hash.hash(HashAlgorithm.SHA3_256, data)
        >>> 
        >>> # Incremental hashing
        >>> with hash.create_context(HashAlgorithm.SHA256) as ctx:
        ...     ctx.update(b"Part 1")
        ...     ctx.update(b"Part 2")
        ...     digest = ctx.digest()
    """
    
    def __init__(self, device: "Device"):
        """Initialize Hash subsystem.
        
        Args:
            device: Parent device instance.
        """
        self._device = device
    
    def hash(
        self,
        algorithm: HashAlgorithm,
        data: Union[bytes, str],
        output_length: Optional[int] = None,
    ) -> bytes:
        """Compute hash of data.
        
        Args:
            algorithm: Hash algorithm to use.
            data: Data to hash (bytes or string).
            output_length: Output length for SHAKE algorithms (required for SHAKE).
            
        Returns:
            Hash digest bytes.
            
        Raises:
            CryptoError: If hashing fails.
            ValueError: If SHAKE algorithm used without output_length.
        """
        lib = get_library()
        
        # Convert data to bytes if string
        if isinstance(data, str):
            data = data.encode("utf-8")
        
        # Determine output size
        if algorithm in (HashAlgorithm.SHAKE128, HashAlgorithm.SHAKE256):
            if output_length is None:
                raise ValueError("output_length required for SHAKE algorithms")
            out_size = output_length
        else:
            out_size = algorithm.digest_size
            if out_size is None:
                raise ValueError(f"Unknown digest size for {algorithm}")
        
        # Allocate buffers
        out_buf = (ctypes.c_uint8 * out_size)()
        data_buf = (ctypes.c_uint8 * len(data))(*data)
        
        result = lib.quac100_hash(
            self._device.handle,
            algorithm.value,
            data_buf,
            len(data),
            out_buf,
            out_size,
        )
        
        check_error(result, "Hash operation failed")
        
        return bytes(out_buf)
    
    def create_context(self, algorithm: HashAlgorithm) -> HashContext:
        """Create an incremental hash context.
        
        Args:
            algorithm: Hash algorithm to use.
            
        Returns:
            HashContext for incremental hashing.
        """
        return HashContext(self._device, algorithm)
    
    # Convenience methods for specific algorithms
    
    def sha256(self, data: Union[bytes, str]) -> bytes:
        """Compute SHA-256 hash."""
        return self.hash(HashAlgorithm.SHA256, data)
    
    def sha384(self, data: Union[bytes, str]) -> bytes:
        """Compute SHA-384 hash."""
        return self.hash(HashAlgorithm.SHA384, data)
    
    def sha512(self, data: Union[bytes, str]) -> bytes:
        """Compute SHA-512 hash."""
        return self.hash(HashAlgorithm.SHA512, data)
    
    def sha3_256(self, data: Union[bytes, str]) -> bytes:
        """Compute SHA3-256 hash."""
        return self.hash(HashAlgorithm.SHA3_256, data)
    
    def sha3_384(self, data: Union[bytes, str]) -> bytes:
        """Compute SHA3-384 hash."""
        return self.hash(HashAlgorithm.SHA3_384, data)
    
    def sha3_512(self, data: Union[bytes, str]) -> bytes:
        """Compute SHA3-512 hash."""
        return self.hash(HashAlgorithm.SHA3_512, data)
    
    def shake128(self, data: Union[bytes, str], output_length: int) -> bytes:
        """Compute SHAKE128 hash with variable output length."""
        return self.hash(HashAlgorithm.SHAKE128, data, output_length)
    
    def shake256(self, data: Union[bytes, str], output_length: int) -> bytes:
        """Compute SHAKE256 hash with variable output length."""
        return self.hash(HashAlgorithm.SHAKE256, data, output_length)
    
    def hmac(
        self,
        algorithm: HashAlgorithm,
        key: bytes,
        data: Union[bytes, str],
    ) -> bytes:
        """Compute HMAC.
        
        Args:
            algorithm: Hash algorithm for HMAC.
            key: HMAC key.
            data: Data to authenticate.
            
        Returns:
            HMAC value.
        """
        lib = get_library()
        
        if isinstance(data, str):
            data = data.encode("utf-8")
        
        out_size = algorithm.digest_size
        if out_size is None:
            raise ValueError(f"HMAC not supported for {algorithm}")
        
        out_buf = (ctypes.c_uint8 * out_size)()
        
        if hasattr(lib, 'quac100_hmac'):
            key_buf = (ctypes.c_uint8 * len(key))(*key)
            data_buf = (ctypes.c_uint8 * len(data))(*data)
            
            result = lib.quac100_hmac(
                self._device.handle,
                algorithm.value,
                key_buf, len(key),
                data_buf, len(data),
                out_buf, out_size,
            )
            check_error(result, "HMAC operation failed")
            return bytes(out_buf)
        else:
            # Fallback: use Python's hmac
            import hmac as hmac_mod
            hash_name = {
                HashAlgorithm.SHA256: 'sha256',
                HashAlgorithm.SHA384: 'sha384',
                HashAlgorithm.SHA512: 'sha512',
                HashAlgorithm.SHA3_256: 'sha3_256',
                HashAlgorithm.SHA3_384: 'sha3_384',
                HashAlgorithm.SHA3_512: 'sha3_512',
            }.get(algorithm, 'sha256')
            return hmac_mod.new(key, data, hash_name).digest()
    
    def hmac_sha256(self, key: bytes, data: Union[bytes, str]) -> bytes:
        """Compute HMAC-SHA256."""
        return self.hmac(HashAlgorithm.SHA256, key, data)
    
    def hmac_sha384(self, key: bytes, data: Union[bytes, str]) -> bytes:
        """Compute HMAC-SHA384."""
        return self.hmac(HashAlgorithm.SHA384, key, data)
    
    def hmac_sha512(self, key: bytes, data: Union[bytes, str]) -> bytes:
        """Compute HMAC-SHA512."""
        return self.hmac(HashAlgorithm.SHA512, key, data)
    
    def hkdf(
        self,
        algorithm: HashAlgorithm,
        ikm: bytes,
        salt: Optional[bytes],
        info: Optional[bytes],
        length: int,
    ) -> bytes:
        """Derive key using HKDF.
        
        Args:
            algorithm: Hash algorithm for HKDF.
            ikm: Input keying material.
            salt: Optional salt (None for default).
            info: Optional context info.
            length: Output key length.
            
        Returns:
            Derived key bytes.
        """
        lib = get_library()
        
        salt = salt or b""
        info = info or b""
        
        out_buf = (ctypes.c_uint8 * length)()
        
        if hasattr(lib, 'quac100_hkdf'):
            ikm_buf = (ctypes.c_uint8 * len(ikm))(*ikm)
            salt_buf = (ctypes.c_uint8 * len(salt))(*salt) if salt else None
            info_buf = (ctypes.c_uint8 * len(info))(*info) if info else None
            
            result = lib.quac100_hkdf(
                self._device.handle,
                algorithm.value,
                ikm_buf, len(ikm),
                salt_buf, len(salt) if salt else 0,
                info_buf, len(info) if info else 0,
                out_buf, length,
            )
            check_error(result, "HKDF operation failed")
            return bytes(out_buf)
        else:
            # Fallback: use Python's hashlib
            import hashlib
            import hmac as hmac_mod
            
            hash_name = {
                HashAlgorithm.SHA256: 'sha256',
                HashAlgorithm.SHA384: 'sha384',
                HashAlgorithm.SHA512: 'sha512',
            }.get(algorithm, 'sha256')
            
            hash_len = algorithm.digest_size or 32
            
            # HKDF-Extract
            if not salt:
                salt = b'\x00' * hash_len
            prk = hmac_mod.new(salt, ikm, hash_name).digest()
            
            # HKDF-Expand
            t = b""
            okm = b""
            for i in range(1, (length + hash_len - 1) // hash_len + 1):
                t = hmac_mod.new(prk, t + info + bytes([i]), hash_name).digest()
                okm += t
            
            return okm[:length]