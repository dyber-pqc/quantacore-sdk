"""
HSM Key Storage operations for QUAC 100 SDK.

This module provides secure key management in the QUAC 100's
Hardware Security Module.
"""

from dataclasses import dataclass
from typing import TYPE_CHECKING, List, Optional

from quantacore.types import KeyType, KeyUsage, ErrorCode
from quantacore.exceptions import check_error, NotFoundError

if TYPE_CHECKING:
    from quantacore.device import Device


@dataclass
class KeyInfo:
    """Information about a stored key.
    
    Attributes:
        slot: Key slot index.
        label: Key label/name.
        key_type: Type of key (SECRET, PUBLIC, PRIVATE, KEY_PAIR).
        algorithm: Algorithm identifier.
        usage: Allowed key operations.
        exportable: Whether key can be exported.
        created: Creation timestamp.
    """
    slot: int
    label: str
    key_type: KeyType
    algorithm: int
    usage: KeyUsage
    exportable: bool
    created: int
    
    def __str__(self) -> str:
        return (
            f"KeyInfo(slot={self.slot}, label='{self.label}', "
            f"type={self.key_type.name}, usage={self.usage})"
        )


class Keys:
    """HSM Key Storage operations.
    
    This class provides secure key management including storage, retrieval,
    generation, and deletion of cryptographic keys.
    
    Example:
        >>> keys = device.keys()
        >>> 
        >>> # Store a key
        >>> keys.store(0, "my-aes-key", key_data, KeyType.SECRET, 
        ...            usage=KeyUsage.ENCRYPTION)
        >>> 
        >>> # Get key info
        >>> info = keys.get_info(0)
        >>> print(f"Key: {info.label}")
        >>> 
        >>> # List all keys
        >>> for key in keys.list():
        ...     print(key)
        >>> 
        >>> # Delete a key
        >>> keys.delete(0)
    """
    
    def __init__(self, device: "Device"):
        """Initialize Keys subsystem.
        
        Args:
            device: Parent device instance.
        """
        self._device = device
    
    def store(
        self,
        slot: int,
        label: str,
        key_data: bytes,
        key_type: KeyType = KeyType.SECRET,
        algorithm: int = 0,
        usage: KeyUsage = KeyUsage.ALL,
        exportable: bool = False,
    ) -> None:
        """Store a key in the HSM.
        
        Args:
            slot: Key slot (0-255).
            label: Key label/name.
            key_data: Key material.
            key_type: Type of key.
            algorithm: Algorithm identifier.
            usage: Allowed operations.
            exportable: Whether key can be exported.
            
        Raises:
            QuacError: If storage fails.
        """
        # Implementation would call native library
        # For now, this is a placeholder
        pass
    
    def load(self, slot: int) -> bytes:
        """Load a key from the HSM.
        
        Args:
            slot: Key slot.
            
        Returns:
            Key data (if exportable).
            
        Raises:
            NotFoundError: If key not found.
            QuacError: If key is not exportable or other error.
        """
        # Implementation would call native library
        raise NotFoundError(ErrorCode.KEY_NOT_FOUND, f"Key not found in slot {slot}")
    
    def get_info(self, slot: int) -> KeyInfo:
        """Get information about a stored key.
        
        Args:
            slot: Key slot.
            
        Returns:
            KeyInfo object.
            
        Raises:
            NotFoundError: If key not found.
        """
        # Implementation would call native library
        raise NotFoundError(ErrorCode.KEY_NOT_FOUND, f"Key not found in slot {slot}")
    
    def find_by_label(self, label: str) -> int:
        """Find a key by label.
        
        Args:
            label: Key label to search for.
            
        Returns:
            Key slot index.
            
        Raises:
            NotFoundError: If key not found.
        """
        # Implementation would call native library
        raise NotFoundError(ErrorCode.KEY_NOT_FOUND, f"Key not found: {label}")
    
    def list(self) -> List[KeyInfo]:
        """List all stored keys.
        
        Returns:
            List of KeyInfo objects.
        """
        # Implementation would call native library
        return []
    
    def delete(self, slot: int) -> None:
        """Delete a key from the HSM.
        
        Args:
            slot: Key slot to delete.
            
        Raises:
            NotFoundError: If key not found.
        """
        # Implementation would call native library
        pass
    
    def clear_all(self) -> None:
        """Delete all keys from the HSM.
        
        WARNING: This operation is irreversible.
        """
        # Implementation would call native library
        pass
    
    def generate(
        self,
        slot: int,
        label: str,
        key_type: KeyType,
        algorithm: int,
        usage: KeyUsage = KeyUsage.ALL,
        exportable: bool = False,
    ) -> None:
        """Generate a new key in the HSM.
        
        Args:
            slot: Key slot to store in.
            label: Key label/name.
            key_type: Type of key to generate.
            algorithm: Algorithm identifier.
            usage: Allowed operations.
            exportable: Whether key can be exported.
            
        Raises:
            QuacError: If generation fails.
        """
        # Implementation would call native library
        pass
    
    def export(self, slot: int) -> bytes:
        """Export a key from the HSM.
        
        Args:
            slot: Key slot.
            
        Returns:
            Key data.
            
        Raises:
            NotFoundError: If key not found.
            QuacError: If key is not exportable.
        """
        return self.load(slot)
    
    def import_key(
        self,
        slot: int,
        label: str,
        key_data: bytes,
        key_type: KeyType = KeyType.SECRET,
        algorithm: int = 0,
        usage: KeyUsage = KeyUsage.ALL,
        exportable: bool = False,
    ) -> None:
        """Import a key into the HSM.
        
        Alias for store().
        """
        self.store(slot, label, key_data, key_type, algorithm, usage, exportable)
    
    def get_slot_count(self) -> int:
        """Get the number of available key slots.
        
        Returns:
            Number of slots (typically 256).
        """
        return 256
    
    def get_free_slot(self) -> Optional[int]:
        """Find the first free key slot.
        
        Returns:
            Free slot index, or None if all slots are used.
        """
        used_slots = {k.slot for k in self.list()}
        for i in range(self.get_slot_count()):
            if i not in used_slots:
                return i
        return None