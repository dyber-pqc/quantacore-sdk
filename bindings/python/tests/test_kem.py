"""
Tests for Key Encapsulation Mechanism (KEM) operations.
"""

import pytest
import quantacore
from quantacore import KemAlgorithm


class TestKem:
    """Test KEM operations."""
    
    def test_generate_keypair_512(self, kem):
        """Test ML-KEM-512 key generation."""
        with kem.generate_keypair(KemAlgorithm.ML_KEM_512) as kp:
            assert kp.public_key is not None
            assert kp.secret_key is not None
            assert len(kp.public_key) == KemAlgorithm.ML_KEM_512.public_key_size
            assert len(kp.secret_key) == KemAlgorithm.ML_KEM_512.secret_key_size
    
    def test_generate_keypair_768(self, kem):
        """Test ML-KEM-768 key generation."""
        with kem.generate_keypair(KemAlgorithm.ML_KEM_768) as kp:
            assert kp.public_key is not None
            assert kp.secret_key is not None
            assert len(kp.public_key) == KemAlgorithm.ML_KEM_768.public_key_size
            assert len(kp.secret_key) == KemAlgorithm.ML_KEM_768.secret_key_size
    
    def test_generate_keypair_1024(self, kem):
        """Test ML-KEM-1024 key generation."""
        with kem.generate_keypair(KemAlgorithm.ML_KEM_1024) as kp:
            assert kp.public_key is not None
            assert kp.secret_key is not None
            assert len(kp.public_key) == KemAlgorithm.ML_KEM_1024.public_key_size
            assert len(kp.secret_key) == KemAlgorithm.ML_KEM_1024.secret_key_size
    
    def test_encapsulate_decapsulate(self, kem):
        """Test full encapsulation/decapsulation cycle."""
        # Generate key pair
        with kem.generate_keypair(KemAlgorithm.ML_KEM_768) as kp:
            # Encapsulate
            with kem.encapsulate(kp.public_key, KemAlgorithm.ML_KEM_768) as encap:
                assert encap.ciphertext is not None
                assert encap.shared_secret is not None
                assert len(encap.ciphertext) == KemAlgorithm.ML_KEM_768.ciphertext_size
                assert len(encap.shared_secret) == 32
                
                # Decapsulate
                shared_secret = kem.decapsulate(
                    kp.secret_key,
                    encap.ciphertext,
                    KemAlgorithm.ML_KEM_768
                )
                
                # Shared secrets should match
                assert shared_secret == encap.shared_secret
    
    def test_convenience_methods(self, kem):
        """Test convenience methods."""
        with kem.generate_keypair_768() as kp:
            with kem.encapsulate_768(kp.public_key) as encap:
                shared = kem.decapsulate_768(kp.secret_key, encap.ciphertext)
                assert shared == encap.shared_secret


class TestKeyPair:
    """Test KeyPair class."""
    
    def test_context_manager(self, kem):
        """Test KeyPair context manager."""
        with kem.generate_keypair_768() as kp:
            pk = kp.public_key
            sk = kp.secret_key
            assert pk is not None
            assert sk is not None
        
        # After context exit, should be closed
        assert kp._closed
    
    def test_repr(self, kem):
        """Test KeyPair string representation."""
        with kem.generate_keypair_768() as kp:
            s = repr(kp)
            assert "ML_KEM_768" in s
            assert "bytes" in s


class TestEncapsulationResult:
    """Test EncapsulationResult class."""
    
    def test_context_manager(self, kem):
        """Test EncapsulationResult context manager."""
        with kem.generate_keypair_768() as kp:
            with kem.encapsulate_768(kp.public_key) as encap:
                ct = encap.ciphertext
                ss = encap.shared_secret
                assert ct is not None
                assert ss is not None
            
            # After context exit, should be closed
            assert encap._closed