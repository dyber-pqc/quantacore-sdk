"""
Tests for digital signature operations - REQUIRES HARDWARE.
"""

import pytest
from quantacore import SignAlgorithm, VerificationError

# Mark all tests in this module as requiring hardware
pytestmark = pytest.mark.hardware


class TestSign:
    """Test signature operations."""

    def test_generate_keypair_44(self, sign):
        keypair = sign.generate_keypair(SignAlgorithm.ML_DSA_44)
        assert len(keypair.public_key) == SignAlgorithm.ML_DSA_44.public_key_size
        assert len(keypair.secret_key) == SignAlgorithm.ML_DSA_44.secret_key_size

    def test_generate_keypair_65(self, sign):
        keypair = sign.generate_keypair(SignAlgorithm.ML_DSA_65)
        assert len(keypair.public_key) == SignAlgorithm.ML_DSA_65.public_key_size
        assert len(keypair.secret_key) == SignAlgorithm.ML_DSA_65.secret_key_size

    def test_sign_verify(self, sign):
        algo = SignAlgorithm.ML_DSA_65
        keypair = sign.generate_keypair(algo)
        message = b"Test message to sign"
        
        signature = sign.sign(keypair.secret_key, message, algo)
        assert len(signature) == algo.signature_size
        
        valid = sign.verify(keypair.public_key, message, signature, algo)
        assert valid is True

    def test_sign_verify_string(self, sign):
        keypair = sign.generate_keypair_65()
        message = "String message"
        
        signature = sign.sign_65(keypair.secret_key, message)
        valid = sign.verify_65(keypair.public_key, message, signature)
        assert valid is True

    def test_verify_invalid(self, sign):
        keypair = sign.generate_keypair_65()
        message = b"Original message"
        
        signature = sign.sign_65(keypair.secret_key, message)
        valid = sign.verify_65(keypair.public_key, b"Modified message", signature)
        assert valid is False

    def test_verify_or_raise(self, sign):
        keypair = sign.generate_keypair_65()
        message = b"Test message"
        signature = sign.sign_65(keypair.secret_key, message)
        
        # Should not raise
        sign.verify_or_raise(keypair.public_key, message, signature, SignAlgorithm.ML_DSA_65)
        
        # Should raise
        with pytest.raises(VerificationError):
            sign.verify_or_raise(keypair.public_key, b"Wrong", signature, SignAlgorithm.ML_DSA_65)