"""
Tests for exception classes - Pure Python, NO HARDWARE REQUIRED.
"""

import pytest
from quantacore.exceptions import (
    QuacError,
    DeviceError,
    CryptoError,
    VerificationError,
    InitializationError,
    InvalidParameterError,
    NotFoundError,
    TimeoutError,
    SecurityError,
)


class TestQuacError:
    """Test base exception class."""

    def test_creation(self):
        err = QuacError(-1, "Test error")
        assert err.error_code == -1
        assert err.message == "Test error"

    def test_str(self):
        err = QuacError(-1, "Test error")
        s = str(err)
        assert "-1" in s
        assert "Test error" in s

    def test_repr(self):
        err = QuacError(-1, "Test error")
        r = repr(err)
        assert "QuacError" in r


class TestSpecificExceptions:
    """Test specific exception subclasses."""

    def test_device_error(self):
        err = DeviceError(-3, "Device not found")
        assert isinstance(err, QuacError)
        assert isinstance(err, DeviceError)

    def test_crypto_error(self):
        err = CryptoError(-10, "Crypto operation failed")
        assert isinstance(err, QuacError)
        assert isinstance(err, CryptoError)

    def test_verification_error(self):
        err = VerificationError(-13, "Verification failed")
        assert isinstance(err, CryptoError)
        assert isinstance(err, VerificationError)

    def test_initialization_error(self):
        err = InitializationError(-2, "Not initialized")
        assert isinstance(err, QuacError)

    def test_invalid_parameter_error(self):
        err = InvalidParameterError(-1, "Invalid parameter")
        assert isinstance(err, QuacError)

    def test_not_found_error(self):
        err = NotFoundError(-6, "Not found")
        assert isinstance(err, QuacError)

    def test_timeout_error(self):
        err = TimeoutError(-5, "Timeout")
        assert isinstance(err, QuacError)

    def test_security_error(self):
        err = SecurityError(-14, "Security violation")
        assert isinstance(err, QuacError)


class TestExceptionInheritance:
    """Test exception can be caught by base class."""

    def test_catch_by_base(self):
        with pytest.raises(QuacError):
            raise DeviceError(-3, "Device error")

    def test_catch_by_specific(self):
        with pytest.raises(DeviceError):
            raise DeviceError(-3, "Device error")

    def test_verification_caught_by_crypto(self):
        with pytest.raises(CryptoError):
            raise VerificationError(-13, "Verification failed")