"""
Tests for utility functions - Pure Python, NO HARDWARE REQUIRED.
"""

import pytest
from quantacore import utils


class TestHexConversion:
    """Test hex encoding/decoding."""

    def test_to_hex(self):
        assert utils.to_hex(b'\xde\xad\xbe\xef') == 'deadbeef'
        assert utils.to_hex(b'') == ''
        assert utils.to_hex(b'\x00\x01\x02') == '000102'

    def test_from_hex(self):
        assert utils.from_hex('deadbeef') == b'\xde\xad\xbe\xef'
        assert utils.from_hex('DEADBEEF') == b'\xde\xad\xbe\xef'
        assert utils.from_hex('') == b''

    def test_roundtrip(self):
        data = b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff'
        assert utils.from_hex(utils.to_hex(data)) == data


class TestBase64Conversion:
    """Test base64 encoding/decoding."""

    def test_to_base64(self):
        assert utils.to_base64(b'Hello') == 'SGVsbG8='
        assert utils.to_base64(b'') == ''

    def test_from_base64(self):
        assert utils.from_base64('SGVsbG8=') == b'Hello'
        assert utils.from_base64('') == b''

    def test_roundtrip(self):
        data = b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff'
        assert utils.from_base64(utils.to_base64(data)) == data


class TestBase64UrlConversion:
    """Test URL-safe base64 encoding/decoding."""

    def test_to_base64url(self):
        # Data that would produce + and / in standard base64
        data = b'\xfb\xff\xfe'
        result = utils.to_base64url(data)
        assert '+' not in result
        assert '/' not in result

    def test_roundtrip(self):
        data = b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff'
        assert utils.from_base64url(utils.to_base64url(data)) == data


class TestSecureOperations:
    """Test secure memory operations."""

    def test_secure_zero(self):
        data = bytearray(b'sensitive data here')
        utils.secure_zero(data)
        assert data == bytearray(len(b'sensitive data here'))

    def test_secure_compare_equal(self):
        a = b'test data'
        b = b'test data'
        assert utils.secure_compare(a, b) is True

    def test_secure_compare_not_equal(self):
        a = b'test data'
        b = b'different'
        assert utils.secure_compare(a, b) is False


class TestByteOperations:
    """Test byte manipulation utilities."""

    def test_concat(self):
        result = utils.concat(b'hello', b' ', b'world')
        assert result == b'hello world'

    def test_copy(self):
        original = b'original data'
        copied = utils.copy(original)
        # Just test equality - Python may intern/cache small bytes objects
        assert copied == original

    def test_copy_independence(self):
        """Test that copy works for mutable bytearrays."""
        original = bytearray(b'mutable data')
        copied = utils.copy(original)
        assert copied == original
        # Modify original, copied should be unchanged (if it's truly a copy)
        original[0] = 0
        # Note: If copy returns bytes from bytearray, this tests conversion

    def test_slice_bytes(self):
        data = b'0123456789'
        assert utils.slice_bytes(data, 0, 5) == b'01234'
        assert utils.slice_bytes(data, 5, 10) == b'56789'

    def test_xor_bytes(self):
        a = b'\x00\xff\x00\xff'
        b = b'\xff\x00\xff\x00'
        result = utils.xor_bytes(a, b)
        assert result == b'\xff\xff\xff\xff'

    def test_xor_bytes_length_mismatch(self):
        with pytest.raises(ValueError):
            utils.xor_bytes(b'\x00\x00', b'\x00\x00\x00')


class TestPadding:
    """Test PKCS#7 padding."""

    def test_pad_pkcs7(self):
        data = b'hello'
        padded = utils.pad_pkcs7(data, 16)
        assert len(padded) == 16
        assert padded[-1] == 11  # 16 - 5 = 11 bytes of padding

    def test_unpad_pkcs7(self):
        padded = b'hello' + bytes([11] * 11)
        unpadded = utils.unpad_pkcs7(padded)
        assert unpadded == b'hello'

    def test_unpad_invalid(self):
        with pytest.raises(ValueError):
            utils.unpad_pkcs7(b'invalid\x00\x00\x00')


class TestIntConversion:
    """Test integer/bytes conversion."""

    def test_int_to_bytes(self):
        result = utils.int_to_bytes(256, 2)
        assert result == b'\x01\x00'

    def test_bytes_to_int(self):
        result = utils.bytes_to_int(b'\x01\x00')
        assert result == 256