"""
Tests for hash operations - REQUIRES HARDWARE.
"""

import pytest
from quantacore import HashAlgorithm

# Mark all tests in this module as requiring hardware
pytestmark = pytest.mark.hardware


class TestHash:
    """Test hash operations."""

    def test_sha256(self, hash_obj):
        data = b"test data"
        digest = hash_obj.sha256(data)
        assert len(digest) == 32
        assert isinstance(digest, bytes)

    def test_sha256_deterministic(self, hash_obj):
        data = b"test data"
        digest1 = hash_obj.sha256(data)
        digest2 = hash_obj.sha256(data)
        assert digest1 == digest2

    def test_sha384(self, hash_obj):
        data = b"test data"
        digest = hash_obj.sha384(data)
        assert len(digest) == 48

    def test_sha512(self, hash_obj):
        data = b"test data"
        digest = hash_obj.sha512(data)
        assert len(digest) == 64

    def test_sha3_256(self, hash_obj):
        data = b"test data"
        digest = hash_obj.sha3_256(data)
        assert len(digest) == 32

    def test_sha3_384(self, hash_obj):
        data = b"test data"
        digest = hash_obj.sha3_384(data)
        assert len(digest) == 48

    def test_sha3_512(self, hash_obj):
        data = b"test data"
        digest = hash_obj.sha3_512(data)
        assert len(digest) == 64

    def test_shake128(self, hash_obj):
        data = b"test data"
        output = hash_obj.shake128(data, 32)
        assert len(output) == 32

    def test_shake128_variable_length(self, hash_obj):
        data = b"test data"
        output32 = hash_obj.shake128(data, 32)
        output64 = hash_obj.shake128(data, 64)
        assert len(output32) == 32
        assert len(output64) == 64
        assert output64[:32] == output32  # Prefix should match

    def test_shake256(self, hash_obj):
        data = b"test data"
        output = hash_obj.shake256(data, 64)
        assert len(output) == 64

    def test_hash_generic(self, hash_obj):
        data = b"test data"
        digest = hash_obj.hash(HashAlgorithm.SHA256, data)
        assert len(digest) == 32

    def test_empty_input(self, hash_obj):
        digest = hash_obj.sha256(b"")
        assert len(digest) == 32


class TestHashContext:
    """Test incremental hashing."""

    def test_create_context(self, hash_obj):
        ctx = hash_obj.create_context(HashAlgorithm.SHA256)
        assert ctx is not None

    def test_incremental_hash(self, hash_obj):
        # Hash in parts
        with hash_obj.create_context(HashAlgorithm.SHA256) as ctx:
            ctx.update(b"hello ")
            ctx.update(b"world")
            incremental = ctx.digest()

        # Hash all at once
        one_shot = hash_obj.sha256(b"hello world")

        assert incremental == one_shot

    def test_context_manager(self, hash_obj):
        with hash_obj.create_context(HashAlgorithm.SHA256) as ctx:
            ctx.update(b"test")
            digest = ctx.digest()
        assert len(digest) == 32


class TestHmac:
    """Test HMAC operations."""

    def test_hmac_sha256(self, hash_obj):
        key = b"secret key"
        data = b"message to authenticate"
        mac = hash_obj.hmac_sha256(key, data)
        assert len(mac) == 32

    def test_hmac_sha256_deterministic(self, hash_obj):
        key = b"secret key"
        data = b"message"
        mac1 = hash_obj.hmac_sha256(key, data)
        mac2 = hash_obj.hmac_sha256(key, data)
        assert mac1 == mac2

    def test_hmac_sha256_different_keys(self, hash_obj):
        data = b"message"
        mac1 = hash_obj.hmac_sha256(b"key1", data)
        mac2 = hash_obj.hmac_sha256(b"key2", data)
        assert mac1 != mac2

    def test_hmac_sha384(self, hash_obj):
        key = b"secret key"
        data = b"message"
        mac = hash_obj.hmac_sha384(key, data)
        assert len(mac) == 48

    def test_hmac_sha512(self, hash_obj):
        key = b"secret key"
        data = b"message"
        mac = hash_obj.hmac_sha512(key, data)
        assert len(mac) == 64

    def test_hmac_generic(self, hash_obj):
        key = b"secret key"
        data = b"message"
        mac = hash_obj.hmac(HashAlgorithm.SHA256, key, data)
        assert len(mac) == 32


class TestHkdf:
    """Test HKDF key derivation."""

    def test_hkdf_basic(self, hash_obj):
        ikm = b"input key material"
        salt = b"random salt"
        info = b"context info"
        
        derived = hash_obj.hkdf(HashAlgorithm.SHA256, ikm, salt, info, 32)
        assert len(derived) == 32

    def test_hkdf_variable_length(self, hash_obj):
        ikm = b"input key material"
        salt = b"salt"
        info = b"info"
        
        key32 = hash_obj.hkdf(HashAlgorithm.SHA256, ikm, salt, info, 32)
        key64 = hash_obj.hkdf(HashAlgorithm.SHA256, ikm, salt, info, 64)
        
        assert len(key32) == 32
        assert len(key64) == 64

    def test_hkdf_deterministic(self, hash_obj):
        ikm = b"input key material"
        salt = b"salt"
        info = b"info"
        
        key1 = hash_obj.hkdf(HashAlgorithm.SHA256, ikm, salt, info, 32)
        key2 = hash_obj.hkdf(HashAlgorithm.SHA256, ikm, salt, info, 32)
        assert key1 == key2

    def test_hkdf_different_info(self, hash_obj):
        ikm = b"input key material"
        salt = b"salt"
        
        key1 = hash_obj.hkdf(HashAlgorithm.SHA256, ikm, salt, b"info1", 32)
        key2 = hash_obj.hkdf(HashAlgorithm.SHA256, ikm, salt, b"info2", 32)
        assert key1 != key2