"""
Tests for QRNG (Quantum Random Number Generation) operations - REQUIRES HARDWARE.
"""

import pytest

# Mark all tests in this module as requiring hardware
pytestmark = pytest.mark.hardware


class TestRandom:
    """Test random number generation."""

    def test_get_entropy_status(self, random):
        status = random.get_entropy_status()
        assert hasattr(status, 'level')
        assert hasattr(status, 'is_healthy')
        assert 0 <= status.level <= 100

    def test_bytes(self, random):
        data = random.bytes(32)
        assert len(data) == 32
        assert isinstance(data, bytes)

    def test_bytes_different(self, random):
        """Two calls should produce different results."""
        data1 = random.bytes(32)
        data2 = random.bytes(32)
        assert data1 != data2

    def test_next_bytes(self, random):
        buffer = bytearray(16)
        random.next_bytes(buffer)
        assert buffer != bytearray(16)  # Should be filled

    def test_next_int(self, random):
        value = random.next_int()
        assert isinstance(value, int)

    def test_next_int_bound(self, random):
        for _ in range(100):
            value = random.next_int(10)
            assert 0 <= value < 10

    def test_randint(self, random):
        for _ in range(100):
            value = random.randint(5, 15)
            assert 5 <= value <= 15

    def test_next_long(self, random):
        value = random.next_long()
        assert isinstance(value, int)

    def test_next_float(self, random):
        value = random.next_float()
        assert isinstance(value, float)
        assert 0.0 <= value < 1.0

    def test_next_double(self, random):
        value = random.next_double()
        assert isinstance(value, float)
        assert 0.0 <= value < 1.0

    def test_uniform(self, random):
        for _ in range(100):
            value = random.uniform(10.0, 20.0)
            assert 10.0 <= value < 20.0

    def test_next_bool(self, random):
        value = random.next_bool()
        assert isinstance(value, bool)

    def test_uuid(self, random):
        uuid_str = random.uuid()
        assert isinstance(uuid_str, str)
        assert len(uuid_str) == 36  # UUID format: 8-4-4-4-12
        assert uuid_str.count('-') == 4

    def test_uuid_unique(self, random):
        uuids = [random.uuid() for _ in range(100)]
        assert len(set(uuids)) == 100  # All unique

    def test_choice(self, random):
        items = ['a', 'b', 'c', 'd', 'e']
        for _ in range(100):
            choice = random.choice(items)
            assert choice in items

    def test_sample(self, random):
        items = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        sample = random.sample(items, 3)
        assert len(sample) == 3
        assert len(set(sample)) == 3  # No duplicates
        for item in sample:
            assert item in items

    def test_shuffle(self, random):
        items = [1, 2, 3, 4, 5]
        original = items.copy()
        random.shuffle(items)
        assert set(items) == set(original)  # Same elements
        # Note: Could be same order by chance, but very unlikely

    def test_shuffled(self, random):
        original = [1, 2, 3, 4, 5]
        shuffled = random.shuffled(original)
        assert original == [1, 2, 3, 4, 5]  # Original unchanged
        assert set(shuffled) == set(original)


class TestEntropyStatus:
    """Test EntropyStatus dataclass."""

    def test_attributes(self, random):
        status = random.get_entropy_status()
        assert hasattr(status, 'level')
        assert hasattr(status, 'is_healthy')
        assert hasattr(status, 'total_generated')
        assert hasattr(status, 'generation_rate')

    def test_repr(self, random):
        status = random.get_entropy_status()
        r = repr(status)
        assert 'EntropyStatus' in r