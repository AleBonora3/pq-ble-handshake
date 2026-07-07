"""
Unit tests for GATT fragmentation protocol.
"""

import pytest
from src.common.fragmentation import fragment_data, reassemble_data, Fragment


def test_fragment_tiny_data():
    """Data smaller than MTU should produce a single fragment."""
    data = b"hello"
    fragments = fragment_data(data, mtu=512)
    assert len(fragments) == 1
    assert reassemble_data(fragments) == data


def test_fragment_exact_one_packet():
    """Data exactly filling one fragment."""
    data = b"x" * 508  # 512 - 4 header
    fragments = fragment_data(data, mtu=512)
    assert len(fragments) == 1
    assert len(fragments[0]) == 512
    assert reassemble_data(fragments) == data


def test_fragment_two_packets():
    """Data spanning exactly two fragments."""
    data = b"x" * 509  # 1 byte over
    fragments = fragment_data(data, mtu=512)
    assert len(fragments) == 2
    assert reassemble_data(fragments) == data


def test_fragment_ml_kem_public_key_size():
    """ML-KEM-768 public key: 1184 bytes → ceil(1184/508) = 3 fragments."""
    data = b"x" * 1184
    fragments = fragment_data(data, mtu=512)
    assert len(fragments) == 3
    assert reassemble_data(fragments) == data


def test_fragment_ml_kem_ciphertext_size():
    """ML-KEM-768 ciphertext: 1088 bytes → ceil(1088/508) = 3 fragments."""
    data = b"x" * 1088
    fragments = fragment_data(data, mtu=512)
    assert len(fragments) == 3
    assert reassemble_data(fragments) == data


def test_fragment_large_data():
    """Test with 10KB of random data."""
    import os
    data = os.urandom(10_000)
    fragments = fragment_data(data, mtu=512)
    assert len(fragments) == 20  # ceil(10000/508)
    assert reassemble_data(fragments) == data


def test_fragment_boundary_exact():
    """Fragment exactly at boundary."""
    data = b"x" * 1016  # 2 * 508
    fragments = fragment_data(data, mtu=512)
    assert len(fragments) == 2
    assert reassemble_data(fragments) == data


def test_reassemble_wrong_order():
    """Reassembly should work regardless of fragment order."""
    import os
    data = os.urandom(2000)
    fragments = fragment_data(data, mtu=512)
    # Reverse order
    assert reassemble_data(list(reversed(fragments))) == data


def test_reassemble_missing_fragment():
    """Missing fragment should raise ValueError."""
    data = b"x" * 2000
    fragments = fragment_data(data, mtu=512)
    with pytest.raises(ValueError, match="Missing fragments"):
        reassemble_data(fragments[:-1])


def test_reassemble_duplicate_fragment():
    """Duplicate fragment should raise ValueError."""
    data = b"x" * 2000
    fragments = fragment_data(data, mtu=512)
    with pytest.raises(ValueError, match="Duplicate"):
        reassemble_data(fragments + [fragments[0]])


def test_reassemble_empty():
    """Empty fragment list should raise ValueError."""
    with pytest.raises(ValueError, match="No fragments"):
        reassemble_data([])


def test_fragment_decode_invalid():
    """Corrupted fragment should raise on decode."""
    with pytest.raises(ValueError, match="too short"):
        Fragment.decode(b"abc")  # 3 bytes < 4 header


def test_fragment_empty_data():
    """Empty data should produce single empty fragment."""
    fragments = fragment_data(b"", mtu=512)
    assert len(fragments) == 1
    assert reassemble_data(fragments) == b""


def test_different_mtu_sizes():
    """Test with different MTU values."""
    data = b"x" * 500
    for mtu in [100, 200, 512]:
        fragments = fragment_data(data, mtu=mtu)
        assert reassemble_data(fragments) == data
        # Each fragment must be ≤ mtu
        for f in fragments:
            assert len(f) <= mtu
