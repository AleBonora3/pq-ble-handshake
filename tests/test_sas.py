"""
Unit tests for SAS Numeric Comparison.
"""

import pytest
from src.common.sas import derive_sas, format_sas, verify_sas


def test_sas_is_6_digits():
    """SAS must be in range [0, 999999]."""
    pk = b"x" * 1184
    ct = b"y" * 1088
    ss = b"z" * 32
    sas = derive_sas(pk, ct, ss)
    assert 0 <= sas <= 999999


def test_format_sas_zero_padded():
    """Small SAS should be zero-padded to 6 digits."""
    # We test the format function directly
    assert format_sas(0) == "000000"
    assert format_sas(42) == "000042"
    assert format_sas(999999) == "999999"


def test_sas_deterministic():
    """Same inputs should always produce the same SAS."""
    pk = b"a" * 1184
    ct = b"b" * 1088
    ss = b"c" * 32
    sas1 = derive_sas(pk, ct, ss)
    sas2 = derive_sas(pk, ct, ss)
    assert sas1 == sas2


def test_sas_different_pk_different_sas():
    """Different public key should produce different SAS."""
    ct = b"x" * 1088
    ss = b"z" * 32
    sas1 = derive_sas(b"a" * 1184, ct, ss)
    sas2 = derive_sas(b"b" * 1184, ct, ss)
    assert sas1 != sas2


def test_sas_different_ct_different_sas():
    """Different ciphertext should produce different SAS."""
    pk = b"x" * 1184
    ss = b"z" * 32
    sas1 = derive_sas(pk, b"a" * 1088, ss)
    sas2 = derive_sas(pk, b"b" * 1088, ss)
    assert sas1 != sas2


def test_sas_different_ss_different_sas():
    """Different shared secret should produce different SAS."""
    pk = b"x" * 1184
    ct = b"y" * 1088
    sas1 = derive_sas(pk, ct, b"a" * 32)
    sas2 = derive_sas(pk, ct, b"b" * 32)
    assert sas1 != sas2


def test_sas_different_size_inputs_work():
    """The SAS function should accept correct-sized inputs."""
    pk = b"x" * 1184
    ct = b"y" * 1088
    ss = b"z" * 32
    sas = derive_sas(pk, ct, ss)
    assert isinstance(sas, int)


def test_sas_distribution():
    """SAS values should be reasonably distributed across range."""
    sas_values = set()
    for i in range(100):
        pk = bytes([i % 256] * 1184)
        ct = bytes([(i * 7) % 256] * 1088)
        ss = bytes([(i * 13) % 256] * 32)
        sas = derive_sas(pk, ct, ss)
        sas_values.add(sas)
    # With 100 iterations, we should see > 90 unique values
    assert len(sas_values) > 90, f"Only {len(sas_values)} unique SAS values"


def test_verify_sas_match():
    """Matching SAS should verify."""
    assert verify_sas(123456, 123456) is True


def test_verify_sas_mismatch():
    """Mismatched SAS should not verify."""
    assert verify_sas(123456, 654321) is False


def test_format_sas_length():
    """Formatted SAS must always be 6 characters."""
    for sas in [0, 1, 42, 999, 123456, 999999]:
        formatted = format_sas(sas)
        assert len(formatted) == 6
        assert formatted.isdigit()


def test_sas_modulus_wrap():
    """Values at the edge of modulus should be handled correctly."""
    pk = bytes([0xFF] * 1184)
    ct = bytes([0xFF] * 1088)
    ss = bytes([0xFF] * 32)
    sas = derive_sas(pk, ct, ss)
    assert 0 <= sas <= 999999
