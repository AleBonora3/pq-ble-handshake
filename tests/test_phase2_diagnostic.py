"""Tests for the exact nine-byte Phase 2 diagnostic format."""

import pytest

from src.common.phase2_diagnostic import (
    PHASE2_STATUS_SUCCESS,
    encode_phase2_diagnostic,
    parse_phase2_diagnostic,
    shared_secret_diagnostic_checksum,
)


def test_zero_shared_secret_known_crc32_vector():
    """CRC-32/IEEE(32 zero bytes) is the cross-language test vector."""
    checksum = shared_secret_diagnostic_checksum(bytes(32))
    assert checksum == 0x190A55AD
    assert encode_phase2_diagnostic(PHASE2_STATUS_SUCCESS, checksum) == bytes.fromhex(
        "50 51 4d 32 00 19 0a 55 ad"
    )


def test_parse_uses_big_endian_checksum():
    result = parse_phase2_diagnostic(bytes.fromhex("50 51 4d 32 00 12 34 56 78"))
    assert result.status == PHASE2_STATUS_SUCCESS
    assert result.checksum == 0x12345678


@pytest.mark.parametrize(
    "data", [b"", b"PQM2\x00\x00\x00\x00", b"PQM2" + bytes(6)]
)
def test_parse_rejects_non_exact_length(data):
    with pytest.raises(ValueError, match="length"):
        parse_phase2_diagnostic(data)


def test_parse_rejects_wrong_magic():
    with pytest.raises(ValueError, match="magic"):
        parse_phase2_diagnostic(b"NOPE\x00\x19\x0a\x55\xad")


def test_checksum_rejects_wrong_shared_secret_size():
    with pytest.raises(ValueError, match="Shared secret size mismatch"):
        shared_secret_diagnostic_checksum(bytes(31))
