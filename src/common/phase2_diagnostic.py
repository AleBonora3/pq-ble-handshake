"""Phase 2 ML-KEM interoperability diagnostic wire format.

The checksum in this module is a TEST-ONLY shared-secret diagnostic checksum.
It is not authentication, not a KDF, not cryptographic key confirmation, and
not part of the final protocol. The ML-KEM shared secret itself is never put
on the wire.
"""

from dataclasses import dataclass
import struct
import zlib

from .constants import SS_SIZE


PHASE2_DIAGNOSTIC_MAGIC = b"PQM2"
PHASE2_DIAGNOSTIC_SIZE = 9

PHASE2_STATUS_SUCCESS = 0x00
PHASE2_STATUS_KEYPAIR_UNAVAILABLE = 0x01
PHASE2_STATUS_CIPHERTEXT_INCOMPLETE = 0x02
PHASE2_STATUS_INTERNAL_FAILURE = 0x03
PHASE2_STATUS_INVALID_STATE = 0x04

PHASE2_STATUS_NAMES = {
    PHASE2_STATUS_SUCCESS: "success",
    PHASE2_STATUS_KEYPAIR_UNAVAILABLE: "keypair unavailable",
    PHASE2_STATUS_CIPHERTEXT_INCOMPLETE: "ciphertext incomplete",
    PHASE2_STATUS_INTERNAL_FAILURE: "internal decapsulation failure",
    PHASE2_STATUS_INVALID_STATE: "invalid protocol state",
}


@dataclass(frozen=True)
class Phase2Diagnostic:
    """Decoded nine-byte Phase 2 diagnostic result."""

    status: int
    checksum: int


def shared_secret_diagnostic_checksum(shared_secret: bytes) -> int:
    """Return the TEST-ONLY CRC-32/IEEE diagnostic for a shared secret."""
    shared_secret = bytes(shared_secret)
    if len(shared_secret) != SS_SIZE:
        raise ValueError(
            f"Shared secret size mismatch: expected {SS_SIZE}, "
            f"got {len(shared_secret)}"
        )
    return zlib.crc32(shared_secret) & 0xFFFFFFFF


def encode_phase2_diagnostic(status: int, checksum: int) -> bytes:
    """Encode ``PQM2 || status || checksum_be32`` for tests and tooling."""
    if not 0 <= status <= 0xFF:
        raise ValueError(f"Status is not a byte: {status}")
    if not 0 <= checksum <= 0xFFFFFFFF:
        raise ValueError(f"Checksum is not a uint32: {checksum}")
    return PHASE2_DIAGNOSTIC_MAGIC + bytes((status,)) + struct.pack(
        ">I", checksum
    )


def parse_phase2_diagnostic(data: bytes) -> Phase2Diagnostic:
    """Strictly decode an exact nine-byte Phase 2 diagnostic result."""
    data = bytes(data)
    if len(data) != PHASE2_DIAGNOSTIC_SIZE:
        raise ValueError(
            "Malformed PQM2 diagnostic length: "
            f"expected {PHASE2_DIAGNOSTIC_SIZE}, got {len(data)}"
        )
    if data[:4] != PHASE2_DIAGNOSTIC_MAGIC:
        raise ValueError(
            "Malformed PQM2 diagnostic magic: "
            f"expected {PHASE2_DIAGNOSTIC_MAGIC!r}, got {data[:4]!r}"
        )
    return Phase2Diagnostic(
        status=data[4],
        checksum=struct.unpack(">I", data[5:9])[0],
    )
