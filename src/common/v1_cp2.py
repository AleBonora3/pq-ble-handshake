"""TEST ONLY: v1 CP2 interoperability diagnostic; not FINISHED or a KDF.

No application authentication, traffic keys, SAS, ECDH or SMP key exporter.
Only mutable buffers owned here can be explicitly cleared; Python and its
cryptographic libraries do not promise erasure of internal/immutable copies.
"""

import hashlib
import hmac

from .constants import CT_SIZE, PK_SIZE, SS_SIZE
from .v1_smp_mlkem import V1_CP2_DIAGNOSTIC_LABEL, V1_CP2_SESSION_ID_SIZE


def clear(buffer: bytearray) -> None:
    buffer[:] = b"\x00" * len(buffer)


def compute_diagnostic(
    shared_secret: bytearray, session_id: bytes, public_key: bytes, ciphertext: bytes,
) -> bytearray:
    """HMAC-SHA256(SS, label || session_id || SHA256(PK || CT)). TEST ONLY."""
    if (len(shared_secret) != SS_SIZE or len(session_id) != V1_CP2_SESSION_ID_SIZE
            or len(public_key) != PK_SIZE or len(ciphertext) != CT_SIZE):
        raise ValueError("invalid CP2 diagnostic input length")
    digest = bytearray(hashlib.sha256(public_key + ciphertext).digest())
    try:
        return bytearray(hmac.digest(
            shared_secret, V1_CP2_DIAGNOSTIC_LABEL + session_id + digest, "sha256",
        ))
    finally:
        clear(digest)
