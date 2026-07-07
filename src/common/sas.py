"""
SAS Numeric Comparison — Out-of-Band Authentication.

After ML-KEM handshake, both parties derive a 6-digit Short
Authentication String from the handshake transcript. The user
visually compares the two numbers. If they match, the channel
is authenticated; if they differ, a MITM attack is detected.

This is the same mechanism used by:
- BLE Secure Connections Numeric Comparison (Core Spec Vol.3 Part H)
- Signal Safety Numbers
- ZRTP Short Authentication String

Security:
- 6 decimal digits = 1,000,000 possible values
- P(false accept) = 1 / 1,000,000 = 0.0001%
- Attacker cannot brute-force: rate-limited by human interaction
"""

import hashlib
from typing import Tuple

from .constants import SAS_DIGITS, SAS_MODULUS


def derive_sas(
    public_key: bytes,
    ciphertext: bytes,
    shared_secret: bytes,
) -> int:
    """
    Derive a 6-digit SAS from the complete handshake transcript.

    The transcript binds all three values, so any MITM
    substitution will produce a different SAS.

    Args:
        public_key:   The peripheral's ML-KEM-768 public key (1184 bytes).
        ciphertext:   The central's ML-KEM-768 ciphertext (1088 bytes).
        shared_secret: The 32-byte ML-KEM shared secret.

    Returns:
        Integer in range [0, 999999] — always zero-padded to 6 digits.
    """
    # Transcript = pk || ct || ss. Any byte difference → different SAS.
    transcript = public_key + ciphertext + shared_secret
    commitment = hashlib.sha256(transcript).digest()

    # First 4 bytes as unsigned big-endian → mod 1,000,000
    sas_raw = int.from_bytes(commitment[:4], byteorder="big")
    sas = sas_raw % SAS_MODULUS

    return sas


def format_sas(sas: int) -> str:
    """Format SAS as zero-padded 6-digit string (e.g. 000042 → '000042')."""
    return str(sas).zfill(SAS_DIGITS)


def verify_sas(local: int, remote: int) -> bool:
    """
    Compare two SAS values. Returns True if they match.

    In practice, the user does this comparison visually.
    This function is for automated testing.
    """
    return local == remote


def derive_both_sas(
    public_key: bytes,
    ciphertext: bytes,
    shared_secret: bytes,
) -> Tuple[int, str]:
    """
    Convenience: derive SAS and return both int and formatted string.
    """
    sas = derive_sas(public_key, ciphertext, shared_secret)
    return sas, format_sas(sas)
