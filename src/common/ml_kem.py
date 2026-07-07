"""
ML-KEM-768 (Kyber) wrapper via liboqs.

Provides a clean Python interface for post-quantum key encapsulation.
ML-KEM-768 is NIST FIPS 203 standard, NIST security category 3
(equivalent to AES-192 brute-force security, ~174-bit quantum security).

Key sizes (ML-KEM-768):
    public key:  1184 bytes
    secret key:  2400 bytes
    ciphertext:  1088 bytes
    shared secret: 32 bytes
"""

from typing import Tuple

import oqs

from .constants import KEM_ALGORITHM


class MLKEM:
    """ML-KEM-768 key encapsulation mechanism."""

    def __init__(self):
        self._kem: oqs.KeyEncapsulation | None = None
        self._secret_key: bytes | None = None

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a new ML-KEM-768 keypair.

        Returns:
            (public_key, secret_key) — 1184 and 2400 bytes respectively.
        """
        self._kem = oqs.KeyEncapsulation(KEM_ALGORITHM)
        pk = self._kem.generate_keypair()
        sk = self._kem.export_secret_key()
        self._secret_key = sk
        return pk, sk

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate a shared secret against the given public key.

        Args:
            public_key: 1184-byte ML-KEM-768 public key.

        Returns:
            (ciphertext, shared_secret) — 1088 and 32 bytes.
        """
        kem = oqs.KeyEncapsulation(KEM_ALGORITHM)
        ciphertext, shared_secret = kem.encap_secret(public_key)
        return ciphertext, shared_secret

    def decapsulate(self, ciphertext: bytes) -> bytes:
        """
        Decapsulate a shared secret using the stored secret key.

        Args:
            ciphertext: 1088-byte ML-KEM-768 ciphertext.

        Returns:
            shared_secret: 32 bytes.

        Raises:
            RuntimeError: If no keypair has been generated yet.
        """
        if self._kem is None or self._secret_key is None:
            raise RuntimeError(
                "No keypair generated. Call generate_keypair() first."
            )
        return self._kem.decap_secret(ciphertext)


# Standalone functions for convenience
def generate_keypair() -> Tuple[bytes, bytes]:
    """Generate ML-KEM-768 keypair. Returns (pk, sk)."""
    kem = oqs.KeyEncapsulation(KEM_ALGORITHM)
    pk = kem.generate_keypair()
    sk = kem.export_secret_key()
    return pk, sk


def encapsulate(public_key: bytes) -> Tuple[bytes, bytes]:
    """Encapsulate against public_key. Returns (ciphertext, shared_secret)."""
    kem = oqs.KeyEncapsulation(KEM_ALGORITHM)
    return kem.encap_secret(public_key)


def decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    """Decapsulate ciphertext with secret_key. Returns shared_secret."""
    kem = oqs.KeyEncapsulation(KEM_ALGORITHM, secret_key=secret_key)
    return kem.decap_secret(ciphertext)