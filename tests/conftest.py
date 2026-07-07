"""
Pytest fixtures for PQ-BLE-HANDSHAKE tests.
"""

import pytest


@pytest.fixture
def sample_public_key():
    """A valid ML-KEM-768 public key (generated at import time)."""
    import oqs
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    pk = kem.generate_keypair()
    return pk


@pytest.fixture
def sample_keypair():
    """Generate a fresh ML-KEM-768 keypair."""
    import oqs
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    pk = kem.generate_keypair()
    sk = kem.export_secret_key()
    return pk, sk


@pytest.fixture
def sample_encapsulation(sample_public_key):
    """Generate ciphertext and shared secret."""
    from src.common.ml_kem import encapsulate
    ct, ss = encapsulate(sample_public_key)
    return ct, ss, sample_public_key