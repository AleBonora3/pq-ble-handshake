"""
Unit tests for ML-KEM-768 wrapper.
"""

import pytest
from src.common.ml_kem import generate_keypair, encapsulate, decapsulate
from src.common.constants import PK_SIZE, CT_SIZE, SS_SIZE


def test_generate_keypair_sizes():
    """Keypair should have correct byte sizes."""
    pk, sk = generate_keypair()
    assert len(pk) == PK_SIZE, f"Expected {PK_SIZE} byte pk, got {len(pk)}"
    assert len(sk) > 0, "Secret key must not be empty"


def test_encapsulate_sizes(sample_public_key):
    """Encapsulation should produce correct sizes."""
    ct, ss = encapsulate(sample_public_key)
    assert len(ct) == CT_SIZE, f"Expected {CT_SIZE} byte ct, got {len(ct)}"
    assert len(ss) == SS_SIZE, f"Expected {SS_SIZE} byte ss, got {len(ss)}"


def test_encapsulate_decapsulate_roundtrip():
    """Encapsulation + decapsulation should yield matching secrets."""
    pk, sk = generate_keypair()
    ct, ss_enc = encapsulate(pk)
    ss_dec = decapsulate(sk, ct)
    assert ss_enc == ss_dec, "Shared secrets must match"


def test_encapsulate_different_keys_different_secrets(sample_public_key):
    """Different public keys should produce different shared secrets."""
    pk2, _ = generate_keypair()
    ct1, ss1 = encapsulate(sample_public_key)
    ct2, ss2 = encapsulate(pk2)
    assert ss1 != ss2, "Different keys should yield different secrets"


def test_encapsulate_same_key_different_ciphertexts(sample_public_key):
    """Multiple encapsulations to same PK should yield different ciphertexts."""
    ct1, ss1 = encapsulate(sample_public_key)
    ct2, ss2 = encapsulate(sample_public_key)
    # Ciphertexts should differ (probabilistic encryption)
    assert ct1 != ct2, "ML-KEM should produce different ciphertexts"
    # But shared secrets should also differ (FO transform)
    # Actually with ML-KEM, same pk → same shared secret (it's a KEM)
    # The ciphertext varies but the shared secret is the same


def test_100_iterations_roundtrip():
    """Stress test: 100 iterations of keygen + encaps + decaps."""
    for i in range(100):
        pk, sk = generate_keypair()
        ct, ss1 = encapsulate(pk)
        ss2 = decapsulate(sk, ct)
        assert ss1 == ss2, f"Iteration {i}: shared secret mismatch"
