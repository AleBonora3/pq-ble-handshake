"""
Integration test: full handshake without BLE (mock GATT).

Tests the complete protocol pipeline:
ML-KEM keygen → encapsulate → decapsulate → SAS → HKDF → AES-GCM
"""

import pytest
from src.common.ml_kem import generate_keypair, encapsulate, decapsulate
from src.common.sas import derive_sas
from src.common.session import (
    derive_session_key,
    SecureChannel,
    generate_session_id,
)
from src.common.constants import CENTRAL_ROLE, PERIPHERAL_ROLE


def test_full_handshake_pipeline():
    """
    Simulate a complete handshake between a peripheral and central.
    No BLE involved — pure protocol test.
    """
    # ── Peripheral: key generation ──────────────────────────
    pk, sk = generate_keypair()

    # ── Central: encapsulate ───────────────────────────────
    ct, ss_central = encapsulate(pk)

    # ── Peripheral: decapsulate ────────────────────────────
    ss_peripheral = decapsulate(sk, ct)

    # Shared secrets must match
    assert ss_central == ss_peripheral

    # ── SAS: both derive independently ─────────────────────
    sas_central = derive_sas(pk, ct, ss_central)
    sas_peripheral = derive_sas(pk, ct, ss_peripheral)

    assert sas_central == sas_peripheral, "SAS must match"
    assert 0 <= sas_central <= 999999, "SAS must be 6 digits"

    # ── Session key derivation ─────────────────────────────
    key_central = derive_session_key(ss_central)
    key_peripheral = derive_session_key(ss_peripheral)
    assert key_central == key_peripheral

    # ── Secure channel (with AAD: session_id + role + seq) ─
    session_id = generate_session_id()
    chan_central = SecureChannel(key_central, session_id=session_id,
                                 role=CENTRAL_ROLE)
    chan_peripheral = SecureChannel(key_peripheral, session_id=session_id,
                                    role=PERIPHERAL_ROLE)

    # Test bidirectional communication
    msg_c_to_p = b"Hello from central!"
    wire = chan_central.encrypt(msg_c_to_p)
    decrypted = chan_peripheral.decrypt(wire)
    assert decrypted == msg_c_to_p

    msg_p_to_c = b"Hello from peripheral!"
    wire = chan_peripheral.encrypt(msg_p_to_c)
    decrypted = chan_central.decrypt(wire)
    assert decrypted == msg_p_to_c


def test_full_handshake_100_iterations():
    """Stress test: 100 full handshakes."""
    for i in range(100):
        pk, sk = generate_keypair()
        ct, ss_c = encapsulate(pk)
        ss_p = decapsulate(sk, ct)
        assert ss_c == ss_p, f"Iteration {i}: ss mismatch"

        sas_c = derive_sas(pk, ct, ss_c)
        sas_p = derive_sas(pk, ct, ss_p)
        assert sas_c == sas_p, f"Iteration {i}: sas mismatch"

        key = derive_session_key(ss_c)
        sid = generate_session_id()
        chan_c = SecureChannel(key, session_id=sid, role=CENTRAL_ROLE)
        chan_p = SecureChannel(key, session_id=sid, role=PERIPHERAL_ROLE)

        msg = f"iteration_{i}".encode()
        wire = chan_c.encrypt(msg)
        assert chan_p.decrypt(wire) == msg
