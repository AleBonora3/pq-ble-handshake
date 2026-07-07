"""
MITM Simulation Test.

Proves that SAS Numeric Comparison detects an active attacker
who substitutes the public key during the handshake.
"""

import pytest
from src.common.ml_kem import generate_keypair, encapsulate, decapsulate
from src.common.sas import derive_sas


def test_mitm_detected_via_sas_mismatch():
    """
    Scenario:
    - Peripheral (Alice) generates (pk_A, sk_A)
    - Mallory (MITM) intercepts pk_A, generates (pk_M, sk_M)
    - Central (Bob) receives pk_M (not pk_A!) and encapsulates against it
    - Mallory decapsulates, re-encapsulates against real pk_A
    - Alice and Bob compute different shared secrets → different SAS
    """

    # ── Alice (Peripheral): generates keypair ───────────────
    pk_A, sk_A = generate_keypair()

    # ── Mallory (MITM): generates her own keypair ───────────
    pk_M, sk_M = generate_keypair()

    # ── Bob (Central): receives pk_M (Mallory's key!) ───────
    # Bob thinks he's talking to Alice
    ct_MB, ss_Bob_Mallory = encapsulate(pk_M)

    # ── Mallory: decapsulates Bob's ciphertext ──────────────
    ss_Mallory_Bob = decapsulate(sk_M, ct_MB)
    assert ss_Mallory_Bob == ss_Bob_Mallory  # Mallory shares Bob's secret

    # Mallory re-encapsulates to Alice's real key
    ct_MA, ss_Mallory_Alice = encapsulate(pk_A)

    # ── Alice: receives ct_MA (Mallory's ciphertext) ────────
    ss_Alice_Mallory = decapsulate(sk_A, ct_MA)

    # Mallory can decrypt Alice's messages
    assert ss_Alice_Mallory == ss_Mallory_Alice

    # ── THE TRAP: SAS MISMATCH ──────────────────────────────

    # Alice computes SAS with her transcript
    sas_alice = derive_sas(pk_A, ct_MA, ss_Alice_Mallory)

    # Bob computes SAS with his transcript (different pk!)
    sas_bob = derive_sas(pk_M, ct_MB, ss_Bob_Mallory)

    # These MUST be different — MITM detected!
    assert sas_alice != sas_bob, (
        f"❌ MITM NOT DETECTED! Both SAS = {sas_alice}. "
        "The protocol is vulnerable!"
    )

    print(f"   Alice SAS: {sas_alice:06d}")
    print(f"   Bob SAS:   {sas_bob:06d}")
    print(f"   ✅ MITM detected successfully — SAS mismatch!")


def test_honest_handshake_sas_matches():
    """Without MITM, SAS must match."""
    pk_A, sk_A = generate_keypair()

    # Honest central
    ct, ss_c = encapsulate(pk_A)
    ss_p = decapsulate(sk_A, ct)

    sas_c = derive_sas(pk_A, ct, ss_c)
    sas_p = derive_sas(pk_A, ct, ss_p)

    assert sas_c == sas_p, (
        f"❌ SAS mismatch in honest handshake! "
        f"Central={sas_c:06d} Peripheral={sas_p:06d}"
    )