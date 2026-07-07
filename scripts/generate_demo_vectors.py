#!/usr/bin/env python3
"""
Generate precomputed ML-KEM-768 demo vectors for the nRF54L15 firmware.

This script generates:
  - pk_A:  ML-KEM-768 public key (1184 bytes) → hardcoded in firmware
  - ct:    ML-KEM-768 ciphertext (1088 bytes) → written by PC central
  - ss:    shared secret (32 bytes) → used to derive session_key
  - session_key: AES-256 key (32 bytes) → derived via HKDF
  - encrypted_payload: AES-256-GCM ciphertext → sent via GATT NOTIFY

Output: C header snippets to paste into firmware/nrf54l15_pq_gatt_skeleton/src/main.c

Usage:
    python scripts/generate_demo_vectors.py
"""

import sys
import os

# Ensure src is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.common.ml_kem import generate_keypair, encapsulate
from src.common.session import derive_session_key, SecureChannel
from src.common.constants import (
    PK_SIZE, CT_SIZE, SS_SIZE,
    CENTRAL_ROLE, PERIPHERAL_ROLE,
)


def bytes_to_c_array(name: str, data: bytes, indent: str = "    ") -> str:
    """Format bytes as a C array initializer."""
    lines = []
    lines.append(f"static uint8_t {name}[{len(data)}] = {{")
    # 12 bytes per line
    for i in range(0, len(data), 12):
        chunk = data[i:i+12]
        hex_vals = ", ".join(f"0x{b:02X}" for b in chunk)
        if i + 12 < len(data):
            lines.append(f"{indent}{hex_vals},")
        else:
            lines.append(f"{indent}{hex_vals}")
    lines.append("};")
    return "\n".join(lines)


def main():
    print("=" * 60)
    print("PQ-BLE Demo Vector Generator (DEMO_PRECOMPUTED_KEM)")
    print("=" * 60)

    # 1. Generate ML-KEM-768 keypair
    print("\n1. Generating ML-KEM-768 keypair...")
    pk, sk = generate_keypair()
    assert len(pk) == PK_SIZE, f"pk size {len(pk)} != {PK_SIZE}"
    print(f"   pk: {len(pk)} bytes ✓")
    print(f"   sk: {len(sk)} bytes ✓")

    # 2. Encapsulate (simulating what the PC central will do)
    print("\n2. Encapsulating (simulating PC central)...")
    ct, ss = encapsulate(pk)
    assert len(ct) == CT_SIZE, f"ct size {len(ct)} != {CT_SIZE}"
    assert len(ss) == SS_SIZE, f"ss size {len(ss)} != {SS_SIZE}"
    print(f"   ct: {len(ct)} bytes ✓")
    print(f"   ss: {len(ss)} bytes ✓")

    # 3. Derive session key
    print("\n3. Deriving session key via HKDF-SHA256...")
    session_key = derive_session_key(ss)
    print(f"   session_key: {len(session_key)} bytes ✓")

    # 4. Generate session ID
    from src.common.session import generate_session_id
    session_id = generate_session_id()
    print(f"   session_id: {session_id.hex()}")

    # 5. Create peripheral-side SecureChannel and encrypt a demo message
    print("\n4. Encrypting demo payload (peripheral → central)...")
    demo_message = b"Hello from nRF54L15 DK!"
    chan_p = SecureChannel(session_key, session_id=session_id, role=PERIPHERAL_ROLE)
    encrypted_payload = chan_p.encrypt(demo_message)
    print(f"   plaintext: {demo_message!r}")
    print(f"   encrypted: {len(encrypted_payload)} bytes")
    print(f"   wire format: seq(8) + msg_type(1) + iv(12) + ct({len(demo_message)}) + tag(16) = {8+1+12+len(demo_message)+16}")

    # 6. Verify decryption (simulating PC central)
    chan_c = SecureChannel(session_key, session_id=session_id, role=CENTRAL_ROLE)
    decrypted = chan_c.decrypt(encrypted_payload)
    assert decrypted == demo_message
    print(f"   decrypt verification: ✓")

    # 7. Output C arrays
    print("\n" + "=" * 60)
    print("C ARRAYS — paste into firmware/nrf54l15_pq_gatt_skeleton/src/main.c")
    print("=" * 60)

    print("\n/* Replace demo_pk[] with: */")
    print(bytes_to_c_array("demo_pk", pk))

    print("\n/* Replace demo_notify_payload[] with: */")
    print(bytes_to_c_array("demo_notify_payload", encrypted_payload))

    print("\n/* Optional: set expected_ct[] to validate written ciphertext: */")
    print(bytes_to_c_array("expected_ct", ct))

    # 8. Also output JSON for reference
    import json
    vectors = {
        "pk_hex": pk.hex(),
        "sk_hex": sk.hex(),
        "ct_hex": ct.hex(),
        "ss_hex": ss.hex(),
        "session_key_hex": session_key.hex(),
        "session_id_hex": session_id.hex(),
        "demo_message": demo_message.decode(),
        "encrypted_payload_hex": encrypted_payload.hex(),
    }
    vectors_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "data", "demo_vectors.json"
    )
    os.makedirs(os.path.dirname(vectors_path), exist_ok=True)
    with open(vectors_path, "w") as f:
        json.dump(vectors, f, indent=2)
    print(f"\nJSON vectors saved to: {vectors_path}")

    print("\n" + "=" * 60)
    print("DONE. Replace the placeholder arrays in main.c with the output above.")
    print("=" * 60)


if __name__ == "__main__":
    main()
