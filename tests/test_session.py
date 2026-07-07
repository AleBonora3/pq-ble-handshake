"""
Unit tests for session key derivation and AES-256-GCM channel.
"""

import pytest
from src.common.session import derive_session_key, SecureChannel
from src.common.constants import SESSION_KEY_SIZE


def test_derive_session_key_size():
    """Session key must be 32 bytes (AES-256)."""
    ss = b"x" * 32
    session_key = derive_session_key(ss)
    assert len(session_key) == SESSION_KEY_SIZE


def test_derive_session_key_deterministic():
    """Same shared secret → same session key."""
    ss = b"test_shared_secret_32_bytes!!"
    key1 = derive_session_key(ss)
    key2 = derive_session_key(ss)
    assert key1 == key2


def test_derive_session_key_different_inputs():
    """Different input → different key."""
    key1 = derive_session_key(b"a" * 32)
    key2 = derive_session_key(b"b" * 32)
    assert key1 != key2


def test_secure_channel_encrypt_decrypt():
    """Encrypt then decrypt should return original."""
    key = derive_session_key(b"test_shared_secret_32_bytes!!")
    channel = SecureChannel(key)

    plaintext = b"Ciao Alessio! Canale PQ-BLE funzionante."
    wire = channel.encrypt(plaintext)
    decrypted = channel.decrypt(wire)

    assert decrypted == plaintext


def test_secure_channel_wire_format():
    """Wire format should be: seq (8) + IV (12) + ciphertext + tag (16)."""
    key = derive_session_key(b"test_shared_secret_32_bytes!!")
    channel = SecureChannel(key)

    plaintext = b"test"
    wire = channel.encrypt(plaintext)

    # seq(8) + msg_type(1) + iv(12) + plaintext + tag(16)
    assert len(wire) >= 8 + 1 + 12 + len(plaintext) + 16


def test_secure_channel_different_keys_fail():
    """Decrypting with wrong key should fail."""
    key1 = derive_session_key(b"a" * 32)
    key2 = derive_session_key(b"b" * 32)

    channel1 = SecureChannel(key1)
    channel2 = SecureChannel(key2)

    wire = channel1.encrypt(b"test message")
    with pytest.raises(Exception):  # InvalidTag
        channel2.decrypt(wire)


def test_secure_channel_tampered_data():
    """Tampered ciphertext should fail authentication."""
    key = derive_session_key(b"test_shared_secret_32_bytes!!")
    channel = SecureChannel(key)

    wire = bytearray(channel.encrypt(b"original message"))
    # Flip a byte in the ciphertext area (after seq+msg_type+IV = byte 21+)
    wire[25] ^= 0x01

    with pytest.raises(Exception):  # InvalidTag
        channel.decrypt(bytes(wire))


def test_secure_channel_empty_message():
    """Empty message should encrypt and decrypt correctly."""
    key = derive_session_key(b"test_shared_secret_32_bytes!!")
    channel = SecureChannel(key)

    wire = channel.encrypt(b"")
    decrypted = channel.decrypt(wire)
    assert decrypted == b""


def test_secure_channel_large_message():
    """Large message (10KB) should round-trip."""
    import os
    key = derive_session_key(b"test_shared_secret_32_bytes!!")
    channel = SecureChannel(key)

    plaintext = os.urandom(10_000)
    wire = channel.encrypt(plaintext)
    decrypted = channel.decrypt(wire)
    assert decrypted == plaintext


def test_secure_channel_multiple_messages():
    """Multiple messages should encrypt/decrypt independently."""
    key = derive_session_key(b"test_shared_secret_32_bytes!!")
    channel = SecureChannel(key)

    messages = [b"msg1", b"msg2", b"hello world", b"", b"x" * 1000]
    for msg in messages:
        wire = channel.encrypt(msg)
        decrypted = channel.decrypt(wire)
        assert decrypted == msg


def test_secure_channel_counter():
    """Sent/received counters should increment."""
    key = derive_session_key(b"test_shared_secret_32_bytes!!")
    channel = SecureChannel(key)

    for i in range(5):
        wire = channel.encrypt(f"msg{i}".encode())
        channel.decrypt(wire)

    assert channel.sent_count == 5
    assert channel.recv_count == 5


def test_secure_channel_iv_uniqueness():
    """Each encryption should use a different IV."""
    key = derive_session_key(b"test_shared_secret_32_bytes!!")
    channel = SecureChannel(key)

    ivs = set()
    for _ in range(100):
        wire = channel.encrypt(b"test")
        iv = wire[9:21]  # seq(8) + msg_type(1) + iv(12)
        ivs.add(iv)

    # All 100 IVs should be unique
    assert len(ivs) == 100


def test_invalid_key_size():
    """Wrong key size should raise ValueError."""
    with pytest.raises(ValueError, match="must be 32"):
        SecureChannel(b"too_short")


# ── AAD and replay protection tests (new) ──────────────────

def test_secure_channel_replay_detection():
    """Decrypting the same message twice should fail (replay)."""
    from src.common.constants import CENTRAL_ROLE, PERIPHERAL_ROLE

    key = derive_session_key(b"test_shared_secret_32_bytes!!")
    sid = b"\x00" * 16
    chan_c = SecureChannel(key, session_id=sid, role=CENTRAL_ROLE)
    chan_p = SecureChannel(key, session_id=sid, role=PERIPHERAL_ROLE)

    wire = chan_c.encrypt(b"first message")
    assert chan_p.decrypt(wire) == b"first message"

    # Second decrypt of the same wire → replay detected
    with pytest.raises(ValueError, match="Replay"):
        chan_p.decrypt(wire)


def test_secure_channel_out_of_order_rejected():
    """Out-of-order sequence numbers should be rejected."""
    from src.common.constants import CENTRAL_ROLE, PERIPHERAL_ROLE

    key = derive_session_key(b"test_shared_secret_32_bytes!!")
    sid = b"\x00" * 16
    chan_c = SecureChannel(key, session_id=sid, role=CENTRAL_ROLE)
    chan_p = SecureChannel(key, session_id=sid, role=PERIPHERAL_ROLE)

    wire0 = chan_c.encrypt(b"msg0")  # seq=0
    wire1 = chan_c.encrypt(b"msg1")  # seq=1

    # Decrypt wire1 first → accepted (1 > -1)
    assert chan_p.decrypt(wire1) == b"msg1"

    # Now decrypt wire0 → rejected (0 <= 1)
    with pytest.raises(ValueError, match="Replay"):
        chan_p.decrypt(wire0)


def test_secure_channel_aad_direction_separation():
    """A message encrypted by the central cannot be decrypted by another central."""
    from src.common.constants import CENTRAL_ROLE, PERIPHERAL_ROLE

    key = derive_session_key(b"test_shared_secret_32_bytes!!")
    sid = b"\x00" * 16
    chan_c1 = SecureChannel(key, session_id=sid, role=CENTRAL_ROLE)
    chan_c2 = SecureChannel(key, session_id=sid, role=CENTRAL_ROLE)

    wire = chan_c1.encrypt(b"reflection attack test")

    # c2's peer_role is PERIPHERAL, but wire was encrypted with CENTRAL role
    # → AAD mismatch → InvalidTag
    with pytest.raises(Exception):  # InvalidTag
        chan_c2.decrypt(wire)


def test_secure_channel_aad_session_binding():
    """Messages bound to session A cannot be decrypted with session B."""
    from src.common.constants import CENTRAL_ROLE, PERIPHERAL_ROLE

    key = derive_session_key(b"test_shared_secret_32_bytes!!")
    sid_a = b"\xAA" * 16
    sid_b = b"\xBB" * 16
    chan_c = SecureChannel(key, session_id=sid_a, role=CENTRAL_ROLE)
    chan_p = SecureChannel(key, session_id=sid_b, role=PERIPHERAL_ROLE)

    wire = chan_c.encrypt(b"cross-session test")

    # p expects sid_b in AAD, but wire has sid_a → InvalidTag
    with pytest.raises(Exception):  # InvalidTag
        chan_p.decrypt(wire)


def test_secure_channel_bidirectional_with_roles():
    """Central→Peripheral and Peripheral→Central with proper AAD roles."""
    from src.common.constants import CENTRAL_ROLE, PERIPHERAL_ROLE
    from src.common.session import generate_session_id

    key = derive_session_key(b"test_shared_secret_32_bytes!!")
    sid = generate_session_id()
    chan_c = SecureChannel(key, session_id=sid, role=CENTRAL_ROLE)
    chan_p = SecureChannel(key, session_id=sid, role=PERIPHERAL_ROLE)

    # Central → Peripheral
    wire = chan_c.encrypt(b"Hello from central!")
    assert chan_p.decrypt(wire) == b"Hello from central!"

    # Peripheral → Central
    wire = chan_p.encrypt(b"Hello from peripheral!")
    assert chan_c.decrypt(wire) == b"Hello from peripheral!"


def test_secure_channel_seq_in_wire():
    """First 8 bytes of wire data should contain the sequence number."""
    key = derive_session_key(b"test_shared_secret_32_bytes!!")
    channel = SecureChannel(key)

    wire0 = channel.encrypt(b"first")
    seq0 = int.from_bytes(wire0[:8], "big")
    assert seq0 == 0

    wire1 = channel.encrypt(b"second")
    seq1 = int.from_bytes(wire1[:8], "big")
    assert seq1 == 1


def test_secure_channel_msg_type_in_wire():
    """Wire format should contain msg_type at offset 8."""
    from src.common.constants import MSG_TYPE_DATA, MSG_TYPE_CONTROL

    key = derive_session_key(b"test_shared_secret_32_bytes!!")
    channel = SecureChannel(key)

    wire_data = channel.encrypt(b"data msg", msg_type=MSG_TYPE_DATA)
    assert wire_data[8:9] == MSG_TYPE_DATA

    wire_ctrl = channel.encrypt(b"ctrl msg", msg_type=MSG_TYPE_CONTROL)
    assert wire_ctrl[8:9] == MSG_TYPE_CONTROL


def test_secure_channel_msg_type_mismatch_rejected():
    """Decrypting a DATA message with expected CONTROL type should fail."""
    from src.common.constants import CENTRAL_ROLE, PERIPHERAL_ROLE, MSG_TYPE_DATA, MSG_TYPE_CONTROL

    key = derive_session_key(b"test_shared_secret_32_bytes!!")
    sid = b"\x00" * 16
    chan_c = SecureChannel(key, session_id=sid, role=CENTRAL_ROLE)
    chan_p = SecureChannel(key, session_id=sid, role=PERIPHERAL_ROLE)

    wire = chan_c.encrypt(b"data message", msg_type=MSG_TYPE_DATA)

    # Try to decrypt as CONTROL → should fail
    with pytest.raises(ValueError, match="Message type mismatch"):
        chan_p.decrypt(wire, msg_type=MSG_TYPE_CONTROL)


def test_secure_channel_aad_msg_type_tampering():
    """Tampering msg_type in wire should cause authentication failure."""
    from src.common.constants import CENTRAL_ROLE, PERIPHERAL_ROLE, MSG_TYPE_DATA, MSG_TYPE_CONTROL

    key = derive_session_key(b"test_shared_secret_32_bytes!!")
    sid = b"\x00" * 16
    chan_c = SecureChannel(key, session_id=sid, role=CENTRAL_ROLE)
    chan_p = SecureChannel(key, session_id=sid, role=PERIPHERAL_ROLE)

    wire = bytearray(chan_c.encrypt(b"test", msg_type=MSG_TYPE_DATA))

    # Flip msg_type byte from DATA to CONTROL
    wire[8] = MSG_TYPE_CONTROL[0]

    # Decrypt with default MSG_TYPE_DATA → wire says CONTROL, mismatch
    with pytest.raises(ValueError, match="Message type mismatch"):
        chan_p.decrypt(bytes(wire), msg_type=MSG_TYPE_DATA)

    # Even if we try to decrypt as CONTROL, the AAD won't match
    # because the original encryption used DATA in AAD
    with pytest.raises(Exception):  # InvalidTag
        chan_p.decrypt(bytes(wire), msg_type=MSG_TYPE_CONTROL)
