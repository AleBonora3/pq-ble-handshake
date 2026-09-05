"""Primitive tests for the v0.6 bidirectional secure channel."""

import pytest
from cryptography.exceptions import InvalidTag

from src.common.constants import (
    CENTRAL_ROLE,
    MSG_TYPE_DATA,
    PERIPHERAL_ROLE,
)
from src.common.phase6 import (
    PHASE6_TRAFFIC_KEY_SIZE,
    derive_phase6_traffic_keys,
    PHASE6_C2P_ACK,
    PHASE6_ERROR,
    encode_phase6_frame,
    parse_phase6_frame,
)
from src.common.session import SecureChannel


K_APP = bytes.fromhex(
    "b08985586f6da81e1253aef6dfba5a9e"
    "7384d25986cb923df1d4ae56ae11b607"
)

EXPECTED_C2P = bytes.fromhex(
    "ba857ba945534bbf1af230ba1790302e"
    "afdc00e34a4e4a2a95742f684bc22fb5"
)

EXPECTED_P2C = bytes.fromhex(
    "7b4242c83ecbf501ad2ea0326b83f3d"
    "dee776e88bed76422670e1de287b9e543"
)

SESSION_ID = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f"
)


def test_phase6_rejects_wrong_application_root_key_size():
    for invalid_size in (0, 1, 31, 33, 64):
        with pytest.raises(ValueError):
            derive_phase6_traffic_keys(bytes(invalid_size))


def test_phase6_traffic_key_sizes():
    keys = derive_phase6_traffic_keys(K_APP)

    assert len(keys.central_to_peripheral) == PHASE6_TRAFFIC_KEY_SIZE
    assert len(keys.peripheral_to_central) == PHASE6_TRAFFIC_KEY_SIZE


def test_phase6_directional_keys_are_different():
    keys = derive_phase6_traffic_keys(K_APP)

    assert keys.central_to_peripheral != keys.peripheral_to_central


def test_phase6_derivation_is_deterministic():
    first = derive_phase6_traffic_keys(K_APP)
    second = derive_phase6_traffic_keys(K_APP)

    assert first == second


def test_phase6_c2p_known_answer_vector():
    keys = derive_phase6_traffic_keys(K_APP)

    assert keys.central_to_peripheral == EXPECTED_C2P


def test_phase6_p2c_known_answer_vector():
    keys = derive_phase6_traffic_keys(K_APP)

    assert keys.peripheral_to_central == EXPECTED_P2C


def test_phase6_root_key_bit_change_changes_both_directional_keys():
    changed_root = bytearray(K_APP)
    changed_root[0] ^= 0x01

    original = derive_phase6_traffic_keys(K_APP)
    changed = derive_phase6_traffic_keys(bytes(changed_root))

    assert (
        original.central_to_peripheral
        != changed.central_to_peripheral
    )
    assert (
        original.peripheral_to_central
        != changed.peripheral_to_central
    )


def test_phase6_c2p_secure_channel_interoperability():
    keys = derive_phase6_traffic_keys(K_APP)

    central_tx = SecureChannel(
        keys.central_to_peripheral,
        session_id=SESSION_ID,
        role=CENTRAL_ROLE,
    )

    peripheral_rx = SecureChannel(
        keys.central_to_peripheral,
        session_id=SESSION_ID,
        role=PERIPHERAL_ROLE,
    )

    wire = central_tx.encrypt(
        b"PING 0",
        msg_type=MSG_TYPE_DATA,
    )

    plaintext = peripheral_rx.decrypt(
        wire,
        msg_type=MSG_TYPE_DATA,
    )

    assert plaintext == b"PING 0"
    assert central_tx.sent_count == 1
    assert peripheral_rx.recv_count == 1


def test_phase6_p2c_secure_channel_interoperability():
    keys = derive_phase6_traffic_keys(K_APP)

    peripheral_tx = SecureChannel(
        keys.peripheral_to_central,
        session_id=SESSION_ID,
        role=PERIPHERAL_ROLE,
    )

    central_rx = SecureChannel(
        keys.peripheral_to_central,
        session_id=SESSION_ID,
        role=CENTRAL_ROLE,
    )

    wire = peripheral_tx.encrypt(
        b"PONG 0",
        msg_type=MSG_TYPE_DATA,
    )

    plaintext = central_rx.decrypt(
        wire,
        msg_type=MSG_TYPE_DATA,
    )

    assert plaintext == b"PONG 0"
    assert peripheral_tx.sent_count == 1
    assert central_rx.recv_count == 1


def test_phase6_wrong_direction_key_rejected():
    keys = derive_phase6_traffic_keys(K_APP)

    central_tx = SecureChannel(
        keys.central_to_peripheral,
        session_id=SESSION_ID,
        role=CENTRAL_ROLE,
    )

    wrong_peripheral_rx = SecureChannel(
        keys.peripheral_to_central,
        session_id=SESSION_ID,
        role=PERIPHERAL_ROLE,
    )

    wire = central_tx.encrypt(b"PING 0")

    with pytest.raises(InvalidTag):
        wrong_peripheral_rx.decrypt(wire)


def test_phase6_replay_rejected():
    keys = derive_phase6_traffic_keys(K_APP)

    central_tx = SecureChannel(
        keys.central_to_peripheral,
        session_id=SESSION_ID,
        role=CENTRAL_ROLE,
    )

    peripheral_rx = SecureChannel(
        keys.central_to_peripheral,
        session_id=SESSION_ID,
        role=PERIPHERAL_ROLE,
    )

    wire = central_tx.encrypt(b"PING 0")

    assert peripheral_rx.decrypt(wire) == b"PING 0"

    with pytest.raises(ValueError, match="Replay|replay|out-of-order"):
        peripheral_rx.decrypt(wire)


def test_phase6_directional_sequence_spaces_both_start_at_zero():
    keys = derive_phase6_traffic_keys(K_APP)

    central_tx = SecureChannel(
        keys.central_to_peripheral,
        session_id=SESSION_ID,
        role=CENTRAL_ROLE,
    )

    peripheral_tx = SecureChannel(
        keys.peripheral_to_central,
        session_id=SESSION_ID,
        role=PERIPHERAL_ROLE,
    )

    c2p_wire = central_tx.encrypt(b"PING 0")
    p2c_wire = peripheral_tx.encrypt(b"PONG 0")

    c2p_seq = int.from_bytes(c2p_wire[:8], "big")
    p2c_seq = int.from_bytes(p2c_wire[:8], "big")

    assert c2p_seq == 0
    assert p2c_seq == 0

def test_phase6_ack_frame_roundtrip():
    encoded = encode_phase6_frame(
        PHASE6_C2P_ACK
    )

    assert encoded == (
        b"PQS6"
        b"\x06"
        b"\x01"
        b"\x00\x00"
    )

    decoded = parse_phase6_frame(
        encoded
    )

    assert decoded.subtype == PHASE6_C2P_ACK
    assert decoded.payload == b""


def test_phase6_error_frame_roundtrip():
    encoded = encode_phase6_frame(
        PHASE6_ERROR,
        b"\x06",
    )

    decoded = parse_phase6_frame(
        encoded
    )

    assert decoded.subtype == PHASE6_ERROR
    assert decoded.payload == b"\x06"


@pytest.mark.parametrize(
    "frame",
    [
        b"",
        b"PQS6",
        b"BAD!\x06\x01\x00\x00",
        b"PQS6\x05\x01\x00\x00",
        b"PQS6\x06\x01\x00\x01",
        b"PQS6\x06\x01\x00\x00\x00",
    ],
)
def test_phase6_frame_parser_rejects_malformed_frames(
    frame,
):
    with pytest.raises(ValueError):
        parse_phase6_frame(frame)


def test_phase6_cli_mode_is_parsed():
    from src.central.main import parse_args

    args = parse_args(
        ["--phase6-c2p"]
    )

    assert args.phase6_c2p is True
    assert args.phase5_auth_pq is False
    assert args.phase3_secure is False
    assert args.phase2_e2e is False