from src.common.constants import (
    CENTRAL_ROLE,
    PERIPHERAL_ROLE,
    MSG_TYPE_DATA,
)
from src.common.phase7 import (
    PHASE7_START7_AUTH,
    PHASE7_READY7_AUTH,
    PHASE7_FINISHED_C,
    PHASE7_FINISHED_P,
    PHASE7_START7_AUTH_FRAME_SIZE,
    PHASE7_READY7_AUTH_FRAME_SIZE,
    PHASE7_FINISHED_FRAME_SIZE,
    derive_phase7_traffic_keys,
)
from src.common.session import SecureChannel


K_APP = bytes.fromhex(
    "2ccee2ee74d05015fb3d0f4fbae67114"
    "155849544ccb997a7f4753cb0f9345e2"
)

EXPECTED_C2P = bytes.fromhex(
    "07279ad8c5a44e75471d72af386cc19e"
    "ef94e0bb546fdd139b720d7cfc1dcf26"
)

EXPECTED_P2C = bytes.fromhex(
    "e9fe283d7b24bac9a3b66d9a8c31e79"
    "a9aa6f0f2eef165e5db316650889a9219"
)

SESSION_ID = bytes(range(16))


def test_phase7_cp3_subtypes_are_frozen():
    assert PHASE7_START7_AUTH == 0x03
    assert PHASE7_READY7_AUTH == 0x04
    assert PHASE7_FINISHED_C == 0x05
    assert PHASE7_FINISHED_P == 0x06


def test_phase7_cp3_frame_sizes_are_frozen():
    assert PHASE7_START7_AUTH_FRAME_SIZE == 89
    assert PHASE7_READY7_AUTH_FRAME_SIZE == 73
    assert PHASE7_FINISHED_FRAME_SIZE == 40


def test_phase7_directional_key_kat():
    keys = derive_phase7_traffic_keys(
        K_APP
    )

    assert (
        keys.central_to_peripheral ==
        EXPECTED_C2P
    )

    assert (
        keys.peripheral_to_central ==
        EXPECTED_P2C
    )


def test_phase7_three_bidirectional_round_trips():
    keys = derive_phase7_traffic_keys(
        K_APP
    )

    central_c2p = SecureChannel(
        keys.central_to_peripheral,
        session_id=SESSION_ID,
        role=CENTRAL_ROLE,
    )

    peripheral_c2p = SecureChannel(
        keys.central_to_peripheral,
        session_id=SESSION_ID,
        role=PERIPHERAL_ROLE,
    )

    peripheral_p2c = SecureChannel(
        keys.peripheral_to_central,
        session_id=SESSION_ID,
        role=PERIPHERAL_ROLE,
    )

    central_p2c = SecureChannel(
        keys.peripheral_to_central,
        session_id=SESSION_ID,
        role=CENTRAL_ROLE,
    )

    for index in range(3):
        ping = f"PING {index}".encode()
        pong = f"PONG {index}".encode()

        c2p_wire = central_c2p.encrypt(
            ping,
            msg_type=MSG_TYPE_DATA,
        )

        assert len(c2p_wire) == 43
        assert (
            int.from_bytes(
                c2p_wire[:8],
                "big",
            ) ==
            index
        )

        assert (
            peripheral_c2p.decrypt(
                c2p_wire,
                msg_type=MSG_TYPE_DATA,
            ) ==
            ping
        )

        p2c_wire = peripheral_p2c.encrypt(
            pong,
            msg_type=MSG_TYPE_DATA,
        )

        assert len(p2c_wire) == 43
        assert (
            int.from_bytes(
                p2c_wire[:8],
                "big",
            ) ==
            index
        )

        assert (
            central_p2c.decrypt(
                p2c_wire,
                msg_type=MSG_TYPE_DATA,
            ) ==
            pong
        )