import pytest

from src.common.constants import (
    PK_SIZE,
    CT_SIZE,
    SESSION_KEY_SIZE,
    SESSION_ID_SIZE,
    FRAGMENT_HEADER_SIZE,
    RESUME_OK_NOTIFY,
    SECURE_CHANNEL_OVERHEAD,
)
from src.common.fragmentation import fragment_data
from src.common.session import (
    SecureChannel,
    build_resume_request,
)


@pytest.mark.parametrize("payload_size", [0, 20, 64, 256, 512, 1024])
def test_secure_channel_has_fixed_37_byte_overhead(payload_size):
    session_key = b"\x11" * SESSION_KEY_SIZE
    channel = SecureChannel(session_key)

    plaintext = b"x" * payload_size
    wire = channel.encrypt(plaintext)

    assert len(wire) == payload_size + SECURE_CHANNEL_OVERHEAD
    assert SECURE_CHANNEL_OVERHEAD == 37


def test_full_handshake_application_material_mtu_247():
    ciphertext = b"x" * CT_SIZE
    fragments = fragment_data(ciphertext, mtu=247)

    assert len(fragments) == 5

    ciphertext_wire_size = sum(len(fragment) for fragment in fragments)

    assert ciphertext_wire_size == (
        CT_SIZE + len(fragments) * FRAGMENT_HEADER_SIZE
    )
    assert ciphertext_wire_size == 1108

    total_application_material = PK_SIZE + ciphertext_wire_size
    assert total_application_material == 2292


def test_resume_control_material_size():
    session_id = b"\x22" * SESSION_ID_SIZE

    request = build_resume_request(session_id)
    response = RESUME_OK_NOTIFY

    assert len(request) == 21
    assert len(response) == 9
    assert len(request) + len(response) == 30