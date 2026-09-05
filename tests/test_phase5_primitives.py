"""Known-answer and invariant tests for the authenticated v0.5 primitives."""

import pytest

from src.common.constants import (
    CENTRAL_ROLE,
    CT_SIZE,
    FINISHED_SIZE,
    PHASE5_DATA_REQUEST,
    PHASE5_DOMAIN,
    PHASE5_FINISHED_C,
    PHASE5_FINISHED_P,
    PHASE5_FRAME_VERSION,
    PHASE5_READY_FOR_SAS,
    PERIPHERAL_ROLE,
    PK_SIZE,
)
from src.common.phase5 import (
    Phase5CentralState,
    Phase5CentralStateMachine,
    Phase5StateError,
    build_phase5_transcript,
    compute_finished_c,
    compute_finished_p,
    compute_phase5_sas,
    compute_phase5_transcript_hash,
    derive_phase5_keys,
    encode_phase5_frame,
    format_phase5_sas,
    parse_phase5_frame,
    verify_finished,
)


SS = bytes(range(32))
SESSION_ID = bytes(range(16))
PUBLIC_KEY = bytes(i % 256 for i in range(PK_SIZE))
CIPHERTEXT = bytes((255 - i) % 256 for i in range(CT_SIZE))

EXPECTED_TRANSCRIPT_HASH = bytes.fromhex(
    "ab2b371cd864a2cbef41c9939fb7c358"
    "bef64da4f1ad2c5e73e8e761e9c738fc"
)
EXPECTED_APPLICATION_KEY = bytes.fromhex(
    "b08985586f6da81e1253aef6dfba5a9e"
    "7384d25986cb923df1d4ae56ae11b607"
)
EXPECTED_SAS_KEY = bytes.fromhex(
    "0ce91a5cef213ec8b4802700dca235e9"
    "064a9af13ff55ff82fbea5fb9da0bf6c"
)
EXPECTED_FINISHED_C_KEY = bytes.fromhex(
    "1dbd910489517311b9381bfe856e3783"
    "14ed2bb0768427e33ba4d3785fe8c696"
)
EXPECTED_FINISHED_P_KEY = bytes.fromhex(
    "eaf95e983336df2f21f268233adcded6"
    "a0368faf99fbb85a2b78b0422f17d505"
)
EXPECTED_FINISHED_C = bytes.fromhex(
    "95696b9fe113fe1285f1298c090970a4"
    "3fdf4b86dedf7c3812b711521c8e2b7d"
)
EXPECTED_FINISHED_P = bytes.fromhex(
    "c2583b0874b81aa07be4f06d1280d931"
    "a67d0d2ca73d466f78b3b41b72a5d616"
)


def _decode_fields(transcript: bytes) -> list[bytes]:
    fields = []
    offset = 0
    while offset < len(transcript):
        length = int.from_bytes(transcript[offset:offset + 2], "big")
        offset += 2
        fields.append(transcript[offset:offset + length])
        offset += length
    assert offset == len(transcript)
    return fields


def test_canonical_transcript_serialization():
    transcript = build_phase5_transcript(
        SESSION_ID, PUBLIC_KEY, CIPHERTEXT
    )

    assert len(transcript) == 2323
    assert _decode_fields(transcript) == [
        PHASE5_DOMAIN,
        CENTRAL_ROLE,
        PERIPHERAL_ROLE,
        SESSION_ID,
        PUBLIC_KEY,
        CIPHERTEXT,
    ]
    assert transcript[:2] == len(PHASE5_DOMAIN).to_bytes(2, "big")


@pytest.mark.parametrize(
    "session_id,public_key,ciphertext,name",
    [
        (SESSION_ID[:-1], PUBLIC_KEY, CIPHERTEXT, "session_id"),
        (SESSION_ID, PUBLIC_KEY[:-1], CIPHERTEXT, "public_key"),
        (SESSION_ID, PUBLIC_KEY, CIPHERTEXT[:-1], "ciphertext"),
    ],
)
def test_canonical_transcript_rejects_wrong_sizes(
    session_id, public_key, ciphertext, name
):
    with pytest.raises(ValueError, match=name):
        build_phase5_transcript(session_id, public_key, ciphertext)


def test_transcript_hash_known_answer():
    assert compute_phase5_transcript_hash(
        SESSION_ID, PUBLIC_KEY, CIPHERTEXT
    ) == EXPECTED_TRANSCRIPT_HASH


def test_key_schedule_known_answer_and_exact_split():
    keys = derive_phase5_keys(SS, EXPECTED_TRANSCRIPT_HASH)

    assert keys.application == EXPECTED_APPLICATION_KEY
    assert keys.sas == EXPECTED_SAS_KEY
    assert keys.finished_c == EXPECTED_FINISHED_C_KEY
    assert keys.finished_p == EXPECTED_FINISHED_P_KEY
    assert all(
        len(value) == 32
        for value in (
            keys.application,
            keys.sas,
            keys.finished_c,
            keys.finished_p,
        )
    )


def test_sas_known_answer_and_leading_zero_format():
    assert compute_phase5_sas(
        EXPECTED_SAS_KEY, EXPECTED_TRANSCRIPT_HASH
    ) == 587494
    assert format_phase5_sas(42) == "000042"
    assert format_phase5_sas(0) == "000000"


def test_same_secret_and_transcript_produce_same_sas():
    keys_a = derive_phase5_keys(SS, EXPECTED_TRANSCRIPT_HASH)
    keys_b = derive_phase5_keys(SS, EXPECTED_TRANSCRIPT_HASH)
    assert compute_phase5_sas(
        keys_a.sas, EXPECTED_TRANSCRIPT_HASH
    ) == compute_phase5_sas(keys_b.sas, EXPECTED_TRANSCRIPT_HASH)


def test_transcript_change_changes_all_authentication_material():
    modified_ct = bytearray(CIPHERTEXT)
    modified_ct[-1] ^= 1
    modified_hash = compute_phase5_transcript_hash(
        SESSION_ID, PUBLIC_KEY, bytes(modified_ct)
    )
    original_keys = derive_phase5_keys(SS, EXPECTED_TRANSCRIPT_HASH)
    modified_keys = derive_phase5_keys(SS, modified_hash)

    assert modified_hash != EXPECTED_TRANSCRIPT_HASH
    assert modified_keys.application != original_keys.application
    assert modified_keys.sas != original_keys.sas
    assert modified_keys.finished_c != original_keys.finished_c
    assert modified_keys.finished_p != original_keys.finished_p
    assert compute_finished_c(
        modified_keys.finished_c, modified_hash
    ) != EXPECTED_FINISHED_C
    assert compute_finished_p(
        modified_keys.finished_p, modified_hash
    ) != EXPECTED_FINISHED_P


def test_finished_known_answers_and_modified_value_rejected():
    assert compute_finished_c(
        EXPECTED_FINISHED_C_KEY, EXPECTED_TRANSCRIPT_HASH
    ) == EXPECTED_FINISHED_C
    assert compute_finished_p(
        EXPECTED_FINISHED_P_KEY, EXPECTED_TRANSCRIPT_HASH
    ) == EXPECTED_FINISHED_P

    modified = bytearray(EXPECTED_FINISHED_P)
    modified[-1] ^= 1
    modified_c = bytearray(EXPECTED_FINISHED_C)
    modified_c[0] ^= 1
    assert verify_finished(EXPECTED_FINISHED_P, EXPECTED_FINISHED_P)
    assert not verify_finished(EXPECTED_FINISHED_P, bytes(modified))
    assert not verify_finished(EXPECTED_FINISHED_C, bytes(modified_c))
    assert not verify_finished(EXPECTED_FINISHED_P, b"short")


def test_phase5_cli_is_explicit_and_mutually_exclusive():
    from src.central.main import parse_args

    args = parse_args(["--phase5-auth-pq"])
    assert args.phase5_auth_pq
    assert args.phase5_negative is None
    assert not args.phase2_e2e
    assert not args.phase3_secure
    negative_args = parse_args(
        ["--phase5-auth-pq", "--phase5-negative", "finished-c"]
    )
    assert negative_args.phase5_negative == "finished-c"
    with pytest.raises(SystemExit):
        parse_args(["--phase5-auth-pq", "--phase3-secure"])


def test_phase5_frame_known_layout_and_strict_parse():
    frame = encode_phase5_frame(PHASE5_FINISHED_C, EXPECTED_FINISHED_C)
    assert frame == (
        b"PQS5"
        + bytes((PHASE5_FRAME_VERSION, PHASE5_FINISHED_C))
        + FINISHED_SIZE.to_bytes(2, "big")
        + EXPECTED_FINISHED_C
    )
    assert parse_phase5_frame(frame).payload == EXPECTED_FINISHED_C


@pytest.mark.parametrize(
    "frame",
    [
        b"PQS5",
        b"NOPE\x05\x01\x00\x00",
        b"PQS5\x04\x01\x00\x00",
        b"PQS5\x05\x01\x00\x01",
        b"PQS5\x05\x01\x00\x00extra",
    ],
)
def test_phase5_frame_rejects_malformed_values(frame):
    with pytest.raises(ValueError):
        parse_phase5_frame(frame)


def test_phase5_state_rejects_finished_before_sas_confirmation():
    machine = Phase5CentralStateMachine()
    machine.start(SESSION_ID)
    with pytest.raises(Phase5StateError, match="invalid in state"):
        machine.confirm_sas(EXPECTED_FINISHED_C)


def test_phase5_state_rejects_duplicate_and_out_of_order_controls():
    machine = Phase5CentralStateMachine()
    machine.start(SESSION_ID)
    ready = parse_phase5_frame(
        encode_phase5_frame(PHASE5_READY_FOR_SAS)
    )
    machine.receive_ready_for_sas(ready)
    with pytest.raises(Phase5StateError, match="invalid in state"):
        machine.receive_ready_for_sas(ready)

    finished_c_frame = machine.confirm_sas(EXPECTED_FINISHED_C)
    assert parse_phase5_frame(finished_c_frame).subtype == PHASE5_FINISHED_C
    finished_p_frame = parse_phase5_frame(
        encode_phase5_frame(PHASE5_FINISHED_P, EXPECTED_FINISHED_P)
    )
    machine.receive_finished_p(finished_p_frame, EXPECTED_FINISHED_P)
    assert machine.state is Phase5CentralState.AUTHENTICATED
    request = parse_phase5_frame(machine.request_application_data())
    assert request.subtype == PHASE5_DATA_REQUEST
    assert request.payload == b""
    with pytest.raises(Phase5StateError, match="invalid in state"):
        machine.request_application_data()
    encode_phase5_frame,
    parse_phase5_frame,
