"""Central Phase 5 orchestration tests with a deterministic mock DK."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from src.central.phase5_auth import (
    PHASE5_EXPECTED_PLAINTEXT,
    Phase5AuthError,
    Phase5AuthResult,
    Phase5NegativeTestPassed,
    _mismatched_local_session_id,
    _tamper_finished_copy,
    run_phase5_auth_pq,
)
from src.common.constants import (
    CT_SIZE,
    MSG_TYPE_DATA,
    PERIPHERAL_ROLE,
    PHASE5_DATA_REQUEST,
    PHASE5_ERROR,
    PHASE5_FINISHED_C,
    PHASE5_FINISHED_P,
    PHASE5_READY_FOR_SAS,
    PHASE5_START_MAGIC,
    PK_SIZE,
    SESSION_ID_SIZE,
    SS_SIZE,
)
from src.common.phase5 import (
    compute_finished_c,
    compute_finished_p,
    compute_phase5_sas,
    compute_phase5_transcript_hash,
    derive_phase5_keys,
    encode_phase5_frame,
    parse_phase5_frame,
    verify_finished,
)
from src.common.session import SecureChannel


PUBLIC_KEY = bytes(i % 256 for i in range(PK_SIZE))
CIPHERTEXT = bytes((255 - i) % 256 for i in range(CT_SIZE))
SHARED_SECRET = bytes(range(SS_SIZE))
SESSION_ID = bytes(range(SESSION_ID_SIZE))


class Phase5MockClient:
    def __init__(self, *, tamper_finished_p: bool = False):
        self.is_connected = True
        self.callback = None
        self.calls = []
        self.tamper_finished_p = tamper_finished_p
        self.authenticated = False
        self.data_request_received = False
        transcript_hash = compute_phase5_transcript_hash(
            SESSION_ID, PUBLIC_KEY, CIPHERTEXT
        )
        self.keys = derive_phase5_keys(SHARED_SECRET, transcript_hash)
        self.sas = compute_phase5_sas(self.keys.sas, transcript_hash)
        self.finished_c = compute_finished_c(
            self.keys.finished_c, transcript_hash
        )
        self.finished_p = compute_finished_p(
            self.keys.finished_p, transcript_hash
        )

    async def start_notify(self, callback):
        self.calls.append("subscribe")
        self.callback = callback

    async def stop_notify(self):
        self.calls.append("unsubscribe")

    async def read_fragmented_public_key(self):
        self.calls.append("read_pk")
        return PUBLIC_KEY

    async def write_fragmented_ciphertext(self, ciphertext):
        self.calls.append(("ciphertext", bytes(ciphertext)))

    async def send_control(self, data):
        data = bytes(data)
        self.calls.append(("control", data))
        if data.startswith(PHASE5_START_MAGIC):
            self.callback(
                1,
                bytearray(encode_phase5_frame(PHASE5_READY_FOR_SAS)),
            )
            return

        frame = parse_phase5_frame(data)
        if frame.subtype == PHASE5_FINISHED_C:
            if not verify_finished(self.finished_c, frame.payload):
                self.callback(
                    1,
                    bytearray(encode_phase5_frame(PHASE5_ERROR, b"\x06")),
                )
                return
            self.authenticated = True
            finished_p = bytearray(self.finished_p)
            if self.tamper_finished_p:
                finished_p[-1] ^= 1
            self.callback(
                1,
                bytearray(
                    encode_phase5_frame(
                        PHASE5_FINISHED_P, bytes(finished_p)
                    )
                ),
            )
        elif frame.subtype == PHASE5_DATA_REQUEST:
            self.data_request_received = True
            if not self.authenticated:
                self.callback(
                    1,
                    bytearray(encode_phase5_frame(PHASE5_ERROR, b"\x04")),
                )
                return
            peripheral_channel = SecureChannel(
                self.keys.application,
                session_id=SESSION_ID,
                role=PERIPHERAL_ROLE,
            )
            wire = peripheral_channel.encrypt(
                PHASE5_EXPECTED_PLAINTEXT,
                msg_type=MSG_TYPE_DATA,
            )
            self.callback(1, bytearray(wire))


@pytest.mark.asyncio
async def test_phase5_positive_flow_orders_finished_before_data():
    client = Phase5MockClient()
    with (
        patch(
            "src.central.phase5_auth.encapsulate",
            return_value=(CIPHERTEXT, SHARED_SECRET),
        ),
        patch(
            "src.central.phase5_auth.generate_session_id",
            return_value=SESSION_ID,
        ),
    ):
        result = await run_phase5_auth_pq(
            client, sas_callback=lambda _sas: True
        )

    assert result.plaintext == PHASE5_EXPECTED_PLAINTEXT
    controls = [
        call[1]
        for call in client.calls
        if isinstance(call, tuple) and call[0] == "control"
    ]
    assert controls[0] == PHASE5_START_MAGIC + SESSION_ID
    finished_c_frame = parse_phase5_frame(controls[1])
    assert finished_c_frame.subtype == PHASE5_FINISHED_C
    assert finished_c_frame.payload == client.finished_c
    assert parse_phase5_frame(controls[2]).subtype == PHASE5_DATA_REQUEST
    assert client.authenticated
    assert client.data_request_received
    assert client.calls[-1] == "unsubscribe"


@pytest.mark.asyncio
async def test_sas_rejection_sends_no_finished_or_data_request():
    client = Phase5MockClient()
    with (
        patch(
            "src.central.phase5_auth.encapsulate",
            return_value=(CIPHERTEXT, SHARED_SECRET),
        ),
        patch(
            "src.central.phase5_auth.generate_session_id",
            return_value=SESSION_ID,
        ),
        pytest.raises(Phase5AuthError, match="SAS rejected"),
    ):
        await run_phase5_auth_pq(
            client, sas_callback=lambda _sas: False
        )

    controls = [
        call[1]
        for call in client.calls
        if isinstance(call, tuple) and call[0] == "control"
    ]
    assert controls == [PHASE5_START_MAGIC + SESSION_ID]
    assert client.calls[-1] == "unsubscribe"


@pytest.mark.asyncio
async def test_modified_finished_p_prevents_data_activation():
    client = Phase5MockClient(tamper_finished_p=True)
    with (
        patch(
            "src.central.phase5_auth.encapsulate",
            return_value=(CIPHERTEXT, SHARED_SECRET),
        ),
        patch(
            "src.central.phase5_auth.generate_session_id",
            return_value=SESSION_ID,
        ),
        pytest.raises(Phase5AuthError, match="FINISHED verification failed"),
    ):
        await run_phase5_auth_pq(
            client, sas_callback=lambda _sas: True
        )

    controls = [
        parse_phase5_frame(call[1]).subtype
        for call in client.calls
        if (
            isinstance(call, tuple)
            and call[0] == "control"
            and call[1].startswith(b"PQS5")
        )
    ]
    assert controls == [PHASE5_FINISHED_C]
    assert not client.data_request_received


def test_negative_helpers_change_exactly_one_requested_bit():
    valid_finished = bytes(range(32))
    tampered_finished = _tamper_finished_copy(valid_finished)
    assert valid_finished == bytes(range(32))
    assert tampered_finished[:-1] == valid_finished[:-1]
    assert tampered_finished[-1] == (valid_finished[-1] ^ 0x01)

    mismatched_session = _mismatched_local_session_id(SESSION_ID)
    assert mismatched_session[0] == (SESSION_ID[0] ^ 0x01)
    assert mismatched_session[1:] == SESSION_ID[1:]
    assert SESSION_ID == bytes(range(SESSION_ID_SIZE))

    correct_hash = compute_phase5_transcript_hash(
        SESSION_ID, PUBLIC_KEY, CIPHERTEXT
    )
    mismatched_hash = compute_phase5_transcript_hash(
        mismatched_session, PUBLIC_KEY, CIPHERTEXT
    )
    assert mismatched_hash != correct_hash


@pytest.mark.asyncio
async def test_finished_c_negative_flips_valid_value_and_is_not_authenticated():
    client = Phase5MockClient()
    with (
        patch(
            "src.central.phase5_auth.encapsulate",
            return_value=(CIPHERTEXT, SHARED_SECRET),
        ),
        patch(
            "src.central.phase5_auth.generate_session_id",
            return_value=SESSION_ID,
        ),
        pytest.raises(
            Phase5NegativeTestPassed,
            match="tampered FINISHED_C rejected by Peripheral",
        ),
    ):
        await run_phase5_auth_pq(
            client,
            sas_callback=lambda _sas: True,
            negative_test="finished-c",
        )

    controls = [
        call[1]
        for call in client.calls
        if isinstance(call, tuple) and call[0] == "control"
    ]
    assert controls[0] == PHASE5_START_MAGIC + SESSION_ID
    sent_finished_c = parse_phase5_frame(controls[1])
    assert sent_finished_c.subtype == PHASE5_FINISHED_C
    assert sent_finished_c.payload[:-1] == client.finished_c[:-1]
    assert sent_finished_c.payload[-1] == (client.finished_c[-1] ^ 0x01)
    assert len(controls) == 2
    assert not client.authenticated
    assert not client.data_request_received


@pytest.mark.asyncio
async def test_finished_p_negative_tampers_local_copy_and_prevents_data_request():
    client = Phase5MockClient()
    original_finished_p = client.finished_p
    with (
        patch(
            "src.central.phase5_auth.encapsulate",
            return_value=(CIPHERTEXT, SHARED_SECRET),
        ),
        patch(
            "src.central.phase5_auth.generate_session_id",
            return_value=SESSION_ID,
        ),
        patch(
            "src.central.phase5_auth._tamper_finished_copy",
            wraps=_tamper_finished_copy,
        ) as tamper,
        pytest.raises(
            Phase5NegativeTestPassed,
            match="tampered FINISHED_P rejected by Central",
        ),
    ):
        await run_phase5_auth_pq(
            client,
            sas_callback=lambda _sas: True,
            negative_test="finished-p",
        )

    tamper.assert_called_once_with(original_finished_p)
    assert client.finished_p == original_finished_p
    assert client.authenticated
    assert not client.data_request_received


@pytest.mark.asyncio
async def test_transcript_negative_changes_only_local_session_and_sas_rejects():
    client = Phase5MockClient()
    central_sas = []

    def reject_sas(sas):
        central_sas.append(sas)
        return False

    with (
        patch(
            "src.central.phase5_auth.encapsulate",
            return_value=(CIPHERTEXT, SHARED_SECRET),
        ),
        patch(
            "src.central.phase5_auth.generate_session_id",
            return_value=SESSION_ID,
        ),
        pytest.raises(
            Phase5NegativeTestPassed,
            match="transcript mismatch detected by SAS",
        ),
    ):
        await run_phase5_auth_pq(
            client,
            sas_callback=reject_sas,
            negative_test="transcript",
        )

    controls = [
        call[1]
        for call in client.calls
        if isinstance(call, tuple) and call[0] == "control"
    ]
    assert controls == [PHASE5_START_MAGIC + SESSION_ID]
    assert central_sas != [f"{client.sas:06d}"]
    assert not client.authenticated
    assert not client.data_request_received


@pytest.mark.asyncio
async def test_transcript_negative_forced_continuation_rejects_finished_c():
    client = Phase5MockClient()
    with (
        patch(
            "src.central.phase5_auth.encapsulate",
            return_value=(CIPHERTEXT, SHARED_SECRET),
        ),
        patch(
            "src.central.phase5_auth.generate_session_id",
            return_value=SESSION_ID,
        ),
        pytest.raises(
            Phase5NegativeTestPassed,
            match="transcript-bound FINISHED_C rejected by Peripheral",
        ),
    ):
        await run_phase5_auth_pq(
            client,
            sas_callback=lambda _sas: True,
            negative_test="transcript",
        )

    assert not client.authenticated
    assert not client.data_request_received


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mode,message",
    [
        (
            "finished-c",
            "NEGATIVE TEST PASS: tampered FINISHED_C rejected by Peripheral",
        ),
        (
            "finished-p",
            "NEGATIVE TEST PASS: tampered FINISHED_P rejected by Central",
        ),
        (
            "transcript",
            "NEGATIVE TEST PASS: transcript mismatch detected by SAS",
        ),
    ],
)
async def test_negative_cli_expected_rejection_returns_zero(
    mode, message, capsys
):
    from src.central import main as central_main

    client = Phase5MockClient()
    client.scan_and_connect = AsyncMock(return_value=True)
    client.disconnect = AsyncMock()
    args = SimpleNamespace(device="PQ-BLE-Device", phase5_negative=mode)

    with (
        patch.object(central_main, "BLECentralClient", return_value=client),
        patch.object(
            central_main,
            "run_phase5_auth_pq",
            new=AsyncMock(side_effect=Phase5NegativeTestPassed(message)),
        ) as runner,
    ):
        assert await central_main._run_phase5_auth_pq_cli(args) == 0

    runner.assert_awaited_once_with(client, negative_test=mode)
    output = capsys.readouterr().out
    assert message in output
    assert "PQ-BLE PHASE5 NEGATIVE TEST: PASS" in output


@pytest.mark.asyncio
async def test_negative_cli_acceptance_returns_nonzero(capsys):
    from src.central import main as central_main

    client = Phase5MockClient()
    client.scan_and_connect = AsyncMock(return_value=True)
    client.disconnect = AsyncMock()
    args = SimpleNamespace(
        device="PQ-BLE-Device", phase5_negative="finished-c"
    )

    with (
        patch.object(central_main, "BLECentralClient", return_value=client),
        patch.object(
            central_main,
            "run_phase5_auth_pq",
            new=AsyncMock(
                return_value=Phase5AuthResult(
                    plaintext=PHASE5_EXPECTED_PLAINTEXT,
                    wire_size=58,
                    sas="000000",
                )
            ),
        ),
    ):
        assert await central_main._run_phase5_auth_pq_cli(args) == 1

    output = capsys.readouterr().out
    assert "NEGATIVE TEST FAIL" in output
    assert "PQ-BLE PHASE5 NEGATIVE TEST: FAIL" in output
