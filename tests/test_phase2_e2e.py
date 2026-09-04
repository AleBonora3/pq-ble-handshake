"""Focused tests for the Central-only Phase 2 BLE flow."""

from types import SimpleNamespace
from threading import Thread
from unittest.mock import AsyncMock, patch

import pytest

from src.central.mlkem_e2e import (
    Phase2E2EError,
    Phase2E2EResult,
    run_phase2_e2e,
)
from src.common.constants import CT_SIZE, PK_SIZE, SS_SIZE
from src.common.phase2_diagnostic import (
    PHASE2_STATUS_CIPHERTEXT_INCOMPLETE,
    PHASE2_STATUS_SUCCESS,
    encode_phase2_diagnostic,
    shared_secret_diagnostic_checksum,
)


class Phase2MockClient:
    def __init__(self, response=None, public_key=None):
        self.is_connected = True
        self.public_key = public_key if public_key is not None else bytes(PK_SIZE)
        self.response = response
        self.callback = None
        self.ciphertext = None
        self.calls = []

    async def start_notify(self, callback):
        self.calls.append("subscribe")
        self.callback = callback

    async def read_fragmented_public_key(self):
        self.calls.append("read_pk")
        return self.public_key

    async def write_fragmented_ciphertext(self, ciphertext):
        self.calls.append("write_ct")
        self.ciphertext = bytes(ciphertext)

    async def send_control(self, value):
        self.calls.append(("control", bytes(value)))
        if self.response is not None:
            self.callback(1, bytearray(self.response))

    async def stop_notify(self):
        self.calls.append("unsubscribe")


class ThreadedNotificationMockClient(Phase2MockClient):
    """Deliver the Bleak-style callback from a foreign thread."""

    async def send_control(self, value):
        self.calls.append(("control", bytes(value)))
        thread = Thread(
            target=self.callback,
            args=(1, bytearray(self.response)),
        )
        thread.start()
        thread.join()


@pytest.mark.asyncio
async def test_phase2_flow_order_and_matching_result():
    shared_secret = bytes(SS_SIZE)
    checksum = shared_secret_diagnostic_checksum(shared_secret)
    client = Phase2MockClient(
        encode_phase2_diagnostic(PHASE2_STATUS_SUCCESS, checksum)
    )
    ciphertext = b"C" * CT_SIZE

    with patch(
        "src.central.mlkem_e2e.encapsulate",
        return_value=(ciphertext, shared_secret),
    ) as encapsulate_mock:
        result = await run_phase2_e2e(client)

    assert result.matches
    assert result.central_checksum == 0x190A55AD
    assert result.peripheral_checksum == 0x190A55AD
    assert client.ciphertext == ciphertext
    assert client.calls == [
        "subscribe",
        "read_pk",
        "write_ct",
        ("control", b"START"),
        "unsubscribe",
    ]
    encapsulate_mock.assert_called_once_with(client.public_key)


@pytest.mark.asyncio
async def test_phase2_accepts_notification_from_foreign_thread():
    shared_secret = bytes(SS_SIZE)
    checksum = shared_secret_diagnostic_checksum(shared_secret)
    client = ThreadedNotificationMockClient(
        encode_phase2_diagnostic(PHASE2_STATUS_SUCCESS, checksum)
    )

    with patch(
        "src.central.mlkem_e2e.encapsulate",
        return_value=(bytes(CT_SIZE), shared_secret),
    ):
        result = await run_phase2_e2e(client)

    assert result.matches
    assert client.calls[-1] == "unsubscribe"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response, message",
    [
        (b"short", "length"),
        (b"WRNG\x00\x19\x0a\x55\xad", "magic"),
        (
            encode_phase2_diagnostic(
                PHASE2_STATUS_CIPHERTEXT_INCOMPLETE, 0
            ),
            "non-success PQM2 status 0x02",
        ),
        (
            encode_phase2_diagnostic(PHASE2_STATUS_SUCCESS, 0xDEADBEEF),
            "shared-secret mismatch",
        ),
        (
            encode_phase2_diagnostic(0x7F, 0),
            "non-success PQM2 status 0x7F",
        ),
    ],
)
async def test_phase2_rejects_response_errors(response, message):
    client = Phase2MockClient(response)
    with patch(
        "src.central.mlkem_e2e.encapsulate",
        return_value=(bytes(CT_SIZE), bytes(SS_SIZE)),
    ):
        with pytest.raises(Phase2E2EError, match=message):
            await run_phase2_e2e(client)
    assert client.calls[-1] == "unsubscribe"


@pytest.mark.asyncio
async def test_phase2_timeout_is_failure_and_unsubscribes():
    client = Phase2MockClient(response=None)
    with patch(
        "src.central.mlkem_e2e.encapsulate",
        return_value=(bytes(CT_SIZE), bytes(SS_SIZE)),
    ):
        with pytest.raises(Phase2E2EError, match="Timed out"):
            await run_phase2_e2e(client, notification_timeout=0.001)
    assert client.calls[-1] == "unsubscribe"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "public_key,ciphertext,shared_secret,message",
    [
        (bytes(PK_SIZE - 1), bytes(CT_SIZE), bytes(SS_SIZE), "Public key"),
        (bytes(PK_SIZE), bytes(CT_SIZE - 1), bytes(SS_SIZE), "Ciphertext"),
        (bytes(PK_SIZE), bytes(CT_SIZE), bytes(SS_SIZE - 1), "Shared secret"),
    ],
)
async def test_phase2_rejects_crypto_size_mismatches(
    public_key, ciphertext, shared_secret, message
):
    client = Phase2MockClient(public_key=public_key)
    with patch(
        "src.central.mlkem_e2e.encapsulate",
        return_value=(ciphertext, shared_secret),
    ):
        with pytest.raises(Phase2E2EError, match=message):
            await run_phase2_e2e(client)
    assert client.calls[-1] == "unsubscribe"


def test_phase2_cli_flag_is_explicit_and_not_demo():
    from src.central.main import parse_args

    args = parse_args(["--phase2-e2e"])
    assert args.phase2_e2e
    assert not args.demo


def test_phase2_and_legacy_demo_are_mutually_exclusive():
    from src.central.main import parse_args

    with pytest.raises(SystemExit):
        parse_args(["--phase2-e2e", "--demo"])


@pytest.mark.asyncio
async def test_main_phase2_branch_bypasses_session_store():
    from src.central import main as central_main

    args = SimpleNamespace(
        device="PQ-BLE-Device",
        demo=False,
        phase2_e2e=True,
        mtu=None,
        log_level="INFO",
    )
    with (
        patch.object(central_main, "parse_args", return_value=args),
        patch.object(central_main, "setup_logging"),
        patch.object(
            central_main,
            "_run_phase2_e2e_cli",
            new=AsyncMock(return_value=0),
        ) as phase2_cli,
        patch.object(central_main, "_load_legacy_components") as load_legacy,
    ):
        assert await central_main.main() == 0

    phase2_cli.assert_awaited_once_with(args)
    load_legacy.assert_not_called()


class Phase2CliMockClient:
    def __init__(self):
        self.disconnected = False

    async def scan_and_connect(self, timeout):
        return True

    async def disconnect(self):
        self.disconnected = True


@pytest.mark.asyncio
async def test_phase2_cli_returns_nonzero_on_protocol_failure(capsys):
    from src.central import main as central_main

    client = Phase2CliMockClient()
    args = SimpleNamespace(device="PQ-BLE-Device")
    with (
        patch.object(central_main, "BLECentralClient", return_value=client),
        patch.object(
            central_main,
            "run_phase2_e2e",
            new=AsyncMock(side_effect=Phase2E2EError("bad PQM2 result")),
        ),
    ):
        assert await central_main._run_phase2_e2e_cli(args) == 1

    assert "ML-KEM E2E SHARED SECRET MATCH: NO" in capsys.readouterr().out
    assert client.disconnected


@pytest.mark.asyncio
async def test_phase2_cli_success_output_and_zero_exit(capsys):
    from src.central import main as central_main

    client = Phase2CliMockClient()
    args = SimpleNamespace(device="PQ-BLE-Device")
    result = Phase2E2EResult(0x190A55AD, 0x190A55AD)
    with (
        patch.object(central_main, "BLECentralClient", return_value=client),
        patch.object(
            central_main,
            "run_phase2_e2e",
            new=AsyncMock(return_value=result),
        ),
    ):
        assert await central_main._run_phase2_e2e_cli(args) == 0

    output = capsys.readouterr().out
    assert "Central TEST-ONLY shared-secret diagnostic checksum: 0x190A55AD" in output
    assert "Peripheral TEST-ONLY shared-secret diagnostic checksum: 0x190A55AD" in output
    assert "ML-KEM E2E SHARED SECRET MATCH: YES" in output
    assert client.disconnected
