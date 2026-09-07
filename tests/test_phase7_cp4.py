"""CP4 host validation, not evidence of hardware PASS.

Hardware: python -m src.central.main --phase7-auth-hybrid
          --phase7-negative-test-only MODE
MODE: sas-reject, finished-c, pre-auth, c2p-tamper, c2p-replay,
      p2c-tamper, p2c-replay. P->C mutations are receiver-local.
Capture PC and DK output together; DK's existing cumulative worker-stack
watermarks provide final stack measurements. PC timings include SAS/operator
time and any explicitly labelled negative probes/observation windows.
"""

import asyncio
from dataclasses import astuple
import hmac
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from bleak.exc import (
    BleakDBusError,
    BleakError,
    BleakGATTProtocolError,
)
from cryptography.exceptions import InvalidTag
import pytest

from src.central import main, phase7_auth as runner
from src.common import phase7 as p7
from src.common.constants import CENTRAL_ROLE, MSG_TYPE_DATA, PERIPHERAL_ROLE
from src.common.ml_kem import decapsulate
from src.common.session import SecureChannel
from tests.test_phase7_cp2 import CP2MockClient
from tests.test_phase7_primitives import CENTRAL_PUBLIC_KEY, SESSION_ID


ATT_REJECTED = "Could not write value: Protocol Error 0xFC: Write Request Rejected"
WINRT_ACCESS_DENIED = "Could not write value b'probe' to characteristic 000E: Access Denied"


def winrt_error(hresult):
    # PyWinRT reports failing HRESULTs through OSError.winerror. Set the
    # attribute explicitly so these host tests also run outside Windows.
    error = OSError("The attribute cannot be written")
    error.winerror = hresult
    return error


class CP4MockClient(CP2MockClient):
    """CP2 transport mock extended with real hybrid/FINISHED/GCM processing.

    Faults intentionally violate the expected Peripheral behavior to ensure
    a broken peer, unrelated failure, or lost connection cannot produce PASS.
    This models the firmware state gate; it does not execute the C firmware.
    """

    def __init__(self, keypair):
        super().__init__(keypair)
        self.controls = []
        self.writes = []
        self.accepted = []
        self.responses = []
        self.rejections = []
        self.authenticated = False
        self.fault = None
        self.rejection = "valid"
        self.preauth_error = BleakError(ATT_REJECTED)
        self.preauth_notification = None

    def notify(self, wire):
        self.callback(1, bytearray(wire))

    def reject(self, status):
        self.rejections.append(status)
        wire = p7.encode_phase7_frame(p7.PHASE7_ERROR, bytes((status,)))
        if self.rejection == "silence":
            return
        if self.rejection == "wrong-status":
            wire = p7.encode_phase7_frame(p7.PHASE7_ERROR, b"\x05")
        elif self.rejection == "malformed":
            wire = wire[:-1]
        elif self.rejection == "finished-p":
            wire = p7.encode_phase7_finished_p(self.finished_p)
        elif self.rejection == "data":
            wire = self.tx.encrypt(b"PONG 0")
        elif self.rejection == "disconnect":
            self.is_connected = False
        self.notify(wire)
        if self.rejection == "extra":
            asyncio.get_running_loop().call_later(
                0.002, self.notify, p7.encode_phase7_finished_p(self.finished_p),
            )

    async def send_control(self, data):
        self.controls.append(bytes(data))
        frame = p7.parse_phase7_frame(data)
        if frame.subtype == p7.PHASE7_START7_AUTH:
            self.session_id, central_key = p7.parse_start7_auth(data)
            private_key = p7.generate_p256_private_key()
            peripheral_key = p7.serialize_p256_public_key(private_key)
            self.digest = p7.compute_phase7_transcript_hash(
                self.session_id, self.public_key, self.ciphertext,
                central_key, peripheral_key,
            )
            self.ss_mlkem = decapsulate(self.secret_key, self.ciphertext)
            self.ss_ecdh = p7.derive_p256_ecdh_shared_secret(private_key, central_key)
            self.keys = p7.derive_phase7_keys(self.ss_mlkem, self.ss_ecdh, self.digest)
            self.finished_c = p7.compute_phase7_finished_c(self.keys.finished_c, self.digest)
            self.finished_p = p7.compute_phase7_finished_p(self.keys.finished_p, self.digest)
            self.traffic = p7.derive_phase7_traffic_keys(self.keys.application)
            self.rx = SecureChannel(
                self.traffic.central_to_peripheral,
                session_id=self.session_id, role=PERIPHERAL_ROLE,
            )
            self.tx = SecureChannel(
                self.traffic.peripheral_to_central,
                session_id=self.session_id, role=PERIPHERAL_ROLE,
            )
            ready = p7.encode_ready7_auth(peripheral_key)
            self.notify(ready[:-1] if self.fault == "bad-ready" else ready)
            return
        assert frame.subtype == p7.PHASE7_FINISHED_C
        # Ordinary equality here is confined to the mock; spy below verifies
        # that the actual Central still uses hmac.compare_digest.
        if frame.payload != self.finished_c and self.fault != "accept-finished":
            self.reject(0x06)
            return
        self.authenticated = True
        finished = p7.encode_phase7_finished_p(self.finished_p)
        if self.fault == "bad-finished-p":
            finished = runner._tamper_last_bit(finished)
        self.notify(finished)

    async def write_secure_data(self, wire):
        self.writes.append(bytes(wire))
        if not self.authenticated:
            # Rejection occurs before any decryption or sequence mutation.
            if self.preauth_notification is not None:
                self.notify(self.preauth_notification)
            if self.preauth_error is not None:
                raise self.preauth_error
            return
        try:
            plaintext = self.rx.decrypt(wire, msg_type=MSG_TYPE_DATA)
        except InvalidTag:
            if self.fault == "tag-advances-sequence":
                self.rx._last_recv_seq = int.from_bytes(wire[:8], "big")
            self.reject(0x06)
            return
        except ValueError:
            self.reject(0x04)
            if self.fault == "duplicate-pong":
                asyncio.get_running_loop().call_later(0.002, self.notify, self.responses[0])
            return
        sequence = int.from_bytes(wire[:8], "big")
        assert plaintext == f"PING {sequence}".encode()
        self.accepted.append(sequence)
        response = self.tx.encrypt(f"PONG {sequence}".encode(), msg_type=MSG_TYPE_DATA)
        if self.fault == "bad-pong":
            response = runner._tamper_last_bit(response)
        self.responses.append(response)
        self.notify(response)


@pytest.fixture
def client(sample_keypair):
    return CP4MockClient(sample_keypair)


async def run(client, mode=None, **kwargs):
    kwargs.setdefault("sas_callback", lambda _sas: mode != "sas-reject")
    kwargs.setdefault("notification_timeout", 0.02)
    return await runner.run_phase7_authenticated_hybrid(client, negative_test=mode, **kwargs)


@pytest.mark.asyncio
async def test_cp3_real_crypto_positive_order_sas_comparison_and_no_secrets(client, caplog, capsys):
    caplog.set_level("INFO")
    with patch.object(runner.hmac, "compare_digest", wraps=hmac.compare_digest) as compare:
        result = await run(client)
    assert result.rounds == 3
    assert result.sas == p7.format_phase7_sas(p7.compute_phase7_sas(client.keys.sas, client.digest))
    assert [p7.parse_phase7_frame(wire).subtype for wire in client.controls] == [
        p7.PHASE7_START7_AUTH, p7.PHASE7_FINISHED_C,
    ]
    assert p7.parse_phase7_finished_c(client.controls[1]) == client.finished_c
    compare.assert_called_once()
    assert compare.call_args.args[0] == client.finished_p
    assert compare.call_args.args[1] == bytearray(32)  # runner buffer wiped
    assert client.accepted == [0, 1, 2]
    assert client.rx.recv_count == client.tx.sent_count == 3
    assert [int.from_bytes(w[:8], "big") for w in client.responses] == [0, 1, 2]
    assert all(len(w) == 43 for w in client.writes + client.responses)
    assert client.calls[-1] == "unsubscribe"
    assert "measurement: handshake" in caplog.text
    assert "includes SAS confirmation" in caplog.text
    assert "measurement: application" in caplog.text
    output = caplog.text + capsys.readouterr().out
    for secret in (client.ss_mlkem, client.ss_ecdh, *astuple(client.keys), *astuple(client.traffic)):
        assert secret.hex() not in output
        assert repr(secret) not in output


@pytest.mark.asyncio
@pytest.mark.parametrize("answer,accepted", [("y", True), ("YES", True), ("n", False), ("", False)])
async def test_normal_mode_keeps_human_confirmation_mandatory(client, answer, accepted):
    with patch("builtins.input", return_value=answer) as prompt:
        if accepted:
            await run(client, sas_callback=None)
        else:
            with pytest.raises(runner.Phase7AuthError, match="SAS rejected"):
                await run(client, sas_callback=None)
            assert len(client.controls) == 1
            assert not client.writes and not client.authenticated
    prompt.assert_called_once()


@pytest.mark.asyncio
async def test_async_sas_callback_supported(client):
    confirm = AsyncMock(return_value=True)
    result = await run(client, sas_callback=confirm)
    confirm.assert_awaited_once_with(result.sas)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", runner.PHASE7_NEGATIVE_MODES)
async def test_all_cp4_modes_require_the_expected_rejection_and_cleanup(client, mode):
    with pytest.raises(runner.Phase7NegativeTestPassed):
        await run(client, mode)
    assert client.calls[-1] == "unsubscribe"
    if mode in {"sas-reject", "finished-c"}:
        assert not client.authenticated
        assert client.rx.recv_count == client.tx.sent_count == 0
        assert not client.accepted and not client.responses
        assert len(client.controls) == (1 if mode == "sas-reject" else 2)
        assert len(client.writes) == 1
        # The rejected application probe is valid under the negotiated keys;
        # rejection must come from the authentication gate, not a wrong key.
        assert client.rx.decrypt(client.writes[0]) == b"PING 0"
        if mode == "finished-c":
            assert p7.parse_phase7_finished_c(client.controls[1]) == runner._tamper_last_bit(client.finished_c)
            assert client.rejections == [0x06]
    else:
        assert client.authenticated
        assert client.accepted == [0, 1, 2]
        assert client.rx.recv_count == client.tx.sent_count == 3
        if mode == "pre-auth":
            assert client.writes[0] == client.writes[1]
        elif mode == "c2p-tamper":
            assert client.writes[0] == runner._tamper_last_bit(client.writes[1])
            assert client.rejections == [0x06]
        elif mode == "c2p-replay":
            assert client.writes[0] == client.writes[1]
            assert client.rejections == [0x04]
        else:
            assert len(client.writes) == 3  # no fabricated P->C BLE path
            assert not client.rejections


@pytest.mark.asyncio
async def test_sas_reject_default_is_deterministic_and_never_prompts(client):
    with patch("builtins.input", side_effect=AssertionError("must not prompt")):
        with pytest.raises(runner.Phase7NegativeTestPassed, match="FINISHED_C not sent"):
            await run(client, "sas-reject", sas_callback=None)


@pytest.mark.asyncio
async def test_sas_reject_cannot_continue_if_callback_accepts(client):
    with pytest.raises(runner.Phase7AuthError, match="requires SAS rejection"):
        await run(client, "sas-reject", sas_callback=lambda _: True)
    assert len(client.controls) == 1
    assert not client.writes and not client.authenticated


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", runner.PHASE7_NEGATIVE_MODES[1:])
async def test_other_negative_modes_cannot_bypass_sas_rejection(client, mode):
    with pytest.raises(runner.Phase7AuthError, match="SAS rejected"):
        await run(client, mode, sas_callback=lambda _: False)
    assert len(client.controls) == 1
    assert not client.authenticated and not client.accepted


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["finished-c", "c2p-tamper", "c2p-replay"])
@pytest.mark.parametrize("response", ["silence", "wrong-status", "malformed", "finished-p", "data", "extra", "disconnect"])
async def test_unrelated_or_missing_rejections_never_pass(client, mode, response):
    client.rejection = response
    with pytest.raises(runner.Phase7AuthError):
        await run(client, mode)
    assert client.calls[-1] == "unsubscribe"


@pytest.mark.asyncio
@pytest.mark.parametrize("mode,fault", [
    ("finished-c", "accept-finished"),
    ("c2p-tamper", "tag-advances-sequence"),
    ("c2p-replay", "duplicate-pong"),
    ("p2c-tamper", "bad-pong"),
    ("p2c-replay", "bad-pong"),
    (None, "bad-ready"),
    (None, "bad-finished-p"),
])
async def test_broken_peer_cannot_pass(client, mode, fault):
    client.fault = fault
    with pytest.raises(runner.Phase7AuthError):
        await run(client, mode)
    if fault == "bad-finished-p":
        assert not client.writes
    assert client.calls[-1] == "unsubscribe"


@pytest.mark.asyncio
@pytest.mark.parametrize("mode,fault", [
    ("p2c-tamper", "accept"), ("p2c-tamper", "count"),
    ("p2c-tamper", "sequence"), ("p2c-replay", "accept"),
    ("p2c-replay", "count"), ("p2c-replay", "wrong-error"),
    ("p2c-replay", "tag-error"),
])
async def test_broken_central_receiver_cannot_pass(client, mode, fault):
    decrypt = SecureChannel.decrypt
    central_calls = 0

    def broken_decrypt(channel, wire, **kwargs):
        nonlocal central_calls
        if channel._role != CENTRAL_ROLE:
            return decrypt(channel, wire, **kwargs)
        central_calls += 1
        injection_call = 1 if mode == "p2c-tamper" else 2
        if central_calls != injection_call:
            return decrypt(channel, wire, **kwargs)
        if fault == "accept":
            return b"PONG 0"
        if fault == "count":
            channel._recv_count += 1
        elif fault == "sequence":
            channel._last_recv_seq = 0
        elif fault == "wrong-error":
            raise ValueError("unrelated parse error")
        elif fault == "tag-error":
            raise InvalidTag
        if mode == "p2c-tamper":
            raise InvalidTag
        raise ValueError("Replay or out-of-order message detected")

    with patch.object(SecureChannel, "decrypt", broken_decrypt):
        with pytest.raises(runner.Phase7AuthError):
            await run(client, mode)
    assert client.calls[-1] == "unsubscribe"


@pytest.mark.asyncio
@pytest.mark.parametrize("error", [
    BleakGATTProtocolError(0xFC),
    BleakGATTProtocolError(0x03),
    BleakError(ATT_REJECTED),
    BleakDBusError(
        "org.bluez.Error.Failed",
        ["ATT error: 0xfc"],
    ),
    BleakError("Could not write value b'probe' to characteristic 000E: Protocol Error 0x03: Write Not Permitted"),
    BleakError(WINRT_ACCESS_DENIED),
    winrt_error(0x80650003),
    winrt_error(0x80650003 - 2**32),
    winrt_error(0x80070005 - 2**32),
])
async def test_preauth_rejection_accepts_ble_write_denials_and_logs_actual_error(error, caplog):
    caplog.set_level("INFO", logger=runner.logger.name)
    fake = SimpleNamespace(is_connected=True, write_secure_data=AsyncMock(side_effect=error))
    await runner._require_preauth_rejection(fake, b"probe", asyncio.Queue(), 0.001)
    assert f"{type(error).__name__}: {error}" in caplog.text
    assert "rejected Secure Data write observed; no unexpected notification" in caplog.text


@pytest.mark.asyncio
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mode",
    [
        "sas-reject",
        "finished-c",
        "pre-auth",
    ],
)
@pytest.mark.parametrize(
    "error",
    [
        BleakGATTProtocolError(0xFC),
        BleakError(ATT_REJECTED),
        BleakError(WINRT_ACCESS_DENIED),
        winrt_error(0x80650003),
    ],
)
async def test_portable_denials_preserve_all_three_modes_semantic_checks(client, mode, error):
    client.preauth_error = error
    with pytest.raises(runner.Phase7NegativeTestPassed):
        await run(client, mode)
    assert client.calls[-1] == "unsubscribe"
    if mode == "pre-auth":
        assert client.writes[0] == client.writes[1]
        assert client.accepted == [0, 1, 2]
        assert client.rx.recv_count == client.tx.sent_count == 3
    else:
        assert not client.authenticated and not client.accepted
        assert client.rx.recv_count == client.tx.sent_count == 0
        assert len(client.controls) == (1 if mode == "sas-reject" else 2)
        assert client.rejections == ([] if mode == "sas-reject" else [0x06])


@pytest.mark.asyncio
@pytest.mark.parametrize("error", [BleakError(ATT_REJECTED), BleakError(WINRT_ACCESS_DENIED), winrt_error(0x80650003)])
async def test_denied_write_on_disconnected_client_cannot_pass(error):
    fake = SimpleNamespace(is_connected=False, write_secure_data=AsyncMock(side_effect=error))
    with pytest.raises(runner.Phase7AuthError, match="disconnection"):
        await runner._require_preauth_rejection(fake, b"probe", asyncio.Queue(), 0.001)


@pytest.mark.asyncio
@pytest.mark.parametrize("error", [
    BleakGATTProtocolError(0x0D),
    BleakGATTProtocolError(0xFE),
    BleakError("Could not write value b'probe' to characteristic 000E: Unreachable"),
    BleakError("Could not write value b'probe' to characteristic 000E: Unexpected status code 0x05"),
    BleakError("Could not write value b'probe' to characteristic 000E: Protocol Error 0x0D: Invalid Attribute Value Length"),
    BleakError("Not connected"), BleakError("timed out"),
    BleakError("Characteristic 000E was not found!"),
    BleakError("Could not read value: Access Denied"),
    OSError("unrelated OS error"), PermissionError("unrelated file permission error"),
    winrt_error(0x800705B4), winrt_error(0x806500FE), winrt_error(0x80004005),
    asyncio.TimeoutError(), ConnectionError("connection lost"),
])
async def test_unrelated_ble_and_os_failures_cannot_pass_with_stale_connected_flag(error):
    fake = SimpleNamespace(is_connected=True, write_secure_data=AsyncMock(side_effect=error))
    with pytest.raises(runner.Phase7AuthError):
        await runner._require_preauth_rejection(fake, b"probe", asyncio.Queue(), 0.001)


@pytest.mark.asyncio
@pytest.mark.parametrize("error", [RuntimeError(WINRT_ACCESS_DENIED), ValueError("logic bug"), TypeError("wrong argument")])
async def test_programming_errors_propagate_unchanged(error):
    fake = SimpleNamespace(is_connected=True, write_secure_data=AsyncMock(side_effect=error))
    with pytest.raises(type(error)) as rejected:
        await runner._require_preauth_rejection(fake, b"probe", asyncio.Queue(), 0.001)
    assert rejected.value is error


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["sas-reject", "finished-c", "pre-auth"])
@pytest.mark.parametrize("error", [None, BleakError("Unreachable"), BleakError("Protocol Error 0xFE: busy"), RuntimeError(ATT_REJECTED), asyncio.TimeoutError()])
async def test_preauth_acceptance_and_generic_transport_errors_never_pass(client, mode, error):
    client.preauth_error = error
    with pytest.raises((runner.Phase7AuthError, RuntimeError, asyncio.TimeoutError)) as rejected:
        await run(client, mode)
    assert not isinstance(rejected.value, runner.Phase7NegativeTestPassed)
    assert client.calls[-1] == "unsubscribe"


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["sas-reject", "finished-c", "pre-auth"])
@pytest.mark.parametrize("error", [BleakError(ATT_REJECTED), BleakError(WINRT_ACCESS_DENIED)])
async def test_preauth_notification_after_att_rejection_is_failure(client, mode, error):
    client.preauth_error = error
    client.preauth_notification = p7.encode_phase7_finished_p(bytes(32))
    with pytest.raises(runner.Phase7AuthError, match="extra notification"):
        await run(client, mode)


@pytest.mark.parametrize("size", [1, 32, 40, 43])
def test_tamper_changes_exactly_one_bit_without_mutating_original(size):
    original = bytes(range(size))
    changed = runner._tamper_last_bit(original)
    assert sum((a ^ b).bit_count() for a, b in zip(original, changed)) == 1
    assert changed[:-1] == original[:-1]
    assert changed[-1] == original[-1] ^ 1
    assert original == bytes(range(size))


def test_empty_tamper_rejected():
    with pytest.raises(ValueError):
        runner._tamper_last_bit(b"")


@pytest.mark.parametrize("status", [0x04, 0x06])
def test_exact_error_status_parser(status):
    runner._require_error_status(p7.encode_phase7_frame(p7.PHASE7_ERROR, bytes((status,))), status)


@pytest.mark.parametrize("wire", [
    b"", b"PQS6\x01\x7f\x00\x01\x06", b"PQS7\x07\x7f\x00\x01", b"PQS7\x07\x7f\x00\x02\x06\x00",
    b"PQS7\x07\x7f\x00\x01\x04", p7.encode_phase7_finished_p(bytes(32)),
])
def test_error_parser_rejects_wrong_protocol_length_subtype_or_status(wire):
    with pytest.raises(runner.Phase7AuthError):
        runner._require_error_status(wire, 0x06)


AUTH_FRAMES = [
    p7.encode_start7_auth(SESSION_ID, CENTRAL_PUBLIC_KEY),
    p7.encode_ready7_auth(CENTRAL_PUBLIC_KEY),
    p7.encode_phase7_finished_c(bytes(32)),
    p7.encode_phase7_finished_p(bytes(32)),
]


@pytest.mark.parametrize("wire", AUTH_FRAMES)
@pytest.mark.parametrize("mutation", ["truncate", "trailing", "magic", "version", "subtype", "length"])
def test_authenticated_frame_parsers_fail_closed(wire, mutation):
    damaged = bytearray(wire)
    if mutation == "truncate":
        damaged = damaged[:-1]
    elif mutation == "trailing":
        damaged += b"\x00"
    else:
        offset = {"magic": 0, "version": 4, "subtype": 5, "length": 7}[mutation]
        damaged[offset] ^= 0x80
    with pytest.raises(ValueError):
        p7.parse_phase7_frame(damaged)


@pytest.mark.parametrize("mode", runner.PHASE7_NEGATIVE_MODES)
def test_cp4_cli_choices_are_explicit_and_require_authenticated_mode(mode):
    args = main.parse_args(["--phase7-auth-hybrid", "--phase7-negative-test-only", mode])
    assert args.phase7_negative_test_only == mode
    with pytest.raises(SystemExit):
        main.parse_args(["--phase7-negative-test-only", mode])


@pytest.mark.parametrize("args", [
    ["--phase7-auth-hybrid", "--no-sas-confirm"],
    ["--phase7-auth-hybrid", "--phase7-negative-test-only", "unknown"],
    ["--phase7-hybrid-e2e", "--phase7-negative-test-only", "pre-auth"],
    ["--phase7-auth-hybrid", "--phase6-negative", "pre-auth"],
    ["--phase7-auth-hybrid", "--phase5-negative", "finished-c"],
    ["--phase7-auth-hybrid", "--phase3-negative", "replay"],
    ["--phase7-auth-hybrid", "--phase7-negative-test-only", "sas-reject", "--no-sas-confirm"],
])
def test_invalid_cli_combinations_fail_before_ble(args):
    with pytest.raises(SystemExit):
        main.parse_args(args)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [None, "connect", "not-found", "runner", "unexpected-positive", "disconnect"])
async def test_cli_exit_status_and_disconnect_before_negative_pass(failure, capsys):
    client = SimpleNamespace(scan_and_connect=AsyncMock(return_value=True), disconnect=AsyncMock())
    test_runner = AsyncMock(side_effect=runner.Phase7NegativeTestPassed("expected rejection"))
    if failure == "connect":
        client.scan_and_connect.side_effect = RuntimeError("connect failed")
    elif failure == "not-found":
        client.scan_and_connect.return_value = False
    elif failure == "runner":
        test_runner.side_effect = runner.Phase7AuthError("invalid response")
    elif failure == "unexpected-positive":
        test_runner.side_effect = None
        test_runner.return_value = runner.Phase7AuthResult(sas="000000", rounds=3)

    async def disconnect():
        assert "CP4 NEGATIVE TEST: PASS" not in capsys.readouterr().out
        if failure == "disconnect":
            raise RuntimeError("disconnect failed")

    client.disconnect.side_effect = disconnect
    args = main.parse_args(["--phase7-auth-hybrid", "--phase7-negative-test-only", "finished-c"])
    with patch.object(main, "BLECentralClient", return_value=client), patch.object(main, "run_phase7_authenticated_hybrid", test_runner):
        assert await main._run_phase7_auth_hybrid_cli(args) == (1 if failure else 0)
    client.disconnect.assert_awaited_once()
    assert ("CP4 NEGATIVE TEST: PASS" in capsys.readouterr().out) == (failure is None)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", [None, *runner.PHASE7_NEGATIVE_MODES])
async def test_cli_full_mock_crypto_flow_and_reset(client, mode, capsys):
    argv = ["--phase7-auth-hybrid"]
    if mode:
        argv += ["--phase7-negative-test-only", mode]
    client.scan_and_connect = AsyncMock(return_value=True)

    async def disconnect():
        client.authenticated = False
        client.is_connected = False

    client.disconnect = AsyncMock(side_effect=disconnect)

    async def test_runner(connected_client, *, negative_test):
        return await run(connected_client, negative_test)

    with patch.object(main, "BLECentralClient", return_value=client), patch.object(main, "run_phase7_authenticated_hybrid", test_runner):
        assert await main._run_phase7_auth_hybrid_cli(main.parse_args(argv)) == 0
    assert not client.authenticated and not client.is_connected
    assert client.calls[-1] == "unsubscribe"
    client.disconnect.assert_awaited_once()
    output = capsys.readouterr().out
    marker = f"CP4 NEGATIVE TEST: PASS ({mode})" if mode else "HYBRID SECURE CHANNEL E2E: PASS"
    assert marker in output
    if mode:
        assert "HYBRID SECURE CHANNEL E2E: PASS" not in output


@pytest.mark.asyncio
async def test_positive_cli_rejects_a_negative_pass_result(capsys):
    client = SimpleNamespace(scan_and_connect=AsyncMock(return_value=True), disconnect=AsyncMock())
    with patch.object(main, "BLECentralClient", return_value=client), patch.object(
        main, "run_phase7_authenticated_hybrid",
        AsyncMock(side_effect=runner.Phase7NegativeTestPassed("unexpected")),
    ):
        assert await main._run_phase7_auth_hybrid_cli(main.parse_args(["--phase7-auth-hybrid"])) == 1
    client.disconnect.assert_awaited_once()
    assert "TEST: PASS" not in capsys.readouterr().out


@pytest.mark.asyncio
async def test_negative_unsubscribe_failure_cannot_pass(client):
    client.stop_notify = AsyncMock(side_effect=RuntimeError("unsubscribe failed"))
    with pytest.raises(runner.Phase7AuthError, match="cleanup failed"):
        await run(client, "sas-reject")


@pytest.mark.asyncio
async def test_invalid_runner_mode_and_timeout_fail_before_transport(client):
    for kwargs in ({"negative_test": "unknown"}, {"notification_timeout": 0}):
        with pytest.raises(runner.Phase7AuthError):
            await runner.run_phase7_authenticated_hybrid(client, **kwargs)
    assert not client.calls


@pytest.mark.parametrize("mode", ["p2c-tamper", "p2c-replay"])
def test_phase7_receiver_local_negatives_preserve_sequence_state_and_direction(mode):
    keys = p7.derive_phase7_traffic_keys(bytes(range(32)))
    peripheral = SecureChannel(keys.peripheral_to_central, session_id=SESSION_ID, role=PERIPHERAL_ROLE)
    central = SecureChannel(keys.peripheral_to_central, session_id=SESSION_ID, role=CENTRAL_ROLE)
    wire = peripheral.encrypt(b"PONG 0")
    if mode == "p2c-tamper":
        with pytest.raises(InvalidTag):
            central.decrypt(runner._tamper_last_bit(wire))
        assert central.recv_count == 0
    assert central.decrypt(wire) == b"PONG 0"
    with pytest.raises(ValueError, match="Replay or out-of-order"):
        central.decrypt(wire)
    assert central.recv_count == 1
    assert central.decrypt(peripheral.encrypt(b"PONG 1")) == b"PONG 1"
    assert central.sent_count == 0 and peripheral.recv_count == 0
