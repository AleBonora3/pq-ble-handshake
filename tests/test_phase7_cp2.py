"""CP2 wire/KAT and isolated Central flow tests; no hardware negatives."""

from dataclasses import asdict
import hmac
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from src.central.main import _run_phase7_hybrid_e2e_cli, parse_args
from src.central.phase7_hybrid import Phase7HybridError, run_phase7_hybrid_e2e
from src.common import phase7 as p7
from src.common.ml_kem import decapsulate
from tests.test_phase7_primitives import (
    CENTRAL_PUBLIC_KEY,
    EXPECTED_K_APP,
    EXPECTED_TRANSCRIPT_HASH,
    PERIPHERAL_PUBLIC_KEY,
    SESSION_ID,
)


DIAGNOSTIC = bytes.fromhex(
    "9ef8e267076b90c7282b443bab8e59c6"
    "09ec87262db5c176c8230579d160c21e"
)
START7 = b"PQS7\x07\x01\x00\x51" + SESSION_ID + CENTRAL_PUBLIC_KEY
READY7 = b"PQS7\x07\x02\x00\x61" + PERIPHERAL_PUBLIC_KEY + DIAGNOSTIC
ERROR7 = b"PQS7\x07\x7f\x00\x01\x05"


def test_exact_frame_definitions():
    assert p7.PHASE7_FRAME_MAGIC == b"PQS7"
    assert p7.PHASE7_FRAME_VERSION == 0x07
    assert p7.PHASE7_FRAME_HEADER_SIZE == 8
    assert p7.PHASE7_START7 == 0x01
    assert p7.PHASE7_READY7_CP2 == 0x02
    assert p7.PHASE7_ERROR == 0x7F
    assert p7.PHASE7_START7_PAYLOAD_SIZE == len(START7[8:]) == 81
    assert p7.PHASE7_START7_FRAME_SIZE == len(START7) == 89
    assert p7.PHASE7_READY7_CP2_PAYLOAD_SIZE == len(READY7[8:]) == 97
    assert p7.PHASE7_READY7_CP2_FRAME_SIZE == len(READY7) == 105
    assert p7.PHASE7_ERROR_FRAME_SIZE == len(ERROR7) == 9


def test_start7_round_trip_and_exact_wire():
    assert p7.encode_start7(SESSION_ID, CENTRAL_PUBLIC_KEY) == START7
    assert p7.parse_start7(START7) == (SESSION_ID, CENTRAL_PUBLIC_KEY)


def test_ready7_round_trip_and_exact_wire():
    assert p7.encode_ready7_cp2(PERIPHERAL_PUBLIC_KEY, DIAGNOSTIC) == READY7
    assert p7.parse_ready7_cp2(READY7) == (PERIPHERAL_PUBLIC_KEY, DIAGNOSTIC)


def test_error_round_trip_and_exact_wire():
    assert p7.encode_phase7_frame(p7.PHASE7_ERROR, b"\x05") == ERROR7
    assert p7.parse_phase7_frame(ERROR7) == p7.Phase7Frame(p7.PHASE7_ERROR, b"\x05")


@pytest.mark.parametrize("wire", [START7, READY7, ERROR7])
@pytest.mark.parametrize("mutation", ["magic", "version", "length", "truncate", "trailing", "subtype"])
def test_malformed_generic_frames_rejected(wire, mutation):
    damaged = bytearray(wire)
    if mutation == "magic":
        damaged[0] ^= 1
    elif mutation == "version":
        damaged[4] = 6
    elif mutation == "length":
        damaged[7] -= 1
    elif mutation == "truncate":
        damaged = damaged[:-1]
    elif mutation == "trailing":
        damaged += b"\x00"
    else:
        # Use an actually unsupported subtype.
        # 0x03-0x06 are valid CP3 authenticated-hybrid subtypes.
        damaged[5] = 0x7E
    with pytest.raises(ValueError):
        p7.parse_phase7_frame(damaged)


@pytest.mark.parametrize("length", range(8))
def test_truncated_header_rejected(length):
    with pytest.raises(ValueError):
        p7.parse_phase7_frame(START7[:length])


@pytest.mark.parametrize("wire", [START7, READY7, ERROR7])
@pytest.mark.parametrize("delta", [-1, 1])
def test_subtype_length_rejected_even_with_consistent_header(wire, delta):
    payload = wire[8:-1] if delta == -1 else wire[8:] + b"\x00"
    malformed = wire[:6] + len(payload).to_bytes(2, "big") + payload
    with pytest.raises(ValueError):
        p7.parse_phase7_frame(malformed)
    with pytest.raises(ValueError):
        p7.encode_phase7_frame(wire[5], payload)


@pytest.mark.parametrize("size", [0, 15, 17])
def test_bad_session_id_rejected(size):
    with pytest.raises(ValueError):
        p7.encode_start7(bytes(size), CENTRAL_PUBLIC_KEY)


@pytest.mark.parametrize("public_key", [b"", CENTRAL_PUBLIC_KEY[:-1], CENTRAL_PUBLIC_KEY + b"\x00", b"\x03" + CENTRAL_PUBLIC_KEY[1:]])
@pytest.mark.parametrize("subtype", [p7.PHASE7_START7, p7.PHASE7_READY7_CP2])
def test_malformed_public_keys_rejected(public_key, subtype):
    with pytest.raises(ValueError):
        if subtype == p7.PHASE7_START7:
            p7.encode_start7(SESSION_ID, public_key)
        else:
            p7.encode_ready7_cp2(public_key, DIAGNOSTIC)
    payload = SESSION_ID + public_key if subtype == p7.PHASE7_START7 else public_key + DIAGNOSTIC
    wire = b"PQS7\x07" + bytes((subtype,)) + len(payload).to_bytes(2, "big") + payload
    with pytest.raises(ValueError):
        p7.parse_phase7_frame(wire)


@pytest.mark.parametrize("size", [0, 31, 33])
def test_malformed_diagnostic_length_rejected(size):
    with pytest.raises(ValueError):
        p7.encode_ready7_cp2(PERIPHERAL_PUBLIC_KEY, bytes(size))


@pytest.mark.parametrize("parser,wire", [(p7.parse_start7, READY7), (p7.parse_ready7_cp2, START7)])
def test_wrong_expected_subtype_rejected(parser, wire):
    with pytest.raises(ValueError):
        parser(wire)


def test_frozen_diagnostic_kat():
    assert p7.PHASE7_CP2_DIAGNOSTIC_LABEL == b"PQ-BLE-HANDSHAKE-v0.7/CP2-DIAGNOSTIC"
    assert p7.PHASE7_CP2_DIAGNOSTIC_SIZE == len(DIAGNOSTIC) == 32
    assert p7.compute_phase7_cp2_diagnostic(EXPECTED_K_APP, EXPECTED_TRANSCRIPT_HASH) == DIAGNOSTIC


@pytest.mark.parametrize("field", ["key", "hash"])
def test_diagnostic_bound_to_both_key_and_transcript(field):
    key = bytearray(EXPECTED_K_APP)
    digest = bytearray(EXPECTED_TRANSCRIPT_HASH)
    (key if field == "key" else digest)[0] ^= 1
    assert p7.compute_phase7_cp2_diagnostic(key, digest) != DIAGNOSTIC


@pytest.mark.parametrize("size", [0, 31, 33])
def test_diagnostic_input_sizes_rejected(size):
    with pytest.raises(ValueError):
        p7.compute_phase7_cp2_diagnostic(bytes(size), EXPECTED_TRANSCRIPT_HASH)
    with pytest.raises(ValueError):
        p7.compute_phase7_cp2_diagnostic(EXPECTED_K_APP, bytes(size))


def test_cli_cp2_mode():
    args = parse_args(["--phase7-hybrid-e2e"])
    assert args.phase7_hybrid_e2e
    assert not args.no_sas_confirm


@pytest.mark.parametrize("mode", ["--demo", "--phase2-e2e", "--phase3-secure", "--phase5-auth-pq", "--phase6-c2p", "--phase6-bidirectional"])
def test_previous_cli_modes_and_cp2_exclusion(mode):
    args = parse_args([mode])
    assert getattr(args, mode[2:].replace("-", "_"))
    assert not args.phase7_hybrid_e2e
    with pytest.raises(SystemExit):
        parse_args([mode, "--phase7-hybrid-e2e"])


class CP2MockClient:
    """Small transport mock using real liboqs decapsulation and P-256 ECDH."""

    def __init__(self, keypair, *, response="valid"):
        self.public_key, self.secret_key = keypair
        self.response = response
        self.is_connected = True
        self.mtu_size = 247
        self.calls = []
        self.starts = []

    async def start_notify(self, callback):
        self.calls.append("subscribe")
        self.callback = callback

    async def read_fragmented_public_key(self):
        self.calls.append("read_pk")
        return self.public_key

    async def write_fragmented_ciphertext(self, ciphertext):
        self.calls.append("write_ct")
        self.ciphertext = ciphertext

    async def send_control(self, data):
        self.calls.append("start7")
        self.starts.append(data)
        session_id, central_key = p7.parse_start7(data)
        private_key = p7.generate_p256_private_key()
        peripheral_key = p7.serialize_p256_public_key(private_key)
        digest = p7.compute_phase7_transcript_hash(
            session_id, self.public_key, self.ciphertext, central_key, peripheral_key
        )
        keys = p7.derive_phase7_keys(
            decapsulate(self.secret_key, self.ciphertext),
            p7.derive_p256_ecdh_shared_secret(private_key, central_key), digest
        )
        diagnostic = p7.compute_phase7_cp2_diagnostic(keys.application, digest)
        wire = p7.encode_ready7_cp2(peripheral_key, diagnostic)
        if self.response == "mismatch":
            wire = wire[:-1] + bytes((wire[-1] ^ 1,))
        elif self.response == "error":
            wire = ERROR7
        elif self.response == "malformed":
            wire = wire[:-1]
        elif self.response == "wrong_subtype":
            wire = START7
        elif self.response == "timeout":
            return
        self.callback(1, bytearray(wire))

    async def stop_notify(self):
        self.calls.append("unsubscribe")


@pytest.mark.asyncio
async def test_runner_real_crypto_flow_and_fresh_inputs(sample_keypair):
    client = CP2MockClient(sample_keypair)
    with (
        patch("src.central.phase7_hybrid.hmac.compare_digest",
              wraps=hmac.compare_digest) as compare,
        patch("src.central.phase7_hybrid.derive_phase7_keys",
              wraps=p7.derive_phase7_keys) as derive,
        patch("src.central.phase7_hybrid.compute_phase7_cp2_diagnostic",
              wraps=p7.compute_phase7_cp2_diagnostic) as diagnostic,
    ):
        first = await run_phase7_hybrid_e2e(client)
        await run_phase7_hybrid_e2e(client)
    assert compare.call_count == 2
    assert all(len(arg) == 32 for arg in compare.call_args.args)
    # Captured mutable runner copies have been wiped by finally.
    for call in derive.call_args_list:
        assert call.args[0] == call.args[1] == bytearray(32)
    for call in diagnostic.call_args_list:
        assert call.args[0] == bytearray(32)
    for call in compare.call_args_list:
        assert call.args[1] == bytearray(32)
    assert asdict(first) == {"response_size": 105}
    assert client.calls == ["subscribe", "read_pk", "write_ct", "start7", "unsubscribe"] * 2
    session_a, key_a = p7.parse_start7(client.starts[0])
    session_b, key_b = p7.parse_start7(client.starts[1])
    assert session_a != session_b
    assert key_a != key_b


@pytest.mark.asyncio
@pytest.mark.parametrize("response,match", [("mismatch", "diagnostic proof: FAIL"), ("error", "PQS7 ERROR: 0x05"), ("malformed", "payload length"), ("wrong_subtype", "expected READY7_CP2"), ("timeout", "Timed out")])
async def test_runner_failures_always_unsubscribe(sample_keypair, response, match):
    client = CP2MockClient(sample_keypair, response=response)
    with pytest.raises(Phase7HybridError, match=match):
        await run_phase7_hybrid_e2e(client, notification_timeout=0.01)
    assert client.calls[-1] == "unsubscribe"


@pytest.mark.asyncio
async def test_runner_requires_connection_and_supported_mtu(sample_keypair):
    client = CP2MockClient(sample_keypair)
    client.is_connected = False
    with pytest.raises(Phase7HybridError, match="not connected"):
        await run_phase7_hybrid_e2e(client)
    assert not client.calls
    client.is_connected = True
    client.mtu_size = 107
    with pytest.raises(Phase7HybridError, match="MTU >= 108"):
        await run_phase7_hybrid_e2e(client)
    assert client.calls == ["subscribe", "unsubscribe"]


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [None, "connect", "runner"])
async def test_cli_disconnects_on_success_and_failure(failure, capsys):
    client = SimpleNamespace(scan_and_connect=AsyncMock(return_value=True), disconnect=AsyncMock())
    runner = AsyncMock()
    if failure == "connect":
        client.scan_and_connect.side_effect = RuntimeError("connect failed")
    elif failure == "runner":
        runner.side_effect = Phase7HybridError("diagnostic failed")
    with patch("src.central.main.BLECentralClient", return_value=client), patch("src.central.main.run_phase7_hybrid_e2e", runner):
        status = await _run_phase7_hybrid_e2e_cli(parse_args(["--phase7-hybrid-e2e"]))
    assert status == (1 if failure else 0)
    client.disconnect.assert_awaited_once()
    assert ("E2E: FAIL" if failure else "E2E: PASS") in capsys.readouterr().out
