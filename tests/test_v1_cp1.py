"""v1.0 CP1 host validation: SMP Security Mode 1 Level 4 foundation.

Not evidence of hardware PASS. Hardware:
    python -m src.central.main --v1-smp-l4-mlkem [--v1-negative MODE]
MODE: pre-l4-only, nc-reject, just-works.

These tests model the firmware gate (GATT denied before L4, allowed after)
and the Windows pairing backend; they do not execute the C firmware or
WinRT. The firmware/config consistency tests parse the real sources.
"""

from __future__ import annotations

import asyncio
import os
import re
from types import SimpleNamespace

from bleak.exc import BleakError, BleakGATTProtocolError
import pytest

from src.central import main
from src.central import v1_smp_mlkem as runner
from src.central.winrt_pairing import PairingOutcome, PairingState
from src.common import v1_smp_mlkem as v1
from src.common.constants import CT_SIZE, PK_SIZE
from src.common.ml_kem import generate_keypair


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIRMWARE = os.path.join(ROOT, "firmware")


def _read(*parts: str) -> str:
    path = os.path.join(FIRMWARE, *parts)
    if not os.path.exists(path):
        pytest.skip(f"missing {path}")
    with open(path, encoding="utf-8") as handle:
        return handle.read()


# ── Exact wire definitions ──────────────────────────────────────────────

SEC_QUERY = b"PQV1\x10\x01\x00\x00"
SEC_INFO_L4 = b"PQV1\x10\x02\x00\x04\x04\x07\x10\x10"
ERROR_V1 = b"PQV1\x10\x7f\x00\x01\x11"

L4_INFO = v1.V1SecurityInfo(
    level=4, secure_connections=True, authenticated=True, gate_open=True,
    enc_key_size=16, profile=0x10,
)


def test_exact_frame_definitions():
    assert v1.V1_FRAME_MAGIC == b"PQV1"
    assert v1.V1_FRAME_VERSION == 0x10
    assert v1.V1_FRAME_HEADER_SIZE == 8
    assert v1.V1_SEC_QUERY == 0x01 and v1.V1_SEC_INFO == 0x02
    assert v1.V1_ERROR == 0x7F
    assert v1.V1_SEC_QUERY_FRAME_SIZE == len(SEC_QUERY) == 8
    assert v1.V1_SEC_INFO_FRAME_SIZE == len(SEC_INFO_L4) == 12
    assert v1.V1_ERROR_FRAME_SIZE == len(ERROR_V1) == 9
    assert v1.V1_DOMAIN == b"PQ-BLE-HANDSHAKE-v1.0/SMP-L4-MLKEM"
    assert v1.V1_SMP_CONTEXT == b"BLE-SMP-SM1-L4"
    assert b"v0.7" not in v1.V1_DOMAIN


def test_sec_query_and_sec_info_round_trip():
    assert v1.encode_sec_query() == SEC_QUERY
    assert v1.parse_v1_frame(SEC_QUERY) == v1.V1Frame(v1.V1_SEC_QUERY, b"")
    assert v1.encode_sec_info(L4_INFO) == SEC_INFO_L4
    assert v1.parse_sec_info(SEC_INFO_L4) == L4_INFO
    assert v1.encode_v1_error(v1.V1_STATUS_LEGACY_CONTROL_REJECTED) == ERROR_V1
    assert v1.parse_v1_frame(ERROR_V1).payload == b"\x11"


@pytest.mark.parametrize("wire", [SEC_QUERY, SEC_INFO_L4, ERROR_V1])
@pytest.mark.parametrize(
    "mutation", ["magic", "version", "length", "truncate", "trailing", "subtype"]
)
def test_malformed_frames_rejected(wire, mutation):
    damaged = bytearray(wire)
    if mutation == "magic":
        damaged[:4] = b"PQS7"          # v0.7 framing must never parse as v1.0
    elif mutation == "version":
        damaged[4] = 0x07
    elif mutation == "length":
        damaged[7] ^= 1
    elif mutation == "truncate":
        damaged = damaged[:-1]
    elif mutation == "trailing":
        damaged += b"\x00"
    else:
        damaged[5] = 0x10              # START is reserved until CP2
    with pytest.raises(ValueError):
        v1.parse_v1_frame(damaged)


@pytest.mark.parametrize("subtype", [v1.V1_START, v1.V1_READY, v1.V1_FINISHED_C, v1.V1_FINISHED_P, 0x03])
def test_reserved_subtypes_cannot_be_encoded(subtype):
    with pytest.raises(ValueError):
        v1.encode_v1_frame(subtype, b"")


def test_sec_info_parse_requires_sec_info_subtype():
    with pytest.raises(ValueError):
        v1.parse_sec_info(SEC_QUERY)


# ── Level 4 acceptance predicate ────────────────────────────────────────

@pytest.mark.parametrize(
    "changes",
    [
        {"level": 2},                          # unauthenticated SC (L2)
        {"level": 3},                          # authenticated legacy (L3)
        {"level": 1},
        {"secure_connections": False},         # authenticated but not LESC
        {"authenticated": False},
        {"gate_open": False},                  # DK gate closed
        {"enc_key_size": 7},
        {"enc_key_size": 15},
        {"profile": 0x07},                     # v0.7 firmware answering
        {"level": 2, "authenticated": False, "secure_connections": True},
    ],
)
def test_only_strict_level4_is_accepted(changes):
    assert v1.is_authenticated_level4(L4_INFO)
    weaker = v1.V1SecurityInfo(**{**L4_INFO.__dict__, **changes})
    assert not v1.is_authenticated_level4(weaker)


# ── Security-denial classification ─────────────────────────────────────

@pytest.mark.parametrize("code", [0x05, 0x08, 0x0F])
def test_att_security_errors_are_denials(code):
    assert v1.classify_security_denial(BleakGATTProtocolError(code)) is not None


@pytest.mark.parametrize("code", [0x03, 0x0D, 0x0E, 0x13, 0xFC, 0xFD])
def test_other_att_errors_are_not_security_denials(code):
    assert v1.classify_security_denial(BleakGATTProtocolError(code)) is None


def test_message_based_and_winrt_denials():
    assert v1.classify_security_denial(
        BleakError("Could not read: Protocol Error 0x05: Insufficient Authentication")
    )
    assert v1.classify_security_denial(BleakError("Could not write value: Access Denied"))
    assert v1.classify_security_denial(BleakError("Could not read: Unreachable")) is None
    assert v1.classify_security_denial(BleakError("Protocol Error 0xFC: rejected")) is None
    err = OSError("denied")
    err.winerror = 0x80650005
    assert v1.classify_security_denial(err)
    err.winerror = 0x80070005
    assert v1.classify_security_denial(err)
    err.winerror = 0x80650013
    assert v1.classify_security_denial(err) is None
    assert v1.classify_security_denial(RuntimeError("boom")) is None


# ── Mock DK + mock Windows pairing backend ──────────────────────────────

class V1MockClient:
    """Models the v1.0 firmware gate; every PQ GATT op is denied until L4."""

    def __init__(self, keypair):
        self.public_key, self.secret_key = keypair
        self.is_connected = True
        self.secured = False           # DK security_changed(L4) observed
        self.reported = None           # override for the SEC_INFO answer
        self.reply = "sec-info"        # "error" | "silence" | "extra"
        self.deny_with = BleakGATTProtocolError(0x05)
        self.gating_bug = set()        # ops allowed even before L4
        self.mtu_size = 247
        self.callback = None
        self.reconnects = 0
        self.log = []
        self.pq_gatt_after_l4 = False  # the state a negative test must not reach

    def _gate(self, op):
        self.log.append((op, self.secured))
        if not self.secured and op not in self.gating_bug:
            raise self.deny_with

    async def reconnect_v1_peer(self, timeout=15.0):
        self.reconnects += 1
        self.is_connected = True
        return True

    async def read_fragmented_public_key(self):
        self._gate("public-key-read")
        self.pq_gatt_after_l4 = True
        return bytearray(self.public_key)

    async def write_raw_ciphertext_fragment(self, fragment):
        self._gate("ciphertext-write")

    async def write_fragmented_ciphertext(self, data):
        self._gate("ciphertext-write")
        assert len(data) == CT_SIZE
        return 5

    async def send_control(self, data):
        self._gate("control-write")
        frame = v1.parse_v1_frame(data)
        assert frame.subtype == v1.V1_SEC_QUERY
        info = self.reported or v1.V1SecurityInfo(4, True, True, True, 16, 0x10)
        if self.reply == "silence" or self.callback is None:
            return                      # no subscriber (pre-L4 gating bug case)
        if self.reply == "error":
            wire = v1.encode_v1_error(v1.V1_STATUS_INVALID_STATE)
        else:
            wire = v1.encode_sec_info(info)
        self.callback(1, bytearray(wire))
        if self.reply == "extra":
            self.callback(1, bytearray(wire))

    async def start_notify(self, callback):
        self._gate("secure-data-cccd")
        self.callback = callback

    async def stop_notify(self):
        pass


class FakePairingBackend:
    """Stands in for winrt_pairing; drives the mock DK's security state."""

    def __init__(self, client, *, paired=False, decision=True, drop_link=False):
        self.client = client
        self.paired = paired
        self.decision = decision
        self.drop_link = drop_link
        self.protection = "ENCRYPTION_AND_AUTHENTICATION"
        self.just_works_accepted = False
        self.calls = []
        self.pin = "123456"
        if paired:
            client.secured = True   # LTK restored on demand

    async def inspect_pairing(self, client):
        self.calls.append("inspect")
        return PairingState(is_paired=self.paired, can_pair=True,
                            protection_level=self.protection if self.paired else "NONE")

    async def unpair(self, client):
        self.calls.append("unpair")
        self.paired = False
        self.client.secured = False
        self.client.is_connected = False

    async def pair_numeric_comparison(self, client, confirm, *, timeout):
        self.calls.append("nc")
        accept = await confirm(self.pin)
        if accept and self.decision:
            self.paired = True
            self.client.secured = True
            if self.drop_link:
                self.client.is_connected = False
            return PairingOutcome("PAIRED", True, self.protection, self.pin,
                                  "CONFIRM_PIN_MATCH", True, True)
        return PairingOutcome("REJECTED_BY_HANDLER" if not accept else "AUTHENTICATION_FAILURE",
                              False, "NONE", self.pin, "CONFIRM_PIN_MATCH", accept, accept)

    async def pair_just_works_test_only(self, client, *, timeout):
        self.calls.append("jw")
        if self.just_works_accepted:
            self.client.secured = True
            return PairingOutcome("PAIRED", True, "ENCRYPTION", None)
        return PairingOutcome("AUTHENTICATION_FAILURE", False, "NONE", None)


@pytest.fixture(scope="module")
def keypair():
    return generate_keypair()


async def _accept(pin):
    return True


async def _reject(pin):
    return False


def _run(client, backend, **kwargs):
    return asyncio.run(runner.run_v1_cp1(
        client, confirm_numeric_comparison=kwargs.pop("confirm", _accept),
        pairing_backend=backend, notification_timeout=0.2, quiet_window=0.01,
        **kwargs,
    ))


def test_cold_pairing_positive_flow(keypair):
    client = V1MockClient(keypair)
    backend = FakePairingBackend(client)
    result = _run(client, backend)
    assert result.scenario == "cold"
    assert set(result.pre_l4_denials) == set(runner.PRE_L4_PROBES)
    assert all("Insufficient Authentication" in r for r in result.pre_l4_denials.values())
    assert backend.calls == ["inspect", "nc"]
    assert result.pairing_status == "PAIRED"
    assert result.security_info == L4_INFO
    assert result.public_key_len == PK_SIZE and result.ciphertext_fragments == 5
    # Every PQ GATT op was tried exactly once before L4 and again after L4.
    before = [op for op, secured in client.log if not secured]
    after = [op for op, secured in client.log if secured]
    assert sorted(before) == sorted(runner.PRE_L4_PROBES)
    assert sorted(after) == sorted(runner.PRE_L4_PROBES)


@pytest.mark.parametrize("op", runner.PRE_L4_PROBES)
def test_any_pq_gatt_success_before_l4_fails_cp1(keypair, op):
    client = V1MockClient(keypair)
    client.gating_bug.add(op)
    backend = FakePairingBackend(client)
    with pytest.raises(runner.V1Error, match="GATING FAILURE"):
        _run(client, backend)
    assert "nc" not in backend.calls


@pytest.mark.parametrize(
    "exc", [BleakError("Could not read: Unreachable"), BleakGATTProtocolError(0x0E),
            BleakGATTProtocolError(0x13), RuntimeError("Not connected")],
)
def test_non_security_failure_before_l4_is_not_a_pass(keypair, exc):
    client = V1MockClient(keypair)
    client.deny_with = exc
    backend = FakePairingBackend(client)
    with pytest.raises(runner.V1Error, match="non-security"):
        _run(client, backend)


def test_disconnect_during_probe_is_reported(keypair):
    client = V1MockClient(keypair)

    def dropped(op):
        client.is_connected = False
        raise BleakError("device disconnected")
    client._gate = dropped
    backend = FakePairingBackend(client)
    with pytest.raises(runner.V1Error, match="connection lost"):
        _run(client, backend)


def test_pairing_rejected_in_positive_mode_never_opens_pq_gatt(keypair):
    client = V1MockClient(keypair)
    backend = FakePairingBackend(client, decision=False)
    with pytest.raises(runner.V1Error, match="pairing failed"):
        _run(client, backend)
    assert client.pq_gatt_after_l4 is False


def test_central_side_rejection_never_opens_pq_gatt(keypair):
    client = V1MockClient(keypair)
    backend = FakePairingBackend(client)
    with pytest.raises(runner.V1Error, match="pairing failed"):
        _run(client, backend, confirm=_reject)
    assert client.secured is False and client.pq_gatt_after_l4 is False


def test_unauthenticated_pairing_outcome_is_refused(keypair):
    client = V1MockClient(keypair)
    backend = FakePairingBackend(client)
    backend.protection = "ENCRYPTION"
    with pytest.raises(runner.V1Error, match="WITHOUT authentication"):
        _run(client, backend)
    assert client.pq_gatt_after_l4 is False


@pytest.mark.parametrize(
    "reported",
    [
        v1.V1SecurityInfo(2, True, False, False, 16, 0x10),   # L2 unauthenticated SC
        v1.V1SecurityInfo(3, False, True, False, 16, 0x10),   # L3 legacy
        v1.V1SecurityInfo(4, True, True, False, 16, 0x10),    # gate closed
        v1.V1SecurityInfo(4, True, True, True, 7, 0x10),      # short key
        v1.V1SecurityInfo(4, True, True, True, 16, 0x07),     # wrong profile
    ],
)
def test_dk_attestation_below_l4_fails_closed(keypair, reported):
    client = V1MockClient(keypair)
    client.reported = reported
    backend = FakePairingBackend(client)
    with pytest.raises(runner.V1Error, match="NOT authenticated Security Mode 1"):
        _run(client, backend)


@pytest.mark.parametrize("reply,pattern", [("error", "PQV1 ERROR"), ("silence", "timed out"), ("extra", "extra notification")])
def test_bad_dk_replies_fail(keypair, reply, pattern):
    client = V1MockClient(keypair)
    client.reply = reply
    backend = FakePairingBackend(client)
    with pytest.raises(runner.V1Error, match=pattern):
        _run(client, backend)


def test_link_drop_after_bonding_is_recovered(keypair):
    client = V1MockClient(keypair)
    backend = FakePairingBackend(client, drop_link=True)
    result = _run(client, backend)
    assert client.reconnects == 1
    assert result.security_info == L4_INFO


def test_bonded_reconnect_skips_probes_and_pairing(keypair):
    client = V1MockClient(keypair)
    backend = FakePairingBackend(client, paired=True)
    result = _run(client, backend)
    assert result.scenario == "bonded"
    assert result.pre_l4_denials == {}
    assert backend.calls == ["inspect"]
    assert result.pairing_status == "ALREADY_PAIRED"
    assert result.security_info == L4_INFO


def test_stale_bond_is_diagnosed(keypair):
    client = V1MockClient(keypair)
    backend = FakePairingBackend(client, paired=True)
    client.secured = False              # DK forgot the bond
    with pytest.raises(runner.V1Error, match="stale/corrupted bond"):
        _run(client, backend)


def test_unpair_first_forces_cold_pairing(keypair):
    client = V1MockClient(keypair)
    backend = FakePairingBackend(client, paired=True)
    result = _run(client, backend, unpair_first=True)
    assert backend.calls == ["inspect", "unpair", "inspect", "nc"]
    assert client.reconnects == 1
    assert result.scenario == "cold"


# ── Negative modes: APP/PQ state must never be reached ──────────────────

def test_negative_pre_l4_only(keypair):
    client = V1MockClient(keypair)
    backend = FakePairingBackend(client)
    with pytest.raises(runner.V1NegativeTestPassed, match="Central custom pairing not invoked"):
        _run(client, backend, negative_test="pre-l4-only")
    assert backend.calls == ["inspect"] and client.pq_gatt_after_l4 is False


def test_negative_nc_reject_passes_only_when_rejected(keypair):
    client = V1MockClient(keypair)
    backend = FakePairingBackend(client, decision=False)
    with pytest.raises(runner.V1NegativeTestPassed, match="remain denied"):
        _run(client, backend, negative_test="nc-reject", confirm=_reject)
    assert client.pq_gatt_after_l4 is False

    # Windows authentication failure after local acceptance cannot prove a
    # DK button rejection or exclude a failure after encryption/key distribution.
    client = V1MockClient(keypair)
    backend = FakePairingBackend(client, decision=False)
    with pytest.raises(runner.V1Error, match="DK-only rejection requires UART evidence"):
        _run(client, backend, negative_test="nc-reject")

    client = V1MockClient(keypair)
    backend = FakePairingBackend(client)          # DK/Windows accepted anyway
    with pytest.raises(runner.V1Error, match="SECURITY FAILURE"):
        _run(client, backend, negative_test="nc-reject")


def test_negative_just_works_must_be_refused_by_dk(keypair):
    client = V1MockClient(keypair)
    backend = FakePairingBackend(client)
    with pytest.raises(runner.V1NegativeTestPassed, match="just-works"):
        _run(client, backend, negative_test="just-works")
    assert backend.calls == ["inspect", "jw", "inspect", "inspect"] and client.pq_gatt_after_l4 is False

    client = V1MockClient(keypair)
    backend = FakePairingBackend(client)
    backend.just_works_accepted = True
    with pytest.raises(runner.V1Error, match="SECURITY FAILURE"):
        _run(client, backend, negative_test="just-works")


def test_negative_modes_require_cold_state(keypair):
    client = V1MockClient(keypair)
    backend = FakePairingBackend(client, paired=True)
    with pytest.raises(runner.V1Error, match="requires the cold-pairing state"):
        _run(client, backend, negative_test="nc-reject")


def test_unknown_negative_mode_rejected(keypair):
    client = V1MockClient(keypair)
    with pytest.raises(ValueError):
        _run(client, FakePairingBackend(client), negative_test="bogus")


@pytest.mark.parametrize("mode", ["nc-reject", "just-works"])
@pytest.mark.parametrize("drop", ["before_result", "deferred_disconnect", "still_live"])
def test_negative_security_rejection_retires_link_before_reprobe(keypair, mode, drop):
    client = V1MockClient(keypair)
    backend = FakePairingBackend(client)
    rejected = False
    retired = False
    original_gate = client._gate

    def gate(op):
        # A delayed Windows disconnect must not become a probe on a dead link.
        if rejected and not retired:
            client.is_connected = False
            raise AssertionError("probed the rejected pairing connection")
        original_gate(op)

    async def reject(*args, **kwargs):
        nonlocal rejected
        rejected = True
        if drop == "before_result":
            client.is_connected = False
        if mode == "nc-reject":
            return PairingOutcome("FAILED", False, "NONE", "673253",
                                  "CONFIRM_PIN_MATCH", False, False)
        return PairingOutcome("AUTHENTICATION_FAILURE", False, "NONE", None)

    async def fresh(timeout=15):
        nonlocal retired
        retired = True
        client.reconnects += 1
        client.is_connected = True
        return True

    client._gate = gate
    client.reconnect_v1_peer = fresh
    backend.pair_numeric_comparison = reject
    backend.pair_just_works_test_only = reject
    with pytest.raises(runner.V1NegativeTestPassed, match="fresh unpaired connection"):
        _run(client, backend, negative_test=mode)
    assert retired and client.reconnects == 1
    assert len(client.log) == 8 and not client.pq_gatt_after_l4


@pytest.mark.parametrize("mode", ["nc-reject", "just-works"])
@pytest.mark.parametrize("status", ["FAILED", "HARDWARE_FAILURE", "NOT_READY_TO_PAIR",
    "OPERATION_ALREADY_IN_PROGRESS", "REQUIRED_HANDLER_NOT_REGISTERED",
    "AUTHENTICATION_TIMEOUT", "ACCESS_DENIED", "PAIRING_CANCELED", "CONNECTION_REJECTED"])
def test_negative_generic_failure_or_transport_drop_is_not_security_evidence(keypair, mode, status):
    client = V1MockClient(keypair)
    backend = FakePairingBackend(client)

    async def failed(*args, **kwargs):
        client.is_connected = False
        return PairingOutcome(status, False, "NONE", None)

    backend.pair_numeric_comparison = failed
    backend.pair_just_works_test_only = failed
    with pytest.raises(runner.V1NegativeTestInconclusive, match="INCONCLUSIVE"):
        _run(client, backend, negative_test=mode)
    assert client.reconnects == 0 and not client.pq_gatt_after_l4


@pytest.mark.parametrize("failure", ["reconnect", "new_link_lost", "bond", "gate", "notification"])
def test_negative_fresh_verification_cannot_hide_failures(keypair, failure):
    client = V1MockClient(keypair)
    backend = FakePairingBackend(client)

    async def fresh(timeout=15):
        if failure == "reconnect":
            return False
        if failure == "bond":
            backend.paired = True
        if failure == "gate":
            client.gating_bug.add("public-key-read")
        if failure == "new_link_lost":
            client.is_connected = False
            client.deny_with = RuntimeError("Not connected")
        return True

    original_pair = backend.pair_just_works_test_only

    async def reject(client, **kwargs):
        outcome = await original_pair(client, **kwargs)
        if failure == "notification":
            # Malicious delivery despite denied CCCD subscription.
            client.negative_handler(1, bytearray(b"unexpected"))
            await asyncio.sleep(0)
        return outcome

    original_notify = client.start_notify

    async def record_handler(handler):
        client.negative_handler = handler
        return await original_notify(handler)

    client.start_notify = record_handler
    client.reconnect_v1_peer = fresh
    backend.pair_just_works_test_only = reject
    with pytest.raises(runner.V1Error):
        _run(client, backend, negative_test="just-works")


def test_post_l4_failure_cleans_up_notification_subscription(keypair):
    client = V1MockClient(keypair)
    client.reply = "silence"
    stopped = []

    async def stop():
        stopped.append(True)

    client.stop_notify = stop
    with pytest.raises(runner.V1Error, match="timed out"):
        _run(client, FakePairingBackend(client))
    assert stopped == [True]


# ── CLI ─────────────────────────────────────────────────────────────────

def test_cli_flags():
    args = main.parse_args(["--v1-smp-l4-mlkem"])
    assert args.v1_smp_l4_mlkem and args.v1_negative is None
    assert main.parse_args(["--v1-smp-l4-mlkem", "--v1-negative", "just-works"]).v1_negative == "just-works"
    for argv in (
        ["--v1-negative", "nc-reject"],
        ["--v1-unpair-first"],
        ["--v1-smp-l4-mlkem", "--no-sas-confirm"],
        ["--v1-smp-l4-mlkem", "--phase7-auth-hybrid"],
        ["--v1-smp-l4-mlkem", "--v1-negative", "bogus"],
    ):
        with pytest.raises(SystemExit):
            main.parse_args(argv)


def _cli_args(**overrides):
    base = dict(device="PQ-BLE-Device", v1_negative=None, v1_unpair_first=False,
                v1_pairing_timeout=1.0)
    base.update(overrides)
    return SimpleNamespace(**base)


def test_cli_positive_and_failure_markers(monkeypatch, capsys):
    connected = []

    class FakeClient:
        def __init__(self, device_name):
            pass

        async def scan_and_connect(self, timeout):
            connected.append(True)
            return True

        async def disconnect(self):
            connected.append(False)

    async def fake_run(client, **kwargs):
        return runner.V1CP1Result(scenario="cold", security_info=L4_INFO,
                                  pairing_status="PAIRED",
                                  pairing_protection="ENCRYPTION_AND_AUTHENTICATION",
                                  pairing_ms=1234.0, public_key_len=PK_SIZE,
                                  ciphertext_fragments=5, post_l4_ms=50.0)

    monkeypatch.setattr(main, "BLECentralClient", FakeClient)
    monkeypatch.setattr(main, "run_v1_cp1", fake_run)
    assert asyncio.run(main._run_v1_smp_l4_mlkem_cli(_cli_args())) == 0
    out = capsys.readouterr().out
    assert "PQ-BLE V1.0 CP1 SMP-L4 FOUNDATION: PASS" in out
    assert connected == [True, False]

    async def failing(client, **kwargs):
        raise runner.V1Error("GATING FAILURE: public-key-read succeeded before Security Level 4")
    monkeypatch.setattr(main, "run_v1_cp1", failing)
    assert asyncio.run(main._run_v1_smp_l4_mlkem_cli(_cli_args())) == 1
    assert "FOUNDATION: FAIL" in capsys.readouterr().out

    async def negative(client, **kwargs):
        raise runner.V1NegativeTestPassed("just-works: pairing rejected")
    monkeypatch.setattr(main, "run_v1_cp1", negative)
    assert asyncio.run(main._run_v1_smp_l4_mlkem_cli(_cli_args(v1_negative="just-works"))) == 0
    assert "NEGATIVE TEST: PASS (just-works)" in capsys.readouterr().out
    # A positive result in negative mode is a failure.
    monkeypatch.setattr(main, "run_v1_cp1", fake_run)
    assert asyncio.run(main._run_v1_smp_l4_mlkem_cli(_cli_args(v1_negative="nc-reject"))) == 1
    assert "NEGATIVE TEST: FAIL (nc-reject)" in capsys.readouterr().out


@pytest.mark.parametrize("outcome,verification,verdict", [
    # Exact 2026-09-08 Windows result: no callback and no rejection provenance.
    (PairingOutcome("FAILED", False, "NONE", None), "closed", "INCONCLUSIVE"),
    (PairingOutcome("FAILED", False, "NONE", None, "CONFIRM_ONLY", None, False),
     "closed", "INCONCLUSIVE"),
    (PairingOutcome("FAILED", False, "NONE", None, "CONFIRM_ONLY", None, True),
     "closed", "PASS"),
    (PairingOutcome("AUTHENTICATION_FAILURE", False, "NONE", None), "closed", "PASS"),
    (PairingOutcome("AUTHENTICATION_TIMEOUT", False, "NONE", None), "closed", "INCONCLUSIVE"),
    (PairingOutcome("PAIRED", True, "ENCRYPTION", None), "closed", "FAIL"),
    (PairingOutcome("AUTHENTICATION_FAILURE", False, "NONE", None), "missing", "INCONCLUSIVE"),
    (PairingOutcome("AUTHENTICATION_FAILURE", False, "NONE", None), "open", "FAIL"),
])
def test_cli_confirm_only_evidence_scope(
    keypair, monkeypatch, capsys, caplog, outcome, verification, verdict,
):
    """Exercise the real runner/oracle through the CLI, including fresh probes."""
    client = V1MockClient(keypair)
    backend = FakePairingBackend(client)

    async def connect(timeout):
        return True

    async def disconnect():
        client.is_connected = False

    async def pair(*args, **kwargs):
        return outcome

    async def reconnect(timeout=15.0):
        client.reconnects += 1
        if verification == "open":
            client.gating_bug.add("public-key-read")
        return verification != "missing"

    async def run(actual_client, **kwargs):
        return await runner.run_v1_cp1(actual_client, pairing_backend=backend, **kwargs)

    client.scan_and_connect = connect
    client.disconnect = disconnect
    client.reconnect_v1_peer = reconnect
    backend.pair_just_works_test_only = pair
    monkeypatch.setattr(main, "BLECentralClient", lambda **kwargs: client)
    monkeypatch.setattr(main, "run_v1_cp1", run)
    code = asyncio.run(main._run_v1_smp_l4_mlkem_cli(_cli_args(v1_negative="just-works")))
    out = capsys.readouterr().out
    assert code == (0 if verdict == "PASS" else 1)
    assert f"NEGATIVE TEST: {verdict} (just-works)" in out
    assert "SMP-L4 FOUNDATION:" not in out
    assert not client.is_connected
    if verdict in ("PASS", "INCONCLUSIVE"):
        assert f"CONFIRM_ONLY FAIL-CLOSED: {verdict}" in out
        assert "RADIO-LEVEL JUST WORKS: NOT DEMONSTRATED" in out
    if verdict == "PASS":
        assert client.reconnects == 1 and len(client.log) == 8
    else:
        assert "PASS" not in out
    if verdict == "INCONCLUSIVE":
        assert "CP1 failed" not in caplog.text
        assert not client.pq_gatt_after_l4
        assert client.reconnects == (1 if verification == "missing" else 0)


def test_pairing_helper_is_windows_only_here():
    from src.central import winrt_pairing
    if os.name == "nt":
        pytest.skip("WinRT available on Windows")
    with pytest.raises(winrt_pairing.PairingUnavailableError):
        asyncio.run(winrt_pairing.inspect_pairing(object()))


# ── Firmware / configuration consistency (source parsing) ───────────────

def test_v07_baseline_prj_conf_untouched():
    assert "CONFIG_BT_SMP=n" in _read("prj.conf")


def test_v1_profile_fragment():
    frag = _read("v1_smp_l4_mlkem.conf")
    for line in (
        "CONFIG_PQ_PROFILE_V10_SMP_L4_MLKEM=y", "CONFIG_BT_SMP=y",
        "CONFIG_BT_SMP_SC_ONLY=y", "CONFIG_BT_SMP_ENFORCE_MITM=y",
        "CONFIG_BT_BONDABLE=y", "CONFIG_BT_SMP_ALLOW_UNAUTH_OVERWRITE=n",
        "CONFIG_BT_SETTINGS=y", "CONFIG_SETTINGS=y", "CONFIG_ZMS=y",
        "CONFIG_DK_LIBRARY=y",
    ):
        assert line in frag, line
    assert "CONFIG_BT_FIXED_PASSKEY" not in frag
    kconfig = _read("Kconfig")
    assert "choice PQ_PROFILE" in kconfig
    assert "config PQ_PROFILE_V07_HYBRID" in kconfig
    assert "config PQ_PROFILE_V10_SMP_L4_MLKEM" in kconfig
    assert "PQ_V1_CLEAR_BONDS_ON_BOOT" in kconfig
    cmake = _read("CMakeLists.txt")
    assert "target_sources_ifdef(CONFIG_PQ_PROFILE_V10_SMP_L4_MLKEM" in cmake
    assert "src/pq_v1_security.c" in cmake and "src/pq_v1_frame.c" in cmake


def test_firmware_gatt_permissions_and_runtime_gate():
    src = _read("src", "main.c")
    assert re.search(
        r"#define PQ_GATT_PERM_READ \(BT_GATT_PERM_READ_AUTHEN \| BT_GATT_PERM_READ_LESC\)", src)
    assert re.search(
        r"#define PQ_GATT_PERM_WRITE \(BT_GATT_PERM_WRITE_AUTHEN \| BT_GATT_PERM_WRITE_LESC\)", src)
    service = src[src.index("BT_GATT_SERVICE_DEFINE("):src.index("BUILD_ASSERT(\n\tARRAY_SIZE(attr_pq_service)")]
    assert service.count("PQ_GATT_PERM_READ,") == 1
    assert service.count("PQ_GATT_PERM_WRITE,") == 3
    assert "PQ_GATT_PERM_CCC" in service
    assert "BT_GATT_PERM_READ," not in service and "BT_GATT_PERM_WRITE," not in service
    for fn in ("read_public_key", "write_ciphertext", "write_secure_data", "write_control"):
        # Definition (not the forward declaration): the signature followed by '{'.
        match = re.search(rf"static ssize_t {fn}\([^;]*?\)\s*\{{", src)
        assert match, fn
        body = src[match.end():match.end() + 900]
        assert "pq_gatt_security_gate(conn," in body, fn
    assert "pq_v1_security_conn_is_l4(conn)" in src
    assert "BT_GATT_ERR(BT_ATT_ERR_AUTHENTICATION)" in src
    assert "pq_v1_security_on_connected(conn)" in src
    assert "pq_v1_security_on_disconnected(conn)" in src
    assert "Legacy v0.x control frame rejected" in src


def test_firmware_numeric_comparison_is_never_auto_accepted():
    sec = _read("src", "pq_v1_security.c")
    body = sec[sec.index("static void auth_passkey_confirm("):sec.index("static void auth_cancel(")]
    assert "bt_conn_auth_passkey_confirm(" not in body
    assert "bt_conn_auth_passkey_confirm(conn)" in sec      # only via button reply
    assert ".passkey_display = auth_passkey_display" in sec
    assert ".passkey_confirm = auth_passkey_confirm" in sec
    assert ".cancel = auth_cancel" in sec
    assert ".pairing_confirm = NULL" in sec
    assert "bt_conn_set_security(conn, BT_SECURITY_L4)" in sec
    assert ".security_changed = security_changed" in sec
    for check in ("bt_conn_get_security(conn) != BT_SECURITY_L4",
                  "BT_SECURITY_FLAG_SC", "enc_key_size != PQ_V1_L4_ENC_KEY_SIZE"):
        assert check in sec, check
    assert "settings_load()" in sec and "bt_unpair(BT_ID_DEFAULT, BT_ADDR_LE_ANY)" in sec
    assert "SECURITY DOWNGRADE" in sec


def test_firmware_and_python_v1_frame_constants_match():
    header = _read("src", "pq_v1_frame.h")
    defines = dict(re.findall(r"#define (PQ_V1_\w+) (0x[0-9A-Fa-f]+|\d+)U?", header))
    assert header.count('#define PQ_V1_FRAME_MAGIC "PQV1"') == 1
    expected = {
        "PQ_V1_FRAME_VERSION": v1.V1_FRAME_VERSION,
        "PQ_V1_FRAME_HEADER_SIZE": v1.V1_FRAME_HEADER_SIZE,
        "PQ_V1_SEC_QUERY": v1.V1_SEC_QUERY,
        "PQ_V1_SEC_INFO": v1.V1_SEC_INFO,
        "PQ_V1_START": v1.V1_START,
        "PQ_V1_READY": v1.V1_READY,
        "PQ_V1_FINISHED_C": v1.V1_FINISHED_C,
        "PQ_V1_FINISHED_P": v1.V1_FINISHED_P,
        "PQ_V1_ERROR": v1.V1_ERROR,
        "PQ_V1_SEC_INFO_PAYLOAD_SIZE": v1.V1_SEC_INFO_PAYLOAD_SIZE,
        "PQ_V1_SEC_FLAG_SC": v1.V1_SEC_FLAG_SC,
        "PQ_V1_SEC_FLAG_AUTHENTICATED": v1.V1_SEC_FLAG_AUTHENTICATED,
        "PQ_V1_SEC_FLAG_GATE_OPEN": v1.V1_SEC_FLAG_GATE_OPEN,
        "PQ_V1_PROFILE_ID": v1.V1_PROFILE_ID,
        "PQ_V1_STATUS_INSUFFICIENT_SECURITY": v1.V1_STATUS_INSUFFICIENT_SECURITY,
        "PQ_V1_STATUS_LEGACY_CONTROL_REJECTED": v1.V1_STATUS_LEGACY_CONTROL_REJECTED,
        "PQ_V1_STATUS_INVALID_STATE": v1.V1_STATUS_INVALID_STATE,
        "PQ_V1_STATUS_NOTIFICATIONS_DISABLED": v1.V1_STATUS_NOTIFICATIONS_DISABLED,
        "PQ_V1_STATUS_UNSUPPORTED_SUBTYPE": v1.V1_STATUS_UNSUPPORTED_SUBTYPE,
    }
    for name, value in expected.items():
        assert name in defines, name
        assert int(defines[name], 0) == value, name
