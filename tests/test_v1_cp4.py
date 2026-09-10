"""CP4 software evidence: real Python/host C crypto, modeled BLE/RTOS lifecycle."""
import asyncio
import ctypes
import hmac
import logging
from pathlib import Path
import subprocess

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.common import v1_cp4 as cp4, v1_smp_mlkem as wire
from src.central import main, v1_cp4 as runner
from src.central.ble_client import BLECentralClient
from src.central.v1_smp_mlkem import V1Error
from tests.test_v1_cp1 import FakePairingBackend, keypair
from tests.test_v1_cp3 import (
    native_cp3, CP3Client, handshake, assert_cleared, flip, C2P, P2C, FP, TH0,
)

SID, PLAIN = bytes(range(16)), bytes(range(16))
IV_C = bytes.fromhex("860a23ba8b7c46a71d65c92e")
IV_P = bytes.fromhex("6b97e484d7d7ca56f4fffde1")
VECTORS = [
    (cp4.APP_C2P, C2P, IV_C, 0, cp4.PING,
     "505156311020002b0000000000000000010010c99979e610542d1a34111f35d3c16b0b929e4cf1eaad45136619992e60924c58"),
    (cp4.APP_C2P, C2P, IV_C, 1, cp4.PING,
     "505156311020002b0000000000000001010010999f38061b419d963d4a1991a1c9d2fe67ff182c37797461b2c848a3b792a922"),
    (cp4.APP_P2C, P2C, IV_P, 0, cp4.PONG,
     "505156311021002b0000000000000000020010add8e8ca9e93cd9d3843ffde52b1c578e62e424e2504adf5992a4d1d621eca98"),
    (cp4.APP_P2C, P2C, IV_P, 1, cp4.PONG,
     "505156311021002b00000000000000010200105f2a1a3dfeb13866cca0c15816922e845ea632876c9dfcd8fe05af53e5907d3f"),
]


@pytest.fixture(scope="module")
def native_cp4(native_cp3):
    exe, lib = native_cp3
    ptr, size, u64, byte = ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint64, ctypes.c_uint8
    lib.pq_v1_cp4_iv.argtypes = [ptr, ptr, byte, ptr]
    lib.pq_v1_cp4_nonce.argtypes = [ptr, u64, ptr]
    lib.pq_v1_cp4_aad.argtypes = [ptr, ptr, size, ptr]
    lib.pq_v1_cp4_encrypt.argtypes = [ptr, ptr, ptr, byte, u64, byte, ptr, size, ptr, size, ptr]
    lib.pq_v1_cp4_decrypt.argtypes = [ptr, ptr, ptr, ptr, size, byte, u64, ptr, size, ptr]
    lib.pq_v1_cp4_parse.argtypes = [ptr, size, byte, ptr]
    return exe, lib


def native_decrypt(lib, key, iv, sid, raw, direction=cp4.APP_C2P, seq=0):
    out, actual = ctypes.create_string_buffer(b"x" * 128, 128), ctypes.c_size_t(99)
    ret = lib.pq_v1_cp4_decrypt(key, iv, sid, raw, len(raw), direction, seq,
                               out, 128, ctypes.byref(actual))
    if ret:
        assert actual.value == 0 and out.raw == bytes(128)
    return ret, out.raw[:actual.value]


@pytest.mark.parametrize("direction,key,iv,seq,typ,hex_wire", VECTORS)
def test_known_answers_and_c_python_interoperability(native_cp4, direction, key, iv, seq, typ, hex_wire):
    _, lib = native_cp4
    raw = bytes.fromhex(hex_wire)
    assert cp4.derive_iv_base(key, SID, direction) == iv
    assert cp4.nonce_for_sequence(iv, seq) == iv[:11] + bytes([iv[11] ^ seq])
    assert cp4.encrypt_application(key, iv, SID, direction, seq, typ, PLAIN) == raw
    assert cp4.decrypt_application(key, iv, SID, raw, direction, seq) == PLAIN
    assert len(raw) == 51 and raw[8:16] == seq.to_bytes(8, "big")
    frame = cp4.parse_application_frame(raw, direction)
    assert frame.msg_type == typ and len(frame.ciphertext) == len(frame.tag) == 16
    assert cp4.encode_application_frame(direction, seq, typ, frame.ciphertext, frame.tag) == raw
    iv_out, nonce = ctypes.create_string_buffer(12), ctypes.create_string_buffer(12)
    assert lib.pq_v1_cp4_iv(key, SID, direction, iv_out) == 0 and iv_out.raw == iv
    assert lib.pq_v1_cp4_nonce(iv, seq, nonce) == 0 and nonce.raw == cp4.nonce_for_sequence(iv, seq)
    assert native_decrypt(lib, key, iv, SID, raw, direction, seq) == (0, PLAIN)
    out, count = ctypes.create_string_buffer(163), ctypes.c_size_t()
    assert lib.pq_v1_cp4_encrypt(key, iv, SID, direction, seq, typ, PLAIN, 16,
                               out, 163, ctypes.byref(count)) == 0
    assert out.raw[:count.value] == raw
    assert cp4.decrypt_application(key, iv, SID, out.raw[:count.value], direction, seq) == PLAIN


def test_aad_known_answer(native_cp4):
    raw = bytes.fromhex(VECTORS[0][-1])
    expected = bytes.fromhex(
        "50512d424c452d48414e445348414b452d76312e302f4350342d414144"
        "000102030405060708090a0b0c0d0e0f505156311020002b0000000000000000010010")
    assert cp4.build_aad(SID, raw[:8], 0, cp4.PING, 16) == expected
    out = ctypes.create_string_buffer(len(expected))
    assert native_cp4[1].pq_v1_cp4_aad(SID, raw, len(raw), out) == 0
    assert out.raw == expected


@pytest.mark.parametrize("direction,key,iv", [(cp4.APP_C2P, C2P, IV_C), (cp4.APP_P2C, P2C, IV_P)])
@pytest.mark.parametrize("field", ["key", "sid", "direction"])
def test_iv_binding(native_cp4, direction, key, iv, field):
    if field == "key": key = flip(key)
    if field == "sid": sid = flip(SID)
    else: sid = SID
    if field == "direction": direction ^= 1
    expected = cp4.derive_iv_base(key, sid, direction)
    assert expected != iv
    out = ctypes.create_string_buffer(12)
    assert native_cp4[1].pq_v1_cp4_iv(key, sid, direction, out) == 0
    assert out.raw == expected


@pytest.mark.parametrize("seq", [-1, 1 << 64, True, 1.5])
def test_invalid_sequence(seq):
    with pytest.raises(ValueError): cp4.nonce_for_sequence(IV_C, seq)
    with pytest.raises(ValueError): cp4.validate_sequence(seq, 0)


def test_full_uint64_nonce(native_cp4):
    seq = 0x0102030405060708
    nonce = ctypes.create_string_buffer(12)
    assert native_cp4[1].pq_v1_cp4_nonce(IV_C, seq, nonce) == 0
    assert nonce.raw == bytes.fromhex("860a23ba8a7e45a31863ce26")
    assert cp4.nonce_for_sequence(IV_C, seq) == nonce.raw
    assert cp4.nonce_for_sequence(IV_C, cp4.UINT64_MAX) != cp4.nonce_for_sequence(IV_C, 0)
    assert IV_C != IV_P


@pytest.mark.parametrize("fault", ["magic", "version", "length", "plain_length", "short_tag", "trailing", "oversize", "subtype", "direction"])
def test_framing_rejections(native_cp4, fault):
    raw = bytes.fromhex(VECTORS[0][-1])
    if fault == "short_tag": raw = raw[:-1]
    elif fault == "trailing": raw += b"x"
    elif fault == "oversize": raw = b"PQV1\x10\x20\x00\x9c" + bytes(8) + b"\x01\x00\x81" + bytes(145)
    elif fault == "subtype": raw = raw[:5] + b"\x23" + raw[6:]
    else: raw = flip(raw, {"magic": 0, "version": 4, "length": 7, "plain_length": 18, "direction": 5}[fault])
    with pytest.raises(ValueError): cp4.parse_application_frame(raw, cp4.APP_C2P)
    assert native_cp4[1].pq_v1_cp4_parse(raw, len(raw), cp4.APP_C2P, ctypes.create_string_buffer(64)) != 0
    assert native_decrypt(native_cp4[1], C2P, IV_C, SID, raw)[0] != 0


def test_size_boundaries_and_exact_big_endian(native_cp4):
    raw = cp4.encode_application_frame(cp4.APP_C2P, 0x0102030405060708, cp4.PING, bytes(128), bytes(16))
    assert len(raw) == 163 and raw[8:19].hex() == "0102030405060708010080"
    assert native_cp4[1].pq_v1_cp4_parse(raw, len(raw), cp4.APP_C2P, ctypes.create_string_buffer(64)) == 0
    with pytest.raises(ValueError): cp4.encode_application_frame(cp4.APP_C2P, 0, 1, bytes(129), bytes(16))
    with pytest.raises(ValueError): cp4.encode_application_frame(cp4.APP_C2P, 0, 1, PLAIN, bytes(15))


@pytest.mark.parametrize("field", ["sid", "direction", "payload_length", "seq", "msg_type", "plaintext_length", "ciphertext", "tag", "key", "directional_key", "nonce"])
def test_authentication_binds_every_field(native_cp4, field):
    raw = bytes.fromhex(VECTORS[0][-1])
    key, sid, iv, direction, seq = C2P, SID, IV_C, cp4.APP_C2P, 0
    if field == "sid": sid = flip(sid)
    elif field == "key": key = flip(key)
    elif field == "directional_key": key = P2C
    elif field == "nonce": iv = flip(iv)
    else:
        raw = flip(raw, {"direction": 5, "payload_length": 7, "seq": 15, "msg_type": 16,
                         "plaintext_length": 18, "ciphertext": 19, "tag": 50}[field])
        if field == "direction": direction = cp4.APP_P2C
        if field == "seq": seq = 1
    with pytest.raises((ValueError, InvalidTag)):
        cp4.decrypt_application(key, iv, sid, raw, direction, seq)
    assert native_decrypt(native_cp4[1], key, iv, sid, raw, direction, seq)[0] != 0
    # Even otherwise inconsistent length fields are bound cryptographically.
    aad = cp4.CP4_AAD_LABEL + sid + raw[:19]
    with pytest.raises(InvalidTag):
        AESGCM(key).decrypt(cp4.nonce_for_sequence(iv, seq), raw[19:], aad)


@pytest.mark.parametrize("typ,size", [(2, 16), (3, 16), (1, 15), (1, 17), (1, 128)])
def test_authenticated_invalid_semantics_never_release_plaintext(native_cp4, typ, size):
    raw = cp4.encrypt_application(C2P, IV_C, SID, cp4.APP_C2P, 0, typ, bytes(size))
    with pytest.raises(ValueError): cp4.decrypt_application(C2P, IV_C, SID, raw, cp4.APP_C2P, 0)
    assert native_decrypt(native_cp4[1], C2P, IV_C, SID, raw)[0] != 0


@pytest.mark.parametrize("failure", [1, 2, 4, 5, 6])
def test_native_crypto_failures_wipe(native_cp4, failure):
    lib = native_cp4[1]
    flag = ctypes.c_int.in_dll(lib, "cp4_psa_failure" if failure < 3 else "cp2_psa_failure")
    flag.value = failure
    try:
        out, count = ctypes.create_string_buffer(b"x" * 163, 163), ctypes.c_size_t(99)
        if failure == 2:
            assert native_decrypt(lib, C2P, IV_C, SID, bytes.fromhex(VECTORS[0][-1]))[0] != 0
        elif failure == 5:
            assert lib.pq_v1_cp4_iv(C2P, SID, cp4.APP_C2P, out) != 0
            assert out.raw[:12] == bytes(12)
        else:
            assert lib.pq_v1_cp4_encrypt(C2P, IV_C, SID, cp4.APP_C2P, 0, cp4.PING, PLAIN, 16,
                                        out, 163, ctypes.byref(count)) != 0
            assert count.value == 0 and out.raw == bytes(163)
    finally:
        flag.value = 0
    assert bytes((ctypes.c_ubyte * 32).in_dll(lib, "cp2_psa_key")) == bytes(32)


def application():
    h = handshake()
    h.accept_ready(wire.encode_v1_frame(wire.V1_READY_CP3, TH0))
    h.accept_finished_p(FP)
    return cp4.CentralApplication(h)


@pytest.mark.parametrize("fault", ["replay", "skip", "tag", "challenge", "tx_exhausted", "rx_exhausted", "mtu"])
def test_central_counters_and_fatal_errors(fault):
    app = application()
    assert app.tx_c2p == app.rx_p2c == 0
    first = app.encrypt_ping(PLAIN, 54)
    assert first == bytes.fromhex(VECTORS[0][-1]) and app.tx_c2p == 1 and app.rx_p2c == 0
    app.accept_pong(bytes.fromhex(VECTORS[2][-1]), PLAIN, 54)
    assert app.tx_c2p == app.rx_p2c == 1
    if fault == "tx_exhausted": app.tx_c2p = cp4.UINT64_MAX
    if fault == "rx_exhausted": app.rx_p2c = cp4.UINT64_MAX
    expected_rx = app.rx_p2c
    with pytest.raises((ValueError, InvalidTag)):
        if fault in ("tx_exhausted", "mtu"):
            app.encrypt_ping(PLAIN, 53 if fault == "mtu" else 54)
        else:
            raw = cp4.encrypt_application(P2C, IV_P, SID, cp4.APP_P2C,
                0 if fault == "replay" else 2 if fault == "skip" else 1, cp4.PONG,
                flip(PLAIN) if fault == "challenge" else PLAIN)
            if fault == "tag": raw = flip(raw)
            app.accept_pong(raw, PLAIN, 247)
    assert app.rx_p2c == expected_rx
    assert_cleared(app.handshake)
    assert not any(app.iv_c2p + app.iv_p2c)
    with pytest.raises(ValueError): app.encrypt_ping(PLAIN, 247)


def test_central_before_secure_and_crypto_failure(monkeypatch):
    h = handshake()
    with pytest.raises(ValueError): cp4.CentralApplication(h)
    assert_cleared(h)
    app = application()
    def failure(*a, **kw): raise RuntimeError("injected encryption error")
    monkeypatch.setattr(cp4, "encrypt_application", failure)
    with pytest.raises(RuntimeError): app.encrypt_ping(PLAIN, 247)
    assert_cleared(app.handshake)
    assert app.tx_c2p == 0


class CP4Client(CP3Client):
    def __init__(self, keypair, fault=None):
        super().__init__(keypair)
        self.fault = fault
        self.pings, self.pongs, self.challenges, self.links = [], [], [], []

    async def start_notify(self, callback):
        await super().start_notify(callback)
        self._v1_notify_link = self.raw_client

    async def stop_notify(self):
        self.stopped = True
        BLECentralClient.clear_v1_cp3(self)

    async def send_control(self, data):
        self.links.append(self.raw_client)
        if data[5] != cp4.APP_C2P:
            return await super().send_control(data)
        self._gate("control-write")
        assert self._v1_cp3_session.state == "APP_SECURE"
        self.pings.append(data)
        seq = len(self.pings) - 1
        sid = self.start[8:]
        iv_c = cp4.derive_iv_base(self.app[0], sid, cp4.APP_C2P)
        challenge = cp4.decrypt_application(self.app[0], iv_c, sid, data, cp4.APP_C2P, seq)
        self.challenges.append(bytes(challenge))
        if self.fault == "send": raise RuntimeError("injected send failure")
        if self.fault == "timeout": return
        if self.fault == "blocked_send": await asyncio.Event().wait()
        if self.fault == "replace": self.raw_client = object()
        if self.fault == "disconnect": self.is_connected = False
        if self.fault == "cccd": self._v1_notify_link = None
        if self.fault == "downgrade":
            self.secured = False
            raise RuntimeError("ATT Insufficient Authentication")
        iv_p = cp4.derive_iv_base(self.app[1], sid, cp4.APP_P2C)
        raw = cp4.encrypt_application(self.app[0] if self.fault == "key" else self.app[1], iv_p, sid,
            cp4.APP_C2P if self.fault == "direction" else cp4.APP_P2C,
            0 if self.fault == "replay" and seq == 1 else 2 if self.fault == "skip" else seq,
            cp4.PING if self.fault == "type" else cp4.PONG,
            flip(challenge) if self.fault == "challenge" else challenge)
        if self.fault == "tag": raw = flip(raw)
        if self.fault == "ciphertext": raw = flip(raw, 19)
        if self.fault == "malformed": raw = raw[:-1]
        self.pongs.append(raw)
        self.callback(1, bytearray(raw))
        if self.fault == "duplicate": self.callback(1, bytearray(raw))


def run_client(client, bonded=True):
    async def accept(pin): return True
    return asyncio.run(runner.run_v1_cp4(client, pairing_backend=FakePairingBackend(client, paired=bonded),
        confirm_numeric_comparison=accept, notification_timeout=0.04, quiet_window=0.002))


@pytest.mark.parametrize("bonded", [False, True])
def test_same_connection_two_rounds(keypair, bonded, caplog):
    caplog.set_level(logging.INFO)
    client = CP4Client(keypair)
    owner = client.raw_client
    result = run_client(client, bonded)
    app = client._v1_cp4_session
    assert result.authenticated_rounds == 2 and result.app_secure and result.finished_p_verified
    assert app.tx_c2p == app.rx_p2c == 2
    assert len(client.pings) == len(client.pongs) == 2 and client.reconnects == 0
    assert all(link is owner for link in client.links)
    assert [cp4.parse_application_frame(raw, cp4.APP_C2P).seq for raw in client.pings] == [0, 1]
    assert [cp4.parse_application_frame(raw, cp4.APP_P2C).seq for raw in client.pongs] == [0, 1]
    assert client.challenges[0] != client.challenges[1]
    for value in (*client.app, *client.challenges, app.iv_c2p, app.iv_p2c):
        assert bytes(value).hex() not in caplog.text and repr(bytes(value)) not in caplog.text
    assert "PING seq=0: SENT" in caplog.text and "PONG seq=1: AUTHENTICATED" in caplog.text
    BLECentralClient.clear_v1_cp3(client)
    assert_cleared(app.handshake)
    assert not any(app.iv_c2p + app.iv_p2c)


@pytest.mark.parametrize("fault", ["send", "timeout", "blocked_send", "replace", "disconnect", "cccd", "downgrade",
    "key", "direction", "replay", "skip", "type", "challenge", "tag", "ciphertext", "malformed", "duplicate"])
def test_central_flow_failure_clears_and_cannot_reuse_nonce(keypair, fault):
    client = CP4Client(keypair, fault)
    observed = []
    original_stop = client.stop_notify
    async def stop():
        observed.append(client._v1_cp4_session)
        await original_stop()
    client.stop_notify = stop
    with pytest.raises(V1Error): run_client(client)
    assert len(client.pings) == (2 if fault == "replay" else 1)
    app = observed[0]
    assert app.tx_c2p == len(client.pings)
    assert_cleared(app.handshake)
    assert not any(app.iv_c2p + app.iv_p2c)
    with pytest.raises(ValueError): app.encrypt_ping(PLAIN, 247)


@pytest.mark.parametrize("extra", [[], ["--v1-cp2"], ["--v1-cp3"], ["--v1-negative", "nc-reject"]])
def test_cli_incompatible(extra):
    argv = ["--v1-cp4"] + (["--v1-smp-l4-mlkem"] + extra if extra else [])
    with pytest.raises(SystemExit): main.parse_args(argv)


@pytest.mark.parametrize("fault", [None, "tag"])
def test_cli_cp4_marker_disconnect_and_standalone_cp3(keypair, monkeypatch, capsys, fault):
    client = CP4Client(keypair, fault)
    observed = []
    async def connect(timeout): return True
    async def disconnect():
        observed.append(getattr(client, "_v1_cp4_session", None))
        BLECentralClient.clear_v1_cp3(client)
        client.is_connected = False
    async def run(client, **kwargs):
        return await runner.run_v1_cp4(client, **kwargs, pairing_backend=FakePairingBackend(client, paired=True),
            notification_timeout=0.04, quiet_window=0.002)
    client.scan_and_connect, client.disconnect = connect, disconnect
    monkeypatch.setattr(main, "BLECentralClient", lambda **kwargs: client)
    monkeypatch.setattr(main, "run_v1_cp4", run)
    args = main.parse_args(["--v1-smp-l4-mlkem", "--v1-cp4"])
    assert args.v1_cp4 and not args.v1_cp3 and not args.v1_cp2
    ret = asyncio.run(main._run_v1_smp_l4_mlkem_cli(args))
    assert ret == (1 if fault else 0) and not client.is_connected
    assert f"CP4 AES-256-GCM BIDIRECTIONAL DATA: {'FAIL' if fault else 'PASS'}" in capsys.readouterr().out
    if not fault: assert_cleared(observed[0].handshake)
    assert not main.parse_args(["--v1-smp-l4-mlkem", "--v1-cp3"]).v1_cp4


@pytest.mark.parametrize("scenario", range(100, 140), ids=[
    "two_rounds", "before_secure", "stale_caller", "stale_generation", "downgrade", "disconnect", "cccd",
    "malformed", "direction", "msg_type", "seq", "worker_busy", "mtu", "unsubscribed", "rx_exhaustion",
    "tx_exhaustion", "tag", "ciphertext", "directional_key", "decrypt_failure", "disconnect_in_crypto",
    "downgrade_in_crypto", "cccd_in_crypto", "generation_in_crypto", "security_error_in_crypto",
    "encrypt_failure", "notify_failure", "key_import", "hmac_failure", "key_destroy", "disconnect_at_notify",
    "downgrade_at_notify", "cccd_at_notify", "generation_at_notify", "security_error_at_notify",
    "replay", "skip", "second_notify_failure", "second_write_while_busy", "stale_before_worker",
])
def test_native_cp4_lifecycle(native_cp4, scenario):
    result = subprocess.run([str(native_cp4[0]), str(scenario)], capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr


def test_profile_isolation_and_worker_dispatch():
    root = Path(__file__).resolve().parents[1]
    cmake = (root / "firmware/CMakeLists.txt").read_text()
    assert "src/pq_v1_cp4.c" in cmake.split("target_sources_ifdef(CONFIG_PQ_PROFILE_V10_SMP_L4_MLKEM")[1]
    source = (root / "firmware/src/mlkem_session.c").read_text()
    from tests.test_v1_cp3 import production_function
    worker = production_function(source, "v1_cp4_result")
    assert "pqble_mlkem_dec" not in worker
    assert "PQ_MLKEM_JOB_V1_CP4_C2P ? v1_cp4_result" in source
    callback = production_function((root / "firmware/src/main.c").read_text(), "handle_v1_cp4")
    assert "pq_v1_cp4_encrypt" not in callback and "pq_v1_cp4_decrypt" not in callback
