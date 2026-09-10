"""CP3 software evidence; hardware acceptance requires actual Windows/DK logs."""
import asyncio
import ctypes
import hashlib
import hmac
import inspect
import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from src.central import main, v1_cp3 as runner
from src.central.ble_client import BLECentralClient
from src.central.v1_smp_mlkem import V1Error
from src.common import v1_cp3 as cp3, v1_smp_mlkem as wire
from src.common.ml_kem import decapsulate, encapsulate
from tests.test_v1_cp1 import keypair, FakePairingBackend, L4_INFO, SEC_INFO_L4
from tests.test_v1_cp2 import CP2Client

PK = bytes(i % 256 for i in range(1184))
CT = bytes((255-i) % 256 for i in range(1088))
SS = bytes(range(32))
START = bytes.fromhex("5051563110140010") + bytes(range(16))
TH0 = bytes.fromhex("81e305b6cbd39fa467eaf4188bcf6d8d9e59655792603f4267679b87186d0ca6")
PRK = bytes.fromhex("6282e21602008499fdfd79ce0c6729b410a0ae77f9a35c3a2c72212c695d9629")
KC = bytes.fromhex("cf3368cd1ac694c080360b4ce4d534ca02f03f65f805e2f6ce6287684741e240")
KP = bytes.fromhex("b6c00b43168b419dd001215914c95b33511e07398f6292f08fc2c5bedec2faea")
FC = bytes.fromhex("5051563110120020f3c310c2747f72bcd76d0ac051a86ee505d596371ed934e1c924fa7b2d7ca7c3")
TH1 = bytes.fromhex("5f85faa6ca53855d8a78148eec9ecade37eb170cc058ca4a065e21dda1d613c7")
FP = bytes.fromhex("5051563110130020e5bc8e1c48f13f863d6cf5317fb223abe91e669b9ff5056a5f36540f0f8e07b7")
TH2 = bytes.fromhex("92b34ac1594996aabddeb65445dbbf51fc0c7ddb133353f45e5812c016c35f74")
C2P = bytes.fromhex("e9256a22af1b2795ee6ed0698bc8b4ead9a40e2f243c81bb0cf99a677ba5f310")
P2C = bytes.fromhex("f9c8128213118cd8af8b9abf2045c6426a64cc9b5d77cbab2adea311e7bf79a0")


def flip(b, index=-1):
    b = bytearray(b)
    b[index] ^= 1
    return bytes(b)


@pytest.mark.parametrize("subtype,size", [(0x14, 16), (0x15, 32), (0x12, 32), (0x13, 32)])
@pytest.mark.parametrize("mutation", [None, "short", "long", "magic", "version", "length", "trailing"])
def test_frames(subtype, size, mutation):
    frame = b"PQV1\x10" + bytes([subtype, 0, size]) + bytes(range(size))
    if mutation is None:
        assert wire.encode_v1_frame(subtype, bytes(range(size))) == frame
        assert wire.parse_v1_frame(frame).payload == bytes(range(size))
        assert len(frame) == size + 8
        return
    if mutation in ("short", "long"):
        size += 1 if mutation == "long" else -1
        with pytest.raises(ValueError):
            wire.encode_v1_frame(subtype, bytes(size))
        frame = b"PQV1\x10" + bytes([subtype, 0, size]) + bytes(size)
    elif mutation == "trailing":
        frame += b"\0"
    else:
        frame = flip(frame, {"magic": 0, "version": 4, "length": 7}[mutation])
    with pytest.raises(ValueError):
        wire.parse_v1_frame(frame)


def test_canonical_transcript_and_schedule_known_answers():
    t0 = cp3.build_transcript(SEC_INFO_L4, PK, CT, START)
    assert t0 == b"PQ-BLE-HANDSHAKE-v1.0/CP3-TRANSCRIPT" + SEC_INFO_L4 + PK + CT + START
    assert len(t0) == 2344
    assert cp3.transcript_hash(SEC_INFO_L4, PK, CT, START) == TH0
    assert cp3.extract(TH0, SS) == PRK
    for label, th, key in [(cp3.FINISHED_C_LABEL, TH0, KC), (cp3.FINISHED_P_LABEL, TH0, KP),
                           (cp3.APP_C2P_LABEL, TH2, C2P), (cp3.APP_P2C_LABEL, TH2, P2C)]:
        assert cp3.expand(PRK, label, th) == key
        assert HKDFExpand(algorithm=hashes.SHA256(), length=32, info=label+th).derive(PRK) == key
    assert cp3.verify_data(KC, cp3.VERIFY_C_LABEL, TH0) == FC[8:]
    assert cp3.chain(TH0, FC) == TH1
    assert cp3.verify_data(KP, cp3.VERIFY_P_LABEL, TH1) == FP[8:]
    assert cp3.chain(TH1, FP) == TH2
    assert C2P != P2C
    # Full 32-byte RFC 5869 test case 1 PRK (independent standard vector).
    prk = hmac.digest(bytes(range(13)), b"\x0b" * 22, "sha256")
    assert prk.hex() == "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"


@pytest.mark.parametrize("index", range(4))
def test_transcript_binds_each_exact_input(index):
    values = [SEC_INFO_L4, PK, CT, START]
    values[index] = flip(values[index])
    changed = cp3.transcript_hash(*values)
    assert changed != TH0
    assert cp3.extract(changed, SS) != PRK
    assert cp3.expand(cp3.extract(changed, SS), cp3.FINISHED_C_LABEL, changed) != KC


@pytest.mark.parametrize("index", range(4))
def test_transcript_rejects_bad_size(index):
    values = [SEC_INFO_L4, PK, CT, START]
    values[index] = values[index][:-1]
    with pytest.raises(ValueError):
        cp3.transcript_hash(*values)


def test_other_secret_and_finished_chaining():
    assert cp3.extract(TH0, flip(SS)) != PRK
    changed_th1 = cp3.chain(TH0, flip(FC))
    assert changed_th1 != TH1
    assert cp3.verify_data(KP, cp3.VERIFY_P_LABEL, changed_th1) != FP[8:]
    assert list(inspect.signature(cp3.extract).parameters) == ["th0", "ss_mlkem"]


def handshake():
    h = cp3.CentralHandshake()
    h.begin(bytearray(SS), SEC_INFO_L4, PK, CT, START)
    return h


def assert_cleared(h):
    assert h.state == "CLOSED"
    assert not any(h.prk + h.finished_c + h.finished_p + h.th + h.app_c2p + h.app_p2c)


def test_central_handshake_keys_unavailable_until_finished_and_wiping(monkeypatch):
    comparisons = []
    compare = hmac.compare_digest
    monkeypatch.setattr(cp3.hmac, "compare_digest", lambda a, b: comparisons.append((len(a), len(b))) or compare(a, b))
    h = handshake()
    assert not h.app_c2p and not h.app_p2c
    assert h.accept_ready(wire.encode_v1_frame(0x15, TH0)) == FC
    assert not h.app_c2p and not h.app_p2c
    h.accept_finished_p(FP)
    assert h.state == "APP_SECURE" and h.app_c2p == C2P and h.app_p2c == P2C
    assert not any(h.prk + h.finished_c + h.finished_p + h.th)
    assert comparisons == [(32, 32), (32, 32)]
    h.clear()
    assert_cleared(h)


@pytest.mark.parametrize("fault", ["wrong_ready", "early_p", "wrong_p", "role_c", "duplicate_ready", "duplicate_p"])
def test_state_and_finished_failures_clear_everything(fault):
    h = handshake()
    with pytest.raises(ValueError):
        if fault == "wrong_ready":
            h.accept_ready(wire.encode_v1_frame(0x15, flip(TH0)))
        elif fault == "early_p":
            h.accept_finished_p(FP)
        else:
            h.accept_ready(wire.encode_v1_frame(0x15, TH0))
            if fault == "duplicate_ready":
                h.accept_ready(wire.encode_v1_frame(0x15, TH0))
            elif fault == "duplicate_p":
                h.accept_finished_p(FP)
                h.accept_finished_p(FP)
            else:
                h.accept_finished_p(FC if fault == "role_c" else flip(FP))
    assert_cleared(h)


class CP3Client(CP2Client):
    async def send_control(self, data):
        frame = wire.parse_v1_frame(data)
        if frame.subtype == wire.V1_SEC_QUERY:
            return await super().send_control(data)
        self._gate("control-write")
        self.controls.append(frame.subtype)
        if frame.subtype == wire.V1_START_CP3:
            assert self.attestations == 2
            self.start = data
            self.th0 = hashlib.sha256(cp3.CP3_TRANSCRIPT_LABEL + wire.encode_sec_info(L4_INFO)
                                     + self.public_key + self.ct + data).digest()
            ss = decapsulate(self.secret_key, self.ct)
            self.prk = hmac.digest(self.th0, ss, "sha256")
            self.kc = HKDFExpand(algorithm=hashes.SHA256(), length=32,
                                info=cp3.FINISHED_C_LABEL + self.th0).derive(self.prk)
            self.kp = HKDFExpand(algorithm=hashes.SHA256(), length=32,
                                info=cp3.FINISHED_P_LABEL + self.th0).derive(self.prk)
            if self.failure == "timeout":
                return
            if self.failure == "start_exception":
                raise RuntimeError("start refused")
            raw = wire.encode_v1_frame(wire.V1_READY_CP3, self.th0)
            if self.failure == "wrong_ready": raw = flip(raw)
            if self.failure == "role_c": raw = FC
            if self.failure == "worker": raw = wire.encode_v1_error(wire.V1_STATUS_CP3_FAILURE)
            if self.failure == "malformed": raw = raw[:-1]
            if self.failure == "ready_replace": self.raw_client = object()
        else:
            assert frame.subtype == wire.V1_FINISHED_C
            assert hmac.compare_digest(frame.payload, hmac.digest(self.kc, cp3.VERIFY_C_LABEL+self.th0, "sha256"))
            th1 = hashlib.sha256(self.th0 + data).digest()
            raw = wire.encode_v1_frame(wire.V1_FINISHED_P, hmac.digest(self.kp, cp3.VERIFY_P_LABEL+th1, "sha256"))
            th2 = hashlib.sha256(th1 + raw).digest()
            self.app = tuple(HKDFExpand(algorithm=hashes.SHA256(), length=32,
                             info=label+th2).derive(self.prk) for label in (cp3.APP_C2P_LABEL, cp3.APP_P2C_LABEL))
            if self.failure == "wrong_p": raw = flip(raw)
            if self.failure == "p_timeout": return
            if self.failure == "p_replace": self.raw_client = object()
            if self.failure == "p_disconnect": self.is_connected = False
            if self.failure == "finished_exception": raise RuntimeError("FINISHED refused")
        self.callback(1, bytearray(raw))
        if self.failure in ("duplicate_ready", "duplicate_p"):
            if (frame.subtype == wire.V1_START_CP3) == (self.failure == "duplicate_ready"):
                self.callback(1, bytearray(raw))


def run_client(client, backend):
    async def accept(pin): return True
    return asyncio.run(runner.run_v1_cp3(client, pairing_backend=backend,
        confirm_numeric_comparison=accept, notification_timeout=0.05, quiet_window=0.005))


@pytest.mark.parametrize("bonded", [False, True])
def test_central_real_mlkem_flow(keypair, bonded):
    client = CP3Client(keypair)
    result = run_client(client, FakePairingBackend(client, paired=bonded))
    assert result.app_secure and result.finished_p_verified and result.transcript_match
    assert client.controls == [1, 1, 0x14, 0x12]
    h = client._v1_cp3_session
    assert (h.app_c2p, h.app_p2c) == client.app
    assert not client.stopped  # keep CCCD and keys for the same live session
    BLECentralClient.clear_v1_cp3(client)
    assert_cleared(h)


@pytest.mark.parametrize("fault", ["weak_initial", "short_pk", "ct_exception", "replace_link", "disconnect",
    "downgrade", "timeout", "start_exception", "worker", "wrong_ready", "role_c", "malformed",
    "ready_replace", "duplicate_ready", "wrong_p", "p_timeout", "p_replace", "p_disconnect",
    "duplicate_p", "finished_exception"])
def test_central_fail_closed_and_wiping(keypair, monkeypatch, fault):
    secrets_seen = []
    encap = runner.encapsulate
    def observed(pk):
        ct, ss = encap(pk)
        owned = bytearray(ss)
        secrets_seen.append(owned)
        return ct, owned
    monkeypatch.setattr(runner, "encapsulate", observed)
    client = CP3Client(keypair, fault)
    with pytest.raises(V1Error):
        run_client(client, FakePairingBackend(client, paired=True))
    assert_cleared(client._v1_cp3_session)
    assert client.stopped and all(not any(secret) for secret in secrets_seen)
    if fault in ("wrong_ready", "duplicate_ready", "role_c"):
        assert 0x12 not in client.controls


def test_cli_explicit_and_incompatible():
    assert not main.parse_args(["--v1-smp-l4-mlkem"]).v1_cp3
    assert not main.parse_args(["--v1-smp-l4-mlkem", "--v1-cp2"]).v1_cp3
    assert main.parse_args(["--v1-smp-l4-mlkem", "--v1-cp3"]).v1_cp3
    for args in (["--v1-cp3"], ["--v1-smp-l4-mlkem", "--v1-cp2", "--v1-cp3"],
                 ["--v1-smp-l4-mlkem", "--v1-cp3", "--v1-negative", "nc-reject"]):
        with pytest.raises(SystemExit): main.parse_args(args)


@pytest.mark.parametrize("fault", [None, "wrong_p", "wrong_ready"])
def test_cli_marker_and_cleanup(keypair, monkeypatch, capsys, fault):
    client = CP3Client(keypair, fault)
    backend = FakePairingBackend(client, paired=True)
    async def connect(timeout): return True
    async def disconnect(): client.is_connected = False
    async def run(client, **kwargs):
        return await runner.run_v1_cp3(client, **kwargs, pairing_backend=backend,
                                      notification_timeout=0.05, quiet_window=0.005)
    client.scan_and_connect, client.disconnect = connect, disconnect
    monkeypatch.setattr(main, "BLECentralClient", lambda **kwargs: client)
    monkeypatch.setattr(main, "run_v1_cp3", run)
    result = asyncio.run(main._run_v1_smp_l4_mlkem_cli(main.parse_args(["--v1-smp-l4-mlkem", "--v1-cp3"])))
    output = capsys.readouterr().out
    assert result == (0 if fault is None else 1)
    assert f"CP3 TRANSCRIPT + FINISHED: {'PASS' if fault is None else 'FAIL'}" in output
    assert "CP2 ML-KEM-L4" not in output and "CP1 SMP-L4 FOUNDATION: PASS" not in output
    assert not client.is_connected
    assert_cleared(client._v1_cp3_session)


def test_constants_and_no_legacy_crypto_or_cp4():
    root = Path(__file__).resolve().parents[1]
    header = (root / "firmware/src/pq_v1_frame.h").read_text()
    for name in ("START_CP3", "READY_CP3", "FINISHED_C", "FINISHED_P", "CP3_SESSION_ID_SIZE",
                 "CP3_HASH_SIZE", "START_CP3_FRAME_SIZE", "READY_CP3_FRAME_SIZE", "FINISHED_FRAME_SIZE"):
        match = re.search(rf"#define PQ_V1_{name} (0x[0-9a-fA-F]+|\d+)U", header)
        assert int(match[1], 0) == getattr(wire, "V1_" + name)
    for path in ("src/common/v1_cp3.py", "src/central/v1_cp3.py", "firmware/src/pq_v1_cp3.c"):
        source = (root / path).read_text()
        for forbidden in ("phase7", "ss_ecdh", "AESGCM", "PING", "PONG", "K_sas"):
            assert forbidden not in source


class CHandshake(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ubyte * 32) for name in ("th0", "prk", "kc", "kp")]


class CApplication(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ubyte * 32) for name in ("c2p", "p2c")]


def production_function(source, name):
    match = re.search(rf"^(?:static )?(?:bool|int|void|ssize_t) {name}\([^;]*?\)\s*\{{", source, re.M)
    assert match, name
    depth, end = 1, match.end()
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


@pytest.fixture(scope="module")
def native_cp3(tmp_path_factory):
    if os.name != "nt" or not shutil.which("gcc"):
        pytest.skip("native CP3 requires Windows BCrypt and host GCC")
    root = Path(__file__).resolve().parents[1]
    build = tmp_path_factory.mktemp("cp3_native")
    native, firmware = root / "tests/native_v1", root / "firmware/src"
    mlkem = root / "firmware/third_party/mlkem-native/mlkem"
    (build / "psa").mkdir()
    (build / "psa/crypto.h").write_text('#include "cp4_psa.h"\n')
    source = (firmware / "main.c").read_text()
    state = source[source.index("enum v1_cp3_state {"):source.index("static void v1_cp3_timeout(")]
    names = ("clear_transfer_storage_locked", "begin_transfer_locked", "write_ciphertext",
             "invalidate_v1_cp2_locked", "invalidate_v1_cp3_locked", "v1_cp3_timeout", "v1_cp3_live_locked",
             "v1_cp4_live_locked", "pq_v1_cp4_job_live", "handle_v1_cp4", "v1_cp4_result_ready",
             "handle_v1_cp3_start", "handle_v1_cp3_finished_c", "v1_cp3_result_ready",
             "handle_v1_cp2_start", "v1_cp2_security_changed", "handle_v1_control",
             "connected", "disconnected", "ccc_config_changed")
    (build / "cp3_main.inc").write_text("\n".join(production_function(source, n) for n in names))
    source = (firmware / "mlkem_session.c").read_text()
    state += source[source.index("static uint32_t v1_cp3_epoch"):source.index("#endif", source.index("static uint32_t v1_cp3_epoch"))]
    (build / "cp3_state.inc").write_text(state)
    names = ("v1_cp4_result", "v1_cp3_start_result", "v1_cp3_finished_result", "v1_cp3_job_complete_locked",
             "pq_mlkem_session_reset_v1_cp3", "pq_mlkem_session_submit_v1_cp3",
             "pq_mlkem_session_submit_v1_cp3_finished_c", "pq_mlkem_session_commit_v1_cp3",
             "pq_mlkem_session_submit_v1_cp4", "pq_mlkem_session_commit_v1_cp4",
             "pq_mlkem_session_submit_v1_cp2", "pq_mlkem_session_reset_v1_cp2")
    (build / "cp3_worker.inc").write_text("\n".join(production_function(source, n) for n in names))
    command = [shutil.which("gcc"), "-std=c11", "-Wall", "-Wextra", "-Werror", "-O1",
               "-DCONFIG_PQ_PROFILE_V10_SMP_L4_MLKEM=1", "-DCONFIG_PQ_V1_CP3_TIMEOUT_MS=30000",
               "-DCP2_NATIVE_HASH_CAPACITY=4096", "-DMLK_CONFIG_PARAMETER_SET=768",
               "-DMLK_CONFIG_NO_RANDOMIZED_API", "-DMLK_CONFIG_NAMESPACE_PREFIX=pqble_mlkem",
               "-DMLK_CONFIG_INTERNAL_API_QUALIFIER=static"]
    for path in (build, native, firmware, mlkem): command += ["-I", str(path)]
    command += [str(native / "cp3_lifecycle.c"), str(firmware / "pq_v1_cp3.c"),
                str(firmware / "pq_v1_cp4.c"),
                str(firmware / "pq_v1_frame.c"), str(mlkem / "mlkem_native.c"), "-lbcrypt"]
    exe, dll = build / "cp3.exe", build / "cp3.dll"
    for output, extra in ((exe, []), (dll, ["-shared"])):
        result = subprocess.run(command + extra + ["-o", str(output)], capture_output=True, text=True, timeout=90)
        assert result.returncode == 0, result.stdout + result.stderr
    return exe, ctypes.CDLL(str(dll))


@pytest.mark.parametrize("fault", range(8))
def test_native_crypto_kat_and_psa_failure_wiping(native_cp3, fault):
    _, lib = native_cp3
    failure = ctypes.c_int.in_dll(lib, "cp2_psa_failure")
    failure.value = fault
    out = ctypes.create_string_buffer(32)
    fn = lib.pq_v1_cp3_transcript
    fn.argtypes = [ctypes.c_char_p, ctypes.c_size_t] * 4 + [ctypes.c_void_p]
    fn.restype = ctypes.c_int
    h, app = CHandshake(), CApplication()
    secret = ctypes.create_string_buffer(SS, 32)
    try:
        ret = fn(SEC_INFO_L4, 12, PK, 1184, CT, 1088, START, 24, out)
        if fault in (1, 2, 3, 7):
            assert ret != 0 and out.raw == bytes(32)
            return
        assert ret == 0 and out.raw == TH0
        ret = lib.pq_v1_cp3_derive(secret, TH0, ctypes.byref(h))
        assert secret.raw == bytes(32)
        if fault:
            assert ret != 0 and bytes(h) == bytes(128)
            return
        assert ret == 0
        assert (bytes(h.th0), bytes(h.prk), bytes(h.kc), bytes(h.kp)) == (TH0, PRK, KC, KP)
        fp = ctypes.create_string_buffer(40)
        assert lib.pq_v1_cp3_finish(ctypes.byref(h), FC, len(FC), fp, ctypes.byref(app)) == 0
        assert fp.raw == FP and bytes(h) == bytes(128)
        assert (bytes(app.c2p), bytes(app.p2c)) == (C2P, P2C)
    finally:
        failure.value = 0
        assert bytes((ctypes.c_ubyte * 32).in_dll(lib, "cp2_psa_key")) == bytes(32)


@pytest.mark.parametrize("fault", ["wrong_c", "direction_p", "short", "mac_failure", "hash_failure"])
def test_native_finished_failure_no_p_or_application_keys(native_cp3, fault):
    _, lib = native_cp3
    h, app = CHandshake(), CApplication()
    secret = ctypes.create_string_buffer(SS, 32)
    assert lib.pq_v1_cp3_derive(secret, TH0, ctypes.byref(h)) == 0
    failure = ctypes.c_int.in_dll(lib, "cp2_psa_failure")
    data = flip(FC) if fault == "wrong_c" else FP if fault == "direction_p" else FC[:-1] if fault == "short" else FC
    failure.value = 5 if fault == "mac_failure" else 2 if fault == "hash_failure" else 0
    fp = ctypes.create_string_buffer(b"x" * 40, 40)
    try:
        assert lib.pq_v1_cp3_finish(ctypes.byref(h), data, len(data), fp, ctypes.byref(app)) != 0
        assert bytes(h) == bytes(128) and bytes(app) == bytes(64) and fp.raw == bytes(40)
    finally:
        failure.value = 0


@pytest.mark.parametrize("scenario", range(34), ids=[
    "success", "pre_l4", "stale_caller", "incomplete_ct", "notify_disabled", "unsubscribed",
    "cp2_active", "worker_busy", "stale_job_ref", "keypair_missing", "short_start", "small_mtu",
    "early_finished", "finished_while_busy", "disconnect_new_peer_during_decap", "downgrade_during_decap",
    "security_error", "stale_generation", "cccd_during_decap", "timeout_during_decap", "psa_failure",
    "decap_failure", "ready_notify_failure", "malformed_worker_reply", "disconnect_wait", "downgrade_wait",
    "cccd_wait", "timeout_wait", "wrong_finished_c", "finished_notify_failure", "disconnect_at_finished_send",
    "timeout_at_finished_send", "cccd_after_secure", "immediate_finished_response",
])
def test_native_lifecycle(native_cp3, scenario):
    exe, _ = native_cp3
    result = subprocess.run([str(exe), str(scenario)], capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("mutated", [False, True])
def test_liboqs_to_c_cp3(native_cp3, keypair, mutated):
    _, lib = native_cp3
    pk, sk = keypair
    ct, ss = encapsulate(pk)
    h = cp3.CentralHandshake()
    h.begin(bytearray(ss), SEC_INFO_L4, pk, ct, START)
    fc = h.accept_ready(wire.encode_v1_frame(0x15, h.th))
    fp, app = ctypes.create_string_buffer(40), CApplication()
    fn = lib.cp3_native_decap
    fn.argtypes = [ctypes.c_char_p] * 6 + [ctypes.c_void_p, ctypes.c_void_p]
    fn.restype = ctypes.c_int
    ret = fn(pk, sk, flip(ct) if mutated else ct, SEC_INFO_L4, START, fc, fp, ctypes.byref(app))
    if mutated:
        assert ret != 0 and fp.raw == bytes(40) and bytes(app) == bytes(64)
    else:
        assert ret == 0
        h.accept_finished_p(fp.raw)
        assert (h.app_c2p, h.app_p2c) == (bytes(app.c2p), bytes(app.p2c))
    h.clear()


@pytest.mark.parametrize("index", range(4))
def test_c_python_transcript_mutation_agreement(native_cp3, index):
    _, lib = native_cp3
    values = [SEC_INFO_L4, PK, CT, START]
    values[index] = flip(values[index])
    output = ctypes.create_string_buffer(32)
    args = []
    for value in values: args.extend([value, len(value)])
    fn = lib.pq_v1_cp3_transcript
    fn.argtypes = [ctypes.c_char_p, ctypes.c_size_t] * 4 + [ctypes.c_void_p]
    assert fn(*args, output) == 0
    assert output.raw == cp3.transcript_hash(*values) != TH0


@pytest.mark.parametrize("index", [-1, *range(32)])
def test_c_constant_time_equal_checks_every_byte(native_cp3, index):
    _, lib = native_cp3
    fn = lib.pq_v1_cp3_equal
    fn.argtypes, fn.restype = [ctypes.c_char_p, ctypes.c_char_p], ctypes.c_bool
    assert fn(TH0, TH0 if index == -1 else flip(TH0, index)) == (index == -1)


@pytest.mark.parametrize("fault", ["random", "extract", "expand_c", "expand_p", "app_c", "app_p", "short_secret", "short_ct"])
def test_owned_secrets_wiped_on_local_crypto_exception(keypair, monkeypatch, fault):
    observed = []
    encap = runner.encapsulate
    def encaps(pk):
        ct, ss = encap(pk)
        owned = bytearray(ss[:-1] if fault == "short_secret" else ss)
        observed.append(owned)
        return (ct[:-1] if fault == "short_ct" else ct), owned
    monkeypatch.setattr(runner, "encapsulate", encaps)
    def fail(*args): raise RuntimeError("injected local crypto failure")
    if fault == "random": monkeypatch.setattr(runner.secrets, "token_bytes", fail)
    if fault == "extract": monkeypatch.setattr(cp3, "extract", fail)
    if fault in ("expand_c", "expand_p", "app_c", "app_p"):
        label = {"expand_c": cp3.FINISHED_C_LABEL, "expand_p": cp3.FINISHED_P_LABEL,
                 "app_c": cp3.APP_C2P_LABEL, "app_p": cp3.APP_P2C_LABEL}[fault]
        expand = cp3.expand
        def faulty(prk, requested, th):
            if requested == label: fail()
            return expand(prk, requested, th)
        monkeypatch.setattr(cp3, "expand", faulty)
    client = CP3Client(keypair)
    with pytest.raises(V1Error): run_client(client, FakePairingBackend(client, paired=True))
    assert observed and all(not any(ss) for ss in observed)
    assert_cleared(client._v1_cp3_session)


def test_absolute_timeout_bounds_blocked_write(keypair, monkeypatch):
    client = CP3Client(keypair)
    async def stalled(ct): await asyncio.Event().wait()
    client.write_fragmented_ciphertext = stalled
    monkeypatch.setattr(runner, "CP3_TIMEOUT", 0.04)
    with pytest.raises(V1Error, match="absolute handshake timeout"):
        run_client(client, FakePairingBackend(client, paired=True))
    assert_cleared(client._v1_cp3_session)


def test_disconnect_callback_ignores_old_link_and_wipes_current():
    client = BLECentralClient()
    old = type("Link", (), {"address": "old"})()
    current = type("Link", (), {"address": "current"})()
    h = handshake()
    h.accept_ready(wire.encode_v1_frame(0x15, TH0))
    h.accept_finished_p(FP)
    client._v1_cp3_link, client._v1_cp3_session = current, h
    client._on_v1_disconnect(old)
    assert h.state == "APP_SECURE" and h.app_c2p == C2P
    client._on_v1_disconnect(current)
    assert_cleared(h)
    assert client._v1_cp3_session is None


@pytest.mark.parametrize("subtype,size", [(0x14, 16), (0x15, 32), (0x12, 32), (0x13, 32)])
@pytest.mark.parametrize("mutation", [None, "short", "long", "magic", "version", "length", "trailing"])
def test_c_python_framing_agreement(native_cp3, subtype, size, mutation):
    _, lib = native_cp3
    raw = wire.encode_v1_frame(subtype, bytes(size))
    if mutation in ("short", "long"):
        size += -1 if mutation == "short" else 1
        raw = b"PQV1\x10" + bytes([subtype, 0, size]) + bytes(size)
    elif mutation == "trailing": raw += b"\0"
    elif mutation: raw = flip(raw, {"magic": 0, "version": 4, "length": 7}[mutation])
    fn = lib.pq_v1_parse_frame
    fn.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    typ, payload, count = ctypes.c_ubyte(), ctypes.c_void_p(), ctypes.c_size_t()
    ret = fn(raw, len(raw), ctypes.byref(typ), ctypes.byref(payload), ctypes.byref(count))
    assert (ret == 0) == (mutation is None)
    if ret == 0:
        assert typ.value == subtype and count.value == size


def test_old_finished_rejected_in_new_session(native_cp3):
    _, lib = native_cp3
    th = cp3.transcript_hash(SEC_INFO_L4, PK, CT, flip(START))
    h, app, fp = CHandshake(), CApplication(), ctypes.create_string_buffer(40)
    ss = ctypes.create_string_buffer(SS, 32)
    assert lib.pq_v1_cp3_derive(ss, bytes(th), ctypes.byref(h)) == 0
    assert lib.pq_v1_cp3_finish(ctypes.byref(h), FC, len(FC), fp, ctypes.byref(app)) != 0
    assert bytes(h) == bytes(128) and bytes(app) == bytes(64) and fp.raw == bytes(40)


def test_cancellation_wipes_handshake(keypair):
    async def scenario():
        client = CP3Client(keypair, "p_timeout")
        async def accept(pin): return True
        task = asyncio.create_task(runner.run_v1_cp3(client, pairing_backend=FakePairingBackend(client, paired=True),
            confirm_numeric_comparison=accept, notification_timeout=5, quiet_window=0.001))
        for _ in range(100):
            await asyncio.sleep(0.001)
            if wire.V1_FINISHED_C in client.controls: break
        assert wire.V1_FINISHED_C in client.controls
        task.cancel()
        with pytest.raises(asyncio.CancelledError): await task
        assert_cleared(client._v1_cp3_session)
    asyncio.run(scenario())


def test_unsolicited_notification_after_secure_wipes_keys(keypair):
    async def scenario():
        client = CP3Client(keypair)
        async def accept(pin): return True
        await runner.run_v1_cp3(client, pairing_backend=FakePairingBackend(client, paired=True),
            confirm_numeric_comparison=accept, notification_timeout=0.05, quiet_window=0.001)
        h = client._v1_cp3_session
        assert h.state == "APP_SECURE"
        client.callback(1, bytearray(FC))
        await asyncio.sleep(0)
        assert_cleared(h)
    asyncio.run(scenario())
