"""CP2 software evidence only; real Windows/DK acceptance requires new logs."""

import asyncio
import ctypes
import hashlib
import hmac
import os
from pathlib import Path
from types import SimpleNamespace
import re
import shutil
import subprocess

import pytest

from src.central import main, v1_cp2 as runner
from src.central.v1_smp_mlkem import V1Error
from src.common import v1_cp2 as diagnostic, v1_smp_mlkem as wire
from src.common.constants import CT_SIZE, PK_SIZE
from src.common.ml_kem import decapsulate, encapsulate
from tests.test_v1_cp1 import FakePairingBackend, L4_INFO, V1MockClient, keypair


SID = bytes(range(16))
LABEL = b"PQ-BLE-HANDSHAKE-v1.0/CP2-DIAGNOSTIC"


@pytest.mark.parametrize("subtype,size", [(wire.V1_START, 16), (wire.V1_READY, 32)])
def test_cp2_exact_wire(subtype, size):
    payload = bytes(range(size))
    frame = b"PQV1\x10" + bytes([subtype, 0, size]) + payload
    assert wire.encode_v1_frame(subtype, payload) == frame
    assert wire.parse_v1_frame(frame).payload == payload
    assert len(frame) == (24 if subtype == wire.V1_START else 40)


@pytest.mark.parametrize("subtype,size", [(wire.V1_START, 16), (wire.V1_READY, 32)])
@pytest.mark.parametrize("mutation", ["short", "long", "magic", "version", "declared", "truncated", "trailing"])
def test_cp2_wire_fail_closed(subtype, size, mutation):
    frame = bytearray(wire.encode_v1_frame(subtype, bytes(size)))
    if mutation in ("short", "long"):
        size += -1 if mutation == "short" else 1
        with pytest.raises(ValueError):
            wire.encode_v1_frame(subtype, bytes(size))
        frame = bytearray(b"PQV1\x10" + bytes([subtype, 0, size]) + bytes(size))
    elif mutation == "magic":
        frame[0] ^= 1
    elif mutation == "version":
        frame[4] ^= 1
    elif mutation == "declared":
        frame[7] ^= 1
    elif mutation == "truncated":
        del frame[-1]
    elif mutation == "trailing":
        frame.append(0)
    with pytest.raises(ValueError):
        wire.parse_v1_frame(frame)


@pytest.mark.parametrize("subtype", [wire.V1_FINISHED_C, wire.V1_FINISHED_P])
def test_cp2_rejects_finished_response(subtype, keypair):
    # FINISHED now has CP3 framing, but can never complete a CP2 exchange.
    client = CP2Client(keypair)
    backend = FakePairingBackend(client, paired=True)
    original = client.send_control

    async def send(data):
        if wire.parse_v1_frame(data).subtype == wire.V1_START:
            client.callback(1, bytearray(wire.encode_v1_frame(subtype, bytes(32))))
        else:
            await original(data)

    client.send_control = send
    with pytest.raises(V1Error, match="expected READY_V1"):
        run(client, backend)


def test_diagnostic_exact_construction():
    secret = bytearray(range(32))
    pk, ct = bytes([0x55]) * PK_SIZE, bytes([0xAA]) * CT_SIZE
    expected = hmac.digest(secret, LABEL + SID + hashlib.sha256(pk + ct).digest(), "sha256")
    assert diagnostic.compute_diagnostic(secret, SID, pk, ct) == expected
    assert wire.V1_CP2_DIAGNOSTIC_LABEL == LABEL


@pytest.mark.parametrize("field", ["secret", "session", "pk", "ct"])
def test_diagnostic_binds_every_input(field):
    inputs = [bytearray(range(32)), SID, bytes(PK_SIZE), bytes(CT_SIZE)]
    expected = diagnostic.compute_diagnostic(*inputs)
    index = ["secret", "session", "pk", "ct"].index(field)
    changed = bytearray(inputs[index])
    changed[0] ^= 1
    inputs[index] = changed if index == 0 else bytes(changed)
    assert not hmac.compare_digest(expected, diagnostic.compute_diagnostic(*inputs))


@pytest.mark.parametrize("index", range(4))
def test_diagnostic_rejects_wrong_input_size(index):
    inputs = [bytearray(32), SID, bytes(PK_SIZE), bytes(CT_SIZE)]
    inputs[index] = inputs[index][:-1]
    with pytest.raises(ValueError):
        diagnostic.compute_diagnostic(*inputs)


class CP2Client(V1MockClient):
    def __init__(self, keypair, failure=None):
        super().__init__(keypair)
        self.raw_client = object()
        self.failure = failure
        self.controls = []
        self.attestations = 0
        self.stopped = False

    async def read_fragmented_public_key(self):
        data = await super().read_fragmented_public_key()
        return data[:-1] if self.failure == "short_pk" else data

    async def write_fragmented_ciphertext(self, ct):
        fragments = await super().write_fragmented_ciphertext(ct)
        self.ct = ct
        if self.failure == "ct_exception":
            raise RuntimeError("ciphertext transfer failed")
        if self.failure == "replace_link":
            self.raw_client = object()
        if self.failure == "disconnect":
            self.is_connected = False
        return fragments

    async def send_control(self, data):
        self._gate("control-write")
        frame = wire.parse_v1_frame(data)
        self.controls.append(frame.subtype)
        if frame.subtype == wire.V1_SEC_QUERY:
            self.attestations += 1
            info = L4_INFO
            if (self.failure == "weak_initial" or
                    self.failure == "downgrade" and self.attestations == 2):
                info = wire.V1SecurityInfo(2, True, False, False, 16, 0x10)
            self.callback(1, bytearray(wire.encode_sec_info(info)))
            return
        assert frame.subtype == wire.V1_START
        assert self.attestations == 2
        if self.failure == "timeout":
            return
        if self.failure == "start_exception":
            raise RuntimeError("START refused")
        if self.failure == "worker":
            response = wire.encode_v1_error(wire.V1_STATUS_CP2_CRYPTO_FAILURE)
        elif self.failure == "wrong_subtype":
            response = wire.encode_sec_info(L4_INFO)
        else:
            ss = bytearray(decapsulate(self.secret_key, self.ct))
            try:
                # Independent oracle, not the helper under test.
                tag = hmac.digest(ss, LABEL + frame.payload + hashlib.sha256(
                    self.public_key + self.ct).digest(), "sha256")
            finally:
                diagnostic.clear(ss)
            response = wire.encode_v1_frame(wire.V1_READY, tag)
            if self.failure == "mismatch":
                response = response[:-1] + bytes([response[-1] ^ 1])
            if self.failure == "malformed":
                response = response[:-1]
        self.callback(1, bytearray(response))
        if self.failure == "duplicate":
            self.callback(1, bytearray(response))
        if self.failure == "ready_replace":
            self.raw_client = object()

    async def stop_notify(self):
        self.stopped = True


def run(client, backend, **kwargs):
    async def accept(pin):
        return True
    return asyncio.run(runner.run_v1_cp2(
        client, pairing_backend=backend, confirm_numeric_comparison=accept,
        notification_timeout=0.02, quiet_window=0.01, **kwargs,
    ))


@pytest.fixture
def observed_secrets(monkeypatch):
    buffers = []
    expected_buffers = []
    original_compute = runner.compute_diagnostic

    def encap(pk):
        ct, secret = encapsulate(pk)
        secret = bytearray(secret)
        buffers.append(secret)
        return ct, secret

    def compute(*args):
        result = original_compute(*args)
        expected_buffers.append(result)
        return result

    monkeypatch.setattr(runner, "encapsulate", encap)
    monkeypatch.setattr(runner, "compute_diagnostic", compute)
    return buffers, expected_buffers


@pytest.mark.parametrize("bonded", [False, True])
def test_real_mlkem_central_flow_and_cleanup(keypair, monkeypatch, observed_secrets, bonded):
    client = CP2Client(keypair)
    backend = FakePairingBackend(client, paired=bonded)
    comparisons = []
    original = hmac.compare_digest

    def compare(a, b):
        comparisons.append((len(a), len(b)))
        return original(a, b)

    monkeypatch.setattr(runner.hmac, "compare_digest", compare)
    result = run(client, backend)
    assert result.diagnostic_match and result.start_sent and result.ready_received
    assert result.scenario == ("bonded" if bonded else "cold")
    assert result.public_key_len == PK_SIZE and result.ciphertext_fragments == 5
    assert client.controls == [wire.V1_SEC_QUERY, wire.V1_SEC_QUERY, wire.V1_START]
    assert ("nc" in backend.calls) != bonded
    assert comparisons == [(32, 32)]
    assert client.stopped
    for group in observed_secrets:
        assert len(group) == 1 and group[0] == bytearray(32)


@pytest.mark.parametrize("failure", [
    "weak_initial", "short_pk", "ct_exception", "replace_link", "disconnect",
    "downgrade", "timeout", "start_exception", "worker", "wrong_subtype",
    "mismatch", "malformed", "duplicate", "ready_replace",
])
def test_central_failure_and_secret_cleanup(keypair, observed_secrets, failure):
    client = CP2Client(keypair, failure)
    backend = FakePairingBackend(client, paired=True)
    with pytest.raises(V1Error):
        run(client, backend)
    assert client.stopped
    for group in observed_secrets:
        assert all(buf == bytearray(len(buf)) for buf in group)
    if failure in ("weak_initial", "short_pk"):
        assert observed_secrets[0] == []
    if failure in ("weak_initial", "short_pk", "ct_exception", "replace_link", "disconnect", "downgrade"):
        assert wire.V1_START not in client.controls


@pytest.mark.parametrize("fault", ["diagnostic", "random", "short_secret", "short_ct"])
def test_cleanup_on_local_crypto_exception(keypair, monkeypatch, observed_secrets, fault):
    client = CP2Client(keypair)
    backend = FakePairingBackend(client, paired=True)

    def fail(*args):
        raise RuntimeError("injected local failure")

    if fault == "diagnostic":
        monkeypatch.setattr(runner, "compute_diagnostic", fail)
    elif fault == "random":
        monkeypatch.setattr(runner.secrets, "token_bytes", fail)
    else:
        original = runner.encapsulate

        def malformed(pk):
            ct, ss = original(pk)
            if fault == "short_secret":
                del ss[-1]
            else:
                ct = ct[:-1]
            return ct, ss

        monkeypatch.setattr(runner, "encapsulate", malformed)
    with pytest.raises(V1Error):
        run(client, backend)
    assert client.stopped
    assert observed_secrets[0] and all(not any(buf) for buf in observed_secrets[0])


def test_cli_cp2_is_explicit():
    assert not main.parse_args(["--v1-smp-l4-mlkem"]).v1_cp2
    assert main.parse_args(["--v1-smp-l4-mlkem", "--v1-cp2"]).v1_cp2
    for args in (["--v1-cp2"], ["--v1-smp-l4-mlkem", "--v1-cp2", "--v1-negative", "nc-reject"]):
        with pytest.raises(SystemExit):
            main.parse_args(args)


@pytest.mark.parametrize("failure", [None, "mismatch", "timeout"])
def test_cli_cp2_marker_and_disconnect(keypair, monkeypatch, capsys, failure):
    client = CP2Client(keypair, failure)
    backend = FakePairingBackend(client, paired=True)

    async def connect(timeout):
        return True

    async def disconnect():
        client.is_connected = False

    async def real_run(actual_client, **kwargs):
        return await runner.run_v1_cp2(actual_client, **kwargs, pairing_backend=backend,
                                        notification_timeout=0.02, quiet_window=0.01)

    client.scan_and_connect = connect
    client.disconnect = disconnect
    monkeypatch.setattr(main, "BLECentralClient", lambda **kwargs: client)
    monkeypatch.setattr(main, "run_v1_cp2", real_run)
    args = main.parse_args(["--v1-smp-l4-mlkem", "--v1-cp2"])
    code = asyncio.run(main._run_v1_smp_l4_mlkem_cli(args))
    output = capsys.readouterr().out
    assert code == (0 if failure is None else 1)
    assert f"CP2 ML-KEM-L4 INTEROPERABILITY: {'PASS' if failure is None else 'FAIL'}" in output
    assert "CP1 SMP-L4 FOUNDATION: PASS" not in output
    assert not client.is_connected


def test_cp2_constants_match_c():
    header = Path("firmware/src/pq_v1_frame.h").read_text()
    import re
    for name in ("CP2_SESSION_ID_SIZE", "CP2_DIAGNOSTIC_SIZE", "START", "READY", "STATUS_CP2_CRYPTO_FAILURE"):
        match = re.search(rf"#define PQ_V1_{name} (0x[0-9A-Fa-f]+|\d+)U", header)
        assert int(match[1], 0) == getattr(wire, "V1_" + name)
    assert f'"{LABEL.decode()}"' in header


def _production_function(source, name):
    """Compile exact production function bodies, not copied test implementations."""
    match = re.search(rf"^(?:static )?(?:int|void|ssize_t) {name}\([^;]*?\)\s*\{{",
                      source, re.MULTILINE)
    assert match, name
    depth, end = 1, match.end()
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


@pytest.fixture(scope="module")
def native_cp2(tmp_path_factory):
    if os.name != "nt":
        pytest.skip("CP2 native PSA adapter uses Windows BCrypt; run on the Windows host")
    gcc = shutil.which("gcc")
    if gcc is None:
        pytest.skip("host GCC unavailable; the NCS build is still required")
    root = Path(__file__).resolve().parents[1]
    build = tmp_path_factory.mktemp("v1_cp2_native")
    native = root / "tests/native_v1"
    firmware = root / "firmware/src"
    mlkem = root / "firmware/third_party/mlkem-native/mlkem"
    (build / "psa").mkdir()
    (build / "psa/crypto.h").write_text('#include "cp2_psa.h"\n')
    source = (firmware / "main.c").read_text()
    (build / "cp2_main.inc").write_text("\n".join(_production_function(source, n) for n in (
        "clear_transfer_storage_locked", "begin_transfer_locked", "write_ciphertext",
        "invalidate_v1_cp2_locked", "handle_v1_cp2_start", "v1_cp2_result_ready",
        "v1_cp2_security_changed",
    )))
    worker = (firmware / "mlkem_session.c").read_text()
    (build / "cp2_worker.inc").write_text("\n".join(_production_function(worker, n) for n in (
        "pq_mlkem_session_submit_v1_cp2", "pq_mlkem_session_reset_v1_cp2", "v1_cp2_result",
    )))
    command = [gcc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-O1",
               "-DCONFIG_PQ_PROFILE_V10_SMP_L4_MLKEM=1", "-DMLK_CONFIG_PARAMETER_SET=768",
               "-DMLK_CONFIG_NO_RANDOMIZED_API", "-DMLK_CONFIG_NAMESPACE_PREFIX=pqble_mlkem",
               "-DMLK_CONFIG_INTERNAL_API_QUALIFIER=static"]
    for path in (build, native, firmware, mlkem):
        command += ["-I", str(path)]
    command += [str(native / "cp2_lifecycle.c"), str(firmware / "pq_v1_cp2.c"),
                str(firmware / "pq_v1_frame.c"), str(mlkem / "mlkem_native.c"), "-lbcrypt"]
    exe = build / "cp2_lifecycle.exe"
    dll = build / "cp2_native.dll"
    for suffix, flags in ((exe, []), (dll, ["-shared"])):
        result = subprocess.run(command + flags + ["-o", str(suffix)],
                                capture_output=True, text=True, timeout=60)
        assert result.returncode == 0, result.stdout + result.stderr
    library = ctypes.CDLL(str(dll))
    return exe, library


@pytest.mark.parametrize("scenario", range(22), ids=[
    "success", "pre_l4", "stale_caller", "incomplete_ct", "no_cccd", "busy_start",
    "no_keypair", "stale_job_ref", "short_session_id", "small_mtu", "worker_busy",
    "disconnect_new_peer", "downgrade", "security_error", "stale_generation",
    "cccd_disabled_during_job", "decap_failure", "hmac_failure", "notify_failure",
    "live_gate_at_delivery", "malformed_worker_reply", "minimum_mtu_43",
])
def test_native_cp2_lifecycle(native_cp2, scenario):
    exe, _ = native_cp2
    result = subprocess.run([str(exe), str(scenario)], capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("mutated", [False, True])
def test_liboqs_to_real_c_mlkem_diagnostic(native_cp2, keypair, mutated):
    _, library = native_cp2
    pk, sk = keypair
    ct, ss = encapsulate(pk)
    expected = diagnostic.compute_diagnostic(bytearray(ss), SID, pk, ct)
    if mutated:
        ct = bytes([ct[0] ^ 1]) + ct[1:]
    output = ctypes.create_string_buffer(32)
    fn = library.cp2_native_dec_diagnostic
    fn.argtypes = [ctypes.c_char_p] * 5
    fn.restype = ctypes.c_int
    assert fn(pk, sk, ct, SID, output) == 0  # modified CT uses implicit rejection
    assert hmac.compare_digest(expected, output.raw) != mutated


@pytest.mark.parametrize("failure", range(8), ids=[
    "known_answer", "hash_setup", "hash_update", "hash_finish", "key_import",
    "mac", "key_destroy", "hash_abort",
])
def test_c_diagnostic_psa_failure_and_cleanup(native_cp2, failure):
    _, library = native_cp2
    fault = ctypes.c_int.in_dll(library, "cp2_psa_failure")
    fault.value = failure
    fn = library.pq_v1_cp2_diagnostic
    fn.argtypes = [ctypes.c_char_p, ctypes.c_size_t] * 4 + [ctypes.c_char_p]
    fn.restype = ctypes.c_int
    secret, pk, ct = bytes(range(32)), bytes([0x55]) * PK_SIZE, bytes([0xAA]) * CT_SIZE
    output = ctypes.create_string_buffer(b"x" * 32, 32)
    try:
        result = fn(secret, 32, SID, 16, pk, PK_SIZE, ct, CT_SIZE, output)
        if failure:
            assert result != 0 and output.raw == bytes(32)
        else:
            assert result == 0
            assert output.raw == diagnostic.compute_diagnostic(bytearray(secret), SID, pk, ct)
        key = (ctypes.c_uint8 * 32).in_dll(library, "cp2_psa_key")
        assert bytes(key) == bytes(32)
    finally:
        fault.value = 0
