"""Production C/Python interoperability, real Windows native cryptography."""
import ctypes as c
from pathlib import Path
import shutil
import subprocess

import pytest

from src.common import resumption as r
from tests.test_resumption import PRK, TH, ticket, flip


@pytest.fixture(scope="module", params=[r.V08, r.V11])
def native(request, tmp_path_factory):
    gcc = shutil.which("gcc")
    if gcc is None:
        pytest.skip("GCC required for native C resume validation")
    build = tmp_path_factory.mktemp(f"resume_native_{request.param}")
    root = Path(__file__).resolve().parents[1]
    firmware = root / "firmware/src"
    (build/"psa").mkdir()
    (build/"psa/crypto.h").write_text('#include "cp4_psa.h"\n')
    config = "CONFIG_PQ_PROFILE_V08_RESUME_HYBRID" if request.param == r.V08 else "CONFIG_PQ_PROFILE_V11_SMP_L4_MLKEM_RESUME"
    dll = build / "resume.dll"
    command = [gcc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-O1", "-shared",
               "-DCP2_NATIVE_HASH_CAPACITY=4096", "-D"+config+"=1"]
    for path in (build, root/"tests/native_v1", firmware):
        command += ["-I", str(path)]
    command += [str(root/"tests/native_resume/core.c")]
    command += [str(firmware/n) for n in ("pq_resume.c", "pq_v1_cp3.c", "pq_v1_frame.c", "pq_v1_cp4.c")]
    command += ["-lbcrypt", "-o", str(dll)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, result.stdout+result.stderr
    lib = c.CDLL(str(dll))
    ptr = c.c_void_p
    lib.test_issue.argtypes = [ptr, ptr, c.c_int64, c.c_int]
    lib.test_accept.argtypes = [ptr, c.c_size_t, ptr, ptr, c.c_int64, c.c_int, c.c_int]
    lib.test_finish.argtypes = [ptr, c.c_size_t, ptr, c.c_int64, c.c_int, c.c_int]
    lib.test_commit.argtypes = [c.c_int64, c.c_int, c.c_int]
    lib.test_eligible.argtypes = [c.c_int64]
    lib.pq_resume_transcript.argtypes = [c.c_uint8]+[ptr]*5
    lib.pq_resume_derive.argtypes = [c.c_uint8]+[ptr]*6
    return request.param, lib


@pytest.fixture
def engine(native):
    profile, lib = native
    c.c_int.in_dll(lib, "cp2_psa_failure").value = 0
    lib.test_reset()
    assert lib.test_issue(PRK, TH, 100000, 1) == 0
    yield profile, lib
    lib.test_reset()
    assert lib.test_ticket_zero() and lib.test_session_zero()


def central(profile):
    return r.CentralResume(ticket(profile), now=100)


def start(lib, client):
    out = c.create_string_buffer(72)
    init = client.begin()
    count = lib.test_count()
    assert lib.test_accept(init, len(init), bytes(range(32)), out, 100000, 1, 1) == 0
    assert lib.test_state() == 1 and lib.test_count() == count
    return client.accept(out.raw)


def finish(lib, client, fc):
    out = c.create_string_buffer(40)
    assert lib.test_finish(fc, len(fc), out, 100000, 1, 1) == 0
    assert lib.test_state() == 2
    assert lib.test_commit(100000, 1, 1) == 0
    client.finish(out.raw)
    keys = c.create_string_buffer(184)
    lib.test_keys(keys)
    assert keys.raw[:96] == bytes(96)
    assert keys.raw[96:128] == client.keys.app_c2p
    assert keys.raw[128:160] == client.keys.app_p2c
    assert keys.raw[160:172] == client.keys.iv_c2p
    assert keys.raw[172:184] == client.keys.iv_p2c
    return out.raw


def test_c_python_transcript_kdf(engine):
    profile, lib = engine
    transcript = c.create_string_buffer(148)
    values = (bytes(16), bytes(range(16)), bytes(range(32)), bytes(range(32, 64)))
    assert lib.pq_resume_transcript(profile, *values, transcript) == 0
    assert transcript.raw == r.transcript(profile, *values)
    keys = c.create_string_buffer(184)
    assert lib.pq_resume_derive(profile, PRK, *values, keys) == 0
    py = r.SessionKeys(profile, PRK, *values)
    assert keys.raw == b"".join(getattr(py, attr) for attr in
        ("th", "confirm_c", "confirm_p", "app_c2p", "app_p2c", "iv_c2p", "iv_p2c"))


def test_c_mutual_resume_and_replay(engine):
    profile, lib = engine
    client = central(profile)
    fc = start(lib, client)
    finish(lib, client, fc)
    assert lib.test_state() == 3 and lib.test_count() == 1
    lib.test_disconnect()
    assert lib.test_session_zero() and lib.test_valid()
    # Replay INIT from that completed session, with the original exact context.
    t = client.ticket
    init = r.encode(profile, r.INIT, t.rid+client.session_id+client.nc+
        r.auth(profile, t.root, b"INIT", t.rid, client.session_id, client.nc))
    out = c.create_string_buffer(72)
    assert lib.test_accept(init, len(init), bytes(32), out, 100000, 1, 1) == r.Reason.REPLAY
    assert lib.test_count() == 1 and lib.test_valid() and lib.test_session_zero()
    new = central(profile)
    start(lib, new)
    fp = c.create_string_buffer(40)
    assert lib.test_finish(fc, len(fc), fp, 100000, 1, 1) == r.Reason.BAD_AUTH
    assert lib.test_session_zero() and fp.raw == bytes(40)


@pytest.mark.parametrize("field", [0, 4, 6, 7, 8, 24, 40, 72, 103])
def test_c_tamper_and_truncation(engine, field):
    profile, lib = engine
    client = central(profile)
    init = client.begin()
    out = c.create_string_buffer(72)
    for raw in (flip(init, field), init[:-1], init+b"\0"):
        assert lib.test_accept(raw, len(raw), bytes(32), out, 100000, 1, 1) != 0
        assert lib.test_session_zero() and lib.test_count() == 0 and lib.test_valid()
        assert out.raw == bytes(72)


def test_c_age_count_send_failure_and_authentication(engine):
    profile, lib = engine
    assert lib.test_issue(PRK, TH, 100000, 0) != 0
    assert lib.test_count() == 0
    client = central(profile)
    fc = start(lib, client)
    fp = c.create_string_buffer(40)
    assert lib.test_finish(fc, len(fc), fp, 100000, 1, 1) == 0
    lib.test_disconnect()  # notification failure: no commit, no success use
    assert lib.test_count() == 0 and lib.test_valid()
    for index in range(100):
        client = central(profile)
        finish(lib, client, start(lib, client))
        assert lib.test_count() == index+1 if index < 99 else lib.test_ticket_zero()
        lib.test_disconnect()
    assert lib.test_eligible(100000) == r.Reason.NO_TICKET
    assert lib.test_issue(PRK, TH, 100000, 1) == 0
    assert lib.test_eligible(100000+r.TTL*1000) == r.Reason.EXPIRED
    assert lib.test_ticket_zero()


@pytest.mark.parametrize("fault", range(1, 8))
def test_c_crypto_failure_wipes_owned_keys(engine, fault):
    profile, lib = engine
    c.c_int.in_dll(lib, "cp2_psa_failure").value = fault
    client = central(profile)
    init = client.begin()
    out = c.create_string_buffer(72)
    assert lib.test_accept(init, len(init), bytes(32), out, 100000, 1, 1) == r.Reason.INTERNAL_ERROR
    assert lib.test_session_zero() and lib.test_valid() and lib.test_count() == 0
    assert bytes((c.c_ubyte*32).in_dll(lib, "cp2_psa_key")) == bytes(32)


def test_c_l4_gate_and_timeout(engine):
    profile, lib = engine
    out = c.create_string_buffer(72)
    if profile == r.V11:
        for l4, bonded in ((0, 0), (0, 1), (1, 0)):
            client = central(profile)
            init = client.begin()
            assert lib.test_accept(init, len(init), bytes(32), out, 100000, l4, bonded) == r.Reason.L4_REQUIRED
            assert lib.test_session_zero() and lib.test_valid()
    client = central(profile)
    fc = start(lib, client)
    fp = c.create_string_buffer(40)
    assert lib.test_finish(fc, len(fc), fp, 130000, 1, 1) == r.Reason.MALFORMED
    assert lib.test_session_zero() and lib.test_count() == 0


def test_c_replay_cache_covers_entire_ticket_lifetime(engine):
    profile, lib = engine
    first = None
    for index in range(r.REPLAY_CAPACITY):
        client = central(profile)
        init = client.begin()
        if first is None:
            first = init
        out = c.create_string_buffer(72)
        assert lib.test_accept(init, len(init), bytes(32), out, 100000, 1, 1) == 0
        lib.test_disconnect()  # Accepted INITs survive failed/incomplete confirmation.
    assert lib.test_count() == 0 and lib.test_valid()
    assert lib.test_accept(first, len(first), bytes(32), out, 100000, 1, 1) == r.Reason.REPLAY
    fresh = central(profile).begin()
    assert lib.test_accept(fresh, len(fresh), bytes(32), out, 100000, 1, 1) == r.Reason.REPLAY_CACHE_FULL
    assert lib.test_count() == 0 and lib.test_valid() and lib.test_session_zero()
