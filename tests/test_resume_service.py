"""Native GATT integration: confirmation commit, profile data paths and L4 loss."""
import ctypes as c
from pathlib import Path
import shutil
import subprocess

import pytest

from src.common import resumption as r, v1_cp4 as app
from tests.test_resumption import PRK, TH, ticket


@pytest.fixture(scope="module", params=[r.V08, r.V11])
def native_service(request, tmp_path_factory):
    compiler = shutil.which("gcc")
    if compiler is None:
        pytest.skip("GCC required for service lifecycle validation")
    profile = request.param
    root = Path(__file__).resolve().parents[1]
    build = tmp_path_factory.mktemp(f"resume_service_{profile}")
    for name in ("zephyr/kernel.h", "zephyr/bluetooth/conn.h", "zephyr/bluetooth/gatt.h",
                 "zephyr/bluetooth/bluetooth.h", "zephyr/logging/log.h", "zephyr/sys/util.h"):
        p = build/name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text('#include "service_stub.h"\n')
    (build/"psa").mkdir()
    (build/"psa/crypto.h").write_text('#include "hybrid_psa.h"\n')
    config = "CONFIG_PQ_PROFILE_V08_RESUME_HYBRID" if profile == r.V08 else "CONFIG_PQ_PROFILE_V11_SMP_L4_MLKEM_RESUME"
    dll = build/"service.dll"
    cmd = [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-O1", "-shared", "-D"+config+"=1",
           "-DCP2_NATIVE_HASH_CAPACITY=4096"]
    for path in (build, root/"tests/native_resume", root/"tests/native_v1", root/"firmware/src"):
        cmd += ["-I", str(path)]
    cmd += [str(root/"tests/native_resume/service.c")]
    cmd += [str(root/"firmware/src"/name) for name in ("pq_resume.c", "pq_v1_cp3.c", "pq_v1_cp4.c", "pq_v1_frame.c")]
    if profile == r.V08:
        source = (root/"firmware/src/pq_phase7.c").read_text()
        # Compile the exact production framing/transcript/KDF/FINISHED code.
        # Exclude P-256 and startup self-tests: deterministic ECDH input below.
        selected = source[:source.index("int pq_phase7_generate_p256_keypair(")]
        selected += source[source.index("static psa_status_t hash_length_prefixed("):
                           source.index("static int production_random_p256_self_test(")]
        (build/"hybrid_primitives.c").write_text(selected)
        cmd += [str(build/"hybrid_primitives.c"), str(root/"firmware/src/pq_secure_channel.c")]
        from tests.test_v1_cp3 import production_function
        worker = (root/"firmware/src/mlkem_session.c").read_text()
        state = worker[worker.index("static struct pq_phase7_keys phase7_keys;"):
                       worker.index("static K_THREAD_STACK_DEFINE(crypto_thread_stack")]
        # Only declarations used by the extracted installation/commit functions.
        import re
        state = re.sub(r"static uint32_t (?:pending_)?phase7_epoch;", "", state)
        (build/"hybrid_worker.inc").write_text(state + "\n" + "\n".join(production_function(worker, n) for n in
            ("clear_phase7_material_locked", "pq_mlkem_session_commit_phase7_authenticated",
             "pq_mlkem_session_install_phase8_application")))
    result = subprocess.run(cmd+["-lbcrypt", "-o", str(dll)], capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, result.stdout+result.stderr
    lib = c.CDLL(str(dll))
    lib.service_control.argtypes = [c.c_void_p, c.c_size_t, c.c_int]
    lib.service_response.restype = c.c_size_t
    lib.service_begin_full.argtypes = [c.c_void_p] * 8
    lib.service_finish_full.argtypes = [c.c_void_p, c.c_size_t, c.c_void_p]
    if profile == r.V08:
        lib.service_hybrid_decrypt.argtypes = [c.c_void_p, c.c_size_t, c.c_void_p]
        lib.service_hybrid_encrypt.argtypes = [c.c_void_p, c.c_size_t, c.c_void_p]
    return profile, lib


@pytest.fixture
def service(native_service):
    profile, lib = native_service
    lib.service_reset()
    lib.service_connect(0)
    assert lib.service_full(PRK, TH) == 0
    lib.service_disconnect()
    assert lib.service_valid() and lib.service_zero()
    lib.service_connect(0)
    yield profile, lib
    lib.service_reset()


def control(lib, raw, wrong_peer=0):
    result = lib.service_control(raw, len(raw), wrong_peer)
    out = c.create_string_buffer(200)
    size = lib.service_response(out)
    return result, out.raw[:size]


def resume(profile, lib):
    client = r.CentralResume(ticket(profile), now=100)
    result, accept = control(lib, client.begin())
    assert result == 0
    fc = client.accept(accept)
    result, fp = control(lib, fc)
    assert result == 0 and lib.service_state() == 3
    client.finish(fp)
    return client


def test_actual_service_resume_cp4_and_cross_session_replay(service):
    profile, lib = service
    client = resume(profile, lib)
    assert lib.service_count() == 1
    if profile == r.V08:
        keys, sid = c.create_string_buffer(64), c.create_string_buffer(16)
        assert lib.service_take_hybrid(keys, sid) == 0
        assert keys.raw == client.app_c2p + client.app_p2c and sid.raw == client.session_id
        assert lib.service_take_hybrid(keys, sid) != 0  # one transfer, no retained traffic key copy
        return
    channel = app.CentralApplication(client, iv_c2p=client.keys.iv_c2p, iv_p2c=client.keys.iv_p2c)
    wire = channel.encrypt_ping(bytes(range(16)), 247)
    result, pong = control(lib, wire)
    assert result == 0
    channel.accept_pong(pong, bytes(range(16)), 247)
    lib.service_disconnect()
    assert lib.service_zero() and lib.service_valid()
    lib.service_connect(0)
    fresh = resume(profile, lib)
    assert client.app_c2p != fresh.app_c2p
    result, pong = control(lib, wire)
    assert result != 0 and not pong and lib.service_zero()
    assert lib.service_count() == 2 and lib.service_valid()


def test_service_failed_delivery_does_not_count(service):
    profile, lib = service
    client = r.CentralResume(ticket(profile), now=100)
    _, accept = control(lib, client.begin())
    fc = client.accept(accept)
    c.c_int.in_dll(lib, "test_notify_error").value = 1
    assert control(lib, fc)[0] != 0
    assert lib.service_count() == 0 and lib.service_zero() and lib.service_valid()


def test_service_expiry_timeout_and_replacement(service):
    profile, lib = service
    client = r.CentralResume(ticket(profile), now=100)
    control(lib, client.begin())
    c.c_int64.in_dll(lib, "test_now").value = 130000
    lib.service_expire()
    assert lib.service_zero() and lib.service_valid() and lib.service_count() == 0
    c.c_int64.in_dll(lib, "test_now").value = 100000+r.TTL*1000
    lib.service_expire()
    assert not lib.service_valid()
    assert lib.service_full(PRK, TH) == 0 and lib.service_valid() and lib.service_state() == 3


def test_service_bond_delete_cold_link_and_l4_loss(service):
    profile, lib = service
    if profile != r.V11:
        return
    client = r.CentralResume(ticket(profile), now=100)
    c.c_bool.in_dll(lib, "test_l4").value = False
    assert control(lib, client.begin())[0] != 0
    assert lib.service_zero() and lib.service_valid()
    c.c_bool.in_dll(lib, "test_l4").value = True
    lib.service_disconnect()
    lib.service_connect(1)  # Bond missing at connect, even if L4 later becomes available.
    c.c_bool.in_dll(lib, "test_bond").value = True
    _, reject = control(lib, r.CentralResume(ticket(profile), now=100).begin())
    r.parse(reject, profile, r.REJECT)
    assert lib.service_count() == 0
    lib.pq_resume_service_bond_changed()
    assert not lib.service_valid() and lib.service_zero()


def test_service_l4_drops_during_final_send(service):
    profile, lib = service
    if profile != r.V11:
        return
    client = r.CentralResume(ticket(profile), now=100)
    _, accept = control(lib, client.begin())
    fc = client.accept(accept)
    c.c_int.in_dll(lib, "test_notify_drop_l4").value = 1
    assert control(lib, fc)[0] != 0
    assert lib.service_zero() and lib.service_valid() and lib.service_count() == 0


def test_service_rejects_other_connection_and_missing_notifications(service):
    profile, lib = service
    client = r.CentralResume(ticket(profile), now=100)
    assert control(lib, client.begin(), wrong_peer=1)[0] != 0
    assert lib.service_zero() and lib.service_valid()
    c.c_bool.in_dll(lib, "test_subscribed").value = False
    assert control(lib, r.CentralResume(ticket(profile), now=100).begin())[0] != 0
    assert lib.service_zero() and lib.service_count() == 0 and lib.service_valid()


def begin_full(profile, lib):
    from src.common.resume_full import FullHandshake, encode_full
    from tests.test_phase7_primitives import (
        SS_MLKEM, SS_ECDH, MLKEM_PUBLIC_KEY, MLKEM_CIPHERTEXT, CENTRAL_PUBLIC_KEY,
        PERIPHERAL_PUBLIC_KEY, SESSION_ID)
    sec = encode_full(r.V11, 2, bytes((4, 7, 16, r.V11)))
    full = FullHandshake(profile)
    full.begin(SS_MLKEM, MLKEM_PUBLIC_KEY, MLKEM_CIPHERTEXT, SESSION_ID,
        ecdh=SS_ECDH, central_public=CENTRAL_PUBLIC_KEY, peripheral_public=PERIPHERAL_PUBLIC_KEY, sec=sec)
    assert lib.service_begin_full(SS_MLKEM, SS_ECDH, MLKEM_PUBLIC_KEY, MLKEM_CIPHERTEXT,
        CENTRAL_PUBLIC_KEY, PERIPHERAL_PUBLIC_KEY, SESSION_ID, sec) == 0
    return full


def test_full_handshake_c_python_ticket_binding_and_application(native_service):
    profile, lib = native_service
    lib.service_reset()
    lib.service_connect(0)
    full = begin_full(profile, lib)
    assert full.ticket is None and not lib.service_valid()
    fc = full.finish_c(authenticated=True)
    assert full.ticket is None and not lib.service_valid()
    fp = c.create_string_buffer(40)
    assert lib.service_finish_full(fc, len(fc), fp) == 0
    full.finish_p(fp.raw, "peer", now=100)
    root, rid = c.create_string_buffer(32), c.create_string_buffer(16)
    lib.service_ticket(root, rid)
    assert root.raw == full.ticket.root and rid.raw == full.ticket.rid
    if profile == r.V08:
        from src.common.resume_hybrid import HybridApplication
        channel = HybridApplication(full)
        for index in range(3):
            ping = channel.encrypt_ping(index, 247)
            plain, pong = c.create_string_buffer(64), c.create_string_buffer(101)
            assert len(ping) == 43
            assert lib.service_hybrid_decrypt(ping, len(ping), plain) == 0
            assert plain.raw[:6] == f"PING {index}".encode("ascii")
            assert lib.service_hybrid_encrypt(f"PONG {index}".encode("ascii"), 6, pong) == 43
            channel.accept_pong(pong.raw[:43], index, 247)
        # Strictly increasing (v0.7), not CP4 exact-next receive sequence.
        channel.c2p._send_seq = 7
        skipped = channel.c2p.encrypt(b"PING 7")
        assert lib.service_hybrid_decrypt(skipped, len(skipped), plain) == 0
        assert lib.service_hybrid_decrypt(skipped, len(skipped), plain) != 0
    old_ticket = full.ticket
    lib.service_disconnect()
    assert lib.service_valid() and lib.service_zero()
    lib.service_connect(0)
    resumed = r.CentralResume(old_ticket, now=100)
    _, accepted = control(lib, resumed.begin())
    finish = resumed.accept(accepted)
    _, reply = control(lib, finish)
    resumed.finish(reply)
    if profile == r.V08:
        from src.common.resume_hybrid import HybridApplication
        keys, sid = c.create_string_buffer(64), c.create_string_buffer(16)
        assert lib.service_take_hybrid(keys, sid) == 0
        channel = HybridApplication(resumed)
        ping = channel.encrypt_ping(0, 247)
        assert lib.service_hybrid_decrypt(ping, len(ping), plain) == 0
        assert lib.service_hybrid_decrypt(skipped, len(skipped), plain) != 0
        assert lib.service_hybrid_encrypt(b"PONG 0", 6, pong) == 43
        channel.accept_pong(pong.raw[:43], 0, 247)
        lib.service_disconnect()
        assert lib.service_hybrid_zero()
    else:
        channel = app.CentralApplication(resumed, iv_c2p=resumed.keys.iv_c2p, iv_p2c=resumed.keys.iv_p2c)
        _, pong = control(lib, channel.encrypt_ping(bytes(16), 247))
        channel.accept_pong(pong, bytes(16), 247)
    lib.service_reset()


@pytest.mark.parametrize("failure", ["bad-finish", "send", "l4", "bond", "rpa"])
def test_failed_full_preserves_previous_ticket(native_service, failure):
    profile, lib = native_service
    if profile == r.V08 and failure in ("l4", "bond", "rpa"):
        return
    lib.service_reset()
    lib.service_connect(0)
    assert lib.service_full(PRK, TH) == 0
    lib.service_disconnect()
    lib.service_connect(0)
    old_root, old_id = c.create_string_buffer(32), c.create_string_buffer(16)
    lib.service_ticket(old_root, old_id)
    full = begin_full(profile, lib)
    fc = full.finish_c(authenticated=True)
    if failure == "bad-finish":
        from tests.test_resumption import flip
        fc = flip(fc)
    elif failure == "send":
        c.c_int.in_dll(lib, "test_notify_error").value = 1
    elif failure == "l4":
        c.c_bool.in_dll(lib, "test_l4").value = False
    elif failure == "bond":
        c.c_bool.in_dll(lib, "test_bond").value = False
    elif failure == "rpa":
        lib.service_identity(1)
    fp = c.create_string_buffer(40)
    assert lib.service_finish_full(fc, len(fc), fp) != 0
    root, rid = c.create_string_buffer(32), c.create_string_buffer(16)
    lib.service_ticket(root, rid)
    assert root.raw == old_root.raw and rid.raw == old_id.raw
    assert lib.service_valid() and not lib.service_count()
    lib.service_reset()


def test_v11_unresolved_private_address_cannot_resume_or_issue(service):
    profile, lib = service
    if profile != r.V11:
        return
    lib.service_identity(1)
    assert lib.service_full(PRK, TH) != 0
    _, reject = control(lib, r.CentralResume(ticket(profile), now=100).begin())
    r.parse(reject, profile, r.REJECT)
    assert lib.service_valid() and not lib.service_count()
    lib.service_identity(0)
    resume(profile, lib)  # Resolved original bond still works; ticket was retained.


def test_measured_resume_struct_sizes(native_service):
    _, lib = native_service
    assert lib.service_ticket_size() == 6224
    assert lib.service_session_size() == 216
