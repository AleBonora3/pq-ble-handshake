"""Whole Central runner against an independent cryptographic GATT peer model."""

import asyncio
import hashlib
import hmac
from types import SimpleNamespace

from bleak.exc import BleakGATTProtocolError
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
import pytest

from src.central import resumption as run, main
from src.common import resumption as r, phase7 as h, v1_cp4 as app
from src.common.ml_kem import generate_keypair, decapsulate
from src.common.resume_full import encode_full, parse_full, FullHandshake, security_info
from src.common.resume_store import TicketStore
from src.common.session import SecureChannel
from src.common.constants import PERIPHERAL_ROLE
from tests.test_v1_cp1 import FakePairingBackend
from tests.test_resumption import flip


@pytest.fixture(scope="module")
def keypair():
    return generate_keypair()


class Peer:
    address = "AA:BB:CC:DD:EE:FF"
    mtu_size = 247

    def __init__(self, profile, keypair):
        self.profile = profile
        self.pk, self.sk = keypair
        self.resume = r.PeripheralResume(profile, clock=lambda: 100)
        self.is_connected = True
        self.raw_client = object()
        self.secured = profile == r.V08
        self.callback = None
        self.fulls = self.reconnects = self.reads = self.cts = 0
        self.application_keys = []
        self.sequences = []
        self.tx = self.rx = 0
        self.fault = None
        self.reported = bytes((4, 7, 16, r.V11))

    def gate(self):
        if not self.secured:
            raise BleakGATTProtocolError(0x05)

    async def start_notify(self, callback):
        self.gate()
        self.callback = callback

    async def stop_notify(self):
        self.callback = None
        for attr in ("_v1_cp4_session", "_v1_cp3_session"):
            value = getattr(self, attr, None)
            if value:
                value.clear()

    async def reconnect_v1_peer(self, timeout=15):
        self.resume.disconnect()
        self.raw_client = object()
        self.reconnects += 1
        self.tx = self.rx = 0
        return True

    async def read_fragmented_public_key(self):
        self.gate()
        self.reads += 1
        return self.pk

    async def write_raw_ciphertext_fragment(self, wire):
        self.gate()

    async def write_fragmented_ciphertext(self, ct):
        self.gate()
        self.ct = ct
        self.cts += 1
        return 5

    def notify(self, wire):
        if self.fault == "link-replace":
            self.raw_client = object()
        self.callback(1, bytearray(wire))

    def activate(self, c2p, p2c, sid, iv_c2p=None, iv_p2c=None):
        self.c2p, self.p2c, self.sid = c2p, p2c, sid
        self.iv_c = app.derive_iv_base(c2p, sid, app.APP_C2P, profile=self.profile) if iv_c2p is None else iv_c2p
        self.iv_p = app.derive_iv_base(p2c, sid, app.APP_P2C, profile=self.profile) if iv_p2c is None else iv_p2c
        self.application_keys.append((bytes(c2p), bytes(p2c), bytes(self.iv_c), bytes(self.iv_p), sid))
        self.tx = self.rx = 0
        if self.profile == r.V08:
            self.legacy_c2p = SecureChannel(bytes(c2p), sid, PERIPHERAL_ROLE)
            self.legacy_p2c = SecureChannel(bytes(p2c), sid, PERIPHERAL_ROLE)

    async def write_secure_data(self, wire):
        assert self.profile == r.V08
        assert len(wire) == 43 and wire[8] == 1
        assert self.legacy_c2p.decrypt(wire) == f"PING {self.rx}".encode("ascii")
        self.sequences.append(self.rx)
        self.notify(self.legacy_p2c.encrypt(f"PONG {self.rx}".encode("ascii")))
        self.rx += 1

    async def send_control(self, wire):
        self.gate()
        if wire[:4] == r.MAGIC:
            try:
                if wire[5] == r.INIT:
                    reply = self.resume.init(wire, self.address, l4=self.secured, bonded=True)
                    if self.fault == "accept-mac":
                        self.fault = None
                        reply = flip(reply)
                    if self.fault == "silence":
                        self.fault = None
                        return
                else:
                    reply = self.resume.finish(wire, l4=self.secured, bonded=True)
                    self.resume.commit()
                    k = self.resume.keys
                    self.activate(k.app_c2p, k.app_p2c, self.resume.session_id, k.iv_c2p, k.iv_p2c)
            except r.ResumeError:
                reply = r.encode(self.profile, r.REJECT)
            self.notify(reply)
            return
        if wire[:4] == b"PQV1" and wire[5] == app.APP_C2P:
            assert self.profile == r.V11
            challenge = app.decrypt_application(self.c2p, self.iv_c, self.sid, wire, app.APP_C2P,
                self.rx, profile=self.profile)
            self.sequences.append(self.rx)
            self.rx += 1
            reply = app.encrypt_application(self.p2c, self.iv_p, self.sid, app.APP_P2C, self.tx,
                app.PONG, challenge, profile=self.profile)
            self.tx += 1
            self.notify(reply)
            return
        f = parse_full(self.profile, wire)
        if self.profile == r.V11 and f.subtype == 1:
            self.sec = encode_full(r.V11, 2, self.reported)
            self.notify(self.sec)
            return
        d = r.domain(self.profile)
        if f.subtype == (3 if self.profile == r.V08 else 0x14):
            self.fulls += 1
            self.sid = f.payload[:16]
            ss = decapsulate(self.sk, self.ct)
            if self.profile == r.V08:
                priv = h.generate_p256_private_key()
                pub = h.serialize_p256_public_key(priv)
                ecdh = h.derive_p256_ecdh_shared_secret(priv, f.payload[16:])
                t = b"".join(r.lp(v) for v in (d, b"\1", b"\2", self.sid, self.pk, self.ct, f.payload[16:], pub))
                self.th = hashlib.sha256(t).digest()
                self.prk = hmac.digest(self.th, r.lp(ss)+r.lp(ecdh), "sha256")
                block = HKDFExpand(algorithm=hashes.SHA256(), length=128, info=d+b"/hybrid-key-schedule").derive(self.prk)
                self.master, self.kc, self.kp = block[:32], block[64:96], block[96:]
                self.notify(encode_full(self.profile, 4, pub))
            else:
                self.th = hashlib.sha256(d+b"/CP3-TRANSCRIPT"+self.sec+self.pk+self.ct+wire).digest()
                self.prk = hmac.digest(self.th, ss, "sha256")
                self.kc = hmac.digest(self.prk, d+b"/FINISHED-C"+self.th+b"\1", "sha256")
                self.kp = hmac.digest(self.prk, d+b"/FINISHED-P"+self.th+b"\1", "sha256")
                self.notify(encode_full(self.profile, 0x15, self.th))
            return
        assert f.subtype == (5 if self.profile == r.V08 else 0x12)
        c_label = b"/FINISHED/C" if self.profile == r.V08 else b"/VERIFY-C"
        assert hmac.compare_digest(f.payload, hmac.digest(self.kc, d+c_label+self.th, "sha256"))
        if self.profile == r.V11:
            self.th = hashlib.sha256(self.th+wire).digest()
        p_label = b"/FINISHED/P" if self.profile == r.V08 else b"/VERIFY-P"
        tag = hmac.digest(self.kp, d+p_label+self.th, "sha256")
        fp = encode_full(self.profile, 6 if self.profile == r.V08 else 0x13, tag)
        if self.fault == "finished-p":
            self.notify(flip(fp))
            return  # model's failed full handshake deliberately issues no ticket
        if self.profile == r.V11:
            self.th = hashlib.sha256(self.th+fp).digest()
            c2p = hmac.digest(self.prk, d+b"/APP-C2P"+self.th+b"\1", "sha256")
            p2c = hmac.digest(self.prk, d+b"/APP-P2C"+self.th+b"\1", "sha256")
        else:
            c2p = hmac.digest(self.master, b"PQ-BLE-TRAFFIC-v0.8/CENTRAL-TO-PERIPHERAL", "sha256")
            p2c = hmac.digest(self.master, b"PQ-BLE-TRAFFIC-v0.8/PERIPHERAL-TO-CENTRAL", "sha256")
        old = self.resume.ticket
        self.resume.ticket = r.Ticket.issue(self.profile, self.address, self.prk, self.th, authenticated=True, now=100)
        if old is not None:
            old.clear()
        self.activate(c2p, p2c, self.sid)
        self.notify(fp)


async def yes(_):
    return True


def execute(peer, store, backend=None, **kwargs):
    return asyncio.run(run.run_session(peer, peer.profile, store=store, sas_callback=yes,
        confirm_numeric_comparison=yes, pairing_backend=backend, timeout=0.05, **kwargs))


@pytest.fixture(params=[r.V08, r.V11])
def setup(request, tmp_path, keypair):
    peer = Peer(request.param, keypair)
    store = TicketStore(tmp_path, clock=lambda: 100)
    backend = FakePairingBackend(peer, paired=request.param == r.V11)
    return peer, store, backend


def test_full_resume_process_restart_and_no_expensive_operations(setup, monkeypatch):
    peer, store, backend = setup
    first = execute(peer, store, backend)
    rounds = 3 if peer.profile == r.V08 else 2
    assert first.path == "full" and first.rounds == rounds
    assert store.load(peer.profile, peer.address).rid == peer.resume.ticket.rid
    asyncio.run(peer.reconnect_v1_peer())
    def forbidden(*a, **kw):
        raise AssertionError("expensive/human full-handshake path reached during resume")
    monkeypatch.setattr(run, "encapsulate", forbidden)
    monkeypatch.setattr(run, "_confirm_sas", forbidden)
    monkeypatch.setattr(h, "generate_p256_private_key", forbidden)
    monkeypatch.setattr(h, "derive_p256_ecdh_shared_secret", forbidden)
    # New store object exercises persisted restart semantics.
    second = execute(peer, TicketStore(store.directory, clock=lambda: 100), backend)
    assert second.path == "resume" and second.rounds == rounds and second.successful_resumes == 1
    assert peer.fulls == peer.reads == peer.cts == 1
    assert peer.sequences == list(range(rounds)) * 2
    for before, after in zip(*peer.application_keys):
        assert before != after
    assert "nc" not in backend.calls


@pytest.mark.parametrize("failure", ["missing", "expired", "maxed", "corrupt", "accept-mac", "silence"])
def test_fallback_and_replacement(setup, failure):
    peer, store, backend = setup
    execute(peer, store, backend)
    old = store.load(peer.profile, peer.address)
    asyncio.run(peer.reconnect_v1_peer())
    if failure == "missing":
        peer.resume.ticket = None
    elif failure == "expired":
        peer.resume.ticket.created_at -= r.TTL
    elif failure == "maxed":
        peer.resume.ticket.successful_resumes = 100
    elif failure == "corrupt":
        store.path(peer.profile, peer.address).write_text("broken")
    else:
        peer.fault = failure
    result = execute(peer, store, backend)
    assert result.path == "full" and result.rounds == (3 if peer.profile == r.V08 else 2) and peer.fulls == 2
    assert store.load(peer.profile, peer.address).root != old.root
    assert store.load(peer.profile, peer.address).rid == peer.resume.ticket.rid


def test_failed_full_never_persists_a_ticket(setup):
    peer, store, backend = setup
    peer.fault = "finished-p"
    with pytest.raises((ValueError, run.V1Error)):
        execute(peer, store, backend)
    assert store.load(peer.profile, peer.address) is None
    assert peer.resume.ticket is None


@pytest.mark.parametrize("mode", ["init-mac", "accept-mac", "replay-init", "replay-finish"])
def test_explicit_negative_modes(setup, mode):
    peer, store, backend = setup
    execute(peer, store, backend)
    asyncio.run(peer.reconnect_v1_peer())
    with pytest.raises(run.NegativePassed):
        execute(peer, store, backend, negative=mode)
    t = store.load(peer.profile, peer.address)
    assert t.valid and t.successful_resumes == (1 if mode == "replay-finish" else 0)


def test_bond_deleted_requires_cold_nc_and_full(tmp_path, keypair):
    peer = Peer(r.V11, keypair)
    backend = FakePairingBackend(peer, paired=True)
    store = TicketStore(tmp_path, clock=lambda: 100)
    execute(peer, store, backend)
    asyncio.run(peer.reconnect_v1_peer())
    old = store.load(r.V11, peer.address)
    backend.paired = peer.secured = False
    result = execute(peer, store, backend)
    assert result.path == "full" and result.scenario == "cold" and "nc" in backend.calls
    assert peer.fulls == 2 and store.load(r.V11, peer.address).rid != old.rid


@pytest.mark.parametrize("info", [bytes((level, flags, size, profile)) for level, flags, size, profile in
    ((1, 0, 0, 17), (2, 5, 16, 17), (3, 6, 16, 17), (4, 7, 15, 17), (4, 3, 16, 17), (4, 7, 16, 16))])
def test_insufficient_attestation_never_attempts_resume(tmp_path, keypair, info):
    peer = Peer(r.V11, keypair)
    backend = FakePairingBackend(peer, paired=True)
    store = TicketStore(tmp_path, clock=lambda: 100)
    execute(peer, store, backend)
    asyncio.run(peer.reconnect_v1_peer())
    peer.reported = info
    with pytest.raises(run.V1Error):
        execute(peer, store, backend)
    assert peer.resume.ticket.successful_resumes == 0 and peer.fulls == 1


def test_cli_profiles_are_explicit():
    assert main.parse_args(["--v08-resume-hybrid"]).v08_resume_hybrid
    assert main.parse_args(["--v11-smp-l4-mlkem-resume"]).v11_smp_l4_mlkem_resume
    for args in (["--resume-full"], ["--v08-resume-hybrid", "--no-sas-confirm"],
        ["--v08-resume-hybrid", "--phase7-auth-hybrid"],
        ["--v11-smp-l4-mlkem-resume", "--v1-cp4"],
        ["--v08-resume-hybrid", "--resume-negative-test-only", "pre-l4"]):
        with pytest.raises(SystemExit):
            main.parse_args(args)
