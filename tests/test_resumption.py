"""Software-only security/lifecycle evidence for the new profiles."""

import hashlib
import hmac
import json

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from src.common import resumption as r
from src.common.resume_store import TicketStore

PROFILES = [r.V08, r.V11]
PRK, TH = bytes(range(32)), bytes(range(32, 64))


def flip(data, index=-1):
    return data[:index] + bytes((data[index] ^ 1,)) + data[index+1:] if index >= 0 else data[:-1] + bytes((data[-1] ^ 1,))


def ticket(profile=r.V08, now=100):
    return r.Ticket.issue(profile, "peer", PRK, TH, authenticated=True, now=now)


def pair(profile=r.V08, now=100):
    c = r.CentralResume(ticket(profile, now), now=now)
    p = r.PeripheralResume(profile, ticket(profile, now), clock=lambda: now)
    return c, p


def exchange(c, p):
    accept = p.init(c.begin(), "peer", l4=True, bonded=True)
    fc = c.accept(accept)
    fp = p.finish(fc, l4=True, bonded=True)
    assert c.state != "APP_SECURE" and p.state != "APP_SECURE"
    p.commit()
    c.finish(fp)
    return accept, fc, fp


@pytest.mark.parametrize("profile", PROFILES)
def test_root_identifier_and_reference_hkdf(profile):
    root = r.derive_root(profile, PRK, TH)
    assert root == HKDFExpand(algorithm=hashes.SHA256(), length=32,
                             info=r.domain(profile)+b"/RESUME-ROOT"+TH).derive(PRK)
    assert root != r.derive_root(profile, flip(PRK), TH)
    assert r.resume_id(profile, root, TH) == hmac.digest(root,
        r.domain(profile)+b"/RESUME-ID"+TH, "sha256")[:16]
    assert r.resume_id(profile, root, TH) != r.resume_id(profile, flip(root), TH)
    assert r.derive_root(r.V08, PRK, TH) != r.derive_root(r.V11, PRK, TH)
    assert root.hex() not in repr(ticket(profile))


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("subtype", r.PAYLOAD_SIZES)
def test_strict_frames(profile, subtype):
    raw = r.encode(profile, subtype, bytes(r.PAYLOAD_SIZES[subtype]))
    assert len(raw) == 8+r.PAYLOAD_SIZES[subtype]
    assert r.parse(raw, profile, subtype)[1] == raw[8:]
    for size in range(len(raw)):
        with pytest.raises(r.ResumeError):
            r.parse(raw[:size], profile)
    for altered in (raw+b"\0", flip(raw, 0), flip(raw, 4), flip(raw, 6), flip(raw, 7)):
        with pytest.raises(r.ResumeError):
            r.parse(altered, profile)


@pytest.mark.parametrize("profile", PROFILES)
def test_mutual_confirmation_keys_and_disconnect(profile):
    c, p = pair(profile)
    exchange(c, p)
    assert c.state == p.state == "APP_SECURE"
    values = [bytes(getattr(c.keys, attr)) for attr in ("app_c2p", "app_p2c", "iv_c2p", "iv_p2c")]
    assert len(set(values)) == 4
    assert c.keys.app_c2p == p.keys.app_c2p and c.keys.iv_p2c == p.keys.iv_p2c
    assert not any(c.keys.confirm_c+c.keys.confirm_p+p.keys.confirm_c+p.keys.confirm_p)
    assert c.ticket.successful_resumes == p.ticket.successful_resumes == 1
    c.clear()
    p.disconnect()
    assert c.ticket.valid and p.ticket.valid
    assert not any(c.keys.app_c2p+c.keys.app_p2c+c.keys.iv_c2p+c.keys.iv_p2c)
    c2 = r.CentralResume(c.ticket, now=100)
    exchange(c2, p)
    assert values != [bytes(getattr(c2.keys, attr)) for attr in ("app_c2p", "app_p2c", "iv_c2p", "iv_p2c")]


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("which", ["sid", "nc", "np", "rid"])
def test_every_fresh_context_field_changes_keys(profile, which):
    args = dict(rid=bytes(16), sid=bytes(16), nc=bytes(32), np=bytes(32))
    before = r.SessionKeys(profile, PRK, **args)
    args[which] = flip(args[which])
    after = r.SessionKeys(profile, PRK, **args)
    for attr in ("confirm_c", "confirm_p", "app_c2p", "app_p2c", "iv_c2p", "iv_p2c"):
        assert getattr(before, attr) != getattr(after, attr)
    assert len({bytes(getattr(before, a)) for a in ("confirm_c", "confirm_p", "app_c2p", "app_p2c")}) == 4


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("index", [8, 24, 40, 72, 103])
def test_init_tamper_preserves_ticket(profile, index):
    c, p = pair(profile)
    with pytest.raises(r.ResumeError, match="BAD_AUTH"):
        p.init(flip(c.begin(), index), "peer", l4=True, bonded=True)
    assert p.state == "IDLE" and p.ticket.valid and p.ticket.successful_resumes == 0
    assert not p.ticket.replay


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("stage", ["accept", "finish_c", "finish_p"])
def test_confirmation_tamper_fails_closed(profile, stage):
    c, p = pair(profile)
    accept = p.init(c.begin(), "peer", l4=True, bonded=True)
    if stage == "accept":
        with pytest.raises(r.ResumeError, match="BAD_AUTH"):
            c.accept(flip(accept))
        assert c.state == "CLOSED" and c.ticket.successful_resumes == 0
        return
    fc = c.accept(accept)
    if stage == "finish_c":
        keys = p.keys
        with pytest.raises(r.ResumeError, match="BAD_AUTH"):
            p.finish(flip(fc), l4=True, bonded=True)
        assert p.state == "IDLE" and not any(keys.app_c2p+keys.confirm_p)
        assert p.ticket.successful_resumes == 0
        return
    fp = p.finish(fc, l4=True, bonded=True)
    with pytest.raises(r.ResumeError, match="BAD_AUTH"):
        c.finish(flip(fp))
    assert c.state == "CLOSED" and c.ticket.successful_resumes == 0
    assert not any(c.keys.app_c2p+c.keys.confirm_p)


def test_replays_and_old_finish_cannot_open_a_new_connection():
    c, p = pair()
    init = c.begin()
    fc = c.accept(p.init(init, "peer"))
    fp = p.finish(fc)
    p.commit()
    c.finish(fp)
    p.disconnect()
    with pytest.raises(r.ResumeError, match="REPLAY"):
        p.init(init, "peer")
    fresh = r.CentralResume(c.ticket, now=100)
    fresh.accept(p.init(fresh.begin(), "peer"))
    with pytest.raises(r.ResumeError, match="BAD_AUTH"):
        p.finish(fc)
    with pytest.raises(r.ResumeError, match="BAD_AUTH"):
        fresh.finish(fp)
    assert p.state == "IDLE" and fresh.state == "CLOSED"
    assert p.ticket.successful_resumes == 1


@pytest.mark.parametrize("l4,bonded", [(False, False), (False, True), (True, False)])
def test_v11_bond_and_l4_required(l4, bonded):
    c, p = pair(r.V11)
    with pytest.raises(r.ResumeError, match="L4_REQUIRED"):
        p.init(c.begin(), "peer", l4=l4, bonded=bonded)
    assert p.state == "IDLE" and p.ticket.valid


def test_profile_peer_missing_expiry_and_full_auth_policy():
    with pytest.raises(r.ResumeError, match="BAD_AUTH"):
        r.Ticket.issue(r.V08, "peer", PRK, TH, authenticated=False)
    for now in (99, 100+r.TTL):
        t = ticket()
        with pytest.raises(r.ResumeError, match="EXPIRED"):
            t.check(r.V08, "peer", now)
        assert not t.valid and not any(t.root)
    for profile, peer in ((r.V11, "peer"), (r.V08, "other")):
        t = ticket()
        with pytest.raises(r.ResumeError, match="PROFILE_MISMATCH"):
            t.check(profile, peer, 100)
        assert t.valid
    c, p = pair()
    p.ticket = None
    with pytest.raises(r.ResumeError, match="NO_TICKET"):
        p.init(c.begin(), "peer")


def test_100_successes_and_failures_do_not_consume_count():
    c, p = pair()
    for index in range(100):
        c = r.CentralResume(c.ticket, now=100)
        exchange(c, p)
        assert c.ticket.successful_resumes == p.ticket.successful_resumes == index+1
        p.disconnect()
    assert not c.ticket.valid and not p.ticket.valid
    assert not any(c.ticket.root+p.ticket.root)
    with pytest.raises(r.ResumeError, match="NO_TICKET"):
        r.CentralResume(c.ticket, now=100)


def test_timeout_send_failure_and_replay_capacity():
    c, p = pair()
    fc = c.accept(p.init(c.begin(), "peer"))
    keys = p.keys
    p.clock = lambda: 130
    with pytest.raises(r.ResumeError):
        p.finish(fc)
    assert not any(keys.app_c2p+keys.confirm_p) and p.ticket.successful_resumes == 0
    p.clock = lambda: 100
    p.ticket.replay = [(i.to_bytes(32, "big"), i.to_bytes(16, "big")) for i in range(r.REPLAY_CAPACITY)]
    fresh = r.CentralResume(c.ticket, now=100)
    with pytest.raises(r.ResumeError, match="REPLAY_CACHE_FULL"):
        p.init(fresh.begin(), "peer")
    assert p.ticket.valid


def test_atomic_persistent_store_and_corruption(tmp_path):
    store = TicketStore(tmp_path, clock=lambda: 100)
    t = ticket()
    assert store.load(r.V08, "peer") is None
    store.save(t)
    loaded = TicketStore(tmp_path, clock=lambda: 100).load(r.V08, "peer")
    assert loaded.root == t.root and loaded.rid == t.rid
    loaded.used()
    store.save(loaded)
    assert store.load(r.V08, "peer").successful_resumes == 1
    path = store.path(r.V08, "peer")
    original = json.loads(path.read_text())
    for key, value in (("schema", True), ("profile", 17), ("peer", "other"),
            ("created_at", float("nan")), ("created_at", True),
            ("successful_resume_count", -1), ("successful_resume_count", True),
            ("resume_id", "00"), ("k_resume", "bad"), ("k_resume", None)):
        path.write_text(json.dumps(original | {key: value}))
        assert store.load(r.V08, "peer") is None
    for raw in ("[]", "null", "{broken", "1", '"text"'):
        path.write_text(raw)
        assert store.load(r.V08, "peer") is None
    store.save(t)
    store.clock = lambda: 100+r.TTL
    assert store.load(r.V08, "peer") is None and not path.exists()
    assert not list(tmp_path.glob(".ticket-*"))


def test_atomic_replace_failure_keeps_old_ticket_and_removes_temporary(tmp_path, monkeypatch):
    import os
    store = TicketStore(tmp_path, clock=lambda: 100)
    old = ticket()
    store.save(old)
    replacement = r.Ticket.issue(r.V08, "peer", flip(PRK), TH, authenticated=True, now=100)
    def fail(*_):
        raise OSError("injected atomic replace failure")
    monkeypatch.setattr(os, "replace", fail)
    with pytest.raises(OSError):
        store.save(replacement)
    assert store.load(r.V08, "peer").root == old.root
    assert not list(tmp_path.glob(".ticket-*"))
    assert "root=" not in repr(old) and repr(old.root) not in repr(old)
    assert set(json.loads(store.path(r.V08, "peer").read_text())) == {
        "schema", "profile", "peer", "resume_id", "k_resume", "created_at", "successful_resume_count"}
