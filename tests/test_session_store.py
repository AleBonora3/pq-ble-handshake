"""
Tests for SessionStore and session resumption (Strada A).

Covers:
- SessionStore save/load/delete
- Session expiry
- Session ID generation
- Resume request wire format
- parse_control_message
- Simulated resume flow (integration)
"""

import os
import time
import tempfile
import pytest

from src.common.session_store import SessionStore, SessionEntry
from src.common.session import (
    generate_session_id,
    build_resume_request,
    parse_control_message,
    derive_session_key,
    SecureChannel,
)
from src.common.constants import (
    SESSION_ID_SIZE,
    SESSION_KEY_SIZE,
    RESUME_MAGIC,
    RESUME_REQ,
    RESUME_OK_NOTIFY,
    RESUME_FAIL_NOTIFY,
)
from src.common.ml_kem import generate_keypair, encapsulate, decapsulate


# ─────────────────────────────────────────────────────────
# Session ID generation
# ─────────────────────────────────────────────────────────

def test_generate_session_id_size():
    sid = generate_session_id()
    assert len(sid) == SESSION_ID_SIZE


def test_generate_session_id_unique():
    # 100 IDs should all be unique (astronomically likely)
    ids = {generate_session_id() for _ in range(100)}
    assert len(ids) == 100


# ─────────────────────────────────────────────────────────
# Resume wire format
# ─────────────────────────────────────────────────────────

def test_build_resume_request():
    sid = b"\x01" * 16
    msg = build_resume_request(sid)
    assert len(msg) == 21  # 4 + 1 + 16
    assert msg[:4] == RESUME_MAGIC
    assert msg[4:5] == RESUME_REQ
    assert msg[5:] == sid


def test_build_resume_request_bad_size():
    with pytest.raises(ValueError):
        build_resume_request(b"short")


# ─────────────────────────────────────────────────────────
# parse_control_message
# ─────────────────────────────────────────────────────────

def test_parse_sas_confirm():
    result = parse_control_message(b"OK")
    assert result == {"type": "sas_confirm"}


def test_parse_resume_request():
    sid = b"\x02" * 16
    msg = build_resume_request(sid)
    result = parse_control_message(msg)
    assert result["type"] == "resume_request"
    assert result["session_id"] == sid


def test_parse_unknown():
    result = parse_control_message(b"HELLO")
    assert result["type"] == "unknown"
    assert result["raw"] == b"HELLO"


def test_parse_short_resume():
    # Too short to be a valid resume request
    result = parse_control_message(RESUME_MAGIC + RESUME_REQ + b"short")
    assert result["type"] == "unknown"


# ─────────────────────────────────────────────────────────
# Session store
# ─────────────────────────────────────────────────────────

@pytest.fixture
def store_path():
    """Temporary JSON file for testing."""
    fd, path = tempfile.mkstemp(suffix=".json", prefix="test_session_store_")
    os.close(fd)
    yield path
    if os.path.exists(path):
        os.unlink(path)


@pytest.fixture
def store(store_path):
    return SessionStore(store_path, max_age_hours=24)


def test_store_save_and_load(store):
    sid = generate_session_id()
    key = os.urandom(SESSION_KEY_SIZE)

    store.save(sid, key)
    loaded = store.load(sid)
    assert loaded == key
    assert store.count == 1


def test_store_load_missing(store):
    sid = generate_session_id()
    assert store.load(sid) is None


def test_store_has(store):
    sid = generate_session_id()
    key = os.urandom(SESSION_KEY_SIZE)

    assert not store.has(sid)
    store.save(sid, key)
    assert store.has(sid)


def test_store_delete(store):
    sid = generate_session_id()
    store.save(sid, b"x" * 32)
    assert store.count == 1

    store.delete(sid)
    assert store.count == 0
    assert store.load(sid) is None


def test_store_bad_session_id(store):
    with pytest.raises(ValueError):
        store.save(b"short", b"x" * 32)


def test_store_persistence(store_path):
    sid = generate_session_id()
    key = os.urandom(SESSION_KEY_SIZE)

    # Save
    store1 = SessionStore(store_path, max_age_hours=24)
    store1.save(sid, key)

    # Reload from disk
    store2 = SessionStore(store_path, max_age_hours=24)
    assert store2.load(sid) == key


def test_store_expiry(store_path):
    sid = generate_session_id()
    key = os.urandom(SESSION_KEY_SIZE)

    # Save with a store that has a very short expiry
    store1 = SessionStore(store_path, max_age_hours=0.0001)  # ~0.36 seconds
    store1.save(sid, key)

    # Wait past expiry
    time.sleep(0.5)

    # Reload — entry should be expired
    store2 = SessionStore(store_path, max_age_hours=0.0001)
    assert store2.load(sid) is None
    assert store2.count == 0


def test_store_expire_older_than(store):
    sid1 = generate_session_id()
    sid2 = generate_session_id()

    store.save(sid1, b"x" * 32)
    store.save(sid2, b"y" * 32)

    # Manually back-date sid1's entry
    sid1_hex = sid1.hex()
    store._sessions[sid1_hex].created_at = time.time() - 3600 * 25  # 25h ago
    store._persist()

    removed = store.expire_older_than(max_age_hours=24)
    assert removed == 1
    assert store.has(sid2)
    assert not store.has(sid1)


def test_store_list_ids(store):
    sid = generate_session_id()
    store.save(sid, b"z" * 32)

    entries = store.list_ids()
    assert len(entries) == 1
    assert entries[0][0] == sid.hex()


def test_store_usage_counter(store):
    sid = generate_session_id()
    store.save(sid, b"a" * 32)

    # First load increments
    store.load(sid)
    entries = store.list_ids()
    assert entries[0][2] == 1  # usage_count

    # Second load increments again
    store.load(sid)
    entries = store.list_ids()
    assert entries[0][2] == 2


# ─────────────────────────────────────────────────────────
# Resume flow simulation (integration)
# ─────────────────────────────────────────────────────────

def test_full_handshake_then_resume():
    """
    Simulate: full PQ handshake → save session → resume on
    next "connection".
    """
    # ── First session: full handshake ───────────────────
    pk, sk = generate_keypair()
    ct, ss = encapsulate(pk)
    ss2 = decapsulate(sk, ct)
    assert ss == ss2

    session_key = derive_session_key(ss)

    # Save on both sides
    sid = generate_session_id()
    with tempfile.TemporaryDirectory() as tmpdir:
        central_store_path = os.path.join(tmpdir, "central.json")
        periph_store_path = os.path.join(tmpdir, "periph.json")

        central_store = SessionStore(central_store_path)
        periph_store = SessionStore(periph_store_path)

        central_store.save(sid, session_key)
        periph_store.save(sid, session_key)

        # ── Second session: resume ──────────────────────
        # Central: build resume request
        resume_msg = build_resume_request(sid)

        # Peripheral: parse and respond
        parsed = parse_control_message(resume_msg)
        assert parsed["type"] == "resume_request"

        # Peripheral: look up session_id
        loaded_key = periph_store.load(parsed["session_id"])
        assert loaded_key is not None
        assert loaded_key == session_key

        # Central also still has it
        central_key = central_store.load(sid)
        assert central_key == session_key


def test_resume_with_wrong_id():
    """Peripheral rejects unknown session_id."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store_path = os.path.join(tmpdir, "periph.json")
        periph_store = SessionStore(store_path)

        unknown_sid = generate_session_id()
        resume_msg = build_resume_request(unknown_sid)

        parsed = parse_control_message(resume_msg)
        assert parsed["type"] == "resume_request"

        # Peripheral rejects
        assert not periph_store.has(parsed["session_id"])
        # -> would send RESUME_FAIL_NOTIFY


def test_resume_encrypted_channel_works():
    """
    After resume, both sides use the same session_key and can
    exchange encrypted data.
    """
    # Full handshake
    pk, sk = generate_keypair()
    ct, ss = encapsulate(pk)
    ss2 = decapsulate(sk, ct)
    assert ss == ss2
    session_key = derive_session_key(ss)

    sid = generate_session_id()

    # Simulate storing
    with tempfile.TemporaryDirectory() as tmpdir:
        c_path = os.path.join(tmpdir, "c.json")
        p_path = os.path.join(tmpdir, "p.json")
        c_store = SessionStore(c_path)
        p_store = SessionStore(p_path)
        c_store.save(sid, session_key)
        p_store.save(sid, session_key)

        # Resume — both load same key
        c_key = c_store.load(sid)
        p_key = p_store.load(sid)
        assert c_key == p_key == session_key

        # Secure channel using resumed key
        channel_c = SecureChannel(c_key)
        channel_p = SecureChannel(p_key)

        plaintext = b"Ciao dal canale sicuro dopo resume!"
        encrypted = channel_c.encrypt(plaintext)
        decrypted = channel_p.decrypt(encrypted)
        assert decrypted == plaintext

        # And in reverse
        reply = b"Messaggio di risposta PQ-protetto"
        encrypted2 = channel_p.encrypt(reply)
        decrypted2 = channel_c.decrypt(encrypted2)
        assert decrypted2 == reply


def test_resume_saves_re_handshake_mitigation():
    """
    After max_age_hours, the session expires and a fresh
    handshake is required (mitigating forward secrecy loss).
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        store_path = os.path.join(tmpdir, "store.json")

        # Store with short expiry
        store = SessionStore(store_path, max_age_hours=0.0001)
        sid = generate_session_id()
        store.save(sid, b"k" * 32)
        assert store.has(sid)

        # Wait for expiry
        time.sleep(0.5)

        # Session should be gone
        assert not store.has(sid)
        assert store.load(sid) is None


def test_usage_counter_persists():
    """Usage counter survives disk round-trip."""
    with tempfile.TemporaryDirectory() as tmpdir:
        store_path = os.path.join(tmpdir, "store.json")
        sid = generate_session_id()

        store1 = SessionStore(store_path)
        store1.save(sid, b"x" * 32)
        store1.load(sid)  # usage: 1

        store2 = SessionStore(store_path)
        entries = store2.list_ids()
        assert entries[0][2] == 1