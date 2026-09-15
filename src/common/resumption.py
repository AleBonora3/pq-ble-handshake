"""v0.8/v1.1 authenticated resumption; no ML-KEM, ECDH or traffic-key storage.

The Peripheral model also specifies the firmware state machine. Owned mutable
buffers are wiped; Python/backend immutable copies cannot be reliably erased.
"""

from dataclasses import dataclass, field
from enum import IntEnum
import hashlib
import hmac
import secrets
import time

from .v1_cp3 import clear, expand

V08, V11 = 0x08, 0x11
TTL = 24 * 60 * 60
MAX_RESUMES = 100
REPLAY_CAPACITY = 128
MAGIC = b"PQRS"
INIT, ACCEPT, FINISH_C, FINISH_P, REJECT = range(0x30, 0x35)
PAYLOAD_SIZES = {INIT: 96, ACCEPT: 64, FINISH_C: 32, FINISH_P: 32, REJECT: 0}


class Reason(IntEnum):
    NO_TICKET = 1
    EXPIRED = 2
    MAX_USES = 3
    PROFILE_MISMATCH = 4
    BAD_AUTH = 5
    REPLAY = 6
    L4_REQUIRED = 7
    MALFORMED = 8
    INTERNAL_ERROR = 9
    REPLAY_CACHE_FULL = 10


class ResumeError(ValueError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason.name)


def domain(profile):
    if profile not in (V08, V11):
        raise ResumeError(Reason.PROFILE_MISMATCH)
    return b"PQ-BLE-HANDSHAKE-" + (b"v0.8" if profile == V08 else b"v1.1")


def sized(value, length):
    if not isinstance(value, (bytes, bytearray, memoryview)) or len(value) != length:
        raise ResumeError(Reason.MALFORMED)
    return bytes(value)


def lp(value):
    return len(value).to_bytes(2, "big") + value


def encode(profile, subtype, payload=b""):
    domain(profile)
    if subtype not in PAYLOAD_SIZES:
        raise ResumeError(Reason.MALFORMED)
    payload = sized(payload, PAYLOAD_SIZES[subtype])
    return MAGIC + bytes((profile, subtype)) + len(payload).to_bytes(2, "big") + payload


def parse(raw, profile, expected=None):
    domain(profile)
    if len(raw) < 8 or raw[:4] != MAGIC:
        raise ResumeError(Reason.MALFORMED)
    if raw[4] != profile:
        raise ResumeError(Reason.PROFILE_MISMATCH)
    subtype = raw[5]
    if (subtype not in PAYLOAD_SIZES or len(raw) != 8 + PAYLOAD_SIZES[subtype]
            or int.from_bytes(raw[6:8], "big") != PAYLOAD_SIZES[subtype]
            or (expected is not None and subtype != expected)):
        raise ResumeError(Reason.MALFORMED)
    return subtype, bytes(raw[8:])


def derive_root(profile, full_prk, full_th):
    return expand(sized(full_prk, 32), domain(profile) + b"/RESUME-ROOT", sized(full_th, 32))


def resume_id(profile, root, full_th):
    return hmac.digest(sized(root, 32), domain(profile) + b"/RESUME-ID" + sized(full_th, 32), "sha256")[:16]


def context(profile, rid, sid, nc, np=None):
    value = bytes((profile,)) + sized(rid, 16) + sized(sid, 16) + sized(nc, 32)
    return value if np is None else value + sized(np, 32)


def auth(profile, root, label, rid, sid, nc, np=None):
    return hmac.digest(sized(root, 32), domain(profile) + b"/RESUME-" + label
                       + context(profile, rid, sid, nc, np), "sha256")


def transcript(profile, rid, sid, nc, np):
    return b"".join(lp(v) for v in (domain(profile) + b"/RESUME-TRANSCRIPT", bytes((profile,)),
        sized(rid, 16), sized(sid, 16), sized(nc, 32), sized(np, 32)))


class SessionKeys:
    def __init__(self, profile, root, rid, sid, nc, np):
        self.profile = profile
        self.th = bytearray(hashlib.sha256(transcript(profile, rid, sid, nc, np)).digest())
        prk = bytearray(hmac.digest(self.th, sized(root, 32), "sha256"))
        self.confirm_c = self.confirm_p = self.app_c2p = self.app_p2c = bytearray()
        self.iv_c2p = self.iv_p2c = bytearray()
        try:
            for attr, label, length in (("confirm_c", b"CONFIRM-C", 32), ("confirm_p", b"CONFIRM-P", 32),
                    ("app_c2p", b"APP-C2P", 32), ("app_p2c", b"APP-P2C", 32),
                    ("iv_c2p", b"IV-C2P", 12), ("iv_p2c", b"IV-P2C", 12)):
                block = expand(prk, domain(profile) + b"/RESUME-" + label, self.th)
                setattr(self, attr, bytearray(block[:length]))
                clear(block)
        except BaseException:
            self.clear()
            raise
        finally:
            clear(prk)

    def finish(self, central):
        label = b"C" if central else b"P"
        return hmac.digest(self.confirm_c if central else self.confirm_p,
            domain(self.profile) + b"/RESUME-FINISH-" + label + self.th, "sha256")

    def clear_confirmation(self):
        for value in (self.confirm_c, self.confirm_p, self.th):
            clear(value)

    def clear(self):
        self.clear_confirmation()
        for value in (self.app_c2p, self.app_p2c, self.iv_c2p, self.iv_p2c):
            clear(value)


@dataclass
class Ticket:
    profile: int
    peer: str
    rid: bytes
    root: bytearray = field(repr=False)
    created_at: float = field(default_factory=time.time)
    successful_resumes: int = 0
    # Peripheral-only, monotonic clock; never written to the Central store.
    replay: list = field(default_factory=list, repr=False)
    valid: bool = True

    @classmethod
    def issue(cls, profile, peer, prk, th, *, authenticated, now=None):
        if not authenticated:
            raise ResumeError(Reason.BAD_AUTH)
        root = derive_root(profile, prk, th)
        return cls(profile, peer, resume_id(profile, root, th), root,
                   time.time() if now is None else now)

    def check(self, profile, peer, now):
        if not self.valid:
            raise ResumeError(Reason.NO_TICKET)
        if now < self.created_at or now - self.created_at >= TTL:
            self.clear()
            raise ResumeError(Reason.EXPIRED)
        if self.successful_resumes >= MAX_RESUMES:
            self.clear()
            raise ResumeError(Reason.MAX_USES)
        if self.profile != profile or self.peer != peer:
            raise ResumeError(Reason.PROFILE_MISMATCH)

    def used(self):
        self.successful_resumes += 1
        if self.successful_resumes >= MAX_RESUMES:
            self.clear()

    def clear(self):
        clear(self.root)
        self.rid = b""
        self.replay.clear()
        self.valid = False


class CentralResume:
    def __init__(self, ticket, *, now=None):
        ticket.check(ticket.profile, ticket.peer, time.time() if now is None else now)
        self.ticket = ticket
        self.profile = ticket.profile
        self.state = "NEW"
        self.session_id = secrets.token_bytes(16)
        self.nc = secrets.token_bytes(32)
        self.keys = None

    def begin(self):
        if self.state != "NEW":
            self.clear()
            raise ResumeError(Reason.MALFORMED)
        self.state = "WAIT_ACCEPT"
        t = self.ticket
        mac = auth(self.profile, t.root, b"INIT", t.rid, self.session_id, self.nc)
        return encode(self.profile, INIT, t.rid + self.session_id + self.nc + mac)

    @property
    def app_c2p(self):
        return self.keys.app_c2p if self.keys is not None else bytearray()

    @property
    def app_p2c(self):
        return self.keys.app_p2c if self.keys is not None else bytearray()

    def accept(self, raw):
        try:
            if self.state != "WAIT_ACCEPT":
                raise ResumeError(Reason.MALFORMED)
            _, payload = parse(raw, self.profile, ACCEPT)
            t, np = self.ticket, payload[:32]
            expected = auth(self.profile, t.root, b"ACCEPT", t.rid, self.session_id, self.nc, np)
            if not hmac.compare_digest(expected, payload[32:]):
                raise ResumeError(Reason.BAD_AUTH)
            self.keys = SessionKeys(self.profile, t.root, t.rid, self.session_id, self.nc, np)
            self.state = "WAIT_FINISH_P"
            return encode(self.profile, FINISH_C, self.keys.finish(True))
        except BaseException:
            self.clear()
            raise

    def finish(self, raw):
        try:
            if self.state != "WAIT_FINISH_P":
                raise ResumeError(Reason.MALFORMED)
            _, payload = parse(raw, self.profile, FINISH_P)
            if not hmac.compare_digest(self.keys.finish(False), payload):
                raise ResumeError(Reason.BAD_AUTH)
            self.keys.clear_confirmation()
            self.ticket.used()
            self.state = "APP_SECURE"
        except BaseException:
            self.clear()
            raise

    def clear(self):
        if self.keys:
            self.keys.clear()
        self.session_id = self.nc = b""
        self.state = "CLOSED"


class PeripheralResume:
    """Explicit model: commit only after FINISH_P was successfully queued.

    A full replay cache refuses further INITs without destroying the ticket.
    No accepted nonce or session ID is evicted during the ticket lifetime.
    """
    def __init__(self, profile, ticket=None, *, clock=time.monotonic):
        self.profile, self.ticket, self.clock = profile, ticket, clock
        self.keys = None
        self.state = "IDLE"
        self.session_id = b""
        self.deadline = 0

    def init(self, raw, peer, *, l4=False, bonded=False):
        try:
            if self.state != "IDLE":
                raise ResumeError(Reason.REPLAY)
            _, payload = parse(raw, self.profile, INIT)
            if self.profile == V11 and not (l4 and bonded):
                raise ResumeError(Reason.L4_REQUIRED)
            if self.ticket is None:
                raise ResumeError(Reason.NO_TICKET)
            t = self.ticket
            t.check(self.profile, peer, self.clock())
            rid, sid, nc, tag = payload[:16], payload[16:32], payload[32:64], payload[64:]
            if not hmac.compare_digest(rid, t.rid) or not hmac.compare_digest(tag,
                    auth(self.profile, t.root, b"INIT", rid, sid, nc)):
                raise ResumeError(Reason.BAD_AUTH)
            if any(nc == old_nc or sid == old_sid for old_nc, old_sid in t.replay):
                raise ResumeError(Reason.REPLAY)
            if len(t.replay) >= REPLAY_CAPACITY:
                raise ResumeError(Reason.REPLAY_CACHE_FULL)
            t.replay.append((nc, sid))
            np = secrets.token_bytes(32)
            self.keys = SessionKeys(self.profile, t.root, rid, sid, nc, np)
            self.session_id = sid
            self.deadline = self.clock() + 30
            self.state = "WAIT_FINISH_C"
            return encode(self.profile, ACCEPT, np + auth(self.profile, t.root, b"ACCEPT", rid, sid, nc, np))
        except BaseException:
            self.disconnect()
            raise

    def finish(self, raw, *, l4=False, bonded=False):
        try:
            if self.profile == V11 and not (l4 and bonded):
                raise ResumeError(Reason.L4_REQUIRED)
            if self.state != "WAIT_FINISH_C" or self.clock() >= self.deadline:
                raise ResumeError(Reason.MALFORMED)
            self.ticket.check(self.profile, self.ticket.peer, self.clock())
            _, payload = parse(raw, self.profile, FINISH_C)
            if not hmac.compare_digest(payload, self.keys.finish(True)):
                raise ResumeError(Reason.BAD_AUTH)
            result = encode(self.profile, FINISH_P, self.keys.finish(False))
            self.state = "PENDING_SEND"
            return result
        except BaseException:
            self.disconnect()
            raise

    def commit(self):
        if self.state != "PENDING_SEND" or self.clock() >= self.deadline:
            self.disconnect()
            raise ResumeError(Reason.MALFORMED)
        self.keys.clear_confirmation()
        self.ticket.used()
        self.state = "APP_SECURE"

    def disconnect(self):
        if self.keys:
            self.keys.clear()
        self.keys = None
        self.session_id = b""
        self.state = "IDLE"
        self.deadline = 0
