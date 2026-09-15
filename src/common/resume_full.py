"""New full-handshake profiles, sharing existing framing and crypto helpers."""

import hashlib
import hmac

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from . import phase7 as hybrid, v1_smp_mlkem as v1
from .resumption import V08, V11, Ticket, domain, sized, lp
from .v1_cp3 import clear, expand, verify_data


def encode_full(profile, subtype, payload=b""):
    domain(profile)
    raw = (hybrid.encode_phase7_frame(subtype, payload) if profile == V08
           else v1.encode_v1_frame(subtype, payload))
    return raw[:4] + bytes((profile,)) + raw[5:]


def parse_full(profile, raw):
    domain(profile)
    if len(raw) < 8 or raw[4] != profile:
        raise ValueError("wrong full-handshake profile/version")
    baseline = 7 if profile == V08 else 16
    adapted = raw[:4] + bytes((baseline,)) + raw[5:]
    return hybrid.parse_phase7_frame(adapted) if profile == V08 else v1.parse_v1_frame(adapted)


def security_info(raw):
    frame = parse_full(V11, raw)
    if frame.subtype != v1.V1_SEC_INFO:
        raise ValueError("expected v1.1 SEC_INFO")
    level, flags, key_size, profile = frame.payload
    if (level, flags, key_size, profile) != (4, 7, 16, V11):
        raise ValueError("v1.1 requires authenticated SC L4, 16-byte key and open gate")
    return v1.V1SecurityInfo(level, True, True, True, key_size, profile)


class FullHandshake:
    """Application outputs and the ticket exist only after verifying FINISHED_P."""
    def __init__(self, profile):
        self.profile = profile
        domain(profile)
        self.state = "NEW"
        self.session_id = b""
        self.prk = self.th = self.confirm_c = self.confirm_p = bytearray()
        self.application = self.sas_key = self.app_c2p = self.app_p2c = bytearray()
        self.ticket = None

    def begin(self, ss, pk, ct, sid, *, ecdh=None, central_public=None, peripheral_public=None, sec=None):
        try:
            if self.state != "NEW":
                raise ValueError("full handshake already started")
            self.session_id = sized(sid, 16)
            sized(ss, 32)
            sized(pk, 1184)
            sized(ct, 1088)
            d = domain(self.profile)
            if self.profile == V08:
                # Reuse the validated canonical fields, replacing only the domain.
                baseline = hybrid.build_phase7_transcript(sid, pk, ct, central_public, peripheral_public)
                canonical = lp(d) + baseline[2+len(hybrid.PHASE7_DOMAIN):]
                ikm = bytearray(hybrid.build_hybrid_ikm(ss, ecdh))
            else:
                security_info(sec)
                canonical = d+b"/CP3-TRANSCRIPT"+sec+pk+ct+encode_full(self.profile, v1.V1_START_CP3, sid)
                ikm = bytearray(ss)
            self.th = bytearray(hashlib.sha256(canonical).digest())
            try:
                self.prk = bytearray(hmac.digest(self.th, ikm, "sha256"))
            finally:
                clear(ikm)
            if self.profile == V08:
                block = bytearray(HKDFExpand(algorithm=hashes.SHA256(), length=128,
                    info=d+b"/hybrid-key-schedule").derive(self.prk))
                try:
                    self.application, self.sas_key = bytearray(block[:32]), bytearray(block[32:64])
                    self.confirm_c, self.confirm_p = bytearray(block[64:96]), bytearray(block[96:])
                finally:
                    clear(block)
            else:
                self.confirm_c = expand(self.prk, d+b"/FINISHED-C", self.th)
                self.confirm_p = expand(self.prk, d+b"/FINISHED-P", self.th)
            self.state = "WAIT_AUTH"
        except BaseException:
            self.clear()
            raise

    def sas(self):
        if self.profile != V08 or self.state != "WAIT_AUTH":
            raise ValueError("SAS unavailable")
        mac = hmac.digest(self.sas_key, domain(self.profile)+b"/SAS"+self.th, "sha256")
        return f"{int.from_bytes(mac, 'big') % 1_000_000:06d}"

    def finish_c(self, *, authenticated):
        try:
            if self.state != "WAIT_AUTH" or not authenticated:
                raise ValueError("full handshake authentication required")
            hybrid_profile = self.profile == V08
            tag = verify_data(self.confirm_c, domain(self.profile)+
                (b"/FINISHED/C" if hybrid_profile else b"/VERIFY-C"), self.th)
            try:
                wire = encode_full(self.profile, hybrid.PHASE7_FINISHED_C if hybrid_profile else v1.V1_FINISHED_C, tag)
            finally:
                clear(tag)
            if not hybrid_profile:
                next_th = bytearray(hashlib.sha256(self.th+wire).digest())
                clear(self.th)
                self.th = next_th
            self.state = "WAIT_FINISHED_P"
            return wire
        except BaseException:
            self.clear()
            raise

    def finish_p(self, raw, peer, *, now=None):
        expected = bytearray()
        try:
            if self.state != "WAIT_FINISHED_P":
                raise ValueError("unexpected FINISHED_P")
            frame = parse_full(self.profile, raw)
            is_hybrid = self.profile == V08
            if frame.subtype != (hybrid.PHASE7_FINISHED_P if is_hybrid else v1.V1_FINISHED_P):
                raise ValueError("wrong FINISHED direction")
            d = domain(self.profile)
            expected = verify_data(self.confirm_p, d+(b"/FINISHED/P" if is_hybrid else b"/VERIFY-P"), self.th)
            if not hmac.compare_digest(expected, frame.payload):
                raise ValueError("FINISHED_P authentication failed")
            if is_hybrid:
                traffic = b"PQ-BLE-TRAFFIC-v0.8/"
                self.app_c2p = bytearray(hmac.digest(self.application, traffic+b"CENTRAL-TO-PERIPHERAL", "sha256"))
                self.app_p2c = bytearray(hmac.digest(self.application, traffic+b"PERIPHERAL-TO-CENTRAL", "sha256"))
            else:
                th2 = bytearray(hashlib.sha256(self.th+raw).digest())
                clear(self.th)
                self.th = th2
                self.app_c2p = expand(self.prk, d+b"/APP-C2P", self.th)
                self.app_p2c = expand(self.prk, d+b"/APP-P2C", self.th)
            self.ticket = Ticket.issue(self.profile, peer, self.prk, self.th, authenticated=True, now=now)
            self.clear_handshake()
            self.state = "APP_SECURE"
        except BaseException:
            self.clear()
            raise
        finally:
            clear(expected)

    def clear_handshake(self):
        for value in (self.prk, self.th, self.confirm_c, self.confirm_p, self.application, self.sas_key):
            clear(value)

    def clear(self):
        self.clear_handshake()
        clear(self.app_c2p)
        clear(self.app_p2c)
        self.session_id = b""
        self.state = "CLOSED"
