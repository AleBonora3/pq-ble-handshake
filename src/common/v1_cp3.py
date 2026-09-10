"""v1 CP3 transcript and ML-KEM-only key confirmation. No application traffic.

Owned mutable secrets are erased on completion/failure. Python, liboqs and
hashlib/hmac do not guarantee erasure of internal or immutable copies.
"""

import hashlib
import hmac

from .constants import PK_SIZE, CT_SIZE
from .v1_smp_mlkem import (
    V1_START_CP3, V1_READY_CP3, V1_FINISHED_C, V1_FINISHED_P,
    encode_v1_frame, parse_v1_frame, parse_sec_info, encode_sec_info,
    is_authenticated_level4,
)

CP3_TRANSCRIPT_LABEL = b"PQ-BLE-HANDSHAKE-v1.0/CP3-TRANSCRIPT"
FINISHED_C_LABEL = b"PQ-BLE-HANDSHAKE-v1.0/FINISHED-C"
FINISHED_P_LABEL = b"PQ-BLE-HANDSHAKE-v1.0/FINISHED-P"
VERIFY_C_LABEL = b"PQ-BLE-HANDSHAKE-v1.0/VERIFY-C"
VERIFY_P_LABEL = b"PQ-BLE-HANDSHAKE-v1.0/VERIFY-P"
APP_C2P_LABEL = b"PQ-BLE-HANDSHAKE-v1.0/APP-C2P"
APP_P2C_LABEL = b"PQ-BLE-HANDSHAKE-v1.0/APP-P2C"


def clear(buffer: bytearray) -> None:
    buffer[:] = b"\x00" * len(buffer)


def build_transcript(sec_info: bytes, pk: bytes, ct: bytes, start: bytes) -> bytes:
    info = parse_sec_info(sec_info)
    if encode_sec_info(info) != sec_info:
        raise ValueError("noncanonical SEC_INFO")
    if len(pk) != PK_SIZE or len(ct) != CT_SIZE:
        raise ValueError("invalid ML-KEM transcript input size")
    if parse_v1_frame(start).subtype != V1_START_CP3:
        raise ValueError("expected START_CP3")
    return CP3_TRANSCRIPT_LABEL + sec_info + pk + ct + start


def transcript_hash(sec_info: bytes, pk: bytes, ct: bytes, start: bytes) -> bytearray:
    return bytearray(hashlib.sha256(build_transcript(sec_info, pk, ct, start)).digest())


def extract(th0: bytearray, ss_mlkem: bytearray) -> bytearray:
    if len(th0) != 32 or len(ss_mlkem) != 32:
        raise ValueError("HKDF-Extract requires 32-byte TH0 and SS_MLKEM")
    return bytearray(hmac.digest(th0, ss_mlkem, "sha256"))


def expand(prk: bytearray, label: bytes, th: bytearray) -> bytearray:
    """RFC 5869 HKDF-Expand, exactly one SHA-256 block (L = 32)."""
    if len(prk) != 32 or len(th) != 32:
        raise ValueError("HKDF-Expand requires 32-byte PRK and transcript hash")
    return bytearray(hmac.digest(prk, label + th + b"\x01", "sha256"))


def verify_data(key: bytearray, label: bytes, th: bytearray) -> bytearray:
    if len(key) != 32 or len(th) != 32:
        raise ValueError("invalid FINISHED input size")
    return bytearray(hmac.digest(key, label + th, "sha256"))


def chain(th: bytearray, frame: bytes) -> bytearray:
    if len(th) != 32 or parse_v1_frame(frame).subtype not in (V1_FINISHED_C, V1_FINISHED_P):
        raise ValueError("invalid transcript chaining input")
    return bytearray(hashlib.sha256(th + frame).digest())


class CentralHandshake:
    """Connection owner must call clear on disconnect, timeout or downgrade.

    Application keys exist only after accepting FINISHED_P. There is no
    repr exposing keys and no AES/nonce API at this checkpoint.
    """

    def __init__(self):
        self.state = "NEW"
        self.th = bytearray()
        self.prk = bytearray()
        self.finished_c = bytearray()
        self.finished_p = bytearray()
        self.app_c2p = bytearray()
        self.app_p2c = bytearray()
        self.session_id = b""

    def begin(self, ss_mlkem, sec_info, pk, ct, start):
        try:
            if self.state != "NEW" or not is_authenticated_level4(parse_sec_info(sec_info)):
                raise ValueError("CP3 requires a new transaction on strict L4")
            self.th = transcript_hash(sec_info, pk, ct, start)
            self.session_id = parse_v1_frame(start).payload
            self.prk = extract(self.th, ss_mlkem)
            self.finished_c = expand(self.prk, FINISHED_C_LABEL, self.th)
            self.finished_p = expand(self.prk, FINISHED_P_LABEL, self.th)
            self.state = "WAIT_READY_CP3"
        except BaseException:
            self.clear()
            raise

    def accept_ready(self, raw):
        tag = bytearray()
        try:
            frame = parse_v1_frame(raw)
            if (self.state != "WAIT_READY_CP3" or frame.subtype != V1_READY_CP3
                    or not hmac.compare_digest(self.th, frame.payload)):
                raise ValueError("READY_CP3 transcript mismatch or invalid state")
            tag = verify_data(self.finished_c, VERIFY_C_LABEL, self.th)
            finished = encode_v1_frame(V1_FINISHED_C, tag)
            next_hash = chain(self.th, finished)
            clear(self.th)
            self.th = next_hash
            self.state = "WAIT_FINISHED_P"
            return finished
        except BaseException:
            self.clear()
            raise
        finally:
            clear(tag)

    def accept_finished_p(self, raw):
        expected = bytearray()
        try:
            frame = parse_v1_frame(raw)
            if self.state != "WAIT_FINISHED_P" or frame.subtype != V1_FINISHED_P:
                raise ValueError("unexpected FINISHED direction/state")
            expected = verify_data(self.finished_p, VERIFY_P_LABEL, self.th)
            if not hmac.compare_digest(expected, frame.payload):
                raise ValueError("FINISHED_P verification failed")
            th2 = chain(self.th, raw)
            clear(self.th)
            self.th = th2
            self.app_c2p = expand(self.prk, APP_C2P_LABEL, self.th)
            self.app_p2c = expand(self.prk, APP_P2C_LABEL, self.th)
            self.clear_handshake()
            self.state = "APP_SECURE"
        except BaseException:
            self.clear()
            raise
        finally:
            clear(expected)

    def clear_handshake(self):
        for buffer in (self.prk, self.finished_c, self.finished_p, self.th):
            clear(buffer)

    def clear(self):
        self.clear_handshake()
        clear(self.app_c2p)
        clear(self.app_p2c)
        self.session_id = b""
        self.state = "CLOSED"
