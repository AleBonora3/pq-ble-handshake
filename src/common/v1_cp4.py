"""CP4 framing and AES-256-GCM, independent of BLE and the CP3 key schedule."""

from dataclasses import dataclass, field
import hmac

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .v1_cp3 import clear
from .v1_smp_mlkem import V1_APP_C2P, V1_APP_P2C, encode_v1_frame, parse_v1_frame

APP_C2P, APP_P2C = V1_APP_C2P, V1_APP_P2C
PING, PONG = 0x01, 0x02
TAG_SIZE, IV_SIZE = 16, 12
CP4_MAX_PLAINTEXT = 128
FRAME_OVERHEAD = 35
CHALLENGE_SIZE = 16
UINT64_MAX = (1 << 64) - 1
CP4_AAD_LABEL = b"PQ-BLE-HANDSHAKE-v1.0/CP4-AAD"
IV_LABELS = {APP_C2P: b"PQ-BLE-HANDSHAKE-v1.0/IV-C2P",
             APP_P2C: b"PQ-BLE-HANDSHAKE-v1.0/IV-P2C"}


def _direction(subtype):
    if subtype not in IV_LABELS:
        raise ValueError("invalid CP4 direction")


def _sequence(seq):
    if not isinstance(seq, int) or isinstance(seq, bool) or not 0 <= seq <= UINT64_MAX:
        raise ValueError("CP4 sequence outside uint64")


def validate_sequence(received, expected):
    _sequence(received)
    _sequence(expected)
    # Reserve the terminal value: every accepted transaction needs a next counter.
    if expected == UINT64_MAX or received != expected:
        raise ValueError("CP4 replay, out-of-order sequence or sequence exhaustion")


def derive_iv_base(key, session_id, subtype):
    _direction(subtype)
    if len(key) != 32 or len(session_id) != 16:
        raise ValueError("invalid CP4 key/session size")
    return bytearray(hmac.digest(key, IV_LABELS[subtype] + session_id + b"\x01", "sha256")[:IV_SIZE])


def nonce_for_sequence(iv_base, seq):
    _sequence(seq)
    if len(iv_base) != IV_SIZE:
        raise ValueError("CP4 IV must be 12 bytes")
    encoded = bytes(4) + seq.to_bytes(8, "big")
    return bytes(a ^ b for a, b in zip(iv_base, encoded))


def _prefix(subtype, seq, msg_type, plaintext_len):
    _direction(subtype)
    _sequence(seq)
    if not 0 <= msg_type <= 255 or not 0 <= plaintext_len <= CP4_MAX_PLAINTEXT:
        raise ValueError("invalid CP4 message type/length")
    return seq.to_bytes(8, "big") + bytes([msg_type]) + plaintext_len.to_bytes(2, "big")


def encode_application_frame(subtype, seq, msg_type, ciphertext, tag):
    if len(tag) != TAG_SIZE:
        raise ValueError("CP4 tag must be 16 bytes")
    prefix = _prefix(subtype, seq, msg_type, len(ciphertext))
    return encode_v1_frame(subtype, prefix + ciphertext + tag)


@dataclass(frozen=True)
class ApplicationFrame:
    subtype: int
    seq: int
    msg_type: int
    ciphertext: bytes = field(repr=False)
    tag: bytes = field(repr=False)


def parse_application_frame(raw, expected_subtype):
    _direction(expected_subtype)
    frame = parse_v1_frame(raw)
    if frame.subtype != expected_subtype:
        raise ValueError("wrong CP4 direction")
    payload = frame.payload
    size = int.from_bytes(payload[9:11], "big")
    if size > CP4_MAX_PLAINTEXT or len(payload) != 27 + size:
        raise ValueError("inconsistent CP4 plaintext length/tag")
    return ApplicationFrame(frame.subtype, int.from_bytes(payload[:8], "big"),
                            payload[8], payload[11:-TAG_SIZE], payload[-TAG_SIZE:])


def build_aad(session_id, exact_header, seq, msg_type, plaintext_len):
    if len(session_id) != 16 or len(exact_header) != 8:
        raise ValueError("invalid CP4 AAD session/header size")
    prefix = _prefix(exact_header[5], seq, msg_type, plaintext_len)
    expected = b"PQV1\x10" + bytes([exact_header[5]]) + (27 + plaintext_len).to_bytes(2, "big")
    if exact_header != expected:
        raise ValueError("inconsistent CP4 AAD header")
    return CP4_AAD_LABEL + session_id + exact_header + prefix


def encrypt_application(key, iv_base, session_id, subtype, seq, msg_type, plaintext):
    if len(key) != 32:
        raise ValueError("CP4 requires AES-256")
    skeleton = encode_application_frame(subtype, seq, msg_type, bytes(len(plaintext)), bytes(TAG_SIZE))
    aad = build_aad(session_id, skeleton[:8], seq, msg_type, len(plaintext))
    sealed = AESGCM(key).encrypt(nonce_for_sequence(iv_base, seq), bytes(plaintext), aad)
    return skeleton[:19] + sealed


def decrypt_application(key, iv_base, session_id, raw, expected_subtype, expected_seq):
    if len(key) != 32:
        raise ValueError("CP4 requires AES-256")
    frame = parse_application_frame(raw, expected_subtype)
    validate_sequence(frame.seq, expected_seq)
    aad = build_aad(session_id, raw[:8], frame.seq, frame.msg_type, len(frame.ciphertext))
    # AESGCM raises on authentication failure; unauthenticated plaintext never escapes.
    plaintext = bytearray(AESGCM(key).decrypt(nonce_for_sequence(iv_base, frame.seq),
                                           frame.ciphertext + frame.tag, aad))
    expected_type = PING if expected_subtype == APP_C2P else PONG
    if frame.msg_type != expected_type or len(plaintext) != CHALLENGE_SIZE:
        clear(plaintext)
        raise ValueError("invalid CP4 PING/PONG semantics")
    return plaintext


class CentralApplication:
    """Borrows CP3's owned key buffers; clearing either owner erases the keys.

    Python/cryptography cannot guarantee erasure of internal immutable copies.
    """

    def __init__(self, handshake):
        self.handshake = handshake
        self.iv_c2p, self.iv_p2c = bytearray(), bytearray()
        self.tx_c2p = self.rx_p2c = 0
        try:
            self.require_secure()
            self.iv_c2p = derive_iv_base(handshake.app_c2p, handshake.session_id, APP_C2P)
            self.iv_p2c = derive_iv_base(handshake.app_p2c, handshake.session_id, APP_P2C)
        except BaseException:
            self.clear()
            raise

    def require_secure(self):
        if self.handshake.state != "APP_SECURE":
            raise ValueError("CP4 requires APP_SECURE")

    def encrypt_ping(self, challenge, mtu):
        try:
            self.require_secure()
            validate_sequence(self.tx_c2p, self.tx_c2p)
            if len(challenge) != CHALLENGE_SIZE or FRAME_OVERHEAD + len(challenge) + 3 > mtu:
                raise ValueError("CP4 challenge/ATT MTU invalid")
            frame = encrypt_application(self.handshake.app_c2p, self.iv_c2p,
                self.handshake.session_id, APP_C2P, self.tx_c2p, PING, challenge)
            self.tx_c2p += 1  # Consume before transport; send failure must clear this session.
            return frame
        except BaseException:
            self.clear()
            raise

    def accept_pong(self, raw, challenge, mtu):
        plaintext = bytearray()
        try:
            self.require_secure()
            if len(raw) + 3 > mtu:
                raise ValueError("CP4 frame exceeds ATT MTU")
            plaintext = decrypt_application(self.handshake.app_p2c, self.iv_p2c,
                self.handshake.session_id, raw, APP_P2C, self.rx_p2c)
            if not hmac.compare_digest(plaintext, challenge):
                raise ValueError("CP4 PONG challenge mismatch")
            self.rx_p2c += 1
        except BaseException:
            self.clear()
            raise
        finally:
            clear(plaintext)

    def clear(self):
        self.handshake.clear()
        clear(self.iv_c2p)
        clear(self.iv_p2c)
