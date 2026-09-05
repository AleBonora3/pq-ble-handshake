"""Pure-PQ authenticated handshake primitives for protocol version 0.5.

The canonical transcript is six ordered, unsigned-16-bit-big-endian
length-prefixed fields:

    domain, Central role, Peripheral role, session_id, ML-KEM public key,
    ML-KEM ciphertext

All functions in this module operate on binary protocol values. Logging and
display formatting are intentionally kept outside the transcript.
"""

from dataclasses import dataclass
from enum import Enum, auto
import hashlib
import hmac

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .constants import (
    CENTRAL_ROLE,
    CT_SIZE,
    FINISHED_SIZE,
    PHASE5_DOMAIN,
    PHASE5_FINISHED_C_LABEL,
    PHASE5_FINISHED_C,
    PHASE5_FINISHED_P_LABEL,
    PHASE5_FINISHED_P,
    PHASE5_DATA_REQUEST,
    PHASE5_ERROR,
    PHASE5_FRAME_HEADER_SIZE,
    PHASE5_FRAME_MAGIC,
    PHASE5_FRAME_VERSION,
    PHASE5_KDF_INFO,
    PHASE5_KEY_BLOCK_SIZE,
    PHASE5_KEY_SIZE,
    PHASE5_READY_FOR_SAS,
    PHASE5_SAS_LABEL,
    PHASE5_START_MAGIC,
    PERIPHERAL_ROLE,
    PK_SIZE,
    SAS_DIGITS,
    SAS_MODULUS,
    SESSION_ID_SIZE,
    SS_SIZE,
    TRANSCRIPT_HASH_SIZE,
)


@dataclass(frozen=True)
class Phase5Keys:
    """The four independent 32-byte outputs of the v0.5 key schedule."""

    application: bytes
    sas: bytes
    finished_c: bytes
    finished_p: bytes


@dataclass(frozen=True)
class Phase5Frame:
    """A strictly parsed v0.5 handshake frame."""

    subtype: int
    payload: bytes


class Phase5CentralState(Enum):
    """Central-side authenticated handshake state."""

    EMPTY = auto()
    WAIT_READY_FOR_SAS = auto()
    WAIT_SAS_CONFIRM = auto()
    WAIT_FINISHED_P = auto()
    AUTHENTICATED = auto()
    WAIT_APPLICATION_DATA = auto()
    COMPLETE = auto()
    ABORTED = auto()


class Phase5StateError(RuntimeError):
    """Raised for a duplicate or out-of-order Phase 5 event."""


def _require_size(name: str, value: bytes, expected: int) -> bytes:
    value = bytes(value)
    if len(value) != expected:
        raise ValueError(
            f"{name} must be {expected} bytes, got {len(value)}"
        )
    return value


def _length_prefixed(value: bytes) -> bytes:
    if len(value) > 0xFFFF:
        raise ValueError("transcript field exceeds the u16 length limit")
    return len(value).to_bytes(2, "big") + value


def build_phase5_transcript(
    session_id: bytes,
    public_key: bytes,
    ciphertext: bytes,
) -> bytes:
    """Serialize the canonical v0.5 transcript."""

    session_id = _require_size("session_id", session_id, SESSION_ID_SIZE)
    public_key = _require_size("public_key", public_key, PK_SIZE)
    ciphertext = _require_size("ciphertext", ciphertext, CT_SIZE)

    fields = (
        PHASE5_DOMAIN,
        CENTRAL_ROLE,
        PERIPHERAL_ROLE,
        session_id,
        public_key,
        ciphertext,
    )
    return b"".join(_length_prefixed(field) for field in fields)


def compute_phase5_transcript_hash(
    session_id: bytes,
    public_key: bytes,
    ciphertext: bytes,
) -> bytes:
    """Return SHA-256(canonical_transcript)."""

    return hashlib.sha256(
        build_phase5_transcript(session_id, public_key, ciphertext)
    ).digest()


def derive_phase5_keys(
    shared_secret: bytes,
    transcript_hash: bytes,
) -> Phase5Keys:
    """Derive and split the exact 128-byte v0.5 HKDF key block."""

    shared_secret = _require_size("shared_secret", shared_secret, SS_SIZE)
    transcript_hash = _require_size(
        "transcript_hash", transcript_hash, TRANSCRIPT_HASH_SIZE
    )
    key_block = bytearray(
        HKDF(
            algorithm=hashes.SHA256(),
            length=PHASE5_KEY_BLOCK_SIZE,
            salt=transcript_hash,
            info=PHASE5_KDF_INFO,
        ).derive(shared_secret)
    )
    try:
        return Phase5Keys(
            application=bytes(key_block[0:PHASE5_KEY_SIZE]),
            sas=bytes(key_block[PHASE5_KEY_SIZE:2 * PHASE5_KEY_SIZE]),
            finished_c=bytes(
                key_block[2 * PHASE5_KEY_SIZE:3 * PHASE5_KEY_SIZE]
            ),
            finished_p=bytes(
                key_block[3 * PHASE5_KEY_SIZE:4 * PHASE5_KEY_SIZE]
            ),
        )
    finally:
        key_block[:] = b"\x00" * len(key_block)


def compute_phase5_sas(sas_key: bytes, transcript_hash: bytes) -> int:
    """Compute the six-digit SAS using the full HMAC as a big-endian integer."""

    sas_key = _require_size("sas_key", sas_key, PHASE5_KEY_SIZE)
    transcript_hash = _require_size(
        "transcript_hash", transcript_hash, TRANSCRIPT_HASH_SIZE
    )
    sas_mac = hmac.digest(
        sas_key,
        PHASE5_SAS_LABEL + transcript_hash,
        "sha256",
    )
    return int.from_bytes(sas_mac, "big") % SAS_MODULUS


def format_phase5_sas(sas: int) -> str:
    """Render a valid Numeric Comparison value as exactly six digits."""

    if not 0 <= sas < SAS_MODULUS:
        raise ValueError(f"SAS must be in [0, {SAS_MODULUS - 1}]")
    return f"{sas:0{SAS_DIGITS}d}"


def _compute_finished(
    finished_key: bytes,
    label: bytes,
    transcript_hash: bytes,
) -> bytes:
    finished_key = _require_size(
        "finished_key", finished_key, PHASE5_KEY_SIZE
    )
    transcript_hash = _require_size(
        "transcript_hash", transcript_hash, TRANSCRIPT_HASH_SIZE
    )
    result = hmac.digest(
        finished_key,
        label + transcript_hash,
        "sha256",
    )
    if len(result) != FINISHED_SIZE:
        raise RuntimeError("unexpected HMAC-SHA256 output size")
    return result


def compute_finished_c(finished_key: bytes, transcript_hash: bytes) -> bytes:
    """Compute the full 32-byte Central FINISHED value."""

    return _compute_finished(
        finished_key,
        PHASE5_FINISHED_C_LABEL,
        transcript_hash,
    )


def compute_finished_p(finished_key: bytes, transcript_hash: bytes) -> bytes:
    """Compute the full 32-byte Peripheral FINISHED value."""

    return _compute_finished(
        finished_key,
        PHASE5_FINISHED_P_LABEL,
        transcript_hash,
    )


def verify_finished(expected: bytes, received: bytes) -> bool:
    """Compare two full FINISHED values in constant time."""

    if len(expected) != FINISHED_SIZE or len(received) != FINISHED_SIZE:
        return False
    return hmac.compare_digest(expected, received)


def build_start5(session_id: bytes) -> bytes:
    """Build ``START5 || session_id`` (exactly 22 bytes)."""

    session_id = _require_size("session_id", session_id, SESSION_ID_SIZE)
    return PHASE5_START_MAGIC + session_id


def encode_phase5_frame(subtype: int, payload: bytes = b"") -> bytes:
    """Encode ``PQS5 || version || subtype || payload_len_be16 || payload``."""

    if not 0 <= subtype <= 0xFF:
        raise ValueError("Phase 5 subtype must fit in one byte")
    payload = bytes(payload)
    if len(payload) > 0xFFFF:
        raise ValueError("Phase 5 payload exceeds the u16 length limit")
    return (
        PHASE5_FRAME_MAGIC
        + bytes((PHASE5_FRAME_VERSION, subtype))
        + len(payload).to_bytes(2, "big")
        + payload
    )


def parse_phase5_frame(data: bytes) -> Phase5Frame:
    """Strictly parse one complete Phase 5 frame."""

    data = bytes(data)
    if len(data) < PHASE5_FRAME_HEADER_SIZE:
        raise ValueError("Phase 5 frame is shorter than its header")
    if data[:4] != PHASE5_FRAME_MAGIC:
        raise ValueError("invalid Phase 5 frame magic")
    if data[4] != PHASE5_FRAME_VERSION:
        raise ValueError("unsupported Phase 5 frame version")
    payload_len = int.from_bytes(data[6:8], "big")
    if len(data) != PHASE5_FRAME_HEADER_SIZE + payload_len:
        raise ValueError("Phase 5 frame payload length mismatch")
    return Phase5Frame(subtype=data[5], payload=data[8:])


class Phase5CentralStateMachine:
    """Enforce the Central ordering independently from BLE timing."""

    def __init__(self) -> None:
        self.state = Phase5CentralState.EMPTY

    def start(self, session_id: bytes) -> bytes:
        self._require(Phase5CentralState.EMPTY)
        self.state = Phase5CentralState.WAIT_READY_FOR_SAS
        return build_start5(session_id)

    def receive_ready_for_sas(self, frame: Phase5Frame) -> None:
        self._require(Phase5CentralState.WAIT_READY_FOR_SAS)
        if frame.subtype != PHASE5_READY_FOR_SAS or frame.payload:
            raise Phase5StateError("expected empty READY_FOR_SAS frame")
        self.state = Phase5CentralState.WAIT_SAS_CONFIRM

    def reject_sas(self) -> None:
        self._require(Phase5CentralState.WAIT_SAS_CONFIRM)
        self.state = Phase5CentralState.ABORTED

    def confirm_sas(self, finished_c: bytes) -> bytes:
        self._require(Phase5CentralState.WAIT_SAS_CONFIRM)
        finished_c = _require_size(
            "FINISHED_C", finished_c, FINISHED_SIZE
        )
        self.state = Phase5CentralState.WAIT_FINISHED_P
        return encode_phase5_frame(PHASE5_FINISHED_C, finished_c)

    def receive_finished_p(
        self,
        frame: Phase5Frame,
        expected_finished_p: bytes,
    ) -> None:
        self._require(Phase5CentralState.WAIT_FINISHED_P)
        if frame.subtype == PHASE5_ERROR:
            code = frame.payload[0] if len(frame.payload) == 1 else None
            suffix = f" 0x{code:02x}" if code is not None else ""
            raise Phase5StateError(f"Peripheral Phase 5 error{suffix}")
        if frame.subtype != PHASE5_FINISHED_P:
            raise Phase5StateError("expected FINISHED_P frame")
        if not verify_finished(expected_finished_p, frame.payload):
            self.state = Phase5CentralState.ABORTED
            raise Phase5StateError("Peripheral FINISHED verification failed")
        self.state = Phase5CentralState.AUTHENTICATED

    def request_application_data(self) -> bytes:
        self._require(Phase5CentralState.AUTHENTICATED)
        self.state = Phase5CentralState.WAIT_APPLICATION_DATA
        return encode_phase5_frame(PHASE5_DATA_REQUEST)

    def complete_application_data(self) -> None:
        self._require(Phase5CentralState.WAIT_APPLICATION_DATA)
        self.state = Phase5CentralState.COMPLETE

    def _require(self, expected: Phase5CentralState) -> None:
        if self.state is not expected:
            raise Phase5StateError(
                f"Phase 5 event invalid in state {self.state.name}; "
                f"expected {expected.name}"
            )
