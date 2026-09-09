"""Protocol version 1.0: BLE SMP Security Mode 1 Level 4 + ML-KEM-768.

CP1 scope (SMP Level 4 foundation). This module defines:

- the versioned ``PQV1`` control framing (same 8-byte header shape as PQS7 so
  the v0.7/v1.0 GATT byte accounting stays comparable);
- the CP1 security attestation exchange ``SEC_QUERY`` / ``SEC_INFO``;
- the strict "authenticated Security Mode 1 Level 4" predicate that the
  Central applies to the DK-reported link state;
- the classification of GATT failures as *security* denials.

The v1.0 transcript domain and key schedule are reserved here but are not
used before CP3, exactly as required by the checkpoint plan.

Terminology: SMP Level 4 is classical (P-256). It authenticates and encrypts
the BLE link and is not post-quantum. Only the ML-KEM application key
establishment (CP2/CP3) is post-quantum.

Keep synchronized with ``firmware/src/pq_v1_frame.h``.
"""

from __future__ import annotations

from dataclasses import dataclass
import re

from bleak.exc import BleakError

try:  # Bleak >= 3.0 exposes the ATT protocol error code structurally.
    from bleak.exc import BleakGATTProtocolError
except ImportError:  # pragma: no cover - older Bleak
    BleakGATTProtocolError = None  # type: ignore[assignment,misc]


# ── Reserved v1.0 domain separation (CP3; not used in CP1) ───────────────
V1_DOMAIN = b"PQ-BLE-HANDSHAKE-v1.0/SMP-L4-MLKEM"
V1_SMP_CONTEXT = b"BLE-SMP-SM1-L4"
V1_KDF_INFO = V1_DOMAIN + b"/key-schedule"
V1_FINISHED_C_LABEL = V1_DOMAIN + b"/FINISHED/C"
V1_FINISHED_P_LABEL = V1_DOMAIN + b"/FINISHED/P"

# ── PQV1 framing ─────────────────────────────────────────────────────────
V1_FRAME_MAGIC = b"PQV1"
V1_FRAME_VERSION = 0x10
V1_FRAME_HEADER_SIZE = 8

V1_SEC_QUERY = 0x01
V1_SEC_INFO = 0x02
# Reserved for CP2/CP3; rejected by parse until implemented.
V1_START = 0x10
V1_READY = 0x11
V1_FINISHED_C = 0x12
V1_FINISHED_P = 0x13
V1_ERROR = 0x7F

V1_SEC_INFO_PAYLOAD_SIZE = 4
V1_SEC_QUERY_FRAME_SIZE = V1_FRAME_HEADER_SIZE
V1_SEC_INFO_FRAME_SIZE = V1_FRAME_HEADER_SIZE + V1_SEC_INFO_PAYLOAD_SIZE
V1_ERROR_FRAME_SIZE = V1_FRAME_HEADER_SIZE + 1

V1_SEC_FLAG_SC = 0x01
V1_SEC_FLAG_AUTHENTICATED = 0x02
V1_SEC_FLAG_GATE_OPEN = 0x04

V1_PROFILE_ID = 0x10

V1_STATUS_INSUFFICIENT_SECURITY = 0x10
V1_STATUS_LEGACY_CONTROL_REJECTED = 0x11
V1_STATUS_INVALID_STATE = 0x12
V1_STATUS_NOTIFICATIONS_DISABLED = 0x13
V1_STATUS_UNSUPPORTED_SUBTYPE = 0x14

V1_STATUS_NAMES = {
    V1_STATUS_INSUFFICIENT_SECURITY: "insufficient security",
    V1_STATUS_LEGACY_CONTROL_REJECTED: "legacy control rejected",
    V1_STATUS_INVALID_STATE: "invalid state",
    V1_STATUS_NOTIFICATIONS_DISABLED: "notifications disabled",
    V1_STATUS_UNSUPPORTED_SUBTYPE: "unsupported subtype",
}

# ── BLE security constants (Zephyr bt_security_t values) ─────────────────
BT_SECURITY_L1 = 1
BT_SECURITY_L2 = 2
BT_SECURITY_L3 = 3
BT_SECURITY_L4 = 4
L4_ENC_KEY_SIZE = 16

_PAYLOAD_SIZES = {
    V1_SEC_QUERY: 0,
    V1_SEC_INFO: V1_SEC_INFO_PAYLOAD_SIZE,
    V1_ERROR: 1,
}


@dataclass(frozen=True)
class V1Frame:
    """One strictly sized PQV1 frame."""

    subtype: int
    payload: bytes


@dataclass(frozen=True)
class V1SecurityInfo:
    """DK-reported BLE link security as carried by ``SEC_INFO``."""

    level: int
    secure_connections: bool
    authenticated: bool
    gate_open: bool
    enc_key_size: int
    profile: int

    def describe(self) -> str:
        return (
            f"level=L{self.level} SC={'YES' if self.secure_connections else 'NO'} "
            f"authenticated={'YES' if self.authenticated else 'NO'} "
            f"key={self.enc_key_size} gate={'OPEN' if self.gate_open else 'CLOSED'} "
            f"profile=0x{self.profile:02X}"
        )


def _validate_payload(subtype: int, payload: bytes) -> None:
    if subtype not in _PAYLOAD_SIZES:
        raise ValueError(f"unsupported PQV1 subtype: {subtype:#x}")
    expected = _PAYLOAD_SIZES[subtype]
    if len(payload) != expected:
        raise ValueError(
            f"PQV1 payload for subtype {subtype:#x} must be {expected} bytes, "
            f"got {len(payload)}"
        )


def encode_v1_frame(subtype: int, payload: bytes = b"") -> bytes:
    payload = bytes(payload)
    _validate_payload(subtype, payload)
    return (
        V1_FRAME_MAGIC
        + bytes((V1_FRAME_VERSION, subtype))
        + len(payload).to_bytes(2, "big")
        + payload
    )


def parse_v1_frame(data: bytes) -> V1Frame:
    data = bytes(data)
    if len(data) < V1_FRAME_HEADER_SIZE:
        raise ValueError("truncated PQV1 frame")
    if data[:4] != V1_FRAME_MAGIC:
        raise ValueError("incorrect PQV1 magic")
    if data[4] != V1_FRAME_VERSION:
        raise ValueError("incorrect PQV1 version")
    declared = int.from_bytes(data[6:8], "big")
    if len(data) != V1_FRAME_HEADER_SIZE + declared:
        raise ValueError("incorrect PQV1 payload length")
    frame = V1Frame(subtype=data[5], payload=data[8:])
    _validate_payload(frame.subtype, frame.payload)
    return frame


def encode_sec_query() -> bytes:
    return encode_v1_frame(V1_SEC_QUERY)


def encode_sec_info(info: V1SecurityInfo) -> bytes:
    """Encode a SEC_INFO frame (used by tests and mock peripherals)."""

    if not 0 <= info.level <= 0xFF or not 0 <= info.enc_key_size <= 0xFF:
        raise ValueError("SEC_INFO fields must be single bytes")
    flags = 0
    if info.secure_connections:
        flags |= V1_SEC_FLAG_SC
    if info.authenticated:
        flags |= V1_SEC_FLAG_AUTHENTICATED
    if info.gate_open:
        flags |= V1_SEC_FLAG_GATE_OPEN
    return encode_v1_frame(
        V1_SEC_INFO,
        bytes((info.level, flags, info.enc_key_size, info.profile & 0xFF)),
    )


def parse_sec_info(data: bytes) -> V1SecurityInfo:
    frame = parse_v1_frame(data)
    if frame.subtype != V1_SEC_INFO:
        raise ValueError("expected SEC_INFO")
    level, flags, key_size, profile = frame.payload
    return V1SecurityInfo(
        level=level,
        secure_connections=bool(flags & V1_SEC_FLAG_SC),
        authenticated=bool(flags & V1_SEC_FLAG_AUTHENTICATED),
        gate_open=bool(flags & V1_SEC_FLAG_GATE_OPEN),
        enc_key_size=key_size,
        profile=profile,
    )


def encode_v1_error(status: int) -> bytes:
    return encode_v1_frame(V1_ERROR, bytes((status,)))


def is_authenticated_level4(info: V1SecurityInfo) -> bool:
    """Strict v1.0 acceptance rule for the DK-reported link security.

    Level 2 (unauthenticated Secure Connections), Level 3, a key shorter than
    16 octets, a link without Secure Connections, a closed firmware gate or a
    foreign firmware profile are all rejected.
    """

    return (
        info.level == BT_SECURITY_L4
        and info.secure_connections
        and info.authenticated
        and info.gate_open
        and info.enc_key_size == L4_ENC_KEY_SIZE
        and info.profile == V1_PROFILE_ID
    )


# ── Security-denial classification of GATT failures ──────────────────────
#
# Before Level 4 the DK must answer every PQ GATT request with an ATT
# security error. Zephyr (subsys/bluetooth/host/gatt.c, bt_gatt_check_perm)
# returns Insufficient Authentication (0x05) when no key exists or the link
# is not authenticated/LESC, and Insufficient Encryption (0x0F) when a key
# exists but encryption is off. Windows/WinRT may surface the same condition
# as GattCommunicationStatus.AccessDenied ("Access Denied") or as an
# HRESULT-backed OSError. Everything else (busy, invalid length, unlikely,
# unreachable, disconnect) is NOT a security denial and must fail a test.

SECURITY_DENIAL_ATT_CODES = {
    0x05: "ATT Insufficient Authentication",
    0x08: "ATT Insufficient Authorization",
    0x0F: "ATT Insufficient Encryption",
}

_ATT_IN_MESSAGE = re.compile(
    r"\b(?:Protocol Error|ATT error:|error code) 0x([0-9a-f]{2})\b", re.IGNORECASE
)
_ACCESS_DENIED = re.compile(r"\bAccess Denied\b", re.IGNORECASE)
_WINRT_ATT_HRESULT_BASE = 0x80650000
_WINRT_E_ACCESSDENIED = 0x80070005


def classify_security_denial(exc: BaseException) -> str | None:
    """Return a reason when ``exc`` is a BLE *security* denial, else ``None``."""

    if BleakGATTProtocolError is not None and isinstance(exc, BleakGATTProtocolError):
        code = int(exc.code)
        return SECURITY_DENIAL_ATT_CODES.get(code)

    if isinstance(exc, BleakError):
        message = str(exc)
        match = _ATT_IN_MESSAGE.search(message)
        if match:
            return SECURITY_DENIAL_ATT_CODES.get(int(match[1], 16))
        if _ACCESS_DENIED.search(message):
            return "WinRT Access Denied (pairing/encryption required)"
        return None

    winerror = getattr(exc, "winerror", None)
    if isinstance(winerror, int):
        hresult = winerror & 0xFFFFFFFF
        if hresult == _WINRT_E_ACCESSDENIED:
            return "WinRT E_ACCESSDENIED"
        if hresult & 0xFFFF0000 == _WINRT_ATT_HRESULT_BASE:
            return SECURITY_DENIAL_ATT_CODES.get(hresult & 0xFF)
    return None
