"""Bidirectional application-traffic primitives for protocol version 0.6.

Phase 6 does not modify the authenticated v0.5 handshake.

The v0.5 application key K_app is treated as an application root key and
expanded into two independent directional AES-256 traffic keys:

    K_c2p = HMAC-SHA256(
        K_app,
        b"PQ-BLE-TRAFFIC-v0.6/CENTRAL-TO-PERIPHERAL",
    )

    K_p2c = HMAC-SHA256(
        K_app,
        b"PQ-BLE-TRAFFIC-v0.6/PERIPHERAL-TO-CENTRAL",
    )

K_app itself is not used directly for application encryption in Phase 6.
Phase 6 also defines a small PQS6 control/status frame used for explicit
diagnostic/error responses. Successful v0.6 application traffic uses the
authenticated SecureChannel wire format in both directions."""

from dataclasses import dataclass
import hmac


PHASE6_TRAFFIC_KEY_SIZE = 32

PHASE6_C2P_LABEL = (
    b"PQ-BLE-TRAFFIC-v0.6/CENTRAL-TO-PERIPHERAL"
)

PHASE6_P2C_LABEL = (
    b"PQ-BLE-TRAFFIC-v0.6/PERIPHERAL-TO-CENTRAL"
)

PHASE6_FRAME_MAGIC = b"PQS6"
PHASE6_FRAME_VERSION = 0x06
PHASE6_FRAME_HEADER_SIZE = 8

PHASE6_C2P_ACK = 0x01
PHASE6_ERROR = 0x7F

# Firmware diagnostic/status values reused by Phase 6 negative tests.
PHASE6_STATUS_INVALID_PROTOCOL_STATE = 0x04
PHASE6_STATUS_AUTHENTICATION_FAILURE = 0x06

@dataclass(frozen=True)
class Phase6TrafficKeys:
    """Independent AES-256 traffic keys for the two BLE directions."""

    central_to_peripheral: bytes
    peripheral_to_central: bytes


@dataclass(frozen=True)
class Phase6Frame:
    """Parsed Phase 6 control/status frame."""

    subtype: int
    payload: bytes


def derive_phase6_traffic_keys(
    application_root_key: bytes,
) -> Phase6TrafficKeys:
    """Derive the two directional v0.6 traffic keys from v0.5 K_app."""

    if len(application_root_key) != PHASE6_TRAFFIC_KEY_SIZE:
        raise ValueError(
            "application root key must be exactly "
            f"{PHASE6_TRAFFIC_KEY_SIZE} bytes"
        )

    central_to_peripheral = hmac.digest(
        application_root_key,
        PHASE6_C2P_LABEL,
        "sha256",
    )

    peripheral_to_central = hmac.digest(
        application_root_key,
        PHASE6_P2C_LABEL,
        "sha256",
    )

    return Phase6TrafficKeys(
        central_to_peripheral=central_to_peripheral,
        peripheral_to_central=peripheral_to_central,
    )


def encode_phase6_frame(subtype: int, payload: bytes = b"") -> bytes:
    """Encode one versioned PQS6 control/status frame."""

    if not 0 <= subtype <= 0xFF:
        raise ValueError("Phase 6 subtype must fit in one byte")

    payload = bytes(payload)

    if len(payload) > 0xFFFF:
        raise ValueError("Phase 6 payload is too large")

    return (
        PHASE6_FRAME_MAGIC
        + bytes((PHASE6_FRAME_VERSION, subtype))
        + len(payload).to_bytes(2, "big")
        + payload
    )


def parse_phase6_frame(frame: bytes | bytearray) -> Phase6Frame:
    """Parse and strictly validate one PQS6 frame."""

    frame = bytes(frame)

    if len(frame) < PHASE6_FRAME_HEADER_SIZE:
        raise ValueError("Phase 6 frame is too short")

    if frame[:4] != PHASE6_FRAME_MAGIC:
        raise ValueError("Invalid Phase 6 frame magic")

    if frame[4] != PHASE6_FRAME_VERSION:
        raise ValueError("Unsupported Phase 6 frame version")

    declared_len = int.from_bytes(frame[6:8], "big")

    if len(frame) != PHASE6_FRAME_HEADER_SIZE + declared_len:
        raise ValueError("Phase 6 frame length mismatch")

    return Phase6Frame(
        subtype=frame[5],
        payload=frame[PHASE6_FRAME_HEADER_SIZE:],
    )