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
"""

from dataclasses import dataclass
import hmac


PHASE6_TRAFFIC_KEY_SIZE = 32

PHASE6_C2P_LABEL = (
    b"PQ-BLE-TRAFFIC-v0.6/CENTRAL-TO-PERIPHERAL"
)

PHASE6_P2C_LABEL = (
    b"PQ-BLE-TRAFFIC-v0.6/PERIPHERAL-TO-CENTRAL"
)


@dataclass(frozen=True)
class Phase6TrafficKeys:
    """Independent AES-256 traffic keys for the two BLE directions."""

    central_to_peripheral: bytes
    peripheral_to_central: bytes


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