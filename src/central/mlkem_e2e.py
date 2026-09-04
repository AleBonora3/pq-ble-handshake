"""Central-side Phase 2 ML-KEM-768 interoperability experiment.

This path deliberately performs only ML-KEM encapsulation and the existing
BLE ciphertext transport. It does not use session resumption, SAS, HKDF, AES,
or session persistence.

The received CRC is a TEST-ONLY shared-secret diagnostic checksum. It is not
authentication, not a KDF, not cryptographic key confirmation, and not part
of the final protocol.
"""

import asyncio
from dataclasses import dataclass
import logging

from ..common.constants import CT_SIZE, PK_SIZE, SS_SIZE
from ..common.ml_kem import encapsulate
from ..common.phase2_diagnostic import (
    PHASE2_STATUS_NAMES,
    PHASE2_STATUS_SUCCESS,
    parse_phase2_diagnostic,
    shared_secret_diagnostic_checksum,
)
from .ble_client import BLECentralClient


logger = logging.getLogger("pq-ble.central.phase2")


class Phase2E2EError(RuntimeError):
    """Raised when the Phase 2 interoperability experiment fails."""


@dataclass(frozen=True)
class Phase2E2EResult:
    """Successful Phase 2 result; no shared-secret bytes are retained."""

    central_checksum: int
    peripheral_checksum: int

    @property
    def matches(self) -> bool:
        return self.central_checksum == self.peripheral_checksum


async def run_phase2_e2e(
    client: BLECentralClient,
    *,
    notification_timeout: float = 10.0,
) -> Phase2E2EResult:
    """Run the intentionally minimal Phase 2 BLE interoperability flow."""
    if not client.is_connected:
        raise Phase2E2EError("BLE client not connected")

    notifications: asyncio.Queue[bytes] = asyncio.Queue()
    event_loop = asyncio.get_running_loop()

    def _notification_handler(_sender, data: bytearray) -> None:
        event_loop.call_soon_threadsafe(notifications.put_nowait, bytes(data))

    notify_started = False
    try:
        # Subscribe before starting the exchange so the fast DK response cannot
        # race notification setup.
        await client.start_notify(_notification_handler)
        notify_started = True

        public_key = bytes(await client.read_fragmented_public_key())
        if len(public_key) != PK_SIZE:
            raise Phase2E2EError(
                f"Public key size mismatch: expected {PK_SIZE}, "
                f"got {len(public_key)}"
            )

        ciphertext, shared_secret = encapsulate(public_key)
        ciphertext = bytes(ciphertext)
        shared_secret = bytes(shared_secret)
        if len(ciphertext) != CT_SIZE:
            raise Phase2E2EError(
                f"Ciphertext size mismatch: expected {CT_SIZE}, "
                f"got {len(ciphertext)}"
            )
        if len(shared_secret) != SS_SIZE:
            raise Phase2E2EError(
                f"Shared secret size mismatch: expected {SS_SIZE}, "
                f"got {len(shared_secret)}"
            )

        central_checksum = shared_secret_diagnostic_checksum(shared_secret)
        logger.info(
            "Central TEST-ONLY shared-secret diagnostic checksum: 0x%08X",
            central_checksum,
        )
        logger.info(
            "The TEST-ONLY shared-secret diagnostic checksum is not "
            "authentication, a KDF, cryptographic key confirmation, or part "
            "of the final protocol."
        )

        await client.write_fragmented_ciphertext(ciphertext)
        await client.send_control(b"START")

        try:
            raw_result = await asyncio.wait_for(
                notifications.get(), timeout=notification_timeout
            )
        except asyncio.TimeoutError as exc:
            raise Phase2E2EError(
                "Timed out waiting for the exact nine-byte PQM2 diagnostic "
                f"result ({notification_timeout:g} s)"
            ) from exc

        try:
            diagnostic = parse_phase2_diagnostic(raw_result)
        except ValueError as exc:
            raise Phase2E2EError(str(exc)) from exc

        if diagnostic.status != PHASE2_STATUS_SUCCESS:
            status_name = PHASE2_STATUS_NAMES.get(
                diagnostic.status, "unknown status"
            )
            raise Phase2E2EError(
                "Peripheral returned non-success PQM2 status "
                f"0x{diagnostic.status:02X} ({status_name})"
            )

        logger.info(
            "Peripheral TEST-ONLY shared-secret diagnostic checksum: 0x%08X",
            diagnostic.checksum,
        )
        result = Phase2E2EResult(
            central_checksum=central_checksum,
            peripheral_checksum=diagnostic.checksum,
        )
        if not result.matches:
            raise Phase2E2EError(
                "ML-KEM E2E shared-secret mismatch: Central TEST-ONLY "
                "shared-secret diagnostic checksum "
                f"0x{central_checksum:08X} != Peripheral TEST-ONLY "
                "shared-secret diagnostic checksum "
                f"0x{diagnostic.checksum:08X}"
            )

        return result
    finally:
        if notify_started:
            try:
                await client.stop_notify()
            except Exception as exc:  # Notification teardown is best effort.
                logger.warning("Could not stop Phase 2 notifications: %s", exc)
