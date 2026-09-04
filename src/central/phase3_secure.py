"""Central-side Phase 3 PQ secure-channel hardware experiment.

This path performs:

    liboqs ML-KEM-768 encapsulation
        -> BLE ciphertext transport
        -> mlkem-native decapsulation on nRF54L15
        -> HKDF-SHA256 on both endpoints
        -> AES-256-GCM Peripheral -> Central
        -> authenticated plaintext recovery

It deliberately bypasses the legacy SAS/session-resumption flow.
"""

import asyncio
from dataclasses import dataclass
import logging

from cryptography.exceptions import InvalidTag

from ..common.constants import (
    CENTRAL_ROLE,
    CT_SIZE,
    MSG_TYPE_DATA,
    PK_SIZE,
    SECURE_CHANNEL_OVERHEAD,
    SESSION_ID_SIZE,
    SS_SIZE,
)
from ..common.ml_kem import encapsulate
from ..common.session import (
    SecureChannel,
    derive_session_key,
    generate_session_id,
)
from .ble_client import BLECentralClient


logger = logging.getLogger("pq-ble.central.phase3")

PHASE3_START_MAGIC = b"START3"
PHASE3_EXPECTED_PLAINTEXT = b"PQ-BLE SECURE CHANNEL"

PHASE3_EXPECTED_WIRE_SIZE = (
    len(PHASE3_EXPECTED_PLAINTEXT) + SECURE_CHANNEL_OVERHEAD
)


class Phase3SecureError(RuntimeError):
    """Raised when the Phase 3 secure-channel experiment fails."""


@dataclass(frozen=True)
class Phase3SecureResult:
    """Successful Phase 3 result; no key material is retained."""

    plaintext: bytes
    wire_size: int


async def run_phase3_secure(
    client: BLECentralClient,
    *,
    notification_timeout: float = 10.0,
    negative_test: str | None = None,
) -> Phase3SecureResult:
    """Run the isolated Phase 3 hardware secure-channel experiment."""

    if not client.is_connected:
        raise Phase3SecureError("BLE client not connected")

    notifications: asyncio.Queue[bytes] = asyncio.Queue()
    event_loop = asyncio.get_running_loop()

    def _notification_handler(_sender, data: bytearray) -> None:
        event_loop.call_soon_threadsafe(
            notifications.put_nowait,
            bytes(data),
        )

    notify_started = False

    try:
        # Subscribe before START3 so the fast peripheral response cannot
        # race notification setup.
        await client.start_notify(_notification_handler)
        notify_started = True

        # ------------------------------------------------------------
        # 1. Read dynamic ML-KEM public key from the DK
        # ------------------------------------------------------------
        public_key = bytes(
            await client.read_fragmented_public_key()
        )

        if len(public_key) != PK_SIZE:
            raise Phase3SecureError(
                f"Public key size mismatch: expected {PK_SIZE}, "
                f"got {len(public_key)}"
            )

        logger.info(
            "Dynamic ML-KEM-768 public key received: %d bytes",
            len(public_key),
        )

        # ------------------------------------------------------------
        # 2. liboqs ML-KEM encapsulation
        # ------------------------------------------------------------
        ciphertext, shared_secret = encapsulate(public_key)

        ciphertext = bytes(ciphertext)
        shared_secret = bytes(shared_secret)

        if len(ciphertext) != CT_SIZE:
            raise Phase3SecureError(
                f"Ciphertext size mismatch: expected {CT_SIZE}, "
                f"got {len(ciphertext)}"
            )

        if len(shared_secret) != SS_SIZE:
            raise Phase3SecureError(
                f"Shared-secret size mismatch: expected {SS_SIZE}, "
                f"got {len(shared_secret)}"
            )

        logger.info("liboqs ML-KEM-768 encapsulation: PASS")
        logger.info("Ciphertext size: %d bytes", len(ciphertext))

        # ------------------------------------------------------------
        # 3. Generate fresh session context
        # ------------------------------------------------------------
        session_id = generate_session_id()

        if len(session_id) != SESSION_ID_SIZE:
            raise Phase3SecureError(
                f"Session ID size mismatch: expected {SESSION_ID_SIZE}, "
                f"got {len(session_id)}"
            )

        logger.info(
            "Fresh Phase 3 session_id generated: %d bytes",
            len(session_id),
        )

        # ------------------------------------------------------------
        # 4. Derive exactly the same session key expected on the DK
        # ------------------------------------------------------------
        session_key = derive_session_key(shared_secret)

        logger.info("Central HKDF-SHA256 session-key derivation: PASS")

        # Central role means decrypt() expects PERIPHERAL_ROLE in AAD.
        secure_channel = SecureChannel(
            session_key,
            session_id=session_id,
            role=CENTRAL_ROLE,
        )

        negative_channel = None

        if negative_test == "tamper":
            # Same key and same AAD context.
            # Only the received authenticated message will be modified.
            negative_channel = SecureChannel(
                session_key,
                session_id=session_id,
                role=CENTRAL_ROLE,
            )

        elif negative_test == "aad":
            wrong_session_id = bytearray(session_id)
            wrong_session_id[0] ^= 0x01

            negative_channel = SecureChannel(
                session_key,
                session_id=bytes(wrong_session_id),
                role=CENTRAL_ROLE,
            )

        elif negative_test == "replay":
            # Replay is tested after the valid message has first been accepted.
            pass

        elif negative_test is not None:
            raise Phase3SecureError(
                f"Unknown Phase 3 negative test: {negative_test}"
            )

        # Do not log key material.
        del shared_secret
        del session_key

        # ------------------------------------------------------------
        # 5. Existing BLE ciphertext transport
        # ------------------------------------------------------------
        await client.write_fragmented_ciphertext(ciphertext)

        # ------------------------------------------------------------
        # 6. START3 || session_id
        # ------------------------------------------------------------
        control_message = PHASE3_START_MAGIC + session_id

        expected_control_len = (
            len(PHASE3_START_MAGIC) + SESSION_ID_SIZE
        )

        if len(control_message) != expected_control_len:
            raise Phase3SecureError(
                "Internal START3 control-message size error"
            )

        logger.info(
            "Sending START3 secure-channel command: %d bytes",
            len(control_message),
        )

        await client.send_control(control_message)

        # ------------------------------------------------------------
        # 7. Wait for encrypted Secure Data notification
        # ------------------------------------------------------------
        try:
            raw_notification = await asyncio.wait_for(
                notifications.get(),
                timeout=notification_timeout,
            )
        except asyncio.TimeoutError as exc:
            raise Phase3SecureError(
                "Timed out waiting for Phase 3 encrypted notification "
                f"({notification_timeout:g} s)"
            ) from exc

        logger.info(
            "Encrypted notification received: %d bytes",
            len(raw_notification),
        )

        # Firmware may return a PQM2 diagnostic if Phase 3 crypto failed.
        if (
            len(raw_notification) == 9
            and raw_notification[:4] == b"PQM2"
        ):
            status = raw_notification[4]
            raise Phase3SecureError(
                "Peripheral returned PQM2 failure diagnostic instead "
                f"of encrypted Phase 3 data: status 0x{status:02X}"
            )

        if len(raw_notification) != PHASE3_EXPECTED_WIRE_SIZE:
            raise Phase3SecureError(
                "Unexpected Phase 3 secure-wire size: expected "
                f"{PHASE3_EXPECTED_WIRE_SIZE}, "
                f"got {len(raw_notification)}"
            )

        # ------------------------------------------------------------
        # 8. AES-256-GCM authentication + decryption
        # ------------------------------------------------------------
        # ------------------------------------------------------------
        # Optional Phase 3 negative tests
        # ------------------------------------------------------------

        if negative_test == "tamper":
            tampered = bytearray(raw_notification)

            # The final 16 bytes are the AES-GCM authentication tag.
            # Flip exactly one bit of the final tag byte.
            tampered[-1] ^= 0x01

            logger.info(
                "NEGATIVE TEST: flipped one bit in the AES-GCM tag"
            )

            try:
                negative_channel.decrypt(
                    bytes(tampered),
                    msg_type=MSG_TYPE_DATA,
                )
            except InvalidTag:
                logger.info(
                    "NEGATIVE TEST PASS: tampered AES-GCM message rejected"
                )
            else:
                raise Phase3SecureError(
                    "NEGATIVE TEST FAIL: tampered AES-GCM message "
                    "was accepted"
                )


        elif negative_test == "aad":
            logger.info(
                "NEGATIVE TEST: decrypting with modified session_id AAD"
            )

            try:
                negative_channel.decrypt(
                    raw_notification,
                    msg_type=MSG_TYPE_DATA,
                )
            except InvalidTag:
                logger.info(
                    "NEGATIVE TEST PASS: wrong session AAD rejected"
                )
            else:
                raise Phase3SecureError(
                    "NEGATIVE TEST FAIL: message authenticated with "
                    "the wrong session_id"
                )
        try:
            plaintext = secure_channel.decrypt(
                raw_notification,
                msg_type=MSG_TYPE_DATA,
            )
        except InvalidTag as exc:
            raise Phase3SecureError(
                "AES-256-GCM authentication failed: invalid tag. "
                "The endpoints did not agree on key/AAD/session context "
                "or the notification was modified."
            ) from exc
        except ValueError as exc:
            raise Phase3SecureError(
                f"Secure-channel wire validation failed: {exc}"
            ) from exc

        logger.info("AES-256-GCM authentication: PASS")

        if plaintext != PHASE3_EXPECTED_PLAINTEXT:
            raise Phase3SecureError(
                "Authenticated plaintext mismatch: expected "
                f"{PHASE3_EXPECTED_PLAINTEXT!r}, got {plaintext!r}"
            )

        if negative_test == "replay":
            logger.info(
                "NEGATIVE TEST: replaying already accepted secure frame"
            )

            try:
                secure_channel.decrypt(
                    raw_notification,
                    msg_type=MSG_TYPE_DATA,
                )
            except ValueError as exc:
                if "Replay or out-of-order" not in str(exc):
                    raise Phase3SecureError(
                        "NEGATIVE TEST FAIL: replay was rejected for an "
                        f"unexpected reason: {exc}"
                    ) from exc

                logger.info(
                    "NEGATIVE TEST PASS: replayed secure frame rejected"
                )
            else:
                raise Phase3SecureError(
                    "NEGATIVE TEST FAIL: replayed secure frame was accepted"
                )
            
        logger.info(
            "Authenticated plaintext recovered: %s",
            plaintext.decode("ascii"),
        )

        return Phase3SecureResult(
            plaintext=plaintext,
            wire_size=len(raw_notification),
        )

    finally:
        if notify_started:
            try:
                await client.stop_notify()
            except Exception as exc:
                logger.warning(
                    "Could not stop Phase 3 notifications: %s",
                    exc,
                )