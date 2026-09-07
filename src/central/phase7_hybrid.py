"""CP2 hybrid BLE key-agreement interoperability, without authentication."""

import asyncio
from dataclasses import dataclass
import hmac
import logging
import secrets

from ..common.phase2_diagnostic import PHASE2_STATUS_NAMES
from ..common.ml_kem import encapsulate
from ..common.phase7 import (
    PHASE7_ERROR,
    PHASE7_MLKEM_CIPHERTEXT_SIZE,
    PHASE7_MLKEM_PUBLIC_KEY_SIZE,
    PHASE7_READY7_CP2_FRAME_SIZE,
    PHASE7_SESSION_ID_SIZE,
    PHASE7_SHARED_SECRET_SIZE,
    compute_phase7_cp2_diagnostic,
    compute_phase7_transcript_hash,
    derive_p256_ecdh_shared_secret,
    derive_phase7_keys,
    encode_start7,
    generate_p256_private_key,
    parse_phase7_frame,
    parse_ready7_cp2,
    serialize_p256_public_key,
)
from .ble_client import BLECentralClient


logger = logging.getLogger("pq-ble.central.phase7")


class Phase7HybridError(RuntimeError):
    """The CP2 exchange or TEST-ONLY diagnostic comparison failed."""


@dataclass(frozen=True)
class Phase7HybridResult:
    """Successful comparison metadata; no session keys are retained."""

    response_size: int


async def run_phase7_hybrid_e2e(
    client: BLECentralClient,
    *,
    notification_timeout: float = 10.0,
) -> Phase7HybridResult:
    """Verify one diagnostic and unsubscribe; the CLI owns disconnection."""

    if not client.is_connected:
        raise Phase7HybridError("BLE client not connected")

    notifications: asyncio.Queue[bytes] = asyncio.Queue()
    event_loop = asyncio.get_running_loop()

    def notification_handler(_sender: object, data: bytearray) -> None:
        event_loop.call_soon_threadsafe(notifications.put_nowait, bytes(data))

    notify_started = False
    ss_mlkem = bytearray()
    ss_ecdh = bytearray()
    application_key = bytearray()
    expected_diagnostic = bytearray()
    private_key = None
    keys = None
    try:
        await client.start_notify(notification_handler)
        notify_started = True
        # ATT Write Request / Notification each reserve three bytes. CP2
        # requires a single 89-byte write and a single 105-byte notification.
        if client.mtu_size < PHASE7_READY7_CP2_FRAME_SIZE + 3:
            raise Phase7HybridError(
                f"CP2 requires negotiated ATT MTU >= 108; got {client.mtu_size}"
            )
        logger.info("CP2 TEST-ONLY interoperability; peer authentication is deferred")
        public_key = bytes(await client.read_fragmented_public_key())
        if len(public_key) != PHASE7_MLKEM_PUBLIC_KEY_SIZE:
            raise Phase7HybridError("ML-KEM public key must be 1184 bytes")
        logger.info("ML-KEM public key received: PASS (%d B)", len(public_key))

        private_key = generate_p256_private_key()
        central_public_key = serialize_p256_public_key(private_key)
        logger.info("Central P-256 public key: %d B", len(central_public_key))
        ciphertext, shared_secret = encapsulate(public_key)
        ss_mlkem = bytearray(shared_secret)
        del shared_secret
        ciphertext = bytes(ciphertext)
        if len(ciphertext) != PHASE7_MLKEM_CIPHERTEXT_SIZE:
            raise Phase7HybridError("ML-KEM ciphertext must be 1088 bytes")
        if len(ss_mlkem) != PHASE7_SHARED_SECRET_SIZE:
            raise Phase7HybridError("ML-KEM shared secret must be 32 bytes")
        logger.info("ML-KEM encapsulation: PASS")

        session_id = secrets.token_bytes(PHASE7_SESSION_ID_SIZE)
        start7 = encode_start7(session_id, central_public_key)
        await client.write_fragmented_ciphertext(ciphertext)
        logger.info("ML-KEM ciphertext transport: PASS (%d B)", len(ciphertext))
        await client.send_control(start7)
        logger.info("START7 written: %d B", len(start7))
        try:
            response = await asyncio.wait_for(
                notifications.get(), timeout=notification_timeout
            )
        except asyncio.TimeoutError as exc:
            raise Phase7HybridError(
                "Timed out waiting for READY7_CP2 or PQS7 ERROR"
            ) from exc

        frame = parse_phase7_frame(response)
        if frame.subtype == PHASE7_ERROR:
            status = frame.payload[0]
            raise Phase7HybridError(
                f"Peripheral PQS7 ERROR: 0x{status:02X} "
                f"({PHASE2_STATUS_NAMES.get(status, 'unknown status')})"
            )
        # Parsing validates the exact SEC1 shape and the curve point using CP1.
        peripheral_public_key, diagnostic = parse_ready7_cp2(response)
        logger.info("Peripheral P-256 public key: %d B", len(peripheral_public_key))
        ss_ecdh = bytearray(
            derive_p256_ecdh_shared_secret(private_key, peripheral_public_key)
        )
        private_key = None
        logger.info("P-256 ECDH: PASS")
        transcript_hash = compute_phase7_transcript_hash(
            session_id, public_key, ciphertext,
            central_public_key, peripheral_public_key,
        )
        logger.info("Canonical v0.7 transcript: PASS")
        keys = derive_phase7_keys(ss_mlkem, ss_ecdh, transcript_hash)
        application_key = bytearray(keys.application)
        # CP1 returns immutable bytes. Release all four outputs immediately;
        # Python/backend internal copies cannot be guaranteed to be erased.
        keys = None
        logger.info("Hybrid v0.7 key schedule: PASS")
        expected_diagnostic = bytearray(
            compute_phase7_cp2_diagnostic(application_key, transcript_hash)
        )
        if not hmac.compare_digest(diagnostic, expected_diagnostic):
            raise Phase7HybridError(
                "CP2 diagnostic proof: FAIL (hybrid key-agreement mismatch)"
            )
        logger.info("CP2 diagnostic proof: PASS")
        return Phase7HybridResult(response_size=len(response))
    except ValueError as exc:
        raise Phase7HybridError(str(exc)) from exc
    finally:
        for buffer in (ss_mlkem, ss_ecdh, application_key, expected_diagnostic):
            buffer[:] = b"\x00" * len(buffer)
        keys = None
        private_key = None
        if notify_started:
            try:
                await client.stop_notify()
            except Exception as exc:
                logger.warning("Could not stop Phase 7 notifications: %s", exc)
