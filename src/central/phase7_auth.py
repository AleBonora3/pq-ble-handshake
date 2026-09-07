"""v0.7 authenticated hybrid ML-KEM-768 + P-256 handshake."""

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from cryptography.exceptions import InvalidTag
import hmac
import inspect
import logging
import secrets

from ..common.ml_kem import encapsulate
from ..common.phase2_diagnostic import PHASE2_STATUS_NAMES
from ..common.phase7 import (
    PHASE7_ERROR,
    PHASE7_FRAME_MAGIC,
    PHASE7_MLKEM_CIPHERTEXT_SIZE,
    PHASE7_MLKEM_PUBLIC_KEY_SIZE,
    PHASE7_SESSION_ID_SIZE,
    PHASE7_SHARED_SECRET_SIZE,
    compute_phase7_finished_c,
    compute_phase7_finished_p,
    compute_phase7_sas,
    compute_phase7_transcript_hash,
    derive_p256_ecdh_shared_secret,
    derive_phase7_keys,
    encode_phase7_finished_c,
    encode_start7_auth,
    format_phase7_sas,
    generate_p256_private_key,
    parse_phase7_finished_p,
    parse_phase7_frame,
    parse_ready7_auth,
    serialize_p256_public_key,
    derive_phase7_traffic_keys,
)
from ..common.constants import (
    CENTRAL_ROLE,
    MSG_TYPE_DATA,
)
from ..common.session import SecureChannel

from .ble_client import BLECentralClient


logger = logging.getLogger(
    "pq-ble.central.phase7-auth"
)


SASCallback = Callable[
    [str],
    bool | Awaitable[bool],
]


class Phase7AuthError(RuntimeError):
    """Authenticated v0.7 hybrid handshake failed."""


@dataclass(frozen=True)
class Phase7AuthResult:
    sas: str
    rounds: int


async def _receive(
    notifications: asyncio.Queue[bytes],
    timeout: float,
    description: str,
) -> bytes:
    try:
        return await asyncio.wait_for(
            notifications.get(),
            timeout=timeout,
        )
    except asyncio.TimeoutError as exc:
        raise Phase7AuthError(
            f"Timed out waiting for {description}"
        ) from exc


async def _confirm_sas(
    sas: str,
    callback: SASCallback | None,
) -> bool:
    print()
    print(f"SAS on Central: {sas}")
    print(
        "Compare with the nRF54L15 serial output."
    )

    if callback is not None:
        result = callback(sas)

        if inspect.isawaitable(result):
            result = await result

        return bool(result)

    loop = asyncio.get_running_loop()

    answer = await loop.run_in_executor(
        None,
        lambda: input(
            "Do the values match? [y/N]: "
        ),
    )

    return answer.strip().lower() in {
        "y",
        "yes",
    }


def _check_error_frame(
    raw: bytes,
) -> None:
    if not raw.startswith(
        PHASE7_FRAME_MAGIC
    ):
        return

    frame = parse_phase7_frame(raw)

    if frame.subtype == PHASE7_ERROR:
        status = frame.payload[0]

        raise Phase7AuthError(
            "Peripheral PQS7 ERROR: "
            f"0x{status:02X} "
            f"({PHASE2_STATUS_NAMES.get(status, 'unknown status')})"
        )


async def run_phase7_authenticated_hybrid(
    client: BLECentralClient,
    *,
    sas_callback: SASCallback | None = None,
    notification_timeout: float = 10.0,
) -> Phase7AuthResult:

    if not client.is_connected:
        raise Phase7AuthError(
            "BLE client not connected"
        )

    notifications: asyncio.Queue[bytes] = (
        asyncio.Queue()
    )

    event_loop = asyncio.get_running_loop()

    def notification_handler(
        _sender: object,
        data: bytearray,
    ) -> None:
        event_loop.call_soon_threadsafe(
            notifications.put_nowait,
            bytes(data),
        )

    notify_started = False

    ss_mlkem = bytearray()
    ss_ecdh = bytearray()

    application_key = bytearray()
    finished_c = bytearray()
    expected_finished_p = bytearray()

    c2p_key_buffer = bytearray()
    p2c_key_buffer = bytearray()

    private_key = None
    keys = None
    traffic_keys = None

    c2p_channel = None
    p2c_channel = None

    try:
        await client.start_notify(
            notification_handler
        )

        notify_started = True

        public_key = bytes(
            await client.read_fragmented_public_key()
        )

        if (
            len(public_key) !=
            PHASE7_MLKEM_PUBLIC_KEY_SIZE
        ):
            raise Phase7AuthError(
                "ML-KEM public key has "
                "invalid size"
            )

        logger.info(
            "ML-KEM public key received: "
            "PASS (%d B)",
            len(public_key),
        )

        private_key = (
            generate_p256_private_key()
        )

        central_public_key = (
            serialize_p256_public_key(
                private_key
            )
        )

        logger.info(
            "Central P-256 public key: %d B",
            len(central_public_key),
        )

        ciphertext, shared_secret = (
            encapsulate(public_key)
        )

        ciphertext = bytes(ciphertext)

        ss_mlkem = bytearray(
            shared_secret
        )

        del shared_secret

        if (
            len(ciphertext) !=
            PHASE7_MLKEM_CIPHERTEXT_SIZE
        ):
            raise Phase7AuthError(
                "ML-KEM ciphertext has "
                "invalid size"
            )

        if (
            len(ss_mlkem) !=
            PHASE7_SHARED_SECRET_SIZE
        ):
            raise Phase7AuthError(
                "ML-KEM shared secret has "
                "invalid size"
            )

        logger.info(
            "ML-KEM encapsulation: PASS"
        )

        session_id = secrets.token_bytes(
            PHASE7_SESSION_ID_SIZE
        )

        start7 = encode_start7_auth(
            session_id,
            central_public_key,
        )

        await client.write_fragmented_ciphertext(
            ciphertext
        )

        logger.info(
            "ML-KEM ciphertext transport: PASS"
        )

        await client.send_control(
            start7
        )

        logger.info(
            "START7_AUTH written: %d B",
            len(start7),
        )

        raw_ready = await _receive(
            notifications,
            notification_timeout,
            "READY7_AUTH",
        )

        _check_error_frame(
            raw_ready
        )

        try:
            peripheral_public_key = (
                parse_ready7_auth(
                    raw_ready
                )
            )
        except ValueError as exc:
            raise Phase7AuthError(
                f"Invalid READY7_AUTH: {exc}"
            ) from exc

        logger.info(
            "Peripheral P-256 public key: %d B",
            len(peripheral_public_key),
        )

        ss_ecdh = bytearray(
            derive_p256_ecdh_shared_secret(
                private_key,
                peripheral_public_key,
            )
        )

        private_key = None

        logger.info(
            "P-256 ECDH: PASS"
        )

        transcript_hash = (
            compute_phase7_transcript_hash(
                session_id,
                public_key,
                ciphertext,
                central_public_key,
                peripheral_public_key,
            )
        )

        logger.info(
            "Canonical v0.7 transcript: PASS"
        )

        keys = derive_phase7_keys(
            bytes(ss_mlkem),
            bytes(ss_ecdh),
            transcript_hash,
        )

        ss_mlkem[:] = (
            b"\x00" *
            len(ss_mlkem)
        )

        ss_ecdh[:] = (
            b"\x00" *
            len(ss_ecdh)
        )

        application_key = bytearray(
            keys.application
        )

        finished_c = bytearray(
            compute_phase7_finished_c(
                keys.finished_c,
                transcript_hash,
            )
        )

        expected_finished_p = bytearray(
            compute_phase7_finished_p(
                keys.finished_p,
                transcript_hash,
            )
        )

        sas = format_phase7_sas(
            compute_phase7_sas(
                keys.sas,
                transcript_hash,
            )
        )

        keys = None

        logger.info(
            "Hybrid v0.7 key schedule: PASS"
        )

        if not await _confirm_sas(
            sas,
            sas_callback,
        ):
            raise Phase7AuthError(
                "SAS rejected; FINISHED_C "
                "was not sent"
            )

        await client.send_control(
            encode_phase7_finished_c(
                bytes(finished_c)
            )
        )

        finished_c[:] = (
            b"\x00" *
            len(finished_c)
        )

        logger.info(
            "Central FINISHED sent"
        )

        raw_finished = await _receive(
            notifications,
            notification_timeout,
            "FINISHED_P",
        )

        _check_error_frame(
            raw_finished
        )

        try:
            received_finished_p = (
                parse_phase7_finished_p(
                    raw_finished
                )
            )
        except ValueError as exc:
            raise Phase7AuthError(
                f"Invalid FINISHED_P: {exc}"
            ) from exc

        if not hmac.compare_digest(
            received_finished_p,
            expected_finished_p,
        ):
            raise Phase7AuthError(
                "Peripheral FINISHED "
                "verification failed"
            )

        expected_finished_p[:] = (
            b"\x00" *
            len(expected_finished_p)
        )

        logger.info(
            "Peripheral FINISHED "
            "verified: PASS"
        )

        logger.info(
            "Authenticated hybrid "
            "handshake: PASS"
        )

        # -------------------------------------------------
        # v0.7 authenticated application traffic
        # -------------------------------------------------
        #
        # FINISHED_P has been successfully verified.
        # Only now may the Central activate application
        # traffic derived from K_app.
        #
        traffic_keys = (
            derive_phase7_traffic_keys(
                bytes(application_key)
            )
        )

        c2p_key_buffer = bytearray(
            traffic_keys.central_to_peripheral
        )

        p2c_key_buffer = bytearray(
            traffic_keys.peripheral_to_central
        )

        traffic_keys = None

        # K_app is only a traffic-key root. It is never
        # used directly for AES-256-GCM application data.
        application_key[:] = (
            b"\x00" *
            len(application_key)
        )

        logger.info(
            "v0.7 directional traffic keys "
            "derived: PASS"
        )

        #
        # Two independent SecureChannel instances give us
        # independent sequence/replay spaces.
        #
        # c2p_channel:
        #   Central encrypts with K_c2p.
        #
        # p2c_channel:
        #   Central decrypts Peripheral traffic using K_p2c.
        #
        # role=CENTRAL_ROLE means decrypt() expects the
        # peer role PERIPHERAL_ROLE in the AAD.
        #
        c2p_channel = SecureChannel(
            bytes(c2p_key_buffer),
            session_id=session_id,
            role=CENTRAL_ROLE,
        )

        p2c_channel = SecureChannel(
            bytes(p2c_key_buffer),
            session_id=session_id,
            role=CENTRAL_ROLE,
        )

        #
        # Positive CP3 application test:
        #
        #   PING 0 -> PONG 0
        #   PING 1 -> PONG 1
        #   PING 2 -> PONG 2
        #
        rounds = 3

        for round_index in range(rounds):
            ping = (
                f"PING {round_index}"
                .encode("ascii")
            )

            expected_pong = (
                f"PONG {round_index}"
                .encode("ascii")
            )

            # ---------------------------------------------
            # Central -> Peripheral
            # ---------------------------------------------
            c2p_wire = c2p_channel.encrypt(
                ping,
                msg_type=MSG_TYPE_DATA,
            )

            c2p_sequence = int.from_bytes(
                c2p_wire[:8],
                "big",
            )

            if c2p_sequence != round_index:
                raise Phase7AuthError(
                    "Unexpected Phase 7 C->P "
                    "sequence: "
                    f"expected {round_index}, "
                    f"got {c2p_sequence}"
                )

            if len(c2p_wire) != 43:
                raise Phase7AuthError(
                    "Unexpected Phase 7 C->P "
                    "wire size: "
                    f"expected 43 B, "
                    f"got {len(c2p_wire)} B"
                )

            await client.write_secure_data(
                c2p_wire
            )

            logger.info(
                "Round %d C->P: seq=%d, "
                "plaintext=%s, wire=%d B",
                round_index,
                c2p_sequence,
                ping.decode("ascii"),
                len(c2p_wire),
            )

            # ---------------------------------------------
            # Peripheral -> Central
            # ---------------------------------------------
            raw_response = await _receive(
                notifications,
                notification_timeout,
                (
                    "Phase 7 P->C secure "
                    f"response for round "
                    f"{round_index}"
                ),
            )

            #
            # A PQS7 frame here means that the DK rejected
            # the application frame instead of returning
            # encrypted PONG data.
            #
            _check_error_frame(
                raw_response
            )

            if len(raw_response) != 43:
                raise Phase7AuthError(
                    "Unexpected Phase 7 P->C "
                    "wire size: "
                    f"expected 43 B, "
                    f"got {len(raw_response)} B"
                )

            p2c_sequence = int.from_bytes(
                raw_response[:8],
                "big",
            )

            if p2c_sequence != round_index:
                raise Phase7AuthError(
                    "Unexpected Phase 7 P->C "
                    "sequence: "
                    f"expected {round_index}, "
                    f"got {p2c_sequence}"
                )

            try:
                plaintext = (
                    p2c_channel.decrypt(
                        raw_response,
                        msg_type=MSG_TYPE_DATA,
                    )
                )
            except (
                InvalidTag,
                ValueError,
            ) as exc:
                raise Phase7AuthError(
                    "Phase 7 P->C "
                    "AES-256-GCM verification "
                    f"failed in round "
                    f"{round_index}: {exc}"
                ) from exc

            if plaintext != expected_pong:
                raise Phase7AuthError(
                    "Unexpected Phase 7 P->C "
                    "plaintext: "
                    f"expected "
                    f"{expected_pong!r}, "
                    f"got {plaintext!r}"
                )

            logger.info(
                "Round %d P->C: seq=%d, "
                "plaintext=%s, wire=%d B, "
                "AES-256-GCM: PASS",
                round_index,
                p2c_sequence,
                plaintext.decode("ascii"),
                len(raw_response),
            )

        logger.info(
            "Authenticated v0.7 "
            "bidirectional application "
            "traffic: PASS (%d rounds)",
            rounds,
        )

        return Phase7AuthResult(
            sas=sas,
            rounds=rounds,
        )

    finally:
        for sensitive in (
            ss_mlkem,
            ss_ecdh,
            application_key,
            finished_c,
            expected_finished_p,
            c2p_key_buffer,
            p2c_key_buffer,
        ):
            sensitive[:] = (
                b"\x00" *
                len(sensitive)
            )

        private_key = None
        keys = None
        traffic_keys = None
        c2p_channel = None
        p2c_channel = None

        if notify_started:
            try:
                await client.stop_notify()
            except Exception as exc:
                logger.warning(
                    "Could not stop Phase 7 "
                    "notifications: %s",
                    exc,
                )