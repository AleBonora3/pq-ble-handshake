"""v0.7 authenticated hybrid ML-KEM-768 + P-256 handshake."""

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from bleak.exc import (
    BleakError,
    BleakGATTProtocolError,
)
from cryptography.exceptions import InvalidTag
import hmac
import inspect
import logging
import re
import secrets
import time

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


PHASE7_NEGATIVE_MODES = (
    "sas-reject", "finished-c", "pre-auth", "c2p-tamper", "c2p-replay",
    "p2c-tamper", "p2c-replay",
)


class Phase7NegativeTestPassed(RuntimeError):
    """Expected TEST-ONLY rejection; never an authenticated result."""


def _tamper_last_bit(wire: bytes) -> bytes:
    """TEST-ONLY: change one bit of a FINISHED value or final GCM-tag byte."""
    if not wire:
        raise ValueError("Cannot tamper an empty value")
    return wire[:-1] + bytes((wire[-1] ^ 1,))


def _require_error_status(raw: bytes, expected: int) -> None:
    """Require the exact existing PQS7 error, not silence or arbitrary failure."""
    try:
        frame = parse_phase7_frame(raw)
    except ValueError as exc:
        raise Phase7AuthError("CP4 expected a well-formed PQS7 ERROR") from exc
    if frame.subtype != PHASE7_ERROR or frame.payload != bytes((expected,)):
        raise Phase7AuthError(f"CP4 expected PQS7 ERROR 0x{expected:02X}")
    logger.info("CP4 expected rejection: PQS7 ERROR 0x%02X", expected)


async def _require_quiet(client, notifications, timeout: float) -> None:
    """Bounded extra-notification check after explicit rejection/valid traffic."""
    try:
        await asyncio.wait_for(notifications.get(), timeout=timeout)
    except asyncio.TimeoutError:
        if not client.is_connected:
            raise Phase7AuthError("CP4 connection lost during observation")
        return
    raise Phase7AuthError("CP4 unexpected extra notification (FINISHED/data/duplicate)")


def _preauth_probe(application_key: bytes, session_id: bytes) -> bytes:
    """TEST-ONLY valid seq=0 probe; does not activate the Central app channel."""
    keys = derive_phase7_traffic_keys(application_key)
    return SecureChannel(
        keys.central_to_peripheral, session_id=session_id, role=CENTRAL_ROLE,
    ).encrypt(b"PING 0", msg_type=MSG_TYPE_DATA)


async def _require_preauth_rejection(client, wire, notifications, timeout):
    try:
        await client.write_secure_data(wire)
    except (BleakError, OSError) as exc:
        message = str(exc)
        logger.info("CP4 Secure Data write failure: %s: %s", type(exc).__name__, message)
        if not client.is_connected or isinstance(exc, (TimeoutError, ConnectionError)):
            raise Phase7AuthError("CP4 write failed due to timeout/disconnection") from exc

        # WinRT can map a denied ATT write to Access Denied or a native
        # HRESULT-backed OSError. Recognize denial outcomes, not every BLE/OS
        # failure: busy, invalid handles/lengths, unreachable and unknown
        # failures must still fail the test, even if is_connected is stale.
        denied_att_codes = (0x03, 0x05, 0x08, 0x0F, 0xFC)
        if isinstance(
            exc,
            BleakGATTProtocolError,
        ):
            # Bleak 3.x exposes ATT/GATT failures through a
            # structured exception with the protocol code.
            gatt_code = int(exc.code)

            logger.info(
                "CP4 GATT protocol rejection code: "
                "0x%02X",
                gatt_code,
            )

            rejected = (
                gatt_code in
                denied_att_codes
            )

        elif isinstance(
            exc,
            BleakError,
        ):
            # Compatibility with older/backend-specific
            # Bleak error representations.
            att_error = re.search(
                r"\b(?:Protocol Error|ATT error:) "
                r"0x([0-9a-f]{2})\b",
                message,
                re.IGNORECASE,
            )

            rejected = (
                int(
                    att_error[1],
                    16,
                ) in denied_att_codes
                if att_error
                else re.fullmatch(
                    r"Could not write value\b.*"
                    r": Access Denied",
                    message,
                    re.DOTALL |
                    re.IGNORECASE,
                ) is not None
            )

        else:
            # Compatibility with native WinRT HRESULT
            # failures exposed as OSError.
            winerror = getattr(
                exc,
                "winerror",
                None,
            )

            rejected = (
                isinstance(
                    winerror,
                    int,
                )
                and (
                    winerror &
                    0xFFFFFFFF
                )
                in (
                    0x80070005,
                    *(
                        0x80650000 |
                        code
                        for code
                        in denied_att_codes
                    ),
                )
            )
        if not rejected:
            raise Phase7AuthError("CP4 write failure is not a recognized BLE write rejection") from exc
    else:
        raise Phase7AuthError("CP4 Peripheral accepted pre-auth Secure Data")
    await _require_quiet(client, notifications, timeout)
    logger.info("CP4 rejected Secure Data write observed; no unexpected notification")


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

    try:
        frame = parse_phase7_frame(raw)
    except ValueError as exc:
        raise Phase7AuthError(f"Invalid PQS7 response: {exc}") from exc

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
    negative_test: str | None = None,
) -> Phase7AuthResult:

    if negative_test not in (None, *PHASE7_NEGATIVE_MODES):
        raise Phase7AuthError(f"Unknown Phase 7 negative test: {negative_test}")
    if notification_timeout <= 0:
        raise Phase7AuthError("notification_timeout must be positive")
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
    preauth_wire = None
    negative_checked = False
    quiet_timeout = min(notification_timeout, 1.0)
    handshake_started = time.perf_counter()

    if negative_test is not None:
        print(f"CP4 TEST-ONLY negative mode: {negative_test}")
        print(f"Extra-notification observation window: {quiet_timeout:g} s")
    if negative_test == "sas-reject" and sas_callback is None:
        sas_callback = lambda _sas: False

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

        if negative_test in {"sas-reject", "finished-c", "pre-auth"}:
            preauth_wire = _preauth_probe(bytes(application_key), session_id)
        if negative_test == "pre-auth":
            await _require_preauth_rejection(
                client, preauth_wire, notifications, quiet_timeout,
            )
            negative_checked = True

        if not await _confirm_sas(
            sas,
            sas_callback,
        ):
            if negative_test == "sas-reject":
                await _require_preauth_rejection(
                    client, preauth_wire, notifications, quiet_timeout,
                )
                raise Phase7NegativeTestPassed(
                    "SAS rejected; FINISHED_C not sent; Secure Data blocked"
                )
            raise Phase7AuthError(
                "SAS rejected; FINISHED_C "
                "was not sent"
            )

        if negative_test == "sas-reject":
            raise Phase7AuthError("CP4 sas-reject requires SAS rejection")
        if negative_test == "finished-c":
            finished_c[:] = _tamper_last_bit(bytes(finished_c))
            logger.info("CP4 TEST-ONLY: flipped exactly one FINISHED_C bit")

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

        if negative_test == "finished-c":
            _require_error_status(raw_finished, 0x06)
            await _require_preauth_rejection(
                client, preauth_wire, notifications, quiet_timeout,
            )
            raise Phase7NegativeTestPassed(
                "tampered FINISHED_C rejected; FINISHED_P not accepted; Secure Data blocked"
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
        logger.info(
            "Phase 7 measurement: handshake %.3f ms (includes SAS confirmation%s)",
            (time.perf_counter() - handshake_started) * 1000,
            "; includes pre-auth probe/observation" if negative_test == "pre-auth" else "",
        )
        application_started = time.perf_counter()

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

            if round_index == 0 and negative_test == "pre-auth":
                # The fresh channel has consumed seq=0; retry the exact probe
                # from WAIT_FINISHED_C using that same sequence and IV/tag.
                c2p_wire = preauth_wire

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

            if round_index == 0 and negative_test == "c2p-tamper":
                await client.write_secure_data(_tamper_last_bit(c2p_wire))
                _require_error_status(await _receive(
                    notifications, notification_timeout, "C->P tag rejection",
                ), 0x06)
                await _require_quiet(client, notifications, quiet_timeout)
                logger.info("CP4 C->P tag rejected; retrying original seq=0 wire")
                negative_checked = True

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

            if round_index == 0 and negative_test == "p2c-tamper":
                logger.info("CP4 TEST-ONLY: tampering received P->C copy locally")
                before = p2c_channel.recv_count
                try:
                    p2c_channel.decrypt(_tamper_last_bit(raw_response), msg_type=MSG_TYPE_DATA)
                except InvalidTag:
                    pass
                else:
                    raise Phase7AuthError("CP4 Central accepted tampered P->C tag")
                if p2c_channel.recv_count != before:
                    raise Phase7AuthError("CP4 P->C tag failure advanced receive count")
                negative_checked = True

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

            if round_index == 0 and negative_test == "c2p-replay":
                await client.write_secure_data(c2p_wire)
                _require_error_status(await _receive(
                    notifications, notification_timeout, "C->P replay rejection",
                ), 0x04)
                await _require_quiet(client, notifications, quiet_timeout)
                logger.info("CP4 exact C->P replay rejected; no duplicate PONG")
                negative_checked = True

            if round_index == 0 and negative_test == "p2c-replay":
                logger.info("CP4 TEST-ONLY: replaying received P->C wire locally")
                before = p2c_channel.recv_count
                try:
                    p2c_channel.decrypt(raw_response, msg_type=MSG_TYPE_DATA)
                except ValueError as exc:
                    if not str(exc).startswith("Replay or out-of-order"):
                        raise Phase7AuthError("CP4 expected P->C replay rejection") from exc
                except InvalidTag as exc:
                    raise Phase7AuthError("CP4 P->C replay reached tag verification") from exc
                else:
                    raise Phase7AuthError("CP4 Central accepted P->C replay")
                if p2c_channel.recv_count != before:
                    raise Phase7AuthError("CP4 P->C replay advanced receive count")
                negative_checked = True

        logger.info(
            "Phase 7 measurement: application %.3f ms (%d valid round trips%s)",
            (time.perf_counter() - application_started) * 1000, rounds,
            "; includes TEST-ONLY injections/observation" if negative_test else "",
        )
        if negative_test is not None:
            if not negative_checked:
                raise Phase7AuthError("CP4 negative mode reached positive result")
            await _require_quiet(client, notifications, quiet_timeout)
            raise Phase7NegativeTestPassed(
                f"{negative_test}: expected rejection and PING/PONG 0/1/2 verified"
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
                if negative_test is not None:
                    raise Phase7AuthError("CP4 notification cleanup failed") from exc
                logger.warning(
                    "Could not stop Phase 7 "
                    "notifications: %s",
                    exc,
                )
