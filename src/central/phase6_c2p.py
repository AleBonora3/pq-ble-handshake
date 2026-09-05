"""v0.6 authenticated bidirectional application traffic and negative tests."""

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
import hashlib
import inspect
import logging
from cryptography.exceptions import InvalidTag

from ..common.constants import (
    CENTRAL_ROLE,
    CT_SIZE,
    FINISHED_SIZE,
    MSG_TYPE_DATA,
    PHASE5_ERROR,
    PHASE5_FINISHED_P,
    PK_SIZE,
    SESSION_ID_SIZE,
    SS_SIZE,
)
from ..common.ml_kem import encapsulate
from ..common.phase5 import (
    Phase5CentralStateMachine,
    Phase5StateError,
    compute_finished_c,
    compute_finished_p,
    compute_phase5_sas,
    compute_phase5_transcript_hash,
    derive_phase5_keys,
    format_phase5_sas,
    parse_phase5_frame,
)
from ..common.phase6 import (
    PHASE6_ERROR,
    PHASE6_FRAME_MAGIC,
    PHASE6_STATUS_AUTHENTICATION_FAILURE,
    PHASE6_STATUS_INVALID_PROTOCOL_STATE,
    derive_phase6_traffic_keys,
    parse_phase6_frame,
)

from ..common.session import SecureChannel, generate_session_id
from .ble_client import BLECentralClient


logger = logging.getLogger("pq-ble.central.phase6")

PHASE6_DEFAULT_ROUNDS = 3

PHASE6_NEGATIVE_MODES = (
    "c2p-tamper",
    "c2p-replay",
    "p2c-tamper",
    "p2c-replay",
    "pre-auth",
)

SASCallback = Callable[[str], bool | Awaitable[bool]]


class Phase6BidirectionalError(RuntimeError):
    """Raised when authenticated v0.6 bidirectional traffic fails."""

class Phase6NegativeTestPassed(RuntimeError):
    """Raised internally when the expected negative-test rejection occurs."""


class Phase6NegativeTestFailed(Phase6BidirectionalError):
    """Raised when deliberately invalid Phase 6 traffic is accepted."""

# Backward-compatible name for the CP2 helper/CLI.
Phase6C2PError = Phase6BidirectionalError


@dataclass(frozen=True)
class Phase6RoundTripResult:
    """One authenticated application-data round trip."""

    c2p_plaintext: bytes
    p2c_plaintext: bytes

    c2p_sequence: int
    p2c_sequence: int

    c2p_wire_size: int
    p2c_wire_size: int


@dataclass(frozen=True)
class Phase6BidirectionalResult:
    """Successful v0.6 authenticated bidirectional exchange."""

    round_trips: tuple[Phase6RoundTripResult, ...]
    sas: str

def _tamper_secure_wire_copy(
    wire: bytes | bytearray,
) -> bytes:
    """Flip exactly one bit in the final GCM-tag byte."""

    if len(wire) < 1:
        raise ValueError(
            "secure wire cannot be empty"
        )

    tampered = bytearray(wire)
    tampered[-1] ^= 0x01

    return bytes(tampered)

async def _confirm_sas(
    sas: str,
    callback: SASCallback | None,
) -> bool:
    print()
    print(f"SAS on Central: {sas}")
    print("Compare with the nRF54L15 serial output.")

    if callback is not None:
        result = callback(sas)

        if inspect.isawaitable(result):
            result = await result

        return bool(result)

    loop = asyncio.get_running_loop()

    answer = await loop.run_in_executor(
        None,
        lambda: input("Do the values match? [y/N]: "),
    )

    return answer.strip().lower() in {"y", "yes"}


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
        raise Phase6C2PError(
            f"Timed out waiting for {description} "
            f"({timeout:g} s)"
        ) from exc

def _parse_phase6_error_status(
    raw: bytes,
) -> int | None:
    """Return the one-byte PQS6 error status, or None if not an error."""

    if not raw.startswith(
        PHASE6_FRAME_MAGIC
    ):
        return None

    try:
        frame = parse_phase6_frame(
            raw
        )
    except ValueError as exc:
        raise Phase6NegativeTestFailed(
            "NEGATIVE TEST FAIL: malformed "
            "PQS6 response"
        ) from exc

    if frame.subtype != PHASE6_ERROR:
        raise Phase6NegativeTestFailed(
            "NEGATIVE TEST FAIL: unexpected "
            "PQS6 control subtype"
        )

    if len(frame.payload) != 1:
        raise Phase6NegativeTestFailed(
            "NEGATIVE TEST FAIL: malformed "
            "PQS6 error payload"
        )

    return frame.payload[0]

async def run_phase6_bidirectional(
    client: BLECentralClient,
    *,
    rounds: int = PHASE6_DEFAULT_ROUNDS,
    sas_callback: SASCallback | None = None,
    notification_timeout: float = 10.0,
    negative_test: str | None = None,
) -> Phase6BidirectionalResult:
    """Authenticate with v0.5 and run bidirectional secure traffic."""

    if rounds < 1:
        raise Phase6BidirectionalError(
            "rounds must be at least 1"
        ) 
    if negative_test not in (
        None,
        *PHASE6_NEGATIVE_MODES,
    ):
        raise Phase6BidirectionalError(
            f"Unknown Phase 6 negative test: "
            f"{negative_test}"
        )   
    if not client.is_connected:
        raise Phase6C2PError("BLE client not connected")

    notifications: asyncio.Queue[bytes] = asyncio.Queue()
    event_loop = asyncio.get_running_loop()

    def _notification_handler(_sender, data: bytearray) -> None:
        event_loop.call_soon_threadsafe(
            notifications.put_nowait,
            bytes(data),
        )

    notify_started = False

    machine = Phase5CentralStateMachine()

    shared_secret_buffer = bytearray()
    application_root_buffer = bytearray()
    finished_c_buffer = bytearray()
    expected_finished_p_buffer = bytearray()
    c2p_key_buffer = bytearray()
    p2c_key_buffer = bytearray()

    try:
        await client.start_notify(
            _notification_handler
        )

        notify_started = True

        if negative_test == "pre-auth":
            #
            # Produce a structurally valid encrypted application frame,
            # but deliberately send it BEFORE the authenticated v0.5
            # handshake has run.
            #
            # The DK must reject the GATT write at the protocol-state
            # boundary; crypto processing must never start.
            #
            dummy_channel = SecureChannel(
                bytes(32),
                session_id=bytes(16),
                role=CENTRAL_ROLE,
            )

            preauth_wire = (
                dummy_channel.encrypt(
                    b"PREAUTH",
                    msg_type=MSG_TYPE_DATA,
                )
            )

            print()
            print(
                "NEGATIVE TEST: Secure Data "
                "WRITE before authentication."
            )

            try:
                await client.write_secure_data(
                    preauth_wire
                )

            except Exception as exc:
                if not client.is_connected:
                    raise Phase6NegativeTestFailed(
                        "NEGATIVE TEST FAIL: "
                        "connection was lost while "
                        "testing pre-auth rejection"
                    ) from exc

                raise Phase6NegativeTestPassed(
                    "NEGATIVE TEST PASS: "
                    "pre-auth Secure Data WRITE "
                    "rejected by Peripheral"
                ) from exc

            raise Phase6NegativeTestFailed(
                "NEGATIVE TEST FAIL: Peripheral "
                "accepted Secure Data before "
                "authentication"
            )
        
        public_key = bytes(
            await client.read_fragmented_public_key()
        )

        if len(public_key) != PK_SIZE:
            raise Phase6C2PError(
                f"Public key size mismatch: "
                f"expected {PK_SIZE}, got {len(public_key)}"
            )

        fingerprint = hashlib.sha256(
            public_key
        ).hexdigest()[:16]

        logger.info(
            "ML-KEM public-key fingerprint: %s",
            fingerprint,
        )

        logger.info(
            "Dynamic ML-KEM PK received: %d bytes",
            len(public_key),
        )

        ciphertext, shared_secret = encapsulate(
            public_key
        )

        ciphertext = bytes(ciphertext)

        shared_secret_buffer = bytearray(
            shared_secret
        )

        shared_secret = b""

        if len(ciphertext) != CT_SIZE:
            raise Phase6C2PError(
                f"Ciphertext size mismatch: "
                f"expected {CT_SIZE}, got {len(ciphertext)}"
            )

        if len(shared_secret_buffer) != SS_SIZE:
            raise Phase6C2PError(
                f"Shared-secret size mismatch: "
                f"expected {SS_SIZE}, "
                f"got {len(shared_secret_buffer)}"
            )

        logger.info(
            "ML-KEM encapsulation: PASS"
        )

        session_id = generate_session_id()

        if len(session_id) != SESSION_ID_SIZE:
            raise Phase6C2PError(
                "Invalid generated session_id length"
            )

        transcript_hash = (
            compute_phase5_transcript_hash(
                session_id,
                public_key,
                ciphertext,
            )
        )

        logger.info(
            "Phase 5 transcript constructed"
        )

        phase5_keys = derive_phase5_keys(
            shared_secret_buffer,
            transcript_hash,
        )

        shared_secret_buffer[:] = (
            b"\x00" *
            len(shared_secret_buffer)
        )

        sas = format_phase5_sas(
            compute_phase5_sas(
                phase5_keys.sas,
                transcript_hash,
            )
        )

        application_root_buffer = bytearray(
            phase5_keys.application
        )

        finished_c_buffer = bytearray(
            compute_finished_c(
                phase5_keys.finished_c,
                transcript_hash,
            )
        )

        expected_finished_p_buffer = bytearray(
            compute_finished_p(
                phase5_keys.finished_p,
                transcript_hash,
            )
        )

        phase5_keys = None

        logger.info(
            "v0.5 key schedule: PASS"
        )

        await client.write_fragmented_ciphertext(
            ciphertext
        )

        logger.info(
            "Ciphertext transported"
        )

        await client.send_control(
            machine.start(session_id)
        )

        raw_ready = await _receive(
            notifications,
            notification_timeout,
            "READY_FOR_SAS",
        )

        try:
            ready = parse_phase5_frame(
                raw_ready
            )

            if ready.subtype == PHASE5_ERROR:
                raise Phase5StateError(
                    "Peripheral rejected Phase 5 start"
                )

            machine.receive_ready_for_sas(
                ready
            )

        except (
            ValueError,
            Phase5StateError,
        ) as exc:
            raise Phase6C2PError(
                f"Invalid READY_FOR_SAS: {exc}"
            ) from exc

        if not await _confirm_sas(
            sas,
            sas_callback,
        ):
            machine.reject_sas()

            raise Phase6C2PError(
                "SAS rejected; Phase 6 traffic "
                "was not activated"
            )

        finished_c_frame = (
            machine.confirm_sas(
                finished_c_buffer
            )
        )

        await client.send_control(
            finished_c_frame
        )

        finished_c_buffer[:] = (
            b"\x00" *
            len(finished_c_buffer)
        )

        logger.info(
            "Central FINISHED sent"
        )

        raw_finished_p = await _receive(
            notifications,
            notification_timeout,
            "FINISHED_P",
        )

        try:
            finished_p_frame = (
                parse_phase5_frame(
                    raw_finished_p
                )
            )

            if (
                finished_p_frame.subtype ==
                PHASE5_ERROR
            ):
                raise Phase5StateError(
                    "Peripheral rejected FINISHED_C"
                )

            if (
                finished_p_frame.subtype !=
                PHASE5_FINISHED_P
            ):
                raise Phase5StateError(
                    "Expected FINISHED_P"
                )

            if (
                len(finished_p_frame.payload) !=
                FINISHED_SIZE
            ):
                raise Phase5StateError(
                    "FINISHED_P has invalid size"
                )

            machine.receive_finished_p(
                finished_p_frame,
                expected_finished_p_buffer,
            )

        except (
            ValueError,
            Phase5StateError,
        ) as exc:
            raise Phase6C2PError(
                f"Peripheral FINISHED verification "
                f"failed: {exc}"
            ) from exc

        expected_finished_p_buffer[:] = (
            b"\x00" *
            len(expected_finished_p_buffer)
        )

        logger.info(
            "Peripheral FINISHED verified: PASS"
        )

        logger.info(
            "Authenticated PQ handshake: PASS"
        )

        traffic_keys = (
            derive_phase6_traffic_keys(
                bytes(application_root_buffer)
            )
        )

        c2p_key_buffer = bytearray(
            traffic_keys.central_to_peripheral
        )

        p2c_key_buffer = bytearray(
            traffic_keys.peripheral_to_central
        )

        traffic_keys = None

        application_root_buffer[:] = (
            b"\x00" *
            len(application_root_buffer)
        )

        logger.info(
            "Phase 6 directional traffic keys "
            "derived: PASS"
        )

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

        if negative_test == "c2p-tamper":
            legitimate_wire = (
                c2p_channel.encrypt(
                    b"PING 0",
                    msg_type=MSG_TYPE_DATA,
                )
            )

            tampered_wire = (
                _tamper_secure_wire_copy(
                    legitimate_wire
                )
            )

            if (
                tampered_wire[:-1] !=
                legitimate_wire[:-1]
                or tampered_wire[-1] !=
                (legitimate_wire[-1] ^ 0x01)
            ):
                raise Phase6NegativeTestFailed(
                    "NEGATIVE TEST FAIL: "
                    "tamper hook changed more "
                    "than the requested bit"
                )

            print()
            print(
                "NEGATIVE TEST: one GCM-tag "
                "bit in C->P wire intentionally "
                "flipped."
            )

            await client.write_secure_data(
                tampered_wire
            )

            raw_error = await _receive(
                notifications,
                notification_timeout,
                "C->P tamper rejection",
            )

            status = (
                _parse_phase6_error_status(
                    raw_error
                )
            )

            if (
                status !=
                PHASE6_STATUS_AUTHENTICATION_FAILURE
            ):
                raise Phase6NegativeTestFailed(
                    "NEGATIVE TEST FAIL: expected "
                    "authentication status 0x06, "
                    f"got {status!r}"
                )

            raise Phase6NegativeTestPassed(
                "NEGATIVE TEST PASS: tampered "
                "C->P AES-GCM frame rejected "
                "by Peripheral"
            )

        if negative_test == "c2p-replay":
            legitimate_wire = (
                c2p_channel.encrypt(
                    b"PING 0",
                    msg_type=MSG_TYPE_DATA,
                )
            )

            #
            # First delivery must succeed.
            #
            await client.write_secure_data(
                legitimate_wire
            )

            first_response = await _receive(
                notifications,
                notification_timeout,
                "legitimate PONG 0",
            )

            if first_response.startswith(
                PHASE6_FRAME_MAGIC
            ):
                raise Phase6NegativeTestFailed(
                    "NEGATIVE TEST FAIL: "
                    "legitimate first C->P frame "
                    "was rejected"
                )

            try:
                first_plaintext = (
                    p2c_channel.decrypt(
                        first_response,
                        msg_type=MSG_TYPE_DATA,
                    )
                )
            except (
                InvalidTag,
                ValueError,
            ) as exc:
                raise Phase6NegativeTestFailed(
                    "NEGATIVE TEST FAIL: "
                    "legitimate PONG 0 could "
                    "not be authenticated"
                ) from exc

            if first_plaintext != b"PONG 0":
                raise Phase6NegativeTestFailed(
                    "NEGATIVE TEST FAIL: "
                    "unexpected first response"
                )

            print()
            print(
                "NEGATIVE TEST: replaying "
                "the exact accepted C->P "
                "seq=0 secure wire."
            )

            #
            # Byte-for-byte replay.
            #
            await client.write_secure_data(
                legitimate_wire
            )

            replay_response = await _receive(
                notifications,
                notification_timeout,
                "C->P replay rejection",
            )

            status = (
                _parse_phase6_error_status(
                    replay_response
                )
            )

            if (
                status !=
                PHASE6_STATUS_INVALID_PROTOCOL_STATE
            ):
                raise Phase6NegativeTestFailed(
                    "NEGATIVE TEST FAIL: expected "
                    "replay/state status 0x04, "
                    f"got {status!r}"
                )

            raise Phase6NegativeTestPassed(
                "NEGATIVE TEST PASS: replayed "
                "C->P secure frame rejected "
                "by Peripheral"
            )

        if negative_test == "p2c-tamper":
            c2p_wire = c2p_channel.encrypt(
                b"PING 0",
                msg_type=MSG_TYPE_DATA,
            )

            await client.write_secure_data(
                c2p_wire
            )

            legitimate_response = (
                await _receive(
                    notifications,
                    notification_timeout,
                    "legitimate PONG 0",
                )
            )

            if legitimate_response.startswith(
                PHASE6_FRAME_MAGIC
            ):
                raise Phase6NegativeTestFailed(
                    "NEGATIVE TEST FAIL: "
                    "Peripheral did not produce "
                    "a legitimate secure response"
                )

            tampered_response = (
                _tamper_secure_wire_copy(
                    legitimate_response
                )
            )

            print()
            print(
                "NEGATIVE TEST: one GCM-tag "
                "bit in the received P->C "
                "copy intentionally flipped."
            )

            try:
                p2c_channel.decrypt(
                    tampered_response,
                    msg_type=MSG_TYPE_DATA,
                )

            except InvalidTag:
                pass

            else:
                raise Phase6NegativeTestFailed(
                    "NEGATIVE TEST FAIL: "
                    "tampered P->C frame was "
                    "accepted by Central"
                )

            #
            # Very important:
            # the failed authentication must NOT advance
            # Central receive sequence state. The untouched
            # legitimate frame must still be accepted.
            #
            try:
                plaintext = (
                    p2c_channel.decrypt(
                        legitimate_response,
                        msg_type=MSG_TYPE_DATA,
                    )
                )

            except Exception as exc:
                raise Phase6NegativeTestFailed(
                    "NEGATIVE TEST FAIL: "
                    "failed P->C authentication "
                    "incorrectly advanced or "
                    "corrupted receive state"
                ) from exc

            if plaintext != b"PONG 0":
                raise Phase6NegativeTestFailed(
                    "NEGATIVE TEST FAIL: "
                    "legitimate P->C frame "
                    "did not decrypt to PONG 0"
                )

            raise Phase6NegativeTestPassed(
                "NEGATIVE TEST PASS: tampered "
                "P->C frame rejected by Central "
                "without advancing receive state"
            )

        if negative_test == "p2c-replay":
            c2p_wire = c2p_channel.encrypt(
                b"PING 0",
                msg_type=MSG_TYPE_DATA,
            )

            await client.write_secure_data(
                c2p_wire
            )

            legitimate_response = (
                await _receive(
                    notifications,
                    notification_timeout,
                    "legitimate PONG 0",
                )
            )

            if legitimate_response.startswith(
                PHASE6_FRAME_MAGIC
            ):
                raise Phase6NegativeTestFailed(
                    "NEGATIVE TEST FAIL: "
                    "Peripheral did not produce "
                    "a legitimate secure response"
                )

            try:
                plaintext = (
                    p2c_channel.decrypt(
                        legitimate_response,
                        msg_type=MSG_TYPE_DATA,
                    )
                )
            except Exception as exc:
                raise Phase6NegativeTestFailed(
                    "NEGATIVE TEST FAIL: "
                    "first legitimate P->C frame "
                    "was rejected"
                ) from exc

            if plaintext != b"PONG 0":
                raise Phase6NegativeTestFailed(
                    "NEGATIVE TEST FAIL: "
                    "unexpected first P->C plaintext"
                )

            print()
            print(
                "NEGATIVE TEST: replaying "
                "the exact already-accepted "
                "P->C seq=0 secure wire locally."
            )

            try:
                p2c_channel.decrypt(
                    legitimate_response,
                    msg_type=MSG_TYPE_DATA,
                )

            except ValueError:
                raise Phase6NegativeTestPassed(
                    "NEGATIVE TEST PASS: replayed "
                    "P->C secure frame rejected "
                    "by Central"
                )

            except InvalidTag as exc:
                raise Phase6NegativeTestFailed(
                    "NEGATIVE TEST FAIL: P->C "
                    "replay reached tag verification "
                    "instead of replay rejection"
                ) from exc

            raise Phase6NegativeTestFailed(
                "NEGATIVE TEST FAIL: replayed "
                "P->C secure frame was accepted "
                "by Central"
            )

        if negative_test is not None:
            raise Phase6NegativeTestFailed(
                "NEGATIVE TEST FAIL: negative "
                "mode reached positive traffic path"
            )
            
        round_results: list[
            Phase6RoundTripResult
        ] = []

        for round_index in range(rounds):
            ping = (
                f"PING {round_index}"
                .encode("ascii")
            )

            expected_pong = (
                f"PONG {round_index}"
                .encode("ascii")
            )

            #
            # Central -> Peripheral
            #
            c2p_wire = c2p_channel.encrypt(
                ping,
                msg_type=MSG_TYPE_DATA,
            )

            c2p_sequence = int.from_bytes(
                c2p_wire[:8],
                "big",
            )

            if c2p_sequence != round_index:
                raise Phase6BidirectionalError(
                    "Unexpected C->P sequence: "
                    f"expected {round_index}, "
                    f"got {c2p_sequence}"
                )

            await client.write_secure_data(
                c2p_wire
            )

            logger.info(
                "C->P secure message sent: "
                "seq=%d, plaintext=%s, wire=%d B",
                c2p_sequence,
                ping.decode("ascii"),
                len(c2p_wire),
            )

            #
            # Peripheral -> Central
            #
            raw_response = await _receive(
                notifications,
                notification_timeout,
                (
                    "Phase 6 P->C secure response "
                    f"for round {round_index}"
                ),
            )

            #
            # A Phase 6 control/status frame at this point
            # means the DK rejected processing.
            #
            if raw_response.startswith(
                PHASE6_FRAME_MAGIC
            ):
                try:
                    control = parse_phase6_frame(
                        raw_response
                    )
                except ValueError as exc:
                    raise Phase6BidirectionalError(
                        "Malformed Phase 6 "
                        "control/status response"
                    ) from exc

                if control.subtype == PHASE6_ERROR:
                    if len(control.payload) != 1:
                        raise Phase6BidirectionalError(
                            "Malformed Phase 6 "
                            "error payload"
                        )

                    status = control.payload[0]

                    raise Phase6BidirectionalError(
                        "Peripheral rejected "
                        "secure application frame "
                        f"with status 0x{status:02x}"
                    )

                raise Phase6BidirectionalError(
                    "Unexpected non-error PQS6 "
                    "control frame during "
                    "bidirectional traffic"
                )

            if len(raw_response) < 8:
                raise Phase6BidirectionalError(
                    "P->C secure response "
                    "is too short"
                )

            p2c_sequence = int.from_bytes(
                raw_response[:8],
                "big",
            )

            try:
                pong = p2c_channel.decrypt(
                    raw_response,
                    msg_type=MSG_TYPE_DATA,
                )

            except InvalidTag as exc:
                raise Phase6BidirectionalError(
                    "P->C AES-256-GCM "
                    "authentication failed"
                ) from exc

            except ValueError as exc:
                raise Phase6BidirectionalError(
                    "P->C secure-channel "
                    f"validation failed: {exc}"
                ) from exc

            if p2c_sequence != round_index:
                raise Phase6BidirectionalError(
                    "Unexpected P->C sequence: "
                    f"expected {round_index}, "
                    f"got {p2c_sequence}"
                )

            if pong != expected_pong:
                raise Phase6BidirectionalError(
                    "Unexpected P->C plaintext: "
                    f"expected "
                    f"{expected_pong!r}, "
                    f"got {pong!r}"
                )

            logger.info(
                "P->C secure response "
                "authenticated: "
                "seq=%d, plaintext=%s, wire=%d B",
                p2c_sequence,
                pong.decode("ascii"),
                len(raw_response),
            )

            round_results.append(
                Phase6RoundTripResult(
                    c2p_plaintext=ping,
                    p2c_plaintext=pong,
                    c2p_sequence=c2p_sequence,
                    p2c_sequence=p2c_sequence,
                    c2p_wire_size=len(c2p_wire),
                    p2c_wire_size=len(
                        raw_response
                    ),
                )
            )

        if c2p_channel.sent_count != rounds:
            raise Phase6BidirectionalError(
                "Unexpected Central send count"
            )

        if p2c_channel.recv_count != rounds:
            raise Phase6BidirectionalError(
                "Unexpected Central receive count"
            )

        logger.info(
            "Phase 6 bidirectional secure traffic: "
            "PASS (%d round trips)",
            rounds,
        )

        return Phase6BidirectionalResult(
            round_trips=tuple(
                round_results
            ),
            sas=sas,
        )

    finally:
        for sensitive in (
            shared_secret_buffer,
            application_root_buffer,
            finished_c_buffer,
            expected_finished_p_buffer,
            c2p_key_buffer,
            p2c_key_buffer,
        ):
            sensitive[:] = (
                b"\x00" *
                len(sensitive)
            )

        if notify_started:
            try:
                await client.stop_notify()
            except Exception as exc:
                logger.warning(
                    "Could not stop Phase 6 "
                    "notifications: %s",
                    exc,
                )

async def run_phase6_c2p(
    client: BLECentralClient,
    *,
    sas_callback: SASCallback | None = None,
    notification_timeout: float = 10.0,
) -> Phase6BidirectionalResult:
    """Backward-compatible one-round Phase 6 hardware regression."""

    return await run_phase6_bidirectional(
        client,
        rounds=1,
        sas_callback=sas_callback,
        notification_timeout=notification_timeout,
    )