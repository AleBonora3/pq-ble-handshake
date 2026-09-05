"""Central runner for the authenticated pure-PQ v0.5 hardware handshake."""

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
    SECURE_CHANNEL_OVERHEAD,
    SESSION_ID_SIZE,
    SS_SIZE,
)
from ..common.ml_kem import encapsulate
from ..common.phase5 import (
    Phase5CentralState,
    Phase5Frame,
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
from ..common.session import SecureChannel, generate_session_id
from .ble_client import BLECentralClient


logger = logging.getLogger("pq-ble.central.phase5")

PHASE5_EXPECTED_PLAINTEXT = b"PQ-BLE SECURE CHANNEL"
PHASE5_EXPECTED_WIRE_SIZE = (
    len(PHASE5_EXPECTED_PLAINTEXT) + SECURE_CHANNEL_OVERHEAD
)

SASCallback = Callable[[str], bool | Awaitable[bool]]
PHASE5_NEGATIVE_MODES = ("finished-c", "finished-p", "transcript")


class Phase5AuthError(RuntimeError):
    """Raised when the authenticated Phase 5 handshake fails."""


class Phase5NegativeTestPassed(RuntimeError):
    """Raised internally when an expected negative-test rejection occurs."""


class Phase5NegativeTestFailed(Phase5AuthError):
    """Raised when deliberately corrupted authentication is accepted."""


@dataclass(frozen=True)
class Phase5AuthResult:
    """Successful result; no key material is retained."""

    plaintext: bytes
    wire_size: int
    sas: str


async def _confirm_sas(sas: str, callback: SASCallback | None) -> bool:
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
        return await asyncio.wait_for(notifications.get(), timeout=timeout)
    except asyncio.TimeoutError as exc:
        raise Phase5AuthError(
            f"Timed out waiting for {description} ({timeout:g} s)"
        ) from exc


def _tamper_finished_copy(value: bytes | bytearray) -> bytes:
    """Return an equal-length copy with exactly its final bit flipped."""

    if len(value) != FINISHED_SIZE:
        raise ValueError(
            f"FINISHED value must be exactly {FINISHED_SIZE} bytes"
        )
    tampered = bytearray(value)
    tampered[-1] ^= 0x01
    return bytes(tampered)


def _mismatched_local_session_id(session_id: bytes) -> bytes:
    """Return a copy differing only in bit zero of the first byte."""

    if len(session_id) != SESSION_ID_SIZE:
        raise ValueError(
            f"session_id must be exactly {SESSION_ID_SIZE} bytes"
        )
    mismatched = bytearray(session_id)
    mismatched[0] ^= 0x01
    return bytes(mismatched)


def _negative_rejection_message(negative_test: str) -> str:
    if negative_test == "finished-c":
        return (
            "NEGATIVE TEST PASS: tampered FINISHED_C rejected by Peripheral"
        )
    if negative_test == "transcript":
        return (
            "NEGATIVE TEST PASS: transcript-bound FINISHED_C rejected by "
            "Peripheral"
        )
    raise ValueError(f"no Peripheral rejection message for {negative_test}")


async def run_phase5_auth_pq(
    client: BLECentralClient,
    *,
    sas_callback: SASCallback | None = None,
    notification_timeout: float = 10.0,
    negative_test: str | None = None,
) -> Phase5AuthResult:
    """Run one authenticated pure-PQ handshake and receive its test data."""

    if not client.is_connected:
        raise Phase5AuthError("BLE client not connected")
    if negative_test not in (None, *PHASE5_NEGATIVE_MODES):
        raise Phase5AuthError(
            f"Unknown Phase 5 negative test: {negative_test}"
        )

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
    application_key_buffer = bytearray()
    finished_c_buffer = bytearray()
    expected_finished_p_buffer = bytearray()

    try:
        await client.start_notify(_notification_handler)
        notify_started = True

        public_key = bytes(await client.read_fragmented_public_key())

        pk_fingerprint = hashlib.sha256(public_key).hexdigest()[:16]

        logger.info(
            "ML-KEM public-key fingerprint: %s",
            pk_fingerprint,
        )

        if len(public_key) != PK_SIZE:
            raise Phase5AuthError(
                f"Public key size mismatch: expected {PK_SIZE}, "
                f"got {len(public_key)}"
            )
        logger.info("Dynamic ML-KEM PK received: %d bytes", len(public_key))

        ciphertext, shared_secret = encapsulate(public_key)
        ciphertext = bytes(ciphertext)
        shared_secret_buffer = bytearray(shared_secret)
        shared_secret = b""
        if len(ciphertext) != CT_SIZE:
            raise Phase5AuthError(
                f"Ciphertext size mismatch: expected {CT_SIZE}, "
                f"got {len(ciphertext)}"
            )
        if len(shared_secret_buffer) != SS_SIZE:
            raise Phase5AuthError(
                f"Shared secret size mismatch: expected {SS_SIZE}, "
                f"got {len(shared_secret_buffer)}"
            )
        logger.info("ML-KEM encapsulation: PASS")

        session_id = generate_session_id()
        if len(session_id) != SESSION_ID_SIZE:
            raise Phase5AuthError("Invalid generated session_id length")

        local_transcript_session_id = session_id
        if negative_test == "transcript":
            local_transcript_session_id = _mismatched_local_session_id(
                session_id
            )

        transcript_hash = compute_phase5_transcript_hash(
            local_transcript_session_id, public_key, ciphertext
        )
        logger.info("Phase 5 transcript constructed")

        keys = derive_phase5_keys(shared_secret_buffer, transcript_hash)
        shared_secret_buffer[:] = b"\x00" * len(shared_secret_buffer)
        sas = format_phase5_sas(
            compute_phase5_sas(keys.sas, transcript_hash)
        )
        application_key_buffer = bytearray(keys.application)
        finished_c_buffer = bytearray(
            compute_finished_c(keys.finished_c, transcript_hash)
        )
        expected_finished_p_buffer = bytearray(
            compute_finished_p(keys.finished_p, transcript_hash)
        )
        keys = None
        logger.info("HKDF key schedule: PASS")

        await client.write_fragmented_ciphertext(ciphertext)
        logger.info("Ciphertext transported")
        await client.send_control(machine.start(session_id))

        raw_ready = await _receive(
            notifications, notification_timeout, "READY_FOR_SAS"
        )
        try:
            ready = parse_phase5_frame(raw_ready)
            if ready.subtype == PHASE5_ERROR:
                raise Phase5StateError("Peripheral rejected Phase 5 start")
            machine.receive_ready_for_sas(ready)
        except (ValueError, Phase5StateError) as exc:
            raise Phase5AuthError(f"Invalid READY_FOR_SAS: {exc}") from exc

        if negative_test == "transcript":
            print()
            print(
                "NEGATIVE TEST: transcript/session mismatch intentionally "
                "injected."
            )
            print("The Central and DK SAS values MUST NOT match.")
            print("Do NOT confirm them as equal.")

        if not await _confirm_sas(sas, sas_callback):
            machine.reject_sas()
            if negative_test == "transcript":
                raise Phase5NegativeTestPassed(
                    "NEGATIVE TEST PASS: transcript mismatch detected by SAS"
                )
            raise Phase5AuthError(
                "SAS rejected; FINISHED and application data were not sent"
            )

        finished_c_to_send = bytes(finished_c_buffer)
        if negative_test == "finished-c":
            print()
            print(
                "NEGATIVE TEST: one bit in FINISHED_C intentionally "
                "flipped after HMAC generation."
            )
            finished_c_to_send = _tamper_finished_copy(
                finished_c_to_send
            )

        finished_c_frame = machine.confirm_sas(finished_c_to_send)
        finished_c_to_send = b""
        await client.send_control(finished_c_frame)
        finished_c_buffer[:] = b"\x00" * len(finished_c_buffer)
        logger.info("Central FINISHED sent")

        try:
            raw_finished_p = await _receive(
                notifications, notification_timeout, "FINISHED_P"
            )
        except Phase5AuthError as exc:
            if negative_test in {"finished-c", "transcript"}:
                raise Phase5NegativeTestPassed(
                    _negative_rejection_message(negative_test)
                ) from exc
            raise

        if negative_test in {"finished-c", "transcript"}:
            try:
                rejection = parse_phase5_frame(raw_finished_p)
            except ValueError as exc:
                raise Phase5NegativeTestFailed(
                    "NEGATIVE TEST FAIL: Peripheral returned malformed data "
                    "after invalid FINISHED_C"
                ) from exc
            if (
                rejection.subtype == PHASE5_ERROR
                and rejection.payload == b"\x06"
            ):
                raise Phase5NegativeTestPassed(
                    _negative_rejection_message(negative_test)
                )
            if rejection.subtype == PHASE5_ERROR:
                raise Phase5NegativeTestFailed(
                    "NEGATIVE TEST FAIL: Peripheral returned unexpected "
                    "Phase 5 error status"
                )
            if rejection.subtype == PHASE5_FINISHED_P:
                if negative_test == "finished-c":
                    message = (
                        "NEGATIVE TEST FAIL: tampered FINISHED_C was accepted"
                    )
                else:
                    message = (
                        "NEGATIVE TEST FAIL: transcript mismatch was accepted"
                    )
                raise Phase5NegativeTestFailed(message)
            raise Phase5NegativeTestFailed(
                "NEGATIVE TEST FAIL: unexpected Peripheral response to "
                "invalid FINISHED_C"
            )

        try:
            finished_p_frame = parse_phase5_frame(raw_finished_p)
            if negative_test == "finished-p":
                if finished_p_frame.subtype != PHASE5_FINISHED_P:
                    raise Phase5StateError(
                        "expected legitimate FINISHED_P before local tamper"
                    )
                print()
                print(
                    "NEGATIVE TEST: one bit in the locally received "
                    "FINISHED_P copy intentionally flipped."
                )
                finished_p_frame = Phase5Frame(
                    subtype=finished_p_frame.subtype,
                    payload=_tamper_finished_copy(
                        finished_p_frame.payload
                    ),
                )
            machine.receive_finished_p(
                finished_p_frame, expected_finished_p_buffer
            )
        except (ValueError, Phase5StateError) as exc:
            if (
                negative_test == "finished-p"
                and machine.state is Phase5CentralState.ABORTED
            ):
                raise Phase5NegativeTestPassed(
                    "NEGATIVE TEST PASS: tampered FINISHED_P rejected by "
                    "Central"
                ) from exc
            raise Phase5AuthError(str(exc)) from exc
        if negative_test == "finished-p":
            raise Phase5NegativeTestFailed(
                "NEGATIVE TEST FAIL: tampered FINISHED_P was accepted"
            )
        expected_finished_p_buffer[:] = (
            b"\x00" * len(expected_finished_p_buffer)
        )
        logger.info("Peripheral FINISHED verified: PASS")
        logger.info("Authenticated PQ handshake: PASS")

        # Instantiate the application channel only after FINISHED_P verifies.
        secure_channel = SecureChannel(
            bytes(application_key_buffer),
            session_id=session_id,
            role=CENTRAL_ROLE,
        )
        application_key_buffer[:] = b"\x00" * len(application_key_buffer)

        await client.send_control(machine.request_application_data())
        raw_application = await _receive(
            notifications, notification_timeout, "authenticated AES data"
        )
        if raw_application[:4] == b"PQS5":
            error_frame = parse_phase5_frame(raw_application)
            raise Phase5AuthError(
                f"Peripheral error while activating data: "
                f"subtype 0x{error_frame.subtype:02x}"
            )
        if len(raw_application) != PHASE5_EXPECTED_WIRE_SIZE:
            raise Phase5AuthError(
                "Unexpected authenticated secure-wire size: expected "
                f"{PHASE5_EXPECTED_WIRE_SIZE}, got {len(raw_application)}"
            )

        try:
            plaintext = secure_channel.decrypt(
                raw_application, msg_type=MSG_TYPE_DATA
            )
        except (InvalidTag, ValueError) as exc:
            raise Phase5AuthError(
                f"AES-256-GCM authentication failed: {exc}"
            ) from exc
        if plaintext != PHASE5_EXPECTED_PLAINTEXT:
            raise Phase5AuthError(
                f"Authenticated plaintext mismatch: {plaintext!r}"
            )

        machine.complete_application_data()
        logger.info("AES-256-GCM authentication: PASS")
        logger.info(
            "Decrypted payload: %s", plaintext.decode("ascii")
        )
        return Phase5AuthResult(
            plaintext=plaintext,
            wire_size=len(raw_application),
            sas=sas,
        )
    finally:
        for sensitive in (
            shared_secret_buffer,
            application_key_buffer,
            finished_c_buffer,
            expected_finished_p_buffer,
        ):
            sensitive[:] = b"\x00" * len(sensitive)
        if notify_started:
            try:
                await client.stop_notify()
            except Exception as exc:
                logger.warning(
                    "Could not stop Phase 5 notifications: %s", exc
                )
