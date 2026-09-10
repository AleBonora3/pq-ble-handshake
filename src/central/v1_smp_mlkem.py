"""v1.0 CP1 Central flow: SMP Security Mode 1 Level 4 foundation.

Goal of CP1 (no ML-KEM key schedule yet):

    connect
    -> prove every PQ GATT operation is denied before Level 4
    -> SMP pairing with real Numeric Comparison (human on both sides)
    -> DK attests authenticated L4 (SEC_INFO)
    -> prove PQ GATT (Public Key read, Ciphertext write, Control write,
       Secure Data CCCD) is accessible after Level 4

Hardware:  python -m src.central.main --v1-smp-l4-mlkem [--v1-negative MODE]
MODE:      pre-l4-only | nc-reject | just-works

``just-works`` is the legacy name for the Windows CONFIRM_ONLY experiment;
the application ceremony does not demonstrate the on-air association method.

Every negative path must end without the "PQ GATT allowed" stage having
been reached, and this module raises rather than returning a result in
those cases. ``APP_SECURE`` does not exist yet in CP1; the strongest state
reachable here is ``L4_GATT_VERIFIED``.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
import logging
import time

from ..common.constants import BLE_MTU, CT_SIZE, PK_SIZE
from ..common.fragmentation import fragment_data
from ..common.ml_kem import encapsulate
from ..common.v1_smp_mlkem import (
    V1_ERROR,
    V1_SEC_INFO,
    V1_STATUS_NAMES,
    V1SecurityInfo,
    classify_security_denial,
    encode_sec_query,
    is_authenticated_level4,
    parse_sec_info,
    parse_v1_frame,
)
from . import winrt_pairing


logger = logging.getLogger("pq-ble.central.v1-smp-l4")

ConfirmCallback = Callable[[str], Awaitable[bool]]

V1_NEGATIVE_MODES = ("pre-l4-only", "nc-reject", "just-works")

PRE_L4_PROBES = (
    "public-key-read",
    "ciphertext-write",
    "control-write",
    "secure-data-cccd",
)


class V1Error(RuntimeError):
    """CP1 failed; the secure state was not (or must not be) reached."""


class V1NegativeTestInconclusive(V1Error):
    """Insufficient negative-test evidence; retain a nonzero exit status."""


class V1NegativeTestPassed(RuntimeError):
    """Expected rejection observed; never a positive result."""


@dataclass
class V1CP1Result:
    scenario: str                      # "cold" or "bonded"
    security_info: V1SecurityInfo
    pre_l4_denials: dict[str, str] = field(default_factory=dict)
    pairing_status: str = ""
    pairing_protection: str = ""
    pairing_ms: float = 0.0
    public_key_len: int = 0
    ciphertext_fragments: int = 0
    post_l4_ms: float = 0.0
    total_ms: float = 0.0


def _ms(start: float) -> float:
    return (time.perf_counter() - start) * 1000.0


async def _probe_denied(name: str, client, operation, denials: dict[str, str]) -> None:
    """Require a *security* denial for one pre-L4 PQ GATT operation."""

    try:
        await operation()
    except Exception as exc:  # noqa: BLE001 - classification decides
        reason = classify_security_denial(exc)
        if reason is None:
            if not client.is_connected:
                raise V1Error(
                    f"{name}: connection lost during the pre-L4 probe"
                ) from exc
            raise V1Error(
                f"{name}: failed for a non-security reason before L4: "
                f"{type(exc).__name__}: {exc}"
            ) from exc
        denials[name] = reason
        logger.info("Pre-L4 %s: DENIED (%s)", name, reason)
        return
    raise V1Error(
        f"GATING FAILURE: {name} succeeded before Security Level 4"
    )


async def _run_pre_l4_probes(client, notification_handler) -> dict[str, str]:
    denials: dict[str, str] = {}
    mtu = min(client.mtu_size, BLE_MTU) if client.mtu_size > 23 else BLE_MTU
    probe_fragment = fragment_data(bytes(CT_SIZE), mtu=mtu)[0]

    await _probe_denied(
        "public-key-read", client, client.read_fragmented_public_key, denials
    )
    await _probe_denied(
        "ciphertext-write",
        client,
        lambda: client.write_raw_ciphertext_fragment(probe_fragment),
        denials,
    )
    await _probe_denied(
        "control-write",
        client,
        lambda: client.send_control(encode_sec_query()),
        denials,
    )
    await _probe_denied(
        "secure-data-cccd",
        client,
        lambda: client.start_notify(notification_handler),
        denials,
    )
    if set(denials) != set(PRE_L4_PROBES):
        raise V1Error("pre-L4 probe bookkeeping mismatch")
    logger.info("Pre-L4 gating: all %d PQ GATT operations denied", len(denials))
    return denials


async def _ensure_connected(client) -> None:
    if client.is_connected:
        return
    logger.warning("Link dropped after pairing (Windows re-bond); reconnecting")
    if not await client.reconnect_v1_peer():
        raise V1Error("could not reconnect after pairing")


def _rejection_evidence(mode: str, outcome: winrt_pairing.PairingOutcome) -> str:
    """Reject ambiguous failures, even if the transport subsequently drops."""
    if outcome.paired or outcome.authenticated:
        raise V1Error(
            f"SECURITY FAILURE: {mode} pairing was accepted "
            f"(status {outcome.status}, protection {outcome.protection_level})"
        )
    security_statuses = {
        "REJECTED_BY_HANDLER", "AUTHENTICATION_FAILURE",
        "AUTHENTICATION_NOT_ALLOWED", "PROTECTION_LEVEL_COULD_NOT_BE_MET",
    }
    if mode == "nc-reject":
        # A generic FAILED with no callback is exactly the original hardware
        # failure, not proof that an operator rejected Numeric Comparison.
        local_reject = (
            outcome.ceremony == "CONFIRM_PIN_MATCH" and outcome.pin_shown is not None
            and outcome.decision is False and not outcome.accept_invoked
        )
        if local_reject and outcome.status in security_statuses | {"FAILED", "PAIRING_CANCELED"}:
            return "explicit PC Numeric Comparison rejection"
    else:
        if outcome.status in security_statuses:
            return "Windows refused the CONFIRM_ONLY-only attempt"
        if (outcome.status == "FAILED" and outcome.ceremony == "CONFIRM_ONLY"
                and outcome.accept_invoked):
            return "CONFIRM_ONLY ceremony observed and accepted; pairing failed"
    guidance = (
        "For nc-reject type 'no' on the PC; a DK-only rejection requires UART evidence."
        if mode == "nc-reject" else
        "CONFIRM_ONLY is a Windows application ceremony; radio-level Just Works "
        "is not demonstrated. This inconclusive experiment does not invalidate "
        "separately validated CP1 foundation results."
    )
    raise V1NegativeTestInconclusive(
        f"INCONCLUSIVE {mode}: {outcome.status}, ceremony={outcome.ceremony}, "
        f"decision={outcome.decision}, paired={outcome.paired}, "
        f"protection={outcome.protection_level}; no sufficient security-rejection evidence. "
        "A timeout, missing handler, or generic FAILED is not a negative-test PASS. "
        + guidance
    )


async def _verify_negative_closed(client, backend, notifications, handler, mode, outcome):
    evidence = _rejection_evidence(mode, outcome)
    logger.info("Security rejection evidence: %s", evidence)
    if not notifications.empty():
        raise V1Error("SECURITY FAILURE: PQ notification received during rejected pairing")
    state = await backend.inspect_pairing(client)
    if state.is_paired:
        raise V1Error("SECURITY FAILURE: Windows retained a bond after rejected pairing")
    # Always retire the attempt's connection. This handles a deferred Windows
    # disconnect without probing a dying link. Reconnect failure is inconclusive,
    # never a PASS. Retain both bond stores as evidence (do not unpair here).
    logger.info("Retiring rejected pairing link; any security disconnect is expected")
    if not await client.reconnect_v1_peer():
        raise V1NegativeTestInconclusive(
            "INCONCLUSIVE: cannot establish fresh link to verify rejected pairing"
        )
    state = await backend.inspect_pairing(client)
    if state.is_paired:
        raise V1Error("SECURITY FAILURE: fresh verification link has a Windows bond")
    denials = await _run_pre_l4_probes(client, handler)
    if not notifications.empty():
        raise V1Error("SECURITY FAILURE: PQ notification received in negative test")
    raise V1NegativeTestPassed(
        f"{mode}: {evidence}; fresh unpaired connection: all {len(denials)} PQ "
        "operations remain denied. No successful PQ operation observed; "
        "verify DK log contains no L4/gate OPEN on either connection."
    )


async def _post_l4_exchange(
    client, notifications: asyncio.Queue, notification_handler,
    *, notification_timeout: float, quiet: float, result: V1CP1Result,
) -> V1SecurityInfo:
    """Exercise every PQ GATT operation after L4 and read the DK attestation."""

    started = time.perf_counter()

    await client.start_notify(notification_handler)
    logger.info("Post-L4 Secure Data CCCD: ALLOWED")

    public_key = bytes(await client.read_fragmented_public_key())
    if len(public_key) != PK_SIZE:
        raise V1Error(f"ML-KEM public key must be {PK_SIZE} bytes, got {len(public_key)}")
    result.public_key_len = len(public_key)
    logger.info("Post-L4 Public Key read: ALLOWED (%d B)", len(public_key))

    # A real ciphertext keeps the transport measurement identical to v0.7.
    # CP1 never starts the ML-KEM handshake: the shared secret is discarded.
    ciphertext, shared_secret = encapsulate(public_key)
    shared_secret = bytearray(shared_secret)
    shared_secret[:] = b"\x00" * len(shared_secret)
    del shared_secret
    result.ciphertext_fragments = await client.write_fragmented_ciphertext(
        ciphertext
    ) or 0
    logger.info("Post-L4 Ciphertext write: ALLOWED (%d B)", len(ciphertext))

    await client.send_control(encode_sec_query())
    logger.info("Post-L4 Control write (SEC_QUERY): ALLOWED")

    try:
        raw = await asyncio.wait_for(notifications.get(), timeout=notification_timeout)
    except asyncio.TimeoutError as exc:
        raise V1Error("timed out waiting for SEC_INFO") from exc

    try:
        frame = parse_v1_frame(raw)
    except ValueError as exc:
        raise V1Error(f"invalid DK reply: {exc}") from exc
    if frame.subtype == V1_ERROR:
        status = frame.payload[0]
        raise V1Error(
            f"DK PQV1 ERROR 0x{status:02X} ({V1_STATUS_NAMES.get(status, 'unknown')})"
        )
    if frame.subtype != V1_SEC_INFO:
        raise V1Error(f"unexpected PQV1 subtype 0x{frame.subtype:02X}")
    info = parse_sec_info(raw)
    logger.info("DK security attestation: %s", info.describe())

    # Bounded quiet window: no unsolicited frames may follow.
    try:
        extra = await asyncio.wait_for(notifications.get(), timeout=quiet)
    except asyncio.TimeoutError:
        extra = None
    if extra is not None:
        raise V1Error("unexpected extra notification after SEC_INFO")

    if not is_authenticated_level4(info):
        raise V1Error(
            "DK reports a link that is NOT authenticated Security Mode 1 "
            f"Level 4 ({info.describe()}); refusing to continue (fail closed)"
        )
    result.post_l4_ms = _ms(started)
    return info


async def _run_v1(
    client,
    *,
    confirm_numeric_comparison: ConfirmCallback,
    negative_test: str | None = None,
    unpair_first: bool = False,
    pairing_timeout: float = 90.0,
    notification_timeout: float = 10.0,
    quiet_window: float = 1.0,
    pairing_backend=winrt_pairing,
    post_l4_exchange=_post_l4_exchange,
    result_type=V1CP1Result,
    checkpoint: str = "CP1",
    retain_notify: bool = False,
) -> V1CP1Result:
    """Run CP1. Raises V1Error / V1NegativeTestPassed; never returns on failure."""

    if negative_test is not None and negative_test not in V1_NEGATIVE_MODES:
        raise ValueError(f"unknown v1 negative test: {negative_test}")
    if not client.is_connected:
        raise V1Error("BLE client not connected")
    client._v1_security_test = True

    total_started = time.perf_counter()
    notifications: asyncio.Queue[bytes] = asyncio.Queue()
    loop = asyncio.get_running_loop()

    def notification_handler(_sender, data: bytearray) -> None:
        loop.call_soon_threadsafe(notifications.put_nowait, bytes(data))

    notify_started = False
    completed = False
    try:
        state = await pairing_backend.inspect_pairing(client)
        logger.info(
            "Windows bond state: paired=%s can_pair=%s protection=%s",
            state.is_paired, state.can_pair, state.protection_level,
        )
        if unpair_first and state.is_paired:
            logger.warning("--v1-unpair-first: removing the Windows bond")
            await pairing_backend.unpair(client)
            await _ensure_connected(client)
            state = await pairing_backend.inspect_pairing(client)
            if state.is_paired:
                raise V1Error("Windows still reports the device as paired after unpair")

        scenario = "bonded" if state.is_paired else "cold"
        result = result_type(
            scenario=scenario,
            security_info=V1SecurityInfo(0, False, False, False, 0, 0),
        )
        logger.info("Scenario: %s", "bonded reconnection" if state.is_paired else "cold pairing")

        if negative_test is not None and state.is_paired:
            raise V1Error(
                f"negative test '{negative_test}' requires the cold-pairing state; "
                "re-run with --v1-unpair-first and clear the DK bonds (BUTTON 3)"
            )

        if scenario == "cold":
            result.pre_l4_denials = await _run_pre_l4_probes(
                client, notification_handler
            )
        else:
            logger.info(
                "Bonded reconnect: pre-L4 probes skipped (Windows restores "
                "encryption with the stored LTK on the first protected access)"
            )

        if negative_test == "pre-l4-only":
            raise V1NegativeTestPassed(
                "all four PQ GATT operations denied before Level 4; "
                "Central custom pairing not invoked (check DK log for unsolicited SMP)"
            )

        if scenario == "cold":
            pairing_started = time.perf_counter()
            if negative_test == "just-works":
                logger.warning("TEST ONLY: offering CONFIRM_ONLY with minimum ENCRYPTION; "
                               "WinRT ceremony selection does not force on-air IO capability")
                outcome = await pairing_backend.pair_just_works_test_only(
                    client, timeout=pairing_timeout
                )
            else:
                outcome = await pairing_backend.pair_numeric_comparison(
                    client, confirm_numeric_comparison, timeout=pairing_timeout
                )
            result.pairing_ms = _ms(pairing_started)
            result.pairing_status = outcome.status
            result.pairing_protection = outcome.protection_level

            if negative_test in ("just-works", "nc-reject"):
                await _verify_negative_closed(
                    client, pairing_backend, notifications, notification_handler,
                    negative_test, outcome,
                )

            if not outcome.paired or outcome.status != "PAIRED":
                raise V1Error(
                    f"SMP pairing failed: {outcome.status}; PQ GATT stays closed"
                )
            if not outcome.authenticated:
                raise V1Error(
                    "pairing completed WITHOUT authentication "
                    f"(protection {outcome.protection_level}); refusing to continue"
                )
            logger.info(
                "SMP pairing complete: %s, protection %s, %.0f ms (includes human time)",
                outcome.status, outcome.protection_level, result.pairing_ms,
            )
            await _ensure_connected(client)
        else:
            result.pairing_status = "ALREADY_PAIRED"
            result.pairing_protection = state.protection_level

        try:
            notify_started = True  # also clean up if a later post-L4 step fails
            info = await post_l4_exchange(
                client, notifications, notification_handler,
                notification_timeout=notification_timeout,
                quiet=quiet_window, result=result,
            )
        except V1Error:
            raise
        except Exception as exc:  # noqa: BLE001
            reason = classify_security_denial(exc)
            if reason is not None and scenario == "bonded":
                raise V1Error(
                    f"stale/corrupted bond: protected GATT access denied ({reason}) "
                    "although Windows holds a bond. Remove it with --v1-unpair-first "
                    "and clear the DK bonds (BUTTON 3 while idle), then pair again"
                ) from exc
            if reason is not None:
                raise V1Error(
                    f"PQ GATT still denied after pairing ({reason}); Level 4 was "
                    "not established on the DK"
                ) from exc
            raise V1Error(f"post-L4 exchange failed: {type(exc).__name__}: {exc}") from exc
        notify_started = True
        result.security_info = info
        result.total_ms = _ms(total_started)
        logger.info("v1.0 %s state: %s (%s)", checkpoint,
                    "APP_SECURE" if checkpoint in ("CP3", "CP4") else "L4_GATT_VERIFIED", scenario)
        completed = True
        return result
    finally:
        if notify_started and not (completed and retain_notify):
            try:
                await client.stop_notify()
            except Exception as exc:  # noqa: BLE001
                logger.warning("Could not stop notifications: %s", exc)


async def run_v1_cp1(client, **kwargs) -> V1CP1Result:
    """CP1 access-only validation; never submits ML-KEM decapsulation."""
    return await _run_v1(client, **kwargs)
