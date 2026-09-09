"""WinRT custom pairing for CP1, with an owned, cancellable NC ceremony.

Cold SMP is initiated here, after registering PairingRequested. The CP1 DK
must not send an unsolicited Security Request for an unbonded connection.
PairingKinds describes Windows ceremonies, not a direct SMP IO-capability
override. Only CONFIRM_PIN_MATCH is supported on the positive path, and the
DK's live SEC_INFO is still required to establish authenticated SC Level 4.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
import logging
import re
import sys
import threading
import time
from types import SimpleNamespace

logger = logging.getLogger("pq-ble.central.winrt-pairing")
ConfirmCallback = Callable[[str], Awaitable[bool]]
PROTECTION_ENCRYPTION_AND_AUTHENTICATION = "ENCRYPTION_AND_AUTHENTICATION"


class PairingUnavailableError(RuntimeError):
    """WinRT pairing requires Windows and Bleak's WinRT backend."""


class PairingError(RuntimeError):
    """Pairing failed or its ceremony could not be verified."""


@dataclass(frozen=True)
class PairingState:
    is_paired: bool
    can_pair: bool
    protection_level: str


@dataclass(frozen=True)
class PairingOutcome:
    status: str
    paired: bool
    protection_level: str
    pin_shown: str | None
    ceremony: str | None = None
    decision: bool | None = None
    accept_invoked: bool = False

    @property
    def authenticated(self) -> bool:
        return self.paired and self.protection_level == (
            PROTECTION_ENCRYPTION_AND_AUTHENTICATION
        )


def _load_winrt() -> SimpleNamespace:
    if sys.platform != "win32":
        raise PairingUnavailableError("SMP Numeric Comparison requires Windows (WinRT)")
    try:
        from winrt.windows.devices.enumeration import (
            DeviceInformation, DevicePairingKinds, DevicePairingProtectionLevel,
            DevicePairingResultStatus,
        )
    except ImportError as exc:  # pragma: no cover - Windows only
        raise PairingUnavailableError("winrt packages missing; install bleak on Windows") from exc
    return SimpleNamespace(
        DeviceInformation=DeviceInformation,
        DevicePairingKinds=DevicePairingKinds,
        DevicePairingProtectionLevel=DevicePairingProtectionLevel,
        DevicePairingResultStatus=DevicePairingResultStatus,
    )


def _enum_name(value) -> str:
    return getattr(value, "name", str(value))


async def _device_information(client, api):
    """Refresh the exact device ID owned by the connected Bleak requester.

    Retain the ID across a Windows pairing disconnect. Never resolve a new
    device by name or guess whether a scanned address is public or random.
    """
    raw = getattr(client, "raw_client", None) or client
    requester = getattr(getattr(raw, "_backend", None), "_requester", None)
    if requester is not None:
        device_id = requester.device_information.id
        client._v1_device_id = device_id
        logger.info("Pairing identity: address=%s device_id=%s", client.address, device_id)
    else:
        device_id = getattr(client, "_v1_device_id", None)
    if not device_id:
        raise PairingError("cannot resolve the connected Bleak WinRT device identity")
    info = await api.DeviceInformation.create_from_id_async(device_id)
    if info is None or info.id != device_id:
        raise PairingError("Windows returned no matching DeviceInformation")
    return info


async def inspect_pairing(client) -> PairingState:
    info = await _device_information(client, _load_winrt())
    return PairingState(bool(info.pairing.is_paired), bool(info.pairing.can_pair),
                        _enum_name(info.pairing.protection_level))


async def read_console_line(prompt: str) -> str:
    """Cancellable Windows console input; no lingering executor/input thread.

    Polling here is only console input handling, never SMP orchestration.
    Redirected stdin cannot establish interactive operator consent.
    """
    if sys.platform != "win32" or not sys.stdin.isatty():
        raise PairingError("Numeric Comparison requires an interactive Windows terminal")
    import msvcrt

    # Discard keystrokes from an earlier/aborted ceremony before showing this PIN's prompt.
    while msvcrt.kbhit():
        msvcrt.getwch()
    print(prompt, end="", flush=True)
    chars = []
    try:
        while True:
            if not msvcrt.kbhit():
                await asyncio.sleep(0.05)
                continue
            char = msvcrt.getwch()
            if char == "\x03":
                raise asyncio.CancelledError
            if char in ("\x00", "\xe0"):
                msvcrt.getwch()  # extended key code
            elif char in ("\r", "\n"):
                print(flush=True)
                return "".join(chars)
            elif char == "\b":
                if chars:
                    chars.pop()
                    print("\b \b", end="", flush=True)
            elif char.isprintable():
                chars.append(char)
                print(char, end="", flush=True)
    except asyncio.CancelledError:
        print("\nNumeric Comparison input cancelled.", flush=True)
        raise


class _Ceremony:
    """Own the event, deferral and decision task until PairAsync terminates.

    WinRT may call handler on any thread, including synchronously from
    PairAsync. Only the synchronous handler is registered with WinRT.
    """

    def __init__(self, kind, confirm):
        self.kind = kind
        self.confirm = confirm
        self.loop = asyncio.get_running_loop()
        self.lock = threading.RLock()
        self.active = True
        self.received = False
        self.pin = None
        self.ceremony = None
        self.decision = None
        self.accept_invoked = False
        self.deferral = None
        self.task = None
        self.error = None
        self.started = time.perf_counter()

    def log(self, message, *args):
        logger.info("[pair +%.3fs] " + message, time.perf_counter() - self.started, *args)

    def _complete(self):
        # Caller holds lock; detach before Complete, including on exceptions.
        if self.deferral is not None:
            deferral, self.deferral = self.deferral, None
            try:
                deferral.complete()
                self.log("deferral completed")
            except Exception as exc:
                self.error = exc
                logger.error("Deferral completion failed: %s", exc)

    def handler(self, sender, args):
        with self.lock:
            if not self.active:
                return  # A queued late event cannot revive this ceremony.
            try:
                self.log("PairingRequested received: kind=%s (%d)",
                         _enum_name(args.pairing_kind), int(args.pairing_kind))
                if self.received:
                    raise PairingError("duplicate PairingRequested event")
                self.received = True
                self.ceremony = _enum_name(args.pairing_kind)
                if args.pairing_kind != self.kind:
                    raise PairingError(f"unsupported pairing kind {self.ceremony}")
                if self.confirm is None:
                    # Only the explicitly selected negative CONFIRM_ONLY test.
                    args.accept()
                    self.accept_invoked = True
                    self.log("TEST ONLY: CONFIRM_ONLY Accept invoked")
                    return
                self.pin = str(args.pin)
                if re.fullmatch(r"[0-9]{6}", self.pin) is None:
                    raise PairingError("Numeric Comparison PIN is not six digits")
                self.log("PIN received: %s; waiting for human confirmation", self.pin)
                self.deferral = args.get_deferral()
                self.loop.call_soon_threadsafe(self._start_decision, args)
            except Exception as exc:
                self.error = exc
                self._complete()
                logger.error("PairingRequested refused: %s", exc)

    def _start_decision(self, args):
        with self.lock:
            if self.active and self.error is None:
                self.task = self.loop.create_task(self._decide(args))

    async def _decide(self, args):
        try:
            decision = await self.confirm(self.pin)
            with self.lock:
                if not self.active or self.error is not None:
                    return
                # Only an explicit boolean True grants consent.
                self.decision = decision is True
                self.log("human %s", "accepted" if self.decision else "rejected")
                if self.decision:
                    args.accept()
                    self.accept_invoked = True
                    self.log("Accept invoked")
        except asyncio.CancelledError:
            self.log("human confirmation cancelled")
            raise
        except Exception as exc:
            with self.lock:
                self.error = exc
            logger.error("Numeric Comparison decision failed: %s", exc)
        finally:
            with self.lock:
                self._complete()

    async def stop(self):
        with self.lock:
            self.active = False
            task = self.task
            self._complete()
        if task is not None:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)


async def _run_custom_pairing(client, api, kind, protection, confirm, timeout):
    if timeout <= 0:
        raise ValueError("pairing timeout must be positive")
    info = await _device_information(client, api)
    # A cold attempt must not silently turn into an already-paired success.
    if info.pairing.is_paired:
        raise PairingError("device became paired before custom pairing; clear both bonds")
    if not info.pairing.can_pair:
        raise PairingError("Windows reports the device cannot be paired")

    ceremony = _Ceremony(kind, confirm)
    custom = info.pairing.custom
    ceremony.log("CustomPairing object acquired")
    token = custom.add_pairing_requested(ceremony.handler)
    ceremony.log("PairingRequested handler registered")
    operation = None
    returned = False
    try:
        ceremony.log("pair_async started: kinds=%s (%d), minimum protection=%s (%d)",
                     _enum_name(kind), int(kind), _enum_name(protection), int(protection))
        operation = custom.pair_with_protection_level_async(kind, protection)
        result = await asyncio.wait_for(operation, timeout=timeout)
        returned = True
        ceremony.log("pair_async returned: status=%s (%d), protection_used=%s",
                     _enum_name(result.status), int(result.status),
                     _enum_name(result.protection_level_used))
    except asyncio.TimeoutError as exc:
        raise PairingError(f"pairing did not complete within {timeout:.0f} s") from exc
    finally:
        try:
            await ceremony.stop()
        finally:
            try:
                if operation is not None and not returned:
                    operation.cancel()  # cancel native WinRT, not just its Python awaiter
                    ceremony.log("native pairing operation cancelled")
            finally:
                custom.remove_pairing_requested(token)
                ceremony.log("PairingRequested handler unregistered")

    if ceremony.error is not None:
        raise PairingError(f"custom pairing handler failed: {ceremony.error}") from ceremony.error
    refreshed = await _device_information(client, api)
    status = _enum_name(result.status)
    reported_success = status in ("PAIRED", "ALREADY_PAIRED")
    paired = bool(refreshed.pairing.is_paired)
    actual_protection = _enum_name(refreshed.pairing.protection_level)
    ceremony.log("Windows paired state=%s protection=%s", paired, actual_protection)
    if reported_success and not paired:
        raise PairingError("pairing result and refreshed Windows bond state disagree")
    if confirm is not None and reported_success and not (
        status == "PAIRED" and ceremony.decision is True and ceremony.accept_invoked
    ):
        raise PairingError("cold pairing succeeded without this handler's explicit NC acceptance")
    outcome = PairingOutcome(status, paired or reported_success, actual_protection,
                             ceremony.pin, ceremony.ceremony, ceremony.decision,
                             ceremony.accept_invoked)
    logger.info("Pairing result: status=%s paired=%s protection=%s ceremony=%s decision=%s",
                outcome.status, outcome.paired, outcome.protection_level,
                outcome.ceremony, outcome.decision)
    return outcome


async def pair_numeric_comparison(client, confirm: ConfirmCallback, *, timeout=90.0):
    api = _load_winrt()
    return await _run_custom_pairing(
        client, api, api.DevicePairingKinds.CONFIRM_PIN_MATCH,
        api.DevicePairingProtectionLevel.ENCRYPTION_AND_AUTHENTICATION, confirm, timeout)


async def pair_just_works_test_only(client, *, timeout=60.0):
    """Offer only CONFIRM_ONLY, permitting unauthenticated encryption.

    This tests refusal of the Windows ceremony. WinRT cannot force the
    on-air IO capability; confirm the association model in the DK log.
    """
    api = _load_winrt()
    return await _run_custom_pairing(
        client, api, api.DevicePairingKinds.CONFIRM_ONLY,
        api.DevicePairingProtectionLevel.ENCRYPTION, None, timeout)


async def unpair(client) -> None:
    raw = getattr(client, "raw_client", None) or client
    await raw.unpair()
    logger.info("Windows bond removed")
