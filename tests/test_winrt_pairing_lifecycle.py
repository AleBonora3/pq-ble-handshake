"""Model the WinRT event boundary, rather than mocking the whole pairer.

The native-style PairAsync method may raise the event before it returns an
awaitable, on a foreign thread. Returning from the event without a deferral
ends the ceremony. Acceptance after Complete is invalid. The OS may finish
PairAsync while a human decision is still pending.
"""

import asyncio
from enum import IntEnum, IntFlag
import inspect
import threading
from types import SimpleNamespace as NS

import pytest

from src.central import winrt_pairing as pairing


class Kinds(IntFlag):
    CONFIRM_ONLY = 1
    CONFIRM_PIN_MATCH = 8


class Protection(IntEnum):
    NONE = 1
    ENCRYPTION = 2
    ENCRYPTION_AND_AUTHENTICATION = 3


class Status(IntEnum):
    PAIRED = 0
    ALREADY_PAIRED = 3
    AUTHENTICATION_FAILURE = 9
    REJECTED_BY_HANDLER = 17
    FAILED = 19


class EventArgs:
    def __init__(self, owner):
        self.owner = owner
        self.pairing_kind = owner.event_kind
        self.pin = owner.pin
        self.deferred = False
        self.completed = 0
        self.accepted = 0

    def get_deferral(self):
        self.owner.events.append("get_deferral")
        if self.owner.deferral_error:
            raise RuntimeError("deferral unavailable")
        self.deferred = True
        return NS(complete=self.complete)

    def complete(self):
        assert self.completed == 0, "deferral completed twice"
        self.completed += 1
        self.owner.events.append("complete")
        self.owner.loop.call_soon_threadsafe(self.owner.finished.set)
        if self.owner.complete_error:
            raise RuntimeError("complete failed")

    def accept(self):
        assert self.completed == 0, "Accept after ceremony lifetime"
        assert self.accepted == 0, "Accept called twice"
        if self.owner.accept_error:
            raise RuntimeError("Accept failed")
        self.accepted += 1
        self.owner.events.append("accept")


class NativeOperation:
    def __init__(self, owner):
        self.owner = owner
        self.cancelled = False

    def cancel(self):
        self.cancelled = True
        self.owner.events.append("native_cancel")

    def __await__(self):
        return self.wait().__await__()

    async def wait(self):
        owner = self.owner
        if owner.return_while_pending:
            await owner.decision_started.wait()
        elif owner.args.deferred:
            await owner.finished.wait()
        status = owner.status
        if status is None:
            status = Status.PAIRED if owner.args.accepted else Status.REJECTED_BY_HANDLER
        owner.paired = status in (Status.PAIRED, Status.ALREADY_PAIRED)
        owner.events.append("result")
        if owner.drop_requester:
            owner.client._backend._requester = None
        return NS(status=status, protection_level_used=Protection.NONE)


class WinRTModel:
    def __init__(self, *, thread=False):
        self.events = []
        self.ids = []
        self.thread = thread
        self.pin = "097689"
        self.event_kind = Kinds.CONFIRM_PIN_MATCH
        self.emit = True
        self.duplicate = False
        self.return_while_pending = False
        self.drop_requester = False
        self.status = None
        self.paired = False
        self.can_pair = True
        self.deferral_error = False
        self.accept_error = False
        self.complete_error = False
        self.protection = Protection.ENCRYPTION_AND_AUTHENTICATION
        self.client = NS(address="AA:BB:CC:DD:EE:FF", _backend=NS(
            _requester=NS(device_information=NS(id="same-ble-device"))))
        self.api = NS(DeviceInformation=NS(create_from_id_async=self.refresh),
                      DevicePairingKinds=Kinds, DevicePairingProtectionLevel=Protection,
                      DevicePairingResultStatus=Status)

    async def refresh(self, device_id):
        self.ids.append(device_id)
        return NS(id=device_id, pairing=NS(is_paired=self.paired, can_pair=self.can_pair,
                  protection_level=self.protection if self.paired else Protection.NONE,
                  custom=self))

    def add_pairing_requested(self, handler):
        assert not inspect.iscoroutinefunction(handler), "WinRT doesn't await Python callbacks"
        self.events.append("register")
        self.handler = handler
        self.token = object()
        return self.token

    def remove_pairing_requested(self, token):
        assert token is self.token
        if self.args.deferred:
            assert self.args.completed == 1
        self.events.append("unregister")
        self.saved_handler = self.handler  # WinRT may already have queued a call
        self.handler = None

    def pair_with_protection_level_async(self, kind, protection):
        assert self.handler is not None, "handler must precede PairAsync"
        self.events.append("pair_async")
        self.request = (kind, protection)
        self.loop = asyncio.get_running_loop()
        self.finished = asyncio.Event()
        self.decision_started = asyncio.Event()
        self.args = EventArgs(self)

        def fire():
            if self.emit:
                self.handler(self, self.args)
                if self.duplicate:
                    self.handler(self, EventArgs(self))
            if not self.args.deferred:
                self.loop.call_soon_threadsafe(self.finished.set)

        if self.thread:
            thread = threading.Thread(target=fire)
            thread.start()
            thread.join(timeout=1)
            assert not thread.is_alive(), "event callback blocked on human input"
        else:
            fire()
        self.operation = NativeOperation(self)
        return self.operation


async def accept(_pin):
    return True


def run_model(monkeypatch, model, confirm=accept, **kwargs):
    monkeypatch.setattr(pairing, "_load_winrt", lambda: model.api)
    return asyncio.run(pairing.pair_numeric_comparison(model.client, confirm, **kwargs))


@pytest.mark.parametrize("thread", [False, True])
def test_positive_nc_real_event_lifetime(monkeypatch, thread):
    model = WinRTModel(thread=thread)

    async def human(pin):
        assert pin == "097689"  # retain leading zero
        assert model.args.accepted == 0
        assert model.args.deferred and model.args.completed == 0
        await asyncio.sleep(0)  # handler must have returned without ending NC
        return True

    result = run_model(monkeypatch, model, human)
    assert result.authenticated and result.accept_invoked and result.decision is True
    assert model.request == (Kinds.CONFIRM_PIN_MATCH, Protection.ENCRYPTION_AND_AUTHENTICATION)
    assert model.events == ["register", "pair_async", "get_deferral", "accept",
                            "complete", "result", "unregister"]


def test_explicit_reject_never_calls_accept(monkeypatch):
    model = WinRTModel()

    async def reject(pin):
        return False

    result = run_model(monkeypatch, model, reject)
    assert result.status == "REJECTED_BY_HANDLER"
    assert result.decision is False and not result.paired
    assert model.args.accepted == 0 and model.args.completed == 1


@pytest.mark.parametrize("mode", ["os_failed", "timeout", "cancel"])
def test_pending_human_is_cancelled_and_cannot_accept_later(monkeypatch, mode):
    model = WinRTModel(thread=True)
    cancelled = []

    async def human(pin):
        model.decision_started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.append(True)

    monkeypatch.setattr(pairing, "_load_winrt", lambda: model.api)

    async def run():
        if mode == "os_failed":
            model.status = Status.FAILED
            model.return_while_pending = True
            outcome = await pairing.pair_numeric_comparison(model.client, human)
            assert outcome.status == "FAILED" and outcome.decision is None
        elif mode == "timeout":
            with pytest.raises(pairing.PairingError, match="did not complete"):
                await pairing.pair_numeric_comparison(model.client, human, timeout=0.05)
        else:
            task = asyncio.create_task(pairing.pair_numeric_comparison(model.client, human))
            while not hasattr(model, "decision_started"):
                await asyncio.sleep(0)
            await model.decision_started.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        # A queued callback after Remove must be harmless.
        late = EventArgs(model)
        model.saved_handler(model, late)
        assert not late.deferred and late.accepted == 0

    asyncio.run(run())
    assert cancelled == [True]
    assert model.args.accepted == 0 and model.args.completed == 1
    assert model.handler is None
    assert model.operation.cancelled == (mode != "os_failed")


@pytest.mark.parametrize("fault", ["wrong_kind", "bad_pin", "duplicate", "get_deferral",
                                  "human", "accept", "complete"])
def test_callback_failures_propagate_and_cleanup(monkeypatch, fault):
    model = WinRTModel()
    if fault == "wrong_kind":
        model.event_kind = Kinds.CONFIRM_ONLY
    if fault == "bad_pin":
        model.pin = "97689"
    model.duplicate = fault == "duplicate"
    model.deferral_error = fault == "get_deferral"
    model.accept_error = fault == "accept"
    model.complete_error = fault == "complete"

    async def human(pin):
        if fault == "human":
            raise ValueError("operator UI broke")
        return True

    with pytest.raises(pairing.PairingError, match="handler failed"):
        run_model(monkeypatch, model, human)
    assert model.handler is None
    if fault not in ("complete",):
        assert model.args.accepted == 0


@pytest.mark.parametrize("status", [Status.PAIRED, Status.ALREADY_PAIRED])
def test_success_without_own_nc_consent_rejected(monkeypatch, status):
    model = WinRTModel()
    model.emit = False
    model.status = status
    with pytest.raises(pairing.PairingError, match="explicit NC acceptance"):
        run_model(monkeypatch, model)


def test_failed_before_event_preserves_missing_evidence(monkeypatch):
    model = WinRTModel()
    model.emit = False
    model.status = Status.FAILED
    result = run_model(monkeypatch, model)
    assert result.ceremony is None and result.pin_shown is None and result.decision is None
    assert model.handler is None


def test_exact_identity_survives_pairing_disconnect(monkeypatch):
    model = WinRTModel()
    model.drop_requester = True
    result = run_model(monkeypatch, model)
    assert result.authenticated  # refreshed state, not result.protection_level_used=NONE
    assert model.ids == ["same-ble-device", "same-ble-device"]


def test_weaker_refreshed_protection_is_not_authenticated(monkeypatch):
    model = WinRTModel()
    model.protection = Protection.ENCRYPTION
    result = run_model(monkeypatch, model)
    assert result.paired and not result.authenticated


def test_already_paired_before_call_is_not_cold_success(monkeypatch):
    model = WinRTModel()
    model.paired = True
    with pytest.raises(pairing.PairingError, match="became paired"):
        run_model(monkeypatch, model)
    assert model.events == []


def test_just_works_offers_encryption_without_demanding_authentication(monkeypatch):
    model = WinRTModel()
    model.event_kind = Kinds.CONFIRM_ONLY
    model.status = Status.AUTHENTICATION_FAILURE
    monkeypatch.setattr(pairing, "_load_winrt", lambda: model.api)
    result = asyncio.run(pairing.pair_just_works_test_only(model.client))
    assert model.request == (Kinds.CONFIRM_ONLY, Protection.ENCRYPTION)
    assert result.ceremony == "CONFIRM_ONLY" and result.accept_invoked
    assert not result.paired and not model.args.deferred


def test_redirected_input_cannot_supply_consent(monkeypatch):
    monkeypatch.setattr(pairing.sys, "stdin", NS(isatty=lambda: False))
    with pytest.raises(pairing.PairingError, match="interactive Windows terminal"):
        asyncio.run(pairing.read_console_line("prompt"))


def test_console_input_is_cancelled_without_executor_thread(monkeypatch, capsys):
    monkeypatch.setattr(pairing.sys, "platform", "win32")
    monkeypatch.setattr(pairing.sys, "stdin", NS(isatty=lambda: True))
    monkeypatch.setitem(pairing.sys.modules, "msvcrt", NS(kbhit=lambda: False))

    async def run():
        task = asyncio.create_task(pairing.read_console_line("Compare this PIN: "))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())
    assert "input cancelled" in capsys.readouterr().out


@pytest.mark.parametrize("value", ["yes", 1, None])
def test_truthy_non_boolean_cannot_implicitly_accept(monkeypatch, value):
    model = WinRTModel()

    async def human(pin):
        return value

    result = run_model(monkeypatch, model, human)
    assert result.decision is False and not result.accept_invoked


def test_v1_reconnect_waits_for_original_address_and_replaces_session(monkeypatch):
    from src.central import ble_client
    events = []
    client = ble_client.BLECentralClient()
    original = NS(address="AA:BB:CC:DD:EE:FF")
    client._device = original

    async def disconnect():
        events.append("disconnect")

    old = NS(disconnect=disconnect)
    client._client = old

    async def find(address, *, timeout):
        assert address == original.address
        events.append("advertisement")
        return original

    class NewClient:
        def __init__(self, device, **kwargs):
            assert device is original
            assert kwargs["winrt"] == {"use_cached_services": False}
            events.append("new_client")
            self.is_connected = False

        async def connect(self):
            self.is_connected = True
            events.append("connect")

    monkeypatch.setattr(ble_client.BleakScanner, "find_device_by_address", find)
    monkeypatch.setattr(ble_client, "BleakClient", NewClient)
    assert asyncio.run(client.reconnect_v1_peer())
    assert client.raw_client is not old
    assert events == ["disconnect", "advertisement", "new_client", "connect"]
