"""CP5 lifecycle evidence only; SMP persistence and reboot still need hardware runs."""
import asyncio
import subprocess
from types import SimpleNamespace

import pytest

from src.central import ble_client, v1_cp3, v1_cp4
from src.central.ble_client import BLECentralClient
from src.central.v1_smp_mlkem import V1Error, PRE_L4_PROBES
from src.common.v1_cp3 import CentralHandshake
from src.common.v1_cp4 import CentralApplication, APP_C2P, APP_P2C, parse_application_frame
from tests.test_v1_cp1 import FakePairingBackend, keypair
from tests.test_v1_cp3 import native_cp3, assert_cleared
from tests.test_v1_cp4 import CP4Client


class LifecycleClient(CP4Client):
    """Reuse CP4's modeled peer, with real Central disconnect/retirement methods."""
    clear_v1_cp3 = BLECentralClient.clear_v1_cp3
    disconnect = BLECentralClient.disconnect
    _on_disconnect = BLECentralClient._on_disconnect
    _on_v1_disconnect = BLECentralClient._on_v1_disconnect

    def connect_model(self, bonded):
        # Only model transport/peer per-connection state here. Production cleanup
        # must have retired the application's state before this new connection.
        assert getattr(self, "_v1_cp3_session", None) is None
        assert getattr(self, "_v1_cp4_session", None) is None
        owner = self

        class Link:
            address = "modeled-DK"
            is_connected = True

            async def disconnect(self):
                self.is_connected = owner.is_connected = False
                owner._on_disconnect(self)

        self.raw_client = self._client = Link()
        self.is_connected, self.secured = True, bonded
        self.attestations = 0
        self.controls, self.pings, self.pongs, self.challenges, self.links = [], [], [], [], []
        self.callback = None


async def exchange(client, backend, run=v1_cp4.run_v1_cp4):
    async def accept(pin): return True
    return await run(client, pairing_backend=backend, confirm_numeric_comparison=accept,
                     notification_timeout=1.0, quiet_window=0.001)


def assert_retired(app):
    assert_cleared(app.handshake)
    assert not app.handshake.session_id
    assert not any(app.iv_c2p + app.iv_p2c)
    with pytest.raises(ValueError, match="APP_SECURE"):
        app.encrypt_ping(bytes(16), 247)


def assert_two_rounds(client, result):
    assert result.app_secure and result.finished_p_verified and result.authenticated_rounds == 2
    assert client.controls == [1, 1, 0x14, 0x12]  # Includes a NEW CP3 START/FINISHED exchange.
    for frames, direction in ((client.pings, APP_C2P), (client.pongs, APP_P2C)):
        assert [parse_application_frame(frame, direction).seq for frame in frames] == [0, 1]
    assert client._v1_cp4_session.tx_c2p == client._v1_cp4_session.rx_p2c == 2


@pytest.mark.asyncio
async def test_cold_then_three_bonded_sessions_are_fresh(keypair, monkeypatch):
    client = LifecycleClient(keypair)
    backend = FakePairingBackend(client)
    apps, secrets, starts, ciphertexts = [], [], [], []
    construct, encapsulate = v1_cp4.CentralApplication, v1_cp3.encapsulate

    def observe_application(handshake):
        app = construct(handshake)
        assert app.tx_c2p == app.rx_p2c == 0
        # Check distinct ownership, without retaining or printing key values.
        assert all(app.handshake is not old.handshake and
                   app.handshake.app_c2p is not old.handshake.app_c2p and
                   app.handshake.app_p2c is not old.handshake.app_p2c and
                   app.iv_c2p is not old.iv_c2p and app.iv_p2c is not old.iv_p2c for old in apps)
        apps.append(app)
        return app

    def observe_encapsulation(pk):
        ct, ss = encapsulate(pk)
        owned = bytearray(ss)
        secrets.append(owned)
        return ct, owned

    monkeypatch.setattr(v1_cp4, "CentralApplication", observe_application)
    monkeypatch.setattr(v1_cp3, "encapsulate", observe_encapsulation)
    for iteration in range(4):
        client.connect_model(backend.paired)
        assert getattr(client, "_v1_cp3_session", None) is None
        result = await exchange(client, backend)
        assert_two_rounds(client, result)
        assert result.scenario == ("cold" if iteration == 0 else "bonded")
        if iteration == 0:
            assert set(result.pre_l4_denials) == set(PRE_L4_PROBES)
        else:
            assert result.pairing_status == "ALREADY_PAIRED"
        starts.append(client.start)
        ciphertexts.append(client.ct)
        await client.disconnect()
        assert_retired(apps[-1])
        assert client._v1_cp3_link is client._v1_notify_link is None
    assert backend.paired and backend.calls.count("nc") == 1
    assert len(apps) == len(secrets) == len(set(starts)) == len(set(ciphertexts)) == 4
    assert all(not any(secret) for secret in secrets)
    for app in apps: assert_retired(app)


@pytest.mark.asyncio
@pytest.mark.parametrize("retire", ["explicit", "callback", "unsubscribe"])
async def test_disconnect_and_invalidation_are_idempotent(keypair, retire):
    client = LifecycleClient(keypair)
    client.connect_model(True)
    backend = FakePairingBackend(client, paired=True)
    await exchange(client, backend)
    app = client._v1_cp4_session
    if retire == "explicit": await client.disconnect()
    elif retire == "callback": await client.raw_client.disconnect()
    else: await client.stop_notify()
    assert_retired(app)
    for _ in range(2):
        client.clear_v1_cp3()
        app.clear()
        await client.disconnect()
    assert_retired(app)
    assert client._v1_cp3_session is client._v1_cp4_session is None
    assert backend.paired  # App teardown does not remove the modeled SMP bond.


@pytest.mark.asyncio
async def test_retired_session_cannot_be_rebound(keypair):
    client = LifecycleClient(keypair)
    client.connect_model(True)
    backend = FakePairingBackend(client, paired=True)
    await exchange(client, backend)
    app = client._v1_cp4_session
    await client.disconnect()
    client.connect_model(True)
    # Even an attempted reattachment cannot restart a CLOSED handshake.
    client._v1_cp3_session, client._v1_cp4_session = app.handshake, app
    client._v1_cp3_link = client.raw_client
    with pytest.raises(V1Error, match="already exists"):
        await exchange(client, backend)
    assert not client.pings and not client.controls
    assert_retired(app)
    await client.disconnect()


def test_bond_does_not_construct_an_application_session():
    client = BLECentralClient()
    client._client = SimpleNamespace(is_connected=True, bonded=True)
    handshake = CentralHandshake()
    assert handshake.state == "NEW" and not handshake.app_c2p and not handshake.app_p2c
    assert getattr(client, "_v1_cp3_session", None) is None
    assert getattr(client, "_v1_cp4_session", None) is None
    with pytest.raises(ValueError, match="APP_SECURE"):
        CentralApplication(handshake)


@pytest.mark.asyncio
async def test_new_central_object_uses_new_application_state(keypair):
    previous = None
    for _ in range(2):
        client = LifecycleClient(keypair)
        client.connect_model(True)
        result = await exchange(client, FakePairingBackend(client, paired=True))
        assert_two_rounds(client, result)
        app = client._v1_cp4_session
        assert app is not previous
        await client.disconnect()
        assert_retired(app)
        if previous is not None: assert_retired(previous)
        previous = app


@pytest.mark.asyncio
async def test_bond_clear_returns_to_cold_numeric_comparison(keypair):
    client = LifecycleClient(keypair)
    backend = FakePairingBackend(client, paired=True)
    client.connect_model(True)
    assert_two_rounds(client, await exchange(client, backend))
    old = client._v1_cp4_session
    await client.disconnect()
    backend.paired = False  # Model the operator clearing BOTH bond stores.
    client.connect_model(False)
    result = await exchange(client, backend)
    assert result.scenario == "cold" and result.pairing_status == "PAIRED"
    assert set(result.pre_l4_denials) == set(PRE_L4_PROBES)
    assert backend.calls.count("nc") == 1
    assert_two_rounds(client, result)
    assert_retired(old)
    await client.disconnect()


@pytest.mark.asyncio
@pytest.mark.parametrize("old_checkpoint", ["cp3", "cp4"])
async def test_old_callbacks_and_events_cannot_complete_new_session(keypair, old_checkpoint):
    client = LifecycleClient(keypair)
    client.connect_model(True)
    backend = FakePairingBackend(client, paired=True)
    await exchange(client, backend, v1_cp3.run_v1_cp3 if old_checkpoint == "cp3" else v1_cp4.run_v1_cp4)
    old_callback, old_link = client.callback, client.raw_client
    await client.disconnect()
    client.connect_model(True)
    send, waiting = client.send_control, asyncio.Event()

    async def hold_first_reply(data):
        if data[5] == APP_C2P and not client.pings:
            current_callback = client.callback
            client.callback = lambda *args: None
            try: await send(data)
            finally: client.callback = current_callback
            waiting.set()
        else:
            await send(data)

    client.send_control = hold_first_reply
    task = asyncio.create_task(exchange(client, backend))
    try:
        await asyncio.wait_for(waiting.wait(), 1.0)
        app = client._v1_cp4_session
        client._on_v1_disconnect(old_link)
        # Route even the NEW valid PONG through the OLD connection's handler.
        # It must go to the retired queue/session, never the new pending event.
        old_callback(1, bytearray(client.pongs[0]))
        for _ in range(3): await asyncio.sleep(0)
        assert not task.done() and app.rx_p2c == 0 and app.handshake.state == "APP_SECURE"
        client.callback(1, bytearray(client.pongs[0]))
        assert_two_rounds(client, await task)
    finally:
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        await client.disconnect()


@pytest.mark.asyncio
@pytest.mark.parametrize("reconnect", ["scan_and_connect", "reconnect_v1_peer"])
async def test_real_transport_replacement_retires_session(keypair, monkeypatch, reconnect):
    modeled = LifecycleClient(keypair)
    modeled.connect_model(True)
    await exchange(modeled, FakePairingBackend(modeled, paired=True))
    app = modeled._v1_cp4_session
    # Exercise the production replacement methods around an already-live CP4 session.
    client = BLECentralClient()
    device = SimpleNamespace(name="DK", address="modeled-DK")
    client._device, client._client = device, modeled.raw_client
    client._v1_cp3_session, client._v1_cp4_session = app.handshake, app
    client._v1_cp3_link = client._v1_notify_link = modeled.raw_client
    fresh = SimpleNamespace(is_connected=True, mtu_size=247, services="modeled")
    async def connect(): pass
    async def scan(*args, **kwargs): return device
    fresh.connect = connect
    monkeypatch.setattr(ble_client.BleakScanner, "find_device_by_name", scan)
    monkeypatch.setattr(ble_client.BleakScanner, "find_device_by_address", scan)
    monkeypatch.setattr(ble_client, "BleakClient", lambda *args, **kwargs: fresh)
    assert await getattr(client, reconnect)()
    assert client.raw_client is fresh
    assert client._v1_cp3_session is client._v1_cp4_session is None
    assert_retired(app)
    await modeled.disconnect()


@pytest.mark.parametrize("scenario", [200, 201, 202, 203, 204], ids=[
    "three_bonded_sessions", "reconnect_before_worker_drains", "reconnect_during_delivery",
    "generation_change_then_recover", "fresh_dk_process_with_modeled_bond",
])
def test_native_lifecycle(native_cp3, scenario):
    result = subprocess.run([str(native_cp3[0]), str(scenario)], capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
