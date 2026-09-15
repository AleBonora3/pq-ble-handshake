"""Explicit v0.8/v1.1 runners preserving their respective baseline data planes."""

import asyncio
from dataclasses import dataclass
import hmac
import logging
import secrets

from ..common import resumption as r, phase7 as hybrid, v1_smp_mlkem as v1
from ..common.resume_full import FullHandshake, encode_full, parse_full, security_info
from ..common.resume_store import TicketStore
from ..common.resume_hybrid import HybridApplication
from ..common.v1_cp3 import clear
from ..common.v1_cp4 import CentralApplication
from ..common.ml_kem import encapsulate
from .phase7_auth import _confirm_sas
from .v1_smp_mlkem import _run_v1, V1Error
from . import measurement as measure, winrt_pairing

logger = logging.getLogger("pq-ble.central.resumption")
NEGATIVE_MODES = ("init-mac", "accept-mac", "replay-init", "replay-finish", "expired", "max-uses", "pre-l4")


class NegativePassed(RuntimeError):
    """Explicit rejection observed; never a positive session result."""


@dataclass
class Result:
    profile: int
    path: str = "full"
    scenario: str = "application"
    fallback_reason: str | None = None
    rounds: int = 0
    app_secure: bool = False
    ticket_saved: bool = False
    successful_resumes: int = 0


def tamper(raw):
    return raw[:-1] + bytes((raw[-1] ^ 1,))


async def _exchange(client, profile, store, peer, *, allow_resume, force_full,
                    result, sas_callback, timeout, negative=None, replay_finish=None):
    queue = asyncio.Queue()
    loop, link = asyncio.get_running_loop(), client.raw_client
    session = None
    app = None
    ticket = None
    client._v1_security_test = True  # shared immediate disconnect wiping

    def require_link():
        if (not client.is_connected or client.raw_client is not link
                or (session is not None and session.state == "CLOSED")):
            raise V1Error("connection lost/replaced during new-profile exchange")

    def on_notify(_sender, data):
        loop.call_soon_threadsafe(queue.put_nowait, bytes(data))

    async def receive():
        raw = await asyncio.wait_for(queue.get(), timeout)
        require_link()
        return raw

    async def attest():
        await client.send_control(encode_full(r.V11, v1.V1_SEC_QUERY))
        sec = await receive()
        info = security_info(sec)
        measure.mark("security_ready_attested")
        logger.info("v1.1 security: %s", info.describe())
        return sec

    def own(value):
        client._v1_cp3_session, client._v1_cp3_link = value, link

    try:
        await client.start_notify(on_notify)
        require_link()
        if profile == r.V11:
            await attest()  # Mandatory BEFORE loading/sending any resume secret proof.
        if not allow_resume:
            store.delete(profile, peer)  # A cold SMP ceremony cannot use the old app ticket.
        ticket = store.load(profile, peer) if allow_resume else None
        if negative in ("expired", "max-uses"):
            if ticket is None:
                raise V1Error("negative lifecycle mode requires an existing Central ticket")
            if negative == "expired":
                ticket.created_at -= r.TTL
            else:
                ticket.successful_resumes = r.MAX_RESUMES
            try:
                ticket.check(profile, peer, store.clock())
            except r.ResumeError as exc:
                result.fallback_reason = exc.reason.name
                store.delete(profile, peer)
                ticket = None
        if ticket is not None and not force_full:
            session = r.CentralResume(ticket, now=store.clock())
            own(session)
            init = session.begin()
            if negative == "init-mac":
                init = tamper(init)
            measure.mark("resume_init_sent")
            await client.send_control(init)
            raw = await receive()
            subtype, _ = r.parse(raw, profile)
            if subtype == r.REJECT:
                if negative == "init-mac":
                    raise NegativePassed("bad INIT MAC explicitly rejected")
                result.fallback_reason = "RESUME_REJECT"
                session.clear()
                # Controlled rejection retires the Peripheral partial state.
                session = None
                client._v1_cp3_session = None
            else:
                if negative == "init-mac":
                    raise V1Error("Peripheral accepted forged INIT")
                measure.mark("resume_accept_received")
                if negative == "replay-init":
                    await client.send_control(init)
                    r.parse(await receive(), profile, r.REJECT)
                    raise NegativePassed("duplicate INIT explicitly rejected")
                if negative == "accept-mac":
                    try:
                        session.accept(tamper(raw))
                    except r.ResumeError as exc:
                        if exc.reason != r.Reason.BAD_AUTH:
                            raise
                        raise NegativePassed("Central rejected tampered ACCEPT; FINISH_C not sent") from exc
                    raise V1Error("Central accepted forged ACCEPT")
                finished = session.accept(raw)
                await client.send_control(replay_finish if replay_finish is not None else finished)
                measure.mark("resume_finish_c_sent")
                reply = await receive()
                if replay_finish is not None:
                    r.parse(reply, profile, r.REJECT)
                    raise NegativePassed("old FINISH_C explicitly rejected in a fresh resume transcript")
                session.finish(reply)
                measure.mark("resume_finish_p_verified")
                store.save(ticket)
                result.path = "resume"
                result.successful_resumes = ticket.successful_resumes
                app = (HybridApplication(session) if profile == r.V08 else
                       CentralApplication(session, iv_c2p=session.keys.iv_c2p, iv_p2c=session.keys.iv_p2c))
                # Non-secret authenticated proof retained only in this process for the replay test.
                result._finish_c_for_test = finished
        if app is None:
            if negative in ("init-mac", "accept-mac", "replay-init", "replay-finish"):
                raise V1Error("negative resume mode requires a valid ticket on both peers")
            if result.fallback_reason is None and not force_full:
                result.fallback_reason = store.last_reason.name if ticket is None else None
            session = FullHandshake(profile)
            own(session)
            secret, ecdh = bytearray(), bytearray()
            private = None
            try:
                with measure.phase("public_key_transfer"):
                    pk = bytes(await client.read_fragmented_public_key())
                require_link()
                r.sized(pk, 1184)
                with measure.phase("mlkem_encapsulate"):
                    ct, ss = encapsulate(pk)
                secret = bytearray(ss)
                del ss
                sid = secrets.token_bytes(16)
                if profile == r.V08:
                    with measure.phase("p256_keygen"):
                        private = hybrid.generate_p256_private_key()
                    public = hybrid.serialize_p256_public_key(private)
                    start = encode_full(profile, hybrid.PHASE7_START7_AUTH, sid+public)
                else:
                    start = encode_full(profile, v1.V1_START_CP3, sid)
                with measure.phase("ciphertext_transfer"):
                    await client.write_fragmented_ciphertext(ct)
                sec = await attest() if profile == r.V11 else None
                if profile == r.V11:
                    session.begin(secret, pk, ct, sid, sec=sec)
                await client.send_control(start)
                measure.mark("start_sent")
                ready = parse_full(profile, await receive())
                measure.mark("ready_received")
                if profile == r.V08:
                    if ready.subtype != hybrid.PHASE7_READY7_AUTH:
                        raise V1Error("expected v0.8 READY_AUTH")
                    with measure.phase("p256_ecdh"):
                        ecdh = bytearray(hybrid.derive_p256_ecdh_shared_secret(private, ready.payload))
                    private = None
                    session.begin(secret, pk, ct, sid, ecdh=ecdh, central_public=public, peripheral_public=ready.payload)
                    clear(secret)
                    clear(ecdh)
                    measure.mark("auth_prompt_ready")
                    with measure.phase("interactive_wait"):
                        confirmed = await _confirm_sas(session.sas(), sas_callback)
                    measure.mark("auth_decision_returned")
                else:
                    if ready.subtype != v1.V1_READY_CP3 or not hmac.compare_digest(ready.payload, session.th):
                        raise V1Error("v1.1 READY transcript mismatch")
                    confirmed = True
                await client.send_control(session.finish_c(authenticated=confirmed))
                measure.mark("finished_c_sent")
                session.finish_p(await receive(), peer, now=store.clock())
                measure.mark("finished_p_verified")
                if ticket is not None:
                    ticket.clear()
                ticket = session.ticket
                store.save(ticket)
                app = HybridApplication(session) if profile == r.V08 else CentralApplication(session)
            finally:
                clear(secret)
                clear(ecdh)
                private = None
        measure.mark("app_secure")
        result.app_secure = True
        result.ticket_saved = ticket is not None and ticket.valid
        client._v1_cp4_session = app
        for round_index in range(3 if profile == r.V08 else 2):
            require_link()
            challenge = round_index if profile == r.V08 else secrets.token_bytes(16)
            wire = app.encrypt_ping(challenge, client.mtu_size)
            measure.mark("application_request")
            if profile == r.V08:
                await client.write_secure_data(wire)
            else:
                await client.send_control(wire)
            app.accept_pong(await receive(), challenge, client.mtu_size)
            measure.mark("application_response_authenticated")
            result.rounds += 1
        if not queue.empty():
            raise V1Error("unsolicited notification after authenticated application traffic")
        logger.info("Profile 0x%02x %s: APP_SECURE, %d authenticated round trips; ticket=%s",
                    profile, result.path, result.rounds, result.ticket_saved)
        return result
    finally:
        # The CLI deliberately closes each connection; its ticket survives.
        if app is not None:
            app.clear()
        if session is not None:
            session.clear()
        if ticket is not None:
            ticket.clear()
        await client.stop_notify()


async def run_session(client, profile, *, store=None, force_full=False, sas_callback=None,
                      confirm_numeric_comparison=None, pairing_backend=winrt_pairing,
                      pairing_timeout=90, timeout=30, negative=None, replay_finish=None):
    store = TicketStore() if store is None else store
    peer = client.address.upper()
    result = Result(profile)
    if negative is not None and negative not in NEGATIVE_MODES:
        raise ValueError("unknown resume negative mode")
    if negative == "pre-l4":
        if profile != r.V11 or (await pairing_backend.inspect_pairing(client)).is_paired:
            raise V1Error("pre-l4 requires v1.1 with both bonds deleted")
        try:
            await client.send_control(r.encode(profile, r.INIT, bytes(96)))
        except Exception as exc:
            if v1.classify_security_denial(exc) is not None:
                raise NegativePassed("actual RESUME_INIT denied by pre-L4 GATT security gate") from exc
            raise
        raise V1Error("pre-L4 RESUME_INIT was accepted")

    async def attempt(force, mode):
        if profile == r.V08:
            return await _exchange(client, profile, store, peer, allow_resume=True, force_full=force,
                result=result, sas_callback=sas_callback, timeout=timeout, negative=mode, replay_finish=replay_finish)

        async def after_l4(_client, _notifications, _handler, **kwargs):
            result.scenario = kwargs["result"].scenario
            await _exchange(client, profile, store, peer, allow_resume=result.scenario == "bonded",
                force_full=force, result=result, sas_callback=None, timeout=timeout,
                negative=mode, replay_finish=replay_finish)
            return v1.V1SecurityInfo(4, True, True, True, 16, r.V11)
        # Reuse the CP1 WinRT ceremony, peer-preserving reconnect and bond checks.
        try:
            await _run_v1(client, confirm_numeric_comparison=confirm_numeric_comparison,
                pairing_backend=pairing_backend, pairing_timeout=pairing_timeout,
                notification_timeout=timeout, post_l4_exchange=after_l4, checkpoint="RESUME")
        except V1Error as exc:
            if isinstance(exc.__cause__, (r.ResumeError, asyncio.TimeoutError, NegativePassed)):
                raise exc.__cause__
            raise
        return result

    if negative == "replay-finish" and replay_finish is None:
        seeded = await attempt(False, None)
        if seeded.path != "resume":
            raise V1Error("replay-finish requires an eligible existing ticket")
        old = seeded._finish_c_for_test
        if not await client.reconnect_v1_peer():
            raise V1Error("could not reconnect original peer for replay test")
        return await run_session(client, profile, store=store, sas_callback=sas_callback,
            confirm_numeric_comparison=confirm_numeric_comparison, pairing_backend=pairing_backend,
            pairing_timeout=pairing_timeout, timeout=timeout, negative=negative, replay_finish=old)
    try:
        return await attempt(force_full, negative)
    except (r.ResumeError, asyncio.TimeoutError) as exc:
        if force_full or negative is not None:
            raise
        result.fallback_reason = getattr(getattr(exc, "reason", None), "name", "TIMEOUT")
        logger.warning("Resume failed (%s); reconnecting original peer for full handshake", result.fallback_reason)
        if not await client.reconnect_v1_peer():
            raise V1Error("could not reconnect original peer for full fallback") from exc
        return await attempt(True, None)
