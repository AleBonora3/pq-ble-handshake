"""Explicit CP3 runner. CP1 supplies human SMP pairing; CP3 sends no app data."""

import asyncio
from dataclasses import dataclass
import logging
import secrets
import time

from ..common.constants import PK_SIZE, CT_SIZE, SS_SIZE
from ..common.ml_kem import encapsulate
from ..common.v1_cp3 import CentralHandshake, clear
from ..common.v1_smp_mlkem import (
    V1_START_CP3, V1_READY_CP3, V1_FINISHED_P, V1_SEC_INFO, V1_ERROR,
    encode_sec_query, encode_v1_frame, parse_v1_frame, parse_sec_info,
    is_authenticated_level4,
)
from .v1_smp_mlkem import V1CP1Result, V1Error, _run_v1

logger = logging.getLogger("pq-ble.central.v1-cp3")
CP3_TIMEOUT = 30.0


@dataclass
class V1CP3Result(V1CP1Result):
    start_sent: bool = False
    transcript_match: bool = False
    finished_c_sent: bool = False
    finished_p_verified: bool = False
    app_secure: bool = False  # evidence of reaching APP_SECURE; not a key container


async def _exchange(client, notifications, notification_handler, *,
                    notification_timeout, quiet, result):
    started = time.perf_counter()
    link = client.raw_client
    secret = bytearray()
    session = CentralHandshake()
    if getattr(client, "_v1_cp3_session", None) is not None:
        raise V1Error("CP3 transaction already exists; reconnect first")
    client._v1_cp3_session = session
    client._v1_cp3_link = link

    def require_same_link():
        if (link is None or not client.is_connected or client.raw_client is not link
                or session.state == "CLOSED"):
            raise V1Error("CP3 connection lost or replaced; refusing to continue")

    loop = asyncio.get_running_loop()

    def deliver_notification(sender, data):
        # Also retire keys on unsolicited messages after the exchange returns.
        # The captured session/link cannot affect a later connection's owner.
        if session.state == "APP_SECURE" or client.raw_client is not link or not client.is_connected:
            session.clear()
        notification_handler(sender, data)

    def on_notification(sender, data):
        loop.call_soon_threadsafe(deliver_notification, sender, bytes(data))

    async def receive(subtype, name):
        require_same_link()
        try:
            raw = await asyncio.wait_for(notifications.get(), notification_timeout)
        except asyncio.TimeoutError as exc:
            raise V1Error(f"CP3 timed out waiting for {name}") from exc
        require_same_link()
        frame = parse_v1_frame(raw)
        if frame.subtype == V1_ERROR:
            raise V1Error(f"DK CP3 ERROR 0x{frame.payload[0]:02x}")
        if frame.subtype != subtype:
            raise V1Error(f"CP3 expected {name}, got subtype 0x{frame.subtype:02x}")
        return raw

    async def attest():
        require_same_link()
        if not notifications.empty():
            raise V1Error("unsolicited CP3 notification before SEC_QUERY")
        await client.send_control(encode_sec_query())
        raw = await receive(V1_SEC_INFO, "SEC_INFO")
        info = parse_sec_info(raw)
        if not is_authenticated_level4(info):
            raise V1Error(f"CP3 requires strict Level 4 ({info.describe()})")
        logger.info("DK security attestation: %s", info.describe())
        return raw, info

    async def guard_notifications_and_link():
        # The transport's disconnect callback wipes immediately. This guard
        # also catches connection replacement and model/test transports.
        while True:
            require_same_link()
            await asyncio.sleep(0.02)

    guard = asyncio.create_task(guard_notifications_and_link())
    current = asyncio.current_task()

    def guard_done(task):
        if not task.cancelled() and task.exception() is not None:
            current.cancel()

    guard.add_done_callback(guard_done)
    success = False
    try:
        require_same_link()
        await client.start_notify(on_notification)
        await attest()
        pk = bytes(await client.read_fragmented_public_key())
        require_same_link()
        if len(pk) != PK_SIZE:
            raise V1Error("ML-KEM public key must be 1184 bytes")
        result.public_key_len = len(pk)
        ct, raw_secret = encapsulate(pk)
        secret = raw_secret if isinstance(raw_secret, bytearray) else bytearray(raw_secret)
        del raw_secret
        if len(ct) != CT_SIZE or len(secret) != SS_SIZE:
            raise V1Error("invalid ML-KEM-768 ciphertext/shared-secret size")
        require_same_link()
        result.ciphertext_fragments = await client.write_fragmented_ciphertext(ct) or 0
        require_same_link()
        sec, info = await attest()  # exact SECOND attestation goes into T0
        start = encode_v1_frame(V1_START_CP3, secrets.token_bytes(16))
        session.begin(secret, sec, pk, ct, start)
        await asyncio.sleep(0)
        require_same_link()
        if not notifications.empty():
            raise V1Error("unsolicited CP3 notification before START_CP3")
        await client.send_control(start)
        require_same_link()
        result.start_sent = True
        logger.info("START_CP3: SENT")
        ready = await receive(V1_READY_CP3, "READY_CP3")
        finished_c = session.accept_ready(ready)
        result.transcript_match = True
        logger.info("READY_CP3: RECEIVED; Transcript hash match: YES")
        await asyncio.sleep(0)
        require_same_link()
        if not notifications.empty():
            raise V1Error("unsolicited CP3 notification before FINISHED_C")
        await client.send_control(finished_c)
        require_same_link()
        result.finished_c_sent = True
        logger.info("FINISHED_C: SENT")
        finished_p = await receive(V1_FINISHED_P, "FINISHED_P")
        session.accept_finished_p(finished_p)
        clear(secret)
        logger.info("FINISHED_P: RECEIVED; FINISHED_P verification on Central: PASS")
        # Reject duplicate/unsolicited replies before reporting success.
        try:
            await asyncio.wait_for(notifications.get(), quiet)
        except asyncio.TimeoutError:
            pass
        else:
            raise V1Error("unexpected extra notification after FINISHED_P")
        require_same_link()
        result.finished_p_verified = True
        result.app_secure = True
        result.post_l4_ms = (time.perf_counter() - started) * 1000.0
        logger.info("K_APP_C2P derived; K_APP_P2C derived (values never logged)")
        logger.info("Application state: APP_SECURE")
        success = True
        return info
    except asyncio.CancelledError:
        if guard.done() and not guard.cancelled() and guard.exception() is not None:
            raise V1Error("CP3 connection lost or replaced") from guard.exception()
        raise
    finally:
        # Erase before awaiting cancellation cleanup, even if a caller cancels twice.
        clear(secret)
        if not success:
            session.clear()
        guard.remove_done_callback(guard_done)
        guard.cancel()
        await asyncio.gather(guard, return_exceptions=True)
        logger.info("v1 CP3 Central temporary handshake secrets cleared")


async def _cp3_exchange(*args, **kwargs):
    try:
        return await asyncio.wait_for(_exchange(*args, **kwargs), CP3_TIMEOUT)
    except asyncio.TimeoutError as exc:
        raise V1Error("CP3 absolute handshake timeout") from exc


async def run_v1_cp3(client, **kwargs) -> V1CP3Result:
    if kwargs.get("negative_test") is not None:
        raise ValueError("CP1 negative modes cannot be combined with CP3")
    try:
        return await _run_v1(client, **kwargs, post_l4_exchange=_cp3_exchange,
                            result_type=V1CP3Result, checkpoint="CP3", retain_notify=True)
    except BaseException:
        session = getattr(client, "_v1_cp3_session", None)
        if session is not None:
            session.clear()
        raise
