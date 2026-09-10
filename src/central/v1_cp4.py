"""Two CP4 application rounds on the connection that completes CP3."""

import asyncio
from dataclasses import dataclass
import logging
import secrets

from ..common.v1_cp3 import clear
from ..common.v1_cp4 import CentralApplication
from .v1_cp3 import V1CP3Result, _cp3_exchange
from .v1_smp_mlkem import V1Error, _run_v1

logger = logging.getLogger("pq-ble.central.v1-cp4")


@dataclass
class V1CP4Result(V1CP3Result):
    authenticated_rounds: int = 0


async def _cp4_exchange(client, notifications, notification_handler, *,
                       notification_timeout, quiet, result):
    app = None
    link = None
    reply = None

    def require_live():
        if (app is None or app.handshake.state != "APP_SECURE" or
                client._v1_cp3_session is not app.handshake or not client.is_connected or
                client.raw_client is not link or client._v1_cp3_link is not link or
                getattr(client, "_v1_notify_link", None) is not link):
            raise V1Error("CP4 connection/session/subscription invalidated")

    def on_application(_sender, data):
        try:
            require_live()
            if reply is None or reply.done():
                raise V1Error("unsolicited or duplicate CP4 notification")
            reply.set_result(bytes(data))
        except BaseException as exc:
            if app is not None:
                app.clear()
            if reply is not None and not reply.done():
                reply.set_exception(exc)

    async def rounds(client, handshake):
        nonlocal app, link, reply
        link = client.raw_client
        app = CentralApplication(handshake)
        client._v1_cp4_session = app
        try:
            for seq in range(2):
                challenge = bytearray()
                try:
                    require_live()
                    challenge = bytearray(secrets.token_bytes(16))
                    frame = app.encrypt_ping(challenge, client.mtu_size)
                    reply = asyncio.get_running_loop().create_future()
                    # A blocked/failed write retires the already-consumed nonce.
                    await asyncio.wait_for(client.send_control(frame), notification_timeout)
                    require_live()
                    logger.info("CP4 C2P PING seq=%d: SENT", seq)
                    raw = await asyncio.wait_for(reply, notification_timeout)
                    require_live()
                    app.accept_pong(raw, challenge, client.mtu_size)
                    reply = None
                    logger.info("CP4 P2C PONG seq=%d: AUTHENTICATED", seq)
                    result.authenticated_rounds += 1
                finally:
                    clear(challenge)
            # Let queued duplicates invalidate the session before reporting PASS.
            await asyncio.sleep(quiet)
            require_live()
            logger.info("Application state: APP_SECURE")
        except BaseException:
            app.clear()
            raise
        finally:
            if reply is not None:
                if not reply.done():
                    reply.cancel()
                elif not reply.cancelled():
                    reply.exception()  # Retrieve errors even if the write failed first.
            reply = None

    try:
        return await _cp3_exchange(client, notifications, notification_handler,
            notification_timeout=notification_timeout, quiet=quiet, result=result,
            application_exchange=rounds, application_notification=on_application)
    except BaseException:
        if app is not None:
            app.clear()
        raise


async def run_v1_cp4(client, **kwargs) -> V1CP4Result:
    if kwargs.get("negative_test") is not None:
        raise ValueError("CP1 negative modes cannot be combined with CP4")
    try:
        return await _run_v1(client, **kwargs, post_l4_exchange=_cp4_exchange,
                            result_type=V1CP4Result, checkpoint="CP4", retain_notify=True)
    except BaseException:
        for name in ("_v1_cp4_session", "_v1_cp3_session"):
            session = getattr(client, name, None)
            if session is not None:
                session.clear()
        raise
