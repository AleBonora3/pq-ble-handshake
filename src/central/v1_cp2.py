"""TEST ONLY: ML-KEM interoperability over the existing CP1 SMP-L4 path."""

import asyncio
from dataclasses import dataclass
import hmac
import logging
import secrets
import time

from ..common.constants import CT_SIZE, PK_SIZE, SS_SIZE
from ..common.ml_kem import encapsulate
from ..common.v1_cp2 import clear, compute_diagnostic
from ..common.v1_smp_mlkem import (
    V1_CP2_SESSION_ID_SIZE, V1_ERROR, V1_READY, V1_SEC_INFO, V1_START,
    V1_STATUS_NAMES, encode_sec_query, encode_v1_frame, is_authenticated_level4,
    parse_sec_info, parse_v1_frame,
)
from .v1_smp_mlkem import V1CP1Result, V1Error, _run_v1

logger = logging.getLogger("pq-ble.central.v1-cp2")


@dataclass
class V1CP2Result(V1CP1Result):
    diagnostic_match: bool = False
    start_sent: bool = False
    ready_received: bool = False


async def _cp2_exchange(
    client, notifications, notification_handler, *, notification_timeout, quiet,
    result: V1CP2Result,
):
    started = time.perf_counter()
    # No reconnect is allowed after this snapshot. CP1 may restore a bond
    # before entering this stage, but a replacement invalidates the whole CP2.
    link = client.raw_client
    secret = bytearray()
    expected = bytearray()

    def require_same_link():
        if link is None or not client.is_connected or client.raw_client is not link:
            raise V1Error("CP2 connection lost or replaced; refusing to continue")

    async def receive(subtype, name):
        try:
            raw = await asyncio.wait_for(notifications.get(), notification_timeout)
        except asyncio.TimeoutError as exc:
            raise V1Error(f"CP2 timed out waiting for {name}") from exc
        require_same_link()
        frame = parse_v1_frame(raw)
        if frame.subtype == V1_ERROR:
            status = frame.payload[0]
            raise V1Error(f"DK CP2 ERROR 0x{status:02x}: {V1_STATUS_NAMES.get(status, 'unknown')}")
        if frame.subtype != subtype:
            raise V1Error(f"CP2 expected {name}, received subtype 0x{frame.subtype:02x}")
        return raw, frame.payload

    async def attest():
        require_same_link()
        if not notifications.empty():
            raise V1Error("unsolicited CP2 notification before SEC_QUERY")
        await client.send_control(encode_sec_query())
        raw, _ = await receive(V1_SEC_INFO, "SEC_INFO")
        info = parse_sec_info(raw)
        if not is_authenticated_level4(info):
            raise V1Error(f"CP2 requires strict authenticated Level 4 ({info.describe()})")
        logger.info("DK security attestation: %s", info.describe())
        return info

    try:
        require_same_link()
        await client.start_notify(notification_handler)
        info = await attest()  # mandatory before any ML-KEM encapsulation
        public_key = bytes(await client.read_fragmented_public_key())
        require_same_link()
        if len(public_key) != PK_SIZE:
            raise V1Error(f"ML-KEM public key must be {PK_SIZE} bytes, got {len(public_key)}")
        result.public_key_len = len(public_key)
        ciphertext, raw_secret = encapsulate(public_key)
        secret = raw_secret if isinstance(raw_secret, bytearray) else bytearray(raw_secret)
        del raw_secret  # liboqs's bytes result cannot be securely erased by Python
        if len(ciphertext) != CT_SIZE or len(secret) != SS_SIZE:
            raise V1Error("invalid ML-KEM-768 ciphertext/shared-secret size")
        require_same_link()
        result.ciphertext_fragments = await client.write_fragmented_ciphertext(ciphertext) or 0
        session_id = secrets.token_bytes(V1_CP2_SESSION_ID_SIZE)
        expected = compute_diagnostic(secret, session_id, public_key, ciphertext)
        # Re-attest after CT transfer, immediately before START. The DK also
        # checks its authoritative live gate at START and READY delivery.
        info = await attest()
        await asyncio.sleep(0)  # drain thread-safe callback dispatch
        require_same_link()
        if not notifications.empty():
            raise V1Error("unsolicited CP2 notification before START_V1")
        await client.send_control(encode_v1_frame(V1_START, session_id))
        result.start_sent = True
        logger.info("START_V1: SENT (24 B)")
        _, received = await receive(V1_READY, "READY_V1")
        result.ready_received = True
        logger.info("READY_V1: RECEIVED (40 B)")
        if not hmac.compare_digest(expected, received):
            raise V1Error("CP2 diagnostic mismatch; fail closed")
        # A duplicate/unsolicited response must not turn into a later session.
        try:
            await asyncio.wait_for(notifications.get(), quiet)
        except asyncio.TimeoutError:
            pass
        else:
            raise V1Error("unexpected extra notification after READY_V1")
        require_same_link()
        result.diagnostic_match = True
        result.post_l4_ms = (time.perf_counter() - started) * 1000.0
        logger.info("CP2 diagnostic match: YES (TEST ONLY; no application keys)")
        return info
    finally:
        clear(secret)
        clear(expected)
        logger.info("v1 CP2 Central temporary secret buffers cleared")


async def run_v1_cp2(client, **kwargs) -> V1CP2Result:
    """Reuse CP1 pairing/gating, replacing only its post-L4 access exercise."""
    if kwargs.get("negative_test") is not None:
        raise ValueError("CP1 negative modes cannot be combined with CP2")
    return await _run_v1(
        client, **kwargs, post_l4_exchange=_cp2_exchange,
        result_type=V1CP2Result, checkpoint="CP2",
    )
