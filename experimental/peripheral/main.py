#!/usr/bin/env python3
"""
PQ-BLE-HANDSHAKE — Peripheral (Server) Entry Point.

Usage:
    python -m src.peripheral.main

Starts the BLE peripheral, advertises the PQ-BLE GATT service,
waits for a central to connect and complete the handshake
(or resume an existing session via Strada A).
"""

import asyncio
import logging
import sys
import time

from src.common.logging_config import setup_logging
from src.common.constants import DEVICE_NAME, SESSION_STORE_PATH
from src.common.session_store import SessionStore
from experimental.peripheral.ble_server import BLEPeripheralServer
from experimental.peripheral.handshake import PeripheralHandshake
from experimental.peripheral.secure_channel import PeripheralSecureChannel

logger = logging.getLogger("pq-ble.peripheral.main")


async def main():
    setup_logging(logging.INFO)
    logger.info("═" * 50)
    logger.info("PQ-BLE-HANDSHAKE — Peripheral (Server)")
    logger.info("═" * 50)

    # ── Session store (persistent resume cache) ──────────────
    store = SessionStore(SESSION_STORE_PATH)
    logger.info("Session store: %d cached session(s).", store.count)
    if store.count > 0:
        for sid_hex, created_at, _usage in store.list_ids():
            age_h = (time.time() - created_at) / 3600
            logger.info("  Cached session %s... (%.1f h old)", sid_hex[:8], age_h)

    # ── Setup ───────────────────────────────────────────────
    server = BLEPeripheralServer(device_name=DEVICE_NAME)
    handshake = PeripheralHandshake(server, session_store=store)

    try:
        # ── Handshake (resume or full) ──────────────────────
        session_key = await handshake.run()

        session_id = handshake.session_id
        if session_id:
            logger.info("Session ID: %s...", session_id.hex()[:16])

        logger.info("✅ Handshake completato. Canale sicuro stabilito.")

        # ── Secure channel ──────────────────────────────────
        channel = PeripheralSecureChannel(session_key, server,
                                          session_id=session_id)

        logger.info("Secure channel ready. Type 'quit' to exit.")

        # ── Interactive loop ────────────────────────────────
        print()
        print("═══ Canale Sicuro PQ-BLE Attivo ═══")
        print(" Scrivi un messaggio e premi INVIO per inviarlo.")
        print(" 'quit' per uscire.")
        print()

        async def print_received():
            while True:
                msg = await channel.receive(timeout=0.5)
                if msg:
                    print(f"\n📩 Ricevuto: {msg.decode(errors='replace')}")

        recv_task = asyncio.create_task(print_received())

        loop = asyncio.get_event_loop()
        while True:
            try:
                message = await loop.run_in_executor(
                    None, lambda: input("📤 > ")
                )
                if message.lower() == "quit":
                    break
                if message.strip():
                    await channel.send(message.encode())
                    print(f"   Inviato {len(message)} byte cifrati")
            except EOFError:
                break

        recv_task.cancel()

    except RuntimeError as e:
        logger.error("Handshake failed: %s", e)
        return 1
    except KeyboardInterrupt:
        logger.info("Interrotto dall'utente.")
    finally:
        await server.stop()

    logger.info("Peripheral terminated.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))