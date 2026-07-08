#!/usr/bin/env python3
"""
PQ-BLE-HANDSHAKE — Central (Client) Entry Point.
Usage:
    python -m src.central.main [options]
Options:
    --device NAME        BLE device name to scan for (default: PQ-BLE-Device)
    --no-sas-confirm     Skip interactive SAS confirmation (auto-accept)
    --demo               Demo mode: send START on Control, wait for notify
    --mtu SIZE           Request specific MTU (default: negotiated by stack)
    --log-level LEVEL    Logging level: DEBUG, INFO, WARNING, ERROR (default: INFO)
"""
import argparse
import asyncio
import logging
import sys
import time
from ..common.logging_config import setup_logging
from ..common.constants import (
    DEVICE_NAME,
    SESSION_STORE_PATH,
    MSG_TYPE_DATA,
)
from ..common.session_store import SessionStore
from .ble_client import BLECentralClient
from .handshake import CentralHandshake
from .secure_channel import CentralSecureChannel

logger = logging.getLogger("pq-ble.central.main")

def parse_args():
    parser = argparse.ArgumentParser(
        description="PQ-BLE-HANDSHAKE Central (Client)"
    )
    parser.add_argument(
        "--device",
        default=DEVICE_NAME,
        help=f"BLE device name to scan for (default: {DEVICE_NAME})",
    )
    parser.add_argument(
        "--no-sas-confirm",
        action="store_true",
        help="Skip interactive SAS confirmation (auto-accept)",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Demo mode: send START on Control and wait for raw firmware notify",
    )
    parser.add_argument(
        "--mtu",
        type=int,
        default=None,
        help="Request specific MTU size (default: negotiated by stack)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (default: INFO)",
    )
    return parser.parse_args()

async def main():
    args = parse_args()
    level = getattr(logging, args.log_level)
    setup_logging(level)

    logger.info("═" * 50)
    logger.info("PQ-BLE-HANDSHAKE — Central (Client)")
    logger.info("═" * 50)
    logger.info("Device: %s | Demo: %s | MTU: %s",
                args.device, args.demo, args.mtu or "auto")

    # ── Session store (persistent resume cache) ──────────────
    store = SessionStore(SESSION_STORE_PATH)
    logger.info("Session store: %d cached session(s).", store.count)
    if store.count > 0:
        for sid_hex, created_at, _usage in store.list_ids():
            age_h = (time.time() - created_at) / 3600
            logger.info("  Cached session %s... (%.1f h old)", sid_hex[:8], age_h)

    # ── Phase 0: Connect ────────────────────────────────────
    client = BLECentralClient(device_name=args.device)

    logger.info("Scanning for peripheral '%s'...", args.device)
    connected = await client.scan_and_connect(timeout=15.0)

    if not connected:
        logger.error(
            "Could not find '%s'. Make sure the peripheral is running.\n"
            "  • nRF54L15 DK: flash firmware/nrf54l15_pq_gatt_skeleton/ and check LED\n"
            "  • Python (experimental, Linux only): PYTHONPATH=. python -m experimental.peripheral.main",
            args.device,
        )
        return 1

    channel = None

    try:
        # ── Handshake (resume or full) ──────────────────────
        handshake = CentralHandshake(client, session_store=store)

        # SAS callback: auto-accept if --no-sas-confirm
        sas_callback = None
        if args.no_sas_confirm:
            async def _auto_accept(sas, sas_str):
                logger.info("SAS: %s (auto-accepted via --no-sas-confirm)", sas_str)
                return True
            sas_callback = _auto_accept

        session_key = await handshake.run(sas_callback=sas_callback)

        session_id = handshake.session_id
        if session_id:
            logger.info("Session ID: %s...", session_id.hex()[:16])

        logger.info("✅ Handshake completato. Canale sicuro stabilito.")

        # ── Secure channel ──────────────────────────────────
        channel = CentralSecureChannel(session_key, client,
                                    session_id=session_id)

        # ── Demo mode: send START, wait for raw firmware notify ──
        if args.demo:
            logger.info("=== DEMO MODE: Sending START on Control ===")
            logger.info(
                "Hardware demo mode: notifications are received as raw bytes. "
                "The current nRF54L15 DK firmware validates BLE/GATT transport but "
                "does not perform on-chip ML-KEM/AES-GCM yet."
            )

            await channel.start_receiving(decrypt_notifications=False)

            await client.send_control(b"START")
            logger.info("START sent. Waiting for raw demo notification...")

            msg = await channel.receive(timeout=10.0)
            if msg:
                logger.info("✅ Raw demo notification received: %d bytes", len(msg))
                logger.debug("Raw demo notification hex: %s", msg.hex())

                print()
                print("📩 Raw demo notification received")
                print(f"   Length: {len(msg)} bytes")
                print(f"   HEX: {msg.hex()}")
                print()
                print("✅ BLE/GATT transport validation completed.")
            else:
                logger.error("No notification received within timeout.")

            return 0

        # Normal secure-channel mode
        await channel.start_receiving(decrypt_notifications=True)

        # ── Interactive loop ────────────────────────────────
        logger.info("Secure channel ready. Type 'quit' to exit.")
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
        if channel is not None:
            await channel.stop()
        await client.disconnect()

    logger.info("Central terminated.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
