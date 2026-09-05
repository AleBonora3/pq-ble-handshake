#!/usr/bin/env python3
"""
PQ-BLE-HANDSHAKE — Central (Client) Entry Point.
Usage:
    python -m src.central.main [options]
Options:
    --device NAME        BLE device name to scan for (default: PQ-BLE-Device)
    --no-sas-confirm     Skip interactive SAS confirmation (auto-accept)
    --demo               Legacy demo: send START, wait for raw notify
    --phase2-e2e         Run ML-KEM-768 liboqs/mlkem-native BLE interop test
    --phase3-secure      Run ML-KEM + HKDF + AES-256-GCM real-DK test
    --phase5-auth-pq     Run authenticated pure-PQ v0.5 hardware handshake
    --phase5-negative    Run an isolated Phase 5 negative hardware test
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
)
from .ble_client import BLECentralClient
from .mlkem_e2e import Phase2E2EError, run_phase2_e2e
from .phase3_secure import Phase3SecureError, run_phase3_secure
from .phase5_auth import (
    PHASE5_NEGATIVE_MODES,
    Phase5AuthError,
    Phase5NegativeTestFailed,
    Phase5NegativeTestPassed,
    run_phase5_auth_pq,
)
from .phase6_c2p import (
    Phase6C2PError,
    run_phase6_c2p,
)

logger = logging.getLogger("pq-ble.central.main")


def _load_legacy_components():
    """Import the legacy full-handshake stack only when that mode is used."""
    from ..common.session_store import SessionStore
    from .handshake import CentralHandshake
    from .secure_channel import CentralSecureChannel

    return SessionStore, CentralHandshake, CentralSecureChannel


def parse_args(argv=None):
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
        help=(
            "Skip interactive SAS confirmation in the legacy flow only; "
            "not permitted with --phase5-auth-pq"
        ),
    )
    execution_mode = parser.add_mutually_exclusive_group()
    execution_mode.add_argument(
        "--demo",
        action="store_true",
        help=(
            "Legacy/deprecated demo: send START on Control and wait for an "
            "unparsed raw firmware notification"
        ),
    )
    execution_mode.add_argument(
        "--phase2-e2e",
        action="store_true",
        help=(
            "Phase 2 ML-KEM-768 BLE interoperability test "
            "(liboqs Central to mlkem-native DK)"
        ),
    )
    execution_mode.add_argument(
        "--phase3-secure",
        action="store_true",
        help=(
            "Phase 3 real-hardware PQ secure-channel test "
            "(ML-KEM + HKDF-SHA256 + AES-256-GCM)"
        ),
    )
    execution_mode.add_argument(
        "--phase5-auth-pq",
        action="store_true",
        help=(
            "Authenticated pure-PQ v0.5 hardware handshake "
            "(transcript + SAS + bidirectional FINISHED + AES-GCM)"
        ),
    )

    execution_mode.add_argument(
        "--phase6-c2p",
        action="store_true",
        help=(
            "v0.6 Checkpoint 2: authenticated "
            "Central-to-Peripheral AES-256-GCM traffic"
        ),
    )

    parser.add_argument(
        "--phase3-negative",
        choices=("tamper", "aad", "replay"),
        default=None,
        help=(
            "Run an optional Phase 3 negative test: "
            "'tamper' flips one AES-GCM tag bit; "
            "'aad' uses a wrong session_id; "
            "'replay' submits the authenticated frame twice"
        ),
    )

    parser.add_argument(
        "--phase5-negative",
        choices=PHASE5_NEGATIVE_MODES,
        default=None,
        help=(
            "Run an isolated Phase 5 negative test: "
            "'finished-c', 'finished-p', or 'transcript'"
        ),
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
    return parser.parse_args(argv)


async def _run_phase2_e2e_cli(args) -> int:
    """Run Phase 2 without constructing any legacy handshake state."""
    client = BLECentralClient(device_name=args.device)
    logger.info("Scanning for peripheral '%s'...", args.device)
    try:
        connected = await client.scan_and_connect(timeout=15.0)
    except Exception as exc:
        logger.error("Phase 2 BLE scan/connect failed: %s", exc)
        try:
            await client.disconnect()
        except Exception as disconnect_exc:
            logger.warning(
                "Phase 2 disconnect after connect failure failed: %s",
                disconnect_exc,
            )
        return 1
    if not connected:
        logger.error(
            "Could not find '%s'. Make sure the Phase 2 firmware is running.",
            args.device,
        )
        return 1

    try:
        logger.info("=== PHASE 2 E2E: liboqs Central -> mlkem-native DK ===")
        result = await run_phase2_e2e(client)
        if not result.matches:
            raise Phase2E2EError(
                "Phase 2 runner returned mismatched diagnostic checksums"
            )

        print()
        print(
            "Central TEST-ONLY shared-secret diagnostic checksum: "
            f"0x{result.central_checksum:08X}"
        )
        print(
            "Peripheral TEST-ONLY shared-secret diagnostic checksum: "
            f"0x{result.peripheral_checksum:08X}"
        )
        print("ML-KEM E2E SHARED SECRET MATCH: YES")
        print()
        print(
            "The TEST-ONLY shared-secret diagnostic checksum is not "
            "authentication, not a KDF, not cryptographic key confirmation, "
            "and not part of the final protocol."
        )
        return 0
    except (Phase2E2EError, RuntimeError) as exc:
        logger.error("Phase 2 E2E failed: %s", exc)
        print("ML-KEM E2E SHARED SECRET MATCH: NO")
        return 1
    except Exception as exc:
        logger.error("Phase 2 E2E transport/encapsulation failed: %s", exc)
        print("ML-KEM E2E SHARED SECRET MATCH: NO")
        return 1
    finally:
        try:
            await client.disconnect()
        except Exception as exc:
            logger.warning("Phase 2 disconnect failed: %s", exc)

async def _run_phase3_secure_cli(args) -> int:
    """Run Phase 3 without constructing legacy handshake/session state."""

    client = BLECentralClient(device_name=args.device)

    logger.info("Scanning for peripheral '%s'...", args.device)

    try:
        connected = await client.scan_and_connect(timeout=15.0)
    except Exception as exc:
        logger.error("Phase 3 BLE scan/connect failed: %s", exc)
        try:
            await client.disconnect()
        except Exception as disconnect_exc:
            logger.warning(
                "Phase 3 disconnect after connect failure failed: %s",
                disconnect_exc,
            )
        return 1

    if not connected:
        logger.error(
            "Could not find '%s'. Make sure the Phase 3 firmware is running.",
            args.device,
        )
        return 1

    try:
        logger.info(
            "=== PHASE 3 SECURE CHANNEL: "
            "ML-KEM + HKDF-SHA256 + AES-256-GCM ==="
        )

        result = await run_phase3_secure(
            client,
            negative_test=args.phase3_negative,
        )

        print()
        print("ML-KEM key establishment: PASS")
        print("HKDF-SHA256 session-key derivation: PASS")
        print("AES-256-GCM authentication: PASS")
        print(
            "Decrypted payload: "
            f"{result.plaintext.decode('ascii')}"
        )
        print(
            f"Authenticated secure-wire length: "
            f"{result.wire_size} bytes"
        )
        print()
        print("PQ-BLE SECURE CHANNEL E2E: PASS")
        print()

        return 0

    except Phase3SecureError as exc:
        logger.error("Phase 3 secure channel failed: %s", exc)

        print()
        print("PQ-BLE SECURE CHANNEL E2E: FAIL")
        print()

        return 1

    except Exception as exc:
        logger.exception(
            "Unexpected Phase 3 transport/crypto failure: %s",
            exc,
        )

        print()
        print("PQ-BLE SECURE CHANNEL E2E: FAIL")
        print()

        return 1

    finally:
        try:
            await client.disconnect()
        except Exception as exc:
            logger.warning("Phase 3 disconnect failed: %s", exc)


async def _run_phase5_auth_pq_cli(args) -> int:
    """Run the isolated authenticated pure-PQ v0.5 path."""

    client = BLECentralClient(device_name=args.device)
    logger.info("Scanning for peripheral '%s'...", args.device)
    try:
        connected = await client.scan_and_connect(timeout=15.0)
    except Exception as exc:
        logger.error("Phase 5 BLE scan/connect failed: %s", exc)
        try:
            await client.disconnect()
        except Exception as disconnect_exc:
            logger.warning(
                "Phase 5 disconnect after connect failure failed: %s",
                disconnect_exc,
            )
        return 1

    if not connected:
        logger.error(
            "Could not find '%s'. Make sure the v0.5 firmware is running.",
            args.device,
        )
        return 1

    try:
        logger.info("=== v0.5 AUTHENTICATED PURE-PQ HANDSHAKE ===")
        result = await run_phase5_auth_pq(
            client,
            negative_test=args.phase5_negative,
        )

        if args.phase5_negative is not None:
            raise Phase5NegativeTestFailed(
                "NEGATIVE TEST FAIL: corrupted authentication unexpectedly "
                "completed"
            )

        print()
        print("Central FINISHED sent")
        print("Peripheral FINISHED verified: PASS")
        print("Authenticated PQ handshake: PASS")
        print("AES-256-GCM authentication: PASS")
        print(f"Decrypted payload: {result.plaintext.decode('ascii')}")
        print()
        print("PQ-BLE AUTHENTICATED HANDSHAKE E2E: PASS")
        print()
        return 0
    except Phase5NegativeTestPassed as exc:
        print()
        print(str(exc))
        print("PQ-BLE PHASE5 NEGATIVE TEST: PASS")
        print()
        return 0
    except Phase5AuthError as exc:
        logger.error("Phase 5 authenticated handshake failed: %s", exc)
        print()
        if args.phase5_negative is not None:
            if not isinstance(exc, Phase5NegativeTestFailed):
                print(f"NEGATIVE TEST FAIL: {exc}")
            else:
                print(str(exc))
            print("PQ-BLE PHASE5 NEGATIVE TEST: FAIL")
        else:
            print("PQ-BLE AUTHENTICATED HANDSHAKE E2E: FAIL")
        print()
        return 1
    except Exception as exc:
        logger.exception("Unexpected Phase 5 failure: %s", exc)
        print()
        if args.phase5_negative is not None:
            print(f"NEGATIVE TEST FAIL: unexpected error: {exc}")
            print("PQ-BLE PHASE5 NEGATIVE TEST: FAIL")
        else:
            print("PQ-BLE AUTHENTICATED HANDSHAKE E2E: FAIL")
        print()
        return 1
    finally:
        try:
            await client.disconnect()
        except Exception as exc:
            logger.warning("Phase 5 disconnect failed: %s", exc)

async def _run_phase6_c2p_cli(args) -> int:
    """Run v0.6 Checkpoint 2 on the real DK."""

    client = BLECentralClient(
        device_name=args.device
    )

    logger.info(
        "Scanning for peripheral '%s'...",
        args.device,
    )

    try:
        connected = await client.scan_and_connect(
            timeout=15.0
        )
    except Exception as exc:
        logger.error(
            "Phase 6 BLE scan/connect failed: %s",
            exc,
        )

        try:
            await client.disconnect()
        except Exception as disconnect_exc:
            logger.warning(
                "Phase 6 disconnect after "
                "connect failure failed: %s",
                disconnect_exc,
            )

        return 1

    if not connected:
        logger.error(
            "Could not find '%s'. "
            "Make sure the v0.6 firmware is running.",
            args.device,
        )

        return 1

    try:
        logger.info(
            "=== v0.6 CHECKPOINT 2: "
            "AUTHENTICATED C->P SECURE TRAFFIC ==="
        )

        result = await run_phase6_c2p(
            client
        )

        print()
        print(
            "Authenticated PQ handshake: PASS"
        )
        print(
            "Directional traffic keys derived: PASS"
        )
        print(
            f"Central secure message sent: "
            f"{result.plaintext_sent.decode('ascii')}"
        )
        print(
            f"C->P sequence: {result.sequence}"
        )
        print(
            f"C->P secure-wire length: "
            f"{result.wire_size} bytes"
        )
        print(
            "Peripheral AES-GCM verification: PASS"
        )
        print()
        print(
            "PQ-BLE PHASE6 C->P SECURE TRAFFIC: PASS"
        )
        print()

        return 0

    except Phase6C2PError as exc:
        logger.error(
            "Phase 6 C->P failed: %s",
            exc,
        )

        print()
        print(
            "PQ-BLE PHASE6 C->P "
            "SECURE TRAFFIC: FAIL"
        )
        print()

        return 1

    except Exception as exc:
        logger.exception(
            "Unexpected Phase 6 failure: %s",
            exc,
        )

        print()
        print(
            "PQ-BLE PHASE6 C->P "
            "SECURE TRAFFIC: FAIL"
        )
        print()

        return 1

    finally:
        try:
            await client.disconnect()
        except Exception as exc:
            logger.warning(
                "Phase 6 disconnect failed: %s",
                exc,
            )

async def main():
    args = parse_args()
    level = getattr(logging, args.log_level)
    setup_logging(level)

    logger.info("=" * 50)
    logger.info("PQ-BLE-HANDSHAKE — Central (Client)")
    logger.info("=" * 50)
    logger.info(
        "Device: %s | Demo: %s | Phase 2 E2E: %s | "
        "Phase 3 Secure: %s | Phase 5 Auth PQ: %s | MTU: %s",
        args.device,
        args.demo,
        args.phase2_e2e,
        args.phase3_secure,
        getattr(args, "phase5_auth_pq", False),
        args.mtu or "auto",
    )

    if args.phase3_negative is not None and not args.phase3_secure:
        logger.error(
            "--phase3-negative can only be used with --phase3-secure"
        )
        return 2

    if (getattr(args, "phase5_negative", None) is not None
            and not getattr(args, "phase5_auth_pq", False)):
        logger.error(
            "--phase5-negative can only be used with --phase5-auth-pq"
        )
        return 2

    if (
        (
            getattr(
                args,
                "phase5_auth_pq",
                False,
            )
            or getattr(
                args,
                "phase6_c2p",
                False,
            )
        )
        and args.no_sas_confirm
    ):
        logger.error(
            "--no-sas-confirm is not allowed with "
            "--phase5-auth-pq or --phase6-c2p; "
            "explicit human SAS confirmation is required"
        )
        return 2
    
    if getattr(args, "phase6_c2p", False):
        return await _run_phase6_c2p_cli(args)
    
    if getattr(args, "phase5_auth_pq", False):
        return await _run_phase5_auth_pq_cli(args)

    if args.phase3_secure:
        return await _run_phase3_secure_cli(args)
    
    # Exit through the isolated path before constructing SessionStore,
    # CentralHandshake, SAS/HKDF, CentralSecureChannel, or persistence state.
    if args.phase2_e2e:
        return await _run_phase2_e2e_cli(args)

    SessionStore, CentralHandshake, CentralSecureChannel = _load_legacy_components()

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

        if args.demo:
            logger.info(
                "[OK] Central-side ML-KEM encapsulation and session-key "
                "derivation completed. BLE/GATT transport demo ready."
            )
        else:
            logger.info("[OK] Handshake completato. Canale sicuro stabilito.")

        # ── Secure channel ──────────────────────────────────
        channel = CentralSecureChannel(session_key, client,
                                    session_id=session_id)

        # ── Demo mode: send START, wait for raw firmware notify ──
        if args.demo:
            logger.warning(
                "=== LEGACY/DEPRECATED DEMO MODE === Use --phase2-e2e to "
                "validate the Phase 2 PQM2 interoperability result."
            )
            logger.info(
                "Legacy demo notifications are received as raw bytes and are "
                "not parsed or verified as a PQM2 result."
            )

            await channel.start_receiving(decrypt_notifications=False)

            await client.send_control(b"START")
            logger.info("START sent. Waiting for raw demo notification...")

            msg = await channel.receive(timeout=10.0)
            if msg:
                logger.info("[OK] Raw demo notification received: %d bytes", len(msg))
                logger.debug("Raw demo notification hex: %s", msg.hex())

                print()
                print("Raw demo notification received")
                print(f"   Length: {len(msg)} bytes")
                print(f"   HEX: {msg.hex()}")
                print()
                print("[OK] BLE/GATT transport validation completed.")
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
                    print(f"\nRicevuto: {msg.decode(errors='replace')}")

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
