"""
Peripheral-side PQ Handshake Logic.

Orchestrates the peripheral side with optional session
resumption (Strada A).

Flow:
  1. Generate ML-KEM-768 keypair (always, in case resume fails)
  2. Expose public key on GATT, start advertising
  3a. IF a RESUME_REQUEST arrives on CONTROL:
      - Look up session_id in SessionStore
      - If found: notify RESUME_OK on DATA, return saved session_key
      - If not found: notify RESUME_FAIL on DATA, continue to 3b
  3b. Wait for ciphertext from central
  4. Decapsulate → shared_secret
  5. Derive SAS, present to user, wait for confirmation
  6. Derive session key via HKDF
  7. Save (session_id, session_key) in SessionStore
"""

import asyncio
import logging
from typing import Optional

from src.common.ml_kem import generate_keypair, decapsulate
from src.common.sas import derive_sas, format_sas
from src.common.session import (
    derive_session_key,
    generate_session_id,
    parse_control_message,
)
from src.common.session_store import SessionStore
from src.common.constants import (
    PK_SIZE,
    CT_SIZE,
    SS_SIZE,
    RESUME_OK_NOTIFY,
    RESUME_FAIL_NOTIFY,
)
from experimental.peripheral.ble_server import BLEPeripheralServer

logger = logging.getLogger("pq-ble.peripheral.handshake")


class PeripheralHandshake:
    """
    Peripheral-side PQ handshake.

    Supports session resumption (Strada A): when a central
    sends a RESUME_REQUEST via the CONTROL characteristic,
    the peripheral looks up the session_id in its SessionStore
    and replies with RESUME_OK (reusing the stored key) or
    RESUME_FAIL (forcing a full handshake).
    """

    def __init__(
        self,
        server: BLEPeripheralServer,
        session_store: Optional[SessionStore] = None,
    ):
        self._server = server
        self._store = session_store
        self._secret_key: Optional[bytes] = None
        self._public_key: Optional[bytes] = None
        self._shared_secret: Optional[bytes] = None
        self._session_key: Optional[bytes] = None
        self._session_id: Optional[bytes] = None

        # Signals
        self._ciphertext_received = asyncio.Event()
        self._resume_requested = asyncio.Event()
        self._resume_session_id: Optional[bytes] = None

    # ── public API ─────────────────────────────────────────

    async def run(self, sas_callback=None) -> bytes:
        """
        Execute the peripheral-side handshake.

        Returns:
            32-byte session key.
        """
        # ── Step 1: Always generate a keypair ──────────────
        logger.info("=== PHASE 1: ML-KEM-768 key generation ===")
        pk, sk = generate_keypair()

        if len(pk) != PK_SIZE:
            raise RuntimeError(
                f"Public key size: expected {PK_SIZE}, got {len(pk)}"
            )

        self._secret_key = sk
        self._public_key = pk
        logger.info("Keypair generated. pk=%d bytes, sk=%d bytes ✓",
                     len(pk), len(sk))

        # ── Step 2: Expose public key and start server ─────
        logger.info("=== PHASE 2: Starting GATT server ===")
        self._server.set_public_key(pk)

        # Register callbacks
        self._server.on_ciphertext(self._on_ciphertext_received)
        self._server.on_control(self._on_control_received)

        server_task = asyncio.create_task(self._server.start())

        # ── Step 3: Wait for ciphertext OR resume request ──
        logger.info("=== PHASE 3: Waiting for central... ===")
        try:
            await self._wait_for_either_or(
                event_a=self._ciphertext_received,
                event_b=self._resume_requested,
                timeout=120.0,
            )
        except asyncio.TimeoutError:
            server_task.cancel()
            raise RuntimeError(
                "Timeout waiting for central (no ciphertext or resume request)"
            )

        # ── Branch: resume accepted ────────────────────────
        if self._resume_requested.is_set() and self._store is not None:
            sid = self._resume_session_id
            if sid is not None:
                session_key = self._store.load(sid)
                if session_key is not None:
                    logger.info(
                        "✅ Session resumed (id=%s...).",
                        sid.hex()[:8],
                    )
                    self._session_key = session_key
                    self._session_id = sid
                    return session_key

            # Should not reach here — we already sent RESUME_OK
            # only if the key was found.  Fall through.
            logger.warning("Resume request handled but key not found; "
                           "falling back to full handshake.")

        # ── Branch: full handshake ─────────────────────────

        ciphertext = self._server.ciphertext
        if len(ciphertext) != CT_SIZE:
            raise RuntimeError(
                f"Ciphertext size mismatch: expected {CT_SIZE}, "
                f"got {len(ciphertext)}"
            )
        logger.info("Ciphertext received: %d bytes ✓", len(ciphertext))

        # ── Step 4: ML-KEM-768 decapsulate ─────────────────
        logger.info("=== PHASE 4: ML-KEM-768 decapsulate ===")
        shared_secret = decapsulate(sk, ciphertext)

        if len(shared_secret) != SS_SIZE:
            raise RuntimeError(
                f"Shared secret size: expected {SS_SIZE}, "
                f"got {len(shared_secret)}"
            )
        logger.info("Decapsulate: ss=%d bytes ✓", len(shared_secret))

        # ── Step 5: SAS verification ───────────────────────
        logger.info("=== PHASE 5: SAS Numeric Comparison ===")
        sas = derive_sas(pk, ciphertext, shared_secret)
        sas_str = format_sas(sas)
        logger.info("SAS derived.")

        confirmed = await self._prompt_sas(sas, sas_str, sas_callback)
        if not confirmed:
            raise RuntimeError(
                "SAS verification failed — user rejected or mismatch."
            )

        # ── Step 6: Session key derivation ─────────────────
        logger.info("=== PHASE 6: Session key derivation ===")
        session_key = derive_session_key(shared_secret)
        logger.info("Session key: %d bytes ✓", len(session_key))

        self._shared_secret = shared_secret
        self._session_key = session_key

        # ── Step 7: Persist session ────────────────────────
        if self._store is not None:
            self._session_id = generate_session_id()
            self._store.save(self._session_id, session_key)
            logger.info(
                "Session saved (id=%s...) for future resumption.",
                self._session_id.hex()[:8],
            )

        return session_key

    # ── callbacks ──────────────────────────────────────────

    async def _on_ciphertext_received(self, ct: bytes):
        """Called when central writes ciphertext."""
        self._ciphertext_received.set()

    async def _on_control_received(self, data: bytes):
        """
        Called when central writes to the CONTROL characteristic.

        Handles both SAS confirmation ("OK") and resume requests.
        """
        msg = parse_control_message(data)

        if msg["type"] == "resume_request":
            await self._handle_resume_request(msg["session_id"])
        elif msg["type"] == "sas_confirm":
            logger.info("SAS confirmation received via control.")
        else:
            logger.info("Unknown control message: %s", data.hex())

    async def _handle_resume_request(self, session_id: bytes) -> None:
        """
        Process a session resumption request.

        Looks up the session_id in the store.  If found, sends
        RESUME_OK on the DATA characteristic and sets the resume
        event.  Otherwise, sends RESUME_FAIL and lets the central
        fall back to a full handshake.
        """
        if self._store is None:
            # No store configured — silently ignore
            return

        found = self._store.has(session_id)

        if found:
            logger.info(
                "Resume request for known session (id=%s...) — accepted.",
                session_id.hex()[:8],
            )
            # Pre-load to confirm it's valid and increment usage
            self._store.load(session_id)
            self._resume_session_id = session_id
            self._resume_requested.set()

            # Notify central that resume was accepted
            await self._server.notify_data(RESUME_OK_NOTIFY)
        else:
            logger.info(
                "Resume request for unknown session (id=%s...) — rejected.",
                session_id.hex()[:8],
            )
            await self._server.notify_data(RESUME_FAIL_NOTIFY)

    # ── helpers ────────────────────────────────────────────

    async def _wait_for_either_or(
        self,
        event_a: asyncio.Event,
        event_b: asyncio.Event,
        timeout: float,
    ) -> None:
        """Wait until either event_a or event_b is set, or timeout."""
        deadline = asyncio.get_event_loop().time() + timeout

        while asyncio.get_event_loop().time() < deadline:
            if event_a.is_set() or event_b.is_set():
                return
            await asyncio.sleep(0.1)

        raise asyncio.TimeoutError()

    async def _prompt_sas(self, sas: int, sas_str: str, callback=None) -> bool:
        """Present SAS to user and wait for confirmation."""
        if callback:
            if asyncio.iscoroutinefunction(callback):
                return await callback(sas, sas_str)
            else:
                return callback(sas, sas_str)

        print()
        print("═" * 45)
        print(f"  SAS (PERIPHERAL):  {sas_str}")
        print("═" * 45)
        print()
        print("Verifica che il SAS mostrato sul CENTRAL sia IDENTICO.")
        print("Se i numeri corrispondono: premi y e INVIO.")
        print("Se sono DIVERSI: premi n e INVIO (MITM rilevato!).")
        print()

        loop = asyncio.get_event_loop()
        answer = await loop.run_in_executor(
            None, lambda: input("  Confermi? [y/n] ").strip().lower()
        )

        if answer in ("y", "yes", "sì", "si"):
            logger.info("User confirmed SAS match.")
            return True
        else:
            logger.warning("User rejected SAS — possible MITM!")
            return False

    # ── properties ─────────────────────────────────────────

    @property
    def shared_secret(self) -> Optional[bytes]:
        return self._shared_secret

    @property
    def session_key(self) -> Optional[bytes]:
        return self._session_key

    @property
    def session_id(self) -> Optional[bytes]:
        return self._session_id

    @property
    def public_key(self) -> Optional[bytes]:
        return self._public_key