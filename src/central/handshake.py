"""
Central-side PQ Handshake Logic.

Orchestrates the full post-quantum handshake with optional
session resumption (Strada A).

Flow:
  IF session store has a cached session:
    1. Send RESUME_REQUEST on CONTROL characteristic
    2. Wait for RESUME_OK or RESUME_FAIL on DATA notification
    3. If OK → reuse stored session key (skip full handshake)
  ELSE (full handshake):
    1. Read peripheral's public key via GATT
    2. ML-KEM encapsulate → ciphertext + shared_secret
    3. Write ciphertext via GATT
    4. Derive SAS, present to user, wait for confirmation
    5. Derive session key via HKDF
    6. Save (session_id, session_key) in SessionStore
"""

import asyncio
import logging
from typing import Optional

from ..common.ml_kem import encapsulate
from ..common.sas import derive_sas, format_sas
from ..common.session import (
    derive_session_key,
    generate_session_id,
    build_resume_request,
)
from ..common.session_store import SessionStore
from ..common.constants import (
    PK_SIZE,
    SS_SIZE,
    RESUME_OK_NOTIFY,
    RESUME_FAIL_NOTIFY,
)
from .ble_client import BLECentralClient

logger = logging.getLogger("pq-ble.central.handshake")


class CentralHandshake:
    """
    Central-side PQ handshake over BLE GATT.

    Supports session resumption (Strada A): if a SessionStore is
    provided, attempts to resume an existing session before falling
    back to a full PQ handshake.
    """

    def __init__(
        self,
        client: BLECentralClient,
        session_store: Optional[SessionStore] = None,
    ):
        self._client = client
        self._store = session_store
        self._shared_secret: Optional[bytes] = None
        self._session_key: Optional[bytes] = None
        self._session_id: Optional[bytes] = None

    # ── public API ─────────────────────────────────────────

    async def run(self, sas_callback=None) -> bytes:
        """
        Execute the handshake, preferring session resumption
        when available.

        Returns:
            32-byte session key.

        Raises:
            RuntimeError: If connection lost, SAS mismatch,
                          or timeout.
        """
        if not self._client.is_connected:
            raise RuntimeError("BLE client not connected")

        # ── Attempt session resumption ─────────────────────
        if self._store is not None and self._store.count > 0:
            session_key = await self._attempt_resume()
            if session_key is not None:
                self._session_key = session_key
                logger.info("✅ Session resumed successfully.")
                return session_key
            logger.info("Resume failed or no cached sessions; "
                        "falling back to full handshake.")

        # ── Full PQ handshake ──────────────────────────────
        return await self._run_full_handshake(sas_callback)

    @property
    def shared_secret(self) -> Optional[bytes]:
        return self._shared_secret

    @property
    def session_key(self) -> Optional[bytes]:
        return self._session_key

    @property
    def session_id(self) -> Optional[bytes]:
        return self._session_id

    # ── resume logic ───────────────────────────────────────

    async def _attempt_resume(self) -> Optional[bytes]:
        """
        Try to resume any cached session.

        Iterates through stored sessions (there's usually just one),
        sends RESUME_REQUEST, and waits for the peripheral's response.

        Returns the session key on success, or None if all attempts fail.
        """
        if self._store is None:
            return None

        for sid_hex, created_at, usage_count in self._store.list_ids():
            session_id = bytes.fromhex(sid_hex)
            session_key = self._store.load(session_id)
            if session_key is None:
                continue

            logger.info(
                "Attempting session resume (id=%s..., created=%d, used=%d)",
                sid_hex[:8], int(created_at), usage_count,
            )

            resume_msg = build_resume_request(session_id)

            # Subscribe to DATA notifications first so we can
            # receive RESUME_OK / RESUME_FAIL
            resume_queue: list[bytes] = []

            def _resume_handler(_sender, data: bytearray):
                resume_queue.append(bytes(data))

            await self._client.start_notify(_resume_handler)

            try:
                # Send resume request on CONTROL
                await self._client.send_control(resume_msg)

                # Wait for response (with timeout)
                response = await self._wait_for_notification(
                    resume_queue, timeout=3.0
                )
            finally:
                await self._client.stop_notify()

            if response == RESUME_OK_NOTIFY:
                logger.info("Peripheral accepted resume request.")
                self._session_id = session_id
                return session_key

            if response == RESUME_FAIL_NOTIFY:
                logger.info("Peripheral rejected resume request (unknown session).")
                self._store.delete(session_id)
            else:
                logger.info("No resume response (timeout or unknown: %s)", response)

        return None

    async def _wait_for_notification(
        self, queue: list, timeout: float
    ) -> Optional[bytes]:
        """Wait up to *timeout* seconds for a notification on *queue*."""
        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            if queue:
                return queue.pop(0)
            await asyncio.sleep(0.1)
        return None

    # ── full handshake ─────────────────────────────────────

    async def _run_full_handshake(self, sas_callback=None) -> bytes:
        """Complete 6-step PQ handshake."""

        # ── Step 1: Read public key ──────────────────────────
        logger.info("=== PHASE 1: Reading public key ===")
        public_key = await self._client.read_fragmented_public_key()

        if len(public_key) != PK_SIZE:
            raise RuntimeError(
                f"Public key size mismatch: expected {PK_SIZE}, "
                f"got {len(public_key)}"
            )
        logger.info("Public key: %d bytes ✓", len(public_key))

        # ── Step 2: ML-KEM encapsulate ───────────────────────
        logger.info("=== PHASE 2: ML-KEM-768 encapsulate ===")
        ciphertext, shared_secret = encapsulate(public_key)

        if len(shared_secret) != SS_SIZE:
            raise RuntimeError(
                f"Shared secret size mismatch: expected {SS_SIZE}, "
                f"got {len(shared_secret)}"
            )
        logger.info("Encapsulate: ct=%d bytes, ss=%d bytes ✓",
                     len(ciphertext), len(shared_secret))

        # ── Step 3: Write ciphertext ─────────────────────────
        logger.info("=== PHASE 3: Writing ciphertext ===")
        await self._client.write_fragmented_ciphertext(ciphertext)
        logger.info("Ciphertext written ✓")

        # ── Step 4: SAS derivation & user confirmation ───────
        logger.info("=== PHASE 4: SAS Numeric Comparison ===")
        sas = derive_sas(public_key, ciphertext, shared_secret)
        sas_str = format_sas(sas)
        logger.info("SAS derived.")

        confirmed = await self._prompt_sas(sas, sas_str, sas_callback)
        if not confirmed:
            raise RuntimeError("SAS verification failed — user rejected or mismatch.")

        # ── Step 5: Session key derivation ───────────────────
        logger.info("=== PHASE 5: Session key derivation ===")
        session_key = derive_session_key(shared_secret)
        logger.info("Session key: %d bytes ✓", len(session_key))

        self._shared_secret = shared_secret
        self._session_key = session_key

        # ── Step 6: Persist session for future resumption ────
        if self._store is not None:
            self._session_id = generate_session_id()
            self._store.save(self._session_id, session_key)
            logger.info(
                "Session saved (id=%s...) for future resumption.",
                self._session_id.hex()[:8],
            )

        return session_key

    async def _prompt_sas(self, sas: int, sas_str: str, callback=None) -> bool:
        if callback:
            if asyncio.iscoroutinefunction(callback):
                return await callback(sas, sas_str)
            else:
                return callback(sas, sas_str)

        print()
        print("═" * 45)
        print(f"  SAS (CENTRAL):  {sas_str}")
        print("═" * 45)
        print()
        print("Verifica che il SAS mostrato sul PERIPHERAL sia IDENTICO.")
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