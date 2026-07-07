"""
Peripheral Secure Channel.

After handshake, handles encrypted data exchange.
"""

import asyncio
import logging

from src.common.session import SecureChannel as _BaseChannel
from src.common.constants import PERIPHERAL_ROLE, MSG_TYPE_DATA
from experimental.peripheral.ble_server import BLEPeripheralServer

logger = logging.getLogger("pq-ble.peripheral.secure_channel")


class PeripheralSecureChannel(_BaseChannel):
    """Peripheral-side secure channel."""

    def __init__(self, session_key: bytes, server: BLEPeripheralServer,
                 session_id: bytes = None):
        super().__init__(session_key, session_id=session_id, role=PERIPHERAL_ROLE)
        self._server = server
        self._received_data: list[bytes] = []
        self._receive_queue: list[bytes] = []

    def on_encrypted_data(self, data: bytes):
        """Handle incoming encrypted data and decrypt."""
        plaintext = self.decrypt(data, msg_type=MSG_TYPE_DATA)
        logger.debug("Decrypted %d bytes", len(plaintext))
        self._receive_queue.append(plaintext)

    async def send(self, plaintext: bytes) -> None:
        """Encrypt and notify the central."""
        wire_data = self.encrypt(plaintext, msg_type=MSG_TYPE_DATA)
        # Send via GATT notification (NOTIFY characteristic)
        # The server handles the actual notification
        await self._server.notify_data(wire_data)
        logger.debug("Notified %d encrypted bytes (%d plaintext)",
                     len(wire_data), len(plaintext))

    async def receive(self, timeout: float = 5.0) -> bytes | None:
        """Wait for the next decrypted message."""
        if self._receive_queue:
            return self._receive_queue.pop(0)

        deadline = asyncio.get_event_loop().time() + timeout
        start_len = len(self._receive_queue)

        while asyncio.get_event_loop().time() < deadline:
            if len(self._receive_queue) > start_len:
                return self._receive_queue.pop(0)
            await asyncio.sleep(0.1)

        return None