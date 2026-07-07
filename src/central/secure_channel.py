"""
Secure Channel — Central side.

After handshake, encrypt/decrypt data over BLE GATT notifications.
"""

import logging

from ..common.session import SecureChannel as _BaseChannel
from ..common.constants import CENTRAL_ROLE, MSG_TYPE_DATA
from .ble_client import BLECentralClient

logger = logging.getLogger("pq-ble.central.secure_channel")


class CentralSecureChannel(_BaseChannel):
    """
    Central-side secure channel.

    Uses bleak GATT notifications for receiving data and
    GATT writes for sending data.
    """

    def __init__(self, session_key: bytes, client: BLECentralClient,
                 session_id: bytes = None):
        super().__init__(session_key, session_id=session_id, role=CENTRAL_ROLE)
        self._client = client
        self._received_data: list[bytes] = []
        self._receive_queue: list[bytes] = []

    async def start_receiving(self) -> None:
        """Subscribe to encrypted data notifications."""

        def _notification_handler(sender, data: bytearray):
            plaintext = self.decrypt(bytes(data), msg_type=MSG_TYPE_DATA)
            logger.debug("Decrypted %d bytes", len(plaintext))
            self._receive_queue.append(plaintext)

        await self._client.start_notify(_notification_handler)

    async def send(self, plaintext: bytes) -> None:
        """
        Encrypt and send data via GATT notification (if supported)
        or write.
        """
        wire_data = self.encrypt(plaintext, msg_type=MSG_TYPE_DATA)
        # On central side, we write to a characteristic the peripheral
        # is subscribed to, or use a write characteristic.
        # For simplicity: we write to the control characteristic
        # with a type prefix, or use a dedicated write characteristic.
        # In the demo, the peripheral handles notify — central writes.
        await self._client.send_control(wire_data)
        logger.debug("Sent %d encrypted bytes (%d plaintext)",
                     len(wire_data), len(plaintext))

    async def receive(self, timeout: float = 5.0) -> bytes | None:
        """
        Wait for and return the next decrypted message.

        Returns None if timeout expires.
        """
        import asyncio

        if self._receive_queue:
            return self._receive_queue.pop(0)

        # Wait for new data
        start_len = len(self._receive_queue)
        deadline = asyncio.get_event_loop().time() + timeout

        while asyncio.get_event_loop().time() < deadline:
            if len(self._receive_queue) > start_len:
                return self._receive_queue.pop(0)
            await asyncio.sleep(0.1)

        return None

    async def stop(self) -> None:
        """Unsubscribe from notifications."""
        await self._client.stop_notify()
