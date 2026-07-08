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

    async def start_receiving(self, decrypt_notifications: bool = True) -> None:
        """
        Subscribe to data notifications.
        decrypt_notifications=True:
            Normal secure-channel mode. Incoming notifications are decrypted
            with AES-GCM.
        decrypt_notifications=False:
            Hardware demo mode. Incoming notifications are accepted as raw bytes.
            This is used with the nRF54L15 DK firmware because the current DK
            firmware validates the BLE/GATT transport layer but does not perform
            on-chip ML-KEM decapsulation or AES-GCM encryption yet.
        """
        from cryptography.exceptions import InvalidTag

        def _notification_handler(sender, data: bytearray):
            raw = bytes(data)

            if not decrypt_notifications:
                logger.info(
                    "Raw notification received from %s: %d bytes",
                    sender,
                    len(raw),
                )
                logger.debug("Raw notification hex: %s", raw.hex())
                self._receive_queue.append(raw)
                return

            try:
                plaintext = self.decrypt(raw, msg_type=MSG_TYPE_DATA)
            except InvalidTag:
                logger.warning(
                    "Received notification, but AES-GCM tag verification failed. "
                    "Packet ignored."
                )
                logger.debug("Invalid notification raw hex: %s", raw.hex())
                return

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
