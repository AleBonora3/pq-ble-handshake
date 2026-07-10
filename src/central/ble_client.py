"""
BLE Central (Client) — connects to the peripheral and discovers
the PQ-BLE GATT service.

Uses bleak for cross-platform BLE access.
"""

import asyncio
import logging
from typing import Optional

from bleak import BleakClient, BleakScanner
from bleak.backends.device import BLEDevice

from ..common.constants import (
    SERVICE_UUID,
    CHAR_PUBKEY_UUID,
    CHAR_CIPHERTEXT_UUID,
    CHAR_DATA_UUID,
    CHAR_CONTROL_UUID,
    DEVICE_NAME,
    BLE_MTU,
    FRAGMENT_HEADER_SIZE,
)
from ..common.fragmentation import fragment_data

logger = logging.getLogger("pq-ble.central.client")


class BLECentralClient:
    """
    BLE Central — scans for the PQ-BLE peripheral, connects,
    and provides access to the custom GATT characteristics.
    """

    def __init__(self, device_name: str = DEVICE_NAME):
        self._device_name = device_name
        self._client: Optional[BleakClient] = None
        self._device: Optional[BLEDevice] = None

    async def scan_and_connect(self, timeout: float = 10.0) -> bool:
        """
        Scan for the peripheral and connect to it.

        Returns True if connected successfully.
        """
        logger.info(f"Scanning for '{self._device_name}' (%ds timeout)...", timeout)

        self._device = await BleakScanner.find_device_by_name(
            self._device_name, timeout=timeout
        )

        if self._device is None:
            logger.error("Device '%s' not found.", self._device_name)
            return False

        logger.info("Found %s (%s), connecting...", self._device.name, self._device.address)

        self._client = BleakClient(
            self._device,
            disconnected_callback=self._on_disconnect,
        )
        await self._client.connect()

        # MTU is negotiated automatically by the BLE stack during
        # connection. We read the negotiated value for fragmentation.
        logger.info("Connected. MTU: %d", self._client.mtu_size)

        # Verify the service exists
        services = self._client.services
        if not services or SERVICE_UUID.lower() not in str(services).lower():
            logger.warning("Custom service %s not found — it may appear after connection.", SERVICE_UUID)

        return True

    async def disconnect(self):
        """Gracefully disconnect."""
        if self._client and self._client.is_connected:
            await self._client.disconnect()
            logger.info("Disconnected.")

    def _on_disconnect(self, client: BleakClient):
        logger.warning("Unexpected disconnect from %s", client.address)

    async def read_fragmented_public_key(self) -> bytes:
        """
        Read the peripheral's ML-KEM public key via GATT.

        BlueZ handles Read Blob transparently: if the characteristic
        value exceeds the negotiated MTU, multiple Read Blob requests
        are issued automatically and the full value is returned.

        This method does NOT assume that 1184 bytes fit in a single
        read. If the BLE stack returns a partial value, the caller
        will detect a size mismatch in the handshake logic.

        Returns:
            Full public key (1184 bytes for ML-KEM-768).
        """
        if not self._client or not self._client.is_connected:
            raise RuntimeError("Not connected")

        data = await self._client.read_gatt_char(CHAR_PUBKEY_UUID)
        logger.info("Read public key: %d bytes (MTU=%d)",
                     len(data), self.mtu_size)
        return data

    # Backward-compatible alias
    async def read_public_key(self) -> bytes:
        """Alias for read_fragmented_public_key()."""
        return await self.read_fragmented_public_key()

    async def write_fragmented_ciphertext(self, data: bytes) -> None:
        """
        Write the ML-KEM ciphertext to the peripheral via GATT.

        Fragments the ciphertext using the application-level
        fragmentation protocol (4-byte header per fragment) and
        writes each fragment as a separate GATT Write Request.
        The peripheral accumulates and reassembles.

        The fragment payload size is calculated from the negotiated
        MTU (or default BLE_MTU if negotiation is unavailable):

            fragment_payload = mtu - FRAGMENT_HEADER_SIZE
        """
        if not self._client or not self._client.is_connected:
            raise RuntimeError("Not connected")

        # Calculate payload size from negotiated MTU
        mtu = self.mtu_size if self.mtu_size > 23 else BLE_MTU
        fragment_payload = mtu - FRAGMENT_HEADER_SIZE

        fragments = fragment_data(data, mtu=mtu)
        logger.info("Writing ciphertext: %d bytes in %d fragments (MTU=%d, payload=%d)",
                     len(data), len(fragments), mtu, fragment_payload)

        for i, frag in enumerate(fragments):
            await self._client.write_gatt_char(CHAR_CIPHERTEXT_UUID, frag)
            logger.debug("  Fragment %d/%d sent (%d bytes)",
                         i + 1, len(fragments), len(frag))

        logger.info("Ciphertext written [OK] (%d fragments)", len(fragments))

    # Backward-compatible alias
    async def write_ciphertext(self, data: bytes) -> None:
        """Alias for write_fragmented_ciphertext()."""
        return await self.write_fragmented_ciphertext(data)

    async def send_control(self, data: bytes) -> None:
        """Send a control message (e.g., SAS confirmation)."""
        if not self._client or not self._client.is_connected:
            raise RuntimeError("Not connected")
        await self._client.write_gatt_char(CHAR_CONTROL_UUID, data)

    async def start_notify(self, callback) -> None:
        """
        Subscribe to encrypted data notifications.

        Args:
            callback: Async function receiving (sender, data) on each notification.
        """
        if not self._client or not self._client.is_connected:
            raise RuntimeError("Not connected")
        await self._client.start_notify(CHAR_DATA_UUID, callback)
        logger.info("Subscribed to data notifications.")

    async def stop_notify(self) -> None:
        """Unsubscribe from data notifications."""
        if self._client and self._client.is_connected:
            await self._client.stop_notify(CHAR_DATA_UUID)

    @property
    def is_connected(self) -> bool:
        return self._client is not None and self._client.is_connected

    @property
    def mtu_size(self) -> int:
        if self._client:
            return self._client.mtu_size
        return 23  # BLE default