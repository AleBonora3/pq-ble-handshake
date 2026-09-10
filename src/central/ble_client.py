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
            winrt={
                "use_cached_services": False,
            },
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

    async def reconnect(self, timeout: float = 15.0) -> bool:
        """Re-scan and reconnect (Windows may drop the link after bonding)."""
        try:
            await self.disconnect()
        except Exception as exc:  # noqa: BLE001
            logger.debug("Ignoring disconnect error before reconnect: %s", exc)
        return await self.scan_and_connect(timeout=timeout)

    async def reconnect_v1_peer(self, timeout: float = 15.0) -> bool:
        """CP1: retire the old GATT session and reconnect the same scanned peer.

        Wait for a new advertisement from the original address (the CP1 DK
        stops advertising while connected). Do not scan by name: another DK
        may advertise the same name. A new BleakClient also isolates delayed
        disconnect events from the old one.
        """
        if self._device is None:
            raise RuntimeError("No known CP1 peer to reconnect")
        old_client = self._client
        if old_client is not None:
            await old_client.disconnect()
        logger.info("CP1 reconnect to original peer %s", self._device.address)
        peer = await BleakScanner.find_device_by_address(self._device.address, timeout=timeout)
        if peer is None:
            logger.error("Original CP1 peer did not resume advertising")
            return False
        self._device = peer
        self._client = BleakClient(
            self._device, timeout=timeout,
            disconnected_callback=self._on_v1_disconnect,
            winrt={"use_cached_services": False},
        )
        await self._client.connect()
        return self._client.is_connected

    def _on_v1_disconnect(self, client: BleakClient):
        if client is getattr(self, "_v1_cp3_link", None):
            self.clear_v1_cp3()
        logger.info("CP1 link disconnected from %s (classified by the active test)",
                    client.address)

    async def disconnect(self):
        """Gracefully disconnect."""
        self.clear_v1_cp3()
        if self._client and self._client.is_connected:
            await self._client.disconnect()
            logger.info("Disconnected.")

    def clear_v1_cp3(self):
        session = getattr(self, "_v1_cp3_session", None)
        if session is not None:
            session.clear()
            self._v1_cp3_session = None
            self._v1_cp3_link = None

    def _on_disconnect(self, client: BleakClient):
        if getattr(self, "_v1_security_test", False):
            self._on_v1_disconnect(client)
            return
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

        # A GATT attribute value is capped at 512 bytes. Some backends report
        # an ATT MTU of 517, which would otherwise produce a 517-byte logical
        # fragment that the peripheral must reject. Keep the established wire
        # format and cap only the logical frame size.
        negotiated_mtu = self.mtu_size
        mtu = min(negotiated_mtu, BLE_MTU) if negotiated_mtu > 23 else BLE_MTU
        fragment_payload = mtu - FRAGMENT_HEADER_SIZE

        fragments = fragment_data(data, mtu=mtu)
        logger.info(
            "Writing ciphertext: %d bytes in %d fragments "
            "(negotiated MTU=%d, logical frame=%d, payload=%d)",
            len(data), len(fragments), negotiated_mtu, mtu, fragment_payload,
        )

        for i, frag in enumerate(fragments):
            await self._client.write_gatt_char(CHAR_CIPHERTEXT_UUID, frag)
            logger.debug("  Fragment %d/%d sent (%d bytes)",
                         i + 1, len(fragments), len(frag))

        logger.info("Ciphertext written [OK] (%d fragments)", len(fragments))
        return len(fragments)

    async def write_raw_ciphertext_fragment(self, fragment: bytes) -> None:
        """Write one already-framed fragment (v1.0 CP1 pre-L4 gating probe)."""

        if not self._client or not self._client.is_connected:
            raise RuntimeError("Not connected")
        await self._client.write_gatt_char(CHAR_CIPHERTEXT_UUID, fragment)

    # Backward-compatible alias
    async def write_ciphertext(self, data: bytes) -> None:
        """Alias for write_fragmented_ciphertext()."""
        return await self.write_fragmented_ciphertext(data)

    async def send_control(self, data: bytes) -> None:
        """Send a control message (e.g., SAS confirmation)."""
        if not self._client or not self._client.is_connected:
            raise RuntimeError("Not connected")
        await self._client.write_gatt_char(CHAR_CONTROL_UUID, data)

    async def write_secure_data(self, data: bytes) -> None:
        """Write one encrypted application frame to Secure Data."""

        if not self._client or not self._client.is_connected:
            raise RuntimeError("Not connected")

        if not data:
            raise ValueError("Secure Data write cannot be empty")

        await self._client.write_gatt_char(
            CHAR_DATA_UUID,
            data,
            response=True,
        )

        logger.info(
            "Secure Data write completed: %d bytes",
            len(data),
        )

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
        self.clear_v1_cp3()
        if self._client and self._client.is_connected:
            await self._client.stop_notify(CHAR_DATA_UUID)

    @property
    def is_connected(self) -> bool:
        return self._client is not None and self._client.is_connected

    @property
    def address(self) -> Optional[str]:
        """Peer Bluetooth address as reported by the scanner."""
        return self._device.address if self._device is not None else None

    @property
    def raw_client(self) -> Optional[BleakClient]:
        """Underlying BleakClient (needed by platform pairing helpers)."""
        return self._client

    @property
    def mtu_size(self) -> int:
        if self._client:
            return self._client.mtu_size
        return 23  # BLE default
