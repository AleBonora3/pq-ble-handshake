"""
BLE Peripheral (Server) — advertises the PQ-BLE GATT service
with custom characteristics for public key, ciphertext, data, and control.

Uses bleak's BleakServer (experimental, Linux-only via BlueZ D-Bus).

⚠️  STATUS: This peripheral implementation uses BleakServer, which is
    an EXPERIMENTAL API in bleak. It has NOT been tested on real BLE
    hardware in this project. For production use, consider replacing
    with `bless` (a library purpose-built for BLE GATT servers) or
    implementing the peripheral as Zephyr firmware on the nRF54L15 DK.
    See docs/design-decisions.md and the README for details.
"""

import asyncio
import logging
from typing import Callable, Optional

from bleak import BleakServer, BleakGATTService, BleakGATTCharacteristic
from bleak.uuids import uuid16_dict

from src.common.constants import (
    SERVICE_UUID,
    CHAR_PUBKEY_UUID,
    CHAR_CIPHERTEXT_UUID,
    CHAR_DATA_UUID,
    CHAR_CONTROL_UUID,
    DEVICE_NAME,
)
from src.common.fragmentation import Fragment, reassemble_data

logger = logging.getLogger("pq-ble.peripheral.server")

# Characteristic properties
READ = ["read"]
WRITE = ["write"]
NOTIFY = ["notify"]
WRITE_NOTIFY = ["write", "notify"]


class BLEPeripheralServer:
    """
    BLE Peripheral — advertises as 'PQ-BLE-Device' and exposes
    custom GATT characteristics for the PQ handshake protocol.
    """

    def __init__(self, device_name: str = DEVICE_NAME):
        self._device_name = device_name
        self._server: Optional[BleakServer] = None

        # Buffers for GATT data exchange
        self._public_key: bytes = b""
        self._ciphertext: bytes = b""
        self._control_message: bytes = b""
        self._ct_fragments: list[bytes] = []   # accumulate ciphertext fragments

        # Callbacks
        self._on_ciphertext_written: Optional[Callable] = None
        self._on_control_written: Optional[Callable] = None
        self._data_notify_callback: Optional[Callable] = None

    def set_public_key(self, pk: bytes) -> None:
        """Set the ML-KEM public key to expose on GATT."""
        self._public_key = pk

    @property
    def ciphertext(self) -> bytes:
        return self._ciphertext

    @property
    def control_message(self) -> bytes:
        return self._control_message

    def on_ciphertext(self, callback: Callable) -> None:
        """Register callback(bytes) for when ciphertext is written."""
        self._on_ciphertext_written = callback

    def on_control(self, callback: Callable) -> None:
        """Register callback(bytes) for when control message is written."""
        self._on_control_written = callback

    def on_data_notify(self, callback: Callable) -> None:
        """Register async callback for data notification sending."""
        self._data_notify_callback = callback

    async def start(self) -> None:
        """Start the GATT server and begin advertising."""
        service = BleakGATTService(SERVICE_UUID)

        # Public key characteristic (READ)
        pubkey_char = BleakGATTCharacteristic(
            uuid=CHAR_PUBKEY_UUID,
            properties=READ,
            value=self._public_key,
            description="ML-KEM-768 Public Key",
        )

        # Ciphertext characteristic (WRITE)
        ciphertext_char = BleakGATTCharacteristic(
            uuid=CHAR_CIPHERTEXT_UUID,
            properties=WRITE,
            description="ML-KEM-768 Ciphertext",
        )

        # Encrypted data characteristic (NOTIFY)
        data_char = BleakGATTCharacteristic(
            uuid=CHAR_DATA_UUID,
            properties=NOTIFY,
            description="Encrypted Data Channel",
        )

        # Control characteristic (WRITE — for SAS confirmation)
        control_char = BleakGATTCharacteristic(
            uuid=CHAR_CONTROL_UUID,
            properties=WRITE,
            description="Control (SAS confirm)",
        )

        service.add_characteristic(pubkey_char)
        service.add_characteristic(ciphertext_char)
        service.add_characteristic(data_char)
        service.add_characteristic(control_char)

        # Write handlers
        def _on_write_ciphertext(char, value: bytearray):
            """Accumulate ciphertext fragments and reassemble when complete."""
            frag = bytes(value)
            self._ct_fragments.append(frag)

            # Check if all fragments have been received
            try:
                first = Fragment.decode(self._ct_fragments[0])
                if len(self._ct_fragments) >= first.total:
                    # All fragments received — reassemble
                    self._ciphertext = reassemble_data(self._ct_fragments)
                    n_frags = len(self._ct_fragments)
                    self._ct_fragments = []  # reset for next handshake
                    logger.info("Ciphertext reassembled: %d bytes (%d fragments)",
                                len(self._ciphertext), n_frags)
                    if self._on_ciphertext_written:
                        asyncio.ensure_future(
                            self._on_ciphertext_written(self._ciphertext)
                            if asyncio.iscoroutinefunction(self._on_ciphertext_written)
                            else _call_sync(self._on_ciphertext_written, self._ciphertext)
                        )
                else:
                    logger.debug("CT fragment %d/%d received (%d bytes), waiting...",
                                 len(self._ct_fragments), first.total, len(frag))
            except (ValueError, IndexError):
                logger.debug("CT write received (%d bytes), accumulating...",
                             len(frag))

        def _on_write_control(char, value: bytearray):
            self._control_message = bytes(value)
            logger.info("Control written: %s", self._control_message)
            if self._on_control_written:
                asyncio.ensure_future(
                    self._on_control_written(self._control_message)
                    if asyncio.iscoroutinefunction(self._on_control_written)
                    else _call_sync(self._on_control_written, self._control_message)
                )

        ciphertext_char.on_write = _on_write_ciphertext
        control_char.on_write = _on_write_control

        def _on_read_pubkey(char, value: bytearray):
            """Refresh public key value on each read."""
            return self._public_key

        pubkey_char.on_read = _on_read_pubkey

        self._server = BleakServer([service])
        await self._server.start()

        logger.info(
            "GATT server started. Advertising as '%s'.\n"
            "  Service UUID:       %s\n"
            "  Pubkey char UUID:   %s\n"
            "  Ciphertext char UUID: %s\n"
            "  Data char UUID:     %s\n"
            "  Control char UUID:  %s",
            self._device_name, SERVICE_UUID, CHAR_PUBKEY_UUID,
            CHAR_CIPHERTEXT_UUID, CHAR_DATA_UUID, CHAR_CONTROL_UUID,
        )

        # Keep server running until cancelled
        try:
            while True:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass

    async def stop(self) -> None:
        """Stop the GATT server."""
        if self._server:
            await self._server.stop()
            logger.info("GATT server stopped.")

    async def notify_data(self, data: bytes) -> None:
        """
        Send data via GATT notification on the DATA characteristic.

        ⚠️  BleakServer is experimental. This method attempts to notify
            subscribed centrals but has NOT been tested on real BLE.
            If the BleakServer API does not support notifications in your
            bleak version, this logs a warning. For production peripheral
            use, replace with `bless` or Zephyr firmware.
        """
        if not self._server:
            raise RuntimeError("Server not started")

        try:
            # BleakServer >= 0.22 pattern: notify subscribers
            # The exact API may vary by bleak version.
            if hasattr(self._server, 'notify'):
                await self._server.notify(CHAR_DATA_UUID, data)
            else:
                logger.warning(
                    "BleakServer.notify() not available in this bleak version. "
                    "Data buffered but not pushed to central. "
                    "Replace with bless for production peripheral."
                )
        except Exception as e:
            logger.warning("GATT notify failed (BleakServer API): %s", e)

        logger.info("Notify: %d bytes", len(data))

    def reset_ciphertext_buffer(self) -> None:
        """Clear the ciphertext fragment buffer (call before new handshake)."""
        self._ct_fragments = []
        self._ciphertext = b""


async def _call_sync(func, *args):
    """Wrap synchronous callback in async context."""
    func(*args)
