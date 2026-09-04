"""
Test: Central BLE transport with mock GATT.

Tests the fragmented read/write flow of BLECentralClient using a
mock GATT client that simulates the nRF54L15 DK peripheral.

Verifies:
- read_fragmented_public_key() returns the full 1184-byte key
- write_fragmented_ciphertext() fragments correctly and writes all fragments
- Fragment headers are valid (idx, total, payload_len)
- Reassembled ciphertext matches the original
- Multiple MTU sizes produce correct fragment counts
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from src.central.ble_client import BLECentralClient
from src.common.constants import (
    SERVICE_UUID,
    CHAR_PUBKEY_UUID,
    CHAR_CIPHERTEXT_UUID,
    PK_SIZE,
    CT_SIZE,
    FRAGMENT_HEADER_SIZE,
    BLE_MTU,
)
from src.common.fragmentation import fragment_data, reassemble_data, Fragment


class MockBleakClient:
    """Simulates a BleakClient connected to the nRF54L15 DK."""

    def __init__(self, mtu_size: int = 512, public_key: bytes = None):
        self._mtu_size = mtu_size
        self._public_key = public_key or bytes(range(256)) * (PK_SIZE // 256) + bytes(range(PK_SIZE % 256))
        self._public_key = self._public_key[:PK_SIZE]
        self._is_connected = False
        self._written_fragments = []
        self._notify_callback = None
        self._notify_enabled = False
        self.services = MagicMock()
        # Make str(services) contain the service UUID
        self.services.__str__ = MagicMock(return_value=SERVICE_UUID)

    async def connect(self):
        self._is_connected = True

    async def disconnect(self):
        self._is_connected = False

    @property
    def is_connected(self):
        return self._is_connected

    @property
    def mtu_size(self):
        return self._mtu_size

    async def read_gatt_char(self, uuid: str) -> bytes:
        if uuid.lower() == CHAR_PUBKEY_UUID.lower():
            return self._public_key
        return b""

    async def write_gatt_char(self, uuid: str, data: bytes):
        if uuid.lower() == CHAR_CIPHERTEXT_UUID.lower():
            self._written_fragments.append(bytes(data))

    async def start_notify(self, uuid: str, callback):
        self._notify_enabled = True
        self._notify_callback = callback

    async def stop_notify(self, uuid: str):
        self._notify_enabled = False
        self._notify_callback = None


def _make_central_with_mock(mtu: int = 512, pk: bytes = None) -> tuple:
    """Create a BLECentralClient with a mock BleakClient connected."""
    mock = MockBleakClient(mtu_size=mtu, public_key=pk)
    central = BLECentralClient()
    central._client = mock
    mock._is_connected = True
    return central, mock


# ── Read tests ──

@pytest.mark.asyncio
async def test_read_fragmented_public_key_full():
    """read_fragmented_public_key should return 1184 bytes."""
    central, mock = _make_central_with_mock()
    pk = await central.read_fragmented_public_key()
    assert len(pk) == PK_SIZE
    assert pk == mock._public_key


@pytest.mark.asyncio
async def test_read_public_key_alias_works():
    """Backward-compatible alias read_public_key should work."""
    central, mock = _make_central_with_mock()
    pk = await central.read_public_key()
    assert len(pk) == PK_SIZE


@pytest.mark.asyncio
async def test_read_fragmented_public_key_not_connected():
    """Should raise RuntimeError if not connected."""
    central = BLECentralClient()
    with pytest.raises(RuntimeError, match="Not connected"):
        await central.read_fragmented_public_key()


# ── Write tests ──

@pytest.mark.asyncio
async def test_write_fragmented_ciphertext_basic():
    """write_fragmented_ciphertext should write all fragments."""
    central, mock = _make_central_with_mock(mtu=512)
    ct = bytes(range(256)) * (CT_SIZE // 256) + bytes(range(CT_SIZE % 256))
    ct = ct[:CT_SIZE]

    await central.write_fragmented_ciphertext(ct)

    # Should have written multiple fragments
    assert len(mock._written_fragments) > 0

    # Reassemble written fragments
    reassembled = reassemble_data(mock._written_fragments)
    assert reassembled == ct


@pytest.mark.asyncio
async def test_write_fragmented_ciphertext_fragment_count():
    """Fragment count should match fragment_data output."""
    central, mock = _make_central_with_mock(mtu=512)
    ct = b"\x42" * CT_SIZE

    expected_frags = fragment_data(ct, mtu=512)
    await central.write_fragmented_ciphertext(ct)

    assert len(mock._written_fragments) == len(expected_frags)


@pytest.mark.asyncio
async def test_write_fragmented_ciphertext_headers_valid():
    """Each written fragment should have a valid 4-byte header."""
    central, mock = _make_central_with_mock(mtu=512)
    ct = b"\x33" * CT_SIZE

    await central.write_fragmented_ciphertext(ct)

    for i, frag in enumerate(mock._written_fragments):
        assert len(frag) >= FRAGMENT_HEADER_SIZE, f"Fragment {i} too short"
        decoded = Fragment.decode(frag)
        assert decoded.index == i, (
            f"Fragment {i} has index {decoded.index}"
        )
        assert decoded.total == len(mock._written_fragments)
        assert len(decoded.payload) == len(frag) - FRAGMENT_HEADER_SIZE


@pytest.mark.asyncio
async def test_write_fragmented_ciphertext_reassembly():
    """Reassembled fragments should match original ciphertext."""
    central, mock = _make_central_with_mock(mtu=247)  # smaller MTU
    ct = bytes(i % 256 for i in range(CT_SIZE))

    await central.write_fragmented_ciphertext(ct)

    reassembled = reassemble_data(mock._written_fragments)
    assert reassembled == ct


@pytest.mark.asyncio
async def test_write_fragmented_ciphertext_small_mtu():
    """Smaller MTU should produce more fragments but same result."""
    central_small, mock_small = _make_central_with_mock(mtu=64)
    central_large, mock_large = _make_central_with_mock(mtu=512)

    ct = b"\xAA" * CT_SIZE

    await central_small.write_fragmented_ciphertext(ct)
    await central_large.write_fragmented_ciphertext(ct)

    # Smaller MTU → more fragments
    assert len(mock_small._written_fragments) > len(mock_large._written_fragments)

    # Both reassemble to the same ciphertext
    assert reassemble_data(mock_small._written_fragments) == ct
    assert reassemble_data(mock_large._written_fragments) == ct


@pytest.mark.asyncio
async def test_write_fragmented_ciphertext_caps_logical_frame_at_512():
    """An ATT MTU above 512 must not create an oversized attribute value."""
    central, mock = _make_central_with_mock(mtu=517)
    ct = b"\xA5" * CT_SIZE

    await central.write_fragmented_ciphertext(ct)

    assert all(len(fragment) <= BLE_MTU for fragment in mock._written_fragments)
    assert reassemble_data(mock._written_fragments) == ct


@pytest.mark.asyncio
async def test_write_fragmented_ciphertext_not_connected():
    """Should raise RuntimeError if not connected."""
    central = BLECentralClient()
    with pytest.raises(RuntimeError, match="Not connected"):
        await central.write_fragmented_ciphertext(b"test")


@pytest.mark.asyncio
async def test_write_ciphertext_alias_works():
    """Backward-compatible alias write_ciphertext should work."""
    central, mock = _make_central_with_mock(mtu=512)
    ct = b"\x55" * CT_SIZE

    await central.write_ciphertext(ct)

    assert len(mock._written_fragments) > 0
    assert reassemble_data(mock._written_fragments) == ct


# ── MTU property tests ──

def test_mtu_size_default():
    """MTU should default to 23 when not connected."""
    central = BLECentralClient()
    assert central.mtu_size == 23


def test_mtu_size_connected():
    """MTU should reflect the mock's value when connected."""
    central, mock = _make_central_with_mock(mtu=247)
    assert central.mtu_size == 247


def test_is_connected_false_initially():
    """Client should not be connected initially."""
    central = BLECentralClient()
    assert not central.is_connected


def test_is_connected_true_with_mock():
    """Client should be connected with mock."""
    central, _ = _make_central_with_mock()
    assert central.is_connected


# ── Control and notify tests ──

@pytest.mark.asyncio
async def test_send_control_writes_to_control_char():
    """send_control should write to the CONTROL characteristic."""
    central, mock = _make_central_with_mock()
    # Add tracking for control writes
    mock._control_writes = []
    original_write = mock.write_gatt_char

    async def tracking_write(uuid, data):
        if uuid.lower() == "12345678-1234-1234-1234-123456789ac0":
            mock._control_writes.append(bytes(data))
        await original_write(uuid, data)

    mock.write_gatt_char = tracking_write

    await central.send_control(b"START")
    assert mock._control_writes == [b"START"]


@pytest.mark.asyncio
async def test_start_notify_subscribes():
    """start_notify should subscribe to DATA characteristic."""
    central, mock = _make_central_with_mock()

    callback = lambda sender, data: None
    await central.start_notify(callback)

    assert mock._notify_enabled
    assert mock._notify_callback is not None


@pytest.mark.asyncio
async def test_stop_notify_unsubscribes():
    """stop_notify should unsubscribe from DATA characteristic."""
    central, mock = _make_central_with_mock()

    await central.start_notify(lambda s, d: None)
    assert mock._notify_enabled

    await central.stop_notify()
    assert not mock._notify_enabled
