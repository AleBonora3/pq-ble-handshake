"""
GATT Fragmentation Protocol.

BLE MTU defaults to 512 bytes (517 with ATT header). ML-KEM-768 keys
are 1184 bytes (pk) and 1088 bytes (ct) — they don't fit in one packet.

This module splits large payloads into fragments and reassembles them.

Wire format (per fragment, up to 508 bytes payload):
    ┌──────────────┬──────────────┬────────────────┬──────────────────────┐
    │ fragment_idx │ total_frags  │ payload_length │ payload              │
    │ uint8        │ uint8        │ uint16 (BE)    │ up to 508 bytes      │
    └──────────────┴──────────────┴────────────────┴──────────────────────┘

Total header: 4 bytes. Max fragment size: MTU - 4.
"""

import struct
from dataclasses import dataclass
from typing import List

HEADER_SIZE = 4
HEADER_FORMAT = "!BBH"  # fragment_idx, total_frags, payload_length


@dataclass
class Fragment:
    """Single fragment in transit."""
    index: int
    total: int
    payload: bytes

    def encode(self) -> bytes:
        """Serialize to wire format."""
        return struct.pack(HEADER_FORMAT, self.index, self.total, len(self.payload)) + self.payload

    @staticmethod
    def decode(data: bytes) -> "Fragment":
        """Deserialize from wire format."""
        if len(data) < HEADER_SIZE:
            raise ValueError(f"Fragment too short: {len(data)} < {HEADER_SIZE}")
        idx, total, payload_len = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
        payload = data[HEADER_SIZE:HEADER_SIZE + payload_len]
        return Fragment(index=idx, total=total, payload=payload)


def fragment_data(data: bytes, mtu: int = 512) -> List[bytes]:
    """
    Split data into fragments suitable for GATT transfer.

    Args:
        data: Raw bytes to fragment.
        mtu: Negotiated BLE MTU (default 512).

    Returns:
        List of encoded fragment bytes, each ≤ mtu.
    """
    max_payload = mtu - HEADER_SIZE
    if len(data) == 0:
        total = 1
    else:
        total = (len(data) + max_payload - 1) // max_payload
    fragments = []

    for i in range(total):
        start = i * max_payload
        end = min(start + max_payload, len(data))
        chunk = data[start:end]
        frag = Fragment(index=i, total=total, payload=chunk)
        fragments.append(frag.encode())

    return fragments


def reassemble_data(fragments: List[bytes]) -> bytes:
    """
    Reassemble fragments back into original data.

    Args:
        fragments: List of encoded fragment bytes (order-independent).

    Returns:
        Reassembled original data.

    Raises:
        ValueError: If fragments are missing, duplicated, or corrupted.
    """
    if not fragments:
        raise ValueError("No fragments provided")

    decoded = [Fragment.decode(f) for f in fragments]
    total_frags = decoded[0].total

    # Validate consistency
    for frag in decoded:
        if frag.total != total_frags:
            raise ValueError(
                f"Inconsistent total_frags: expected {total_frags}, got {frag.total}"
            )

    # Check for duplicates
    indices = [f.index for f in decoded]
    if len(indices) != len(set(indices)):
        raise ValueError(f"Duplicate fragment indices: {indices}")

    # Check completeness
    if len(decoded) != total_frags:
        missing = set(range(total_frags)) - set(indices)
        raise ValueError(
            f"Missing fragments: {sorted(missing)}. "
            f"Got {len(decoded)}/{total_frags}"
        )

    # Reassemble in order
    sorted_frags = sorted(decoded, key=lambda f: f.index)
    return b"".join(f.payload for f in sorted_frags)
