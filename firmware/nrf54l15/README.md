# PQ-BLE Handshake Firmware for nRF54L15 DK

> ⚠️ **STATUS: Reference design — NOT compiled, NOT tested.**
>
> This firmware is a **future development** target, not part of the
> current Python proof-of-concept. The current PoC validates the
> cryptographic protocol (ML-KEM-768, SAS, HKDF, AES-256-GCM with
> AAD and replay protection) entirely in Python with 78 automated
> tests. This firmware would replace the Python peripheral with an
> embedded GATT server on the nRF54L15 DK.

## What This Firmware Would Do

The firmware implements a **GATT peripheral** that exposes the PQ-BLE
custom service with four characteristics matching the Python constants:

| Characteristic | UUID suffix | Properties | Purpose |
|---|---|---|---|
| Public Key | `...9abd` | READ | ML-KEM-768 public key (1184 B) |
| Ciphertext | `...9abe` | WRITE | ML-KEM-768 ciphertext (1088 B, fragmented) |
| Secure Data | `...9abf` | NOTIFY | AES-256-GCM encrypted payloads |
| Control | `...9ac0` | WRITE | SAS confirm / session resume |

### Two Implementation Paths

**Path 1 — Serial Bridge (simpler):**
- Host PC generates ML-KEM keypair, sends public key via UART
- Firmware stores it in the GATT characteristic
- When ciphertext fragments arrive, firmware forwards them via UART
- Host PC decapsulates, derives keys, sends session key back
- Firmware uses session key for AES-GCM NOTIFY

**Path 2 — On-chip Crypto (harder):**
- Port liboqs (or a compact ML-KEM implementation) to Cortex-M33
- All crypto runs on the DK
- SAS displayed via UART or GPIO/LED
- No host PC required during operation

## Build Environment (when implemented)

- nRF Connect SDK >= 2.8.0 (nRF54L15 support)
- Zephyr toolchain (arm-none-eabi-gcc)
- West build system

```bash
cd firmware/nrf54l15
west build -b nrf54l15dk/nrf54l15/cpuapp -p always
west flash
```

## Serial Monitor

```bash
screen /dev/ttyACM0 115200
# or
minicom -D /dev/ttyACM0
```

## Fragmentation Protocol

The ciphertext write handler accumulates fragments using the same
4-byte header protocol as Python `fragmentation.py`:

```
┌──────────────┬──────────────┬────────────────┬──────────────────────┐
│ fragment_idx │ total_frags  │ payload_length │ payload              │
│ uint8        │ uint8        │ uint16 (BE)    │ up to 508 bytes      │
└──────────────┴──────────────┴────────────────┴──────────────────────┘
```

When all fragments are received, the ciphertext is reassembled and
the handshake can proceed.

## Current Limitations

- **Not compiled**: the firmware has not been built with any SDK version.
- **No crypto**: the current skeleton does not perform ML-KEM or AES-GCM.
- **Fragment reassembly incomplete**: the `write_ct` handler stores
  fragments but does not fully reassemble (TODO marker in code).
- **No serial bridge**: UART communication with host PC is not implemented.
- **No SAS display**: no mechanism to show the 6-digit SAS to the user.

These are all documented as TODO markers in `main.c`.
