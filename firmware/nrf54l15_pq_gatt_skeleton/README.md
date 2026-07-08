# nRF54L15 DK Firmware — PQ-BLE GATT Skeleton

> **STATUS**: This firmware implements a real BLE/GATT peripheral on the nRF54L15 DK.
> It validates the BLE/GATT transport layer on real hardware.
>
> **It does NOT execute ML-KEM on-chip.** Full embedded post-quantum cryptography is future work.
> The current firmware exposes the GATT interface required by the PQ-BLE handshake and uses demo/precomputed data for transport validation.

## What this firmware does

| Feature | Status |
|---------|--------|
| BLE advertising as `PQ-BLE-Device` | Implemented |
| GATT Service with correct UUIDs | Implemented |
| Public Key characteristic (READ) | Implemented |
| Ciphertext characteristic (WRITE) | Fragment accumulation + reassembly |
| Secure Data characteristic (NOTIFY) | Real `bt_gatt_notify()` |
| Control characteristic (WRITE) | START command handling |
| CCCD notification subscription | Implemented |
| MTU negotiation logging | Implemented |
| ML-KEM key generation on-chip | Future work |
| ML-KEM decapsulation on-chip | Future work |
| AES-256-GCM on-chip | Future work |
| Session store on flash | Future work |

## Current demo mode

The current firmware validates the BLE/GATT transport path between:

```text
PC Central  ←── BLE ──→  nRF54L15 DK Peripheral
```

The firmware exposes:

1. a readable Public Key characteristic;
2. a writable Ciphertext characteristic;
3. a notifiable Secure Data characteristic;
4. a writable Control characteristic.

The expected BLE/GATT flow is:

1. the PC central connects to the nRF54L15 DK;
2. the PC reads the public key from the Public Key characteristic;
3. the PC writes the ciphertext to the Ciphertext characteristic using fragmentation;
4. the PC enables notifications on the Secure Data characteristic;
5. the PC writes `START` to the Control characteristic;
6. the firmware sends a demo notification with `bt_gatt_notify()`.

This validates the real BLE/GATT transport layer on hardware.

The cryptographic operations are not executed on the nRF54L15 DK in this firmware version. ML-KEM, session key derivation, AES-GCM encryption/decryption, replay protection, and secure channel logic are currently implemented and tested on the Python side.

## Build and flash

From the firmware directory:

```bash
cd firmware/nrf54l15_pq_gatt_skeleton
west build -b nrf54l15dk/nrf54l15/cpuapp -p always
west flash
```

On Windows, to avoid path length issues, it is recommended to copy the firmware project to a short path such as:

```text
C:\myfw\pq
```

and build from there:

```powershell
cd C:\myfw\pq
west build -b nrf54l15dk/nrf54l15/cpuapp -p always
west flash
```

The successful build generates:

```text
build/merged.hex
```

## Hardware setup

```text
PC (Python/Bleak)  ←── BLE ──→  nRF54L15 DK (Zephyr firmware)
         ↑
         │ sniffed by
    nRF52840 Dongle (Wireshark, passive)
```

- **nRF54L15 DK**: BLE peripheral running this firmware.
- **PC**: BLE central running the Python client.
- **nRF52840 Dongle**: passive sniffer used with Wireshark.

## UUID reference

| Element | UUID | Properties |
|---|---|---|
| Service | `12345678-1234-1234-1234-123456789abc` | — |
| Public Key | `12345678-1234-1234-1234-123456789abd` | READ |
| Ciphertext | `12345678-1234-1234-1234-123456789abe` | WRITE |
| Secure Data | `12345678-1234-1234-1234-123456789abf` | NOTIFY |
| Control | `12345678-1234-1234-1234-123456789ac0` | WRITE |

These UUIDs must match `src/common/constants.py`.

## Manual validation with nRF Connect Mobile

After flashing the firmware:

1. scan for `PQ-BLE-Device`;
2. connect to the device;
3. read the Public Key characteristic;
4. enable notifications on the Secure Data characteristic;
5. write `START` to the Control characteristic.

If `START` is sent before writing the ciphertext, the firmware correctly logs that the ciphertext has not yet been received.

## Current validation status

The firmware has been validated for:

- successful build on nRF Connect SDK 3.0.0;
- successful flash on nRF54L15 DK;
- BLE advertising;
- connection from nRF Connect Mobile;
- MTU negotiation;
- Public Key long read;
- notification subscription;
- Control write with `START`.

## Future work: on-chip ML-KEM

To execute ML-KEM-768 entirely on the nRF54L15 DK:

1. port a lightweight ML-KEM implementation to Cortex-M33;
2. generate the ML-KEM keypair on-chip;
3. expose the public key through GATT;
4. decapsulate the received ciphertext on-chip;
5. derive the session key on-chip;
6. execute AES-256-GCM on-chip;
7. persist session/resumption state in flash;
8. expose SAS confirmation through UART, LEDs, buttons, or a display.
