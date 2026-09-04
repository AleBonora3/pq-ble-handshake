# PQ-BLE Firmware

Embedded peripheral implementation for PQ-BLE-HANDSHAKE.

## Hardware

Validated on:

- Nordic nRF54L15 DK
- Target: nrf54l15dk/nrf54l15/cpuapp
- nRF Connect SDK 3.0.0
- Zephyr 4.0.99
- Zephyr SDK 0.17.0 / GCC 12.2

## Current cryptographic status

ML-KEM-768:
- mlkem-native v2.0.0
- portable C backend
- on-device KeyGen: validated
- on-device Encapsulation: validated
- on-device Decapsulation: validated
- deterministic startup self-test: PASS

BLE integration:
- public key transport: validated
- ciphertext transport: validated
- ML-KEM decapsulation of BLE-received ciphertext: next milestone

# nRF54L15 DK Firmware — PQ-BLE GATT Skeleton

> **STATUS**: This firmware implements a real BLE/GATT peripheral on the nRF54L15 DK.
> It validates the BLE/GATT transport layer on real hardware and runs an
> isolated deterministic ML-KEM-768 startup self-test.
>
> **The self-test is not connected to GATT.** The current GATT interface still
> uses demo/precomputed data for transport validation.

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
| Deterministic ML-KEM-768 startup self-test | Implemented |
| ML-KEM key generation used by GATT | Future work |
| ML-KEM decapsulation of received GATT ciphertext | Future work |
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

The startup self-test executes deterministic ML-KEM-768 key generation,
encapsulation, and decapsulation on the nRF54L15. It compares the two shared
secrets and prints an explicit PASS or FAIL result. This generated keypair and
the received GATT ciphertext are deliberately not connected yet. Session key
derivation, AES-GCM encryption/decryption, replay protection, and secure-channel
logic remain outside this firmware milestone.

## Embedded ML-KEM integration

The firmware vendors `pq-code-package/mlkem-native` v2.0.0 at commit
`d1b2fe782888bdb761a50336012923180be7f502` under
`third_party/mlkem-native`. See `third_party/mlkem-native/VENDORED.md` and the
preserved upstream `LICENSE` for the exact source selection, configuration, and
license attribution.

Only the portable C arithmetic and portable C FIPS-202 implementation are
compiled. The deterministic API is enabled with fixed coins marked
`TEST ONLY - NOT FOR PRODUCTION`; the randomized API and production RNG are not
part of this milestone.

The main stack is configured as 24576 B, up from the previous 20480 B after an
on-device decapsulation stack overflow. This reserves an additional 4096 B for
the next measurement build, and 20480 B above the original 4096 B baseline.
`CONFIG_INIT_STACKS` and
`CONFIG_THREAD_STACK_INFO` enable cumulative main-thread stack watermark
reports at each self-test checkpoint. The self-test also has 4736 B of writable
file-static result buffers plus 96 B of fixed test coins (4832 B total static
test data). A Memory
Report delta therefore must distinguish reserved stack, static test data,
other BSS/data, and library code; it is not a direct measurement of ML-KEM peak
runtime memory. Peak main-thread stack usage is measured separately at runtime.

## Build and flash

The normal Windows workflow remains the nRF Connect for VS Code **Actions**
panel. Select the existing build configuration for
`nrf54l15dk/nrf54l15/cpuapp`, run **Pristine Build** once so the new CMake and
Kconfig settings are applied, then use **Flash**. No alternate build system or
standalone Makefile is required.

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

## Future cryptographic milestones

The startup self-test intentionally stops before protocol integration. Future
work includes:

1. integrate a production CSPRNG/PSA/hardware RNG;
2. connect an on-device ML-KEM keypair to the Public Key characteristic;
3. decapsulate the received ciphertext on-chip;
4. derive the session key on-chip;
5. execute AES-256-GCM on-chip;
6. add the hybrid ECDH + ML-KEM handshake;
7. persist session/resumption state in flash;
8. expose SAS confirmation through UART, LEDs, buttons, or a display.
