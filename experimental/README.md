# Experimental — Python BLE Peripheral (BleakServer)

> ⚠️ **NOT USED IN THE REAL BLE DEMO**
>
> The real demo uses:
> - **PC** as Central (Python + Bleak) → `src/central/`
> - **nRF54L15 DK** as Peripheral (Zephyr firmware) → `firmware/nrf54l15_pq_gatt_skeleton/`
> - **nRF52840 Dongle** as passive sniffer only (Wireshark)
>
> This Python peripheral is based on `bleak`'s `BleakServer`, which is:
> - **Experimental** — not a stable API
> - **Linux-only** — depends on BlueZ D-Bus
> - **Untested on real BLE hardware** in this project
> - **Fragile** — notification support is incomplete in many bleak versions
>
> It is kept here for reference and local testing of the protocol logic
> without hardware. Do **not** use it as part of the real BLE demo.

## Usage (experimental, Linux only)

```bash
# From project root
PYTHONPATH=. python -m experimental.peripheral.main
```

## What works

- GATT service definition with correct UUIDs
- Public key read handler
- Ciphertext write handler with fragment accumulation
- Control message parsing (SAS confirm, resume request)
- Session resumption logic (Strada A)

## What does NOT work reliably

- GATT notifications (`notify_data()` may fail depending on bleak version)
- Advertising on some Linux/BlueZ configurations
- No testing on real BLE hardware has been performed

## For the real demo

Use the Zephyr firmware on nRF54L15 DK instead:

```bash
cd firmware/nrf54l15_pq_gatt_skeleton
west build -b nrf54l15dk/nrf54l15/cpuapp -p always
west flash
```
