# Test Results

Risultati aggiornati della validazione del progetto **PQ-BLE-HANDSHAKE**.

Comando usato per eseguire la suite Python:

```bash
python -m pytest tests/ -v
```

Risultato corrente della suite attiva:

```text
101 passed
```

La suite attiva valida la parte crittografica, la frammentazione GATT, la logica di sessione, la protezione replay, il mock del trasporto BLE central e alcuni controlli firmware di base.

---

## Python automated test suite

| Test file | Active tests | Scope |
|---|---:|---|
| `test_ml_kem.py` | 6 | ML-KEM-768 key generation, encapsulation, decapsulation, roundtrip and repeated iterations |
| `test_fragmentation.py` | 14 | GATT fragmentation/reassembly, single and multiple fragments, missing fragments, duplicates, variable MTU |
| `test_sas.py` | 12 | 6-digit SAS Numeric Comparison, determinism, sensitivity to transcript changes, formatting and distribution |
| `test_session.py` | 22 | HKDF, AES-256-GCM, AAD, replay protection, out-of-order rejection, role separation, session binding, `msg_type` binding, tampering detection and IV uniqueness |
| `test_session_store.py` | 23 | Session ID generation, resume request parsing, persistent store, expiry, usage counter and re-handshake mitigation |
| `test_handshake_mock.py` | 2 | Full handshake pipeline without real BLE hardware |
| `test_mitm_simulation.py` | 2 | MITM simulation and SAS mismatch detection |
| `test_firmware_uuids.py` | 3 | Firmware device name, SMP disabled, `bt_gatt_notify()` present |
| `test_central_transport_mock.py` | 17 | Fragmented public-key read and ciphertext write with mock GATT client, header validation, reassembly and MTU handling |
| **Total** | **101** | Current active proof-of-concept validation |

---

## Notes on firmware UUID tests

The previous strict UUID parser tests were disabled/commented because they were tied to an older firmware UUID declaration format.

The currently active firmware checks still validate that:

- the firmware uses the expected device name;
- BLE SMP is disabled as intended;
- the firmware contains a real `bt_gatt_notify()` path.

UUID consistency is currently validated through:

1. the firmware source and README UUID table;
2. nRF Connect Mobile GATT inspection;
3. the real PC central ↔ nRF54L15 DK hardware demo;
4. the passive nRF52840/Wireshark capture.

---

## nRF54L15 DK hardware validation

A real BLE/GATT hardware validation was performed using:

- **Windows PC** as BLE central;
- **nRF54L15 DK** as BLE peripheral/GATT server;
- **nRF Connect Mobile** for manual GATT inspection;
- **nRF52840 Dongle** as passive Wireshark sniffer.

The nRF54L15 DK firmware was successfully built and flashed.

Validated firmware path:

```text
firmware/nrf54l15_pq_gatt_skeleton/
```

Validated board target:

```text
nrf54l15dk/nrf54l15/cpuapp
```

Observed flash result:

```text
Board with serial number ... flashed successfully.
```

---

## Manual validation with nRF Connect Mobile

The device was visible as:

```text
PQ-BLE-Device
```

Manual GATT validation confirmed:

- successful connection from phone;
- MTU negotiation;
- public key characteristic long read;
- notification subscription;
- control characteristic write;
- correct handling of `START`.

Observed DK firmware log for manual phone test:

```text
PK read: offset=0, len=246
PK read: offset=246, len=246
PK read: offset=492, len=246
Notifications ENABLED
Control write: len=5
Control data: START
Received START command
START received but ciphertext not yet written
```

This is expected when `START` is sent before writing the ciphertext.

---

## PC central ↔ nRF54L15 DK hardware demo

The PC central demo was executed with:

```bash
python -m src.central.main --device PQ-BLE-Device --demo --no-sas-confirm --log-level DEBUG
```

Observed result:

```text
Found PQ-BLE-Device
Connected
Read public key: 1184 bytes
Encapsulate: ct=1088 bytes, ss=32 bytes
Writing ciphertext: 1088 bytes in 5 fragments
Ciphertext written
SAS derived
Session key: 32 bytes
START sent
Raw demo notification received: 57 bytes
BLE/GATT transport validation completed.
```

Validated hardware flow:

1. PC central discovered `PQ-BLE-Device`;
2. PC central connected to the nRF54L15 DK;
3. MTU was negotiated to 247;
4. the 1184-byte public key was read from the DK;
5. the PC generated a 1088-byte ML-KEM ciphertext;
6. the ciphertext was written to the DK in 5 GATT fragments;
7. SAS was derived on the PC side;
8. the session key was derived on the PC side;
9. `START` was written to the Control characteristic;
10. the DK sent a 57-byte raw notification;
11. the central received the notification and completed the BLE/GATT transport validation.

A raw execution log is available in:

```text
docs/hardware-validation-log.txt
```

---

## Passive nRF52840/Wireshark capture

A passive BLE capture was performed using the nRF52840 Dongle with Wireshark/nRF Sniffer.

The capture confirms that the PQ-BLE exchange is transported over standard BLE ATT/GATT operations.

Observed ATT/GATT evidence:

| Evidence | Wireshark interpretation |
|---|---|
| MTU negotiation | ATT Exchange MTU Request/Response |
| Public key read | ATT Read Request + ATT Read Blob Requests |
| Ciphertext transfer | ATT Prepare Write / Execute Write operations |
| START command | GATT write containing `53 54 41 52 54` (`START`) |
| Firmware response | ATT Handle Value Notification |

Observed handles:

| GATT element | Handle |
|---|---:|
| Public Key characteristic value | `0x0012` |
| Ciphertext characteristic value | `0x0014` |
| Notification CCCD | `0x0017` |
| Control characteristic value | `0x0019` |

The 1184-byte public key was read through long GATT read operations on handle `0x0012`, with offsets:

```text
0, 246, 492, 738, 984
```

The 1088-byte ML-KEM ciphertext was generated by the PC central and transported to the DK through the Ciphertext characteristic on handle `0x0014`. At the PQ-BLE application layer it is split into 5 fragments. In the Windows/Bleak capture, the BLE stack represents the long GATT writes through ATT Prepare Write and Execute Write operations.

This provides packet-level evidence that the hardware demo uses standard ATT/GATT transport.

---

## Current interpretation

The current implementation validates:

- the Python cryptographic protocol logic;
- the Python secure channel implementation;
- replay protection and AAD binding;
- GATT fragmentation/reassembly logic;
- BLE central transport logic;
- real BLE/GATT communication between PC and nRF54L15 DK;
- passive packet-level observation with nRF52840/Wireshark.

The current firmware does **not** yet validate:

- on-chip ML-KEM decapsulation;
- on-chip HKDF/session key derivation;
- on-chip AES-256-GCM encryption;
- persistent session storage on the DK.

Therefore, in the current hardware demo, the final DK notification is treated as a **raw hardware-demo notification**, not as a fully decryptable secure-channel message.
