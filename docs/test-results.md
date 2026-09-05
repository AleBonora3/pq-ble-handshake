# Test Results

Risultati aggiornati della validazione del progetto **PQ-BLE-HANDSHAKE**.

Comando riproducibile per eseguire la suite Python:

```bash
python -m pytest tests/ -v
```

Risultato verificato dopo l'implementazione v0.5:

```text
170 passed, 2 warnings
```

Il primo warning segnala che il wrapper temporaneo `liboqs-python` 0.16.0 ha
trovato la libreria liboqs 0.15.0 installata. `ML-KEM-768` era disponibile e
tutti i test crittografici liboqs sono passati. Il secondo riguarda i permessi
della directory `.pytest_cache` esistente e non modifica l'esito dei test.

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
| `test_firmware_uuids.py` | 9 | Firmware/Python UUID parity, device name, SMP disabled and `bt_gatt_notify()` present |
| `test_central_transport_mock.py` | 18 | Fragmented public-key read and ciphertext write with mock GATT client, reassembly, MTU handling and 512-byte frame cap |
| `test_phase2_diagnostic.py` | 7 | Exact 9-byte `PQM2` codec, big-endian checksum and known CRC vector |
| `test_phase2_e2e.py` | 16 | Isolated Phase 2 Central flow, cross-thread notification delivery, exact-result validation and failure exits |
| `test_phase5_primitives.py` | 19 | Canonical transcript, deterministic KATs, SAS/FINISHED, framing and state rejection |
| `test_phase5_auth_mock.py` | 12 | Positive/SAS-rejection paths, one-bit FINISHED hooks, transcript mismatch, no-DATA assertions and CLI exit status |
| **Total** | **170** | Complete active Python suite |

---

## Phase 2 implementation validation status

Implemented in source:

- production-random on-device ML-KEM-768 KeyGen using PSA Crypto, with
  immediate erasure of the 64-byte `d || z` input;
- dynamic GATT Public Key value and RAM-only DK secret key;
- dedicated 28672-byte preemptible ML-KEM worker for KeyGen and Decaps;
- cumulative worker stack watermark reporting after KeyGen and every Decaps;
- explicit ciphertext states `EMPTY`, `RECEIVING`, `CT_READY` and
  `CRYPTO_BUSY`, with hardened validation and one-use `START` semantics;
- protected Zephyr connection lifetime across asynchronous decapsulation;
- exact nine-byte `PQM2` result and explicit Central `--phase2-e2e` path;
- Python validation of the 32-zero-byte CRC-32/IEEE vector `0x190A55AD`, plus
  a firmware startup KAT that is compiled and awaits execution on the DK.

The Phase 2 Central deliberately bypasses resumption, SAS, HKDF, AES
SecureChannel semantics and persistence. The **TEST-ONLY shared-secret
diagnostic checksum** is not authentication, not a KDF, not cryptographic key
confirmation and not part of the final protocol. No shared-secret bytes are
sent over BLE.

Validation matrix:

| Item | Status |
|---|---|
| Focused Phase 2/transport/firmware Python tests | **50 passed** |
| Complete Python suite | **170 passed**, 1 version warning plus 1 pytest cache-permission warning |
| NCS 3.0.0 pristine build for `nrf54l15dk/nrf54l15/cpuapp` | **PASS**; 183716 B flash, 104944 B RAM |
| NCS 3.0.0 build with `phase1_selftest.conf` | **PASS**; opt-in symbol enabled |
| Real-DK `--phase2-e2e` shared-secret equality | **Pending hardware validation** |

No `MATCH: YES` claim is made for Phase 2 hardware until the final row is
executed on the physical DK.

---

## v0.5 authenticated pure-PQ validation status

Implemented in source:

- one versioned, length-prefixed transcript on Python and PSA SHA-256 paths;
- one transcript-salted 128-byte HKDF-SHA256 schedule split into four keys;
- independent six-digit transcript-bound SAS computation on PC and DK;
- full direction-specific Central and Peripheral HMAC-SHA256 FINISHED values;
- strict `PQS5` framing and out-of-order/duplicate rejection;
- explicit user confirmation defaulting to no;
- activation of the existing 58-byte AES-256-GCM application message only
  after Peripheral FINISHED has been verified by the Central;
- disconnect epoch and connection-generation checks for stale worker results.

The exact public KAT, formulas, wire formats, and first hardware procedure are
in
[`research/milestones/v0.5-authenticated-pq-handshake.md`](research/milestones/v0.5-authenticated-pq-handshake.md).
The pristine v0.5 NCS 3.0.0 build passed at 200384 B FLASH and 105744 B RAM;
the detailed baseline comparison is recorded there.
The positive authenticated handshake passed twice on the physical DK, including
after a power cycle. SAS rejection also passed. Public-key fingerprint prefixes
changed from `168802e5a8a4edcd` to `27becddf8df08ef0` across boots, confirming a
fresh runtime keypair. The remaining FINISHED_C, FINISHED_P and transcript
negative modes await their physical runs, so v0.5 must not yet be tagged.

---

## Notes on firmware UUID tests

The parser now normalizes the C preprocessor line continuations used by active
`firmware/src/main.c`. Six assertions compare all five firmware UUIDs with the
Python constants and require the complete set. Three additional checks cover
the advertised device name, disabled SMP, and the real `bt_gatt_notify()`
path. Historical nRF Connect and Wireshark evidence remains useful as a
separate hardware-level check.

---

## nRF54L15 DK hardware validation

A real BLE/GATT hardware validation was performed using:

- **Windows PC** as BLE central;
- **nRF54L15 DK** as BLE peripheral/GATT server;
- **nRF Connect Mobile** for manual GATT inspection;
- **nRF52840 Dongle** as passive Wireshark sniffer.

The nRF54L15 DK firmware was successfully built and flashed.

Validated historical firmware source is now located under:

```text
firmware/
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

## Historical PC central ↔ nRF54L15 DK transport demo

The pre-Phase-2 Central demo was executed with:

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

Validated historical hardware flow:

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

This run used the former offline public key and raw 57-byte placeholder. It is
preserved as transport evidence and is not a Phase 2 E2E ML-KEM result.

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
- real-DK execution of the deterministic Phase 1 mlkem-native
  KeyGen → Encaps → Decaps self-test, frozen as `v0.2-mlkem-ondevice`.

The implemented Phase 2 source adds on-device ML-KEM KeyGen/Decaps integrated
with GATT. The following are **not yet validated as a Phase 2 real-hardware
result**:

- liboqs Central and mlkem-native DK deriving the same secret over real BLE;
- the hardened connection/state behavior under real disconnect and error cases;
- the crypto-worker stack watermark after the integrated E2E exchange;
- on-chip HKDF/session key derivation;
- on-chip AES-256-GCM encryption;
- persistent session storage on the DK.

The old capture's raw notification remains historical. The Phase 2 firmware
uses `PQM2 || status || crc32_be` on the same Secure Data characteristic, and
the Phase 2 real-DK result remains pending.
