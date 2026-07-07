# PQ-BLE-HANDSHAKE

## Canale sicuro post-quantum su BLE via GATT con SAS Numeric Comparison

Proof-of-concept per stabilire un canale cifrato post-quantum sopra Bluetooth Low Energy GATT, senza modificare lo stack BLE nativo.

Il protocollo usa:

1. **ML-KEM-768** (NIST FIPS 203, security category 3) per derivare una shared secret post-quantum.
2. **SAS Numeric Comparison** a 6 cifre per rilevare MITM attivi tramite confronto umano.
3. **HKDF-SHA256** per derivare la session key.
4. **AES-256-GCM** con AAD e replay protection per cifrare e autenticare i payload applicativi.
5. **Session resumption** tramite `session_id` e store JSON, con re-handshake periodico.

---

## Validation layers

Validation is split into three layers:

1. **Cryptographic validation (Python)**: ML-KEM-768, SAS, HKDF, AES-256-GCM with AAD,
   fragmentation, session resumption, replay protection — 109+ automated tests.

2. **BLE/GATT transport validation (nRF54L15 DK)**: The DK runs a Zephyr firmware
   exposing the PQ-BLE custom GATT service. The PC acts as Central and exchanges
   protocol messages over real BLE. Mode: `DEMO_PRECOMPUTED_KEM` (precomputed vectors).

3. **Observational validation (nRF52840 Dongle)**: The dongle passively captures
   the PC↔DK connection in Wireshark, confirming that PQ-BLE messages are
   transported as GATT operations.

Full embedded ML-KEM execution on nRF54L15 is left as future work.

---

## Hardware architecture

```
PC (Python + Bleak)     ←── BLE/GATT ──→     nRF54L15 DK (Zephyr firmware)
  Central / Client                                 Peripheral / GATT Server
         ↑
         │ passively sniffed by
    nRF52840 Dongle (Wireshark)
```

| Role | Hardware | Software | Status |
|------|----------|----------|--------|
| Central | PC | Python + Bleak | ✅ Implemented |
| Peripheral | nRF54L15 DK | Zephyr firmware (`DEMO_PRECOMPUTED_KEM`) | ✅ GATT transport implemented |
| Sniffer | nRF52840 Dongle | Wireshark / nRF Sniffer | Passive capture |
| ML-KEM on-chip | nRF54L15 | liboqs port | ❌ Future work |

> The nRF52840 Dongle is **only a sniffer**. It is NOT used as central or peripheral.
>
> The Python peripheral (`experimental/peripheral/`, based on BleakServer) is
> **NOT part of the real BLE demo**. It is experimental, Linux-only, and untested
> on real BLE hardware.

---

## Status

- ✅ **Cryptographic logic** (ML-KEM-768, SAS, HKDF, AES-256-GCM with AAD + replay protection): implemented and tested in Python.
- ✅ **Central BLE transport** (Python + Bleak): fragmented read/write, MTU negotiation, notify subscription.
- ✅ **Firmware GATT service** (nRF54L15 DK, Zephyr): correct UUIDs, fragment accumulation, real `bt_gatt_notify()`.
- ✅ **Firmware UUID consistency test**: automated check that firmware UUIDs match Python `constants.py`.
- ✅ **Central transport mock test**: mock GATT client validates fragmented read/write flow.
- ✅ **Comparative sniffing simulation**: Scenario A (plaintext) vs Scenario B (encrypted), with exportable reports.
- ⚠️ **Firmware not compiled**: the firmware source is complete but has NOT been compiled or tested on hardware yet.
- ⚠️ **No real BLE end-to-end test**: requires flashing the DK and running the central on a PC with BLE adapter.
- ❌ **On-chip ML-KEM**: porting liboqs to Cortex-M33 is future work.

---

## Quickstart

```bash
# 1. Setup
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 2. Run tests
pytest tests/ -v

# 3. Benchmark
bash benchmarks/run_all.sh

# 4. Comparative sniffing simulation
python tests/sniff_test.py
```

---

## Real hardware demo

### Prerequisites

- nRF54L15 DK (PCA10155)
- nRF52840 Dongle (for sniffing)
- PC with Bluetooth adapter (Linux + BlueZ recommended)
- nRF Connect SDK >= 2.8.0
- Wireshark + nRF Sniffer for Bluetooth LE

### Step 1: Generate demo vectors

```bash
python scripts/generate_demo_vectors.py
# Copy the generated C arrays into firmware/nrf54l15_pq_gatt_skeleton/src/main.c
```

### Step 2: Build and flash firmware

```bash
cd firmware/nrf54l15_pq_gatt_skeleton
west build -b nrf54l15dk/nrf54l15/cpuapp -p always
west flash
```

### Step 3: Start Wireshark with nRF52840 sniffer

1. Plug in the nRF52840 Dongle
2. Open Wireshark
3. Select "nRF Sniffer for Bluetooth LE" interface
4. Filter: `btatt` (to see GATT operations)

### Step 4: Run the central

```bash
cd ../..  # back to project root
python -m src.central.main --device PQ-BLE-Device --demo --log-level DEBUG
```

CLI options:

```
--device NAME        BLE device name (default: PQ-BLE-Device)
--no-sas-confirm     Skip interactive SAS confirmation
--demo               Demo mode: send START, wait for precomputed notify
--mtu SIZE           Request specific MTU
--log-level LEVEL    DEBUG | INFO | WARNING | ERROR
```

### Expected Wireshark capture

```
ADV_IND              — advertising: "PQ-BLE-Device"
CONNECT_IND          — PC → DK connection
ATT Exchange MTU     — MTU negotiation (if supported)
ATT Read Request     — Public Key characteristic
ATT Read Blob        — (multiple, if pk > MTU)
ATT Read Response    — 1184 bytes total
ATT Write Request    — Ciphertext fragment 1/3 (header + payload)
ATT Write Request    — Ciphertext fragment 2/3
ATT Write Request    — Ciphertext fragment 3/3
ATT Write Request    — Control: "START"
ATT Handle Value Notification — encrypted payload (AES-256-GCM)
```

**What the sniffer sees:**
- ✅ Public key (ML-KEM-768) — public, safe to observe
- ✅ Ciphertext (ML-KEM) — public, IND-CCA secure
- ✅ AES-256-GCM encrypted payload — not decryptable without session key
- ❌ SMP pairing: **absent** (expected — security is application-layer)
- ❌ Link-layer encryption: **absent** (expected — no BLE Security Manager)
- ❌ Plaintext application data: **not visible** (protected by AES-GCM)

---

## Test suite

| File | Tests | Scope |
|---|---:|---|
| `test_ml_kem.py` | 6 | ML-KEM keygen, encaps, decaps |
| `test_fragmentation.py` | 14 | GATT fragmentation and reassembly |
| `test_sas.py` | 12 | SAS Numeric Comparison |
| `test_session.py` | 22 | HKDF, AES-GCM, AAD, replay protection, msg_type binding |
| `test_session_store.py` | 23 | Session resumption and persistent store |
| `test_handshake_mock.py` | 2 | Full pipeline without real BLE |
| `test_mitm_simulation.py` | 2 | MITM detection via SAS mismatch |
| `test_firmware_uuids.py` | 11 | Firmware UUID consistency with Python constants |
| `test_central_transport_mock.py` | 17 | Fragmented read/write with mock GATT |
| **Total** | **109** | Full proof-of-concept validation |

---

## Structure

```text
pq-ble-handshake/
├── src/
│   ├── common/           # ML-KEM, fragmentation, SAS, HKDF, AES-GCM, SessionStore
│   └── central/          # BLE client + handshake (PC central with Bleak)
├── experimental/
│   └── peripheral/       # Python BleakServer peripheral (NOT used in real demo)
├── firmware/
│   ├── nrf54l15_pq_gatt_skeleton/  # Zephyr firmware for DK (DEMO_PRECOMPUTED_KEM)
│   │   ├── src/main.c
│   │   ├── CMakeLists.txt
│   │   ├── prj.conf
│   │   └── README.md
│   └── nrf54l15/         # Reference design (older, kept for comparison)
├── tests/                # 109 automated tests
├── benchmarks/           # Latency/throughput/fragmentation benchmarks
├── scripts/              # setup.sh, run_demo.sh, generate_demo_vectors.py
├── docs/                 # Protocol spec, design decisions, testing guide, security analysis
└── data/keys/            # Session store JSON (auto-generated)
```

---

## Protocol

### 1. Handshake ML-KEM-768

The peripheral generates `(pk_A, sk_A)` and exposes `pk_A` via GATT. The central reads `pk_A`, runs `encapsulate(pk_A)`, and sends the ciphertext `ct` to the peripheral.

| Object | Size |
|---|---:|
| Public key | 1184 B |
| Ciphertext | 1088 B |
| Shared secret | 32 B |

With 512-byte MTU and 4-byte fragment header, payload per fragment = 508 B:

| Object | Raw | Wire | Fragments |
|---|---:|---:|---:|
| `pk_A` | 1184 B | 1196 B | 3 |
| `ct` | 1088 B | 1100 B | 3 |
| Total | 2272 B | 2296 B | 6 |

### 2. SAS Numeric Comparison

```text
transcript = pk_A || ct || shared_secret
sas = SHA256(transcript)[0:4] mod 1_000_000
```

The 6-digit code must be compared by the user. If it doesn't match, the handshake is aborted.

### 3. Secure channel (AES-256-GCM with AAD)

Session key derived via HKDF-SHA256. Payloads encrypted with AES-256-GCM.

**AAD** (Additional Authenticated Data):
```
session_id (16) || sender_role (1) || seq_num (8) || msg_type (1)
```

**Wire format:**
```
seq_num (8) || msg_type (1) || iv (12) || ciphertext || tag (16)
```

Security properties:
- **Replay protection**: monotonically increasing seq; receiver rejects seq ≤ last accepted.
- **Direction separation**: each side encrypts with own role, decrypts expecting peer's role (prevents reflection).
- **Session binding**: session_id in AAD prevents cross-session confusion.
- **Message-type binding**: msg_type in AAD prevents data↔control substitution.

### 4. Session resumption

After the first handshake, both sides can persist `session_id → session_key`. On reconnect, the central sends `RESUME(session_id)`. If found, the encrypted channel is restored without repeating ML-KEM and SAS.

---

## Limitations

- ML-KEM-768 is post-quantum, but this protocol is NOT a Bluetooth SIG standard.
- SAS requires human interaction; doesn't scale for massive IoT deployments.
- Encryption is application-layer; it does NOT replace BLE Security Manager functions.
- The DK firmware does NOT execute ML-KEM on-chip (future work). Current mode uses precomputed vectors.
- SMP pairing is intentionally disabled (`CONFIG_BT_SMP=n`): link-layer encryption is absent by design.
- The Python peripheral (`experimental/`) uses BleakServer (experimental, Linux-only, untested on BLE).
- MTU 512 is a default, not a guarantee. The code negotiates MTU and falls back gracefully.

---

## Roadmap

- ✅ AAD with `session_id + role + seq_num + msg_type`, replay protection, direction separation.
- ✅ Fragmentation integrated in central transport path.
- ✅ Firmware UUIDs aligned with Python constants.
- ✅ Firmware UUID consistency test.
- ✅ Central transport mock test.
- [ ] Compile and flash firmware on nRF54L15 DK.
- [ ] Real BLE end-to-end demo: PC central + DK peripheral + nRF52840 sniffer.
- [ ] Wireshark capture screenshots for tesina.
- [ ] Port liboqs to Cortex-M33 for on-chip ML-KEM.
- [ ] Replace precomputed vectors with on-chip key generation.
- [ ] ML-DSA (NIST FIPS 204) for non-interactive authentication.
- [ ] Hybrid ECDH + ML-KEM handshake.
