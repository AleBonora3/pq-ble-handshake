# PQ-BLE-HANDSHAKE

**Post-quantum secure-channel proof of concept over Bluetooth Low Energy GATT.**

PQ-BLE-HANDSHAKE demonstrates how a post-quantum application-layer handshake can be transported over standard BLE GATT without modifying the native Bluetooth stack.

The protocol combines:

- **ML-KEM-768** — NIST FIPS 203, security category 3;
- **6-digit SAS Numeric Comparison** — interactive MITM detection;
- **HKDF-SHA256** — session-key derivation;
- **AES-256-GCM** — authenticated encryption with AAD;
- **monotonic sequence numbers** — replay and out-of-order protection;
- **session resumption** — time- and usage-bounded cached sessions.

> [!IMPORTANT]
> The validated `v0.4-pq-secure-channel` baseline provides the Phase 3 pure-PQ
> AES-256-GCM channel. Milestone v0.5 adds production-random on-device KeyGen,
> a versioned transcript, transcript-bound keys and six-digit SAS, bidirectional
> FINISHED, and authenticated activation of that existing channel. Its software
> tests, firmware build, and positive physical-DK handshake are complete.
> SAS rejection is also validated; three isolated FINISHED/transcript negative
> hardware tests remain. See
> [`docs/research/milestones/v0.5-authenticated-pq-handshake.md`](docs/research/milestones/v0.5-authenticated-pq-handshake.md).
> Hybrid P-256 + ML-KEM and bidirectional application traffic are not included.

---

## Project status

| Component | Status |
|---|---|
| Python cryptographic protocol | ✅ Implemented and tested |
| AES-256-GCM secure channel with AAD | ✅ Implemented and tested |
| Replay and out-of-order protection | ✅ Implemented and tested |
| Session resumption store | ✅ Implemented and tested |
| Re-handshake after 24 hours or 100 successful resumes | ✅ Implemented and tested |
| PC central ↔ nRF54L15 DK BLE/GATT demo | ✅ Validated on real hardware |
| nRF Connect Mobile manual GATT inspection | ✅ Completed |
| nRF52840 Dongle + Wireshark passive capture | ✅ Completed |
| Wireshark screenshots and `.pcapng` evidence | ✅ Included |
| Reproducible benchmark suite | ✅ Completed |
| Protocol-overhead validation | ✅ Implemented and tested |
| LaTeX report and compiled PDF | ✅ Included |
| On-device ML-KEM-768 self-test (Phase 1) | ✅ Validated on real hardware and frozen as `v0.2-mlkem-ondevice` |
| Phase 2 liboqs ↔ mlkem-native BLE diagnostic | ✅ Implemented and preserved |
| Phase 3 pure-PQ AES-256-GCM channel | ✅ Validated 10/10 on real hardware (`v0.4`) |
| Phase 5 authenticated pure-PQ handshake | ✅ Positive physical-DK E2E validated twice |
| Phase 5 SAS rejection | ✅ Physical-DK validation complete |
| Phase 5 FINISHED/transcript negative modes | Implemented; physical runs pending |
| Production-random on-device ML-KEM KeyGen | ✅ Implemented with PSA Crypto |
| Persistent session storage on the DK | ⏳ Future work |

The current automated result is recorded in
[`docs/test-results.md`](docs/test-results.md).

---

## Validation model

The project is validated at three distinct levels.

### 1. Cryptographic and protocol validation

The Python implementation covers:

- ML-KEM-768 key generation, encapsulation and decapsulation;
- FIPS 203 size checks for public key, secret key, ciphertext and shared secret;
- SAS derivation and comparison;
- HKDF-SHA256 session-key derivation;
- AES-256-GCM encryption and decryption;
- AAD binding;
- direction separation;
- session binding;
- message-type binding;
- replay and out-of-order rejection;
- fragmentation and reassembly;
- fixed SecureChannel overhead and full-handshake application-size checks;
- session persistence, expiry and bounded resumption;
- MITM simulations;
- mocked GATT transport.

### 2. Phase 2 ML-KEM interoperability implementation

The explicit `--phase2-e2e` path performs only:

```text
connect -> subscribe -> read dynamic DK public key
        -> liboqs ML-KEM-768 encapsulation
        -> existing fragmented ciphertext write -> START
        -> exact PQM2 notification -> compare diagnostic checksums
```

It bypasses `SessionStore`/resumption, SAS, HKDF, AES SecureChannel semantics
and session persistence. The DK performs production-random KeyGen at startup
using PSA Crypto and decapsulation in a dedicated preemptible Zephyr worker
with a 28672-byte stack;
ML-KEM never runs in a GATT callback. The firmware reports that worker's
cumulative configured, unused and estimated peak stack after KeyGen and each
decapsulation.

The final result is a nine-byte **TEST-ONLY shared-secret diagnostic checksum**
message, not the shared secret itself. It is not authentication, a KDF,
cryptographic key confirmation or part of the final protocol. Software tests
cover the exact message format and Central behavior. This diagnostic path
remains available for regression testing alongside Phase 3 and Phase 5.

### 3. Historical real BLE/GATT transport validation

Validated setup:

```text
Windows PC + Python/Bleak  <---- BLE/GATT ---->  nRF54L15 DK + Zephyr
```

Before Phase 2, the PC central successfully:

1. discovers `PQ-BLE-Device`;
2. connects to the nRF54L15 DK;
3. negotiates an ATT MTU of 247;
4. reads the 1184-byte ML-KEM public key;
5. verifies the public-key SHA-256 fingerprint;
6. performs ML-KEM encapsulation on the PC;
7. generates a 1088-byte ciphertext;
8. writes the ciphertext in 5 logical PQ-BLE fragments;
9. derives the SAS and session key on the PC side;
10. sends the `START` control command;
11. receives a 57-byte raw notification from the DK.

Observed result:

```text
Read public key: 1184 bytes
Encapsulate: ct=1088 bytes, ss=32 bytes
Writing ciphertext: 1088 bytes in 5 fragments
Raw demo notification received: 57 bytes
BLE/GATT transport validation completed.
```

This historical transport result used the former offline public key and
57-byte placeholder notification; it is not evidence of Phase 2 shared-secret
equality. The complete execution log is available in
[`docs/hardware-validation-log.txt`](docs/hardware-validation-log.txt).

### 4. Passive packet-level validation

The BLE exchange was captured with:

- **nRF52840 Dongle**;
- **nRF Sniffer for Bluetooth LE**;
- **Wireshark**.

The capture confirms:

- ATT MTU negotiation;
- public-key long read;
- ciphertext transfer;
- `START` control write;
- final Handle Value Notification.

Capture files:

- [`docs/captures/Cattura_PQ_BLE.pcapng`](docs/captures/Cattura_PQ_BLE.pcapng)
- [`docs/captures/Cattura_PQ_BLE_filtro_btatt.pcapng`](docs/captures/Cattura_PQ_BLE_filtro_btatt.pcapng)

---

## Hardware architecture

```text
                         passive capture
                    +-----------------------+
                    |                       v
Windows PC          |                 nRF52840 Dongle
Python + Bleak      |                 Wireshark / nRF Sniffer
Central / Client    |
        |
        +------------- BLE/GATT ------------+
                                           |
                                           v
                                  nRF54L15 DK
                                  Zephyr Peripheral
                                  Custom GATT Server
```

| Role | Hardware | Software | Purpose |
|---|---|---|---|
| Central | Windows PC | Python + Bleak | Protocol orchestration and ML-KEM encapsulation |
| Peripheral | nRF54L15 DK | Zephyr / nRF Connect SDK | Real GATT transport validation |
| Sniffer | nRF52840 Dongle | Wireshark + nRF Sniffer | Passive ATT/GATT observation |

The nRF52840 Dongle is used **only as a passive sniffer**.

The Python peripheral under `experimental/peripheral/` is not part of the real
hardware demo.

---

## Firmware keypair strategy

The nRF54L15 firmware generates its ML-KEM-768 keypair on-device at startup.
After `psa_crypto_init()`, `psa_generate_random()` supplies the 64-byte `d || z`
input to mlkem-native's deterministic KeyGen primitive; those temporary coins
are wiped immediately. The secret key exists only in DK RAM and is never logged
or exposed over GATT. The generated public key is returned by the unchanged
Public Key characteristic.

The historical `demo_public_key.h` remains reference material and is not the
active public key. The separate opt-in deterministic self-test remains
TEST-ONLY and does not supply runtime keys.

---

## GATT service

Service UUID:

```text
12345678-1234-1234-1234-123456789abc
```

| Characteristic | UUID suffix | Properties | Value handle | Purpose |
|---|---|---|---:|---|
| Public Key | `9abd` | READ | `0x0012` | Exposes the 1184-byte ML-KEM public key |
| Ciphertext | `9abe` | WRITE | `0x0014` | Receives the 1088-byte ciphertext |
| Secure Data | `9abf` | NOTIFY | `0x0016` | Sends Phase 2 diagnostics, Phase 3 data, or Phase 5 frames/data |
| Secure Data CCCD | — | READ/WRITE | `0x0017` | Enables notifications |
| Control | `9ac0` | WRITE | `0x0019` | Receives `START` and resume messages |

The observed handle layout is:

```text
0x0010  Custom service
0x0011  Public Key declaration
0x0012  Public Key value
0x0013  Ciphertext declaration
0x0014  Ciphertext value
0x0015  Secure Data declaration
0x0016  Secure Data value / notification handle
0x0017  Secure Data CCCD
0x0018  Control declaration
0x0019  Control value
```

---

## Wireshark evidence

### ATT MTU exchange

![ATT MTU exchange](docs/images/wireshark_MTU_exchange.png)

### ML-KEM public-key long read

![ML-KEM public-key long read](docs/images/wireshark_public_key_read.png)

The 1184-byte key is transferred through an ATT Read followed by Read Blob
operations at offsets:

```text
0, 246, 492, 738, 984
```

### ML-KEM ciphertext transfer

![ML-KEM ciphertext transfer](docs/images/wireshark_ciphertext_write.png)

The application fragmentation layer uses a validated logical fragment size of
247 bytes. Each logical fragment includes a 4-byte PQ-BLE header, leaving
243 bytes for ciphertext data:

```text
Logical fragment size = 247 bytes
PQ-BLE header         = 4 bytes
Ciphertext payload    = 243 bytes
Fragments             = ceil(1088 / 243) = 5
```

The 247-byte value is the budget passed to the PQ-BLE fragmentation function;
it must not be interpreted as the raw payload of a single ATT Write PDU.
On Windows/Bleak, the stack can map each logical write to ATT Prepare Write
and Execute Write procedures and can apply further lower-layer fragmentation.
If a backend reports MTU 517, the Central caps the logical value at the GATT
attribute maximum of 512 bytes (508 bytes after the existing header).

The Phase 2 firmware hardens the receiver without changing this wire format.
Its connection-scoped states are `EMPTY`, `RECEIVING`, `CT_READY` and
`CRYPTO_BUSY`. It rejects `idx >= total`, inconsistent totals and any final
length other than the mlkem-native ML-KEM-768 ciphertext size (1088 bytes),
handles duplicates without mixing transfers, resets stale reassembly for a new
valid transfer, and rejects fragments while crypto is busy. A successful
`START` consumes `CT_READY`, so the same ciphertext cannot be reused by a
second `START`. Disconnect clears the peer's transfer state.

The `START` callback gives the worker a complete ciphertext copy and a protected
Zephyr connection reference. If that peer disconnects while decapsulation is
running, the operation may finish, but the result is not sent to a stale or
replacement connection and all references are released.

### `START` control write

![START control write](docs/images/wireshark_start_write.png)

The payload:

```text
53 54 41 52 54
```

is the ASCII encoding of:

```text
START
```

### Historical final 57-byte notification

![Final 57-byte notification](docs/images/wireshark_start_notification_57_byte.png)

This captured Phase 1 transport-demo notification was sent through the Secure
Data value handle `0x0016`. Phase 2 reuses the same characteristic and
attribute order for its nine-byte `PQM2` result; no Phase 2 packet capture has
yet been recorded.

Useful display filters:

```text
btatt
btatt.handle == 0x0012
btatt.handle == 0x0014
btatt.handle == 0x0019
btatt.handle == 0x0016
btatt.opcode == 0x1b
```

---

## Protocol overview

### ML-KEM-768 exchange

```text
Peripheral / DK                         Central / PC

generates pk/sk in worker RAM
exposes dynamic pk through READ     --> read pk
                                        encapsulate(pk) -> ct, ss
receives ct through GATT WRITE      <-- write ct
worker decapsulates(sk, ct) -> ss
PQM2(status, CRC32(ss))             --> compare with CRC32(ss)
```

The Phase 2 implementation performs the decapsulation shown above on the DK,
but its real-BLE interoperability result is not considered validated until the
hardware run is completed. The checksum is diagnostic only; it does not add
authentication or key confirmation to the protocol.

The exact notification is:

```text
"PQM2" (4) || status (1) || CRC-32/IEEE(shared_secret) (4, big-endian)
```

Status values are `0x00` success, `0x01` keypair unavailable, `0x02`
ciphertext incomplete, `0x03` genuine local/API decapsulation failure and
`0x04` invalid protocol state. The known vector is 32 zero bytes →
`0x190A55AD`.

ML-KEM has implicit rejection: a structurally valid modified ciphertext can
complete normally with status `0x00` but derive a different secret. The Phase 2
observable is then checksum mismatch and `MATCH: NO`, not necessarily a
decapsulation API error.

ML-KEM-768 sizes:

| Object | Size |
|---|---:|
| Public key | 1184 B |
| Secret key | 2400 B |
| Ciphertext | 1088 B |
| Shared secret | 32 B |

ML-KEM is a key-encapsulation mechanism, not a signature algorithm. It is
used only to establish the shared secret. The current proof of concept
authenticates the handshake interactively through the SAS; ML-DSA-based
authentication remains future work.

### SAS Numeric Comparison

```text
transcript = public_key || ciphertext || shared_secret
sas = SHA256(transcript)[0:4] mod 1_000_000
```

The six-digit value must be compared by the users or endpoints. A mismatch
aborts the handshake.

### Session-key derivation

```text
session_key = HKDF-SHA256(shared_secret)
```

### AES-256-GCM secure channel

AAD:

```text
session_id (16) || sender_role (1) || seq_num (8) || msg_type (1)
```

Wire format:

```text
seq_num (8) || msg_type (1) || iv (12) || ciphertext || tag (16)
```

Authenticated metadata provides:

- replay protection;
- out-of-order rejection;
- direction separation;
- cross-session protection;
- message-type binding.

---
## Where the post-quantum overhead is paid

The large post-quantum objects are exchanged only during a full handshake:

| Object | Size |
|---|---:|
| ML-KEM-768 public key | 1184 B |
| ML-KEM-768 ciphertext | 1088 B |
| Cryptographic material | 2272 B |
| Application material with 247-byte logical fragments | 2292 B |

The 2292-byte figure consists of:

```text
1184 B public key
1088 B ciphertext
  20 B five application-fragment headers
------
2292 B
```

It does not include ATT, L2CAP, Link Layer or radio retransmission overhead.

After the session key has been derived, ML-KEM is no longer used for ordinary
application data. The channel switches to AES-256-GCM, whose wire format adds
a fixed 37-byte overhead:

```text
seq_num (8) || msg_type (1) || IV (12) ||
ciphertext || GCM tag (16)
```

Therefore:

```text
protected_message_size = plaintext_size + 37
```

| Plaintext | Protected message | Overhead |
|---:|---:|---:|
| 20 B | 57 B | 185.00% |
| 64 B | 101 B | 57.81% |
| 256 B | 293 B | 14.45% |
| 512 B | 549 B | 7.23% |
| 1024 B | 1061 B | 3.61% |

The 37-byte cost is not an ML-KEM or post-quantum object. It comes from the
application-layer secure-channel format, authenticated-encryption tag and
replay-protection metadata.

A Python session-resumption exchange uses 21 bytes for the request and 9 bytes
for `RESUME_OK`, for 30 application bytes before ATT/GATT overhead. A successful
resume avoids retransmitting the 1184-byte public key and the 1088-byte
ciphertext.

---

## Session resumption

The Python implementation stores:

```text
session_id -> session_key
```

A cached session is valid until the first of these limits is reached:

- **24 hours**;
- **100 successful resumptions**.

The usage counter is incremented only after a positive `RESUME_OK` response.
Timeouts and failed resume attempts do not consume the counter.

After the 100th successful resume, the cached entry is removed and the next
connection requires a full ML-KEM handshake.

The current nRF54L15 firmware does not yet implement on-device session
resumption, so hardware resume attempts fall back to the full transport demo.

### Forward-secrecy trade-off

Resumption reuses an existing session key and therefore does not provide full
forward secrecy for resumed sessions. Compromise of the cached key exposes all
traffic protected with that key until the next full handshake. Time- and
usage-based re-handshake limits reduce this exposure window.

---

## Automated tests

Run the complete suite:

```bash
python -m pytest tests/ -v
```

| Test module | Tests | Scope |
|---|---:|---|
| `test_ml_kem.py` | 6 | FIPS 203 sizes, key generation, encapsulation, decapsulation and roundtrip |
| `test_fragmentation.py` | 14 | Fragmentation and reassembly |
| `test_sas.py` | 12 | SAS derivation, comparison and formatting |
| `test_session.py` | 22 | HKDF, AES-GCM, AAD, replay and tampering |
| `test_session_store.py` | 23 | Persistence, expiry, usage limit and resumption |
| `test_handshake_mock.py` | 2 | Complete mocked handshake |
| `test_mitm_simulation.py` | 2 | SAS-based MITM detection |
| `test_firmware_uuids.py` | 9 | Firmware/Python UUID parity, name, SMP configuration and notification path |
| `test_central_transport_mock.py` | 18 | Mocked GATT read/write transport, including the 512-byte logical-frame cap |
| `test_protocol_overhead.py` | 8 | Fixed 37-byte overhead, 2292-byte full handshake and 30-byte resume exchange |
| `test_phase2_diagnostic.py` | 7 | Exact `PQM2` codec, big-endian CRC and zero-secret vector |
| `test_phase2_e2e.py` | 16 | Isolated Central flow, strict response validation and nonzero failure paths |
| `test_phase5_primitives.py` | 19 | Canonical transcript, KATs, framing and state rejection |
| `test_phase5_auth_mock.py` | 12 | Positive/rejection flows and isolated FINISHED/transcript negative modes |
| **Total** | **170** | Complete active Python suite |

The exact current pass count and commands used are recorded in
[`docs/test-results.md`](docs/test-results.md).

The protocol-overhead tests verify that:

- the SecureChannel adds exactly 37 bytes to every plaintext;
- the 1088-byte ciphertext becomes five logical fragments with the
  247-byte configuration;
- the fragmented ciphertext occupies 1108 application bytes;
- public key plus fragmented ciphertext occupy 2292 application bytes;
- the Python resume request and positive response occupy 30 application bytes.

Strict legacy UUID-parser tests remain disabled because they target an older
firmware declaration format. UUID consistency is additionally verified through
the source code, nRF Connect Mobile, the hardware log and the Wireshark capture.

---

## Benchmarks

The repository includes reproducible benchmarks for:

- ML-KEM key generation, encapsulation and decapsulation;
- SAS and HKDF latency;
- AES-256-GCM CPU throughput;
- application fragmentation and reassembly;
- 247-byte versus 512-byte logical fragment sizes;
- application-layer wire overhead.

### Windows PowerShell

```powershell
.\.venv\Scripts\activate
.\benchmarks\run_all.ps1
python scripts\generate_benchmark_latex.py
```

### Linux

```bash
source .venv/bin/activate
bash benchmarks/run_all.sh
python scripts/generate_benchmark_latex.py
```

Measured results are stored in
[`benchmarks/results/`](benchmarks/results/):

```text
environment.txt
handshake.txt
handshake_latency.json
throughput.txt
throughput.json
fragmentation.txt
fragmentation_overhead.json
latest.txt
```

The generator reads the JSON artifacts and writes:

```text
report/benchmark_values.tex
```

Interpretation:

- the handshake benchmark measures **cryptographic CPU latency**, excluding BLE
  scan, connection and GATT transfer;
- the throughput benchmark measures **AES-256-GCM CPU throughput**, not BLE
  radio throughput;
- the fragmentation benchmark measures the ciphertext with 247-byte and
  512-byte logical fragment sizes;
- the public key is not application-fragmented in the hardware demo and is
  transferred through ATT Long Read / Read Blob;
- the secure-channel wire overhead is 37 bytes:
  `seq(8) + msg_type(1) + IV(12) + tag(16)`.

---

## Report

The complete Italian academic report is available in LaTeX and PDF format:

- [LaTeX source](report/tesina.tex)
- [Generated benchmark values](report/benchmark_values.tex)
- [Compiled PDF](report/tesina.pdf)

The report includes the protocol design, threat model, implementation,
automated tests, hardware validation, Wireshark evidence, limitations and future
work.

---

## Quick start

### Windows PowerShell

```powershell
git clone https://github.com/AleBonora3/pq-ble-handshake.git
cd pq-ble-handshake

python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt

python -m pytest tests\ -v
```

Run the Phase 2 interoperability central after flashing the Phase 2 firmware:

```powershell
python -m src.central.main `
    --device PQ-BLE-Device `
    --phase2-e2e `
    --log-level DEBUG
```

`--demo` remains an explicit legacy/deprecated path and is not an alias for
Phase 2.

Run all benchmarks and regenerate the LaTeX values:

```powershell
.\benchmarks\run_all.ps1
python scripts\generate_benchmark_latex.py
```

### Linux

```bash
git clone https://github.com/AleBonora3/pq-ble-handshake.git
cd pq-ble-handshake

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python -m pytest tests/ -v
```

---

## nRF54L15 DK firmware

Firmware directory:

```text
firmware/
```

Build and flash:

```bash
cd firmware
west build -b nrf54l15dk/nrf54l15/cpuapp -p always
west flash
```

On Windows, a short path is recommended to avoid Zephyr/NCS path-length
problems:

```powershell
Copy-Item -Recurse `
    firmware `
    C:\myfw\pq

cd C:\myfw\pq
west build -b nrf54l15dk/nrf54l15/cpuapp -p always
west flash
```

Validated environment:

```text
Board: nrf54l15dk/nrf54l15/cpuapp
SDK:   nRF Connect SDK 3.0.0
```

---

## Repository structure

```text
pq-ble-handshake/
├── src/
│   ├── common/                  # ML-KEM, SAS, HKDF, AES-GCM, sessions
│   └── central/                 # Bleak central and hardware demo
├── experimental/
│   └── peripheral/              # Experimental Python peripheral
├── firmware/
│   ├── src/
│   │   ├── main.c
│   │   ├── mlkem_session.c
│   │   ├── mlkem_selftest.c
│   │   └── demo_public_key.h       # historical, inactive in Phase 2
│   ├── third_party/mlkem-native/   # pinned upstream v2.0.0
│   ├── CMakeLists.txt
│   ├── Kconfig
│   ├── phase1_selftest.conf   # optional frozen Phase 1 regression profile
│   ├── prj.conf
│   └── README.md
├── scripts/
│   ├── generate_firmware_public_key.py
│   ├── generate_demo_vectors.py
│   └── generate_benchmark_latex.py
├── tests/
│   ├── test_phase2_diagnostic.py
│   ├── test_phase2_e2e.py
│   └── ...
├── benchmarks/
│   ├── results/                 # Measured TXT/JSON artifacts
│   ├── benchmark_handshake.py
│   ├── benchmark_throughput.py
│   ├── benchmark_fragmentation.py
│   ├── run_all.ps1
│   └── run_all.sh
├── docs/
│   ├── captures/                # Wireshark .pcapng files
│   ├── images/                  # Wireshark screenshots
│   ├── hardware-validation-log.txt
│   ├── protocol-spec.md
│   ├── security-analysis.md
│   ├── test-results.md
│   └── testing-guide.md
├── report/
│   ├── benchmark_values.tex
│   ├── tesina_pq_ble_handshake_finale_IT.tex
│   └── tesina_pq_ble_handshake_finale_IT.pdf
└── README.md
```

---

## Security scope and limitations

- The protocol is a research proof of concept, not a Bluetooth SIG standard.
- BLE SMP is intentionally disabled in the DK firmware:
  `CONFIG_BT_SMP=n`.
- Runtime ML-KEM KeyGen uses PSA production randomness; the frozen deterministic
  self-test remains TEST-ONLY and isolated from runtime keys.
- Phase 2 does not derive a session key or produce AES-GCM ciphertext on the
  DK. Its nine-byte `PQM2` notification is only a TEST-ONLY shared-secret
  diagnostic checksum.
- That CRC32 is not authentication, a KDF, cryptographic key confirmation or
  part of the final protocol; the ML-KEM shared secret itself is never sent.
- SAS requires human comparison and does not scale to large unattended IoT
  deployments.
- Session resumption preserves resistance to passive store-now-decrypt-later
  attacks, but reusing a cached key does not provide full forward secrecy.
- v0.5 positive and SAS-rejection hardware validation are complete; the three
  isolated FINISHED/transcript negative hardware runs remain pending.
- The first application-data direction is Peripheral to Central only.
- Hybrid P-256 + ML-KEM, side-channel evaluation, energy measurements, and
  formal verification remain outside v0.5.
- The research UI displays the Peripheral SAS on the serial console.
- liboqs 0.15.0 with liboqs-python 0.16.0 emits the known version warning.

---

## Roadmap

### Completed

- [x] ML-KEM-768 Python implementation through liboqs
- [x] SAS Numeric Comparison
- [x] HKDF-SHA256 session-key derivation
- [x] AES-256-GCM with authenticated metadata
- [x] replay and out-of-order protection
- [x] session resumption store
- [x] 24-hour re-handshake limit
- [x] 100-successful-resume limit
- [x] GATT fragmentation and reassembly
- [x] protocol-overhead and key-size validation
- [x] automated Python test suite, including Phase 2 diagnostic/Central tests
- [x] nRF54L15 DK Zephyr firmware build
- [x] firmware flash and phone inspection
- [x] Windows PC ↔ nRF54L15 DK demo
- [x] valid offline-generated ML-KEM public key in the historical transport demo
- [x] public-key fingerprint verification over BLE
- [x] nRF52840/Wireshark passive capture
- [x] `.pcapng` evidence
- [x] five Wireshark screenshots
- [x] reproducible benchmark suite and measured result files
- [x] LaTeX report and compiled PDF
- [x] on-device deterministic ML-KEM-768 KeyGen/Encaps/Decaps self-test on the
  real DK (`v0.2-mlkem-ondevice`)
- [x] Phase 2 dedicated ML-KEM worker and hardened ciphertext state machine
- [x] explicit Central `--phase2-e2e` implementation and strict `PQM2` parser
- [x] Phase 3 pure-PQ AES-256-GCM channel validated 10/10 on real hardware
- [x] PSA production-random runtime ML-KEM-768 KeyGen
- [x] v0.5 canonical transcript, key schedule, SAS, and bidirectional FINISHED
- [x] explicit `--phase5-auth-pq` Central and DK state machines
- [x] positive Phase 5 physical-DK E2E validation, repeated after power cycle
- [x] production-random public-key change verified across power cycles
- [x] Phase 5 SAS-rejection physical-DK validation
- [x] isolated Central negative modes for FINISHED_C, FINISHED_P and transcript

### Future work

- [ ] run the remaining v0.5 FINISHED_C, FINISHED_P and transcript negative
  hardware tests
- [ ] persistent session store in DK flash
- [ ] bidirectional encrypted application traffic
- [ ] ML-DSA-based non-interactive authentication
- [ ] hybrid ECDH + ML-KEM handshake
- [ ] embedded latency, RAM, flash and energy benchmarks
- [ ] side-channel evaluation
- [ ] formal verification with ProVerif or Tamarin

---

## Author

**Alessio Bonora**

Project developed for the *Network Security* course, M.Sc. in Computer
Security, A.Y. 2025/2026.
