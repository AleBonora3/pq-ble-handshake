# PQ-BLE-HANDSHAKE

**Authenticated hybrid post-quantum secure channel over Bluetooth Low Energy GATT**

PQ-BLE-HANDSHAKE is a research proof of concept that implements and validates an application-layer secure channel over standard Bluetooth Low Energy GATT.

The current complete protocol version, **v0.7**, combines:

- **ML-KEM-768** — post-quantum key establishment;
- **NIST P-256 ECDH** — classical ephemeral key agreement;
- **SHA-256 canonical transcript binding**;
- **HKDF-SHA256** — hybrid key schedule;
- **6-digit SAS Numeric Comparison** — interactive MITM detection;
- **bidirectional FINISHED** — explicit key confirmation;
- **direction-separated traffic keys**;
- **AES-256-GCM** — authenticated bidirectional application traffic;
- **independent monotonic sequence spaces** — replay and out-of-order protection;
- **fail-closed state transitions and session cleanup**.

The protocol runs **above BLE GATT** and does **not modify the Bluetooth stack**.

> [!IMPORTANT]
> The validated v0.7 protocol intentionally runs with `CONFIG_BT_SMP=n`.
> The P-256 ECDH used by v0.7 is an **application-layer ECDH component** and is distinct from BLE SMP Secure Connections.
>
> A future experiment may run this application-layer protocol over BLE Security Mode 1 Level 4, but that is outside the completed v0.7 milestone.

---

## Current release: v0.7

Status: **COMPLETE**

The complete v0.7 path has been validated between:

```text
Windows PC / Python / Bleak / liboqs
                |
                | BLE GATT
                |
        nRF54L15 DK / Zephyr
        mlkem-native / PSA Crypto
```

Validated end-to-end properties:

- ML-KEM-768 public-key transport;
- ML-KEM encapsulation on the Central;
- ML-KEM decapsulation on the nRF54L15 DK;
- fresh P-256 key pairs on both endpoints;
- P-256 public-key validation;
- P-256 ECDH;
- canonical hybrid transcript;
- transcript-bound hybrid key schedule;
- matching six-digit SAS;
- explicit human SAS confirmation;
- FINISHED_C verification;
- FINISHED_P verification;
- authenticated traffic-key activation;
- directional `K_c2p` / `K_p2c`;
- AES-256-GCM C→P;
- AES-256-GCM P→C;
- replay rejection;
- no sequence advancement after failed authentication;
- three authenticated application round trips: `PING 0/1/2 ↔ PONG 0/1/2`;
- seven CP4 negative/security tests on the physical setup.

Positive hardware marker:

```text
PQ-BLE PHASE7 AUTHENTICATED HYBRID SECURE CHANNEL E2E: PASS
```

Detailed milestone:

```text
docs/research/milestones/v0.7-authenticated-hybrid-secure-channel.md
```

Raw Central/DK validation logs:

```text
docs/research/logs/v0.7/
```

---

## Project evolution

| Version / checkpoint | Main result | Status |
|---|---|---|
| v0.2 | ML-KEM-768 on-device integration and self-test | ✅ Frozen |
| Phase 2 | liboqs Central ↔ mlkem-native DK interoperability | ✅ Validated |
| v0.4 | pure-PQ HKDF + AES-256-GCM secure channel | ✅ Frozen |
| v0.5 | authenticated pure-PQ handshake with transcript, SAS and FINISHED | ✅ Frozen |
| v0.6 | authenticated bidirectional application traffic | ✅ Frozen |
| v0.7 CP1 | P-256 + hybrid primitives + deterministic KATs | ✅ Complete |
| v0.7 CP2 | real-BLE ML-KEM + P-256 hybrid key agreement | ✅ Complete |
| v0.7 CP3 | authenticated hybrid handshake + bidirectional traffic | ✅ Complete |
| v0.7 CP4 | negative/security validation + final measurements | ✅ Complete |

---

# Architecture

## Roles

| Role | Platform | Main responsibilities |
|---|---|---|
| Central | Windows PC | BLE orchestration, ML-KEM encapsulation, P-256 ECDH, SAS/FINISHED verification, application encryption/decryption |
| Peripheral | nRF54L15 DK | GATT server, ML-KEM KeyGen/decapsulation, P-256 ECDH, SAS/FINISHED generation/verification, application encryption/decryption |
| Passive sniffer | nRF52840 Dongle | Wireshark / nRF Sniffer observation of BLE traffic |

The nRF52840 Dongle is used only as a passive sniffer.

---

## Validated environment

```text
Board:        nrf54l15dk/nrf54l15/cpuapp
NCS:          3.0.0
Zephyr:       4.0.99
Zephyr SDK:   0.17.0
Central:      Windows + Python + Bleak
PQ Central:   liboqs / liboqs-python
PQ DK:        mlkem-native v2.0.0
BLE SMP:      disabled
```

A known local warning may appear when the installed versions are:

```text
liboqs         0.15.0
liboqs-python  0.16.0
```

The mismatch warning did not prevent the validated hardware runs.

---

# Cryptographic design

## ML-KEM-768

Runtime ML-KEM key generation is performed on the DK using production randomness from PSA Crypto.

ML-KEM-768 sizes:

| Object | Size |
|---|---:|
| Public key | 1184 B |
| Secret key | 2400 B |
| Ciphertext | 1088 B |
| Shared secret | 32 B |

The secret key remains in DK RAM and is never exposed through GATT. The Central reads the 1184-byte public key, performs ML-KEM encapsulation and sends the 1088-byte ciphertext to the DK. The ML-KEM shared secret is never transmitted.

---

## P-256 ECDH

v0.7 adds a fresh classical ECDH contribution on NIST P-256 / secp256r1.

```text
private scalar: 32 B
public key:     65 B
                0x04 || X(32) || Y(32)
ECDH secret:    32 B
```

Both endpoints generate fresh ephemeral key pairs for each authenticated v0.7 session. The DK uses PSA Crypto for P-256 operations.

---

# v0.7 handshake

## High-level flow

```text
Central / PC                                      Peripheral / DK
    |                                                   |
    | <----------- ML-KEM public key -------------------|
    |                                                   |
    | ML-KEM Encaps(pk)                                 |
    | -> CT_MLKEM                                       |
    | -> SS_MLKEM                                       |
    |                                                   |
    | -------- ML-KEM ciphertext ---------------------> |
    |                                                   |
    | generate ephemeral P-256 key pair                 |
    |                                                   |
    | -- START7_AUTH(session_id, C_P256_pub) ---------> |
    |                                                   |
    |                              ML-KEM Decaps         |
    |                              -> SS_MLKEM           |
    |                              P-256 KeyGen          |
    |                              validate C public key |
    |                              P-256 ECDH            |
    |                              -> SS_ECDH            |
    |                                                   |
    | <-- READY7_AUTH(P_P256_pub) --------------------- |
    |                                                   |
    | validate P public key                             |
    | P-256 ECDH -> SS_ECDH                             |
    |                                                   |
    | BOTH:                                             |
    |   canonical transcript                            |
    |   transcript_hash = SHA-256(transcript)           |
    |   hybrid IKM = SS_MLKEM + SS_ECDH                 |
    |   HKDF-SHA256                                     |
    |                                                   |
    |   K_app                                           |
    |   K_sas                                           |
    |   K_finished_c                                    |
    |   K_finished_p                                    |
    |                                                   |
    | SAS: 6 digits                 SAS: 6 digits        |
    | -------- human comparison / confirmation -------- |
    |                                                   |
    | -------- FINISHED_C ----------------------------> |
    |                              verify FINISHED_C     |
    |                              derive pending        |
    |                              traffic keys          |
    |                                                   |
    | <------- FINISHED_P ----------------------------- |
    | verify FINISHED_P                                 |
    |                                                   |
    |              AUTHENTICATED SESSION                |
    |                                                   |
    | ===== AES-256-GCM bidirectional traffic ========  |
```

---

## Canonical transcript

The v0.7 domain separator is:

```text
PQ-BLE-HANDSHAKE-v0.7
```

The canonical transcript is exactly **2457 bytes**:

```text
u16be(21)   || "PQ-BLE-HANDSHAKE-v0.7"
u16be(1)    || 0x01
u16be(1)    || 0x02
u16be(16)   || session_id
u16be(1184) || ML-KEM public key
u16be(1088) || ML-KEM ciphertext
u16be(65)   || Central P-256 public key
u16be(65)   || Peripheral P-256 public key
```

Then:

```text
transcript_hash = SHA-256(canonical_transcript)
```

The transcript binds the derived keys to the exact handshake instance and to both public-key contributions.

---

## Hybrid combiner

The protocol requires both shared secrets:

```text
SS_MLKEM = 32 B
SS_ECDH  = 32 B
```

Hybrid input:

```text
hybrid_IKM =
    u16be(32) || SS_MLKEM ||
    u16be(32) || SS_ECDH
```

Total:

```text
68 B
```

There is no fallback to a single component. If either ML-KEM or P-256 processing fails, the handshake fails closed.

---

## Hybrid key schedule

```text
key_block = HKDF-SHA256(
    IKM  = hybrid_IKM,
    salt = transcript_hash,
    info = b"PQ-BLE-HANDSHAKE-v0.7/hybrid-key-schedule",
    L    = 128
)
```

The output is split into:

```text
K_app        = 32 B
K_sas        = 32 B
K_finished_c = 32 B
K_finished_p = 32 B
```

Raw ML-KEM and ECDH shared secrets are cleared after the hybrid key schedule has been derived.

---

# SAS Numeric Comparison

Both endpoints independently compute:

```text
sas_mac = HMAC-SHA256(
    K_sas,
    b"PQ-BLE-HANDSHAKE-v0.7/SAS" || transcript_hash
)

SAS = int(sas_mac) mod 1_000_000
```

The value is displayed as six decimal digits.

Example:

```text
Central:    841049
Peripheral: 841049
```

Normal authenticated mode requires explicit human confirmation.

If SAS comparison is rejected:

```text
FINISHED_C is not sent
-> application traffic remains unavailable
-> session is not authenticated
```

---

# Bidirectional FINISHED

After SAS acceptance:

```text
FINISHED_C = HMAC-SHA256(
    K_finished_c,
    b"PQ-BLE-HANDSHAKE-v0.7/FINISHED/C" || transcript_hash
)
```

The DK verifies FINISHED_C using the firmware constant-time comparison helper.

Then:

```text
FINISHED_P = HMAC-SHA256(
    K_finished_p,
    b"PQ-BLE-HANDSHAKE-v0.7/FINISHED/P" || transcript_hash
)
```

The Central verifies FINISHED_P using `hmac.compare_digest`.

FINISHED therefore provides explicit bidirectional confirmation that both endpoints derived the expected transcript-bound key material.

---

# Authenticated traffic-key activation

`K_app` is not used directly for AES traffic.

Two independent traffic keys are derived:

```text
K_c2p = HMAC-SHA256(
    K_app,
    b"PQ-BLE-TRAFFIC-v0.7/CENTRAL-TO-PERIPHERAL"
)

K_p2c = HMAC-SHA256(
    K_app,
    b"PQ-BLE-TRAFFIC-v0.7/PERIPHERAL-TO-CENTRAL"
)
```

On the DK, the traffic keys are first retained as **pending**. The session is promoted to application-level `AUTHENTICATED` state only after FINISHED_P has been successfully queued to the originating live BLE connection.

---

# AES-256-GCM application channel

## Secure wire

```text
seq_be64(8)
|| msg_type(1)
|| IV(12)
|| ciphertext
|| GCM_tag(16)
```

Fixed overhead:

```text
37 B
```

For the physical validation payload `PING 0`, the plaintext is 6 bytes and the secure wire is therefore 43 bytes.

---

## AAD

```text
AAD =
    session_id(16)
    || sender_role(1)
    || seq_be64(8)
    || msg_type(1)
```

Roles:

```text
Central    = 0x01
Peripheral = 0x02
```

This provides cross-session binding, sender-direction binding, sequence binding and message-type binding.

---

## Replay protection

C→P and P→C maintain independent sequence spaces.

```text
C->P seq=0  PING 0
P->C seq=0  PONG 0

C->P seq=1  PING 1
P->C seq=1  PONG 1

C->P seq=2  PING 2
P->C seq=2  PONG 2
```

Receive state advances only after successful AES-GCM authentication. A tampered frame therefore cannot consume a sequence number. An already accepted wire is rejected as replay/out-of-order.

---

# GATT transport

Service UUID:

```text
12345678-1234-1234-1234-123456789abc
```

The v0.7 work preserves the existing GATT layout.

| Characteristic | UUID suffix | Properties | Purpose |
|---|---|---|---|
| Public Key | `9abd` | READ | dynamic ML-KEM-768 public key |
| Ciphertext | `9abe` | WRITE | fragmented ML-KEM ciphertext |
| Secure Data | `9abf` | WRITE / NOTIFY | encrypted application traffic and protocol responses |
| Secure Data CCCD | — | READ / WRITE | enables notifications |
| Control | `9ac0` | WRITE | v0.7 handshake control frames |

Previously observed value handles:

```text
0x0012  Public Key
0x0014  Ciphertext
0x0016  Secure Data
0x0017  Secure Data CCCD
0x0019  Control
```

---

## ML-KEM public-key read

At the validated ATT MTU, the 1184-byte public key is read through long-read operations at offsets:

```text
0
246
492
738
984
```

---

## Ciphertext transport

The 1088-byte ML-KEM ciphertext is transported through the existing PQ-BLE fragmentation layer.

```text
logical fragment size = 247 B
PQ-BLE header         =   4 B
payload per fragment  = 243 B
ciphertext            = 1088 B
fragments             =   5
```

The firmware reassembly state is connection-scoped and rejects incomplete, inconsistent, duplicate/stale or invalid transfers according to the current state machine.

---

# PQS7 handshake framing

Generic frame:

```text
"PQS7" (4)
|| version=0x07 (1)
|| subtype (1)
|| payload_len_be16 (2)
|| payload
```

| Subtype | Code | Direction | Payload | Total |
|---|---:|---|---:|---:|
| `START7` | `0x01` | C→P | sid + C P-256 pub | 89 B |
| `READY7_CP2` | `0x02` | P→C | P P-256 pub + diagnostic | 105 B |
| `START7_AUTH` | `0x03` | C→P | sid + C P-256 pub | 89 B |
| `READY7_AUTH` | `0x04` | P→C | P P-256 pub | 73 B |
| `FINISHED_C` | `0x05` | C→P | FINISHED_C | 40 B |
| `FINISHED_P` | `0x06` | P→C | FINISHED_P | 40 B |
| `ERROR` | `0x7F` | P→C | status | 9 B |

---

# Peripheral state and worker model

The authenticated v0.7 path uses a separate state machine:

```text
IDLE
 -> CRYPTO_BUSY
 -> WAIT_FINISHED_C
 -> FINISHED_BUSY
 -> AUTHENTICATED
 -> DATA_BUSY
 -> AUTHENTICATED
```

Cryptography is not executed in GATT callbacks.

The dedicated worker performs:

- ML-KEM decapsulation;
- P-256 generation and ECDH;
- transcript hashing;
- hybrid HKDF;
- SAS;
- FINISHED verification/generation;
- traffic-key derivation;
- C→P AES-GCM verification;
- P→C AES-GCM response generation.

Epoch and BLE connection-generation checks reject stale worker results. Disconnect and notification teardown clear retained Phase 7 state.

---

# Security validation

v0.7 CP4 includes seven explicit TEST-ONLY security modes.

```powershell
python -m src.central.main --phase7-auth-hybrid --phase7-negative-test-only MODE
```

Supported modes:

```text
sas-reject
finished-c
pre-auth
c2p-tamper
c2p-replay
p2c-tamper
p2c-replay
```

All seven have been validated against the physical setup.

## SAS rejection

Validated:

```text
SAS rejected
-> FINISHED_C not sent
-> Secure Data blocked
-> no authenticated state
```

## FINISHED_C tamper

Validated:

```text
Phase 7 FINISHED_C verification: FAIL
PQS7 ERROR 0x06
Secure Data blocked
no authenticated application session
```

## Pre-authenticated Secure Data

A valid seq=0 application wire is attempted in `WAIT_FINISHED_C`.

Validated:

```text
write rejected
no application response
sequence state unchanged
```

After successful authentication the original seq=0 wire remains valid, followed by seq=1 and seq=2.

## C→P tag tamper

Validated:

```text
tampered seq=0
-> AES-GCM authentication FAIL
-> ERROR 0x06
-> receive sequence does not advance

original seq=0 -> PASS
seq=1          -> PASS
seq=2          -> PASS
```

## C→P replay

Validated:

```text
first seq=0       -> PASS
exact same wire   -> replay/out-of-order
                    -> ERROR 0x04
                    -> no duplicate PONG
seq=1 / seq=2     -> PASS
```

The authenticated session remains usable after the rejected replay.

## P→C local tag tamper

A real P→C BLE response is copied and modified locally at the Central.

Validated:

```text
tampered local copy
-> reject
-> receive state unchanged

original response
-> PASS
```

The firmware is intentionally not modified to emit malformed traffic.

## P→C local replay

A real accepted P→C BLE response is replayed locally at the Central.

Validated:

```text
first response      -> PASS
same response again -> replay/out-of-order reject
subsequent responses -> PASS
```

---

# Resource usage

Final v0.7 pristine build:

```text
FLASH: 225788 B / 1428 KB = 15.44%
RAM:   106560 B / 188 KB  = 55.35%
```

Crypto worker:

```text
configured stack:       28672 B
maximum observed peak:  24264 B
unused at peak:           4408 B
margin:                  ~15.37%
```

No CP4 negative path exceeded the final observed stack peak.

---

## Evolution versus v0.6

| Version | FLASH | RAM | Worker peak |
|---|---:|---:|---:|
| v0.6 | 205184 B | 105992 B | 23344 B |
| v0.7 | 225788 B | 106560 B | 24264 B |

Delta:

```text
FLASH:       +20604 B
RAM:           +568 B
worker peak:   +920 B
```

---

# Timing notes

One positive physical run measured:

```text
handshake:   2176.236 ms
application: 358.959 ms for 3 valid round trips
```

The handshake value is end-to-end wall-clock time and includes human SAS confirmation. It is not a pure cryptographic latency measurement.

Negative modes may additionally include TEST-ONLY injection and observation windows.

Primitive-level and CPU-only benchmark results remain under:

```text
benchmarks/results/
```

---

# Automated validation

Run:

```powershell
python -m compileall -q src tests
python -m pytest -q
git diff --check
```

The current complete suite passes. The exact final test count should be recorded in `docs/test-results.md` and in the v0.7 milestone from the final release run.

CP4 host tests cover, among other cases:

- positive hybrid flow;
- all seven negative modes;
- malformed PQS7 frames;
- wrong status codes;
- missing and extra notifications;
- SAS acceptance/rejection;
- FINISHED verification behavior;
- Central receiver tag/replay rejection;
- sequence-state preservation;
- disconnect/cleanup behavior;
- Bleak/WinRT GATT rejection mappings, including structured `BleakGATTProtocolError`.

---

# Quick start

## 1. Clone and create the Python environment

```powershell
git clone https://github.com/AleBonora3/pq-ble-handshake.git
cd pq-ble-handshake

python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Run software tests:

```powershell
python -m pytest -q
```

---

## 2. Build the nRF54L15 DK firmware

From an initialized nRF Connect SDK 3.0.0 environment:

```powershell
cd firmware

west build `
  -b nrf54l15dk/nrf54l15/cpuapp `
  -p always

west flash
```

A short Windows path is recommended for NCS/Zephyr builds.

Expected startup includes:

```text
ML-KEM production-random KeyGen: PASS
Phase 7 production-random P-256 ECDH self-test: PASS
Phase 7 hybrid transcript KAT: PASS
Phase 7 hybrid key-schedule KAT: PASS
Phase 7 SAS/FINISHED KAT: PASS
Phase 7 directional-key KAT: PASS
Advertising as 'PQ-BLE-Device'
```

---

## 3. Run the complete v0.7 positive flow

```powershell
python -m src.central.main --phase7-auth-hybrid
```

Compare the six-digit SAS printed by the Central with the DK serial output and accept only if the values match.

Expected final result:

```text
ML-KEM + P-256 hybrid key agreement: PASS
FINISHED_C / FINISHED_P: PASS
Authenticated bidirectional traffic: PASS (3 rounds)

PQ-BLE PHASE7 AUTHENTICATED HYBRID SECURE CHANNEL E2E: PASS
```

---

## 4. Run CP4 negative tests

```powershell
python -m src.central.main --phase7-auth-hybrid --phase7-negative-test-only sas-reject
python -m src.central.main --phase7-auth-hybrid --phase7-negative-test-only finished-c
python -m src.central.main --phase7-auth-hybrid --phase7-negative-test-only pre-auth
python -m src.central.main --phase7-auth-hybrid --phase7-negative-test-only c2p-tamper
python -m src.central.main --phase7-auth-hybrid --phase7-negative-test-only c2p-replay
python -m src.central.main --phase7-auth-hybrid --phase7-negative-test-only p2c-tamper
python -m src.central.main --phase7-auth-hybrid --phase7-negative-test-only p2c-replay
```

A successful negative validation prints:

```text
PQ-BLE PHASE7 CP4 NEGATIVE TEST: PASS (<mode>)
```

---

# Regression modes

Phase 2 hybrid interoperability:

```powershell
python -m src.central.main --phase7-hybrid-e2e
```

v0.5 authenticated pure-PQ:

```powershell
python -m src.central.main --phase5-auth-pq
```

v0.6 authenticated bidirectional traffic:

```powershell
python -m src.central.main --phase6-bidirectional
```

These remain useful to verify that v0.7 development did not break frozen earlier paths.

---

# Wireshark evidence

Historical passive BLE captures are available under:

```text
docs/captures/
```

Screenshots are available under:

```text
docs/images/
```

The captures demonstrate the underlying BLE/GATT transport, including ATT MTU exchange, ML-KEM public-key long read, ciphertext transfer, Control writes and Secure Data notifications.

Existing captures may correspond to earlier protocol checkpoints; the v0.7 milestone and raw v0.7 Central/DK logs are the authoritative evidence for the complete authenticated hybrid protocol.

Useful filters:

```text
btatt
btatt.handle == 0x0012
btatt.handle == 0x0014
btatt.handle == 0x0016
btatt.handle == 0x0019
btatt.opcode == 0x1b
```

---

# Repository structure

```text
pq-ble-handshake/
├── src/
│   ├── common/
│   │   ├── phase7.py
│   │   ├── session.py
│   │   └── ...
│   └── central/
│       ├── main.py
│       ├── phase7_hybrid.py
│       ├── phase7_auth.py
│       └── ...
├── firmware/
│   ├── src/
│   │   ├── main.c
│   │   ├── mlkem_session.c
│   │   ├── mlkem_session.h
│   │   ├── pq_phase7.c
│   │   ├── pq_phase7.h
│   │   └── ...
│   ├── third_party/mlkem-native/
│   ├── CMakeLists.txt
│   ├── Kconfig
│   └── prj.conf
├── tests/
│   ├── test_phase7_primitives.py
│   ├── test_phase7_cp2.py
│   ├── test_phase7_cp3.py
│   ├── test_phase7_cp4.py
│   └── ...
├── docs/
│   ├── captures/
│   ├── images/
│   ├── research/
│   │   ├── milestones/
│   │   │   └── v0.7-authenticated-hybrid-secure-channel.md
│   │   └── logs/
│   │       └── v0.7/
│   ├── protocol-spec.md
│   ├── security-analysis.md
│   ├── test-results.md
│   └── testing-guide.md
├── benchmarks/
├── report/
├── experimental/
└── README.md
```

---

# Deterministic v0.7 KAT

v0.7 includes deterministic TEST-ONLY known-answer vectors covering P-256 public keys, P-256 ECDH shared secret, canonical transcript hash, hybrid key schedule, SAS, FINISHED_C, FINISHED_P, directional traffic keys and the CP2 diagnostic.

These vectors are public test fixtures and are not runtime production secrets.

See:

```text
docs/research/milestones/v0.7-authenticated-hybrid-secure-channel.md
```

for the full vector set.

---

# Security scope

v0.7 demonstrates a concrete application-layer hybrid design and validates its behavior experimentally.

Implemented properties include:

- post-quantum ML-KEM-768 contribution;
- independent classical P-256 ECDH contribution;
- mandatory hybrid combination;
- transcript binding;
- interactive MITM detection through SAS;
- bidirectional key confirmation;
- authenticated application activation;
- direction-separated AES-256-GCM keys;
- session-, role-, sequence- and message-type-bound AAD;
- replay/out-of-order rejection;
- no receive-state advancement after failed authentication;
- pre-authenticated application-data rejection;
- stale connection/session result cancellation;
- best-effort secret cleanup.

---

# Limitations and non-goals

PQ-BLE-HANDSHAKE is a **research proof of concept**, not a Bluetooth SIG standard and not production-certified software.

Current limitations:

- authentication is interactive through SAS;
- no ML-DSA/certificate-based unattended authentication;
- BLE SMP is intentionally disabled for the completed v0.7 experiment;
- no persistent v0.7 session resumption on the DK;
- no formal protocol proof with ProVerif/Tamarin;
- no physical side-channel assessment;
- no fault-injection assessment;
- no energy-consumption campaign yet;
- no production SAS UI on the embedded device;
- no production secure-element integration;
- no claim of Bluetooth SIG interoperability beyond use of standard GATT transport.

The older Python resumption framework is not equivalent to a completed hardware-v0.7 resumption implementation and should not be presented as a v0.7 feature.

---

# Future work

Potential follow-up experiments include:

- run the v0.7 application protocol over BLE Security Mode 1 Level 4 and compare it with the current SMP-disabled baseline;
- measure repeated E2E latency excluding and including user SAS time;
- energy measurements on the nRF54L15 DK;
- session resumption for the complete v0.7 protocol;
- ML-DSA or certificate-based non-interactive authentication;
- packet-level capture of the final v0.7 authenticated hybrid flow;
- side-channel and fault-injection analysis;
- formal verification with ProVerif or Tamarin;
- RAM/FLASH/stack optimization.

These are extensions beyond the frozen v0.7 protocol.

---

# Research evidence

The repository separates conclusions from raw experimental evidence.

Milestone:

```text
docs/research/milestones/v0.7-authenticated-hybrid-secure-channel.md
```

Raw physical logs:

```text
docs/research/logs/v0.7/
```

Recommended log naming:

```text
positive-central.txt
positive-dk.txt
negative-sas-reject-central.txt
negative-sas-reject-dk.txt
negative-finished-c-central.txt
negative-finished-c-dk.txt
negative-pre-auth-central.txt
negative-pre-auth-dk.txt
negative-c2p-tamper-central.txt
negative-c2p-tamper-dk.txt
negative-c2p-replay-central.txt
negative-c2p-replay-dk.txt
negative-p2c-tamper-central.txt
negative-p2c-tamper-dk.txt
negative-p2c-replay-central.txt
negative-p2c-replay-dk.txt
```

---

# Release policy

Earlier validated versions remain frozen. Existing v0.5/v0.6 tags must not be moved or recreated.

The complete authenticated hybrid release should be tagged only after:

```text
software suite PASS
positive physical v0.7 PASS
7/7 CP4 negatives PASS
pristine firmware build PASS
milestone committed
raw logs committed
README committed
main updated
```

Recommended tag:

```text
v0.7-authenticated-hybrid-secure-channel
```

---

# Author

**Alessio Bonora**

