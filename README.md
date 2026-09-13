# PQ-BLE-HANDSHAKE

**Post-quantum protected communication over Bluetooth Low Energy on resource-constrained embedded hardware.**

PQ-BLE-HANDSHAKE is a research proof of concept built around a **Windows PC Central** and an **nRF54L15 DK Peripheral**. It contains two completed, hardware-validated BLE/PQ protocol architectures and a completed experimental comparison between them:

- **v0.7** — application-level hybrid **ML-KEM-768 + ephemeral P-256 ECDH**, application SAS/FINISHED authentication, and AES-256-GCM traffic;
- **v1.0** — **BLE Security Mode 1 Level 4 + ML-KEM-768**, transcript-bound FINISHED confirmation, and AES-256-GCM application traffic.

Both use standard BLE GATT transport without modifying the Bluetooth stack.

> [!IMPORTANT]
> **v1.0 is complete through CP1–CP5.**
>
> The later comparison of frozen v0.7 and v1.0 is a separate **Post-v1.0 Comparative Evaluation**, organized as **EVAL-A through EVAL-E**.
>
> Historical benchmark identifiers still contain `CP6` (`PQBLE-CP6-SETUP-A`, `cp6c-*`, `cp6d-*`, etc.). In those artifacts, **CP6 is only the legacy/internal name of the post-v1.0 evaluation campaign**. It is retained for provenance and reproducibility and is not a sixth v1.0 implementation checkpoint.

---

## Status

| Track | Status |
|---|---|
| v0.7 authenticated hybrid protocol | **COMPLETE / hardware validated** |
| v1.0 SMP L4 + ML-KEM protocol | **COMPLETE / hardware validated through CP1–CP5** |
| Post-v1.0 Comparative Evaluation | **COMPLETE** |

### v1.0 checkpoints

| Checkpoint | Goal | Status |
|---|---|---|
| CP1 | SMP Security Mode 1 Level 4, Numeric Comparison, bonding, strict PQ GATT gate | **PASS on real hardware** |
| CP2 | ML-KEM-768 interoperability over authenticated L4 | **PASS on real hardware** |
| CP3 | Canonical transcript, ML-KEM-only KDF, `FINISHED_C` / `FINISHED_P`, `APP_SECURE` | **PASS on real hardware** |
| CP4 | Bidirectional AES-256-GCM application traffic | **PASS on real hardware** |
| CP5 | Cold/bonded/reconnect/reboot/multi-session lifecycle validation | **PASS on real hardware** |

The v1.0 release audit recorded **1064 passed, 1 skipped, 1 warning** on 2026-09-10. The warning is the known native liboqs `0.15.0` / liboqs-python `0.16.0` mismatch in the validated environment.

### Post-v1.0 evaluation stages

| Stage | Scope | Status |
|---|---|---|
| **EVAL-A** | Reproducible measurement infrastructure and provenance | **COMPLETE** |
| **EVAL-B** | Repeated hardware latency campaign | **COMPLETE** |
| **EVAL-C** | Firmware resources, stack high-water, GATT observations, passive BLE captures | **COMPLETE** |
| **EVAL-D** | Hardware negative/security validation | **COMPLETE — 9/9 PASS** |
| **EVAL-E** | Final architectural and experimental comparison | **COMPLETE** |

---

## Research objective

The project investigates practical ways to add post-quantum key establishment to BLE communication on constrained embedded hardware.

The central research comparison is between two architectures:

1. **v0.7 — application-defined hybrid security**\
   Classical and post-quantum contributions are combined inside the application protocol.

2. **v1.0 — layered BLE + PQ security**\
   Standard BLE SMP Level 4 handles classical authenticated association and BLE link protection, while ML-KEM independently establishes post-quantum application key material.

The completed evaluation compares these designs in:

- architecture;
- end-to-end latency;
- firmware FLASH/RAM;
- crypto-worker stack use;
- GATT/API behavior;
- passive BLE visibility;
- negative/security behavior.

---

# Protocol architectures

## v1.0 — BLE SMP Level 4 + ML-KEM-768

v1.0 is a **layered classical/post-quantum design**:

```text
Application PING/PONG
        |
        v
AES-256-GCM application channel
        |
        | directional keys / IVs / counters
        v
ML-KEM-derived application keys
        |
        | transcript-bound HKDF-SHA256
        | FINISHED_C / FINISHED_P
        v
ML-KEM-768
        |
        v
protected PQ GATT
        |
        v
BLE SMP Security Mode 1 Level 4
        |
        | authenticated LE Secure Connections
        | Numeric Comparison + bonding
        v
encrypted BLE link
```

BLE SMP uses classical P-256 internally and provides authenticated BLE association and link protection.

ML-KEM-768 provides the application-layer post-quantum shared secret:

```text
SS_MLKEM
```

`SS_MLKEM` alone is used as the application KDF input.

v1.0 therefore has:

- no application P-256 ECDH;
- no application SAS;
- no `SS_MLKEM || SS_ECDH` combiner;
- no export of the SMP DHKey;
- no export or use of the BLE LTK in the application KDF.

> [!NOTE]
> v1.0 is **not** a hybrid key agreement.
>
> It provides classical authenticated BLE L4 below post-quantum ML-KEM application key establishment. It must not be described as providing post-quantum peer-identity authentication.

Full milestone:

[`docs/research/milestones/v1.0-smp-l4-mlkem-final.md`](docs/research/milestones/v1.0-smp-l4-mlkem-final.md)

---

## v0.7 — Application-level ML-KEM + P-256 hybrid

v0.7 is the retained application-level hybrid baseline.

BLE SMP is intentionally disabled:

```text
CONFIG_BT_SMP=n
```

Its application protocol combines:

```text
ML-KEM-768
    +
ephemeral application P-256 ECDH
    |
    v
SS_MLKEM || SS_ECDH
    |
    v
HKDF-SHA256
    |
    +--> application SAS
    +--> FINISHED
    +--> AES-256-GCM traffic
```

The exact hybrid KDF input is:

```text
u16be(32) || SS_MLKEM || u16be(32) || SS_ECDH
```

The application transcript binds the protocol domain/version, roles, session identifier, ML-KEM public key and ciphertext, and both P-256 public keys. Human comparison of the six-digit application SAS precedes FINISHED and secure-channel activation.

Full milestone:

[`docs/research/milestones/v0.7-authenticated-hybrid-secure-channel.md`](docs/research/milestones/v0.7-authenticated-hybrid-secure-channel.md)

---

## v0.7 vs v1.0

| Aspect | v0.7 | v1.0 |
|---|---|---|
| BLE SMP | Disabled | Security Mode 1 Level 4 |
| Classical authentication | Application SAS + FINISHED | LE Secure Connections Numeric Comparison + bonding |
| Application P-256 ECDH | Yes | No |
| ML-KEM | ML-KEM-768 | ML-KEM-768 |
| Application KDF input | `SS_MLKEM \|\| SS_ECDH` | `SS_MLKEM` only |
| SMP secret mixed into app KDF | N/A | No |
| BLE link encryption | No SMP | Yes |
| Application confirmation | FINISHED | `FINISHED_C` / `FINISHED_P` |
| Application AEAD | AES-256-GCM | AES-256-GCM |
| Replay protection | Strict directional sequence numbers | Strict directional sequence numbers |
| Bonding | No SMP bonds | Persistent SMP bonding |
| Session after reconnect | Fresh hybrid session | Fresh ML-KEM/application session even when bond persists |

---

# v1.0 flow

1. **Establish BLE L4.**\
   Protected PQ GATT operations remain unavailable before authenticated Level 4.

2. **Verify the live security state.**\
   The Central requires L4, Secure Connections, authentication, a 16-byte encryption key, the PQ gate open, and the v1.0 profile active.

3. **Exchange ML-KEM material.**\
   The Central reads the **1184 B** ML-KEM-768 public key, encapsulates, and writes the **1088 B** ciphertext. The validated MTU 247 path uses five ciphertext fragments.

4. **Bind the transcript.**\
   The Central sends `START_CP3`; the DK decapsulates on the crypto worker and returns `READY_CP3`.

5. **Confirm keys.**\
   `FINISHED_C` and `FINISHED_P` provide explicit bidirectional key confirmation before `APP_SECURE`.

6. **Exchange application data.**\
   CP4 uses independent AES-256-GCM keys and 64-bit counters for C→P and P→C.

7. **Retire state on disconnect/failure.**\
   A new connection establishes fresh ML-KEM/application state even when the BLE bond is reused.

See the v1.0 milestone for the exact transcript, HKDF labels, FINISHED construction, and state machines.

---

# Secure application traffic

The v1.0 CP4 frame is:

```text
PQV1 | version | subtype | payload_len | seq | msg_type | plaintext_len | ciphertext | tag
  4       1         1          2          8       1            2              N        16
```

Properties:

- AES-256-GCM;
- 16-byte tag;
- session- and direction-bound AAD;
- separate C→P / P→C keys and IV bases;
- strict 64-bit directional sequence numbers;
- duplicates, gaps, replay, and reordering rejected;
- `UINT64_MAX` reserved.

Frame overhead is **35 B**.

The active v1.0 hardware workload uses a 16-byte application challenge, producing a **51 B** protected frame. Minimum ATT MTU is **54**; hardware runs used **247**.

---

# Post-v1.0 Comparative Evaluation

The completed comparison uses frozen v0.7 and v1.0 protocol baselines.
The [evaluation guide](docs/research/post-v1-comparative-evaluation.md) records
EVAL-A through EVAL-E completion and the reproducibility methodology.

For reproducibility, existing benchmark internals keep their original CP6 naming:

```text
benchmarks/post_v1/
PQBLE-CP6-SETUP-A
cp6c-...
cp6d-...
```

**CP6 in benchmark artifacts means only the historical benchmark campaign identifier.**

The public/documentation naming is now:

```text
Post-v1.0 Comparative Evaluation
EVAL-A -> EVAL-B -> EVAL-C -> EVAL-D -> EVAL-E
```

No protocol checkpoint was added after v1.0 CP5.

---

## Final latency results

Retained successful strata:

| Scenario | n | Mean `secure_machine_ms` | Median |
|---|---:|---:|---:|
| v0.7 hybrid | 30 | **3584.773 ms** | **3091.119 ms** |
| v1.0 bonded | 30 | **5446.180 ms** | **5459.655 ms** |
| v1.0 cold | 5 | unavailable as pure machine time | unavailable |

The measured v1.0 bonded mean is approximately **51.9% higher** than the v0.7 mean.

This is an **end-to-end implementation result**, not a primitive-cryptography comparison.

Central ML-KEM encapsulation was effectively unchanged:

```text
v0.7 mean:        0.653 ms
v1.0 bonded mean: 0.638 ms
```

The larger observed differences appear mainly in host/BLE/GATT phases such as public-key read and ciphertext transport. The result must therefore **not** be summarized as “ML-KEM is slower in v1.0”.

For the five cold v1.0 runs:

```text
secure_wall_ms mean   = 8333.861 ms
secure_wall_ms median = 6650.285 ms
```

Cold wall time includes interactive Numeric Comparison. A complete machine-only cold timing boundary was not available.

### Application RTT caveat

The frozen workloads differ:

```text
v0.7: 3 x 6 B PING/PONG, 43 B protected frame
v1.0: 2 x 16 B challenge/response, 51 B protected frame
```

Application RTT is therefore **not** a matched-payload cross-profile benchmark.

---

## Firmware resources

| Metric | v0.7 | v1.0 | Delta |
|---|---:|---:|---:|
| FLASH | **225,652 B** | **279,428 B** | **+53,776 B (+23.8%)** |
| RAM | **106,048 B** | **109,464 B** | **+3,416 B (+3.2%)** |
| Crypto-worker stack allocation | 28,672 B | 28,672 B | 0 |
| Observed crypto-worker peak | **24,264 B** | **24,264 B** | 0 |

The observed peak is about **84.6%** of the configured worker stack, leaving **4,408 B** headroom in the measured runs.

---

## Passive BLE observations

### v0.7 dedicated capture

```text
run:       cp6c-v07-hybrid-20260913T115408
packets:   716
duration:  8.145325 s
ATT:       95
SMP:       0
```

The connection was followed through `LL_TERMINATE_IND`. The ATT-level trace exposes the GATT transport because SMP link encryption is disabled.

Observed **4710 LL payload bytes** are not total over-the-air bytes or airtime.

### v1.0 cold

```text
packets:   512
duration:  7.605352 s
ATT:       50
SMP:       9
```

The sniffer observed the LE Secure Connections pairing sequence up to the transition into encrypted link traffic.

### v1.0 bonded

```text
packets:   37
duration:  0.945367 s
ATT:       0
SMP:       1
```

Without the LTK, the passive sniffer cannot decode later ATT/GATT traffic after BLE link encryption.

The v1.0 captures therefore demonstrate the **link-layer visibility difference**; they are not complete total-traffic or airtime measurements.

---

## Negative/security validation

Final hardware result:

```text
v0.7: 7/7 PASS
v1.0: 2/2 PASS
total: 9/9 PASS
```

v0.7 validates:

- SAS rejection;
- corrupted `FINISHED_C`;
- application access before FINISHED;
- C→P AES-GCM tamper;
- C→P replay;
- P→C local-copy tamper;
- P→C local-copy replay.

The two P→C tests are **receiver-local Central checks**, not over-the-air BLE packet injection.

v1.0 validates:

- all four protected PQ GATT operations denied before L4;
- explicit PC Numeric Comparison rejection leaves the peer unpaired and protected PQ GATT inaccessible after reconnect.

Milestone:

[`docs/research/milestones/eval-d-hardware-negative-validation.md`](docs/research/milestones/eval-d-hardware-negative-validation.md)

---

## Final interpretation

The experiment shows a trade-off rather than a single winner.

**v0.7**

- lower measured machine-time latency;
- lower FLASH and RAM footprint;
- classical/PQ hybrid and authentication logic implemented in the application layer.

**v1.0**

- higher measured footprint and end-to-end overhead;
- standard BLE L4 handles classical association and link protection;
- ML-KEM independently supplies post-quantum application key establishment;
- cleaner separation between BLE security and PQ application cryptography;
- encrypted BLE link hides post-encryption ATT/GATT from a passive observer without the LTK.

The comparison does **not** justify saying that v1.0 is slower because of ML-KEM, nor that either design dominates every dimension.

Final analysis:

[`docs/research/milestones/eval-e-final-comparative-analysis.md`](docs/research/milestones/eval-e-final-comparative-analysis.md)

---

# Hardware and software environment

| Component | Validated environment |
|---|---|
| Peripheral | Nordic nRF54L15 DK |
| Board | `nrf54l15dk/nrf54l15/cpuapp` |
| nRF Connect SDK | **3.0.0** |
| Zephyr | **4.0.99 / v4.0.99-ncs1** |
| Central | Windows PC |
| Python | **3.13.3** |
| Bleak | **3.0.2** |
| liboqs-python | **0.16.0** |
| native liboqs | **0.15.0** in the audited environment |
| ATT MTU | **247** |
| Passive sniffer | nRF52840 USB Dongle |
| Capture stack | Nordic nRF Sniffer 4.1.1 / Wireshark-TShark 4.4.7 / Npcap 1.80 |

The validated v1.0 pairing path uses Windows WinRT custom pairing. Equivalent real-hardware validation is not claimed for other host OS backends.

---

# Firmware profiles

| Profile | Configuration | Purpose |
|---|---|---|
| v0.7 | `firmware/prj.conf` | Hybrid application baseline, SMP disabled |
| v1.0 | `prj.conf` + `firmware/v1_smp_l4_mlkem.conf` | SMP L4 + ML-KEM layered architecture |

Important v1.0 BLE settings include:

```text
CONFIG_BT_SMP=y
CONFIG_BT_SMP_SC_ONLY=y
CONFIG_BT_SMP_ENFORCE_MITM=y
CONFIG_BT_SMP_MIN_ENC_KEY_SIZE=16
CONFIG_BT_BONDABLE=y
CONFIG_BT_SETTINGS=y
CONFIG_SETTINGS=y
```

Both profiles use the nRF54L15 DK crypto worker and vendored `mlkem-native`.

---

# Build and run

## Python environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

The native liboqs shared library must also be installed and discoverable.

## v1.0 firmware

```powershell
cd firmware

west build -d build_v1 `
    -b nrf54l15dk/nrf54l15/cpuapp `
    -p always -- `
    '-DCONF_FILE=prj.conf' `
    '-DEXTRA_CONF_FILE=v1_smp_l4_mlkem.conf'

west flash -d build_v1
```

Cold v1.0 CP4 run:

```powershell
cd ..

python -m src.central.main `
    --v1-smp-l4-mlkem `
    --v1-cp4 `
    --v1-unpair-first `
    --log-level DEBUG
```

For a bonded run, preserve the existing bond.

Focused v1.0 runners remain available for CP1, CP2, CP3, and CP4 research testing. CP5 is a lifecycle campaign rather than a separate wire-protocol mode.

## v0.7 firmware

```powershell
cd firmware

west build -d build_v07 `
    -b nrf54l15dk/nrf54l15/cpuapp `
    -p always

west flash -d build_v07

cd ..

python -m src.central.main --phase7-auth-hybrid
```

---

# Testing

From the repository root:

```powershell
python -m pytest -q
python -m compileall -q src tests benchmarks
git diff --check
```

The v1.0 release audit recorded:

```text
1064 passed
1 skipped
1 warning
```

Hardware validation is separate from software regression and includes real BLE pairing/bonding, ML-KEM transport, DK decapsulation, FINISHED, AES-GCM application traffic, lifecycle tests, passive captures, and the post-v1.0 comparative campaign.

---

# Repository structure

```text
pq-ble-handshake/
├── README.md
├── REQUIREMENTS.md / requirements.txt
│
├── firmware/
│   ├── src/                         v0.7 / v1.0 Peripheral implementation
│   ├── third_party/mlkem-native/
│   ├── prj.conf                     v0.7 profile
│   └── v1_smp_l4_mlkem.conf         v1.0 overlay
│
├── src/
│   ├── central/                     BLE / WinRT / protocol runners
│   └── common/                      framing and crypto helpers
│
├── tests/
│   └── native_v1/
│
├── benchmarks/
│   ├── post_v1/                     comparative-evaluation harness
│   └── results/                     measurement artifacts
│
├── docs/
│   ├── research/milestones/
│   ├── research/logs/
│   ├── captures/
│   └── images/
│
├── scripts/
├── report/
├── experimental/                    historical Python Peripheral paths
└── data/keys/                       legacy session-store location
```

The hardware Peripheral is `firmware/`. Historical Python Peripheral/session-resumption paths are not part of the v1.0 hardware architecture.

---

# Evidence and reproducibility

The project distinguishes:

1. software regression;
2. firmware builds/resource reports;
3. real Windows ↔ nRF54L15 DK protocol runs;
4. passive nRF52840/Wireshark observations;
5. post-v1.0 comparative measurements.

Raw evaluation artifacts are stored under:

```text
benchmarks/results/post_v1/
```

The benchmark dataset preserves original run IDs and CP6 labels for traceability.

The documentation layer uses **EVAL-A through EVAL-E** to avoid confusing the comparison campaign with the v1.0 CP1–CP5 implementation checkpoints.

---

# Security scope and limitations

This repository is a research proof of concept, not a Bluetooth SIG standard or production security product.

Important boundaries:

- v1.0 BLE peer authentication remains classical because LE Secure Connections uses P-256;
- ML-KEM provides post-quantum application key establishment, not post-quantum identity authentication;
- v1.0 never combines SMP secret material with `SS_MLKEM`;
- v0.7 and v1.0 are different architectures and should not both be described as hybrid key agreements;
- application RTT is not directly comparable because the frozen workloads differ;
- passive v1.0 captures become opaque after BLE encryption without the LTK;
- GATT/API counters are not ATT/LL packet counts or radio airtime;
- no energy measurements were performed;
- side-channel resistance was not experimentally characterized;
- negative tests validate implemented failure paths but are not a formal security proof;
- human SAS/Numeric Comparison is research interaction, not an unattended deployment UX.

---

# Version history

```text
v0.7
application hybrid
ML-KEM-768 + application P-256 ECDH
        |
        v
hardware-validated authenticated channel
        |
        v
v1.0
BLE SMP Security Mode 1 Level 4
+
ML-KEM-768
+
FINISHED
+
AES-256-GCM
        |
        v
CP1 -> CP5 COMPLETE
        |
        v
Post-v1.0 Comparative Evaluation
EVAL-A -> EVAL-E COMPLETE
```

Earlier protocol milestones remain in the repository for research traceability.

---

# Final result

The project now provides:

- two completed real-hardware BLE/PQ protocol implementations;
- a validated layered v1.0 architecture;
- a retained v0.7 application-level hybrid baseline;
- a reproducible comparative benchmark framework;
- repeated latency/resource/radio observations;
- **9/9 hardware negative/security tests PASS**;
- a final architectural comparison.

The measured results show that **v0.7 is lighter and faster in the current implementation**, while **v1.0 provides a cleaner integration with standard BLE security and authenticated BLE link protection beneath ML-KEM-derived application security**.

For continued development, **v1.0 is the architectural baseline**; v0.7 remains the experimental hybrid reference.
