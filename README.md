# PQ-BLE-HANDSHAKE

PQ-BLE-HANDSHAKE is a research proof of concept for post-quantum protected communication over Bluetooth Low Energy on resource-constrained embedded hardware.

## Current status

**v1.0 — COMPLETE / HARDWARE VALIDATED through CP1–CP5.**

The current architecture runs between a **Windows PC Central** and an **nRF54L15 DK Peripheral**. It provides BLE SMP Security Mode 1 Level 4, ML-KEM-768 application key establishment, transcript-bound HKDF-SHA256, bidirectional FINISHED confirmation, and a bidirectional AES-256-GCM application channel.

- **Hardware:** cold pairing, authenticated LE Secure Connections with Numeric Comparison, bonded reconnection, encrypted application traffic, and connection/session lifecycle scenarios are recorded as passed.
- **Software:** the full suite was rerun on 2026-09-10 at `912fe85` (`v1.0`): **1064 passed, 1 skipped, 1 warning**.
- **Firmware:** both the current v1.0 profile and the v0.7 baseline were rebuilt successfully during this audit with NCS 3.0.0.
- **Architecture:** SMP and ML-KEM provide separate security layers. SMP key material is neither exported nor combined with the ML-KEM secret.
- **Baseline:** the completed, hardware-validated **v0.7 application-level ML-KEM + P-256 hybrid protocol** remains available for experiments. It is still the default firmware build profile; v1.0 is selected explicitly.
- **Next phase:** controlled comparison of the frozen v0.7 and v1.0 architectures, with repeated measurements and further security experiments.

See the [final v1.0 milestone](docs/research/milestones/v1.0-smp-l4-mlkem-final.md) and the [hardware evidence and its scope](#hardware-validation).

## Research objective

The project designs, implements, and experimentally evaluates practical ways to add post-quantum security to BLE communication on constrained embedded devices. Both implementations use standard BLE GATT transport without modifying the Bluetooth stack.

Two experimentally relevant architectures address this objective: v0.7 constructs authentication and a classical/PQ hybrid key schedule in the application; v1.0 delegates classical association and link protection to standard BLE SMP and adds post-quantum application key establishment. Their implementation and validation are complete; their controlled comparative evaluation is the next research phase.

## Protocol architectures

### v1.0 — BLE SMP Level 4 + ML-KEM-768

v1.0 is a **layered classical/post-quantum architecture**:

```text
Application: authenticated PING/PONG
    |
AES-256-GCM application channel
    |  separate C->P / P->C keys, IV bases, and counters
PQ-derived application keys
    |  transcript-bound HKDF-SHA256 + FINISHED_C / FINISHED_P
ML-KEM-768 application key establishment
    |
BLE GATT: access gated on authenticated Level 4
    |
BLE SMP Security Mode 1 Level 4
    |  authenticated LE Secure Connections, Numeric Comparison, bonding
BLE Link Layer: encrypted/authenticated link
```

SMP uses classical P-256 internally and establishes the authenticated BLE link. The application obtains `SS_MLKEM` through ML-KEM-768 and uses **only that secret** as the input keying material for its key schedule. v1.0 has no application P-256 ECDH, no application SAS, and no `SS_MLKEM || SS_ECDH` combiner. Neither the SMP DHKey nor the Long Term Key (LTK) is exported into the application KDF.

The firmware implements the strict L4 gate in [pq_v1_security.c](firmware/src/pq_v1_security.c). The Python protocol primitives are in [v1_cp3.py](src/common/v1_cp3.py) and [v1_cp4.py](src/common/v1_cp4.py), with corresponding firmware implementations in [pq_v1_cp3.c](firmware/src/pq_v1_cp3.c) and [pq_v1_cp4.c](firmware/src/pq_v1_cp4.c).

### v0.7 — Application-level ML-KEM + P-256 hybrid

v0.7 is the previous completed architecture and a retained experimental baseline. BLE SMP is intentionally disabled for this profile (`CONFIG_BT_SMP=n`). Its application protocol combines independent ML-KEM-768 and ephemeral NIST P-256 ECDH contributions:

```text
SS_MLKEM (32 B) + SS_ECDH (32 B)
    |
length-prefixed hybrid IKM + canonical transcript
    |
HKDF-SHA256
    |
6-digit application SAS + bidirectional FINISHED
    |
direction-separated AES-256-GCM application traffic
```

The exact hybrid input is `u16be(32) || SS_MLKEM || u16be(32) || SS_ECDH` (68 bytes). Its 2457-byte canonical transcript binds the version domain, endpoint roles, session identifier, ML-KEM public key/ciphertext, and both 65-byte P-256 public keys. Human comparison of the application SAS precedes authenticated channel activation.

The [v0.7 milestone](docs/research/milestones/v0.7-authenticated-hybrid-secure-channel.md) preserves CP1 hybrid primitives/KATs, CP2 BLE interoperability, CP3 authenticated bidirectional traffic, and CP4 negative validation and resource measurements. Physical validation includes three `PING 0/1/2` ↔ `PONG 0/1/2` rounds and seven negative cases. The P→C tamper/replay cases inject faults locally at the Central receiver while using a real DK session.

## v0.7 vs v1.0

| Aspect | v0.7 application hybrid | v1.0 SMP L4 + ML-KEM |
|---|---|---|
| BLE SMP | Disabled | Authenticated LE Secure Connections, Level 4 |
| Peer authentication | Interactive application SAS over the hybrid transcript, followed by FINISHED | Classical SMP Numeric Comparison/bond, followed by application FINISHED key confirmation |
| P-256 location | Ephemeral application ECDH on both endpoints | Inside standard BLE SMP only |
| ML-KEM | ML-KEM-768 application contribution | ML-KEM-768 application secret |
| Secret combination | ML-KEM and application ECDH secrets combined in hybrid HKDF | SMP and ML-KEM layered; SMP key material never exported or combined |
| Authentication UI | Application SAS displayed on PC/DK UART; explicit Central confirmation | SMP Numeric Comparison on Windows and DK UART; PC confirmation and DK buttons |
| Link protection | No SMP link encryption | SMP-authenticated, encrypted BLE link |
| Application AEAD | Direction-separated AES-256-GCM | Direction-separated AES-256-GCM |
| Bonding | No SMP bonds; no completed DK application-session resumption | Persistent SMP bonds; fresh application session on every connection |
| Main research role | Completed application-level hybrid baseline | Current completed layered architecture |

## v1.0 protocol flow

1. **Connect and establish L4.** A cold connection first probes Public Key read, Ciphertext write, Control write, and Secure Data CCCD subscription; all must be denied. Windows requests `CONFIRM_PIN_MATCH` with `ENCRYPTION_AND_AUTHENTICATION`. The operator compares the Windows and DK values and confirms both. A bonded connection restores authenticated L4 using the stored bond.
2. **Check protected GATT access.** Subscribe to Secure Data notifications and exchange `SEC_QUERY` / `SEC_INFO`. The Central requires L4, Secure Connections, authentication, a 16-byte encryption key, an open PQ gate, and profile `0x10`. Firmware also checks the current connection and generation on sensitive operations.
3. **Exchange ML-KEM material.** The Central reads the DK's 1184-byte public key, encapsulates with liboqs, and writes the 1088-byte ciphertext using the existing fragmentation transport. The hardware logs show five ciphertext fragments at negotiated ATT MTU 247. The secret is 32 bytes; the 2400-byte decapsulation key remains in DK RAM.
4. **Bind the transcript.** After a second strict `SEC_INFO`, the Central sends `START_CP3` with a fresh 16-byte session identifier. The DK worker decapsulates, reconstructs the canonical transcript, and replies with `READY_CP3(TH0)`. The Central checks the transcript hash.
5. **Confirm the keys.** The DK verifies `FINISHED_C` and queues `FINISHED_P`; application keys remain pending until that notification is successfully queued. The Central verifies `FINISHED_P` before activating its keys. Both reach `APP_SECURE`.
6. **Exchange application data on the same connection.** CP4 sends two encrypted 16-byte random PING challenges and authenticates matching PONG responses, using sequences 0 and 1 in each direction.
7. **Retire the session.** Disconnect or session-invalidating failure clears the owned application state. A later connection repeats ML-KEM/CP3 and starts new CP4 counters at zero, even when the SMP bond persists.

The active CP3 transcript and schedule are:

```text
T0  = "PQ-BLE-HANDSHAKE-v1.0/CP3-TRANSCRIPT"
      || SEC_INFO_frame(12) || MLKEM_public_key(1184)
      || MLKEM_ciphertext(1088) || START_CP3_frame(24)
TH0 = SHA256(T0)
PRK = HKDF-Extract-SHA256(salt=TH0, IKM=SS_MLKEM)

K_FINISHED_C = HKDF-Expand-SHA256(PRK, D || "FINISHED-C" || TH0, 32)
K_FINISHED_P = HKDF-Expand-SHA256(PRK, D || "FINISHED-P" || TH0, 32)
VERIFY_C = HMAC-SHA256(K_FINISHED_C, D || "VERIFY-C" || TH0)
TH1 = SHA256(TH0 || exact_FINISHED_C_frame)
VERIFY_P = HMAC-SHA256(K_FINISHED_P, D || "VERIFY-P" || TH1)
TH2 = SHA256(TH1 || exact_FINISHED_P_frame)
K_APP_C2P = HKDF-Expand-SHA256(PRK, D || "APP-C2P" || TH2, 32)
K_APP_P2C = HKDF-Expand-SHA256(PRK, D || "APP-P2C" || TH2, 32)

D = ASCII "PQ-BLE-HANDSHAKE-v1.0/" (without a terminating NUL)
```

`SEC_INFO_frame` is the exact second attestation on the Central and the canonical live-L4 representation reconstructed by the DK. `READY_CP3` synchronizes transcript hashes; FINISHED provides explicit key confirmation. Each FINISHED carries 32 bytes of HMAC verification data in a 40-byte PQV1 frame.

The standalone CP2 `START_V1` / `READY_V1` exchange remains a **TEST-ONLY HMAC diagnostic** for ML-KEM interoperability. The complete CP3/CP4 path uses its own START/READY messages and does not use that diagnostic as FINISHED.

## v1.0 checkpoints

| Checkpoint | Purpose | Software status | Hardware status |
|---|---|---|---|
| CP1 | SMP L4, Numeric Comparison, persistent bonds, strict GATT gate | PASS: security/framing, WinRT and native lifecycle tests | PASS: cold/bonded, pre-L4 denials, explicit PC rejection |
| CP2 | ML-KEM-768 over L4; TEST-ONLY shared-secret agreement diagnostic | PASS: primitives, interoperability and lifecycle | PASS: cold and bonded |
| CP3 | Canonical transcript, ML-KEM-only HKDF, bidirectional FINISHED | PASS: KATs, C/Python agreement and failure/lifecycle tests | PASS: cold and bonded, `APP_SECURE` |
| CP4 | Bidirectional AES-256-GCM application data | PASS: framing, AEAD, sequencing, replay and invalidation | PASS: cold and bonded, two PING/PONG rounds |
| CP5 | Connection/session lifecycle and stale-work cleanup | PASS: 17 dedicated lifecycle tests plus full regression | PASS recorded: cold/bonded, repeated reconnects, reboot, Central restart, bond reset |

CP1–CP5 complete the implementation and lifecycle-validation track. The later CP6 security/comparison campaign is a separate experimental phase. See [research evidence](#research-evidence) for checkpoint-specific records.

## Secure application traffic

The current CP4 format is defined by [pq_v1_frame.h](firmware/src/pq_v1_frame.h), [pq_v1_cp4.h](firmware/src/pq_v1_cp4.h), and the matching [Python implementation](src/common/v1_cp4.py). Multi-byte integers use big-endian encoding; sizes below are bytes.

```text
PQV1 | version | subtype | payload_len | seq | msg_type | plaintext_len | ciphertext | tag
  4       1         1          2          8       1             2             N        16
<------------- 8-byte header ----------><---------------- payload ---------------------->
```

| Field | Meaning |
|---|---|
| Magic / version | ASCII `PQV1` / `0x10` |
| Subtype | `APP_C2P = 0x20` via Control write; `APP_P2C = 0x21` via Secure Data notification |
| `payload_len` | `27 + N`, excluding the 8-byte header |
| `seq` | Unsigned 64-bit directional sequence number |
| `msg_type` | `PING = 0x01`, `PONG = 0x02` |
| `plaintext_len` | `N`; ciphertext has the same length |
| `tag` | Full 16-byte AES-GCM authentication tag |

Frame overhead is **35 bytes**. The parser/crypto helpers bound `N` to 128 bytes, but the active application accepts exactly **16-byte PING/PONG challenges**: each validated frame is **51 bytes**, requiring ATT MTU **54 or greater**. Hardware runs used MTU **247**. CP4 has no application-frame fragmentation; it rejects an insufficient MTU.

For each direction `dir = C2P` or `P2C`:

```text
IV_dir = HMAC-SHA256(
    K_APP_dir, "PQ-BLE-HANDSHAKE-v1.0/IV-" || dir || session_id || 0x01
)[0:12]

nonce = IV_dir XOR (0x00000000 || u64be(seq))

AAD = "PQ-BLE-HANDSHAKE-v1.0/CP4-AAD" || session_id(16)
      || exact_PQV1_header(8) || u64be(seq) || msg_type(1) || u16be(N)
```

`dir` in the IV label is ASCII. The IV construction is the one-block HKDF-Expand form with the directional application key as its input PRK. IV bases and nonces are derived locally and are not transmitted. The AAD binds the session, direction, version/header, sequence, message type, and length.

The Central owns `tx_c2p` / `rx_p2c`; the DK owns `rx_c2p` / `tx_p2c`. Receivers require `received_seq == expected_rx_seq`: no replay window, duplicates, gaps, or reordering are accepted. The terminal value `UINT64_MAX` is reserved to prevent wraparound.

The Central consumes a transmit sequence before sending; send failure invalidates the session. The DK commits counter advancement after successful authentication, PONG generation, live-session checks, and notification queueing. Authentication, sequence, or fatal transport/lifecycle failure invalidates the application session rather than continuing with ambiguous state. Software/native tests exercise these failure paths; hardware logs demonstrate the positive sequence progression and reset across sessions.

## Hardware and software environment

| Component | Verified environment / implementation |
|---|---|
| Peripheral | Nordic nRF54L15 DK; board target `nrf54l15dk/nrf54l15/cpuapp` |
| Firmware SDK | nRF Connect SDK **3.0.0** |
| RTOS | Zephyr **4.0.99**, build version **v4.0.99-ncs1** |
| Toolchain | Zephyr SDK **0.17.0** |
| Central | Windows PC; current audited `.venv`: Python **3.13.3**, Bleak **3.0.2** |
| Python cryptography | `cryptography` **50.0.1**; liboqs **0.15.0** / liboqs-python **0.16.0** |
| Test runner | pytest **9.1.1**, pytest-asyncio **1.4.0** |
| Embedded ML-KEM | Vendored **mlkem-native v2.0.0**, portable C, ML-KEM-768 |
| Embedded crypto API | PSA Crypto through Nordic `nrf_security`: SHA-256/HMAC, HKDF construction, AES-GCM and production randomness; P-256 support for SMP or the v0.7 application |
| Historical passive capture | nRF52840 Dongle with nRF Sniffer/Wireshark; not the protocol Peripheral |

These are observed versions, not a dependency lock. [requirements.txt](requirements.txt) specifies minimum Python package versions; [REQUIREMENTS.md](REQUIREMENTS.md) contains broader historical setup notes. The liboqs/wrapper mismatch is present in the validated environment and produces the single test warning. Exact older benchmark environments are recorded with their results.

The [vendoring record](firmware/third_party/mlkem-native/VENDORED.md) pins mlkem-native to commit `d1b2fe782888bdb761a50336012923180be7f502`. The firmware supplies PSA-generated random coins to its deterministic API at startup; deterministic KAT inputs are test fixtures.

Firmware profiles are deliberately separate:

| Profile | Configuration | Relevant settings |
|---|---|---|
| v0.7, default | [prj.conf](firmware/prj.conf) | `PQ_PROFILE_V07_HYBRID`; `CONFIG_BT_SMP=n` |
| v1.0, explicit | `prj.conf` + [v1_smp_l4_mlkem.conf](firmware/v1_smp_l4_mlkem.conf) | `CONFIG_PQ_PROFILE_V10_SMP_L4_MLKEM=y`, `CONFIG_BT_SMP=y`, `CONFIG_BT_SMP_SC_ONLY=y`, MITM enforcement, 16-byte minimum encryption key, bonding and settings persistence |

The v1.0 fragment overrides the baseline SMP setting. Both profiles share the GATT layout and a **28,672-byte crypto worker stack**. Expensive cryptographic operations execute on that worker, outside GATT callbacks. Profile selection and handshake/UI deadlines are defined in [Kconfig](firmware/Kconfig).

## Repository structure

```text
pq-ble-handshake/
├── README.md
├── REQUIREMENTS.md / requirements.txt
├── firmware/
│   ├── src/                       GATT, crypto worker, v0.x and v1.0 protocols
│   ├── third_party/mlkem-native/  pinned embedded ML-KEM implementation
│   ├── CMakeLists.txt / Kconfig
│   ├── prj.conf                   default v0.7 profile
│   └── v1_smp_l4_mlkem.conf        explicit v1.0 overlay
├── src/
│   ├── central/                   BLE client, WinRT pairing, protocol runners
│   └── common/                    framing, cryptography, legacy session helpers
├── tests/
│   └── native_v1/                 host adapters exercising firmware C logic
├── docs/
│   ├── research/milestones/       checkpoint specifications and conclusions
│   ├── research/logs/             recorded PC/DK validation output
│   ├── captures/                  historical BLE packet captures
│   └── images/                    capture screenshots
├── scripts/                       setup, build and UART capture helpers
├── benchmarks/results/            earlier CPU/primitive benchmark artifacts
├── report/                        LaTeX research report and figures
├── experimental/                  historical Python Peripheral prototype
└── data/keys/                     legacy local session-store location
```

The hardware Peripheral is `firmware/`. The experimental Python Peripheral and older Python session-resumption framework are separate historical paths, not v1.0 hardware features.

## Build and run

### Python Central setup

From the repository root, on Windows:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

The native **liboqs shared library must also be installed and discoverable**; the Python wrapper alone is insufficient. [setup_windows.ps1](scripts/setup_windows.ps1) contains the repository's MSVC/CMake liboqs setup procedure, and [setup.sh](scripts/setup.sh) provides the historical Linux procedure. The Windows helper creates `venv/`, whereas the audited environment uses `.venv/`; use the environment that contains your installed dependencies. Fresh setup scripts are not pinned reproductions of the version table above.

The validated v1.0 pairing path uses Windows WinRT custom pairing. Linux/macOS support in the shared BLE client does not establish equivalent v1.0 hardware validation.

### v1.0 SMP-L4 firmware

From an initialized **nRF Connect SDK 3.0.0** environment:

```powershell
cd firmware
west build -d build_v1_fix -b nrf54l15dk/nrf54l15/cpuapp -p always -- `
  '-DCONF_FILE=prj.conf' '-DEXTRA_CONF_FILE=v1_smp_l4_mlkem.conf'
west flash -d build_v1_fix
cd ..
```

Alternatively, the checked-in Windows helper loads the Nordic toolchain environment and builds the current sources:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build_v1_cp3.ps1 -Profile v1
```

Despite its historical filename, this helper includes the current CP4/CP5 code and uses `firmware/build_v1_cp3/`. Its default paths are `C:\ncs\v3.0.0` and `C:\ncs\toolchains\0b393f9e1b`; override `-NcsRoot` and `-Toolchain` for another installation. Its optional `-Flash` uses `-SerialNumber` to select the DK.

Run the full application path:

```powershell
python -m src.central.main --v1-smp-l4-mlkem --v1-cp4
```

For cold pairing, clear DK bonds with **BUTTON 3 while disconnected**, then remove the Windows bond through the explicit test option:

```powershell
python -m src.central.main --v1-smp-l4-mlkem --v1-cp4 --v1-unpair-first
```

Compare the six-digit Windows value with the DK UART output. On the DK, **BUTTON 0 accepts** and **BUTTON 1 rejects**; the PC also requires explicit confirmation. Retain both bonds and repeat the ordinary CP4 command for bonded reconnection. Each invocation creates a new application session and runs two PING/PONG rounds before disconnecting.

Expected successful completion:

```text
PQ-BLE V1.0 CP4 AES-256-GCM BIDIRECTIONAL DATA: PASS
```

Checkpoint runners remain available: `--v1-smp-l4-mlkem` alone exercises CP1, `--v1-cp2` selects the TEST-ONLY interoperability diagnostic, and `--v1-cp3` selects transcript/FINISHED without application data. CP5 is a lifecycle campaign using the CP4 runner; there is no separate `--v1-cp5` mode.

### v0.7 baseline firmware and Central

Build the baseline without the v1.0 configuration fragment:

```powershell
cd firmware
west build -b nrf54l15dk/nrf54l15/cpuapp -p always
west flash
cd ..
python -m src.central.main --phase7-auth-hybrid
```

The Windows build helper also supports `-Profile v07`, which explicitly clears the extra configuration fragment. Use a separate baseline build configuration when switching profiles.

Compare the application SAS with the DK UART and confirm it at the Central. A successful run ends with:

```text
PQ-BLE PHASE7 AUTHENTICATED HYBRID SECURE CHANNEL E2E: PASS
```

The v0.7 negative runner accepts `--phase7-negative-test-only MODE` with `sas-reject`, `finished-c`, `pre-auth`, `c2p-tamper`, `c2p-replay`, `p2c-tamper`, or `p2c-replay`. See the [v0.7 milestone](docs/research/milestones/v0.7-authenticated-hybrid-secure-channel.md) for their procedures and interpretations.

## Testing

Run software regression from the repository root with the Python environment active:

```powershell
python -m pytest -q
python -m compileall -q src tests
git diff --check
```

**Verified audit result, 2026-09-10: 1064 passed, 1 skipped, 1 warning (49.19 s).** The skipped case tests unavailable-WinRT handling and is intentionally skipped on Windows. The warning is the liboqs 0.15.0 / liboqs-python 0.16.0 mismatch.

The successful audit used a fresh workspace temporary directory after an existing directory denied access:

```powershell
python -m pytest -q -ra --tb=short --maxfail=1 `
  --basetemp=C:\pq_ble\.pytest_readme_audit_20260910 `
  -o cache_dir=C:\pq_ble\.pytest_readme_cache
```

Adapt these absolute paths to your checkout and choose a fresh temporary directory if an existing one has incompatible permissions. Native tests require host GCC; some PSA adapters use Windows BCrypt. Other environments can have different skip counts.

The suite includes earlier-protocol regressions, deterministic vectors, real liboqs/mlkem-native interoperability, C/Python framing and crypto checks, modeled BLE/WinRT behavior, and native firmware lifecycle tests. These tests do not reproduce radio pairing or persistent hardware bonds; those require the separate manual E2E campaign.

## Hardware validation

The recorded platform is **Windows Central ↔ BLE ↔ nRF54L15 DK**. CP1 passed on 2026-09-08, CP2 on 2026-09-09, and CP3–CP5 on 2026-09-10.

| Evidence | Recorded result and scope |
|---|---|
| [CP1 logs](docs/research/logs/v1_cp1_1-tests.txt) | Four pre-L4 GATT denials; real Numeric Comparison; L4/SC/authentication with 16-byte link key; bond creation/reconnection; explicit PC NC rejection |
| [CP2 logs](docs/research/logs/v1_cp2_test.txt) | Cold/bonded ML-KEM encapsulation/decapsulation and matching TEST-ONLY diagnostic |
| [CP3 logs](docs/research/logs/v1_cp3-tests.txt) | Cold/bonded transcript agreement, both FINISHED verifications, directional key derivation and `APP_SECURE` |
| [CP4 logs](docs/research/logs/v1_cp4_tests.txt) | Cold/bonded bidirectional AES-256-GCM; sequence 0 and 1; DK authentication and PONG queueing |
| [CP5 campaign](docs/research/logs/v1_cp5_tests.txt) | Cold/bonded baselines, three bonded reconnects, DK reboot retaining the bond, Central restart, bond clearing and return to cold pairing |

CP5 records all scenarios as passed. Its cold/bonded baselines and DK reboot have detailed PC/DK transcripts; bond reset has a detailed Central transcript. The three consecutive reconnects and Central restart are retained as brief operator `OK` confirmations, with fuller conclusions in the final milestone. Their archival detail is therefore less complete than the other scenarios.

The recorded new sessions repeat ML-KEM/CP3 and restart application counters at zero. Lifecycle cleanup, stale-callback isolation, and the CP5 fix that releases a retired CP4 worker's transfer slot are additionally covered by software/native tests. Hardware positive traces alone do not demonstrate every injected failure case.

**Firmware build audit (2026-09-10):** the Windows helper was run with `-Profile v1 -Incremental` and `-Profile v07 -Incremental`. Both builds succeeded and generated `merged.hex`.

| Audit build | FLASH used / region | RAM used / region |
|---|---:|---:|
| v1.0 | 279,428 B / 1420 KB | 109,464 B / 188 KB |
| v0.7 baseline at current HEAD | 225,652 B / 1428 KB | 106,048 B / 188 KB |

These are incremental build observations using the helper's configuration, including disabled `DEBUG_THREAD_INFO`, not pristine release benchmarks. Existing deprecated Bluetooth API/buffer settings and `void main(void)` warnings remain. Local build logs are generated under `firmware/build_cp3_logs/`.

The CP3 milestone records successful v1.0 and v0.7 regression builds; the CP4 milestone records build, flash and boot success. The historical v0.7 release recorded **225,788 B FLASH**, **106,560 B RAM**, and a maximum observed **24,264 B** crypto-worker stack peak. These remain historical build observations, not matched v0.7/v1.0 benchmark results. The CP4 milestone explicitly lacks a recorded CP4 memory report.

The CP1 Windows `CONFIRM_ONLY` attempt failed closed, but its automated `just-works` result was **inconclusive**: an actual on-air BLE Just Works association was not demonstrated. Historical [packet captures](docs/captures/) document earlier GATT transport; they are not packet-level proof of the completed v1.0 channel. Hardware was not reflashed or rerun during this README audit.

## Security properties

| Layer | Implemented property | Boundary |
|---|---|---|
| BLE SMP Level 4 | Authenticated LE Secure Connections, human Numeric Comparison for cold pairing, bond restoration, encrypted/authenticated link | **Classical P-256; not post-quantum** |
| Firmware GATT gate | Sensitive operations require the current authenticated L4 connection, SC flag and 16-byte encryption key | Uses both GATT permissions and live runtime checks |
| ML-KEM-768 | Post-quantum application key-establishment secret | Peer association/authentication comes from SMP in v1.0 |
| Transcript and FINISHED | Bind key derivation to the application exchange and explicitly confirm possession of the derived keys | No independent PQ identity authentication or SMP-secret channel binding |
| AES-256-GCM | Application-payload confidentiality/integrity, with session/direction/header binding in AAD | Protects the application messages, not all BLE metadata |
| Sequence and lifecycle checks | Strict ordered reception, replay rejection, nonce discipline, invalidation on fatal failures and stale connection work | Fresh application state is required on reconnection |

These are implemented mechanisms supported by tests and the stated hardware observations, not a formal security proof. In v0.7, application SAS and the hybrid transcript provide the interactive authentication mechanism instead of SMP; the two authentication ceremonies must not be conflated.

## Limitations / threat model

- This is a research proof of concept, not production-certified software or a new Bluetooth standard. Validation concerns the stated Windows/DK setup, not a broad interoperability certification.
- The design assumes trusted endpoints, secure randomness, and correct human comparison. It does not address endpoint compromise, radio jamming, physical key extraction, or concealment of BLE traffic metadata.
- v1.0 does not make the whole BLE stack post-quantum secure. SMP peer authentication remains classical; there is no ML-DSA/certificate-based PQ identity authentication, and ML-KEM alone does not authenticate a peer.
- The DK generates its ML-KEM key pair **once at boot** and reuses it until reboot. A new application session uses fresh encapsulation randomness and a fresh session identifier, not a newly generated DK key pair. Per-session ML-KEM forward secrecy against later compromise of that decapsulation key is not claimed.
- SMP bonds persist; v1.0 application keys and counters do not. The historical Python session store is not hardware application-session resumption for either completed architecture.
- The current v1.0 application is a two-round, 16-byte PING/PONG demonstrator with strict sequencing. General application messaging, recovery/retransmission policies and broader MTU/platform evaluation require further work.
- Owned firmware secret buffers are cleared; Python cleanup is best effort and cannot guarantee erasure of immutable or library-internal copies.
- No formal protocol verification, experimental physical side-channel resistance, fault-injection assessment, or completed energy campaign is claimed. The later comparative/security campaign remains pending.

## Experimental comparison / next phase

The next major research task is a controlled evaluation of **v0.7 application-level ML-KEM + P-256 hybrid establishment** against **v1.0 SMP Level 4 + ML-KEM application protection**.

The [post-v1 evaluation plan](docs/research/milestones/v1.0-smp-l4-mlkem-final.md#post-v1-comparative-evaluation) supports repeated latency measurements, protocol/GATT overhead, fragmentation, FLASH/RAM, crypto-worker stack usage, cold/bonded behavior, and further negative/security experiments. The checkpoint documents also identify MTU-dependent transport behavior and the need to separate cryptographic work, BLE transport, and human confirmation time.

**These comparative measurements are future work.** Existing one-shot hardware timings include different scheduling, transport, or human-interaction effects; they do not establish a performance ranking. The earlier [benchmark results](benchmarks/results/README.md) measure PC-side cryptographic operations, AES-GCM CPU throughput, and fragmentation/reassembly. They exclude real BLE scan/connection/GATT costs and are not the v0.7-versus-v1.0 hardware study.

## Project evolution

| Milestone | Completed contribution |
|---|---|
| v0.1 | BLE/GATT transport proof of concept |
| [v0.2](docs/research/milestones/v0.2-mlkem-ondevice.md) | On-device ML-KEM-768 integration and deterministic self-test |
| [v0.3](docs/research/milestones/v0.3-mlkem-ble-e2e.md) | Real BLE liboqs Central ↔ mlkem-native DK interoperability |
| [v0.4](docs/research/milestones/v0.4-pq-secure-channel.md) | Pure-PQ HKDF/AES-GCM secure channel |
| [v0.5](docs/research/milestones/v0.5-authenticated-pq-handshake.md) | Transcript, application SAS and bidirectional FINISHED |
| [v0.6](docs/research/milestones/v0.6-bidirectional-secure-channel.md) | Authenticated bidirectional application traffic |
| [v0.7 CP1–CP4](docs/research/milestones/v0.7-authenticated-hybrid-secure-channel.md) | Application P-256/ML-KEM hybrid primitives, interoperability, authenticated channel, seven negative cases and final resource observations; historical release suite: 495 passed |
| v1.0 CP1 | SMP Level 4 foundation and real Numeric Comparison |
| v1.0 CP2 | ML-KEM interoperability over L4 |
| v1.0 CP3 | ML-KEM-only transcript/key schedule and FINISHED |
| v1.0 CP4 | Bidirectional AES-256-GCM application channel |
| v1.0 CP5 | Multi-session lifecycle validation and retired-worker cleanup; tagged `v1.0` at `912fe85` |

The frozen release tags remain available, including `v0.7-authenticated-hybrid-secure-channel` and `v1.0`.

## Research evidence

| Record | Purpose |
|---|---|
| [v1.0 final milestone](docs/research/milestones/v1.0-smp-l4-mlkem-final.md#cp5--lifecycle-and-multi-session-validation) | CP5 lifecycle specification, scenario acceptance and final completion decision |
| [CP1 hardware-fix audit](docs/research/milestones/v1.0-cp1-hardware-fix-audit.md) | Pairing/gating fixes, observations and limits |
| [CP1/CP2 milestone](docs/research/milestones/v1.0-smp-l4-mlkem.md) | Foundational SMP/ML-KEM specification and checkpoint evidence |
| [CP3 milestone](docs/research/milestones/v1.0-smp-l4-mlkem-cp3-pass.md) | Exact transcript, HKDF and FINISHED specification; software/build/hardware results |
| [CP4 milestone](docs/research/milestones/v1.0-smp-l4-mlkem-cp4-pass.md) | Exact AEAD frame, IV/nonce/AAD and cold/bonded validation |
| [v0.7 milestone](docs/research/milestones/v0.7-authenticated-hybrid-secure-channel.md) | Hybrid specification, public KAT vectors, checkpoint history and measurements |
| [v0.7 positive log](docs/research/logs/v0.7-positive-test.txt) / [negative log](docs/research/logs/v0.7-negative-tests.txt) | Recorded physical-baseline validation |
| [Research logs](docs/research/logs/) / [milestone archive](docs/research/milestones/) | Earlier experiments and their original evidence |

Documentation is chronological and contains stale status text. In particular, the final v1.0 milestone retains an earlier checkpoint table/completion condition that conflicts with its later CP5 acceptance and final release decision. Earlier [protocol](docs/protocol-spec.md), [security](docs/security-analysis.md), [testing](docs/testing-guide.md), [test-results](docs/test-results.md), and [firmware](firmware/README.md) documents also predate parts of the current implementation. Read their claims in checkpoint context; the current source, release history, final acceptance sections, and linked logs establish the status summarized here.

## Author

Alessio Bonora

