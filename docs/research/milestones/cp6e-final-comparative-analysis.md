# CP6-E — Final Comparative Analysis

**Project:** PQ-BLE Handshake  
**Milestone:** CP6-E  
**Status:** FINAL COMPARATIVE ANALYSIS  
**Analysis baseline commit:** `ebbac7f2c59bd00b461c3061a95ed0749e14ad11`

## 1. Objective

CP6-E consolidates the post-v1 experimental campaign and compares the frozen **v0.7 authenticated hybrid application protocol** with **v1.0 BLE Security Mode 1 Level 4 + ML-KEM-768**.

The comparison is deliberately multi-dimensional. It does not reduce the result to a single “faster” or “more secure” ranking. Instead it evaluates:

1. architecture and security-layer placement;
2. repeated hardware latency;
3. firmware resource footprint and crypto-thread stack high-water mark;
4. host/GATT and passive BLE observations;
5. hardware negative/security validation.

CP6-E uses the evidence collected in CP6-A through CP6-D. No energy claims are made because energy was not measured.

## 2. Architectural comparison

### v0.7

v0.7 implements the classical and post-quantum handshake logic at the application layer:

- ML-KEM-768;
- ephemeral application P-256 ECDH;
- hybrid key material based on `SS_MLKEM || SS_ECDH`;
- canonical transcript binding;
- application SAS Numeric Comparison;
- application FINISHED messages;
- AES-256-GCM bidirectional application channel.

BLE SMP is disabled in this profile. Consequently, the BLE link itself does not provide SMP-based authenticated encryption.

### v1.0

v1.0 separates classical BLE authentication from post-quantum application key establishment:

- BLE Security Mode 1 Level 4;
- authenticated LE Secure Connections Numeric Comparison;
- persistent BLE bonding;
- ML-KEM-768 for application key establishment;
- transcript-bound application FINISHED exchange;
- AES-256-GCM bidirectional application channel.

The SMP secret is **not** combined with the ML-KEM secret. BLE SMP authenticates and protects the link, while ML-KEM provides the application-layer PQ key-establishment component.

This separation reduces bespoke application-level classical authentication logic and places classical identity/authentication enforcement in the standard BLE security layer. It must not be interpreted as making the BLE L4 mechanism itself post-quantum: the PQ property is provided by the ML-KEM application key establishment, whereas BLE LE Secure Connections remains a classical mechanism.

## 3. Latency

The final repeated hardware strata are:

- v0.7 hybrid: `n = 30`
- v1.0 bonded: `n = 30`
- v1.0 cold: `n = 5`

Warm-ups, failed runs, negative tests, and infrastructure-invalid runs are excluded from latency statistics.

### 3.1 Machine-time comparison

| Metric | v0.7 hybrid | v1.0 bonded |
|---|---:|---:|
| `secure_machine_ms` mean | 3584.773 ms | 5446.180 ms |
| median | 3091.119 ms | 5459.655 ms |
| sample SD | 1419.824 ms | 1563.321 ms |
| min | 2486.334 ms | 3850.277 ms |
| max | 7480.383 ms | 9594.870 ms |
| p95 | 7330.164 ms | 9266.920 ms |

Relative to v0.7, the v1.0 bonded mean is approximately **+51.9%**, while the median is approximately **+76.6%**.

This is an **end-to-end implementation observation**, not a primitive-cryptography comparison.

Central ML-KEM encapsulation time was essentially similar:

- v0.7 mean: **0.653 ms**
- v1.0 bonded mean: **0.638 ms**

Therefore, the larger v1.0 bonded end-to-end time must not be described as “ML-KEM being slower”. The dominant observed differences are in BLE/GATT/API phases, particularly public-key read and ciphertext transport.

| Phase | v0.7 mean | v1.0 bonded mean |
|---|---:|---:|
| Public-key read | 192.988 ms | 617.186 ms |
| Ciphertext transfer | 658.618 ms | 1772.878 ms |
| Connect/service | 2399.808 ms | 2461.810 ms |

### 3.2 Cold v1.0

For v1.0 cold:

- `n = 5`
- `secure_wall_ms` mean: **8333.861 ms**
- median: **6650.285 ms**

`secure_machine_ms` is intentionally unavailable for this stratum because the full human Numeric Comparison wait is not independently observable at both boundaries.

Accordingly, v1.0 cold wall time is **not** used to estimate machine-only cryptographic overhead.

### 3.3 Application RTT limitation

The frozen application workloads differ:

- v0.7: 3 exchanges, 6-byte `PING/PONG`, 43-byte application frames;
- v1.0: 2 exchanges, 16-byte challenge, 51-byte application frames.

Application RTT values are therefore **not a matched-payload benchmark** and are not used for direct performance ranking.

## 4. Firmware resources

| Resource | v0.7 | v1.0 | Delta |
|---|---:|---:|---:|
| FLASH | 225,652 B | 279,428 B | +53,776 B (+23.8%) |
| RAM | 106,048 B | 109,464 B | +3,416 B (+3.2%) |
| Configured crypto-thread stack | 28,672 B | 28,672 B | 0 B |
| Observed crypto-thread peak | 24,264 B | 24,264 B | 0 B |

The matched CP6-C UART measurements observed the same crypto-thread high-water mark in both profiles:

- configured: **28,672 B**
- unused at high-water: **4,408 B**
- estimated cumulative peak: **24,264 B**
- utilization: approximately **84.6%**

Therefore, the larger total RAM footprint of v1.0 does not correspond to a larger observed crypto-thread peak in these measurements.

## 5. BLE/GATT and passive-capture observations

### 5.1 v0.7 complete passive observation

The dedicated v0.7 CP6-C capture used Access Address `0x7288a3cf` and was followed through `LL_TERMINATE_IND`.

Observed:

- 716 connection packets;
- 8.145325 s followed;
- 95 decoded ATT packets;
- 0 SMP packets;
- 4,710 observed LL payload bytes;
- public-key reads, ciphertext transport, application authentication exchange, FINISHED, and the three application round trips visible at ATT level.

The `4,710` value is **LL payload observed in the capture**, not total over-the-air bytes or airtime.

### 5.2 v1.0 cold

The dedicated cold capture used Access Address `0xaa8f45cf`.

Observed:

- 512 packets;
- 7.605352 s followed;
- 50 ATT packets;
- 9 SMP packets.

The passive sniffer clearly observed the LE Secure Connections ceremony, including Pairing Request/Response, public keys, Confirm/Random, DHKey Check, and the transition into link encryption.

After `LL_START_ENC_REQ`, packets could not be meaningfully decrypted because the LTK was not exported.

### 5.3 v1.0 bonded

The dedicated bonded capture used Access Address `0xdd8ce664`.

Observed:

- 37 packets;
- 0.945367 s followed;
- 0 decoded ATT packets;
- 1 decoded SMP packet.

The sniffer observed encryption restoration but could not follow the later encrypted application protocol as decoded ATT traffic.

### 5.4 Interpretation

These captures demonstrate an architectural visibility difference:

- v0.7 leaves ATT/GATT transport visible because SMP link encryption is disabled, while application payload protection is provided by the application protocol;
- v1.0 additionally protects the BLE link using L4, making post-encryption ATT/GATT opaque to the passive sniffer without the LTK.

The v1.0 captures are therefore **not** suitable for total protocol traffic or airtime comparisons.

## 6. CP6-D security-negative validation

Final CP6-D result:

- v0.7: **7/7 PASS**
- v1.0: **2/2 PASS**
- total: **9/9 PASS**

### v0.7 validated paths

- explicit SAS rejection;
- corrupted `FINISHED_C`;
- application access before FINISHED;
- C→P AES-GCM tag tamper;
- C→P replay;
- P→C local-copy tag tamper;
- P→C local-copy replay.

The two P→C tests are **receiver-local Central checks**, not over-the-air BLE packet injection.

### v1.0 validated paths

- all four protected PQ GATT operations denied before L4;
- explicit PC rejection of Numeric Comparison leaves Windows unpaired with `protection=NONE`, and protected PQ GATT remains denied after reconnection.

These tests validate the implemented negative paths. They are not a formal security proof.

## 7. Overall comparison

| Dimension | v0.7 | v1.0 |
|---|---|---|
| Classical authentication placement | Application layer | BLE SMP L4 |
| PQ KEM | ML-KEM-768 | ML-KEM-768 |
| Classical ECDH used for app key schedule | Yes | No |
| BLE link authenticated/encrypted | No SMP | Yes, L4 |
| Application AES-GCM | Yes | Yes |
| Mean machine time | Lower in measured campaign | Higher in bonded campaign |
| FLASH | Lower | +23.8% vs v0.7 |
| RAM | Lower | +3.2% vs v0.7 |
| Crypto-thread peak | 24,264 B | 24,264 B |
| Passive ATT visibility | Essentially full session | Opaque after L4 encryption |
| CP6-D negative validation | 7/7 PASS | 2/2 PASS |

## 8. Research interpretation

The results expose a clear architectural trade-off.

**v0.7** is the leaner measured implementation. It uses less FLASH and RAM and shows a lower measured machine-time mean in the frozen hardware campaign. Its security architecture is predominantly application-defined: hybrid ML-KEM + P-256 key establishment, SAS/FINISHED authentication, and AES-256-GCM application traffic.

**v1.0** introduces a cleaner separation of responsibilities. Standard BLE SMP L4 handles classical authenticated link establishment and protects ATT/GATT, while ML-KEM remains an independent application-layer PQ key-establishment mechanism. This adds implementation and transport overhead in the measured system, but it also removes the need to reproduce classical BLE authentication semantics entirely in the application protocol and adds authenticated BLE link protection beneath the PQ application channel.

The campaign therefore does not support a simplistic conclusion that one design dominates the other in every dimension:

- v0.7 is lighter and faster in the measured implementation;
- v1.0 provides stronger integration with the standard BLE security model and an additional protected-link layer;
- ML-KEM itself is not responsible for the observed end-to-end latency increase;
- neither the application RTTs nor passive-PCAP byte counts form a payload-matched cross-profile benchmark.

For a production-oriented BLE design, v1.0 is the cleaner architectural baseline because standard BLE L4 is used for classical link authentication/protection while ML-KEM is layered for PQ application key establishment. v0.7 remains valuable as the experimental hybrid baseline and as a reference showing the cost and behavior of implementing the classical/PQ hybrid and authentication logic entirely at application level.

## 9. Limitations

1. v1.0 cold has only five retained successful runs.
2. Cold human Numeric Comparison time cannot be completely separated from machine time.
3. The application workloads differ between profiles.
4. Passive v1.0 PCAPs are incomplete as decoded protocol traces after BLE encryption because the LTK was deliberately not exported.
5. GATT operation counts represent host/API observations rather than packet- or radio-level overhead.
6. No energy measurements were collected.
7. CP6-D is an implementation-level negative-test campaign, not a formal proof of cryptographic security.

## 10. Conclusion

The post-v1 experimental campaign is complete through CP6-E.

Across CP6-A–CP6-E, the project now has:

- reproducible measurement infrastructure and provenance;
- repeated v0.7 and v1.0 hardware latency datasets;
- frozen firmware resource measurements;
- matched crypto-thread high-water evidence;
- passive BLE evidence illustrating the link-layer visibility difference;
- 9/9 hardware negative/security tests passing;
- a final architectural and experimental comparison.

The central result is a measurable trade-off between a lighter application-defined hybrid design (v0.7) and a more layered design integrated with standard BLE L4 security (v1.0). The latter incurs additional footprint and observed end-to-end overhead in the current implementation, while providing authenticated BLE link protection and a cleaner separation between classical BLE authentication and post-quantum application key establishment.
