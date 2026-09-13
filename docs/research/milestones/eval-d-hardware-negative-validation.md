# EVAL-D — Hardware Negative / Security Validation

**Project:** PQ-BLE Handshake\
**Milestone:** EVAL-D\
**Status:** COMPLETE — 9/9 negative tests PASS\
**Date:** 2026-09-13\

## 1. Scope

This is part of the completed [Post-v1.0 Comparative Evaluation](../post-v1-comparative-evaluation.md), separate from v1.0 implementation and validation, which completed at CP5.

> [!NOTE]
> Historical benchmark artifacts retain the CP6 identifier for provenance and
> reproducibility. In those artifacts, CP6 refers only to the post-v1.0 comparative
> evaluation campaign and is not a v1.0 implementation checkpoint.

EVAL-D validates fail-closed behavior and selected authentication, tamper, replay, and pre-authentication properties of the two frozen protocol profiles on real hardware.

The campaign covers:

- **v0.7 authenticated hybrid profile**: application-level ML-KEM-768 + ephemeral P-256 ECDH, SAS, FINISHED, and AES-256-GCM protected application traffic.
- **v1.0 profile**: BLE Security Mode 1 Level 4 using authenticated LE Secure Connections Numeric Comparison, with PQ GATT access gated until L4 is established.

These tests are qualitative negative/security checks. They are not latency samples and are not used in the statistical performance comparison.

## 2. Hardware and environment

- Peripheral: nRF54L15 DK
- DK serial: `1057790967`
- Central: Windows PC `LALESSIO`
- Bluetooth adapter: Realtek Bluetooth 5 Adapter, driver `1.9.1051.3011`
- Python: repository virtual environment
- Bleak: `3.0.2`
- Expected ATT MTU: `247`

Frozen firmware evidence used during the Post-v1.0 Comparative Evaluation:

- v0.7 ELF SHA-256: `4be5399d35a920e777fca2c23003cba9c93f5598ce5aefe77da1931bba614e91`
- v0.7 merged.hex SHA-256: `a76f42eda90eaf75656d6db54fee0ac854083a30a425caca5f77f48f0e9736c1`
- v1.0 ELF SHA-256: `a843bd955966e6ea13dad8287f51fe4c8ec6733359e5b6262111ea482905b243`

The v1.0 firmware hash was re-checked before the v1.0 EVAL-D tests.

## 3. Evidence model

Each valid negative test produces a dedicated run directory under:

`benchmarks/results/post_v1/raw/<run_id>/`

The primary machine-readable evidence is `run.json`, accompanied by `central.log`.

A successful EVAL-D negative test requires:

- `measurement_kind == "negative"`
- `success == true`
- `failure_reason == null`
- `negative_result.verdict == "PASS"`
- the expected scenario classification
- the expected rejection behavior observed by the existing runner

A consolidated local summary was generated at:

- `benchmarks/results/post_v1/summaries/cp6d-security-negatives/summary.json`
- `benchmarks/results/post_v1/summaries/cp6d-security-negatives/summary.csv`

These benchmark-result directories are intentionally local/ignored artifacts and are not required to be committed.

## 4. Results

| Profile | Test | Run ID | Fault / probe | Expected behavior | Result |
|---|---|---|---|---|---|
| v0.7 | `sas-reject` | `cp6d-v07-sas-reject-20260913T121152` | Explicit SAS rejection | FINISHED withheld and application write denied | **PASS** |
| v0.7 | `finished-c` | `cp6d-v07-finished-c-20260913T135229` | Flip one bit of `FINISHED_C` | Authentication error and pre-auth application denial | **PASS** |
| v0.7 | `pre-auth` | `cp6d-v07-pre-auth-20260913T135642` | Application write before FINISHED | Denied before authentication; valid traffic succeeds after FINISHED | **PASS** |
| v0.7 | `c2p-tamper` | `cp6d-v07-c2p-tamper-20260913T135854` | Flip transmitted C→P application tag bit | Reject tampered frame; original sequence remains usable | **PASS** |
| v0.7 | `c2p-replay` | `cp6d-v07-c2p-replay-20260913T140038` | Replay transmitted C→P `seq=0` | Exact replay rejection; no duplicate PONG | **PASS** |
| v0.7 | `p2c-tamper` | `cp6d-v07-p2c-tamper-20260913T140353` | Mutate received P→C copy locally | Central rejects tag; receive counter unchanged | **PASS** |
| v0.7 | `p2c-replay` | `cp6d-v07-p2c-replay-20260913T140439` | Replay received P→C copy locally | Central rejects replay; receive counter unchanged | **PASS** |
| v1.0 | `pre-l4-only` | `cp6d-v10-pre-l4-only-20260913T140943` | Four protected PQ GATT accesses before L4 | All four denied for security reasons | **PASS** |
| v1.0 | `nc-reject` | `cp6d-v10-nc-reject-20260913T141152` | Explicit PC Numeric Comparison rejection | Pairing rejected and protected GATT remains closed | **PASS** |

**Final result: 9/9 PASS.**

## 5. Observed security behavior

### 5.1 v0.7 application-level authentication and channel protection

The v0.7 campaign verified that the protocol remains fail-closed before completion of its application authentication stage.

`finished-c` corrupted exactly one bit of the Central FINISHED value. The peripheral returned the expected protocol authentication error (`PQS7 ERROR 0x06`), and a subsequent Secure Data access remained rejected.

`pre-auth` attempted valid application traffic while the protocol was still in `WAIT_FINISHED_C`. The write was rejected before authentication. After a valid SAS confirmation and FINISHED exchange, the same session successfully completed authenticated AES-256-GCM application traffic.

### 5.2 v0.7 C→P tamper and replay resistance

For `c2p-tamper`, a transmitted application frame with a modified AES-GCM tag was rejected. The rejected frame did not consume the expected sequence number: the original valid `seq=0` frame was subsequently accepted, followed by valid `seq=1` and `seq=2` traffic.

For `c2p-replay`, a previously accepted `seq=0` frame was replayed. The peripheral returned the expected replay error (`PQS7 ERROR 0x04`), no duplicate PONG was accepted, and later sequence numbers continued normally.

### 5.3 v0.7 P→C receiver-local checks

`p2c-tamper` and `p2c-replay` are **receiver-local Central tests**.

They do not represent BLE packet injection or over-the-air mutation:

- `p2c-tamper` mutates a local copy of a received authenticated P→C frame and verifies that AES-GCM authentication fails.
- `p2c-replay` locally reprocesses an already accepted P→C frame and verifies that replay/out-of-order handling rejects it without incorrectly advancing receive state.

The original valid traffic continued successfully after both checks.

### 5.4 v1.0 pre-L4 GATT gating

In `pre-l4-only`, both bonds had been deleted and Windows reported:

- `paired=False`
- `protection=NONE`
- observed scenario `cold`

Before L4 was established, all four protected PQ GATT operations were denied:

- public-key read
- ciphertext write
- control write
- Secure Data CCCD access

The runner therefore confirmed the PQ GATT gate remained closed before authenticated BLE security was established.

### 5.5 v1.0 explicit Numeric Comparison rejection

In `nc-reject`, a real LE Secure Connections Numeric Comparison ceremony was initiated.

The Central received the displayed PIN and the operator explicitly rejected the comparison on the PC. Windows returned:

- `status=REJECTED_BY_HANDLER`
- `paired=False`
- `protection=NONE`

The rejected link was retired and the runner reconnected to the same peer. After reconnection, all four protected PQ GATT operations were again denied.

This confirms that explicit rejection of the L4 authentication ceremony does not leave the PQ GATT surface accessible.

## 6. Infrastructure-invalid attempts excluded from the final result

Infrastructure/setup failures were preserved separately where applicable but are **not** counted as protocol/security failures.

Notable excluded attempts include:

- an early `sas-reject` run that exercised the expected rejection but failed later in benchmark record validation because the v0.7 negative-path scenario was not recorded before the controlled negative-test exception;
- an early `finished-c` attempt that failed in the Windows/Bleak connection path with `OSError` before SAS, fault injection, or any negative-test behavior was reached;
- Codex/local-shell startup attempts that selected the wrong Python environment or an invalid interpreter path and therefore never started a hardware test.

Only the nine successful runs listed in Section 4 are included in the final EVAL-D verdict.

## 7. Interpretation and limitations

EVAL-D demonstrates the expected behavior of the implemented negative-test paths on the tested Windows ↔ nRF54L15 DK setup.

The campaign supports the following implementation-level conclusions:

- v0.7 denies application access before completion of its application authentication stage;
- corrupted FINISHED data is rejected;
- C→P authenticated-data tampering is detected without consuming the valid sequence number;
- C→P replay is rejected without producing a duplicate valid response;
- Central-side P→C authentication and replay checks reject modified/replayed local copies;
- v1.0 keeps PQ GATT operations inaccessible before BLE Security Mode 1 Level 4;
- explicit rejection of Numeric Comparison leaves the peer unpaired and the PQ GATT gate closed.

These results do **not** constitute a formal proof of protocol security. They validate the implemented negative paths exercised by this campaign.

No energy-consumption claims are made.

## 8. Milestone conclusion

**EVAL-D is complete.**

Final hardware negative/security validation result:

- v0.7: **7/7 PASS**
- v1.0: **2/2 PASS**
- Total: **9/9 PASS**

[EVAL-E is also complete](eval-e-final-comparative-analysis.md), consolidating the EVAL-A through EVAL-D evidence into the final architectural and experimental comparison between v0.7 and v1.0.
