# Session Resumption Evaluation

**Preparation only. Hardware measurements have not been collected.** This is a
new campaign. Do not edit or append to `benchmarks/results/post_v1`, the EVAL-A–E
documents, historical captures or `cp6*` artifacts. New observations belong in
the ignored `benchmarks/results/session_resumption/` directory.

The [experiment template](experiment.example.json) defines these future
populations. The [hardware plan](../../docs/research/session-resumption-hardware-plan.md)
gives executable operator commands for each protocol path and its prerequisites.

| Scenario ID | Required state and observed path | Baseline-compatible application workload |
|---|---|---|
| `v07_full` | Frozen v0.7, full hybrid + SAS | 3 x 6-byte PING/PONG, 43-byte protected frames |
| `v08_full` | v0.8, force full hybrid + SAS | Same v0.7 workload and worker |
| `v08_resume` | Seeded valid v0.8 ticket, observed resume | Same v0.7 workload and worker |
| `v10_bonded_full` | Frozen v1.0, both BLE bonds present, full ML-KEM | 2 x 16-byte challenge/echo, 51-byte CP4 frames |
| `v11_cold_full` | Both bonds absent, Numeric Comparison, full ML-KEM | Same v1.0 workload |
| `v11_bonded_full` | Bonded L4, full ML-KEM | Same v1.0 workload; split forced-full from ticket-miss fallback |
| `v11_bonded_resume` | Bonded L4 plus valid app ticket, observed resume | Same v1.0 workload |

A requested resume that falls back is **not** a resume latency sample. Record
`requested_scenario`, `observed_path`, `observed_ble_state`, fallback reason and
outcome separately. Reject wrong-profile, unexpected-cold and partial runs from
the intended population; retain their failure records. Firmware reboot between
resume samples destroys the RAM ticket and invalidates the experiment setup.

## Measurement contract

Keep four separate groups; never label application/GATT value bytes as **OTA
bytes**:

1. **Application/control bytes:** exact protocol frames sent/received, separating
   full handshake, resume frames, SEC_INFO attestation, rejects/fallback and
   application data. Successful resume frames are 256 bytes. The current v1.1
   runner also exchanges 20 bytes of SEC_QUERY/SEC_INFO before resume (276 bytes
   including that attestation). Record ciphertext fragmentation headers separately
   from the 1088-byte ML-KEM ciphertext and distinguish reassembled key bytes
   from each API read's returned value length.
2. **GATT API operations:** read/write/notification/subscribe/unsubscribe attempts
   and successes, characteristic, value length and API duration. A read API call
   may cause multiple ATT Read Blob exchanges. API calls are not LL packet counts.
   The four resume frames use two Control write calls and two Data notifications;
   subscriptions, attestation and reconnect operations are additional.
3. **Latency:** preserve wall-clock end-to-end latency, interactive SAS/NC wait,
   scan/connect, security restoration, ticket I/O, resume INIT-to-verified-FINISH_P,
   full application handshake and authenticated application round-trip durations.
   Use the existing `src.central.measurement.Recorder` events and monotonic clocks.
   Mark incomplete phases. Never turn an unobserved/overlapping interval into zero
   or call whole-run-minus-human time pure crypto CPU time. New resume event names
   are `resume_init_sent`, `resume_accept_received`, `resume_finish_c_sent`,
   `resume_finish_p_verified`; full runs mark `start_sent`, `ready_received`,
   `finished_c_sent`, `finished_p_verified`, followed by `app_secure`.
4. **BLE/radio observations:** separate sniffer captures with timestamps, channel
   coverage, capture completeness, retransmission evidence and encryption visibility.
   Missing packets and encrypted v1.1 payloads do not establish zero traffic.
   Air bytes/airtime require adequate capture/controller evidence and must never be
   inferred simply by renaming the first two groups.

For each record include run ID, UTC date, dirty-tree source hashes and baseline
HEAD, exact command, firmware ELF/HEX/config SHA-256, selected profile, NCS/Zephyr,
Python/Bleak/liboqs versions, board/adapter identity, negotiated MTU, connection
parameters if observable, ticket age/use count, seed/full run ID, and outcome.
Store no K_RESUME, traffic key, IV-base or full ticket JSON in benchmark results.
Keep PC/UART logs and capture hashes; confirmation of cryptographic output should
come from authenticated application success, not a secret dump.

Plan 30 noninteractive samples plus 3 marked warmups, within the 100-use ticket
limit (warmups and successful setup resumes also count). Use multiple independently
seeded tickets and report ticket/session clustering; randomize block order to limit
host/BLE drift. Cold/full human ceremonies need explicit manual confirmation and
their own smaller declared sample budget. Record full-to-resume crossover within
each architecture; do not confound it with the different v0.7/v1.0 workloads.

The existing historical runner is intentionally unchanged and does not accept
these new scenario IDs. This directory supplies the separate campaign design and
recording contract; collection orchestration and radio capture are future work
after hardware correctness validation. No numerical latency/radio claim can be
made from the software-only builds or tests.
