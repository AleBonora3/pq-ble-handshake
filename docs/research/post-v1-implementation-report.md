# Post-v1.0 evaluation: implementation and audit report

This iteration prepares CP6-A and the hardware campaigns. It does not claim new
BLE hardware PASS, new radio observations or a scientific performance ranking.
The complete [operator guide](post-v1-experimental-evaluation.md) contains metric
definitions, commands, capture steps, negative-test scope and the ordered checklist.

## A. Repository audit

- Starting HEAD: `c23e32176e4a0fce324dc93792f65c04cf7c4970`, branch `main`;
  initial `git status --short` was empty. No local AGENTS.md was found.
- `v0.7-authenticated-hybrid-secure-channel`: `5b1019e`; implementation history
  includes `b111a24`, `f723a56`, `39a8ada`, `6b2d636`.
- `v1.0`: `912fe85`; CP1 `df02ce2`, CP2 `301e34c`, CP3 `a657cae`,
  CP4 `cbb5b01`, CP5 `912fe85`; current HEAD adds the final README audit.
- Older tags retained: `v0.1-transport-poc`, `v0.2-mlkem-ondevice`,
  `v0.3-mlkem-ble-e2e`, `v0.4-pq-secure-channel`,
  `v0.5-authenticated-pq-handshake`, `v0.6-bidirectional-secure-channel`.
- Audited README, v0.7 and final v1.0 milestones; Central transport, pairing,
  hybrid/CP1/CP3/CP4 runners and common primitives; firmware Kconfig/conf/CMake,
  worker/security/timer/stack code; software/native tests, lifecycle tools,
  existing benchmarks, historical hardware logs/captures and result directories.
- v0.7 remains default `prj.conf` / `PQ_PROFILE_V07_HYBRID` with SMP disabled.
  v1.0 explicitly adds `v1_smp_l4_mlkem.conf`, selecting the authenticated SMP
  L4 layered implementation. Board: `nrf54l15dk/nrf54l15/cpuapp`.
- Current retained profiles are compared at one checkout; later shared fixes
  mean the current v0.7 build is not asserted byte-identical to its older tag.
- Existing CPU benchmarks have JSON and nanosecond timers but fixed summary
  filenames and no real BLE measurement. Existing Central timings include UI
  and/or quiet checks; DK has cumulative stack watermarks, no active independent
  crypto-operation timer. No existing per-hardware-run result schema was found.
- Existing v0.7 seven negative paths and v1.0 CP1 pre-L4/NC rejection paths are
  reused. CP3/CP4/CP5 Python/native tests cover broader failures but are not
  reclassified as hardware measurements.
- The final milestone's stale CP5/CP6 completion table was corrected to agree
  with its final release decision. Protocol behavior was not changed to resolve it.

Environment: Windows 11 25H2 build 26200; Python 3.13.3, Bleak 3.0.2,
cryptography 50.0.1, liboqs 0.15.0 / wrapper 0.16.0, pytest 9.1.1,
pytest-asyncio 1.4.0. NCS 3.0.0; Zephyr 4.0.99 / v4.0.99-ncs1; SDK 0.17.0;
west 1.2.0; mlkem-native 2.0.0 portable C. Wireshark/TShark/dumpcap 4.4.7,
Npcap 1.80; Nordic extcap 4.1.1 scripts present. Global Python has pyserial 3.5
and psutil 7.0.0; the protocol `.venv` does not need them.

Nordic capture readiness remains an operator check: no Nordic interface was
listed, and direct extcap inspection could not write its existing log outside
the workspace sandbox. Serial enumeration found ports but did not identify the
physical boards. No global tools or drivers were installed or changed.

## B. Baseline validation

Before source changes:

```text
.venv\Scripts\python.exe -m pytest -q -ra --tb=short
  --basetemp=.pytest_cp6_before_20260911 -o cache_dir=.pytest_cp6_cache
1064 passed, 1 skipped, 1 warning in 42.39s
```

The skip is the unavailable-WinRT test on a machine where WinRT is available.
The warning is the existing liboqs/wrapper version mismatch.

Both baseline builds succeeded in fresh directories:
`firmware/build_post_v1_baseline_v07_20260911` and
`firmware/build_post_v1_baseline_v10_20260911`, generating `merged.hex`.
Logs are `.pytest_post_v1_v07_baseline_build.log` and
`.pytest_post_v1_v10_baseline_build.log` (local, ignored).

Initial direct PowerShell build attempts split unquoted CMake arguments at
`prj.conf` and failed configuration. Quoted argument arrays corrected the
invocation; no firmware/config changes were made. Subsequent resource-helper
testing exposed process execution policy and UTF-16 log encoding; the helper
now uses process-local policy and the parser supports both UTF-16 and UTF-8.
Failed attempts and valid existing artifacts were retained under unique paths.

## C. Changed and created files

| File | Purpose |
|---|---|
| `.gitignore` | Keep generated post-v1 datasets separate from source commits |
| `README.md` | Short guide/report pointer and removal of the now-corrected stale-table warning |
| `docs/research/milestones/v1.0-smp-l4-mlkem-final.md` | Align checkpoint table with completed CP5 and independent evaluation |
| `docs/research/post-v1-experimental-evaluation.md` | Complete methodology, commands, operator checklist and measurement limits |
| `docs/research/post-v1-implementation-report.md` | This audit/deliverable/validation report |
| `src/central/measurement.py` | Optional ContextVar recorder, monotonic spans, payload-free API counters, callback context preservation |
| `src/central/ble_client.py` | Observe scan/connect/service boundary, MTU, API reads/writes/subscriptions and notifications |
| `src/central/phase7_auth.py` | Observe existing hybrid computation, SAS wait, FINISHED/secure transition and three authenticated RTTs |
| `src/central/v1_smp_mlkem.py` | Observe actual cold/bonded classification and pairing API interval |
| `src/central/v1_cp3.py` | Observe strict L4 attestations, existing crypto blocks, READY/FINISHED/APP_SECURE |
| `src/central/v1_cp4.py` | Observe the existing two authenticated application rounds |
| `benchmarks/post_v1/__init__.py` | Isolated experimental-tool namespace |
| `benchmarks/post_v1/run.py` | Configurable campaign using existing runners, per-run output/failure cleanup, existing negative paths |
| `benchmarks/post_v1/records.py` | Provenance/hashes, closed validation, safe serialization, derived times and API counters |
| `benchmarks/post_v1/schemas/run.schema.json` | Portable machine-readable raw hardware result contract |
| `benchmarks/post_v1/experiment.example.json` | Explicit operator setup template; rejected until completed |
| `benchmarks/post_v1/analyze.py` | Condition-stratified statistics and JSON/CSV/Markdown output |
| `benchmarks/post_v1/resources.py` | Fresh build orchestration, linker/ELF/static-symbol parsers, stack-log importer |
| `benchmarks/post_v1/pcap.py` | Optional metadata-only TShark parsing and run/window correlation |
| `scripts/build_v1_cp3.ps1` | Optional unique build/log directories, checked before pristine build |
| `scripts/capture_v1_cp3_uart.ps1` | Refuse overwriting existing UART evidence |
| `tests/test_post_v1.py` | Synthetic unit/integration fixtures for every new component and changed helper behavior |

No files under `firmware/` or `src/common/` were changed. Firmware images, raw
logs and generated resource JSON remain ignored local artifacts. No measured
latency dataset or new PCAP was created. Synthetic test data stays in pytest temp.

## D. Experimental infrastructure

One fresh client/connection per run; defaults 3 warm-ups and 30 measurements for
bonded/v0.7, 0 and 1 for controlled cold/negative runs. IDs combine scenario, UTC
time and random suffix; explicit IDs are supported for one isolated run. All
new evidence outputs use unique paths/exclusive creation. `pending.json` preserves
intent; final `run.json` retains success, errors and available partial measurements.
The first failure stops a campaign.

`perf_counter_ns` spans measure Python/API boundaries. Callbacks retain the recorder
across Bleak/WinRT threads. Serialization has a closed field contract and never
serializes protocol result/key containers, payloads or exception contents. The
usual Central CLI and human decisions remain intact.

Machine time subtracts the observed v0.7 SAS wait; bonded sessions have no expected
human wait. Cold machine time remains null because the independent DK NC-button
wait cannot be reconstructed from the PC callback. Raw/full intervals remain
available. Warm-ups, failures and negatives are excluded explicitly; incompatible
conditions receive separate summary groups, and RTT round identities stay separate.

Resources identify fresh build paths, command, source/config/ELF/map/HEX hashes,
SDK/version evidence, FLASH/RAM output, ELF sections, static symbol sizes and stack
allocation. Existing UART watermarks can be imported under the run ID.
PCAP correlation uses the same filename, explicit data Access Address, time window
and clock offset, plus tool/version/filter and input hashes. Manual capture is
the supported workflow because automatic Nordic interface readiness was not proven.

## E. Available metrics and limits

| Layer | Now collectable |
|---|---|
| Central | Scan; combined connect/service discovery; pairing API boundaries; strict SEC_INFO readiness; PK read; CT transfer; ML-KEM encapsulate; v0.7 P-256 KeyGen/ECDH/transcript/hybrid HKDF/SAS/FINISHED/traffic-KDF blocks; v1 transcript/KDF/FINISHED blocks; READY/FINISHED/APP_SECURE milestones; PC authentication wait; secure wall/machine time where valid; authenticated RTT by round |
| DK | Existing cumulative since-boot stack peaks, configured/unused stack logs; independent crypto duration remains pending |
| Project/GATT | Attempts/completions and value bytes for reads/writes, notification deliveries, subscriptions; ciphertext fragment calls; known payload/frame/round configuration; hidden Read Blob/ATT counts remain unknown |
| Build resources | FLASH/RAM region totals; text/data/bss and reported ELF sections; top static B/D symbols; worker allocation; exact image/config/source identity |
| Sniffer | Observed filtered packet count, timestamps, capture lengths, LL data-header payload lengths when decoded, raw Nordic direction flag, ATT/SMP decode presence; no automatic retransmission/airtime/energy inference |

Detailed measurement boundaries are in the operator guide. Pure DK crypto time,
exact controller-level SMP duration, complete physical radio-byte totals and energy
are not claimed. v0.7 uses 3 × 6-byte exchanges; v1.0 uses 2 × 16-byte exchanges.
This difference is retained in metadata and prevents an equal-workload RTT claim.

## F. Exact commands

The guide's **Exact operator commands** section contains complete copy-paste
PowerShell sequences, including initialization and variables, for:

1. Both-profile or individual fresh builds and resource-record selection.
2. v0.7/v1.0 flashing through the existing helper with exact image hash checks.
3. Completed setup/firmware metadata, v0.7 repeated real-SAS runs.
4. Deliberate DK/Windows bond deletion, fresh cold NC and captured cold samples.
5. Bonded repeated sessions without automatic NC acceptance.
6. Nordic extcap checks, dongle preparation, Wireshark follow/capture/save,
   per-run UART capture, exact filenames and Access Address selection.
7. Offline PCAP, cumulative stack, and JSON/CSV/Markdown analysis.
8. v1 `pre-l4-only` / `nc-reject`, and all seven existing v0.7 fault modes.

The available command families are:

```text
python -m benchmarks.post_v1.resources build --profile both
python -m benchmarks.post_v1.run --scenario v07_hybrid ...
python -m benchmarks.post_v1.run --scenario v10_cold ...
python -m benchmarks.post_v1.run --scenario v10_bonded ...
python -m benchmarks.post_v1.run --scenario v10_cold --negative pre-l4-only ...
python -m benchmarks.post_v1.run --scenario v10_cold --negative nc-reject ...
python -m benchmarks.post_v1.run --scenario v07_hybrid --negative MODE ...
python -m benchmarks.post_v1.pcap RUN_JSON CAPTURE --access-address ADDRESS --clock-offset-seconds OFFSET --output NEW_JSON
python -m benchmarks.post_v1.resources stack --run RUN_JSON --log RUN_ID_DK_LOG --output NEW_JSON
python -m benchmarks.post_v1.analyze RAW_DIRECTORY --output NEW_DIRECTORY
```

These abbreviated entries are an index, not replacements for the complete guide.
No additional v1 CP3/CP4 fault injections were added in this infrastructure-first
iteration; their hardware execution remains CP6-D work.

## G. Automated validation

Final validation on 2026-09-11:

| Check | Exact outcome |
|---|---|
| Dedicated new suite | **61 passed, 1 warning in 1.73s** |
| Complete pytest suite, final code | **1125 passed, 1 skipped, 1 warning in 55.75s** |
| `python -m compileall -q src tests benchmarks/post_v1` | PASS, exit 0 |
| `git diff --check` under repository configuration | PASS, exit 0; only existing CRLF-conversion notices |
| New untracked-file whitespace scan | PASS |
| Modified PowerShell AST parsing | PASS |
| Local documentation links | PASS |
| Fresh v0.7 resource build | PASS, `merged.hex` and parsed resource record |
| Fresh v1.0 resource build | PASS, `merged.hex` and parsed resource record |

Commands used for the final test runs:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_post_v1.py --basetemp=.pytest_cp6_dedicated_verified -o cache_dir=.pytest_cp6_cache --tb=short
.\.venv\Scripts\python.exe -m pytest -q -ra --tb=short --basetemp=.pytest_cp6_verified -o cache_dir=.pytest_cp6_cache
.\.venv\Scripts\python.exe -m compileall -q src tests benchmarks/post_v1
git diff --check
```

The final full-suite log is `.pytest_cp6_verified.log` (ignored local artifact).
Tests cover
serialization/schema/secret-field rejection, phase validity/incomplete failures,
nearest-rank percentiles and sample statistics, scenario and workload grouping,
CLI constraints, bond classification before pairing, real human callback return
values, counter logic, cross-thread observer context, resource encoding/sections/
stack parsing, PCAP correlation/fields/errors, exclusive writes and cleanup on
success/failure/cancellation. Existing real-crypto modeled v0.7/v1.0 runners are
also exercised with measurement enabled.

Earlier full regression found an inactive reconnect MTU property access against
a minimal test backend. This was corrected with lazy observation and a regression
test; no protocol checks were relaxed. A real TShark smoke check exposed boolean
direction fields (`True`/`False`); both boolean and numeric representations now parse.
The historical capture's 1,060 data records parsed successfully during a read-only
smoke check; this was parser validation, not a new experimental result or dataset.

## H. Firmware build measurements

Successful fresh resource set:
`benchmarks/results/post_v1/resources/resources-20260911T073924-a3a134673bdf/`.
Each profile contains its build log, `build-start.json` and `resources.json`;
the parent has `comparison.json`. Both generated `merged.hex`.

| Actual build measurement | v0.7 | v1.0 |
|---|---:|---:|
| FLASH region used | 225,652 B | 279,428 B |
| RAM region used | 106,048 B | 109,464 B |
| ELF text | 188,372 B | 233,856 B |
| ELF datas | 2,229 B | 2,579 B |
| ELF bss | 23,957 B | 25,684 B |
| Crypto worker allocation | 28,672 B | 28,672 B |
| New DK worker peak | measurement pending | measurement pending |

These are measured linker/ELF values from this task, not guessed sizes or copied
historical observations. v1.0 uses 53,776 B more FLASH and 3,416 B more RAM in
these matched helper builds. Regions differ because the bonded profile reserves
storage; used-byte totals, raw config and memory reports should be read together.
Both use the same helper's disabled `DEBUG_THREAD_INFO` setting and unchanged
firmware source. Static-symbol reports show, for example, the Bluetooth RX thread
stack at 1,024 B (v0.7) versus 2,200 B (v1.0), alongside unchanged 28,672 B crypto
worker and 24,576 B main stacks. Symbol sizes are build evidence, not secret values.

ELF identities:

```text
v07 4cd645ad47cb3afb0bef25953f2916f5e208c2ac71d3e7e1d70ef0cc5f30520b
v10 ab81333a626bf9749edaa09c46ee6b5069534716ae332796bbf57e3d7cf0f9ff
```

No device was flashed or physically exercised by this iteration. Existing
deprecation / `void main(void)` firmware warnings remain unchanged.

## I. Remaining manual hardware work

Follow the guide's strict 12-step ordered checklist: identify/connect both boards
and PC adapter, verify Nordic interface/UART, build and retain artifacts, flash
v0.7 and verify metadata, collect warm-up/measured/SAS/Group-A captures, run its
chosen negatives, flash v1.0 and deliberately reset bonds, collect cold NC/Group-B
samples, retain a bond for repeated bonded/Group-C sessions, run lifecycle and
pre-L4/NC-rejection blocks, review MTU/capture/clock/identity evidence, then analyze
and archive the dataset. Each hardware result is still measurement pending.

## J. Limitations

- No new hardware latency/security campaign or passive capture was performed.
- Nordic capture readiness and physical device identity require operator checks.
- Cold pure machine time lacks an independently synchronized DK decision boundary.
- Existing application workloads are different; comparisons must say so.
- No frozen-worker per-operation crypto timer; DK timing remains pending.
- Windows/Python/Bleak/FFI scheduling and measurement/logging overhead affect times.
- Service discovery, controller security transitions and hidden ATT packetization
  are not independently observable at these Python boundaries.
- Per-run connection parameters are operator metadata when not otherwise observable.
- PC/DK/sniffer timestamps are not proven synchronized; passive captures can drop
  packets, and encrypted v1.0 application payloads can remain undecodable.
- No validated energy measurement or conversion from bytes to energy is provided.
- Broader v1.0 CP3/CP4 hardware fault injections remain later CP6-D work.
- Matched results require archiving ignored data and verifying the actual flashed
  image; source hashes/metadata alone cannot remotely attest physical firmware.

## K. Git summary

No commit, push or tag was created. HEAD/branch remain unchanged. Suggested commit:

```text
feat: prepare post-v1.0 experimental measurement framework
```

Final `git diff --stat` (tracked modifications only):

```text
 .gitignore                                         |   1 +
 README.md                                          |   4 +-
 .../research/milestones/v1.0-smp-l4-mlkem-final.md    |   8 +-
 scripts/build_v1_cp3.ps1                            |  13 +-
 scripts/capture_v1_cp3_uart.ps1                     |   4 +-
 src/central/ble_client.py                           |  53 +++++---
 src/central/phase7_auth.py                          | 137 ++++++++++++---------
 src/central/v1_cp3.py                               |  22 +++-
 src/central/v1_cp4.py                               |   4 +
 src/central/v1_smp_mlkem.py                         |   4 +
 10 files changed, 163 insertions(+), 87 deletions(-)
```

Additionally **12 new untracked files** are ready for review: the eight files in
`benchmarks/post_v1/` (including schema/template), two research documents,
`src/central/measurement.py` and `tests/test_post_v1.py`. Section C explains each.
Thus the review includes 22 source/document/test files in total. Nothing was
staged. `git diff --stat` correctly excludes those new files until the user stages
them; no index modification was made merely to produce a combined statistic.
