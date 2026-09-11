# Post-v1.0 Experimental and Security Evaluation

Status: CP6-A infrastructure prepared; new BLE hardware latency, negative and
radio campaigns **measurement pending**. This work is independent of the
completed v1.0 CP1–CP5 release. Build measurements are not hardware protocol
measurements. The [implementation/audit report](post-v1-implementation-report.md)
records this iteration's actual validation and changed files.

## Research question and frozen baselines

What are the practical latency, protocol overhead, resource, radio traffic and
security trade-offs between the completed v0.7 application-level ML-KEM + P-256
hybrid handshake and the completed v1.0 BLE SMP Level 4 + ML-KEM layered
architecture on the same nRF54L15 DK?

v0.7 uses unsecured BLE transport (`CONFIG_BT_SMP=n`), ML-KEM-768,
application ephemeral P-256 ECDH, a transcript-bound hybrid HKDF, interactive
application SAS, bidirectional FINISHED and directional AES-256-GCM traffic.
v1.0 establishes authenticated LE Secure Connections / Numeric Comparison /
persistent bonding at Security Mode 1 Level 4, then runs ML-KEM, transcript-bound
HKDF, FINISHED and directional AES-256-GCM above the protected GATT link.
**v1.0 never combines SMP secrets with the ML-KEM secret.**

Algorithms, transcripts, key schedules, frames, states, GATT permissions,
authentication decisions, sequence/replay checks and cleanup remain frozen.
The hooks record only names, times, lengths and outcomes; they never receive
cryptographic keys or export payloads. No firmware/common crypto source changes
are required. Never export ML-KEM/ECDH private/shared secrets, application or
FINISHED keys, LTKs or SMP DHKeys for this evaluation or for Wireshark decryption.

| Phase | Scope | This iteration |
|---|---|---|
| CP6-A | Reproducible measurement infrastructure | Implemented and software tested |
| CP6-B | Repeated hardware latency | Operator campaign prepared |
| CP6-C | Resources, project/GATT overhead, passive BLE captures | Build collector, API counters, capture methodology and offline parser |
| CP6-D | Hardware security failures | Existing validated test paths integrated; broader faults remain planned |
| CP6-E | Analysis and architectural comparison | JSON/CSV/Markdown aggregation; scientific conclusion pending data |

## Audit findings that affect the experiment

The starting checkout was clean `main`, HEAD
`c23e32176e4a0fce324dc93792f65c04cf7c4970`. Relevant tags are
`v0.7-authenticated-hybrid-secure-channel` at `5b1019e` and `v1.0` at `912fe85`.
The retained v0.7 profile at current HEAD includes later shared transport and
lifecycle work; it is not byte-identical to the historical v0.7 tag. This campaign
compares both retained profiles from the same checkout and records source/ELF
hashes. A historical-tag experiment would be a separately identified dataset.

Firmware target: `nrf54l15dk/nrf54l15/cpuapp`.
`firmware/prj.conf` plus Kconfig's default selects v0.7. The v1.0 build adds
`firmware/v1_smp_l4_mlkem.conf` with SMP SC-only, MITM, authenticated L4 gating,
bonding/settings and the real DK button UI. Both allocate a 28,672-byte crypto
worker stack. The existing build helper disables `DEBUG_THREAD_INFO` in both
profiles; this convention is retained and recorded in commands/config hashes.

Existing Central CPU benchmarks in `benchmarks/benchmark_*.py` use
`perf_counter_ns`, nearest-rank percentiles and JSON, but exclude real BLE.
Their summaries overwrite fixed historical filenames and are not suitable as
raw hardware datasets. This framework stays within `benchmarks/`, using a new
versioned schema and unique subdirectories under its existing results root.

Existing v0.7 runner wall time includes SAS and all three application rounds.
Existing v1.0 timing includes human pairing and diagnostic quiet windows.
These values cannot be reused as pure machine latency. The frozen firmware
contains **cumulative worker stack watermarks but no active per-crypto-operation
cycle timer**. Historical log times do not establish accurate crypto durations.
`crypto_timings` is empty until such a measurement is independently available;
Central crypto spans are in `phase_timings`.

The final v1 milestone had an obsolete CP5/CP6 table and completion condition
contradicting its later CP5 acceptance. These have been corrected. Prior
milestone and hardware logs remain historical evidence, outside the new samples.

## Hardware and observed environment

| Component | Audited value / role |
|---|---|
| DUT | nRF54L15 DK; historical serial `1057790967`, verify physical label |
| Central | Windows 11 25H2 build 26200; Python 3.13.3 in `.venv` |
| BLE library | Bleak 3.0.2 / WinRT |
| Crypto | liboqs 0.15.0, liboqs-python 0.16.0; cryptography 50.0.1 |
| Embedded ML-KEM | mlkem-native v2.0.0 portable C, vendored commit `d1b2fe782888bdb761a50336012923180be7f502` |
| Firmware tools | NCS 3.0.0, Zephyr 4.0.99 / v4.0.99-ncs1, Zephyr SDK 0.17.0, west 1.2.0 |
| Test tools | pytest 9.1.1, pytest-asyncio 1.4.0; host GCC available |
| Radio observer | nRF52840 USB Dongle, passive only; never the DUT |
| Packet tools | Wireshark/TShark/dumpcap 4.4.7, Npcap 1.80 |
| Nordic extcap | Personal extcap scripts report 4.1.1; dongle firmware still needs verification |

The global/system Python and protocol `.venv` are separate. The `.venv` lacks
pyserial, which the measurement CLI does not need. The existing Nordic launcher
uses `py -3`, whose audited packages include pyserial 3.5 and psutil 7.0.0.
No global package installation, driver
change, firmware flash, bond deletion or NC/SAS confirmation was performed by
this iteration. Serial port names alone do not establish which device is present.

`tshark -D` did not expose a Nordic interface in the agent environment. Direct
extcap inspection hit a denied write to the existing Nordic log directory
outside the workspace. This is an environment/sandbox limitation, not proof that
the dongle is absent or broken. Complete the checks below from a normal operator
terminal. The BLE network adapter and USBPcap interfaces are not substitutes for
the Nordic passive over-the-air interface.

## Fairness and populations

Use one DK, PC, Bluetooth adapter/driver, USB/power arrangement, room, placement,
distance, Python environment, SDK/toolchain and build settings. Record these in
the experiment metadata; hold them fixed throughout a comparison block. Record
boot state and key-pair lifetime: DK ML-KEM KeyGen occurs at boot, not per session.
Bonded application sessions still perform fresh ML-KEM encapsulation and CP3.

The default expected ATT MTU is 247. The CLI checks the actual Bleak-reported MTU
after connection and records it at later transfer/application boundaries;
changed/missing MTU prevents a successful measurement. `--expected-mtu` validates
an observation, **it does not negotiate or force an MTU**. Controller connection
interval, latency, timeout and PHY are not accurately available through the
current Python abstraction: annotate verified values in `connection_parameters`
or leave null, then corroborate with DK/capture evidence.

There are three populations: `v07_hybrid`, `v10_cold`, `v10_bonded`. The Windows
bond-state check occurs before pairing: asking for bonded on an unpaired PC fails
instead of silently creating a cold sample. Cold samples require deliberate
deletion on **both endpoints** before every run. A PC bond alone is not proof
that restoration succeeded; strict SEC_INFO and the frozen protocol must pass.

The frozen application workloads differ:

| Profile | Application payload per direction | Exchanges | Frame per direction |
|---|---:|---:|---:|
| v0.7 | 6-byte `PING n` / `PONG n` | 3 | 43 B |
| v1.0 | 16-byte random challenge | 2 | 51 B |

Do not report an equal-payload application comparison from these demos. Compare
handshake-to-APP_SECURE separately; retain round-specific RTTs and frame sizes.
Changing the demos merely to match payloads is outside this frozen-baseline task.
Quiet checks remain enabled: v1.0 waits one second after FINISHED before CP4 and
again after CP4. APP_SECURE is timed at the verified state transition before the
first quiet window; campaign success still requires all later checks to pass.

## Measurement boundaries

All offsets and spans use `time.perf_counter_ns()` relative to the run's monotonic
origin. A nearby UTC timestamp anchors manual PCAP/log correlation, not precise
clock synchronization. Nanosecond storage does not imply nanosecond accuracy.

| Measurement | Definition / precision boundary |
|---|---|
| `scan` | Python scanner API entry to return; excluded from handshake wall time |
| `connect_and_service_discovery` | Bleak connect entry to return; backend service discovery included, not independently resolved |
| reconnect spans/events | Same boundaries for Windows pairing-induced reconnect; retained separately |
| subscription readiness | Successful `start_notify` return; descriptor PDUs hidden by backend |
| `public_key_read` | One logical Bleak read entry to return, including hidden ATT Long Read/Read Blob |
| `mlkem_encapsulate` | Central encapsulate call, including Python/library overhead |
| `ciphertext_transfer` | Existing fragmented write routine; separate API write records per fragment |
| v0.7 `p256_keygen`, `p256_ecdh`, `transcript`, `hybrid_hkdf` | Existing Central computation blocks; no inferred DK time |
| v0.7 `finished_c_generate`, `finished_p_expected_generate`, `sas_compute_format`, `finished_p_verify`, `application_traffic_kdf` | Existing FINISHED generation/comparison, SAS computation/formatting, and traffic KDF blocks |
| v1 `transcript_hkdf_finished_keys` | `CentralHandshake.begin`: transcript, HKDF and FINISHED-key derivation together |
| v1 `ready_verify_finished_c` | READY parsing/hash check, FINISHED_C generation and transcript chaining together |
| v1 `finished_p_verify_app_kdf` | FINISHED_P verification and application KDF together |
| `start_to_ready_ms` | START write returned to READY consumed by runner; excludes the START write await |
| `finished_exchange_ms` | FINISHED_C write returned to verified FINISHED_P; write duration available separately |
| `security_ready_attested` | Parsed strict SEC_INFO accepted; first and second attestation both retained |
| `connection_to_l4_attested_ms` | Connection request to first strict attestation; an upper-bound API observation, not exact SMP controller time |
| `pairing_api_start/returned` | Full WinRT pairing API interval, including human and stack waits |
| `auth_prompt_ready`, `auth_decision_returned`, `interactive_wait` | PC authentication callback/input interval; v0.7 includes its prompt printing |
| `secure_wall_ms` | First connection request to Central APP_SECURE; includes any pairing reconnect |
| `secure_machine_ms` | v0.7 wall minus completed SAS wait; bonded wall; **null for cold** |
| `application_rtt_ms` | Before Central PING encryption to authenticated PONG/challenge validation; one sample per round |
| total session | `run_start` to `run_end`; includes discovery, application, quiet checks and disconnect |

Cold NC involves two human decisions. The PC callback does not observe the DK
button timestamp, which can precede or follow it. Subtracting only PC wait would
produce an unjustified machine-latency claim. Therefore cold machine time stays
null; use the human-free post-L4 spans for quantitative work until both ceremony
boundaries can be measured and aligned defensibly. Never auto-confirm NC/SAS.

No independent DK ML-KEM decapsulation/ECDH/HKDF/FINISHED durations, Windows
controller SMP start/end, ATT transaction count or on-device secure-state
timestamp are claimed. Python spans include scheduling, library/FFI overhead and
small observer overhead; enabled observers also allocate a few records. Ordinary
execution has an inactive observer. No disk writes occur inside measurement hooks.

## Result contract and analysis

Canonical raw schema: [`run.schema.json`](../../benchmarks/post_v1/schemas/run.schema.json).
The dependency-free validator implements its used type, enum, required,
additionalProperties, pattern and minimum vocabulary, plus profile, timing,
MTU, success and correlation invariants. Standard Draft 2020-12 validators can
also consume the schema. Unknown fields are rejected; result objects containing
keys are never serialized. Operator notes must also contain no secrets.

Each run records source commit/exact tag/branch/dirty status, hashes of current
Central and benchmark sources, detected Python/library versions, fixed operator
setup, flashed ELF identity, firmware/profile/scenario, build-record hash,
NCS/Zephyr/config identity, command, UTC anchor, monotonic raw events/spans,
iteration/warm-up/outcome, MTU samples, workload, raw API operations, counters,
derived times and PCAP filename. Unknown values are null or empty measurements.

```text
benchmarks/post_v1/                    implementation, metadata template, schema
benchmarks/results/post_v1/
  resources/<unique-build-id>/         build logs, startup provenance, resource JSON
  raw/<run_id>/pending.json            intent retained even if process crashes
  raw/<run_id>/central.log             INFO output carrying run_id
  raw/<run_id>/run.json                final raw result, also on handled failure/cancel
  raw/<run_id>/<run_id>-dk.log          operator UART capture
  pcaps/<run_id>.pcapng                manually saved passive capture
  summaries/<unique-analysis-id>/      summary.json, summary.csv, summary.md
```

Raw run directories, JSON, summaries and UART logs use exclusive creation.
`pending.json` is retained after success; analysis loads only `run.json`.
An unhandled process kill can leave only intent/logs; preserve and classify that
run manually as interrupted. Failures stop a campaign after saving available
observations. Do not retry under an existing run ID. Generated campaign data is
git-ignored; archive raw JSON, logs, build records and PCAPs together externally.

Defaults are 3 warm-ups + 30 measured runs for bonded and v0.7, and 0 + 1 for
cold/negative work. Counts are configurable. v0.7 still requires SAS each time.
Analyze only successful measured latency runs. Warm-ups, failed runs and negative
tests are listed as excluded, not silently removed or treated as zero time.
Retain failure rates separately. Summaries stratify scenario, software/source
identity, build/config, setup, workload, MTU and capture expectation.

Each metric reports n, missing-run count, mean, median, sample standard deviation,
min, max, nearest-rank p95, p25, p75 and IQR. Sample standard deviation is null for
n<2. Percentiles match the historical nearest-rank convention. Each application
round gets its own across-run statistic; correlated within-session RTTs are not
pooled as independent handshake samples. Summary rendering uses three decimal
places for milliseconds; this is formatting, not a claimed clock resolution.

## Protocol, resource and radio layers

`gatt_operations` records API attempts/completions and value lengths for public
key reads, ciphertext/control/data writes, subscriptions and delivered
notifications. Failed writes are attempts, not proven transmitted frames. Read
Blob is hidden; subscriptions are not counted as a known number of ATT PDUs.
Ciphertext write calls are application-fragment observations: 4-byte project
headers are included in their value lengths. Public-key application fragments
are zero (the implementation uses a long read); actual Read Blob count is null.
Cold pre-L4 probes contribute attempts and must be separated using their event
window when comparing protocol-only traffic. There are no application indications
in these frozen runners. Successful-run workload records specify application
payload and frame lengths separately; value-byte counts include project headers
and cryptographic overhead. They are **not airtime or on-air bytes**.

Resource builds use fresh unique directories and the existing build helper.
They parse actual linker FLASH/RAM region output, ELF `zephyr.stat` section sizes
(`text`, `datas`, `bss`, plus other sections), `.config` worker stack allocation,
and GNU nm static B/D symbols. Static-symbol names/sizes expose no stored values.
ELF/config/map/merged-HEX hashes and raw reports allow verification. `.bss` alone
is not RAM usage: noinit, stacks, special sections and alignment also matter.
The UART importer records existing **cumulative since-boot** stack peaks, including
startup/self-tests. It does not claim per-session peak or dynamic RAM measurement.

The offline PCAP helper records tool version, exact command/fields/display filter,
PCAP hash/run ID, clock offset/window and individual packet metadata. It reports
filtered observed packet count, timestamps, capture-record lengths, captured
lengths, dissected LL data payload lengths (when present), raw Nordic direction
flags, and counts of packets with decoded ATT/SMP. `frame.len` includes capture
encapsulation; it is not physical radio bytes. Direction flag mapping must be
confirmed in the installed dissector before labeling C→P/P→C.

Retransmissions, connection-event counts, fragmentation, L2CAP, encryption-start
and connection intervals require manual dissector review and capture-quality
assessment. This helper does not infer them from sequence bits or byte totals.
Its connection-data Access Address filter intentionally excludes advertising and
CONNECT_IND; inspect/cite those separately for setup analysis.
**Energy measurement not performed.** The sniffer does not measure DUT power.

## Exact operator commands

Run from `C:\pq_ble` in PowerShell. The following commands use existing tools;
`-ExecutionPolicy Bypass` applies only to the child process running the reviewed
local helper and does not change the global PowerShell execution policy.

### Build both profiles and select their records

```powershell
Set-Location C:\pq_ble
$python = 'C:\pq_ble\.venv\Scripts\python.exe'
$results = 'C:\pq_ble\benchmarks\results\post_v1'
& $python -m benchmarks.post_v1.resources build --profile both
if ($LASTEXITCODE -ne 0) { throw 'Resource build failed; inspect its retained logs' }
$comparison = Get-ChildItem -LiteralPath "$results\resources" -Filter comparison.json -Recurse |
    Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
$buildSet = Split-Path -Parent $comparison.FullName
$v07Record = Join-Path $buildSet 'v07\resources.json'
$v10Record = Join-Path $buildSet 'v10\resources.json'
$v07 = Get-Content -LiteralPath $v07Record -Raw | ConvertFrom-Json
$v10 = Get-Content -LiteralPath $v10Record -Raw | ConvertFrom-Json
Write-Output $v07Record
Write-Output $v10Record
```

Single-profile builds: replace `--profile both` with `--profile v07` or
`--profile v10`. The printed resource path is authoritative for that invocation.
Do not select an older comparison after a failed build.

### Flash the exact measured build

The helper restores the Nordic toolchain environment. `-Incremental` reuses the
selected build for flashing; verify the resulting image hash against the resource
record. Use a new log directory for every invocation. Do not modify firmware
sources between measurement and flashing.

v0.7:

```powershell
$flashLog = Join-Path $results ('flash-v07-' + [guid]::NewGuid().ToString('N'))
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\build_v1_cp3.ps1 `
  -Profile v07 -BuildDirectory $v07.build_directory -LogDirectory $flashLog `
  -Incremental -Flash -SerialNumber 1057790967
if ($LASTEXITCODE -ne 0) { throw 'Flash failed' }
if ((Get-FileHash -LiteralPath (Join-Path $v07.build_directory 'merged.hex')).Hash.ToLower() -ne $v07.merged_hex_sha256) {
    throw 'Image changed: regenerate its resource record before benchmarking'
}
```

v1.0:

```powershell
$flashLog = Join-Path $results ('flash-v10-' + [guid]::NewGuid().ToString('N'))
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\build_v1_cp3.ps1 `
  -Profile v1 -BuildDirectory $v10.build_directory -LogDirectory $flashLog `
  -Incremental -Flash -SerialNumber 1057790967
if ($LASTEXITCODE -ne 0) { throw 'Flash failed' }
if ((Get-FileHash -LiteralPath (Join-Path $v10.build_directory 'merged.hex')).Hash.ToLower() -ne $v10.merged_hex_sha256) {
    throw 'Image changed: regenerate its resource record before benchmarking'
}
```

Create metadata outside tracked source, edit all setup fields and identify the
flashed ELF. This records an operator assertion; Python cannot attest flash
contents remotely. The CLI refuses a template or a mismatching ELF identity.

```powershell
$meta07 = Join-Path $results 'experiment-v07.json'
$meta10 = Join-Path $results 'experiment-v10.json'
if ((Test-Path -LiteralPath $meta07) -or (Test-Path -LiteralPath $meta10)) {
    throw 'Metadata already exists; review it or choose fresh filenames'
}
Copy-Item benchmarks\post_v1\experiment.example.json -Destination $meta07
Copy-Item benchmarks\post_v1\experiment.example.json -Destination $meta10
Write-Output ('v07 ELF: ' + $v07.elf_sha256)
Write-Output ('v10 ELF: ' + $v10.elf_sha256)
notepad $meta07
notepad $meta10
```

Set `firmware_flashed_elf_sha256` from the appropriate displayed value, remove
`TEMPLATE ONLY`/`REPLACE_...` markers, and retain the same setup/placement fields
for both profiles. Pin the actual Bluetooth adapter/driver and dongle version.

### v0.7 latency

```powershell
& $python -m benchmarks.post_v1.run --scenario v07_hybrid `
  --metadata $meta07 --firmware-record $v07Record --iterations 30 --warmup 3
```

Every run requires genuine SAS comparison with the DK serial display and a human
answer. Abort on mismatch. Do not use historical `--no-sas-confirm` paths.

### v1.0 cold: deliberate reset, fresh pairing, capture

Disconnect all Central instances. While the DK is idle press **BUTTON 3**
(DK_BTN4/sw3) to clear DK bonds and verify its UART confirmation. In Windows
Settings → Bluetooth & devices, remove the matching PQ-BLE device. This deletes
only this experiment's peer association. Verify the device identity before removal.

The existing explicit Windows unpair CLI remains available when needed:

```powershell
& $python -m src.central.main --v1-smp-l4-mlkem --v1-unpair-first --v1-negative pre-l4-only
```

That command connects, deletes the PC bond and performs the existing gating test;
it does not reset DK bonds or produce a latency sample. Complete DK idle bond
reset as above, then start a fresh measured invocation:

```powershell
& $python -m benchmarks.post_v1.run --scenario v10_cold `
  --metadata $meta10 --firmware-record $v10Record --iterations 1 --warmup 0 --expect-pcap
```

The runner prints a run ID and pauses before connecting so capture/bond preparation
can finish. Compare all six digits on PC/DK, then explicitly confirm the PC and
DK **BUTTON 0** (DK_BTN1/sw0). Reject mismatches (DK BUTTON 1). Neither the
runner nor sniffer confirms the ceremony. Repeat a small configurable sample set
(for example 5), clearing both bonds before **every** cold iteration.

### v1.0 bonded: repeated automatic sessions

After one successful cold pairing, retain both bonds and the same firmware:

```powershell
& $python -m benchmarks.post_v1.run --scenario v10_bonded `
  --metadata $meta10 --firmware-record $v10Record --iterations 30 --warmup 3
```

Each iteration uses a fresh client/connection and the existing CP3/CP4 lifecycle.
The campaign stops on the first failure. Missing/stale bonds require investigation,
not relabeling as a successful bonded run. Reboot/DK restart/Central restart can
be separate setup blocks; change metadata notes and retain their own strata.

### Passive sniffer preparation and capture

Topology: `Windows Central ↔ nRF54L15 DK`, independently observed by
`nRF52840 Dongle → Nordic extcap → Wireshark → PCAPNG`.

Check the existing 4.1.1 setup from a normal operator terminal first:

```powershell
& 'C:\Program Files\Wireshark\tshark.exe' --version
& 'C:\Program Files\Wireshark\tshark.exe' -G folders
& "$env:APPDATA\Wireshark\extcap\nrf_sniffer_ble.bat" --extcap-interfaces
& 'C:\Program Files\Wireshark\tshark.exe' -D
py -3 -m pip show pyserial psutil
```

If the dongle needs preparation, use the matching Nordic **nRF52840 Dongle**
sniffer firmware, not a DK image. Put the dongle into its USB bootloader and
program the package using Nordic Programmer. Verify the selected physical device
and record firmware/package version. If dependencies are missing, repair the
interpreter used by the existing launcher; do not assume the protocol `.venv`
is its interpreter. Follow [Nordic's 4.x setup guide](https://academy.nordicsemi.com/topic/test/)
for firmware naming and extcap requirements. No automated installation is included.

1. Connect the dongle close to the fixed DUT/Central placement. Open Wireshark's
   Nordic **BLE sniffer COM interface**, enable its device toolbar and follow the
   actual DUT advertiser. Begin before connecting so connection setup is captured.
2. Start the benchmark with `--expect-pcap`; it prints the unique filename and
   waits. Start/verify capture and UART, then press Enter in the benchmark.
3. Perform the normal authentication ceremony. Keep capture running through
   FINISHED, APP_SECURE, application exchanges and disconnect.
4. Stop capture; Save As PCAPNG to the exact printed
   `benchmarks/results/post_v1/pcaps/<run_id>.pcapng`. Do not overwrite a capture.
5. In the next sample start a fresh capture. A no-pause 30-run bonded campaign
   is the latency path; a captured campaign pauses for one PCAP per run. Do not
   reuse one multi-run file under several IDs without documenting split boundaries.
6. Save operator observations, capture drops and verified data Access Address.
   Validate setup traffic and timestamps before accepting radio metrics.

Group A is complete v0.7 (ML-KEM, ECDH, SAS-related/FINISHED and encrypted app
traffic). Group B is cold v1.0 (SMP/NC, encryption transition and post-L4 protocol).
Group C is bonded v1.0 (bond restoration and fresh ML-KEM/FINISHED/app session).
Use a representative capture in each group, then extend the sample count.

For a precisely named individual capture, choose a fresh ID with this command
and use it in both benchmark/UART invocations:

```powershell
$runId = 'v10_bonded-' + (Get-Date -Format yyyyMMddTHHmmss) + '-' + [guid]::NewGuid().ToString('N').Substring(0,8)
& $python -m benchmarks.post_v1.run --scenario v10_bonded --metadata $meta10 `
  --firmware-record $v10Record --iterations 1 --warmup 0 --run-id $runId --expect-pcap
```

While the benchmark is paused, in another terminal set the printed run ID and
confirmed DK COM port, then run:

```powershell
$runId = Read-Host 'Paste the exact benchmark run_id'
$dkPort = Read-Host 'DK UART port, for example COM8 (verify device identity)'
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\capture_v1_cp3_uart.ps1 `
  -Port $dkPort -Seconds 180 `
  -Log "C:\pq_ble\benchmarks\results\post_v1\raw\$runId\$runId-dk.log"
```

This UART helper now refuses an existing file. Use a live UART terminal when
the capture's start would omit boot/keygen watermarks; record whether the DK was
reset and the full since-boot scope. UART timestamps are DK uptime, not synchronized
to PC wall time; the filename/notes carry the run ID without changing protocol bytes.

### PCAP and stack analysis

Save PCAP before invoking analysis. `pcap_available` in raw JSON is a snapshot at
run completion and can remain false when Wireshark saves afterward; the offline
analysis independently verifies the actual file and hash. Do not edit raw JSON to
claim the capture was available earlier.

```powershell
$runId = Read-Host 'Run ID to analyze'
$dataAddress = Read-Host 'DUT connection data Access Address, e.g. 0x12345678, verified in Wireshark'
$runJson = "$results\raw\$runId\run.json"
$analysisId = [guid]::NewGuid().ToString('N')
& $python -m benchmarks.post_v1.pcap $runJson "$results\pcaps\$runId.pcapng" `
  --tshark 'C:\Program Files\Wireshark\tshark.exe' --access-address $dataAddress `
  --window full --clock-offset-seconds 0 --output "$results\summaries\$runId-pcap-$analysisId.json"
& $python -m benchmarks.post_v1.resources stack --run $runJson `
  --log "$results\raw\$runId\$runId-dk.log" `
  --output "$results\summaries\$runId-stack-$analysisId.json"
& $python -m benchmarks.post_v1.analyze "$results\raw" `
  --output "$results\summaries\comparison-$analysisId"
```

Use clock offset 0 only after verifying both files use the same PC clock. Check
`--window handshake` and `--window application` separately if their endpoints
exist. Cold pairing can reconnect: inspect each connection's Access Address and
produce separately named analysis artifacts. A single-address filter does not
automatically merge multiple connections. The observed fields are documented by
Wireshark's [Nordic dissector reference](https://www.wireshark.org/docs/dfref/n/nordic_ble.html)
and [BLE Link Layer reference](https://www.wireshark.org/docs/dfref/b/btle.html).

### Selected security campaign: existing fault paths, new records

The v1 CP1 gating and NC-rejection tests already classify security denials and
reject ambiguous timeouts. Reuse them. Clear **both** bonds before each command:

```powershell
& $python -m benchmarks.post_v1.run --scenario v10_cold --metadata $meta10 `
  --firmware-record $v10Record --negative pre-l4-only --iterations 1 --warmup 0
& $python -m benchmarks.post_v1.run --scenario v10_cold --metadata $meta10 `
  --firmware-record $v10Record --negative nc-reject --iterations 1 --warmup 0
```

For `nc-reject`, type **no on the PC**. A DK-only rejection lacks the current
Central classifier's PC evidence. A PASS requires the existing test's explicit
rejection/closed-GATT checks, not mere silence. The legacy `just-works` / Windows
CONFIRM_ONLY experiment is excluded from this wrapper: it did not establish an
on-air Just Works association in the historical evidence.

v0.7 has seven existing hardware-assisted negative paths. To collect fresh,
separate records with v0.7 flashed:

```powershell
foreach ($fault in @('sas-reject','finished-c','pre-auth','c2p-tamper','c2p-replay','p2c-tamper','p2c-replay')) {
    & $python -m benchmarks.post_v1.run --scenario v07_hybrid --metadata $meta07 `
      --firmware-record $v07Record --negative $fault --iterations 1 --warmup 0
    if ($LASTEXITCODE -ne 0) { throw "Negative test failed: $fault" }
}
```

`sas-reject` is the existing explicit test-only refusal, never automatic acceptance.
Other v0.7 paths require human SAS acceptance. P→C tamper/replay mutate a received
copy locally at the PC and are labeled as receiver-local tests; they are not
injected on the air. v0.7's documented recovery behavior is retained. Each JSON
negative result records precondition, fault, expected/observed behavior, verdict,
log and tri-state rejection/invalidation/key-clear/reconnect observations.
Unobservable key clearing or internal state stays null; no keys are inspected.

Existing Python/native C tests cover malformed lengths/subtypes, duplicate START,
wrong state, invalid/duplicate FINISHED, AEAD tags, replay/sequence gaps, stale
connections/work and subscription/lifecycle failures (CP3/CP4/CP5/native suite).
They are software evidence, not new hardware PASS. Explicit hardware fault paths
for the broader v1 CP3/CP4 matrix remain a later CP6-D extension; do not improvise
protocol changes to expose them. Historical v0.7 evidence remains separate from
any newly collected runs.

## Strict campaign order and acceptance

1. Review the frozen-profile audit and run the software checks below.
2. Connect/identify nRF54L15 DK and nRF52840 Dongle; verify UART and Nordic BLE
   capture interface. Pin PC/adapter, cables, placement, SDK and interpreter.
3. Build both profiles into fresh directories and retain all resource artifacts.
4. Flash measured v0.7; verify image identity, boot profile and metadata. Capture
   its startup watermark separately if needed.
5. Collect v0.7 warm-ups and measured sessions with real SAS. Capture Group A;
   store per-run PCAP/UART under its exact ID and inspect packet visibility.
6. Run selected v0.7 negative cases if collecting fresh evidence; archive their
   independent outcomes and keep them out of latency summaries.
7. Flash measured v1.0; verify image identity/profile. Clear both bonds deliberately.
8. Capture Group B and complete genuine NC. Repeat the controlled cold sample set,
   resetting both bonds before every cold iteration.
9. Retain the final valid bond. Run 3 bonded warm-ups + 30 measured reconnects;
   collect Group C with capture pauses as needed. Record failures without substitution.
10. For lifecycle blocks, reboot DK/restart Central and keep explicit setup notes;
    do not pool changed conditions. Reset both bonds for each v1 negative case.
11. Confirm every raw outcome, MTU, source/build identity, PCAP mapping, capture
    loss and clock alignment. Resolve missing metadata before statistical comparison.
12. Import stack/capture metadata, generate a fresh summary directory and archive
    raw data plus exact inputs. Report unmatched application workloads explicitly.

Expected positive output includes a unique `run_id`, the unchanged protocol's
authenticated completion/round output, then `PASS` and `raw/<run_id>/run.json`.
A mismatch, lost link, timeout or invalid authentication produces a failed record
and nonzero exit; interrupted intent can remain in `pending.json`. No PCAP implies
radio **measurement pending**, regardless of a successful protocol run.

## Limitations and pending scientific tables

Windows scheduling and controller behavior, Python/Bleak/FFI overhead, callback
delivery latency, cold UI on two endpoints, unsynchronized DK logs, passive packet
loss, capture-clock accuracy and encrypted v1.0 payload invisibility all limit
inference. Neither byte counts nor packet counts establish airtime or energy.
Source hashes do not remotely prove which firmware is flashed; the operator
must verify its image and boot profile. Bond/state metadata and unknown connection
parameters must be reviewed before claiming matched physical conditions.

v0.7 may reveal public ML-KEM material, ECDH public values, control/FINISHED frames
and encrypted app frames to passive inspection. Observable protocol structure
does not imply secret compromise. v1.0 should still reveal timing/size/direction/
connection metadata and pre-encryption SMP, while encrypted post-SMP ATT contents
may not decode. Treat that opacity as expected link confidentiality. Never export
BLE keys or weaken GATT/security to help decoding. Manually record the actual
visibility observed in each capture; this task asserts no new capture outcome.

| Campaign metric | v0.7 | v1.0 cold | v1.0 bonded |
|---|---|---|---|
| Handshake latency | measurement pending | measurement pending | measurement pending |
| Pure machine end-to-end latency | measurement pending | unresolved DK human-wait boundary | measurement pending |
| DK crypto latency | measurement pending | measurement pending | measurement pending |
| Authenticated app RTT | measurement pending, 6 B | measurement pending, 16 B | measurement pending, 16 B |
| GATT/project overhead | measurement pending | measurement pending | measurement pending |
| Observed LL traffic/visibility | measurement pending | measurement pending | measurement pending |
| Worker stack watermark | measurement pending | measurement pending | measurement pending |
| Energy | not performed | not performed | not performed |

## Software validation commands

```powershell
& $python -m pytest -q tests/test_post_v1.py
& $python -m pytest -q -ra --tb=short --basetemp=('.pytest_cp6_' + [guid]::NewGuid().ToString('N'))
& $python -m compileall -q src tests benchmarks/post_v1
git diff --check
```

Synthetic fixtures stay in pytest temporary directories. They must never be
copied into `benchmarks/results/post_v1` or presented as experimental results.
