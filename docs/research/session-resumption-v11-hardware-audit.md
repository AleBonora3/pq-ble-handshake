# v1.1 full-handshake / first-CP4 hardware failure audit and post-fix validation

Date: 2026-09-15. Branch: `feature/session-resumption-v08-v11`.
Workspace: `C:\pq_ble`. Diagnosis was presented before firmware changes.
No commit, push, merge or tag was performed during this audit. The diagnosis and software fix were completed before flashing; the final post-audit image was then flashed and validated in the hardware campaign recorded below.

## A. Root cause and confidence

**Confirmed software defect: the successful v1.1 full handshake leaves a stale
`CIPHERTEXT_CRYPTO_BUSY` reservation. The outer Control dispatcher therefore
rejects the first CP4 PING with ATT 0x13, before attempting decryption.**

Confidence is high: actual production functions reproduced the rejection both
immediately and after advancing the test clock by 60 seconds, with the state
tuple `cp3=4 ciphertext=3 resume=3` (APP_SECURE, CRYPTO_BUSY, SECURE).
A second thread receiving FINISHED_P also reproduced the rejection after
waiting for the protocol mutex. The scoped fix makes all three cases pass.

References use final source line numbers unless marked **pre-fix**. Only five
lines were added to firmware by this audit, inside the successful CP3 commit.

### Causal chain

1. `handle_v1_cp3_start()` consumes/clears reassembly storage, then reserves it
   as `CIPHERTEXT_CRYPTO_BUSY`: [main.c:1356](../../firmware/src/main.c#L1356).
2. The crypto worker finishes the job, clears `job_active`, retires its inputs,
   and delivers its result: [mlkem_session.c:2276](../../firmware/src/mlkem_session.c#L2276).
3. `mlkem_result_ready()` routes CP3 to `v1_cp3_result_ready()` and returns:
   [main.c:2111](../../firmware/src/main.c#L2111). It never reaches the generic
   ciphertext-state cleanup at [main.c:2253](../../firmware/src/main.c#L2253).
4. Before the fix, successful `pq_mlkem_session_commit_v1_cp3()` was followed
   by APP_SECURE without releasing that transfer reservation. The only cleanup
   at the end of this callback was conditional on CP3 being IDLE, so successful
   APP_SECURE did not qualify.
5. v1.1 application subtypes 0x20/0x21 are intercepted in `write_control()`:
   [main.c:1803](../../firmware/src/main.c#L1803). The readiness expression at
   [main.c:1809](../../firmware/src/main.c#L1809) requires the ciphertext state
   not to be CRYPTO_BUSY. It fails, skips the service call, and maps `-EACCES`
   to `BT_GATT_ERR(BT_ATT_ERR_VALUE_NOT_ALLOWED)` at line 1834.

This explains why the notification-lock fix alone did not solve the failure.
An incoming CP4 write can now wait for the commit, then still fail that guard.
An arbitrary delay cannot repair a state that never transitions.

### What the supplied logs establish

The earlier UART trace proves START_CP3 and FINISHED_C were accepted and
FINISHED_C verification passed. Its next 51-byte Control write is consistent
with the Central's first CP4 PING. The latest abbreviated Central trace alone
does **not** identify the failed write: v1.1 does not emit the v1.0 per-step
START/FINISHED/PING log messages. Both START and first CP4 exceptions are
wrapped as `post-L4 exchange failed`.

Thus first CP4 is the established failing path in the inspected implementation
and the most likely explanation of the latest hardware attempt. There is no
new UART/ATT capture proving that exact attempt's failing request.

### Existing build / flash evidence

The pre-audit image remains at `firmware/build_hw_resume_v11/merged.hex`.

| Evidence | Value |
|---|---|
| Source directory in build metadata | `C:/pq_ble/firmware` |
| NCS / Zephyr | NCS 3.0.0 / Zephyr 4.0.99 |
| Board | `nrf54l15dk/nrf54l15/cpuapp` |
| Profile configuration | V11=y, RESUMPTION=y, V10 unset |
| Overlay order | `prj.conf`, `v1_smp_l4_mlkem.conf`, `v11_smp_l4_mlkem_resume.conf` |
| RX stack / crypto stack | 8192 / 28672 bytes |
| `main.c` modification UTC | 2026-09-15 16:49:27 |
| `main.c.obj` modification UTC | 2026-09-15 16:52:29 |
| ELF / merged HEX UTC | 16:52:46 / 16:52:48 |
| Generated flash batch UTC | 16:52:50 |
| HEX SHA-256 | `aa3ad29d388e7f7124a44fe12f76f6ac361c4ae95f736b51f48b5edebe1cdebb` |
| ELF SHA-256 | `8e80ae458bf0cb5885264214925ae22ae4aa438bc368ab7426e03b6692eb8172` |

Disassembly, not just timestamps, confirms the prior fixes:

- `strict_sec.0` at `0x3fe89` contains `505156311102000404071011`.
- The inlined successful FINISHED_P path calls notification at `0x12102`,
  branches through validation, and calls CP3 commit at `0x12132` without a
  protocol unlock between them. READY takes the separate unlock path at
  `0x1208c`.
- `write_control` at `0x13460` loads the ciphertext state at `0x20005b44`,
  compares it against 3 at `0x13462`, then branches to the rejection path.
  `0x13448` forms `-19` using `mvn r6, #18`.

The generated nrfutil batch names this merged HEX and requests `VERIFY_READ`.
That batch alone records a planned operation, not its result. During final
verification, the attached DK was independently compared against this image:

```powershell
C:\nordic_tools\nrfutil.exe --json --log-output stdout device fw-verify --firmware C:\pq_ble\firmware\build_hw_resume_v11\merged.hex --serial-number 001057790967 --family nrf54l --core application
```

At **2026-09-15 17:18:54 UTC**, nrfutil-device 2.10.1 reported verification of
all four segments succeeded, followed by `Firmware was verified on 1057790967`,
`result=success`, exit 0. The log is preserved at
`firmware/build_v11_audit_after_logs_20260915/v11-existing-device-verify.jsonl`.
**The connected DK therefore contained both earlier fixes and the stale-state
bug identified here at the time of diagnosis.** That step was verification only.
The corrected post-audit image was subsequently flashed and is covered by the
hardware validation section below.

## Full-handshake state machine and key ownership

| Boundary | Central | Peripheral |
|---|---|---|
| Link protection | Shared WinRT cold pairing or bonded restoration | Runtime and GATT L4 gates; security subsystem enters L4_SECURED |
| First SEC_QUERY | Requires strict v1.1 SEC_INFO | `handle_v1_control()` reports authoritative link protection |
| ML-KEM transfer | Reads 1184-byte PK; encapsulates; writes 1088-byte CT in five fragments at MTU 247 | Reassembly EMPTY -> RECEIVING -> READY |
| Second SEC_QUERY | Uses this exact SEC_INFO in transcript | Fresh security snapshot |
| START_CP3, 24 B | Sends PQV1 / version 0x11 / subtype 0x14 / 16-byte SID | CP3 IDLE -> CRYPTO_BUSY; reserves ciphertext slot; queues worker |
| READY_CP3, 40 B | Checks transcript hash | Worker decapsulates/derives confirmation keys; main arms WAIT_FINISHED_C before notifying outside protocol lock |
| FINISHED_C, 40 B | Sends subtype 0x12 after READY verification | WAIT_FINISHED_C -> FINISHED_P_BUSY; worker verifies C and derives pending app keys/root |
| FINISHED_P, 40 B | Verifies subtype 0x13 proof, derives app keys and local ticket | Queues notification with protocol lock held; commits service context; publishes APP_SECURE; clears delivery-active before unlocking |
| First PING, 51 B | Uses subtype 0x20, sequence 0, 16-byte challenge | Outer v1.1 dispatcher must see completed transfer and no active worker/delivery; service authenticates and queues PONG |
| Second round | Authenticates PONG 0, then sends PING 1 | Service commits counters after PONG queue success while locks remain held |

Central calls are in [resumption.py:158](../../src/central/resumption.py#L158)
through line 226. There is no `src/central/resume_full.py`; the full-handshake
object is [src/common/resume_full.py](../../src/common/resume_full.py).

There is no separate ticket notification in this implementation. Both peers
derive the ticket root/identifier from the authenticated full transcript;
the Central persists its ticket at `resumption.py:207`. SMP keys never enter
the ML-KEM or resume KDF. The Peripheral ticket remains RAM-only.

### What commit installs

`pq_mlkem_session_commit_v1_cp3()` at
[mlkem_session.c:2560](../../firmware/src/mlkem_session.c#L2560):

1. Requires pending keys and no active worker application session.
2. Clears pending; temporarily sets its application flag and resets its CP4
   counters/pending flags.
3. For v1.1, passes root, full transcript hash, both directional app keys and
   START's SID to `pq_resume_service_full()`.
4. Wipes its application-key copy and clears its application flag.
5. Returns the service result to the caller holding `protocol_lock`.

`pq_resume_service_full()` at
[pq_resume_service.c:141](../../firmware/src/pq_resume_service.c#L141):

1. Acquires `resume_lock`; clears old application session and both counters.
2. Requires a live protected owner and, for v1.1, a resolved identity bond.
3. Derives both full-handshake CP4 IV bases from the supplied app keys and SID.
4. Issues the ticket; on success copies the app keys and SID and sets
   `PQ_RESUME_SECURE`.
5. On failure clears the application session and returns an error.

It does not choose a new full-handshake SID, reset the main ciphertext state,
or install keys back into the v1.0 CP4 worker. Its success log appears during
the enclosing main commit, before main publishes APP_SECURE.

After v1.1 commit, the correct ownership is:

| Subsystem | State / ownership |
|---|---|
| SMP security | L4_SECURED, independently mandatory |
| Main CP3 | APP_SECURE; no active worker/delivery |
| ML-KEM worker | Application copy wiped; `v1_cp3_app_secure=false` intentionally |
| Resume service | SECURE; owns directional keys, IVs, SID, counters |
| Ciphertext transfer | **EMPTY after this fix; incorrectly CRYPTO_BUSY before it** |

For a resumed connection, main CP3 remains IDLE and the resume service becomes
SECURE after INIT/ACCEPT/FINISH_C/FINISH_P. The dispatcher deliberately accepts
both main IDLE and APP_SECURE; service state is authoritative for its CP4 keys.

Cold L4 can precede identity/bond completion. `pq_resume_service_full()` can
fail its bond check even after FINISHED_P was queued. The existing caller then
fails closed; this is a separate possible failure, not evidence of missing
CP4 keys after a successful `RES full authenticated` marker.

## B. Why the previous tests missed this

- [test_v1_cp3.py:340](../../tests/test_v1_cp3.py#L340) compiles only the V10
  profile. Its lifecycle tests call `handle_v1_control`, not outer
  `write_control`, and therefore never execute the v1.1 guard.
- [native_resume/service.c:55](../../tests/native_resume/service.c#L55) calls
  the service directly. Its v1.1 full helper at line 129 calls service-full
  directly rather than the production worker commit and main callback.
- The existing full C/Python test previously exercised full-handshake
  application traffic only for v0.8; v1.1 traffic was exercised after reconnect
  and resumption. The missing full-v1.1 application check is now included.
- [test_resume_central.py:188](../../tests/test_resume_central.py#L188) installs
  peer keys before delivering FINISHED_P and has no transfer reservation.
- The old native lock adapter is just a depth counter. Its notification call
  is synchronous and selected callbacks reenter the same thread. It cannot
  reproduce a separately scheduled Zephyr RX handler blocking on a mutex.

The initial dirty diff also removed CP4/CP5 cancellation injections from the
native notification stub. The pre-fix targeted run recorded five failing CP4
notification-time scenarios. Those hooks were restored, preserving the new
READY/FINISHED/error depth checks.

## C. All relevant ATT 0x13 sources

Line numbers in this table are **pre-fix** (add five to main.c lines after
1481). The repository-wide search found all explicit VALUE_NOT_ALLOWED returns
in `main.c`; the primitive/service modules return errno-style failures mapped
by the dispatcher.

| Path | Exact rejecting condition | Can explain this run? |
|---|---|---|
| `write_control`, 1804-1829 | Owner mismatch, notifications disabled, non-null crypto owner, CT busy, incompatible phase7 state, CP2 active, CP3 worker/delivery active, main CP3 neither IDLE nor APP_SECURE, or nonzero service result | **CT busy is sufficient even after successful commit** |
| `pq_resume_service_control`, 203, 240-253, mapped at 1829 | Wrong owner, missing L4, input MTU too small; service not SECURE; RX/TX exhausted; parse/profile/direction/length/sequence failure; AES-GCM/tag failure; wrong PING type or challenge length; encrypt/PONG queue failure | Valid alternatives if service is reached; stale CT prevents that here |
| `write_control`, 1831-1839 | Resume service busy on a non-PQRS/non-app message; aborts service | Extra full/control traffic after secure or during resume, not ordinary cold CP3 |
| `write_control`, 1848-1849 | Frame shorter than 8 or subtype not SEC_QUERY/START_CP3/FINISHED_C after app routing | Malformed or unsupported control |
| `handle_v1_control`, 1691-1693 | Parser rejects magic, profile version, declared/actual/subtype length | Possible at START or FINISHED; previous UART accepted both |
| `handle_v1_cp3_start`, 1333-1335 | MTU <43, ciphertext not READY, keypair unavailable | Excluded by successful START marker; MTU 247 is sufficient |
| `handle_v1_cp3_start`, 1345-1349 | Submit returns anything except 0/-EBUSY: bad CT pointer/length, strict SEC_INFO mismatch, malformed/wrong START | Original hardcoded SEC_INFO bug; fixed in inspected ELF |
| `handle_v1_cp3_finished_c`, 1367-1375 | Not WAIT_FINISHED_C, worker active, or submit fails (invalid frame, active/pending worker, no pending confirmation) | Possible generally; previous UART shows successful verification |
| `handle_v1_cp4`, 1251-1257 | Bad owner/generation/CP3 state/L4/subscription/MTU, active worker/delivery/CP2, crypto owner, or rejected worker submit | v1.0 path, bypassed for correctly routed v1.1 CP4 |
| `pq_mlkem_session_submit_v1_cp4`, 2584-2588, mapped above | Invalid direction/frame/PING/16-byte size; no worker app keys; active/pending job; pending CP4; wrong/exhausted sequence | v1.1 deliberately has no worker app keys; must use service path |
| `read_public_key`, 429 | Resume service non-IDLE | Earlier read succeeded |
| `write_ciphertext`, 465/542/559/582 | Resume service non-IDLE; first fragment not zero; changed total; conflicting duplicate | Earlier transfer succeeded |
| `write_control`, 1874 | Non-PQV1 legacy control in v1 profile | Not valid 24/40/51-byte messages |

Size alone does not select a characteristic or handler. Valid 24-byte START,
40-byte FINISHED_C and 51-byte CP4 all arrive on Control (service attr 9);
notifications use Secure Data (attr 6). v1.1 Secure Data writes return Write
Not Permitted at main.c:649. Ciphertext writes use the fragment handler.
The remaining legacy 0x13 returns (pre-fix lines 925, 1029, 1042, 1069, 1121,
1172, 1547, 1845, 1914, 1946, 1982) belong to legacy/CP2/v0.8 paths which the
v1.1 whitelist and early returns exclude for this exchange.

L4 denial is ATT 0x05; bad offset is 0x07; CCC errors, protocol-busy errors and
malformed-fragment length errors use other codes. They must not be conflated
with the reported decimal 19. Likewise FINISHED_P's subtype 0x13 is unrelated
to ATT error 0x13. `Could not stop notifications: 21` occurs during cleanup and
does not localize the original write failure.

## D. v1.0 / v1.1 delta

| Behavior | v1.0 | v1.1 |
|---|---|---|
| CP4 owner | ML-KEM session worker | Resume service for both full and resumed sessions |
| Ciphertext reservation after CP3, before fix | Left busy; CP4 handler does not test it | Left busy; added outer dispatch guard tests it |
| Full keys | Retained in worker; worker app flag true | Transferred to service; worker copy erased |
| Full SID / counters | START SID, counters zero | Same SID copied into service, its counters zero |
| Full IV derivation | CP4 HKDF-expand labels | Same algorithm with v1.1 domain |
| Resumed IVs | No resumption | Fresh resume KDF outputs |
| Central post-FINISHED_P | Quiet-window extra-notification check, default 1 s | Verify, save ticket, construct app and send PING immediately |
| Wire | PQV1 / version and SEC_INFO profile 0x10 | PQV1 / version and SEC_INFO profile 0x11; PQRS for resume |
| Application characteristic | Control write / Secure Data notify | Same |

The v1.0 quiet window is at `src/central/v1_cp3.py:165`; CP4 begins through its
application callback at line 178. v1.1 has a separate runner and does not call
`run_v1_cp4()`: `resumption.py:202-225` goes straight from verified FINISHED_P
through ticket persistence to CP4. Immediate traffic after authenticated
FINISHED_P is legitimate; a delay is not a protocol synchronization mechanism.

Constants are coherent after the pre-existing strict SEC_INFO correction:
`pq_profile.h` selects `PQ_APP_VERSION=0x11` and
`PQ_APP_DOMAIN="PQ-BLE-HANDSHAKE-v1.1"`; `pq_v1_frame.h` maps both version and
profile ID to it. Python `FullHandshake` and `CentralApplication` use the same
profile/domain. The application frame is 8-byte header + 8-byte sequence +
1-byte type + 2-byte plaintext length + 16-byte challenge + 16-byte tag = 51 B.
There is no special `len == 51` acceptance shortcut bypassing parsing/AEAD.

## E. Minimal safe fix and notification reasoning

At [main.c:1482](../../firmware/src/main.c#L1482), only after successful commit:

```c
#if defined(CONFIG_PQ_PROFILE_V11_SMP_L4_MLKEM_RESUME)
    ciphertext_state = CIPHERTEXT_EMPTY;
#endif
    v1_cp3_state = V1_CP3_APP_SECURE;
```

Both assignments occur with `protocol_lock` held. Delivery-active clears before
unlock. Existing error paths and all dispatcher checks remain intact. The CT
bytes were already consumed/cleared; the worker's copy was retired before the
callback. This releases a completed reservation, not a running operation.

The installed NCS `zephyr/subsys/bluetooth/host/gatt.c:2541-2555` allocates a
notification PDU, copies the bytes, and passes it to `bt_att_send()`. Queue
success does not acknowledge peer processing. `bt_gatt_notify()` supplies no
application completion callback. The API separately supports completion
callbacks in system-workqueue context; see the
[Zephyr GATT notification documentation](https://docs.zephyrproject.org/apidoc/latest/group__bt__gatt__server.html).
The local NCS source, rather than the current online version, was used to
verify this build's implementation.

FINISHED_P can reach the Central before the worker finishes committing. With
the existing lock fix, the RX handler then waits for protocol state and keys
to become coherent. The new assignment completes that coherence. No sleep,
extra notification, weakened state guard, L4 bypass or key-schedule change is
needed. CP4 service PONG queueing and counter advancement also occur under
protocol/resume locks, so the next request observes the committed counters.

## F. Regression coverage and limits

New [test_v11_full_lifecycle.py](../../tests/test_v11_full_lifecycle.py) compiles
the entire production Control dispatcher, actual CP3 handlers/worker commit,
real ML-KEM and the actual resume service. It adapts only the platform APIs;
unreachable legacy paths are declared and the legacy CP4 worker submission
aborts if accidentally used. It does not copy the readiness predicate.

The Windows thread/event adapter uses real blocking locks. For the concurrent
case, FINISHED_P queueing waits until a second RX thread has reached the
protocol mutex, then verifies that RX has not completed before allowing the
worker to commit. Events control the schedule; no timing sleeps are used.

Scenarios: immediate/delayed/concurrent first PING; two authenticated rounds;
pre-commit and pre-L4 rejection; failed FINISHED_P queueing; failed bond-gated
commit; bad version/direction/sequence/tag; replay; subscription loss; L4 loss.
The test checks key transfer, erased worker keys, service SID and counters.

The existing service interoperability test now also encrypts and authenticates
two v1.1 full-handshake CP4 rounds with Python before disconnect/resumption.
Existing CP4/CP5 notification-time cancellation hooks were restored.

These tests do not emulate the radio, controller scheduling, WinRT, PSA Cracen
timing or Bluetooth buffer exhaustion. The new concurrency test proves the
selected application-lock interleaving, not every possible Zephyr schedule.

## G. Hardware retest plan and execution

Use the newly built v1.1 artifact recorded in the validation section. Record
its hash, the exact build/flash command, target serial number, and successful
program/read-verification output. Do not substitute a stale IDE build folder.

1. **Cold full:** deliberately clear bonds on both peers for this test and use
   `--v11-smp-l4-mlkem-resume --resume-full`. Observe all four pre-L4 denials,
   Numeric Comparison, paired=True, authenticated encryption and strict
   `level=L4 SC=YES authenticated=YES key=16 gate=OPEN profile=0x11`.
2. **UART handshake:** `Control write: len=24`; START_CP3 accepted; CP3 crypto
   PASS; READY_CP3 queued / WAIT_FINISHED_C; `Control write: len=40`;
   FINISHED_C accepted and verification PASS; `RES full authenticated: ticket
   issued in RAM; profile=0x11; APP_SECURE`; FINISHED_P queued; main APP_SECURE.
3. **Application:** two `Control write: len=51` requests must complete with
   authenticated PONGs, sequence 0 then 1. Existing Central success marker:
   `Profile 0x11 full: APP_SECURE, 2 authenticated round trips; ticket=True`.
   The v1.1 service does not currently emit v1.0's per-PONG UART success line.
4. **Bonded resume, no DK reset:** run without `--resume-full`. Expect restored
   L4, `RES mutual confirmation: fresh keys/IVs; APP_SECURE; no ML-KEM/P-256/SAS`,
   and `Profile 0x11 resume: APP_SECURE, 2 authenticated round trips; ticket=True`.
5. **DK reset, bond retained:** Central's persisted ticket meets an empty DK
   ticket store. Expect a generic RESUME_REJECT, controlled full ML-KEM fallback
   over L4, ticket reissue, and two authenticated CP4 rounds.
6. **Negative checks:** pre-L4 resume denial; forged/replayed messages;
   wrong-version/direction/sequence/tag; subscription loss and disconnect/L4
   invalidation. Verify no accepted unauthenticated PING and no retained traffic
   keys after failure. Repeat the existing baseline profile checks.

`Control write: len=51` is logged before mutex acquisition, so it may precede
the commit logs even after the fix. Do not infer acceptance order from that
entry alone. Successful ATT response and authenticated PONG are decisive.
For precise failure localization, the existing measurement recorder captures
control-write size/success and `start_sent`, `ready_received`,
`finished_c_sent`, `finished_p_verified`, `app_secure`, `application_request`
events; it is inactive in ordinary CLI logs. An ATT capture can alternatively
identify the failing characteristic handle and frame header without key logs.


## H. Post-fix hardware validation — COMPLETE

The corrected v1.1 image was flashed to the nRF54L15 DK and the core lifecycle
was re-run from a clean cold state. The final hardware result is **PASS**.

### H.1 Cold full handshake and first CP4

After deleting stale bonds and starting from a real cold connection, the Central
observed:

```text
Windows bond state: paired=False
Scenario: cold pairing
Pre-L4 gating: all 4 PQ GATT operations denied
SMP pairing complete: PAIRED
v1.1 security: level=L4 SC=YES authenticated=YES key=16 gate=OPEN profile=0x11
Profile 0x11 full: APP_SECURE, 2 authenticated round trips; ticket=True
v1.1 cold full: APP_SECURE, 2 authenticated round trips; ticket saved=True
```

The DK confirmed:

```text
START_CP3 accepted: L4_SECURED -> CP3_CRYPTO_BUSY
v1 CP3 decapsulation + transcript + HKDF: PASS
READY_CP3 queued: 40 B; WAIT_FINISHED_C
FINISHED_C accepted: WAIT_FINISHED_C -> FINISHED_P_BUSY
FINISHED_C verification on DK: PASS
RES full authenticated: ticket issued in RAM; profile=0x11; APP_SECURE
FINISHED_P queued: 40 B
Application state: APP_SECURE
Control write: len=51
Control write: len=51
```

This closes the original first-CP4 regression on real hardware. A `Control
write: len=51` entry may precede later commit log lines because that entry is
printed before the RX path acquires `protocol_lock`; the successful ATT write
and authenticated PONG are the decisive acceptance evidence.

The cumulative crypto-worker high-water observed in the full v1.1 run was
**24,296 B** of the configured **28,672 B** stack, leaving **4,376 B** unused.
This is a cumulative boot high-water and is not attributed to resumption alone.

### H.2 Repeated bonded resume

Two consecutive reconnects restored authenticated L4 from the BLE bond and
completed application resumption without a new Numeric Comparison or ML-KEM.

Peripheral evidence:

```text
RES mutual confirmation: fresh keys/IVs; APP_SECURE; no ML-KEM/P-256/SAS; count=1
RES mutual confirmation: fresh keys/IVs; APP_SECURE; no ML-KEM/P-256/SAS; count=2
```

Each resumed session completed two authenticated 51-byte CP4 challenge/response
rounds.

### H.3 DK reboot with BLE bond retained

After resetting the DK:

1. the persistent BLE bond restored authenticated L4;
2. the RAM-only application ticket was absent;
3. `RESUME_INIT` was rejected locally;
4. the Central automatically fell back to full ML-KEM/CP3 over the already
   authenticated L4 link;
5. a new application ticket was issued;
6. two authenticated CP4 round trips passed;
7. the following reconnect resumed successfully with the new ticket.

Central markers included:

```text
v1.1 bonded full: APP_SECURE, 2 authenticated round trips; ticket saved=True
Full-handshake fallback: RESUME_REJECT
```

This confirms experimentally that **BLE bond != application resume ticket**.

### H.4 Negative resume checks

The final v1.1 image passed the resume authentication/replay negatives on real
hardware:

| Negative | Central / Peripheral result | Outcome |
|---|---|---|
| pre-L4 `RESUME_INIT` | denied by protected GATT gate | **PASS** |
| bad INIT MAC | `bad INIT MAC explicitly rejected`; local generic reason 5 | **PASS** |
| duplicate/replayed INIT | `duplicate INIT explicitly rejected`; local reason 6 | **PASS** |
| tampered ACCEPT | Central rejects ACCEPT; `FINISH_C` not sent | **PASS** |
| replayed old `FINISH_C` | rejected in a fresh transcript; local reason 5 | **PASS** |

A normal bonded resume was executed after every negative. All recoveries
returned to `APP_SECURE` and completed two authenticated CP4 rounds.

The successful-use counter advanced only for successful mutually authenticated
resumes. Failed INIT/ACCEPT/FINISH attempts did not consume the ticket's
successful-resume budget.

### H.5 Bond deletion / new pairing

The BLE bond was deleted on both Windows and the DK and the DK was reset. The
next connection was correctly classified as cold:

```text
Windows bond state: paired=False
Scenario: cold pairing
Pre-L4 gating: all 4 PQ GATT operations denied
```

A new Numeric Comparison (`778618` in the recorded run) was required. After the
new L4 association, the Central performed full ML-KEM/CP3, issued a new ticket
and completed two authenticated CP4 round trips.

Central reported:

```text
Profile 0x11 full: APP_SECURE, 2 authenticated round trips; ticket=True
v1.1 cold full: APP_SECURE, 2 authenticated round trips; ticket saved=True
Full-handshake fallback: NO_TICKET
```

The immediately following connection used the new bond and ticket and completed
a normal resume with Peripheral `count=1`.

This validates the intended security boundary: an application ticket cannot be
used to bypass a new SMP L4 pairing after bond deletion.

### H.6 Final hardware classification

```text
v1.1 CORE HARDWARE VALIDATION
===========================================
Cold SMP L4 pairing                     PASS
Pre-L4 fail-closed gating               PASS
Full ML-KEM-768                         PASS
CP3 mutual confirmation                 PASS
Full-session ticket issuance            PASS
CP4 bidirectional authenticated data    PASS
Bonded resumption                       PASS
Repeated bonded resumption              PASS
DK reboot / RAM-ticket loss             PASS
Resume rejection after reboot           PASS
Automatic full ML-KEM fallback          PASS
Resume after fallback                   PASS
Bad INIT MAC                            PASS
Replay INIT                             PASS
Tampered ACCEPT                         PASS
Replay FINISH_C                         PASS
Ticket retention after failures         PASS
Failed attempts do not consume count    PASS
BLE bond deletion / new pairing         PASS
App resume cannot bypass SMP L4         PASS
```

The recurring Central cleanup warning `Could not stop notifications: 21`
appeared only after the authenticated application exchanges had already
succeeded and is classified as a WinRT cleanup/disconnection warning, not an
handshake or application-security failure.

### H.7 Deferred extended validation

The following policy-limit tests are intentionally not part of the completed
core hardware campaign:

- **100 successful resumes** on one ticket;
- **real 24-hour TTL expiry**.

They remain covered in software/native validation and will be executed later as
extended/long-duration hardware tests.

## Validation results

The pre-fix production integration reproduction failed immediate, delayed and
concurrent first CP4; four fail-closed cases passed. After the firmware fix,
the targeted CP3/CP4/CP5/resumption suite passed **502 tests**.

| Check | Result |
|---|---|
| Targeted CP3/CP4/CP5/resumption tests | 502 passed |
| Full pytest suite, including the added Python full-CP4 interoperability check | 1290 passed, 1 skipped |
| `python -m compileall -q src tests benchmarks` | Exit 0 |
| `git diff --check` | Exit 0 |
| Four fresh NCS builds | All exit 0; merged HEX files produced |
| Attached DK's existing firmware versus preserved pre-audit HEX | nrfutil fw-verify: four segments matched, exit 0 |
| Final corrected v1.1 image, post-audit hardware campaign | **Core lifecycle PASS**: cold full, CP4, bonded resume, reboot fallback, negatives, bond deletion/new pairing |

The skip is the non-Windows WinRT-unavailable case, on this Windows host.
The existing liboqs 0.15.0 / liboqs-python 0.16.0 version warning remains.
NCS also reports existing deprecation warnings such as BT_BUF_ACL_RX_COUNT;
these did not fail compilation.

### Resource and artifact comparison

| Profile | Final FLASH (B) | Final RAM (B) | Evidence of no audit regression |
|---|---:|---:|---|
| v0.7 | 225652 | 106048 | Merged HEX matches the recorded baseline hash |
| v1.0 | 279544 | 109464 | Fresh before/after-audit merged HEX files are byte-identical |
| v0.8 | 229480 | 119792 | Merged HEX matches both existing hardware artifact and recorded baseline hash |
| v1.1 | 283488 | 122056 | +4 bytes FLASH/code, 0 RAM versus inspected pre-audit hardware image |

The pre-existing dirty notification-ordering change also applies to v1.0.
Its current 279544-byte FLASH usage is 116 bytes above the repository's older
279428-byte measurement. This difference was already present in the fresh
**before-audit** build. This audit's guarded change introduces no additional
v1.0 difference; it does not claim the incoming dirty tree equals the frozen
historical binary.

Fresh build directories are
`firmware/build_v11_audit_after_{v07,v10,v08,v11}_20260915`.
Logs are in `firmware/build_v11_audit_after_logs_20260915`.
The independent before-audit v1.0 build is
`firmware/build_v11_audit_before_v10_20260915`.

| Merged HEX | SHA-256 |
|---|---|
| v0.7 | `a76f42eda90eaf75656d6db54fee0ac854083a30a425caca5f77f48f0e9736c1` |
| v1.0, both before and after this fix | `6870b5d5f83e55fb5f754d34eea5d1437af46f5d1168a0a78e0232e871df9589` |
| v0.8 | `9833fed5876c3f3d4f4420c738e2c87a76dd8d4fe8b9f46c811b8ede2c75ce42` |
| **New v1.1** | `1608b743e80348d4c922f5325b792c0c721c2a090540d5c3b83e395af0fd2ea6` |

The new v1.1 ELF calls commit at `0x12132`, clears ciphertext state at `0x1213c`,
then stores APP_SECURE at `0x12140`. The notification lock fix remains present.
The original `build_hw_resume_v11` image was not overwritten.

Reproduction commands used the workspace `.venv/Scripts/python.exe`:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_v11_full_lifecycle.py tests/test_v1_cp3.py tests/test_v1_cp4.py tests/test_v1_cp5.py tests/test_resume_service.py tests/test_resume_central.py tests/test_resumption.py tests/test_resume_wiring.py tests/test_resume_native.py --basetemp=.pytest_v11_audit_targeted_20260915_01 -o cache_dir=.pytest_v11_audit_cache --tb=short
.\.venv\Scripts\python.exe -m pytest -q --basetemp=.pytest_v11_audit_full_20260915_01 -o cache_dir=.pytest_v11_audit_cache --tb=short
.\.venv\Scripts\python.exe -m compileall -q src tests benchmarks
git diff --check
```

Each build used `scripts/build_v1_cp3.ps1` with `-Profile` respectively `v07`,
`v1`, `v08`, `v11`, its fresh `-BuildDirectory`, and the log directory above.
No `-Flash` was passed. For example:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build_v1_cp3.ps1 -Profile v11 -BuildDirectory C:\pq_ble\firmware\build_v11_audit_after_v11_20260915 -LogDirectory C:\pq_ble\firmware\build_v11_audit_after_logs_20260915
```

### Final file changes

Changes made by this audit:

- `firmware/src/main.c`: five added lines; v1.1-only consumed-CT release after
  successful service commit, before APP_SECURE and protocol unlock.
- `tests/native_v1/cp3_lifecycle.c`: restored the existing CP4/CP5 notification
  cancellation hooks removed by the incoming diff; retained CP3 depth checks.
- `tests/test_resume_service.py`: nine added lines checking Python/C full-v1.1
  CP4 traffic before resumption.
- `tests/test_v11_full_lifecycle.py` and
  `tests/native_resume/v11_full_lifecycle.c`: new production integration and
  concurrent-receive regression tests.
- This audit report.

`firmware/src/mlkem_session.c` remains modified by the incoming profile-aware
SEC_INFO fix; this audit made no further changes to that file. The larger
`git diff` in main.c and the old harness includes the user's earlier fixes.
