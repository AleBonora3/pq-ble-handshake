# v0.8 / v1.1 session resumption

Status: **IMPLEMENTED / SOFTWARE VALIDATED; HARDWARE VALIDATION PENDING**.
See [software evidence](session-resumption-software-validation.md) and the
[future hardware procedure](session-resumption-hardware-plan.md). No hardware
measurements or real-device PASS are claimed for these profiles.

## Architecture and baseline preservation

The explicit Kconfig/CLI profiles extend frozen v0.7 and v1.0. Their historical
milestones, configurations, captures, and Post-v1.0 Comparative Evaluation data
remain unchanged. Shared source has guarded additions; the baseline behavior
and application primitives remain the reference.

| Profile | Full authentication | Resumed authentication | Application data plane |
|---|---|---|---|
| v0.8 (`0x08`) | ML-KEM-768 + ephemeral application P-256; human SAS; FINISHED | Proof of the retained authenticated hybrid ticket; mutual FINISH | Existing v0.7 worker, Secure Data writes, encrypted Data notifications |
| v1.1 (`0x11`) | Authenticated BLE SC L4 + independent ML-KEM-768; FINISHED | Restore bonded L4, then prove the separate application ticket | Existing v1.0 CP4 framing, Control writes and Data notifications |

v0.8 has SMP disabled. It does not use CP4 application framing. The unfinished
implementation initially used CP4 for both profiles; this was corrected because
it changed the experimental baseline:

| Property | v0.7 and corrected v0.8 | v1.0 and v1.1 CP4 |
|---|---|---|
| Wire | `seq_be64 || type_u8 || random_iv_12 || ciphertext || tag_16` | `PQV1 header_8 || seq_be64 || type_u8 || plaintext_len_be16 || ciphertext || tag_16` |
| AAD | `session_id_16 || sender_role_u8 || seq_be64 || type_u8` | `D || /CP4-AAD || session_id_16 || exact_header_8 || seq_be64 || type_u8 || plaintext_len_be16` |
| Nonce | New CSPRNG 12-byte IV carried in each frame | Directional IV base XOR `(zero_32 || seq_be64)`; not sent |
| Receive sequence | Strictly increasing, independently per direction; authenticate before advancing | Exact next sequence, independently per direction |
| Test application | Three `PING n` / `PONG n` rounds, 6-byte plaintext; 43 bytes per frame | Two 16-byte challenge/echo rounds; 51 bytes per frame |
| Application input | Secure Data characteristic | Control characteristic |

For v0.8, both full and resume install fresh directional keys into the existing
v0.7 worker. Its responder, AES-GCM primitive, random-IV generation, sequence
rules and application error notifications are unchanged. Resumed KDF IV outputs
are deliberately **not** installed as CP4 IV bases; each v0.8 frame still gets a
fresh random IV. The shared resumption schedule derives those outputs for both
profiles, then clears the unused v0.8 copies with the temporary key bundle.

v1.1 preserves CP4 framing and semantics, with the explicit version byte and
v1.1 domain labels. Its new service currently performs the small CP4 AES-GCM
operations in the GATT RX context, whereas the baseline performs them in its
crypto worker. Record application latency separately from handshake latency;
software validation does not establish scheduling or timing equivalence.

## Full-handshake ticket binding

All strings below are ASCII without trailing NUL. `||` is concatenation,
`H` is SHA-256, `MAC(k,m)` is HMAC-SHA256, and `LP(x)` is
`uint16_be(len(x)) || x`. `Expand(prk,label,th)` means the 32-byte RFC 5869
HKDF-Expand result with `info = label || th`, equivalently
`MAC(prk, label || th || 0x01)`.

`D8 = "PQ-BLE-HANDSHAKE-v0.8"`,
`D11 = "PQ-BLE-HANDSHAKE-v1.1"`; both are 21 bytes.

For v0.8:

```text
T8 = LP(D8) || LP(0x01) || LP(0x02) || LP(full_session_id_16)
     || LP(MLKEM_public_key_1184) || LP(MLKEM_ciphertext_1088)
     || LP(Central_SEC1_P256_public_65) || LP(Peripheral_SEC1_P256_public_65)
TH8 = H(T8)                              # T8 is 2457 bytes
IKM8 = LP(SS_MLKEM_32) || LP(SS_ECDH_32) # 68 bytes
full_PRK8 = MAC(TH8, IKM8)
key_block = HKDF-Expand(full_PRK8, D8 || "/hybrid-key-schedule", 128)
# Split into K_app, K_sas, K_finished_C, K_finished_P, each 32 bytes.
FINISHED_C_tag = MAC(K_finished_C, D8 || "/FINISHED/C" || TH8)
FINISHED_P_tag = MAC(K_finished_P, D8 || "/FINISHED/P" || TH8)
full_th8 = TH8
```

Here `full_th8` is **before FINISHED frames**. Both FINISHED tags bind that exact
transcript; SAS and the key schedule use the v0.8 domain. Full traffic keys use
the v0.8 traffic labels and K_app, as in v0.7's direction-separated construction.

For v1.1:

```text
TH0 = H(D11 || "/CP3-TRANSCRIPT" || exact_SEC_INFO_frame_12
        || MLKEM_public_key_1184 || MLKEM_ciphertext_1088 || exact_START_CP3_frame_24)
full_PRK11 = MAC(TH0, SS_MLKEM_32)
K_finished_C = Expand(full_PRK11, D11 || "/FINISHED-C", TH0)
K_finished_P = Expand(full_PRK11, D11 || "/FINISHED-P", TH0)
FINISHED_C_tag = MAC(K_finished_C, D11 || "/VERIFY-C" || TH0)
TH1 = H(TH0 || exact_FINISHED_C_frame_40)
FINISHED_P_tag = MAC(K_finished_P, D11 || "/VERIFY-P" || TH1)
full_th11 = TH2 = H(TH1 || exact_FINISHED_P_frame_40)
```

Here `full_th11` is **after both FINISHED frames**, using the existing CP3 hash
chain. The exact SEC_INFO payload must be `04 07 10 11` (authenticated SC L4,
open gate, 16-byte BLE key, profile 0x11). No SMP DHKey, LTK, or other SMP secret
is an input to the application PRK or K_RESUME.

For either profile, using its own D, full_PRK and full_th:

```text
K_RESUME = Expand(full_PRK, D || "/RESUME-ROOT", full_th)  # 32 bytes
resume_id = MAC(K_RESUME, D || "/RESUME-ID" || full_th)[0:16]
```

The Peripheral may hold a **pending** candidate root while full authentication
is incomplete; it is not an eligible ticket. v0.8 installs the ticket in
`pq_mlkem_session_commit_phase7_authenticated`; v1.1 does so in
`pq_mlkem_session_commit_v1_cp3`, after FINISHED_C verifies, FINISHED_P generation
succeeds, and `bt_gatt_notify` returns success for the current connection
generation. The Central issues/persists a ticket only after verifying
FINISHED_P. A successful send means **accepted into the local notification
queue**, not proof that the remote application received it. Lost final delivery
can desynchronize counters/tickets; authenticated full fallback recovers.

The deterministic native tests begin with public full-handshake inputs and
execute production C transcript, schedule, FINISHED and ticket functions. They
compare both roots/IDs to the real Central FullHandshake and check failed
FINISHED/send paths retain the prior ticket. v0.8 tests also compile its actual
worker commit/key-installation functions and exchange baseline-format data.

## Resume authentication and fresh key schedule

Fresh per-attempt `session_id` is 16 CSPRNG bytes; `nonce_C` and `nonce_P` are
32 CSPRNG bytes each. None is reused from the full session.

```text
C0 = profile_u8 || resume_id_16 || session_id_16 || nonce_C_32
C1 = C0 || nonce_P_32
INIT_MAC = MAC(K_RESUME, D || "/RESUME-INIT" || C0)
ACCEPT_MAC = MAC(K_RESUME, D || "/RESUME-ACCEPT" || C1)

T_resume = LP(D || "/RESUME-TRANSCRIPT") || LP(profile_u8)
           || LP(resume_id_16) || LP(session_id_16) || LP(nonce_C_32) || LP(nonce_P_32)
TH_resume = H(T_resume)                  # T_resume is exactly 148 bytes
PRK_resume = MAC(TH_resume, K_RESUME)     # HKDF-Extract(TH_resume, K_RESUME)

K_confirm_C = Expand(PRK_resume, D || "/RESUME-CONFIRM-C", TH_resume)
K_confirm_P = Expand(PRK_resume, D || "/RESUME-CONFIRM-P", TH_resume)
K_app_C2P   = Expand(PRK_resume, D || "/RESUME-APP-C2P", TH_resume)
K_app_P2C   = Expand(PRK_resume, D || "/RESUME-APP-P2C", TH_resume)
IV_C2P     = Expand(PRK_resume, D || "/RESUME-IV-C2P", TH_resume)[0:12]
IV_P2C     = Expand(PRK_resume, D || "/RESUME-IV-P2C", TH_resume)[0:12]
FINISH_C_tag = MAC(K_confirm_C, D || "/RESUME-FINISH-C" || TH_resume)
FINISH_P_tag = MAC(K_confirm_P, D || "/RESUME-FINISH-P" || TH_resume)
```

No ML-KEM, application ECDH or SAS operation occurs on a successful resume.
v1.1 must first restore authenticated bonded L4. No APP_SECURE or successful-use
increment occurs on the Peripheral until FINISH_C authenticates and FINISH_P
queues successfully; the Central waits for verified FINISH_P. Confirmation
keys and temporary PRKs are then erased. Directional sequences restart at zero
only with the fresh keys and session ID.

## Actual wire format and byte accounting

Header: `"PQRS"_4 || profile_u8 || subtype_u8 || payload_length_be16`.
The parser requires the exact profile, subtype, payload length and total size;
it rejects truncation and trailing bytes. Rejects disclose no detailed reason.

| Frame | Subtype | Payload | Header + payload |
|---|---|---|---:|
| RESUME_INIT | 0x30 | resume_id(16), session_id(16), nonce_C(32), INIT_MAC(32) | 8 + 96 = **104 B** |
| RESUME_ACCEPT | 0x31 | nonce_P(32), ACCEPT_MAC(32) | 8 + 64 = **72 B** |
| RESUME_FINISH_C | 0x32 | FINISH_C_tag(32) | 8 + 32 = **40 B** |
| RESUME_FINISH_P | 0x33 | FINISH_P_tag(32) | 8 + 32 = **40 B** |
| RESUME_REJECT | 0x34 | none | **8 B** |

Successful resume control exchange: **104 + 72 + 40 + 40 = 256 application
bytes**, before GATT/L2CAP/LL overhead. It uses two Control writes and two Data
notifications at sufficient MTU; resume requires ATT MTU >=107. Subscription,
v1.1 SEC_QUERY/SEC_INFO (8+12=20 additional application bytes), pairing, link
setup, and subsequent application data are outside that 256-byte figure.
The current v1.1 resumed runner performs one such security attestation before
INIT, so its application handshake values total 276 bytes including attestation.

The historical Python PoC's approximately 30-byte session-reuse path reused
stored session traffic material. This new design is intentionally larger: it
adds a fresh session ID, two fresh nonces, mutual authentication, explicit
bidirectional key confirmation and fresh traffic-key derivation. No frame-size
optimization or claim of equal security/cost is made.

## Ticket lifetime, replay and storage

Policy: **24 hours from full issuance, at most 100 successful resumes**. Resume
does not extend the deadline. A 30-second Peripheral resume deadline covers
INIT through final send/commit. The Central bounds notification waits and
reconnects to the original peer for full fallback on timeout or invalid proof.
A generic REJECT permits full fallback on the current clean connection. Missing,
expired, exhausted or corrupt Central tickets select full authentication.

Peripheral: one RAM-only ticket, identified by profile and resume_id. Disconnect
clears session/traffic keys and counters but preserves the ticket. A scheduled
work item expires the root even while disconnected; each protocol operation
also checks age/count. Reboot naturally loses the entire application ticket and
replay history, forcing a full handshake. Full authenticated replacement
zeroizes the prior ticket. The 100th successful resume clears the ticket/root;
the already authenticated application session may continue. Ticket expiry is
an eligibility policy, not an active application-session timeout.

The replay cache stores all authenticated INIT `(nonce_C, session_id)` pairs,
including interrupted attempts. Reuse of **either** value is rejected. Forged
MACs and malformed frames do not consume cache entries or invalidate the ticket.
Replays, failed FINISH and failed notification sends do not count as successful
resumes. No entry is evicted within the ticket lifetime. At 128 entries, further
fresh INITs are rejected until full authentication replaces the ticket; aborted
authenticated attempts can therefore force fallback before 100 successes.
This bounded availability tradeoff preserves replay safety.

Measured structures (native ABI and ARM ELF symbols): `pq_resume_ticket` **6224 B**,
`pq_resume_session` **216 B**. The 128 x (32+16) replay array is **6144 B**;
ticket metadata/padding adds 80 B. Total ticket/session storage is 6440 B,
before mutex, owner, counters, scheduled work and stack allocations. New RX
stacks are 8192 B versus 1024 B in v0.7 and 2200 B in v1.0. See the build table
for actual aggregate deltas; the cache was retained without compaction.

Central: `data/keys/resumption/<SHA256(profile_u8 || peer_UTF8)>.json`, one file
per profile and uppercased selected peer address. This directory is covered by
the existing `data/keys/*` Git ignore rule and contains no tracked ticket.
Schema 1 stores only profile, peer, resume_id, K_RESUME, creation time and success
count. **Traffic keys, IVs, confirmation keys and nonces are not persisted.**
Writes use a temporary file in the same directory, flush + fsync, then atomic
`os.replace`; replacement failure preserves the prior file and cleans the temp.
Ticket repr omits the root. Logs contain only state/reasons/counts, never roots.
Corrupt/oversized/wrong-schema/wrong-peer tickets fail closed. Expiry and count
exhaustion delete the stored ticket when accessed; there is no background
Central file-expiry daemon. Successful full authentication atomically replaces
stale/corrupt contents. The Peripheral's monotonic age/count checks remain
authoritative if Central wall time or persisted metadata rolls back.

This is **plaintext local research/PoC secret storage**, with ordinary filesystem
access controls, not Windows Credential Manager or OS secure-storage integration.
Atomic replacement is not anti-rollback protection or guaranteed physical erasure.
Concurrent Central processes are not serialized. C owned buffers use volatile
zeroization and transient PSA key destruction; Python wipes owned bytearrays
and releases AES backend objects but cannot guarantee erasure of immutable or
backend copies. Compromise of K_RESUME allows deriving recorded resumed keys
from public transcripts; symmetric resume does not add fresh asymmetric forward
secrecy. No cloud storage is used.

## v1.1 bonded identity audit (installed NCS v3.0.0)

The application ticket peer field is `address_type_u8 || address_bytes_6`, using
`bt_conn_get_dst()`, matched against `bt_foreach_bond(BT_ID_DEFAULT, ...)`.
The firmware uses only the default local advertising identity. It requires an
identity-shaped address and an existing matching bond at full issuance; resume
also requires that this bond existed at connection establishment and still
exists, plus live authenticated L4. A newly completed SMP ceremony invalidates
old application continuity and cannot resume on that cold link.

Evidence from the checked-out SDK (Zephyr `v4.0.99-ncs1`):

- `zephyr/subsys/bluetooth/host/conn.c`: `bt_conn_get_dst` returns `conn->le.dst`;
  `bt_conn_get_info` exposes that as `info.le.dst`, while `info.le.remote` uses
  `le.init_addr` or `le.resp_addr` (the on-air address).
- `host/hci_core.c`: `translate_addrs` separates resolved controller identity
  events from RPAs, or uses `bt_lookup_id_addr`; connection setup copies the
  identity into `conn->le.dst` before connected callbacks.
- `host/smp.c`: `smp_ident_addr_info` validates a received identity and updates
  `conn->le.dst` when cold-pairing identity distribution resolves an RPA.
- `include/zephyr/bluetooth/addr.h`: `bt_addr_le_is_identity` accepts public and
  static random identities; the new check rejects an unresolved private address.

Thus `bt_conn_get_info().le.dst` would be the same representation, not a stronger
replacement. Using `info.le.remote` instead would select the wrong field.
Native regression checks reject unresolved RPAs, preserve the valid ticket and
allow the original resolved bond; actual RPA rotation remains a hardware test.

The real `pq_v1_security.c` auth-info registration includes `bond_deleted` and
`pairing_complete`; both invoke `pq_resume_service_bond_changed` outside the
security lock. Native tests execute that registration and both callbacks.
Bond invalidation wipes the RAM ticket and resumed application state. Main's
security-change callback aborts the resume state on L4 loss/error; service
operations and final commit independently check live L4. BLE bond storage and
application-ticket storage remain separate, including after DK reboot.
