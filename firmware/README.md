# PQ-BLE nRF54L15 DK firmware

This is the Phase 2 experimental peripheral for PQ-BLE-HANDSHAKE.

Validated target/toolchain baseline:

- Nordic nRF54L15 DK
- `nrf54l15dk/nrf54l15/cpuapp`
- nRF Connect SDK 3.0.0
- Zephyr 4.0.99
- Zephyr SDK 0.17.0 / GCC 12.2

The firmware uses the portable-C backend of the vendored mlkem-native v2.0.0
source pinned at commit `d1b2fe782888bdb761a50336012923180be7f502`.
Files below `third_party/mlkem-native` are upstream code and must not be edited.

## Phase 2 behavior

At startup, a dedicated worker performs deterministic ML-KEM-768 KeyGen. The
coins are visibly marked `TEST ONLY - NOT FOR PRODUCTION`. The 2400-byte secret
key remains only in DK RAM: it is never logged, returned over GATT, or included
in a notification. Bluetooth starts only after KeyGen succeeds.

The generated 1184-byte public key is returned through the existing Public Key
characteristic. The old `demo_public_key.h` file remains only as historical
reference and is not included by the active firmware.

The Phase 2 exchange is:

1. the Central subscribes to Secure Data notifications;
2. the Central reads the dynamically generated public key;
3. liboqs encapsulates and produces a 1088-byte ciphertext;
4. the Central writes that ciphertext using the existing four-byte fragment
   header (`index || total || payload_length_be16`);
5. the Central writes `START`;
6. the dedicated worker decapsulates with mlkem-native;
7. the DK sends the nine-byte `PQM2` result over the unchanged Secure Data
   characteristic.

The result is a **TEST-ONLY shared-secret diagnostic checksum**. It is not
authentication, not a KDF, not cryptographic key confirmation, and not part of
the final protocol. The shared secret itself is never transmitted.

No production RNG, PSA Crypto integration, HKDF, AES-GCM, ECDH, or hybrid
handshake is implemented in this phase.

## Ciphertext state machine

The application serializes protocol and connection state with one Zephyr
mutex. Its explicit states are:

```text
EMPTY -> RECEIVING -> CT_READY -> CRYPTO_BUSY -> EMPTY
```

- A transfer must begin with fragment index zero.
- The first accepted fragment establishes `total`; an inconsistent total is
  rejected. An inconsistent new index-zero attempt also clears the stale
  partial transfer so a clean retry cannot mix fragments.
- A repeated index-zero fragment safely restarts a partial transfer because
  the frozen format has no transfer identifier.
- An identical duplicate at another index is accepted idempotently; a
  conflicting duplicate is rejected.
- `index >= total`, invalid/empty payloads, overflow, and a complete aggregate
  length other than mlkem-native's ML-KEM-768 ciphertext constant are rejected.
- A new valid index-zero fragment replaces stale `CT_READY` data.
- `START` atomically consumes `CT_READY`, copies the ciphertext into the worker
  job, clears the reassembly storage, and enters `CRYPTO_BUSY`.
- Fragments and another `START` are rejected while `CRYPTO_BUSY`.
- After completion, another `START` is rejected until a new complete
  ciphertext has arrived.
- Disconnect clears connection-specific fragment state. If crypto is still
  running, the state remains busy until the worker completes, so a new peer
  cannot interleave a transfer with the old job.

ML-KEM decapsulation has implicit rejection semantics. A structurally valid
modified ciphertext normally completes with `PQM2` success status but produces
a different checksum; the expected Central outcome is `MATCH: NO`. Status
`0x03` is reserved for a genuine local/mlkem-native API failure.

## Worker, stack, and connection lifetime

`src/mlkem_session.c` owns the public key, RAM-only secret key, deterministic
startup KeyGen, a single ciphertext job slot, decapsulation, and checksum
calculation. A semaphore wakes the worker; a second semaphore reports startup
completion to `main`; a module mutex protects job/keypair state.

The worker stack is configured at 28672 bytes. KeyGen and every Decapsulation
log the **cumulative** worker high-water mark:

- configured crypto-thread stack;
- unused stack;
- estimated cumulative peak (`configured - unused`).

The worker uses preemptible priority 14. For the NCS 3.0.0 build,
`CONFIG_NUM_PREEMPT_PRIORITIES=15`, so 14 is the lowest application
preemptible priority. Controller/MPSL and driver RX (effective priority -10),
HCI TX (-9), host RX (-8), the system workqueue (-1), and the Bluetooth long
workqueue (+10) can all preempt it. The logging thread also uses +14; millisecond-scale
logging delay while ML-KEM runs is acceptable for this experiment.

On a successful `START`, the application obtains a dedicated
`bt_conn_ref(conn)` for the asynchronous job in addition to the normal active
connection reference. A monotonically increasing connection generation and
pointer equality are both checked before notifying. Disconnect clears the
current generation, releases both owned references when still held, and marks
the job stale; decapsulation may finish, but its result is discarded. If result
handling already took ownership of the job reference, it releases that
reference after the notification attempt. The exact referenced connection is
always used, so a replacement peer can never receive an old result.

## Diagnostic format

The Secure Data notification is exactly nine bytes:

```text
offset  size  meaning
0       4     ASCII "PQM2"
4       1     status
5       4     CRC-32/IEEE, unsigned big-endian
```

Statuses are:

| Value | Meaning |
|---:|---|
| `0x00` | Decapsulation operation completed; checksum is meaningful |
| `0x01` | Keypair unavailable / initialization failure |
| `0x02` | Ciphertext incomplete |
| `0x03` | Genuine local/API decapsulation failure |
| `0x04` | Invalid protocol state |

For non-success results, the checksum field is zero. Pre-scheduling failures
are rejected at the GATT write with a distinct log and appropriate ATT error;
they do not fabricate a decapsulation result. A failure from
`bt_gatt_notify()` is logged explicitly because a failed notification cannot
report its own failure to the peer.

The firmware checks this cross-language CRC-32/IEEE vector at startup:

```text
32 zero bytes -> 0x190A55AD
```

Again, this is only a **TEST-ONLY shared-secret diagnostic checksum**.

## GATT layout

The service UUIDs and attribute order have not changed:

| Index | Attribute |
|---:|---|
| 0 | Primary Service |
| 1 | Public Key declaration |
| 2 | Public Key value (`READ`) |
| 3 | Ciphertext declaration |
| 4 | Ciphertext value (`WRITE`) |
| 5 | Secure Data declaration |
| 6 | Secure Data value (`NOTIFY`) |
| 7 | Secure Data CCCD |
| 8 | Control declaration |
| 9 | Control value (`WRITE`) |

The notifier continues to use `pq_service.attrs[6]`, guarded by a compile-time
attribute-count assertion.

| Element | UUID |
|---|---|
| Service | `12345678-1234-1234-1234-123456789abc` |
| Public Key | `12345678-1234-1234-1234-123456789abd` |
| Ciphertext | `12345678-1234-1234-1234-123456789abe` |
| Secure Data | `12345678-1234-1234-1234-123456789abf` |
| Control | `12345678-1234-1234-1234-123456789ac0` |

## Normal Phase 2 build

In nRF Connect for VS Code, use the existing build configuration whose
application directory is this `firmware` directory and whose board is
`nrf54l15dk/nrf54l15/cpuapp`. Run **Pristine Build** after pulling these source
and Kconfig changes, then flash from the Actions panel.

CLI equivalent from this directory:

```powershell
west build -b nrf54l15dk/nrf54l15/cpuapp -p always
west flash
```

`CONFIG_MAIN_STACK_SIZE=24576` is intentionally unchanged in Phase 2. Normal
KeyGen and Decapsulation execute on the dedicated 28672-byte worker stack.

## Opt-in frozen Phase 1 self-test

`src/mlkem_selftest.c` and `src/mlkem_selftest.h` are retained unchanged. The
complete deterministic KeyGen -> Encapsulation -> Decapsulation regression is
off during a normal Phase 2 boot.

To select it in nRF Connect for VS Code:

1. open the application's **Build Configuration**;
2. expand **Advanced**;
3. keep `prj.conf` as the base configuration and add
   `phase1_selftest.conf` under **Extra Kconfig fragments**;
4. save the configuration and run **Pristine Build**.

CLI equivalent:

```powershell
west build -b nrf54l15dk/nrf54l15/cpuapp -p always -- `
  '-DCONF_FILE=prj.conf' '-DEXTRA_CONF_FILE=phase1_selftest.conf'
```

Remove the extra fragment and pristine-build again to return to normal Phase 2
startup. This optional regression mode is test-only; it executes the preserved
Phase 1 test before starting the Phase 2 worker.
