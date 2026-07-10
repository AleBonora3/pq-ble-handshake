# Protocollo PQ-BLE-HANDSHAKE — Specifica Formale

## 1. Introduzione

PQ-BLE-HANDSHAKE è un protocollo di handshake post-quantum a livello applicativo che opera sopra BLE GATT.

L'obiettivo è stabilire un canale applicativo cifrato e autenticato, resistente alla minaccia **store-now-decrypt-later**, senza modificare lo stack Bluetooth nativo.

Il progetto usa BLE/GATT come trasporto. La sicurezza del payload applicativo è fornita dal protocollo PQ-BLE, non dal BLE Security Manager.

---

## 1.1 Modello di riferimento

```text
+-------------------------------------------------+
| PQ-BLE-HANDSHAKE (Application Layer)            |
| - ML-KEM-768 key encapsulation                  |
| - SAS Numeric Comparison                        |
| - HKDF-SHA256 session key derivation            |
| - AES-256-GCM with AAD and replay protection    |
+-------------------------------------------------+
| GATT / ATT                                      |
| - Custom service                                |
| - Public Key READ                               |
| - Ciphertext WRITE                              |
| - Secure Data NOTIFY                            |
| - Control WRITE                                 |
+-------------------------------------------------+
| BLE Stack (L2CAP, Link Layer, Physical)         |
| - Untouched                                     |
| - SMP disabled in the DK firmware               |
+-------------------------------------------------+
```

---

## 2. Costanti e parametri

| Parametro | Valore | Note |
|---|---:|---|
| Algoritmo KEM | ML-KEM-768 | NIST FIPS 203 |
| NIST security category | 3 | Comparabile ad AES-192 |
| Public key size | 1184 byte | ML-KEM-768 |
| Ciphertext size | 1088 byte | ML-KEM-768 |
| Shared secret size | 32 byte | Input per HKDF |
| SAS digits | 6 | False accept rate: 10^-6 |
| Cipher suite | AES-256-GCM | AEAD |
| Session key size | 32 byte | AES-256 |
| Nonce/IV size | 12 byte | GCM nonce |
| GCM tag size | 16 byte | Authentication tag |
| HKDF hash | SHA-256 | RFC 5869 |
| Default MTU assumption | 512 byte | Used by tests/default configuration |
| Validated hardware MTU | 247 byte | Observed in PC Windows ↔ nRF54L15 DK demo |
| Fragment header | 4 byte | `[idx:1][total:1][len:2]` |

---

## 3. GATT service definition

### Service UUID

```text
12345678-1234-1234-1234-123456789abc
```

### Characteristics

| Name | UUID | Properties | Logical content |
|---|---|---|---|
| Public Key | `12345678-1234-1234-1234-123456789abd` | READ | Peripheral public key, 1184 byte |
| Ciphertext | `12345678-1234-1234-1234-123456789abe` | WRITE | Central ciphertext, 1088 byte |
| Secure Data | `12345678-1234-1234-1234-123456789abf` | NOTIFY | Secure data or raw hardware-demo notification |
| Control | `12345678-1234-1234-1234-123456789ac0` | WRITE | `START`, SAS confirm, resume request |

---

## 4. Protocol flow

### Phase 0 — BLE connection

```text
Peripheral: advertising as "PQ-BLE-Device"
Central: scan, discover, connect
```

The current DK firmware intentionally disables BLE SMP:

```text
CONFIG_BT_SMP=n
```

Therefore, BLE link-layer encryption is not used. Security is implemented at the application layer.

### Phase 1 — ML-KEM-768 key exchange

```text
Peripheral:
    keygen() -> (sk_A, pk_A)
    expose pk_A through GATT READ

Central:
    read pk_A
    encapsulate(pk_A) -> (ct, ss)
    write ct through GATT

Peripheral:
    receive ct
    decapsulate(sk_A, ct) -> ss
```

In the current hardware firmware, the DK exposes a 1184-byte demo/public-key buffer and receives the ciphertext, but it does not perform on-chip decapsulation yet. Full on-chip ML-KEM execution is future work.

### Phase 2 — SAS Numeric Comparison

Both peers derive:

```text
transcript = pk_A || ct || ss
commitment = SHA256(transcript)
sas = int(commitment[0:4]) mod 1_000_000
```

The 6-digit SAS must be compared by the user. A mismatch indicates a potential MITM attack.

### Phase 3 — Session key derivation

```text
session_key = HKDF-SHA256(
    ikm    = ss,
    salt   = "PQ-BLE-HANDSHAKE-v1",
    info   = "BLE-PQ-SESSION-KEY",
    length = 32
)
```

### Phase 4 — Secure channel

Payloads are protected with AES-256-GCM.

AAD:

```text
session_id (16) || sender_role (1) || seq_num (8) || msg_type (1)
```

Wire format:

```text
seq_num (8) || msg_type (1) || iv (12) || ciphertext || tag (16)
```

Security properties:

- replay protection through monotonic sequence numbers;
- direction separation through sender role binding;
- session binding through `session_id`;
- message-type binding through `msg_type`;
- integrity/authenticity through the GCM tag.

---

## 5. Fragmentation

PQ-BLE uses an application-level fragment header:

```text
idx (1) || total (1) || payload_len (2, big endian) || payload
```

Header size:

```text
4 bytes
```

With MTU 247, the useful payload per fragment is:

```text
247 - 4 = 243 bytes
```

For the validated hardware demo:

| Object | Size | Transport |
|---|---:|---|
| Public key | 1184 byte | ATT long read / Read Blob |
| Ciphertext | 1088 byte | 5 PQ-BLE fragments over GATT writes |

The public key is read through ATT long read operations. The ciphertext is fragmented by the PQ-BLE central and written to the Ciphertext characteristic.

On Windows/Bleak, Wireshark can show these writes as ATT Prepare Write / Execute Write operations.

---

## 6. Session resumption

After a successful full handshake, the central can cache:

```text
session_id -> session_key
```

On reconnect, the central can attempt:

```text
RESUME(session_id)
```

If the peer recognizes the session ID, the secure channel can be restored without repeating ML-KEM and SAS.

In the current DK firmware, full persistent on-device resume support is future work. Current hardware logs may show failed resume attempts followed by fallback to full handshake.

Production note: a production central should limit resume attempts or use shorter resume timeouts to avoid several seconds of delay when multiple stale sessions are cached.

---

## 7. Hardware validation

Validated hardware setup:

```text
PC Windows + Python/Bleak  <--- BLE/GATT --->  nRF54L15 DK
                         sniffed by
                   nRF52840 Dongle + Wireshark
```

Observed central-side result:

```text
Read public key: 1184 bytes
Encapsulate: ct=1088 bytes, ss=32 bytes
Writing ciphertext: 1088 bytes in 5 fragments
Raw demo notification received: 57 bytes
BLE/GATT transport validation completed.
```

Observed Wireshark evidence:

| Evidence | Interpretation |
|---|---|
| ATT Exchange MTU | MTU negotiation |
| ATT Read/Read Blob on handle `0x0012` | Public key long read |
| ATT Prepare Write / Execute Write on handle `0x0014` | Ciphertext transfer |
| Write on handle `0x0019` | `START` command |
| ATT Handle Value Notification | DK notification |

---

## 8. Security properties

| Property | Status |
|---|---|
| Post-quantum key establishment | Provided by ML-KEM-768 in Python implementation |
| MITM detection | SAS Numeric Comparison |
| Payload confidentiality | AES-256-GCM |
| Payload integrity | AES-256-GCM tag |
| Replay protection | Sequence number in AAD and wire format |
| Direction separation | Sender role in AAD |
| Session binding | `session_id` in AAD |
| Message type binding | `msg_type` in AAD |

---

## 9. Current limitations

- The protocol is not a Bluetooth SIG standard.
- BLE SMP is intentionally disabled in the DK firmware.
- BLE link-layer encryption is not used in the current demo.
- The DK firmware validates BLE/GATT transport but does not yet execute ML-KEM/AES-GCM on-chip.
- The final DK notification is a raw hardware-demo payload.
- Full on-chip cryptographic processing and persistent session store are future work.
