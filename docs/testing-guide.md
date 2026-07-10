# Guida al Testing

Questa guida descrive come validare il progetto **PQ-BLE-HANDSHAKE** a tre livelli:

1. test automatici Python;
2. demo hardware reale PC central ↔ nRF54L15 DK;
3. cattura osservazionale con nRF52840 Dongle e Wireshark.

---

## Suite di test Python

La suite attiva contiene attualmente:

```text
101 passed
```

Comando per eseguire tutti i test:

```bash
python -m pytest tests/ -v
```

Su Windows PowerShell, dalla root della repo:

```powershell
.\.venv\Scripts\activate
python -m pytest tests/ -v
```

---

## Test per modulo

```bash
python -m pytest tests/test_ml_kem.py -v
python -m pytest tests/test_fragmentation.py -v
python -m pytest tests/test_sas.py -v
python -m pytest tests/test_session.py -v
python -m pytest tests/test_session_store.py -v
python -m pytest tests/test_handshake_mock.py -v
python -m pytest tests/test_mitm_simulation.py -v
python -m pytest tests/test_firmware_uuids.py -v
python -m pytest tests/test_central_transport_mock.py -v
```

---

## Copertura test

| Modulo | File test | Test attivi | Cosa verifica |
|---|---|---:|---|
| ML-KEM-768 | `test_ml_kem.py` | 6 | Key generation, encapsulation, decapsulation, roundtrip, 100 iterazioni |
| Frammentazione | `test_fragmentation.py` | 14 | Encode/decode, ordine, frammenti mancanti, duplicati, edge case, MTU variabili |
| SAS | `test_sas.py` | 12 | Derivazione SAS, confronto, determinismo, sensibilità, formato a 6 cifre |
| Canale sicuro | `test_session.py` | 22 | HKDF, AES-256-GCM, AAD, replay protection, direction separation, session binding, `msg_type` binding, tampering, IV uniqueness |
| Session Resumption | `test_session_store.py` | 23 | Session ID, save/load/delete, expiry, wire format, resume flow, usage counter |
| Handshake mock | `test_handshake_mock.py` | 2 | Pipeline completa senza BLE reale |
| MITM | `test_mitm_simulation.py` | 2 | Rilevamento MITM tramite SAS mismatch |
| Firmware base | `test_firmware_uuids.py` | 3 | Device name, SMP disabled, presenza di `bt_gatt_notify()` |
| Central transport mock | `test_central_transport_mock.py` | 17 | Fragmented read/write con mock GATT, header validation, reassembly, MTU handling |
| **Totale** |  | **101** | Test automatici attivi |

---

## Nota sui test UUID firmware

I vecchi test stretti di parsing automatico degli UUID firmware sono stati commentati perché erano legati a un formato precedente di dichiarazione degli UUID nel firmware C.

La coerenza degli UUID è attualmente verificata tramite:

1. tabella UUID nella README del firmware;
2. sorgente firmware `firmware/nrf54l15_pq_gatt_skeleton/src/main.c`;
3. ispezione GATT con nRF Connect Mobile;
4. demo hardware reale PC central ↔ nRF54L15 DK;
5. cattura Wireshark con nRF52840 Dongle.

---

## Demo hardware reale con nRF54L15 DK

La demo reale usa:

```text
PC Windows + Python/Bleak  ←── BLE/GATT ──→  nRF54L15 DK + Zephyr firmware
```

Il peripheral Python in `experimental/peripheral/` **non** è parte della demo reale.

---

## Demo PC central ↔ nRF54L15 DK

Dalla root della repo:

```bash
python -m src.central.main --device PQ-BLE-Device --demo --no-sas-confirm --log-level DEBUG
```

Output atteso:

```text
Found PQ-BLE-Device
Connected
Read public key: 1184 bytes
Encapsulate: ct=1088 bytes, ss=32 bytes
Writing ciphertext: 1088 bytes in 5 fragments
Ciphertext written
SAS derived
Session key: 32 bytes
START sent
Raw demo notification received: 57 bytes
BLE/GATT transport validation completed.
```

---

## Cattura completata con nRF52840 Dongle e Wireshark

È stata eseguita una cattura passiva con nRF52840 Dongle e Wireshark/nRF Sniffer.

Filtro principale usato:

```text
btatt
```

La cattura conferma:

- MTU exchange;
- public key long read;
- ciphertext transfer;
- control write `START`;
- final Handle Value Notification.

### Handle osservati

| Elemento GATT | Handle |
|---|---:|
| Public Key characteristic value | `0x0012` |
| Ciphertext characteristic value | `0x0014` |
| Notification CCCD | `0x0017` |
| Control characteristic value | `0x0019` |

### Public key read

Filtro utile:

```text
btatt.handle == 0x0012
```

La public key ML-KEM-768 da 1184 byte è letta tramite:

```text
ATT Read Request
ATT Read Blob Request offset 246
ATT Read Blob Request offset 492
ATT Read Blob Request offset 738
ATT Read Blob Request offset 984
```

### Ciphertext transfer

Filtro utile:

```text
btatt.handle == 0x0014 || btatt.opcode == 0x18 || btatt.opcode == 0x19
```

Il ciphertext ML-KEM da 1088 byte è frammentato a livello PQ-BLE in 5 frammenti applicativi. Su Windows/Bleak, Wireshark mostra il trasferimento come ATT Prepare Write ed Execute Write sulla characteristic `0x0014`.

### START e notification

Filtro utile:

```text
btatt.handle == 0x0019 || btatt.opcode == 0x1b
```

Il comando `START` appare come payload:

```text
53 54 41 52 54
```

La risposta del DK appare come ATT Handle Value Notification.

---

## Interpretazione della notification raw

Nel firmware attuale il DK **non** esegue ancora:

- ML-KEM decapsulation on-chip;
- HKDF/session key derivation on-chip;
- AES-256-GCM encryption on-chip.

Per questo motivo la notification finale viene trattata come **raw hardware-demo notification**.

La demo hardware valida il trasporto BLE/GATT reale, ma non ancora la cifratura end-to-end eseguita interamente sul DK.

---

## Cosa è testato

### Testato con test automatici Python

- ML-KEM-768 keygen, encapsulate, decapsulate.
- Frammentazione e riassemblaggio GATT.
- SAS Numeric Comparison.
- HKDF-SHA256.
- AES-256-GCM con AAD.
- Replay protection.
- Direction separation.
- Session binding.
- `msg_type` binding.
- Tampering detection.
- Session resumption e persistent store.
- Handshake completo mock senza BLE.
- MITM detection via SAS mismatch.
- Central transport mock con fragmented read/write.

### Testato su hardware reale

- Firmware nRF54L15 DK compilato.
- Firmware nRF54L15 DK flashato.
- BLE advertising come `PQ-BLE-Device`.
- Connessione da nRF Connect Mobile.
- Public key long read da telefono.
- Notification subscription.
- Control write con `START`.
- Connessione PC central ↔ nRF54L15 DK.
- Read public key da PC central.
- Write ciphertext in 5 frammenti GATT.
- Raw notification da 57 byte ricevuta dal PC central.
- Cattura Wireshark/nRF52840 del traffico ATT/GATT.
- Conferma packet-level di MTU, public key read, ciphertext transfer, START e notification.

---

## Cosa non è ancora testato / future work

- On-chip ML-KEM decapsulation sul nRF54L15 DK.
- On-chip HKDF/session key derivation.
- On-chip AES-256-GCM encryption.
- Persistent session store sul DK.
- Full secure-channel payload decryptato dal central a partire da ciphertext prodotto dal DK.

---

## Troubleshooting

### MTU inizialmente pari a 23

È normale che subito dopo la connessione il log mostri:

```text
Connected. MTU: 23
```

Poi, dopo la discovery/negoziazione, il central può usare un MTU più alto, ad esempio:

```text
Read public key: 1184 bytes (MTU=247)
```

### Unexpected disconnect a fine demo

Se compare dopo:

```text
BLE/GATT transport validation completed.
```

non è grave. Il programma chiude la connessione al termine della demo e il callback può loggare una disconnessione inattesa.

### InvalidTag durante la notification

Se la demo viene eseguita in modalità secure-channel normale, la notification raw del firmware può causare:

```text
cryptography.exceptions.InvalidTag
```

Usare la modalità demo:

```bash
python -m src.central.main --device PQ-BLE-Device --demo --no-sas-confirm --log-level DEBUG
```
