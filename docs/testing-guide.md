# Guida al Testing

Questa guida descrive come validare il progetto **PQ-BLE-HANDSHAKE** a tre livelli:

1. test automatici Python;
2. demo hardware reale PC central ↔ nRF54L15 DK;
3. cattura osservazionale con nRF52840 Dongle e Wireshark.

---

## Suite di test Python

Il risultato corrente verificato è registrato in `docs/test-results.md`.

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
python -m pytest tests/test_phase2_diagnostic.py -v
python -m pytest tests/test_phase2_e2e.py -v
python -m pytest tests/test_phase5_primitives.py -v
python -m pytest tests/test_phase5_auth_mock.py -v
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
| Firmware base | `test_firmware_uuids.py` | 9 | Parità UUID firmware/Python, device name, SMP disabled, presenza di `bt_gatt_notify()` |
| Central transport mock | `test_central_transport_mock.py` | 18 | Fragmented read/write con mock GATT, reassembly, MTU handling e cap frame a 512 byte |
| Phase 2 diagnostic | `test_phase2_diagnostic.py` | 7 | Formato esatto `PQM2`, CRC big-endian e vettore noto `0x190A55AD` |
| Phase 2 E2E mock | `test_phase2_e2e.py` | 16 | Sequenza isolata, callback cross-thread, bypass completo, timeout/mismatch/status/malformed response |
| Phase 5 primitives | `test_phase5_primitives.py` | 19 | Transcript e hash KAT, key schedule, SAS, FINISHED, framing e stato fuori ordine |
| Phase 5 E2E/negative mock | `test_phase5_auth_mock.py` | 12 | Flusso positivo, rifiuto SAS, hook FINISHED/transcript, blocco DATA_REQUEST ed exit status CLI |

---

## Nota sui test UUID firmware

Il parser dei test normalizza ora le continuazioni di riga del preprocessore C
usate da `firmware/src/main.c`. Sei test attivi confrontano automaticamente i
cinque UUID con `src/common/constants.py` e verificano che il set sia completo;
altri tre controllano device name, SMP disabilitato e `bt_gatt_notify()`.
L'ispezione nRF Connect e la cattura Wireshark restano verifiche hardware
separate.

---

## Demo hardware reale con nRF54L15 DK

La demo reale usa:

```text
PC Windows + Python/Bleak  ←── BLE/GATT ──→  nRF54L15 DK + Zephyr firmware
```

Il peripheral Python in `experimental/peripheral/` **non** è parte della demo reale.

---

## Phase 2 E2E: PC central ↔ nRF54L15 DK

Flashare prima il firmware Phase 2 compilato per
`nrf54l15dk/nrf54l15/cpuapp`, quindi dalla root della repo eseguire:

```bash
python -m src.central.main --device PQ-BLE-Device --phase2-e2e --log-level DEBUG
```

Questo percorso esegue esclusivamente:

```text
connect
subscribe
read public key dinamica
liboqs ML-KEM-768 encapsulation
write ciphertext con la frammentazione esistente
START
wait exact 9-byte PQM2 result
compare diagnostic checksums
```

Non vengono istanziati o eseguiti `SessionStore`/resumption, SAS, HKDF,
AES SecureChannel o persistenza. Una risposta malformata, timeout, status
non-success o checksum mismatch termina con messaggio chiaro ed exit status
nonzero.

Output di successo atteso dopo la futura validazione sul DK reale:

```text
Central TEST-ONLY shared-secret diagnostic checksum: 0x........
Peripheral TEST-ONLY shared-secret diagnostic checksum: 0x........
ML-KEM E2E SHARED SECRET MATCH: YES
```

Il percorso è coperto da 50 test focalizzati e da un build pristine NCS 3.0.0;
la suite Python completa v0.5 conta 170 test passati. Il risultato positivo
Phase 5 e il rifiuto SAS sono stati validati sul DK fisico; le tre modalità
negative FINISHED/transcript restano da eseguire.

La notifica Phase 2 è esattamente:

```text
50 51 4d 32 || status:1 || crc32_ieee(shared_secret):4 big-endian
```

Status: `0x00` success, `0x01` keypair unavailable, `0x02` ciphertext
incomplete, `0x03` genuine local/API decapsulation failure, `0x04` invalid
protocol state. Il vettore automatico comune è 32 byte zero → `0x190A55AD`.

Il valore è un **TEST-ONLY shared-secret diagnostic checksum**: non è
autenticazione, non è una KDF, non è cryptographic key confirmation e non fa
parte del protocollo finale. Il shared secret non viene trasmesso.

ML-KEM applica implicit rejection. Un ciphertext modificato ma strutturalmente
valido può produrre normalmente status `0x00` e un secret differente; il test
deve quindi mostrare checksum differenti e `MATCH: NO`, non necessariamente
un errore di decapsulazione.

## Demo transport legacy (evidenza storica)

Il comando storico era:

```bash
python -m src.central.main --device PQ-BLE-Device --demo --no-sas-confirm --log-level DEBUG
```

L'output registrato era:

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

`--demo` resta un percorso esplicito legacy/deprecated e non è un alias per
`--phase2-e2e`. La notifica raw da 57 byte e la cattura associata validano il
trasporto della milestone precedente, non l'uguaglianza dei shared secret
Phase 2.

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

## Interpretazione della notification raw storica

Nella milestone di trasporto precedente il DK non eseguiva:

- ML-KEM decapsulation on-chip;
- HKDF/session key derivation on-chip;
- AES-256-GCM encryption on-chip.

Per questo motivo quella notification finale viene trattata come **raw
hardware-demo notification**.

La cattura rimane evidenza del trasporto BLE/GATT reale, ma non costituisce
evidenza Phase 2. Il firmware Phase 2 sostituisce il payload raw con il risultato
diagnostico `PQM2`; non implementa comunque una cifratura end-to-end AES-GCM.

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
- Codec diagnostico Phase 2, inclusi formato esatto, big-endian e vettore noto.
- Orchestrazione Central `--phase2-e2e`, ordine delle operazioni e failure path.
- Transcript, key schedule, SAS e FINISHED Phase 5 con vettori noti condivisi.
- Orchestrazione `--phase5-auth-pq`, inclusi rifiuto SAS, FINISHED alterato e
  messaggi duplicati/fuori ordine.
- Coerenza degli UUID tra firmware e Python, device name, SMP disabilitato e
  presenza del path `bt_gatt_notify()`.

### Testato su hardware reale nella milestone precedente

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

Separatamente, la milestone `v0.2-mlkem-ondevice` ha validato sul DK reale il
self-test deterministico KeyGen → Encaps → Decaps di mlkem-native e i relativi
watermark del main thread. Il self-test completo è conservato come profilo
opt-in e non fa parte del normale boot Phase 2.

---

## Cosa richiede ancora validazione sul DK reale / future work

- FINISHED_C alterato, FINISHED_P alterato localmente e transcript/session ID
  differente sul dispositivo reale. Il flusso positivo e il rifiuto SAS sono
  già validati.
- State machine sotto disconnessione durante il worker sul dispositivo reale.
- Watermark cumulativo del crypto thread da 28672 byte dopo KeyGen, Decaps,
  transcript/key schedule, SAS/FINISHED e AES-GCM.
- Persistent session store sul DK.
- Traffico applicativo Central → Peripheral, ibrido P-256 + ML-KEM, energy
  benchmark e formal verification.

La procedura byte-per-byte e i comandi di accettazione v0.5 sono in
[`research/milestones/v0.5-authenticated-pq-handshake.md`](research/milestones/v0.5-authenticated-pq-handshake.md).

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

Per la vecchia cattura raw usare la modalità legacy:

```bash
python -m src.central.main --device PQ-BLE-Device --demo --no-sas-confirm --log-level DEBUG
```

Per il firmware Phase 2 usare invece `--phase2-e2e`; questo percorso interpreta
solo un risultato `PQM2` esatto e non tenta la decifratura AES-GCM.
