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
python -m pytest -q --basetemp=C:\pq_ble\.pytest-temp
```

Use the explicit writable basetemp on this Windows PC. The earlier
`PermissionError` at `C:\Users\alebo\AppData\Local\Temp\pytest-of-alebo`
was a temporary-directory setup issue, not a test failure; the command above
resolved it. The 2026-09-08 hardware-session baseline is **635 passed,
1 skipped, 1 warning** (liboqs 0.15.0 versus liboqs-python 0.16.0).
Final consolidation results are recorded in [test-results.md](test-results.md).
The 2026-09-09 consolidation passed with **643 passed, 1 skipped, 1 warning**
(eight additional reporting regressions) and `git diff --check` passed.
If activation is blocked by PowerShell execution policy, invoke
`.\.venv\Scripts\python.exe` in place of `python`; no policy change is needed.
The final run used normal host access to the existing basetemp. Its generated
files are excluded by `.gitignore`.

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
python -m pytest tests/test_v1_cp1.py -v
```

### v1.0 CP1 (SMP Security Mode 1 Level 4 foundation)

The hardware-fix regressions also include `tests/test_winrt_pairing_lifecycle.py`
(realistic synchronous WinRT events/deferrals/cancellation) and
`tests/test_v1_firmware_lifecycle.py` (actual CP1 C state machine on host GCC).
See [the CP1 audit](research/milestones/v1.0-cp1-hardware-fix-audit.md).
**CP1 foundation passed on real Windows PC + nRF54L15 DK on 2026-09-08**:
pre-L4 gating, cold NC with matching PIN 177415, bonded reconnect without
new NC and PC NC rejection with PIN 705752. B/C both returned authenticated
L4, SC, key=16, gate OPEN and profile=0x10, and allowed all four PQ GATT
operations. See the preserved [PC/DK log](research/logs/v1.0-1-tests.txt).
For `nc-reject`, type `no` in the PC console for the automated verdict;
DK-only rejection needs the UART history. A generic FAILED with no ceremony
is inconclusive. Clear both bonds between negative scenarios as specified
in the milestone procedure below.

The retained `--v1-negative just-works` name means **Windows CONFIRM_ONLY
with minimum ENCRYPTION**. `DevicePairingKinds.CONFIRM_ONLY` is an application
pairing ceremony, not proof of the BLE on-air Just Works association model.
In run E, Windows returned FAILED, paired=False, protection=NONE,
ceremony=None, decision=None; no authenticated bond or L4 was established.
The reviewed observation is **CONFIRM_ONLY FAIL-CLOSED: PASS (observed
outcome)**; **RADIO-LEVEL JUST WORKS: NOT DEMONSTRATED**. The full automated
rejection oracle remains INCONCLUSIVE because it had neither a specific
security refusal nor an observed/accepted ceremony; it did not perform
fresh probes after E.

Current CLI interpretation:

| Evidence | Result and exit |
|---|---|
| Generic FAILED with no ceremony; timeout/setup status; missing fresh verification connection | `NEGATIVE TEST: INCONCLUSIVE`, exit **1**; no automated PASS and no claim that the CP1 foundation failed. |
| Specific security refusal, or FAILED after observed/accepted CONFIRM_ONLY, then no bond/notification and four fresh security denials | `NEGATIVE TEST: PASS (just-works)` plus `CONFIRM_ONLY FAIL-CLOSED: PASS`, exit **0**. |
| Pairing/bond accepted, successful pre-L4 PQ operation or notification | Negative test **FAIL**, exit **1**. |

The CONFIRM_ONLY PASS and INCONCLUSIVE reports both explicitly state
`RADIO-LEVEL JUST WORKS: NOT DEMONSTRATED`. Exceptions during setup still
fail with a nonzero exit; they are not evidence of security refusal. The
complete physical negative oracle also requires DK history with no L4/gate
OPEN throughout the attempt and verification. Keep the original raw log's
old E FAIL marker unchanged; its presentation is superseded by this distinction.

These documentation/reporting changes require no new firmware build or
hardware run. Reproduction is optional, as is a future radio-level Just
Works experiment with a peer using controlled `NoInputNoOutput` IO capability.
The separate DK-only BUTTON 1 variant is not claimed as a completed run.
Neither optional variant blocks CP1 acceptance. Do not start CP2 or change
the v0.7 profile for these checks.

`tests/test_v1_cp1.py` valida su host: framing `PQV1`, predicato
"authenticated Level 4", classificazione dei rifiuti GATT di sicurezza,
flusso CP1 con DK e backend di pairing Windows simulati (positivo, bug di
gating, rifiuti, bond stale, modalità negative) e coerenza dei sorgenti
firmware (`prj.conf` invariato, frammento `v1_smp_l4_mlkem.conf`, permessi
GATT `AUTHEN | LESC`, gate runtime in ogni callback, nessuna auto-conferma
della Numeric Comparison). Non è evidenza hardware.

Riproduzione hardware (Windows PC + nRF54L15 DK con profilo v1.0):

```powershell
python -m src.central.main --v1-smp-l4-mlkem --v1-negative pre-l4-only
python -m src.central.main --v1-smp-l4-mlkem
# Repeat without clearing bonds for bonded reconnect (C).
python -m src.central.main --v1-smp-l4-mlkem
# Clear both bonds before each negative scenario; follow the milestone.
python -m src.central.main --v1-smp-l4-mlkem --v1-negative nc-reject
python -m src.central.main --v1-smp-l4-mlkem --v1-negative just-works
```

Procedura completa, mappa dei pulsanti e log attesi:
[CP1 milestone](research/milestones/v1.0-smp-l4-mlkem.md#hardware-reproduction-procedure).
Archive any new logs under new names; preserve both `v1.0-tests.txt` and
`v1.0-1-tests.txt` in `docs/research/logs/` unchanged.

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
