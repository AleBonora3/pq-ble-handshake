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
# ML-KEM-768
python -m pytest tests/test_ml_kem.py -v

# Frammentazione GATT
python -m pytest tests/test_fragmentation.py -v

# SAS Numeric Comparison
python -m pytest tests/test_sas.py -v

# HKDF + AES-256-GCM + AAD + replay protection
python -m pytest tests/test_session.py -v

# Session resumption e store JSON
python -m pytest tests/test_session_store.py -v

# Handshake completo mock senza BLE reale
python -m pytest tests/test_handshake_mock.py -v

# Simulazione MITM via SAS mismatch
python -m pytest tests/test_mitm_simulation.py -v

# Controlli firmware base
python -m pytest tests/test_firmware_uuids.py -v

# Mock BLE central transport
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
4. demo hardware reale PC central ↔ nRF54L15 DK.

I test attivi in `test_firmware_uuids.py` rimangono utili per controllare:

- device name atteso;
- BLE SMP disabilitato;
- presenza del path reale `bt_gatt_notify()`.

---

## Demo hardware reale con nRF54L15 DK

La demo reale usa:

```text
PC Windows + Python/Bleak  ←── BLE/GATT ──→  nRF54L15 DK + Zephyr firmware
```

Il peripheral Python in `experimental/peripheral/` **non** è parte della demo reale. È sperimentale, Linux-only e non usato nella validazione hardware.

---

## Prerequisiti hardware

- nRF54L15 DK;
- PC con adattatore Bluetooth;
- Python virtual environment con dipendenze installate;
- nRF Connect SDK compatibile con nRF54L15 DK;
- nRF Connect for VS Code;
- opzionale: nRF Connect Mobile per test manuale;
- opzionale: nRF52840 Dongle per sniffing passivo;
- opzionale: Wireshark + nRF Sniffer for Bluetooth LE.

---

## Build e flash firmware nRF54L15 DK

Dalla cartella firmware:

```bash
cd firmware/nrf54l15_pq_gatt_skeleton
west build -b nrf54l15dk/nrf54l15/cpuapp -p always
west flash
```

Su Windows è consigliato usare un path corto per evitare problemi di lunghezza percorso con Zephyr/NCS:

```text
C:\myfw\pq
```

Esempio PowerShell:

```powershell
cd C:\myfw\pq
west build -b nrf54l15dk/nrf54l15/cpuapp -p always
west flash
```

Risultato atteso:

```text
Board with serial number ... flashed successfully.
```

---

## Validazione manuale con nRF Connect Mobile

Dopo il flash:

1. apri nRF Connect Mobile;
2. scansiona i dispositivi BLE;
3. cerca `PQ-BLE-Device`;
4. connettiti;
5. leggi la Public Key characteristic;
6. abilita le notification sulla Secure Data characteristic;
7. scrivi `START` sulla Control characteristic.

Se `START` viene inviato prima del ciphertext, il firmware deve stampare qualcosa di simile:

```text
Received START command
START received but ciphertext not yet written
```

Questo comportamento è corretto.

---

## Demo PC central ↔ nRF54L15 DK

Dalla root della repo:

```bash
python -m src.central.main --device PQ-BLE-Device --demo --no-sas-confirm --log-level DEBUG
```

Su Windows PowerShell:

```powershell
.\.venv\Scripts\activate
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

Questa demo valida il path reale BLE/GATT:

1. scan BLE;
2. connect;
3. public key read;
4. ML-KEM encapsulation lato PC;
5. ciphertext fragmentation;
6. ciphertext write su GATT;
7. SAS derivation;
8. session key derivation lato PC;
9. `START` control write;
10. notification dal DK al central.

---

## Interpretazione della notification raw

Nel firmware attuale il DK **non** esegue ancora:

- ML-KEM decapsulation on-chip;
- HKDF/session key derivation on-chip;
- AES-256-GCM encryption on-chip.

Per questo motivo la notification finale viene trattata come **raw hardware-demo notification**.

La demo hardware valida il trasporto BLE/GATT reale, ma non ancora la cifratura end-to-end eseguita interamente sul DK.

---

## Cattura con nRF52840 Dongle e Wireshark

Il prossimo step osservazionale è catturare il traffico BLE con nRF52840 Dongle.

Procedura prevista:

1. collega nRF52840 Dongle;
2. apri Wireshark;
3. seleziona l’interfaccia `nRF Sniffer for Bluetooth LE`;
4. avvia la cattura;
5. avvia la demo PC central ↔ DK;
6. filtra con:

```text
btatt
```

Pacchetti attesi:

```text
ADV_IND                       advertising: "PQ-BLE-Device"
CONNECT_IND                   PC → DK connection
ATT Exchange MTU              MTU negotiation
ATT Read Request              Public Key characteristic
ATT Read Blob                 public key long read
ATT Write Request             ciphertext fragments
ATT Write Request             Control: START
ATT Handle Value Notification raw demo notification
```

Cosa dovrebbe vedere lo sniffer:

- public key ML-KEM pubblica;
- ciphertext ML-KEM pubblico;
- GATT writes dei frammenti;
- write del comando `START`;
- notification dal DK.

Cosa non bisogna aspettarsi nel firmware attuale:

- BLE SMP pairing;
- link-layer encryption;
- on-chip ML-KEM decapsulation;
- on-chip AES-GCM encryption.

---

## Benchmark

Per eseguire tutti i benchmark:

```bash
bash benchmarks/run_all.sh
```

Singoli benchmark:

```bash
python benchmarks/benchmark_handshake.py
python benchmarks/benchmark_throughput.py
python benchmarks/benchmark_fragmentation.py
```

Su Linux, se gli script sono eseguibili:

```bash
./benchmarks/run_all.sh
```

---

## Demo sperimentale Python peripheral

La vecchia demo con peripheral Python è sperimentale e non rappresenta la demo hardware reale.

```bash
# Terminale 1
PYTHONPATH=. python -m experimental.peripheral.main

# Terminale 2
python -m src.central.main
```

Questa modalità può essere utile per esperimenti locali, ma:

- non è la validazione hardware principale;
- non usa il nRF54L15 DK;
- dipende da supporto BLE backend/OS;
- il peripheral Python è considerato sperimentale.

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

---

## Cosa non è ancora testato / future work

- Cattura Wireshark completa con nRF52840 Dongle.
- Analisi packet-level della demo PC central ↔ DK.
- On-chip ML-KEM decapsulation sul nRF54L15 DK.
- On-chip HKDF/session key derivation.
- On-chip AES-256-GCM encryption.
- Persistent session store sul DK.
- Full secure-channel payload decryptato dal central a partire da ciphertext prodotto dal DK.

---

## Troubleshooting

### Device not found durante lo scan BLE

Controlli rapidi:

- verifica che il DK sia alimentato e flashato;
- verifica che `PQ-BLE-Device` compaia su nRF Connect Mobile;
- assicurati che il telefono non sia ancora connesso al DK;
- spegni/riaccendi Bluetooth sul PC;
- rilancia il firmware o premi reset sul DK.

Su Linux:

```bash
sudo hciconfig hci0 up
hcitool lescan
```

Su alcuni sistemi Linux possono servire permessi aggiuntivi:

```bash
sudo setcap cap_net_admin+ep $(which python3)
```

### liboqs not found

Su Windows, `liboqs-python` può installare automaticamente `liboqs` nella cartella utente.

Se l’installazione automatica fallisce:

- verifica di avere compilatore/CMake/Ninja disponibili;
- verifica che il virtual environment sia attivo;
- reinstalla le dipendenze:

```bash
pip install -r requirements.txt
```

Su Linux:

```bash
sudo ldconfig
ldconfig -p | grep liboqs
```

### MTU inizialmente pari a 23

È normale che subito dopo la connessione il log mostri:

```text
Connected. MTU: 23
```

Poi, dopo la discovery/negoziazione, il central può usare un MTU più alto, ad esempio:

```text
Read public key: 1184 bytes (MTU=247)
```

Nel test hardware validato, il ciphertext da 1088 byte è stato scritto in 5 frammenti con MTU 247.

### Unexpected disconnect a fine demo

Se compare dopo:

```text
BLE/GATT transport validation completed.
```

non è grave.

Il programma chiude la connessione al termine della demo e il callback può loggare una disconnessione inattesa. Il test è comunque da considerare completato.

### InvalidTag durante la notification

Se la demo viene eseguita in modalità secure-channel normale, la notification raw del firmware può causare:

```text
cryptography.exceptions.InvalidTag
```

Questo è previsto perché il firmware attuale non cifra la notification con la session key derivata dal central.

Usare la modalità demo aggiornata:

```bash
python -m src.central.main --device PQ-BLE-Device --demo --no-sas-confirm --log-level DEBUG
```

La demo deve ricevere la notification come raw hardware-demo payload.
