# Guida al Testing

## Suite di test (109 test totali)

```bash
# Tutti i test
python -m pytest tests/ -v

# Test per modulo
python -m pytest tests/test_ml_kem.py -v           # ML-KEM-768 (6 test)
python -m pytest tests/test_fragmentation.py -v    # Frammentazione GATT (14 test)
python -m pytest tests/test_sas.py -v              # SAS Numeric Comparison (12 test)
python -m pytest tests/test_session.py -v          # HKDF + AES-256-GCM (12 test)
python -m pytest tests/test_handshake_mock.py -v   # Handshake completo mock (2 test)
python -m pytest tests/test_mitm_simulation.py -v  # Simulazione MITM (2 test)
python -m pytest tests/test_session_store.py -v    # Session Resumption (17 test)
python -m pytest tests/test_handshake_mock.py -v   # Handshake mock senza BLE
```

## Copertura test

| Modulo | File test | N° test | Cosa verifica |
|---|---|---|---|
| ML-KEM-768 | `test_ml_kem.py` | 6 | Keygen, encaps/decaps, 100 iterazioni |
| Frammentazione | `test_fragmentation.py` | 14 | Encode/decode, ordine, edge case |
| SAS | `test_sas.py` | 12 | Derivazione, confronto, distribuzione |
| Canale sicuro | `test_session.py` | 19 | HKDF, AES-GCM, AAD, replay protection, direction separation |
| Handshake | `test_handshake_mock.py` | 2 | Pipeline completa, 100 iterazioni |
| MITM | `test_mitm_simulation.py` | 2 | Rilevamento MITM via SAS mismatch |
| **Session Resumption** | `test_session_store.py` | **23** | Save/load/delete/expiry, wire format, resume flow |

## Demo Completa

```bash
# Avvia peripheral + central
./scripts/run_demo.sh

# Oppure manualmente in due terminali separati:
# Terminale 1:
PYTHONPATH=. python -m experimental.peripheral.main

# Terminale 2:
python -m src.central.main
```

## Benchmark

```bash
# Esegui tutti i benchmark
./benchmarks/run_all.sh

# Singoli benchmark
python3 benchmarks/benchmark_handshake.py
python3 benchmarks/benchmark_throughput.py
python3 benchmarks/benchmark_fragmentation.py
```

## Demo Completa

```bash
# Avvia peripheral + central
./scripts/run_demo.sh

# Oppure manualmente in due terminali separati:
# Terminale 1:
PYTHONPATH=. python3 -m experimental.peripheral.main

# Terminale 2:
python3 -m src.central.main
```

## Test con nRF54L15 (sviluppo futuro)

> ⚠️ Il firmware in `firmware/nrf54l15_pq_gatt_skeleton/` ha un **GATT service completo con UUID corretti** ma non è ancora compilato né testato su hardware reale.
> Il reference design precedente è in `firmware/nrf54l15/`.

Quando il firmware sarà implementato:

1. Generare vettori precomputati: `python scripts/generate_demo_vectors.py`
2. Incollare i vettori in `firmware/nrf54l15_pq_gatt_skeleton/src/main.c`
3. Flash sul nRF54L15 DK: `cd firmware/nrf54l15_pq_gatt_skeleton && west build -b nrf54l15dk/nrf54l15/cpuapp -p always && west flash`
4. Il nRF espone il GATT server e stampa log via UART seriale
5. Collega il nRF via USB e apri il terminale seriale:
   ```bash
   screen /dev/ttyACM0 115200
   ```
6. Avvia il central sul PC:
   ```bash
   python3 -m src.central.main
   ```

## Cosa è testato vs Cosa non è testato

### ✅ Testato (Python, 109 test automatizzati)
- ML-KEM-768 keygen, encapsulate, decapsulate (6 test)
- Frammentazione e riassemblaggio GATT (14 test)
- SAS Numeric Comparison derivation e verifica (12 test)
- AES-256-GCM con AAD, replay protection, direction separation, msg_type binding (22 test)
- Session resumption: save/load/delete/expiry (23 test)
- Handshake completo senza BLE (2 test, 100 iterazioni)
- MITM detection via SAS mismatch (2 test)
- Firmware UUID consistency: firmware ↔ Python constants (11 test)
- Central transport mock: fragmented read/write con mock GATT (17 test)
- Simulazione sniffing comparativa prima/dopo (sniff_test.py)

### ❌ Non testato (sviluppo futuro)
- Peripheral BLE reale: il peripheral Python (BleakServer, sperimentale) è in `experimental/` e NON è parte della demo reale. La demo reale usa firmware Zephyr su nRF54L15 DK.
- Firmware nRF54L15 (non compilato, non testato)
- Traffico BLE reale con nRF52840 sniffer + Wireshark
- Frammentazione su transport BLE reale (la logica è testata, il path BLE no)

## Troubleshooting

### "Device not found" durante lo scan BLE
- Verifica che l'adattatore BLE sia acceso: `sudo hciconfig hci0 up`
- Su Linux, potresti aver bisogno di permessi: `sudo setcap cap_net_admin+ep $(which python3)`
- Prova con `hcitool lescan` per verificare che l'hardware funzioni

### "liboqs not found"
- Hai eseguito `./scripts/setup.sh`?
- Verifica: `ldconfig -p | grep liboqs`
- Su Linux: `sudo ldconfig` dopo l'installazione

### "MTU negotiation failed"
- BLE 4.2+ richiesto per MTU > 23 byte
- Alcuni adattatori USB economici potrebbero non supportare MTU negotiation
- Verifica: `btmon` per vedere i pacchetti HCI