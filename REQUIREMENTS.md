# PQ-BLE-HANDSHAKE — Requisiti e Dipendenze

## Sistema Operativo

### Linux (consigliato per sviluppo completo)
- Ubuntu 22.04+, Debian 12+, Fedora 38+
- BlueZ ≥ 5.43: `sudo apt install bluez bluez-tools`
- Permessi BLE: `sudo setcap cap_net_admin+ep $(which python3)`

### Windows 10/11 (central + test/benchmark nativi)
- Windows 10 21H2+ o Windows 11
- Visual Studio Build Tools 2022 (gratis, per compilare liboqs)
  - https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022
  - Selezionare: ☑ Desktop development with C++
- CMake ≥ 3.16: `winget install Kitware.CMake`
- Git: `winget install Git.Git`
- BLE driver: nessuno richiesto — bleak usa WinRT nativamente
- Il peripheral Python NON funziona su Windows → usa nRF54L15 o VM Linux
- Per lo sviluppo su Windows, usa una VM Linux (VirtualBox/Ubuntu) per il peripheral e mantieni il central su Windows

### macOS 12+
- Adattatore BLE integrato (tutti i Mac dal 2015)
- Complica la gestione del BLE advertising (sandbox macOS)

## Dipendenze Python
Installate automaticamente con `pip install -r requirements.txt`:

| Pacchetto | Versione | Ruolo |
|---|---|---|
| `bleak` | ≥ 0.21.0 | BLE GATT client/server cross-platform |
| `cryptography` | ≥ 41.0.0 | AES-256-GCM, HKDF-SHA256 |
| `matplotlib` | ≥ 3.7.0 | Grafici per benchmark e tesina |
| `pytest` | ≥ 7.0.0 | Test automatizzati |
| `pytest-asyncio` | ≥ 0.21.0 | Supporto async per pytest |

## liboqs (Post-Quantum Cryptography)
- **liboqs** — libreria C con implementazioni reference degli algoritmi PQC NIST
  - Repository: https://github.com/open-quantum-safe/liboqs
  - Build: CMake ≥ 3.10, compilatore C (gcc/clang)
  - Algoritmo usato: ML-KEM-768 (Kyber)
- **liboqs-python** — binding Python per liboqs
  - Repository: https://github.com/open-quantum-safe/liboqs-python

Lo script `scripts/setup.sh` automatizza l'installazione di entrambi.

## Hardware BLE

### Opzione A: Laptop con BLE integrato (consigliata per sviluppo)
- Qualsiasi laptop con chip BLE 4.2+ (praticamente tutti dal 2015)
- Due adattatori BLE USB (CSR8510, ~€5-10 l'uno) per test central ↔ peripheral sullo stesso PC

### Opzione B: nRF54L15 DK (per test embedded, opzionale)
- nRF54L15 Development Kit (già in possesso di Alessio)
- nRF Connect SDK o Zephyr RTOS per firmware
- nRF Dongle per sniffing BLE con Wireshark

### Verifica hardware
```bash
./scripts/test_ble.sh    # Verifica che il BLE funzioni
```

## Permessi Linux
Su Linux, bleak richiede permessi per il BLE advertising:
```bash
# Opzione 1: permessi capabilities (consigliato)
sudo setcap cap_net_admin+ep $(which python3)

# Opzione 2: esegui come root (non consigliato)
sudo PYTHONPATH=. python3 -m experimental.peripheral.main
```

## Spazio Disco
- Codice: ~500 KB
- liboqs compilata: ~50 MB
- Dipendenze Python: ~200 MB
- Totale: ~300 MB