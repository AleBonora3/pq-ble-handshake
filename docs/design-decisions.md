# Decisioni Progettuali — Rationale

## 1. Perché ML-KEM-768 e non ML-KEM-512 o ML-KEM-1024?

- **ML-KEM-512**: NIST security category 1 (equivalente AES-128). Più veloce (pk=800B, ct=768B) ma sicurezza insufficiente per "store-now-decrypt-later".
- **ML-KEM-768**: NIST security category 3 (equivalente AES-192, ~174-bit quantum security). Bilanciamento ottimale tra sicurezza e dimensione chiavi. Standardizzato come FIPS 203.
- **ML-KEM-1024**: NIST security category 5 (equivalente AES-256). Overkill. pk=1568B, ct=1568B → 4 frammenti per chiave su GATT. Latenza maggiore senza benefici di sicurezza misurabili nel contesto BLE.

**Scelta: ML-KEM-768** — è lo standard, offre category 3 (sufficiente per resistenza quantistica), e la differenza di performance rispetto a ML-KEM-512 è trascurabile.

## 2. Perché SAS Numeric Comparison invece di QR code?

Vedi discussione completa nel report finale. In sintesi:

| | QR code | SAS |
|---|---|---|
| Hardware extra | Display + fotocamera | **Nessuno** (terminale seriale) |
| Testabile con nRF54L15 | ❌ No | ✅ Sì (via UART seriale) |
| Righe di codice | ~100 | ~10 |
| Standard di riferimento | Signal Safety Numbers | **BLE Core Spec + Signal** |

**Scelta: SAS Numeric Comparison** — testabile immediatamente con hardware esistente, standardizzato, più semplice da implementare e documentare.

## 3. Perché Python e non C/Rust?

- **Velocità di sviluppo**: Python + bleak permette di prototipare in ore, non giorni
- **Librerie**: bleak è la libreria BLE Python più matura; liboqs ha binding Python ufficiali
- **Performance crittografica**: ML-KEM e AES-GCM sono chiamate a librerie C (liboqs, OpenSSL) — Python è solo collante
- **Dimostrabilità**: il docente può eseguire il codice su qualsiasi laptop senza toolchain embedded
- **Limite**: Python non è adatto per produzione embedded. Menzionato onestamente nella tesina come "proof-of-concept".

**Scelta: Python** per il central (PC + Bleak). Il peripheral reale è firmware Zephyr su nRF54L15 DK. Il peripheral Python (BleakServer) è in `experimental/` e non è parte della demo reale.

## 4. Perché frammentazione custom invece di GATT Long Write?

- **GATT Long Write** (Prepare Write + Execute Write) è supportato da bleak ma non da tutte le periferiche BLE
- **Frammentazione custom** dà controllo totale, è portabile, e dimostra competenza ingegneristica
- **Codice**: ~50 righe di Python. Vale la pena come punto di discussione nella tesina.

**Scelta: Frammentazione custom** — più robusta, più didattica.

## 5. Perché AES-256-GCM e non ChaCha20-Poly1305?

- Entrambi sono AEAD sicuri.
- AES-GCM è lo standard de facto per BLE (usato nel BLE CCM a livello link)
- AES ha accelerazione hardware (AES-NI) su tutte le CPU x86 moderne
- ChaCha20-Poly1305 è preferibile su CPU senza AES-NI (es. ARM Cortex-M4 senza crypto extensions)

**Scelta: AES-256-GCM** — standard, performante su x86, familiare al contesto BLE.

## 6. Perché non Dilithium per autenticazione completa?

- Dilithium (ML-DSA) permetterebbe autenticazione senza interazione umana
- Ma le firme sono ~2500 byte → 5 frammenti GATT aggiuntivi
- Aggiunge complessità implementativa significativa per un 6 CFU
- SAS Numeric Comparison con Dilithium come "future work" dimostra visione completa

**Scelta: SAS ora, Dilithium nella sezione "Sviluppi Futuri"** — il progetto è completo e funzionale, e dimostri di conoscere la soluzione completa.

## 7. Architettura dei moduli

```
src/common/   → tutto il codice condiviso: crypto, frammentazione, SAS
src/central/  → logica client: connessione, handshake lato central
experimental/peripheral/ → server Python (BleakServer, SPERIMENTALE): advertising, handshake lato peripheral
tests/        → indipendente da BLE: testa la logica pura
benchmarks/   → indipendente da BLE: testa le performance crittografiche
```

**Scelta: Separazione pulita** — central e peripheral condividono la logica crittografica ma sono eseguibili indipendentemente. I test sono disaccoppiati dall'hardware.