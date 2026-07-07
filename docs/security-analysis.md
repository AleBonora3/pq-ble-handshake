# Security Analysis — PQ-BLE-HANDSHAKE

Analisi sintetica delle proprietà di sicurezza del protocollo.

## Tabella riepilogativa

| Proprietà | Stato | Motivazione |
|---|---|---|
| **Confidenzialità post-quantum** | Garantita a livello di handshake | La chiave di sessione deriva da ML-KEM-768, NIST security category 3 |
| **Integrità dei messaggi** | Garantita | AES-256-GCM autentica ogni payload tramite tag GCM |
| **Autenticazione del peer** | Interattiva, non automatica | Il SAS autentica la trascrizione se l'utente confronta correttamente il codice |
| **Rilevamento MITM** | Sì, con SAS verificato | La sostituzione della public key produce transcript e SAS diversi. P(false accept) = 10⁻⁶ |
| **Forward secrecy** | Buona con handshake effimero; ridotta con session resumption | Il salvataggio della session key accelera la riconnessione ma aumenta l'impatto di una compromissione locale. Re-handshake periodico (default: 24h) come mitigazione |
| **Replay protection applicativa** | Garantita | AAD = `session_id \|\| sender_role \|\| seq_num` + monotonically increasing sequence number; replay e out-of-order rifiutati |
| **Protezione contro jamming** | Non coperta | Il jamming è un attacco fisico/radio fuori scope |

## Modello di minaccia

### Assunzioni
1. L'attaccante può intercettare tutti i pacchetti BLE sul canale radio (passivo)
2. L'attaccante può iniettare, modificare e sopprimere pacchetti GATT (attivo MITM)
3. L'utente verifica correttamente il SAS (confronto visivo senza errori)
4. L'hardware non è compromesso (nessun attacco side-channel sul chip)
5. Il generatore di numeri casuali è sicuro (`/dev/urandom` su Linux)

### Minacce coperte

| Minaccia | Mitigazione |
|---|---|
| Store-now-decrypt-later (quantum) | ML-KEM-768: categoria NIST 3, comparabile ad AES-192 |
| MITM attivo con sostituzione pk | SAS Numeric Comparison: P(false accept) = 10⁻⁶ |
| Replay attack | AAD con `session_id + role + seq_num` + sequenza monotona crescente; replay e riordino rifiutati a livello applicativo |
| Modifica dei dati cifrati | AES-256-GCM: authentication tag da 16 byte |
| Attacco di forza bruta sul SAS | Rate-limited dall'interazione umana |

### Minacce non coperte

| Minaccia | Motivazione |
|---|---|
| Jamming radio BLE | Fuori scope: richiede protezioni a livello fisico |
| Side-channel attacks | Richiede contromisure hardware dedicate |
| Compromissione dell'endpoint | La sicurezza è limitata al canale di comunicazione |
| Attacco all'RNG | Mitigato usando `/dev/urandom`; fuori scope attacchi fisici all'RNG |

## Limitazioni note

- **Nessuna protezione a livello link BLE**: non usando il Security Manager BLE, la cifratura nativa del link non viene attivata. Il protocollo protegge il payload applicativo con AES-GCM.
- **SAS non scala**: in scenari IoT con migliaia di dispositivi, l'interazione umana non è praticabile. Per deployment reali servirebbe autenticazione automatica (es. ML-DSA).
- **Session resumption e forward secrecy**: il trade-off tra usabilità (resume veloce) e sicurezza (forward secrecy piena) è gestito con re-handshake periodico.

## Evoluzioni previste

1. **~~Counter/AAD in AES-GCM~~** ✅ Implementato: AAD = `session_id || sender_role || sequence_number`; replay protection con sequence number monotono crescente; direction separation via role binding (previene reflection attack).
2. **ML-DSA per autenticazione automatica**: firme digitali post-quantum per eliminare l'interazione umana.
3. **Ibrido ECDH + ML-KEM**: combinare P-256 e ML-KEM-768 per sicurezza anche in caso di breakthrough crittoanalitico su uno dei due.
4. **Peripheral su hardware reale**: il peripheral Python (BleakServer, sperimentale, Linux-only) è in `experimental/` e NON è parte della demo reale. La demo reale usa firmware Zephyr su nRF54L15 DK (`firmware/nrf54l15_pq_gatt_skeleton/`), con modalità `DEMO_PRECOMPUTED_KEM`. Il porting completo di ML-KEM su Cortex-M33 è sviluppo futuro.
5. **Test su BLE reale**: validare il protocollo con traffico BLE reale catturato dal nRF52840 sniffer + Wireshark, confrontando payload in chiaro (prima) vs cifrati AES-GCM (dopo).