# Security Analysis — PQ-BLE-HANDSHAKE

Analisi sintetica delle proprietà di sicurezza del protocollo.

---

## Tabella riepilogativa

| Proprietà | Stato | Motivazione |
|---|---|---|
| **Confidenzialità post-quantum** | Garantita a livello di handshake Python | La chiave di sessione deriva da ML-KEM-768, NIST security category 3 |
| **Integrità dei messaggi** | Garantita nel secure channel Python | AES-256-GCM autentica ogni payload tramite tag GCM |
| **Autenticazione del peer** | Interattiva, non automatica | Il SAS autentica la trascrizione se l'utente confronta correttamente il codice |
| **Rilevamento MITM** | Sì, con SAS verificato | La sostituzione della public key produce transcript e SAS diversi; P(false accept) = 10^-6 |
| **Forward secrecy** | Buona con handshake effimero; ridotta con session resumption | Il salvataggio della session key accelera la riconnessione ma aumenta l'impatto di una compromissione locale |
| **Replay protection applicativa** | Garantita nel secure channel Python | AAD = `session_id || sender_role || seq_num || msg_type` + sequence number monotono |
| **Message-type binding** | Garantito | `msg_type` è autenticato in AAD e incluso nel wire format |
| **Protezione contro jamming** | Non coperta | Il jamming è un attacco fisico/radio fuori scope |

---

## Modello di minaccia

### Assunzioni

1. L'attaccante può intercettare tutti i pacchetti BLE sul canale radio.
2. L'attaccante può iniettare, modificare e sopprimere pacchetti GATT.
3. L'utente verifica correttamente il SAS.
4. L'hardware non è compromesso.
5. Il generatore di numeri casuali è sicuro.
6. Gli endpoint sono trusted.

---

## Minacce coperte

| Minaccia | Mitigazione |
|---|---|
| Store-now-decrypt-later | ML-KEM-768, NIST security category 3 |
| MITM attivo con sostituzione public key | SAS Numeric Comparison |
| Replay attack | `session_id`, `sender_role`, `seq_num`, `msg_type` in AAD + sequenza monotona |
| Out-of-order packet injection | Receiver rejects non-monotonic sequence numbers |
| Reflection/cross-direction attack | Sender role binding in AAD |
| Cross-session confusion | `session_id` binding in AAD |
| Data/control substitution | `msg_type` binding in AAD |
| Payload tampering | AES-256-GCM authentication tag |

---

## Minacce non coperte

| Minaccia | Motivazione |
|---|---|
| Jamming radio BLE | Fuori scope: richiede protezioni a livello fisico |
| Side-channel attacks | Richiede contromisure hardware dedicate |
| Compromissione endpoint | La sicurezza è limitata al canale di comunicazione |
| Attacco all'RNG | Fuori scope se l'RNG dell'endpoint è compromesso |
| Phishing/social engineering sul SAS | Il SAS protegge solo se l'utente confronta correttamente il codice |
| Traffico BLE metadata leakage | Il protocollo cifra il payload applicativo, non nasconde metadati radio/GATT |

---

## AAD e wire format

Il secure channel Python usa AES-256-GCM con AAD.

AAD:

```text
session_id (16) || sender_role (1) || seq_num (8) || msg_type (1)
```

Wire format:

```text
seq_num (8) || msg_type (1) || iv (12) || ciphertext || tag (16)
```

Questo design garantisce che il tag GCM autentichi non solo il payload, ma anche:

- la sessione;
- la direzione del messaggio;
- il numero di sequenza;
- il tipo di messaggio.

---

## Hardware security interpretation

La demo hardware reale valida il trasporto BLE/GATT, non il full secure channel on-chip.

Validato su hardware:

- advertising BLE;
- connessione PC central ↔ nRF54L15 DK;
- MTU exchange;
- public key long read;
- ciphertext write frammentato;
- control write `START`;
- raw notification dal DK;
- cattura passiva nRF52840/Wireshark.

Non ancora validato su DK:

- ML-KEM decapsulation on-chip;
- HKDF/session key derivation on-chip;
- AES-256-GCM encryption on-chip;
- persistent session store on-chip.

Questa distinzione è importante: la sicurezza crittografica completa è testata in Python; il firmware attuale dimostra che il trasporto BLE/GATT reale è compatibile con il protocollo.

---

## Session resumption

La session resumption migliora usabilità e latenza, ma riduce la forward secrecy rispetto a un handshake effimero completo a ogni riconnessione.

Mitigazioni:

- re-handshake periodico;
- scadenza delle sessioni;
- usage counter;
- eliminazione delle sessioni vecchie;
- timeout breve sui resume stale.

Nota ingegneristica: nei log hardware possono comparire più tentativi di resume falliti se il central ha molte sessioni cached. In una versione di produzione conviene limitare il numero di tentativi o usare timeout più brevi, per evitare ritardi prima del fallback al full handshake.

---

## Limitazioni note

- **Nessuna protezione a livello link BLE**: non usando il Security Manager BLE, la cifratura nativa del link non viene attivata. Il protocollo protegge il payload applicativo con AES-GCM.
- **SAS non scala**: in scenari IoT con molti dispositivi, l'interazione umana non è praticabile. Per deployment reali servirebbe autenticazione automatica, ad esempio con ML-DSA.
- **Firmware DK non crittografico completo**: il firmware attuale valida il trasporto GATT e invia una notification raw/demo, ma non esegue ancora ML-KEM/AES-GCM on-chip.
- **Demo public key placeholder**: il firmware può esporre un buffer demo da 1184 byte per validare il trasporto. Per una demo crittografica end-to-end embedded serviranno vettori coerenti o generazione ML-KEM on-chip.
- **Wireshark non dimostra segretezza da solo**: la cattura dimostra il trasporto ATT/GATT e l'assenza di SMP, ma la sicurezza del payload dipende dalla corretta implementazione crittografica testata in Python.

---

## Stato delle evoluzioni

Completed:

1. AAD con `session_id || sender_role || seq_num || msg_type`.
2. Replay protection con sequence number monotono.
3. Direction separation via role binding.
4. Message-type binding via `msg_type`.
5. Firmware Zephyr su nRF54L15 DK per validazione GATT.
6. Test BLE reale PC central ↔ nRF54L15 DK.
7. Cattura passiva nRF52840/Wireshark.

Future work:

1. ML-KEM decapsulation on-chip.
2. HKDF/session key derivation on-chip.
3. AES-256-GCM encryption on-chip.
4. Persistent session store su DK.
5. ML-DSA per autenticazione automatica.
6. Hybrid ECDH + ML-KEM handshake.
