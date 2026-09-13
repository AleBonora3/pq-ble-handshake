# Confronto tra PQ-BLE v0.7 e v1.0

## 1. Obiettivo

Questo documento descrive le due implementazioni principali del progetto PQ-BLE-HANDSHAKE e ne confronta architettura, gestione della riconnessione, overhead, prestazioni, risorse e proprietà di sicurezza validate.

Le due versioni non rappresentano semplicemente due revisioni dello stesso handshake. Sono due scelte architetturali differenti:

- **v0.7**: protocollo ibrido interamente applicativo, basato su ML-KEM-768 e P-256 ECDH;
- **v1.0**: architettura a livelli, con BLE Security Mode 1 Level 4 per autenticazione/protezione del link e ML-KEM-768 per il key establishment applicativo post-quantum.

La v1.0 termina con CP5. La successiva Post-v1.0 Comparative Evaluation (EVAL-A–EVAL-E) confronta le due baseline congelate.

## 2. v0.7: handshake ibrido applicativo

Nel profilo v0.7 BLE SMP è disabilitato. La sicurezza è costruita sopra GATT a livello applicativo.

La derivazione parte da due contributi indipendenti:

```text
SS_MLKEM
+
SS_ECDH
        |
        v
u16be(32) || SS_MLKEM || u16be(32) || SS_ECDH
        |
        v
HKDF-SHA256
        |
        +--> SAS applicativo
        +--> FINISHED
        +--> chiavi direzionali AES-256-GCM
```

Il transcript canonico lega session identifier, public key e ciphertext ML-KEM, public key P-256 dei due endpoint e ruoli di protocollo. Il SAS a sei cifre viene confrontato dall'operatore prima dell'attivazione del canale autenticato.

Il data-plane usa AES-256-GCM con sequence number direzionali e protezione anti-replay.

### 2.1 Overhead del data-plane v0.7

Nel formato v0.7 il messaggio protetto aggiunge **37 byte** al plaintext:

```text
sequence number   8 B
message type      1 B
IV                12 B
GCM tag           16 B
----------------------
overhead          37 B
```

Nel workload hardware congelato:

```text
plaintext = 6 B
frame     = 43 B
```

Questo valore riguarda il wire format applicativo e non include ATT, L2CAP, Link Layer o eventuali ritrasmissioni.

## 3. Session resumption storica e v0.7 finale

Una fonte di possibile confusione è la session resumption mostrata nel PoC iniziale e nella presentazione precedente del progetto.

Il **prototipo Python storico**, antecedente alla v0.7 hardware finale, disponeva di un `SessionStore` persistente. La sessione conservava:

- `session_id`;
- `session_key`;
- timestamp di creazione;
- numero di resume riusciti.

La stessa session key poteva essere riutilizzata fino al primo limite tra:

```text
24 ore
oppure
100 resume riusciti
```

Timeout e resume falliti non consumavano il contatore. Il protocollo di resume mostrato nel PoC richiedeva circa:

```text
21 B request
+
9 B response
=
30 B applicativi
```

prima dell'overhead GATT.

Questa ottimizzazione riduceva fortemente il costo delle riconnessioni perché evitava un nuovo full handshake. Il prezzo era il riutilizzo della stessa session key, con una finestra di esposizione più ampia e senza nuova forward secrecy a ogni connessione.

### 3.1 Punto fondamentale

**La session resumption del PoC storico non è la riconnessione implementata nella v0.7 hardware finale.**

Nel profilo v0.7 utilizzato nella comparazione:

- BLE SMP è disabilitato;
- non esiste un bond BLE;
- non è stata completata una session-resumption persistente sul DK;
- i run hardware eseguono il percorso applicativo ibrido completo.

Pertanto non è corretto descrivere la v0.7 finale come una versione che riutilizza per 24 ore/100 connessioni la stessa chiave. Quella era una funzionalità del prototipo Python precedente.

## 4. v1.0: BLE L4 + ML-KEM

La v1.0 separa le responsabilità.

```text
BLE SMP Security Mode 1 Level 4
        |
        | associazione classica autenticata
        | cifratura/autenticazione del link BLE
        v
ML-KEM-768
        |
        v
SS_MLKEM
        |
        v
transcript + HKDF-SHA256
        |
        v
FINISHED_C / FINISHED_P
        |
        v
K_APP_C2P / K_APP_P2C
        |
        v
AES-256-GCM applicativo
```

L4 usa LE Secure Connections con Numeric Comparison e bonding persistente. ML-KEM rimane indipendente: il materiale SMP non viene esportato né combinato con `SS_MLKEM`.

La v1.0 non è quindi un hybrid key agreement. È una composizione a livelli tra autenticazione/protezione BLE classica e key establishment applicativo post-quantum.

## 5. Riconnessione nella v1.0

La v1.0 distingue esplicitamente:

```text
bond BLE persistente
!=
sessione applicativa persistente
```

### 5.1 Prima connessione: cold

Quando non esiste un bond:

```text
connessione BLE
->
PQ GATT negato pre-L4
->
LE Secure Connections Numeric Comparison
->
L4 autenticato
->
ML-KEM
->
CP3 / FINISHED
->
APP_SECURE
```

### 5.2 Riconnessione bonded

Quando il bond esiste:

```text
nuova connessione
->
ripristino del bond SMP
->
L4 autenticato
->
nuovo ML-KEM
->
nuovo CP3
->
nuove chiavi applicative
->
counter CP4 da zero
```

La Numeric Comparison non viene ripetuta, ma la sessione ML-KEM/applicativa viene ricreata.

Questa proprietà è stata verificata su riconnessioni bonded ripetute, reboot del DK e restart del processo Central.

### 5.3 Conseguenza

Il bonding riduce l'overhead di **associazione/autenticazione BLE** nelle connessioni successive, ma non elimina il costo del nuovo key establishment ML-KEM applicativo.

Inoltre la public key ML-KEM del DK viene generata una volta al boot e può essere riutilizzata fino al reboot; ogni sessione usa però nuova randomness di encapsulation e un nuovo `session_id`, quindi produce nuove chiavi applicative. Non viene comunque rivendicata forward secrecy rispetto a una futura compromissione della private key ML-KEM persistente.

## 6. Overhead del data-plane v1.0

Il frame CP4 è:

```text
PQV1             4 B
version          1 B
subtype          1 B
payload_len      2 B
seq              8 B
msg_type         1 B
plaintext_len    2 B
ciphertext       N B
tag             16 B
```

L'overhead applicativo è quindi:

```text
8 B PQV1 header
+ 8 B sequence
+ 1 B message type
+ 2 B plaintext length
+16 B GCM tag
=35 B
```

L'IV non è trasmesso. Viene derivato dalla chiave direzionale, dal `session_id` e dal sequence number.

Nel workload congelato:

```text
plaintext = 16 B
frame     = 51 B
```

## 7. Confronto dell'overhead per messaggio

A parità di plaintext `N`:

```text
v0.7 = N + 37 B
v1.0 = N + 35 B
```

Quindi il formato applicativo v1.0 risparmia **2 byte per messaggio** rispetto a v0.7.

| Plaintext | v0.7 | v1.0 | Overhead v0.7 | Overhead v1.0 |
|---:|---:|---:|---:|---:|
| 16 B | 53 B | 51 B | 231.3% | 218.8% |
| 64 B | 101 B | 99 B | 57.8% | 54.7% |
| 256 B | 293 B | 291 B | 14.5% | 13.7% |
| 512 B | 549 B | 547 B | 7.2% | 6.8% |
| 1024 B | 1061 B | 1059 B | 3.6% | 3.4% |

Le percentuali sono `overhead / plaintext`. Per payload grandi la reale trasmissione BLE può richiedere frammentazione; la tabella descrive soltanto il formato applicativo.

### 7.1 Il v1.0 ha quindi meno overhead radio?

Non è possibile concluderlo direttamente.

I 35 e 37 byte misurano solo il formato applicativo. v1.0 utilizza anche la cifratura/autenticazione BLE Link Layer introdotta da L4, mentre v0.7 non usa SMP. Il link protetto introduce quindi ulteriore overhead a livello BLE che non appare nel frame applicativo.

Inoltre le catture passive v1.0 diventano opache dopo l'attivazione della cifratura se non si esporta la LTK. Per questo la campagna non fornisce un confronto completo e payload-matched dei byte fisici over-the-air.

La conclusione difendibile è:

> v1.0 ha 2 byte in meno di overhead nel proprio frame applicativo, ma dai dati attuali non si può affermare che abbia meno overhead radio totale.

## 8. Overhead dell'handshake

Anche qui occorre distinguere i livelli.

### v0.7

Il full handshake deve trasportare e processare:

- public key ML-KEM;
- ciphertext ML-KEM;
- public key P-256 applicative;
- transcript ibrido;
- SAS;
- FINISHED.

### v1.0 cold

Il protocollo applicativo elimina il P-256 ECDH e il SAS custom, ma prima del percorso ML-KEM deve eseguire SMP L4 e Numeric Comparison.

### v1.0 bonded

La riconnessione non ripete la Numeric Comparison; il bond ripristina L4. Rimangono però:

- ML-KEM;
- transcript CP3;
- FINISHED;
- derivazione di nuove chiavi applicative.

Perciò L4/bonding ottimizza la parte BLE di autenticazione, ma non rende la riconnessione equivalente a un semplice resume di session key.

## 9. Risultati sperimentali

Il confronto post-v1.0 ha mantenuto separati i dataset:

```text
v0.7 hybrid:    n = 30
v1.0 bonded:    n = 30
v1.0 cold:      n = 5
```

Tempo medio `secure_machine_ms`:

```text
v0.7            3584.773 ms
v1.0 bonded     5446.180 ms
```

La v1.0 bonded è quindi risultata più lenta nell'implementazione misurata, nonostante non richieda una nuova Numeric Comparison.

Questo non è dovuto a ML-KEM in sé: il tempo medio di encapsulation lato Central è rimasto praticamente uguale:

```text
v0.7            0.653 ms
v1.0 bonded     0.638 ms
```

Le differenze principali sono state osservate nelle fasi BLE/GATT/API, in particolare public-key read e ciphertext transfer.

Quindi non è corretto affermare:

> L4 rende la riconnessione v1.0 globalmente più leggera di v0.7.

È corretto affermare:

> Il bonding L4 evita la nuova cerimonia di pairing/Numeric Comparison, mentre la v1.0 mantiene un nuovo handshake applicativo ML-KEM a ogni connessione.

## 10. Risorse

| Risorsa | v0.7 | v1.0 | Delta |
|---|---:|---:|---:|
| FLASH | 225652 B | 279428 B | +53776 B (+23.8%) |
| RAM | 106048 B | 109464 B | +3416 B (+3.2%) |
| Crypto worker stack | 28672 B | 28672 B | 0 |
| Peak osservato | 24264 B | 24264 B | 0 |

## 11. Visibilità del traffico

La cattura v0.7 ha seguito la connessione fino alla terminazione:

```text
716 packet
8.145325 s
95 ATT
0 SMP
```

Nel v1.0 cold sono stati osservati:

```text
512 packet
7.605352 s
50 ATT
9 SMP
```

mentre nel bonded:

```text
37 packet
0.945367 s
0 ATT decodificato
1 SMP
```

Dopo l'attivazione della cifratura BLE, senza la LTK il passive sniffer non può decodificare il successivo traffico ATT. Questi valori descrivono la visibilità della cattura e non rappresentano un confronto completo del volume radio.

## 12. Validazione di sicurezza

La campagna EVAL-D ha prodotto:

```text
v0.7: 7/7 PASS
v1.0: 2/2 PASS
totale: 9/9 PASS
```

I test P->C della v0.7 sono receiver-local sul Central e non packet injection BLE.

## 13. Conclusione

Le due implementazioni rappresentano due trade-off differenti.

**v0.7** concentra sicurezza classica, contributo post-quantum, autenticazione umana e canale sicuro nel protocollo applicativo. È più leggera in FLASH/RAM e più veloce nella campagna misurata.

**v1.0** delega autenticazione e protezione del link a BLE L4 e mantiene ML-KEM come key establishment applicativo post-quantum. Questo rende l'architettura più modulare e vicina al modello BLE standard, ma introduce un maggiore footprint e, nell'implementazione misurata, maggiore latenza end-to-end.

Sul piano dell'overhead:

- v1.0 ha un frame applicativo leggermente più compatto: **35 B contro 37 B**;
- il bonding v1.0 evita la nuova Numeric Comparison nelle riconnessioni;
- v1.0 esegue comunque un nuovo ML-KEM/CP3 a ogni connessione;
- il vecchio resume da 24 ore / 100 utilizzi apparteneva al PoC Python storico, non alla v0.7 hardware finale;
- non esiste al momento evidenza sufficiente per dire che v1.0 abbia meno byte radio totali rispetto a v0.7.
