# Protocollo PQ-BLE-HANDSHAKE — Specifica Formale

## 1. Introduzione

PQ-BLE-HANDSHAKE è un protocollo di handshake post-quantum a livello
applicativo che opera sopra BLE GATT. Stabilisce un canale sicuro
autenticato resistente ad attacchi quantistici (store-now-decrypt-later).

### 1.1 Modello di riferimento

```
+-------------------------------------------------+
|  PQ-BLE-HANDSHAKE (Application Layer)          |
|  - ML-KEM-768 key encapsulation                |
|  - SAS Numeric Comparison (authentication)     |
|  - AES-256-GCM encrypted channel               |
+-------------------------------------------------+
|  GATT (BLE Generic Attribute Profile)          |
|  - Custom service: 12345678-...                |
|  - Characteristics: pubkey, ciphertext, data   |
+-------------------------------------------------+
|  BLE Stack (L2CAP, Link Layer, Physical)       |
|  - Untouched, standard BLE 4.2+               |
+-------------------------------------------------+
```

## 2. Costanti e Parametri

| Parametro | Valore | Note |
|---|---|---|
| Algoritmo KEM | ML-KEM-768 | NIST FIPS 203, livello sicurezza V |
| Public key size | 1184 byte | |
| Ciphertext size | 1088 byte | |
| Shared secret size | 32 byte | |
| SAS digits | 6 | 1/1.000.000 false accept rate |
| Cipher suite | AES-256-GCM | AEAD |
| Session key size | 32 byte | |
| Nonce (IV) size | 12 byte | Random, mai riusato |
| Tag size | 16 byte | Authentication tag |
| HKDF hash | SHA-256 | RFC 5869 |
| MTU BLE | 512 byte | BLE 4.2+ default |
| Fragment header | 4 byte | [idx:1][total:1][len:2] |

## 3. GATT Service Definition

### Service UUID
`12345678-1234-1234-1234-123456789abc`

### Characteristics

| Nome | UUID | Proprietà | Descrizione |
|---|---|---|---|
| Public Key | `...9abd` | READ | pk_A del Peripheral (1184B, frammentato) |
| Ciphertext | `...9abe` | WRITE | ct dal Central (1088B, frammentato) |
| Data | `...9abf` | NOTIFY | Dati cifrati AES-256-GCM |
| Control | `...9ac0` | WRITE | Controllo (SAS confirm) |

## 4. Flusso del Protocollo

### Fase 1: Connessione BLE (standard)
- Peripheral: advertising con nome "PQ-BLE-Device"
- Central: scan → connect()

### Fase 2: Scambio Chiavi ML-KEM
```
Peripheral:  keygen() → (sk_A, pk_A)
             expose pk_A on GATT READ

Central:     GATT READ → pk_A
             encapsulate(pk_A) → (ct, ss)
             GATT WRITE → ct

Peripheral:  GATT receive → ct
             decapsulate(sk_A, ct) → ss
```

### Fase 3: SAS Numeric Comparison
```
Entrambi:    transcript = pk_A || ct || ss
             commitment = SHA-256(transcript)
             sas = int(commitment[0:4]) mod 10^6
             display(sas) → user confirmation
```

### Fase 4: Derivazione Chiave di Sessione
```
Entrambi:    session_key = HKDF-SHA256(
                 ikm = ss,
                 salt = "PQ-BLE-HANDSHAKE-v1",
                 info = "BLE-PQ-SESSION-KEY",
                 length = 32
             )
```

### Fase 5: Canale Cifrato
```
Sender:      iv = random(12)
             (ct, tag) = AES-256-GCM.encrypt(session_key, iv, plaintext)
             GATT NOTIFY(iv || ct || tag)

Receiver:    GATT receive → iv || ct || tag
             plaintext = AES-256-GCM.decrypt(session_key, iv, ct, tag)
             verify tag (automatico in AES-GCM)
```

## 5. Sicurezza

### Threat Model
- **Attaccante passivo**: può sniffare tutti i pacchetti BLE
- **Attaccante attivo**: può intercettare, modificare, iniettare pacchetti GATT
- **Assunzione**: l'utente verifica correttamente il SAS (confronto visivo)

### Proprietà di sicurezza
- **Confidenzialità post-quantum**: ML-KEM-768 resiste a Shor (quantum) e a lattice reduction (classico)
- **Autenticazione**: SAS Numeric Comparison lega le identità con P(false accept) = 10⁻⁶
- **Forward secrecy**: ogni sessione genera nuove chiavi effimere ML-KEM
- **Integrità**: AES-256-GCM autentica ogni messaggio

## 6. Frammentazione GATT

```
Frame (max 512 byte):
┌──────┬──────┬──────────┬─────────────────────────┐
│ idx  │ total│ pay_len  │ payload                 │
│ u8   │ u8   │ u16 (BE) │ up to 508 bytes         │
└──────┴──────┴──────────┴─────────────────────────┘

ML-KEM-768 pk (1184B):  ceil(1184/508) = 3 fragments
ML-KEM-768 ct (1088B):  ceil(1088/508) = 3 fragments
Total GATT packets for handshake: 6
```

## 7. Riferimenti

- NIST FIPS 203: Module-Lattice-based Key-Encapsulation Mechanism Standard
- Bluetooth Core Specification 5.4, Vol. 3, Part H: Security Manager
- RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- NIST SP 800-38D: Recommendation for Block Cipher Modes: Galois/Counter Mode (GCM)