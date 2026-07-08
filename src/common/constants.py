"""
PQ-BLE-HANDSHAKE — Costanti di protocollo.
Tutti i magic number, UUID GATT e dimensioni in un unico file.
Modifica qui se cambi algoritmo PQ o parametri.
"""

# ── BLE GATT ──────────────────────────────────────────────────
SERVICE_UUID        = "12345678-1234-1234-1234-123456789abc"
CHAR_PUBKEY_UUID    = "12345678-1234-1234-1234-123456789abd"  # READ  — pk_A
CHAR_CIPHERTEXT_UUID= "12345678-1234-1234-1234-123456789abe"  # WRITE — ciphertext
CHAR_DATA_UUID      = "12345678-1234-1234-1234-123456789abf"  # NOTIFY — encrypted data
CHAR_CONTROL_UUID   = "12345678-1234-1234-1234-123456789ac0"  # WRITE — SAS confirm

DEVICE_NAME         = "PQ-BLE-Device"

# ── ML-KEM-768 ────────────────────────────────────────────────
KEM_ALGORITHM       = "ML-KEM-768"
PK_SIZE             = 1184   # byte — ML-KEM-768 public key
CT_SIZE             = 1088   # byte — ML-KEM-768 ciphertext
SS_SIZE             = 32     # byte — shared secret

# ── Frammentazione GATT ───────────────────────────────────────
BLE_MTU             = 512    # byte — BLE 4.2+ default
FRAGMENT_PAYLOAD    = 508    # byte — MTU - 4 (header)
FRAGMENT_HEADER_SIZE= 4      # byte — [idx:1][total:1][len:2]

# ── SAS Numeric Comparison ────────────────────────────────────
SAS_DIGITS          = 6      # numero di cifre decimali
SAS_MODULUS         = 10 ** SAS_DIGITS  # 1_000_000

# ── Crittografia Canale ───────────────────────────────────────
SESSION_KEY_SIZE    = 32     # byte — AES-256
GCM_IV_SIZE         = 12     # byte — AES-GCM nonce
GCM_TAG_SIZE        = 16     # byte — AES-GCM authentication tag
SEQ_NUM_SIZE        = 8      # byte — sequence number (uint64 big-endian)

# ── Ruoli canale (binding direzionale AAD) ───────────────────
# Ogni lato cifra con il proprio ruolo; l'altro lato decifra
# aspettandosi il ruolo opposto. Previene attacchi reflection.
CENTRAL_ROLE        = b"\x01"   # Central (client) sender role
PERIPHERAL_ROLE     = b"\x02"   # Peripheral (server) sender role

# ── Message types (inclusi in AAD) ───────────────────────────
# Ogni messaggio cifrato include il tipo come AAD per impedire
# confusione tra messaggi di dati e messaggi di controllo.
MSG_TYPE_SIZE       = 1      # byte
MSG_TYPE_DATA       = b"\x01"   # dati applicativi
MSG_TYPE_CONTROL    = b"\x02"   # messaggio di controllo (es. resume)
MSG_TYPE_HANDSHAKE  = b"\x03"   # messaggio di handshake (es. SAS)

# ── HKDF ──────────────────────────────────────────────────────
HKDF_SALT           = b"PQ-BLE-HANDSHAKE-v1"
HKDF_INFO            = b"BLE-PQ-SESSION-KEY"
HKDF_HASH            = "SHA-256"

# ── Session Resumption ───────────────────────────────────────
SESSION_ID_SIZE     = 16     # byte — random session identifier
SESSION_STORE_PATH  = "data/keys/session_store.json"
REHANDSHAKE_HOURS   = 24     # forza re-handshake dopo N ore
REHANDSHAKE_SESSIONS= 100    # forza re-handshake dopo N sessioni

# ── Resume Wire Protocol ─────────────────────────────────────
RESUME_MAGIC        = b"PQBL"          # 4 byte — magic prefix
RESUME_REQ          = b"\x01"          # RESUME_REQUEST
RESUME_ACK          = b"\x02"          # RESUME_ACCEPT
RESUME_NACK         = b"\x03"          # RESUME_REJECT
RESUME_OK_NOTIFY    = b"RESUME_OK"     # notified on DATA char
RESUME_FAIL_NOTIFY  = b"RESUME_FAIL"   # notified on DATA char