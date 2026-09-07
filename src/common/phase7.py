"""Hybrid ML-KEM-768/P-256 primitives for protocol version 0.7.

This module is deliberately independent from the v0.5 and v0.6 runtime
protocols.  It defines only the cryptographic building blocks needed by the
first Phase 7 checkpoint; it does not define BLE messages or handshake state.
"""

from dataclasses import dataclass
import hashlib
import hmac

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


PHASE7_DOMAIN = b"PQ-BLE-HANDSHAKE-v0.7"
PHASE7_CENTRAL_ROLE = b"\x01"
PHASE7_PERIPHERAL_ROLE = b"\x02"
PHASE7_KDF_INFO = b"PQ-BLE-HANDSHAKE-v0.7/hybrid-key-schedule"
PHASE7_SAS_LABEL = b"PQ-BLE-HANDSHAKE-v0.7/SAS"
PHASE7_FINISHED_C_LABEL = b"PQ-BLE-HANDSHAKE-v0.7/FINISHED/C"
PHASE7_FINISHED_P_LABEL = b"PQ-BLE-HANDSHAKE-v0.7/FINISHED/P"
PHASE7_C2P_LABEL = b"PQ-BLE-TRAFFIC-v0.7/CENTRAL-TO-PERIPHERAL"
PHASE7_P2C_LABEL = b"PQ-BLE-TRAFFIC-v0.7/PERIPHERAL-TO-CENTRAL"

PHASE7_SESSION_ID_SIZE = 16
PHASE7_MLKEM_PUBLIC_KEY_SIZE = 1184
PHASE7_MLKEM_CIPHERTEXT_SIZE = 1088
PHASE7_P256_PRIVATE_KEY_SIZE = 32
PHASE7_P256_PUBLIC_KEY_SIZE = 65
PHASE7_SHARED_SECRET_SIZE = 32
PHASE7_HYBRID_IKM_SIZE = 68
PHASE7_TRANSCRIPT_SIZE = 2457
PHASE7_HASH_SIZE = 32
PHASE7_KEY_SIZE = 32
PHASE7_KEY_BLOCK_SIZE = 128
PHASE7_SAS_MODULUS = 1_000_000

# Order of NIST P-256. This is used only to reject invalid deterministic test
# scalars before asking the cryptography backend to construct a private key.
_P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
    16,
)


@dataclass(frozen=True)
class Phase7Keys:
    """The four independent 32-byte outputs of the v0.7 key schedule."""

    application: bytes
    sas: bytes
    finished_c: bytes
    finished_p: bytes


@dataclass(frozen=True)
class Phase7TrafficKeys:
    """Independent v0.7 application traffic keys."""

    central_to_peripheral: bytes
    peripheral_to_central: bytes


def _require_size(name: str, value: bytes, expected: int) -> bytes:
    value = bytes(value)
    if len(value) != expected:
        raise ValueError(f"{name} must be {expected} bytes, got {len(value)}")
    return value


def _length_prefixed(value: bytes) -> bytes:
    if len(value) > 0xFFFF:
        raise ValueError("transcript field exceeds the u16 length limit")
    return len(value).to_bytes(2, "big") + value


def generate_p256_private_key() -> ec.EllipticCurvePrivateKey:
    """Generate a production-random NIST P-256 private key."""

    return ec.generate_private_key(ec.SECP256R1())


def p256_private_key_from_scalar(
    scalar: int,
) -> ec.EllipticCurvePrivateKey:
    """Create a deterministic TEST-ONLY P-256 key from an integer scalar."""

    if not isinstance(scalar, int) or isinstance(scalar, bool):
        raise TypeError("P-256 private scalar must be an integer")
    if not 1 <= scalar < _P256_ORDER:
        raise ValueError("P-256 private scalar is outside the valid range")
    return ec.derive_private_key(scalar, ec.SECP256R1())


def serialize_p256_public_key(
    key: ec.EllipticCurvePublicKey | ec.EllipticCurvePrivateKey,
) -> bytes:
    """Serialize a P-256 public key as SEC1 uncompressed ``0x04 || X || Y``."""

    public_key = key.public_key() if isinstance(
        key, ec.EllipticCurvePrivateKey
    ) else key
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise TypeError("key must be an elliptic-curve public or private key")
    if not isinstance(public_key.curve, ec.SECP256R1):
        raise ValueError("public key must use NIST P-256")

    encoded = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    if (
        len(encoded) != PHASE7_P256_PUBLIC_KEY_SIZE
        or encoded[0] != 0x04
    ):
        raise RuntimeError("unexpected P-256 SEC1 public-key encoding")
    return encoded


def load_p256_public_key(encoded: bytes) -> ec.EllipticCurvePublicKey:
    """Validate and load one exact 65-byte P-256 SEC1 public key."""

    encoded = _require_size(
        "P-256 public key", encoded, PHASE7_P256_PUBLIC_KEY_SIZE
    )
    if encoded[0] != 0x04:
        raise ValueError("P-256 public key must use SEC1 uncompressed format")
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), encoded
        )
    except ValueError as exc:
        raise ValueError("invalid P-256 public key") from exc


def derive_p256_ecdh_shared_secret(
    private_key: ec.EllipticCurvePrivateKey,
    peer_public_key: bytes | ec.EllipticCurvePublicKey,
) -> bytes:
    """Derive the exact 32-byte raw P-256 ECDH shared secret."""

    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise TypeError("private_key must be an elliptic-curve private key")
    if not isinstance(private_key.curve, ec.SECP256R1):
        raise ValueError("private key must use NIST P-256")

    if isinstance(peer_public_key, (bytes, bytearray, memoryview)):
        peer = load_p256_public_key(bytes(peer_public_key))
    elif isinstance(peer_public_key, ec.EllipticCurvePublicKey):
        if not isinstance(peer_public_key.curve, ec.SECP256R1):
            raise ValueError("peer public key must use NIST P-256")
        peer = peer_public_key
    else:
        raise TypeError("peer_public_key must be SEC1 bytes or a public key")

    shared_secret = private_key.exchange(ec.ECDH(), peer)
    if len(shared_secret) != PHASE7_SHARED_SECRET_SIZE:
        raise RuntimeError("unexpected P-256 ECDH shared-secret size")
    return shared_secret


def _validate_transcript_public_key(name: str, encoded: bytes) -> bytes:
    encoded = _require_size(name, encoded, PHASE7_P256_PUBLIC_KEY_SIZE)
    if encoded[0] != 0x04:
        raise ValueError(f"{name} must use SEC1 uncompressed format")
    return encoded


def build_phase7_transcript(
    session_id: bytes,
    mlkem_public_key: bytes,
    mlkem_ciphertext: bytes,
    central_p256_public_key: bytes,
    peripheral_p256_public_key: bytes,
) -> bytes:
    """Serialize the exact eight-field canonical v0.7 transcript."""

    session_id = _require_size(
        "session_id", session_id, PHASE7_SESSION_ID_SIZE
    )
    mlkem_public_key = _require_size(
        "ML-KEM public key",
        mlkem_public_key,
        PHASE7_MLKEM_PUBLIC_KEY_SIZE,
    )
    mlkem_ciphertext = _require_size(
        "ML-KEM ciphertext",
        mlkem_ciphertext,
        PHASE7_MLKEM_CIPHERTEXT_SIZE,
    )
    central_p256_public_key = _validate_transcript_public_key(
        "Central P-256 public key", central_p256_public_key
    )
    peripheral_p256_public_key = _validate_transcript_public_key(
        "Peripheral P-256 public key", peripheral_p256_public_key
    )

    transcript = b"".join(
        _length_prefixed(field)
        for field in (
            PHASE7_DOMAIN,
            PHASE7_CENTRAL_ROLE,
            PHASE7_PERIPHERAL_ROLE,
            session_id,
            mlkem_public_key,
            mlkem_ciphertext,
            central_p256_public_key,
            peripheral_p256_public_key,
        )
    )
    if len(transcript) != PHASE7_TRANSCRIPT_SIZE:
        raise RuntimeError("unexpected canonical v0.7 transcript size")
    return transcript


def compute_phase7_transcript_hash(
    session_id: bytes,
    mlkem_public_key: bytes,
    mlkem_ciphertext: bytes,
    central_p256_public_key: bytes,
    peripheral_p256_public_key: bytes,
) -> bytes:
    """Return SHA-256 of the canonical v0.7 transcript."""

    return hashlib.sha256(
        build_phase7_transcript(
            session_id,
            mlkem_public_key,
            mlkem_ciphertext,
            central_p256_public_key,
            peripheral_p256_public_key,
        )
    ).digest()


def build_hybrid_ikm(ss_mlkem: bytes, ss_ecdh: bytes) -> bytes:
    """Construct ``u16be(32) || SS_MLKEM || u16be(32) || SS_ECDH``."""

    ss_mlkem = _require_size(
        "ML-KEM shared secret", ss_mlkem, PHASE7_SHARED_SECRET_SIZE
    )
    ss_ecdh = _require_size(
        "ECDH shared secret", ss_ecdh, PHASE7_SHARED_SECRET_SIZE
    )
    hybrid_ikm = _length_prefixed(ss_mlkem) + _length_prefixed(ss_ecdh)
    if len(hybrid_ikm) != PHASE7_HYBRID_IKM_SIZE:
        raise RuntimeError("unexpected hybrid IKM size")
    return hybrid_ikm


def derive_phase7_keys(
    ss_mlkem: bytes,
    ss_ecdh: bytes,
    transcript_hash: bytes,
) -> Phase7Keys:
    """Derive and split the exact 128-byte v0.7 hybrid key block."""

    transcript_hash = _require_size(
        "transcript_hash", transcript_hash, PHASE7_HASH_SIZE
    )
    hybrid_ikm = build_hybrid_ikm(ss_mlkem, ss_ecdh)
    key_block = bytearray(
        HKDF(
            algorithm=hashes.SHA256(),
            length=PHASE7_KEY_BLOCK_SIZE,
            salt=transcript_hash,
            info=PHASE7_KDF_INFO,
        ).derive(hybrid_ikm)
    )
    try:
        return Phase7Keys(
            application=bytes(key_block[0:32]),
            sas=bytes(key_block[32:64]),
            finished_c=bytes(key_block[64:96]),
            finished_p=bytes(key_block[96:128]),
        )
    finally:
        key_block[:] = b"\x00" * len(key_block)


def compute_phase7_sas(sas_key: bytes, transcript_hash: bytes) -> int:
    """Compute the v0.7 six-digit Numeric Comparison value."""

    sas_key = _require_size("sas_key", sas_key, PHASE7_KEY_SIZE)
    transcript_hash = _require_size(
        "transcript_hash", transcript_hash, PHASE7_HASH_SIZE
    )
    sas_mac = hmac.digest(
        sas_key, PHASE7_SAS_LABEL + transcript_hash, "sha256"
    )
    return int.from_bytes(sas_mac, "big") % PHASE7_SAS_MODULUS


def format_phase7_sas(sas: int) -> str:
    """Render a valid v0.7 SAS as exactly six decimal digits."""

    if not 0 <= sas < PHASE7_SAS_MODULUS:
        raise ValueError("SAS must be in [0, 999999]")
    return f"{sas:06d}"


def _compute_finished(
    finished_key: bytes,
    label: bytes,
    transcript_hash: bytes,
) -> bytes:
    finished_key = _require_size(
        "finished_key", finished_key, PHASE7_KEY_SIZE
    )
    transcript_hash = _require_size(
        "transcript_hash", transcript_hash, PHASE7_HASH_SIZE
    )
    return hmac.digest(
        finished_key, label + transcript_hash, "sha256"
    )


def compute_phase7_finished_c(
    finished_key: bytes, transcript_hash: bytes
) -> bytes:
    """Compute the full v0.7 Central FINISHED value."""

    return _compute_finished(
        finished_key, PHASE7_FINISHED_C_LABEL, transcript_hash
    )


def compute_phase7_finished_p(
    finished_key: bytes, transcript_hash: bytes
) -> bytes:
    """Compute the full v0.7 Peripheral FINISHED value."""

    return _compute_finished(
        finished_key, PHASE7_FINISHED_P_LABEL, transcript_hash
    )


def derive_phase7_traffic_keys(
    application_root_key: bytes,
) -> Phase7TrafficKeys:
    """Derive the direction-separated v0.7 application traffic keys."""

    application_root_key = _require_size(
        "application root key", application_root_key, PHASE7_KEY_SIZE
    )
    return Phase7TrafficKeys(
        central_to_peripheral=hmac.digest(
            application_root_key, PHASE7_C2P_LABEL, "sha256"
        ),
        peripheral_to_central=hmac.digest(
            application_root_key, PHASE7_P2C_LABEL, "sha256"
        ),
    )
