"""
Session Key Derivation and Secure Channel.

After authenticated ML-KEM handshake:
1. HKDF-SHA256 derives a 32-byte session key from the shared secret.
2. AES-256-GCM provides authenticated encryption for all subsequent data.

HKDF follows RFC 5869.
AES-256-GCM follows NIST SP 800-38D.
"""

import os
from typing import Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .constants import (
    SESSION_KEY_SIZE,
    SESSION_ID_SIZE,
    GCM_IV_SIZE,
    GCM_TAG_SIZE,
    SEQ_NUM_SIZE,
    MSG_TYPE_SIZE,
    MSG_TYPE_DATA,
    MSG_TYPE_CONTROL,
    CENTRAL_ROLE,
    PERIPHERAL_ROLE,
    HKDF_SALT,
    HKDF_INFO,
    RESUME_MAGIC,
    RESUME_REQ,
    RESUME_ACK,
    RESUME_NACK,
    RESUME_OK_NOTIFY,
    RESUME_FAIL_NOTIFY,
)


def derive_session_key(shared_secret: bytes) -> bytes:
    """
    Derive AES-256 session key from ML-KEM shared secret via HKDF.

    Args:
        shared_secret: 32-byte ML-KEM-768 shared secret.

    Returns:
        32-byte AES-256 session key.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=SESSION_KEY_SIZE,
        salt=HKDF_SALT,
        info=HKDF_INFO,
    )
    return hkdf.derive(shared_secret)


def generate_session_id() -> bytes:
    """
    Generate a cryptographically random session identifier.

    Returns:
        16 random bytes, suitable for use as a session_id
        in the session resumption protocol.
    """
    return os.urandom(SESSION_ID_SIZE)


def build_resume_request(session_id: bytes) -> bytes:
    """
    Build the wire-format resume request.

    Format: RESUME_MAGIC (4) || RESUME_REQ (1) || session_id (16)
    Total: 21 bytes.
    """
    if len(session_id) != SESSION_ID_SIZE:
        raise ValueError(
            f"session_id must be {SESSION_ID_SIZE} bytes, "
            f"got {len(session_id)}"
        )
    return RESUME_MAGIC + RESUME_REQ + session_id


def parse_control_message(data: bytes) -> dict:
    """
    Parse a control-characteristic message.

    Returns a dict:
      - {"type": "resume_request", "session_id": bytes}   if resume request
      - {"type": "sas_confirm"}                           if SAS OK
      - {"type": "unknown", "raw": bytes}                 otherwise
    """
    if data == b"OK":
        return {"type": "sas_confirm"}

    if (len(data) == 5 + SESSION_ID_SIZE
            and data[:4] == RESUME_MAGIC
            and data[4:5] == RESUME_REQ):
        session_id = data[5:]
        return {"type": "resume_request", "session_id": session_id}

    return {"type": "unknown", "raw": data}


class SecureChannel:
    """
    Bidirectional secure channel using AES-256-GCM with
    authenticated associated data (AAD) and replay protection.

    AAD binds each message to the session, the sender's role,
    a monotonically increasing sequence number, and the message type:

        AAD = session_id (16) || sender_role (1) || seq_num (8) || msg_type (1)

    Wire format:

        seq_num (8) || msg_type (1) || iv (12) || ciphertext || tag (16)

    Security properties:
    - **Confidentiality + integrity**: AES-256-GCM (AEAD).
    - **Replay protection**: receiver rejects any message whose
      sequence number is not strictly greater than the last
      accepted one.
    - **Direction separation**: each side encrypts with its own
      role and decrypts expecting the peer's role.  A message
      sent by the central cannot be replayed back to the central
      because the AAD role would not match (reflection attack
      prevention).
    - **Session binding**: the session_id in the AAD prevents
      cross-session message confusion.
    - **Message-type binding**: the msg_type in the AAD prevents
      substitution of a data message for a control message (or
      vice versa) even if the ciphertext is otherwise valid.
    """

    def __init__(
        self,
        session_key: bytes,
        session_id: bytes | None = None,
        role: bytes | None = None,
    ):
        if len(session_key) != SESSION_KEY_SIZE:
            raise ValueError(
                f"Session key must be {SESSION_KEY_SIZE} bytes, "
                f"got {len(session_key)}"
            )
        self._aesgcm = AESGCM(session_key)
        self._session_id = session_id or b"\x00" * SESSION_ID_SIZE
        self._role = role or b"\x00"

        # Peer role: used in decrypt AAD (expect the other party's role)
        if role == CENTRAL_ROLE:
            self._peer_role = PERIPHERAL_ROLE
        elif role == PERIPHERAL_ROLE:
            self._peer_role = CENTRAL_ROLE
        else:
            self._peer_role = b"\x00"

        self._send_seq = 0       # next sequence number to use
        self._last_recv_seq = -1  # last accepted sequence number
        self._sent_count = 0
        self._recv_count = 0

    def _build_aad(self, seq: int, role: bytes, msg_type: bytes) -> bytes:
        """Build the AAD for a given sequence number, sender role, and message type."""
        return (
            self._session_id
            + role
            + seq.to_bytes(SEQ_NUM_SIZE, "big")
            + msg_type
        )

    def encrypt(self, plaintext: bytes, msg_type: bytes = MSG_TYPE_DATA) -> bytes:
        """
        Encrypt plaintext with AES-256-GCM.

        Args:
            plaintext: Data to encrypt.
            msg_type: Message type byte (MSG_TYPE_DATA or MSG_TYPE_CONTROL).

        Returns: seq_num (8) || msg_type (1) || iv (12) || ciphertext || tag (16)
        """
        seq = self._send_seq
        iv = os.urandom(GCM_IV_SIZE)
        aad = self._build_aad(seq, self._role, msg_type)
        ciphertext_with_tag = self._aesgcm.encrypt(iv, plaintext, aad)
        self._send_seq += 1
        self._sent_count += 1
        return (
            seq.to_bytes(SEQ_NUM_SIZE, "big")
            + msg_type
            + iv
            + ciphertext_with_tag
        )

    def decrypt(self, wire_data: bytes, msg_type: bytes = MSG_TYPE_DATA) -> bytes:
        """
        Decrypt wire format: seq_num (8) || msg_type (1) || iv (12) || ciphertext || tag.

        The msg_type extracted from the wire must match the expected msg_type.

        Returns plaintext.

        Raises:
            ValueError: If wire data is too short, message type mismatch,
                        or replay/out-of-order detected.
            InvalidTag: If authentication fails (tampering detected).
        """
        min_len = SEQ_NUM_SIZE + MSG_TYPE_SIZE + GCM_IV_SIZE + GCM_TAG_SIZE
        if len(wire_data) < min_len:
            raise ValueError(
                f"Wire data too short: {len(wire_data)} bytes. "
                f"Need at least {min_len}"
            )

        seq = int.from_bytes(wire_data[:SEQ_NUM_SIZE], "big")
        wire_msg_type = wire_data[SEQ_NUM_SIZE:SEQ_NUM_SIZE + MSG_TYPE_SIZE]
        iv_start = SEQ_NUM_SIZE + MSG_TYPE_SIZE
        iv = wire_data[iv_start:iv_start + GCM_IV_SIZE]
        ciphertext_with_tag = wire_data[iv_start + GCM_IV_SIZE:]

        # Message-type check
        if wire_msg_type != msg_type:
            raise ValueError(
                f"Message type mismatch: expected {msg_type.hex()}, "
                f"got {wire_msg_type.hex()}"
            )

        # Replay / out-of-order protection
        if seq <= self._last_recv_seq:
            raise ValueError(
                f"Replay or out-of-order message detected: "
                f"seq {seq} <= last accepted {self._last_recv_seq}"
            )

        aad = self._build_aad(seq, self._peer_role, wire_msg_type)
        plaintext = self._aesgcm.decrypt(iv, ciphertext_with_tag, aad)
        self._last_recv_seq = seq
        self._recv_count += 1
        return plaintext

    @property
    def sent_count(self) -> int:
        return self._sent_count

    @property
    def recv_count(self) -> int:
        return self._recv_count
