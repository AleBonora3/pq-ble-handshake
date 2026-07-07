"""
Session Store — persistent key-value storage for session resumption.

After a successful PQ handshake, the (session_id, session_key) pair
is saved locally. On reconnection, the central can send a resume
request with the session_id; if the peripheral still has it, both
devices skip the full handshake and reuse the existing session key.

Uses a JSON file for persistence.  Session expiry is enforced on load.
"""

import json
import os
import time
from dataclasses import dataclass, field
from typing import Dict, Optional

from .constants import SESSION_ID_SIZE, REHANDSHAKE_HOURS


@dataclass
class SessionEntry:
    """A stored session."""
    session_key: bytes
    created_at: float = field(default_factory=time.time)
    usage_count: int = 0

    def to_dict(self) -> dict:
        return {
            "session_key": self.session_key.hex(),
            "created_at": self.created_at,
            "usage_count": self.usage_count,
        }

    @staticmethod
    def from_dict(d: dict) -> "SessionEntry":
        return SessionEntry(
            session_key=bytes.fromhex(d["session_key"]),
            created_at=d.get("created_at", time.time()),
            usage_count=d.get("usage_count", 0),
        )


class SessionStore:
    """
    Persistent store for session keys.

    Thread-safe for the single-asyncio-event-loop pattern used
    throughout PQ-BLE-HANDSHAKE.

    Usage:
        store = SessionStore("data/keys/session_store.json")
        store.save(session_id, session_key)
        key = store.load(session_id)   # None if expired or missing
        store.delete(session_id)
    """

    def __init__(self, storage_path: str, max_age_hours: float = REHANDSHAKE_HOURS):
        self._path = storage_path
        self._max_age_hours = max_age_hours
        self._sessions: Dict[str, SessionEntry] = {}
        self._load_from_disk()

    # ── public API ──────────────────────────────────────────

    def save(self, session_id: bytes, session_key: bytes) -> None:
        """
        Save or overwrite a session.

        Args:
            session_id: SESSION_ID_SIZE-byte random identifier.
            session_key: 32-byte AES-256 session key.
        """
        if len(session_id) != SESSION_ID_SIZE:
            raise ValueError(
                f"session_id must be {SESSION_ID_SIZE} bytes, "
                f"got {len(session_id)}"
            )

        sid_hex = session_id.hex()
        self._sessions[sid_hex] = SessionEntry(session_key=session_key)
        self._persist()

    def load(self, session_id: bytes) -> Optional[bytes]:
        """
        Load a stored session key, or None if expired / missing.

        Automatically increments the usage counter and re-persists.
        Removes expired entries on access.
        """
        self._expire_old()

        sid_hex = session_id.hex()
        entry = self._sessions.get(sid_hex)
        if entry is None:
            return None

        entry.usage_count += 1
        self._persist()
        return entry.session_key

    def delete(self, session_id: bytes) -> None:
        """Remove a session entry."""
        sid_hex = session_id.hex()
        self._sessions.pop(sid_hex, None)
        self._persist()

    def has(self, session_id: bytes) -> bool:
        """Check whether a session_id is present and not expired."""
        self._expire_old()
        return session_id.hex() in self._sessions

    def list_ids(self) -> list:
        """Return list of (session_id_hex, created_at, usage_count)."""
        self._expire_old()
        return [
            (sid, e.created_at, e.usage_count)
            for sid, e in self._sessions.items()
        ]

    def expire_older_than(self, max_age_hours: float | None = None) -> int:
        """
        Remove all sessions older than max_age_hours.
        Returns the number of removed entries.
        """
        threshold = max_age_hours or self._max_age_hours
        cutoff = time.time() - threshold * 3600

        expired = [
            sid for sid, e in self._sessions.items()
            if e.created_at < cutoff
        ]
        for sid in expired:
            del self._sessions[sid]

        if expired:
            self._persist()
        return len(expired)

    @property
    def count(self) -> int:
        return len(self._sessions)

    # ── internal ────────────────────────────────────────────

    def _expire_old(self) -> None:
        """Remove sessions past their max age."""
        self.expire_older_than(self._max_age_hours)

    def _load_from_disk(self) -> None:
        """Load sessions from the JSON file, skipping expired ones."""
        if not os.path.exists(self._path):
            return

        try:
            with open(self._path, "r") as f:
                raw = json.load(f)
        except (json.JSONDecodeError, IOError):
            return

        cutoff = time.time() - self._max_age_hours * 3600
        for sid_hex, d in raw.items():
            entry = SessionEntry.from_dict(d)
            if entry.created_at >= cutoff:
                self._sessions[sid_hex] = entry

    def _persist(self) -> None:
        """Write all sessions to disk as JSON."""
        os.makedirs(os.path.dirname(self._path), exist_ok=True)

        payload = {
            sid: entry.to_dict()
            for sid, entry in self._sessions.items()
        }
        with open(self._path, "w") as f:
            json.dump(payload, f, indent=2)