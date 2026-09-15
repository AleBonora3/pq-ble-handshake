"""Atomic repo-local ticket storage, separate from historical SessionStore."""

import hashlib
import json
import math
import os
from pathlib import Path
import tempfile
import time

from .resumption import Ticket, ResumeError, Reason, domain, sized

SCHEMA = 1
DEFAULT_DIRECTORY = Path(__file__).resolve().parents[2] / "data" / "keys" / "resumption"


class TicketStore:
    def __init__(self, directory=DEFAULT_DIRECTORY, *, clock=time.time):
        self.directory, self.clock = Path(directory), clock
        self.last_reason = Reason.NO_TICKET

    def path(self, profile, peer):
        domain(profile)
        if not isinstance(peer, str) or not peer or len(peer) > 1024:
            raise ValueError("invalid peer identity")
        name = hashlib.sha256(bytes((profile,)) + peer.encode("utf-8")).hexdigest()
        return self.directory / (name + ".json")

    def load(self, profile, peer):
        ticket = None
        try:
            path = self.path(profile, peer)
            if path.stat().st_size > 8192:
                raise ValueError("oversized ticket")
            raw = json.loads(path.read_text(encoding="utf-8"))
            if (not isinstance(raw, dict) or type(raw.get("schema")) is not int
                    or raw["schema"] != SCHEMA or type(raw.get("profile")) is not int
                    or raw["profile"] != profile or raw.get("peer") != peer):
                raise ValueError("invalid ticket schema/identity")
            created, count = raw["created_at"], raw["successful_resume_count"]
            if (type(created) not in (float, int) or not math.isfinite(created)
                    or type(count) is not int or not 0 <= count <= 100):
                raise ValueError("invalid ticket age/count")
            ticket = Ticket(profile, peer, sized(bytes.fromhex(raw["resume_id"]), 16),
                bytearray(sized(bytes.fromhex(raw["k_resume"]), 32)), float(created), count)
            ticket.check(profile, peer, self.clock())
            return ticket
        except FileNotFoundError:
            self.last_reason = Reason.NO_TICKET
        except ResumeError as exc:
            self.last_reason = exc.reason
            if ticket is not None:
                ticket.clear()
            self.delete(profile, peer)
        except (ValueError, TypeError, KeyError, OSError, OverflowError):
            self.last_reason = Reason.MALFORMED
            if ticket is not None:
                ticket.clear()
        return None

    def save(self, ticket):
        if not ticket.valid:
            self.delete(ticket.profile, ticket.peer)
            return
        ticket.check(ticket.profile, ticket.peer, self.clock())
        path = self.path(ticket.profile, ticket.peer)
        self.directory.mkdir(parents=True, exist_ok=True)
        payload = {"schema": SCHEMA, "profile": ticket.profile, "peer": ticket.peer,
            "resume_id": sized(ticket.rid, 16).hex(), "k_resume": sized(ticket.root, 32).hex(),
            "created_at": ticket.created_at, "successful_resume_count": ticket.successful_resumes}
        fd, name = tempfile.mkstemp(prefix=".ticket-", dir=self.directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(payload, stream, separators=(",", ":"), allow_nan=False)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, path)
        finally:
            Path(name).unlink(missing_ok=True)

    def delete(self, profile, peer):
        self.path(profile, peer).unlink(missing_ok=True)
