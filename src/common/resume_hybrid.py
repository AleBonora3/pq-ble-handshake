"""v0.8 adapter for the unchanged v0.7 authenticated application data plane."""

from .constants import CENTRAL_ROLE, MSG_TYPE_DATA
from .resumption import V08
from .session import SecureChannel


class HybridApplication:
    """Same Secure Data endpoint, explicit random IV and PING/PONG as v0.7.

    The full/resumed handshake owns the fresh directional keys. Dropping these
    backend objects releases their key copies; Python cannot guarantee erasure.
    """
    def __init__(self, session):
        if session.profile != V08 or session.state != "APP_SECURE":
            raise ValueError("v0.8 authenticated application session required")
        self.session = session
        self.c2p = SecureChannel(bytes(session.app_c2p), session.session_id, CENTRAL_ROLE)
        self.p2c = SecureChannel(bytes(session.app_p2c), session.session_id, CENTRAL_ROLE)

    def _ready(self):
        if self.session.state != "APP_SECURE" or self.c2p is None or self.p2c is None:
            raise ValueError("v0.8 application session closed")

    def encrypt_ping(self, round_index, mtu):
        self._ready()
        if not 0 <= round_index <= 9 or mtu < 46:
            raise ValueError("invalid v0.7 test round/MTU")
        return self.c2p.encrypt(f"PING {round_index}".encode("ascii"), MSG_TYPE_DATA)

    def accept_pong(self, raw, round_index, mtu):
        self._ready()
        if len(raw) != 43 or len(raw) > mtu - 3 or int.from_bytes(raw[:8], "big") != round_index:
            raise ValueError("invalid v0.7 PONG size/sequence")
        if self.p2c.decrypt(raw, MSG_TYPE_DATA) != f"PONG {round_index}".encode("ascii"):
            raise ValueError("invalid v0.7 PONG plaintext")

    def clear(self):
        self.c2p = self.p2c = None
        self.session.clear()
