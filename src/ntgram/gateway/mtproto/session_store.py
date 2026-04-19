from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass, field


@dataclass(slots=True)
class AuthSession:
    auth_key_id: int
    auth_key: bytes
    server_salt: int
    session_id: int
    user_id: int | None = None
    last_msg_id: int = 0
    seen_msg_ids: set[int] = field(default_factory=set)
    created_at: float = field(default_factory=time.time)
    qts: int = 0
    pts: int = 0
    seq: int = 0
    layer: int = 0
    date: int = field(default_factory=lambda: int(time.time()))
    pending_outgoing_msg_ids: set[int] = field(default_factory=set)

    def touch_msg_id(self, msg_id: int) -> bool:
        """Return True for new msg_id, False if replay/old."""
        if msg_id in self.seen_msg_ids:
            return False
        if self.last_msg_id and msg_id <= self.last_msg_id:
            return False
        self.seen_msg_ids.add(msg_id)
        self.last_msg_id = msg_id
        return True

    def touch_updates_state(
        self, pts_inc: int = 0, qts_inc: int = 0, seq_inc: int = 0,
    ) -> None:
        self.pts += pts_inc
        self.qts += qts_inc
        self.seq += seq_inc
        self.date = int(time.time())


@dataclass(slots=True)
class HandshakeState:
    nonce: int | None = None
    server_nonce: int | None = None
    new_nonce: int | None = None
    stage: str = "init"
    # PQ factorization
    pq: int = 0
    p: int = 0
    q: int = 0
    # DH params (server side)
    dh_secret_a: int = 0
    g_a: int = 0


class SessionStore:
    def __init__(self) -> None:
        self._handshakes: dict[int, HandshakeState] = {}
        self._sessions: dict[int, AuthSession] = {}
        self._by_user: dict[int, set[int]] = {}

    @staticmethod
    def _make_server_nonce() -> int:
        return secrets.randbits(128)

    @staticmethod
    def make_auth_key_id(auth_key: bytes) -> int:
        """auth_key_id = lower 64 bits of SHA1(auth_key), as LE uint64."""
        sha1 = hashlib.sha1(auth_key).digest()
        return int.from_bytes(sha1[-8:], "little", signed=False)

    @staticmethod
    def make_auth_key_aux_hash(auth_key: bytes) -> int:
        """auth_key_aux_hash = upper 64 bits of SHA1(auth_key), as LE uint64."""
        sha1 = hashlib.sha1(auth_key).digest()
        return int.from_bytes(sha1[:8], "little", signed=False)

    @staticmethod
    def make_server_salt(new_nonce: int, server_nonce: int) -> int:
        """server_salt = substr(new_nonce, 0, 8) XOR substr(server_nonce, 0, 8)."""
        nn = new_nonce.to_bytes(32, "little")
        sn = server_nonce.to_bytes(16, "little")
        return int.from_bytes(
            bytes(a ^ b for a, b in zip(nn[:8], sn[:8], strict=True)),
            "little",
            signed=False,
        )

    def get_or_create_handshake(self, session_id: int) -> HandshakeState:
        if session_id not in self._handshakes:
            self._handshakes[session_id] = HandshakeState()
        return self._handshakes[session_id]

    def complete_handshake(
        self,
        session_id: int,
        auth_key: bytes,
        new_nonce: int,
        server_nonce: int,
    ) -> AuthSession:
        """Register a new AuthSession with a DH-derived auth_key."""
        auth_key_id = self.make_auth_key_id(auth_key)
        server_salt = self.make_server_salt(new_nonce, server_nonce)
        session = AuthSession(
            auth_key_id=auth_key_id,
            auth_key=auth_key,
            server_salt=server_salt,
            session_id=session_id,
        )
        self._sessions[auth_key_id] = session
        self._handshakes.pop(session_id, None)
        return session

    def get_session(self, auth_key_id: int) -> AuthSession | None:
        return self._sessions.get(auth_key_id)

    def bind_user(self, auth_key_id: int, user_id: int) -> None:
        session = self._sessions.get(auth_key_id)
        if session is not None:
            if session.user_id is not None and session.user_id != user_id:
                old = self._by_user.get(session.user_id)
                if old is not None:
                    old.discard(auth_key_id)
            session.user_id = user_id
            self._by_user.setdefault(user_id, set()).add(auth_key_id)

    def register_outgoing_msg(self, auth_key_id: int, msg_id: int) -> bool:
        session = self._sessions.get(auth_key_id)
        if session is None:
            return False
        session.pending_outgoing_msg_ids.add(msg_id)
        return True

    def ack_outgoing_msgs(self, auth_key_id: int, msg_ids: list[int]) -> int:
        session = self._sessions.get(auth_key_id)
        if session is None:
            return 0
        removed = 0
        for msg_id in msg_ids:
            if msg_id in session.pending_outgoing_msg_ids:
                session.pending_outgoing_msg_ids.remove(msg_id)
                removed += 1
        return removed

    def update_layer(self, auth_key_id: int, layer: int) -> bool:
        if layer <= 0:
            return False
        session = self._sessions.get(auth_key_id)
        if session is None:
            return False
        session.layer = layer
        return True

    def get_sessions_for_user(self, user_id: int) -> list[AuthSession]:
        """Return all sessions bound to a user_id."""
        key_ids = self._by_user.get(user_id, set())
        return [
            self._sessions[kid]
            for kid in key_ids
            if kid in self._sessions
        ]
