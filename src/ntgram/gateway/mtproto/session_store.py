from __future__ import annotations

import hashlib
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Protocol

from ntgram.gateway.mtproto.outbox_registry import OutboxRegistry, PendingOutgoingRpc
from ntgram.gateway.mtproto.replay_window import ReplayWindow
from ntgram.gateway.mtproto.salt_schedule import (
    SERVER_SALT_INTERVAL_SEC,
    SaltSchedule,
)
from ntgram.gateway.mtproto.seq_counters import (
    MtprotoSessionCounters,
    SessionCounterStore,
)
logger = logging.getLogger(__name__)

__all__ = [
    "MtprotoSessionCounters",
    "PendingOutgoingRpc",
    "SERVER_SALT_INTERVAL_SEC",
    "TempAuthKeyBinding",
    "AuthSession",
    "AuthSessionRepository",
    "HandshakeState",
    "SessionStore",
]


@dataclass(slots=True, frozen=True)
class TempAuthKeyBinding:
    """Binding between one permanent auth key and one temporary auth key."""
    perm_auth_key_id: int
    temp_auth_key_id: int
    nonce: int
    temp_session_id: int
    expires_at: int
    bound_at: float = field(default_factory=time.time)


@dataclass(slots=True)
class AuthSession:
    """Aggregate state for one authenticated MTProto auth_key."""

    auth_key_id: int
    auth_key: bytes
    session_id: int = 0
    known_session_ids: set[int] = field(default_factory=set)
    user_id: int | None = None
    layer: int = 0
    created_at: float = field(default_factory=time.time)
    temp_auth_key_binding: TempAuthKeyBinding | None = None

    salt: SaltSchedule = field(
        default_factory=lambda: SaltSchedule(server_salt=0),
    )
    replay: ReplayWindow = field(default_factory=ReplayWindow)
    outbox: OutboxRegistry = field(default_factory=OutboxRegistry)
    counters: SessionCounterStore = field(
        default_factory=SessionCounterStore,
    )

    def __post_init__(self) -> None:
        if self.counters.auth_key_id == 0:
            self.counters.auth_key_id = self.auth_key_id

    # session multiplexing

    def bind_mtproto_session(self, session_id: int) -> bool:
        """Register a new (or validate a known) MTProto session_id."""
        is_new = session_id not in self.known_session_ids
        if self.session_id == 0:
            self.session_id = session_id
        if is_new:
            self.known_session_ids.add(session_id)
            self.counters.for_session(session_id)
            logger.info(
                "new MTProto session registered: auth_key_id=%s "
                "session_id=%s total_sessions=%s",
                self.auth_key_id,
                session_id,
                len(self.known_session_ids),
            )
        return True

    def forget_mtproto_session(self, session_id: int) -> bool:
        """Remove a multiplexed MTProto session_id (destroy_session)."""
        if session_id not in self.known_session_ids:
            return False
        self.known_session_ids.discard(session_id)
        self.counters.forget_session(session_id)
        if self.session_id == session_id:
            self.session_id = next(iter(self.known_session_ids), 0)
        return True

    # delegations preserved for backward source-compatibility

    def touch_msg_id(self, msg_id: int) -> bool:
        return self.replay.touch(msg_id)

    def is_accepted_server_salt(self, salt: int) -> bool:
        return self.salt.is_accepted(salt)

    def rotate_server_salt_if_needed(self, now: int | None = None) -> bool:
        return self.salt.rotate_if_needed(now)

    def register_future_salt_entries(
        self, entries: list[tuple[int, int, int]],
    ) -> None:
        self.salt.register_future_salt_entries(entries)

    def validate_inbound_seq_no(
        self, session_id: int, seq_no: int, *, content_related: bool,
    ) -> int | None:
        return self.counters.validate_inbound(
            session_id, seq_no, content_related=content_related,
        )

    def next_server_seq_no(
        self, session_id: int, *, content_related: bool,
    ) -> int:
        return self.counters.next_outbound(
            session_id, content_related=content_related,
        )

    # legacy field aliases

    @property
    def server_salt(self) -> int:
        return self.salt.server_salt

    @server_salt.setter
    def server_salt(self, value: int) -> None:
        self.salt.server_salt = value

    @property
    def server_salt_valid_since(self) -> int:
        return self.salt.server_salt_valid_since

    @server_salt_valid_since.setter
    def server_salt_valid_since(self, value: int) -> None:
        self.salt.server_salt_valid_since = value

    @property
    def server_salt_valid_until(self) -> int:
        return self.salt.server_salt_valid_until

    @server_salt_valid_until.setter
    def server_salt_valid_until(self, value: int) -> None:
        self.salt.server_salt_valid_until = value

    @property
    def server_salt_dirty(self) -> bool:
        return self.salt.server_salt_dirty

    @server_salt_dirty.setter
    def server_salt_dirty(self, value: bool) -> None:
        self.salt.server_salt_dirty = value

    @property
    def accepted_future_salts(self) -> dict[int, tuple[int, int]]:
        return self.salt.accepted_future_salts

    @property
    def previous_salts(self) -> dict[int, int]:
        """Recently-rotated salts still accepted within the grace window."""
        return self.salt.previous_salts

    @property
    def last_msg_id(self) -> int:
        return self.replay.last_msg_id

    @property
    def seen_msg_ids(self) -> set[int]:
        return self.replay.seen_msg_ids

    @property
    def pending_outgoing_msg_ids(self) -> set[int]:
        return self.outbox.pending_outgoing_msg_ids

    @property
    def pending_outgoing_rpcs(self) -> dict[int, PendingOutgoingRpc]:
        return self.outbox.pending_outgoing_rpcs

class AuthSessionRepository(Protocol):
    """Persistence port for completed MTProto auth sessions."""

    def load(self, auth_key_id: int) -> AuthSession | None:
        """Return a persisted session or None when the key is unknown."""

    def save(self, session: AuthSession) -> None:
        """Persist current session state needed after gateway restart."""


@dataclass(slots=True)
class HandshakeState:
    nonce: int | None = None
    server_nonce: int | None = None
    new_nonce: int | None = None
    stage: str = "init"
    pq: int = 0
    p: int = 0
    q: int = 0
    dh_secret_a: int = 0
    g_a: int = 0


class SessionStore:
    """In-memory cache of authenticated sessions, backed by an optional repository."""

    def __init__(self, repository: AuthSessionRepository | None = None) -> None:
        self._handshakes: dict[int, HandshakeState] = {}
        self._sessions: dict[int, AuthSession] = {}
        self._by_user: dict[int, set[int]] = {}
        self._repository = repository

    # crypto helpers

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

    # handshake

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
        """Register a new `AuthSession` with a DH-derived auth_key."""
        auth_key_id = self.make_auth_key_id(auth_key)
        server_salt = self.make_server_salt(new_nonce, server_nonce)
        session = AuthSession(
            auth_key_id=auth_key_id,
            auth_key=auth_key,
            # MTProto session_id is created by the client in encrypted data;
            # the handshake session_id is only a local pre-auth correlation key.
            session_id=0,
            salt=SaltSchedule(server_salt=server_salt),
            counters=SessionCounterStore(auth_key_id=auth_key_id),
        )
        self._sessions[auth_key_id] = session
        self._handshakes.pop(session_id, None)
        self.save_session(auth_key_id)
        return session

    # identity / persistence

    def get_session(self, auth_key_id: int) -> AuthSession | None:
        session = self._sessions.get(auth_key_id)
        if session is not None:
            return session
        if self._repository is None:
            return None
        session = self._repository.load(auth_key_id)
        if session is not None:
            self._sessions[auth_key_id] = session
            if session.user_id is not None:
                self._by_user.setdefault(session.user_id, set()).add(auth_key_id)
        return session

    def save_session(self, auth_key_id: int) -> bool:
        """Persist an in-memory session through the repository."""
        session = self._sessions.get(auth_key_id)
        if session is None or self._repository is None:
            return False
        self._repository.save(session)
        return True

    def mark_server_salt_clean(self, auth_key_id: int) -> None:
        """Persist a freshly rotated salt and clear the dirty flag."""
        session = self._sessions.get(auth_key_id)
        if session is None or not session.salt.server_salt_dirty:
            return
        session.salt.server_salt_dirty = False
        self.save_session(auth_key_id)

    # user index

    def bind_user(self, auth_key_id: int, user_id: int) -> None:
        session = self._sessions.get(auth_key_id)
        if session is None:
            return
        if session.user_id is not None and session.user_id != user_id:
            old = self._by_user.get(session.user_id)
            if old is not None:
                old.discard(auth_key_id)
        session.user_id = user_id
        self._by_user.setdefault(user_id, set()).add(auth_key_id)
        self.save_session(auth_key_id)

    def unbind_user(self, auth_key_id: int) -> None:
        """Clear user_id for this auth key (e.g. auth.logOut)."""
        session = self.get_session(auth_key_id)
        if session is None:
            return
        uid = session.user_id
        if uid is not None:
            bucket = self._by_user.get(uid)
            if bucket is not None:
                bucket.discard(auth_key_id)
                if not bucket:
                    self._by_user.pop(uid, None)
        session.user_id = None
        self.save_session(auth_key_id)

    def get_sessions_for_user(self, user_id: int) -> list[AuthSession]:
        """Return all in-memory sessions bound to user_id."""
        key_ids = self._by_user.get(user_id, set())
        return [
            self._sessions[kid] for kid in key_ids if kid in self._sessions
        ]

    # misc lifecycle

    def update_layer(self, auth_key_id: int, layer: int) -> bool:
        if layer <= 0:
            return False
        session = self._sessions.get(auth_key_id)
        if session is None:
            return False
        session.layer = layer
        self.save_session(auth_key_id)
        return True

    def destroy_mtproto_session(
        self, auth_key_id: int, target_session_id: int,
    ) -> bool:
        """Forget counters/state for target_session_id under auth_key_id."""
        session = self.get_session(auth_key_id)
        if session is None:
            return False
        if not session.forget_mtproto_session(target_session_id):
            return False
        self.save_session(auth_key_id)
        return True
