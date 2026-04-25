from __future__ import annotations

import hashlib
import logging
import secrets
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Protocol

MAX_SEEN_MSG_IDS = 8192
logger = logging.getLogger(__name__)


@dataclass(slots=True)
class MtprotoSessionCounters:
    """Per MTProto session_id sequence number counters.

    MTProto specifies that msg_seqno is session-scoped: a client may share
    one auth_key across several TCP connections/sessions, each with independent
    sequence numbering.
    """
    inbound_content_count: int = 0
    outbound_content_count: int = 0


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
    auth_key_id: int
    auth_key: bytes
    server_salt: int
    session_id: int
    known_session_ids: set[int] = field(default_factory=set)
    # seq counters are per MTProto session_id (not per auth_key_id)
    _session_counters: dict[int, MtprotoSessionCounters] = field(default_factory=dict)
    user_id: int | None = None
    last_msg_id: int = 0
    seen_msg_ids: set[int] = field(default_factory=set)
    seen_msg_id_order: deque[int] = field(default_factory=deque)
    created_at: float = field(default_factory=time.time)
    qts: int = 0
    pts: int = 0
    seq: int = 0
    layer: int = 0
    date: int = field(default_factory=lambda: int(time.time()))
    pending_outgoing_msg_ids: set[int] = field(default_factory=set)
    temp_auth_key_binding: TempAuthKeyBinding | None = None
    # Salts issued by get_future_salts: salt -> (valid_since, valid_until) unix seconds.
    accepted_future_salts: dict[int, tuple[int, int]] = field(default_factory=dict)

    def _counters_for(self, session_id: int) -> MtprotoSessionCounters:
        """Return (creating if needed) the per-session seq counters."""
        if session_id not in self._session_counters:
            self._session_counters[session_id] = MtprotoSessionCounters()
        return self._session_counters[session_id]

    def touch_msg_id(self, msg_id: int) -> bool:
        """Return True for new msg_id, False if replay/old."""
        if msg_id in self.seen_msg_ids:
            return False
        if self.last_msg_id and msg_id <= self.last_msg_id:
            return False
        self.seen_msg_ids.add(msg_id)
        self.seen_msg_id_order.append(msg_id)
        while len(self.seen_msg_id_order) > MAX_SEEN_MSG_IDS:
            old_msg_id = self.seen_msg_id_order.popleft()
            self.seen_msg_ids.discard(old_msg_id)
        self.last_msg_id = msg_id
        return True

    def bind_mtproto_session(self, session_id: int) -> bool:
        """Register a new (or validate a known) MTProto session_id.

        Multiple session_ids per auth_key_id are allowed by MTProto spec.
        Each session gets its own independent seq_no counters.
        Returns True always (session is registered); never rejects a valid session_id.
        """
        is_new = session_id not in self.known_session_ids
        if self.session_id == 0:
            self.session_id = session_id
        if is_new:
            self.known_session_ids.add(session_id)
            # Initialize per-session counters eagerly.
            self._counters_for(session_id)
            logger.info(
                "new MTProto session registered: auth_key_id=%s session_id=%s total_sessions=%s",
                self.auth_key_id,
                session_id,
                len(self.known_session_ids),
            )
        return True

    def register_future_salt_entries(
        self, entries: list[tuple[int, int, int]],
    ) -> None:
        """Register salts from ``get_future_salts`` (valid_since, valid_until, salt)."""
        now = int(time.time())
        expired = [s for s, (_, vu) in self.accepted_future_salts.items() if vu < now]
        for salt in expired:
            self.accepted_future_salts.pop(salt, None)
        for valid_since, valid_until, salt in entries:
            if salt == self.server_salt or salt == 0:
                continue
            self.accepted_future_salts[salt] = (valid_since, valid_until)

    def is_accepted_server_salt(self, salt: int) -> bool:
        """True if ``salt`` matches primary server salt or a valid issued future salt."""
        if salt == self.server_salt:
            return True
        window = self.accepted_future_salts.get(salt)
        if window is None:
            return False
        valid_since, valid_until = window
        now = int(time.time())
        return valid_since <= now <= valid_until

    def forget_mtproto_session(self, mtproto_session_id: int) -> bool:
        """Remove another MTProto session_id for this auth key (destroy_session).

        Returns True if the session_id was known and removed.
        """
        if mtproto_session_id not in self.known_session_ids:
            return False
        self.known_session_ids.discard(mtproto_session_id)
        self._session_counters.pop(mtproto_session_id, None)
        if self.session_id == mtproto_session_id:
            self.session_id = next(iter(self.known_session_ids), 0)
        return True

    def validate_inbound_seq_no(
        self, session_id: int, seq_no: int, *, content_related: bool,
    ) -> int | None:
        """Return MTProto bad_msg_notification error code if seq_no is invalid.

        Counters are per MTProto session_id (spec-correct).
        """
        counters = self._counters_for(session_id)
        expected = counters.inbound_content_count * 2 + (1 if content_related else 0)

        # Parity check (error codes from MTProto spec).
        if content_related and (seq_no & 1) == 0:
            logger.warning(
                "bad seq_no parity (content must be odd): auth_key_id=%s session_id=%s seq_no=%s",
                self.auth_key_id, session_id, seq_no,
            )
            return 35
        if not content_related and (seq_no & 1) == 1:
            logger.warning(
                "bad seq_no parity (non-content must be even): auth_key_id=%s session_id=%s seq_no=%s",
                self.auth_key_id, session_id, seq_no,
            )
            return 34

        if content_related:
            if seq_no < expected:
                # Strict: seq too low means duplicate / replay.
                logger.warning(
                    "content seq too low: auth_key_id=%s session_id=%s seq_no=%s expected_min=%s",
                    self.auth_key_id, session_id, seq_no, expected,
                )
                return 32
            # Accept and advance the per-session counter.
            # seq_no for the n-th content message is 2n+1, so n = (seq_no+1)//2.
            counters.inbound_content_count = (seq_no + 1) // 2
            return None

        # Non-content: only reject if clearly stale (too low).
        if seq_no < expected:
            logger.warning(
                "non-content seq too low: auth_key_id=%s session_id=%s seq_no=%s expected_min=%s",
                self.auth_key_id, session_id, seq_no, expected,
            )
            return 32
        return None

    def next_server_seq_no(self, session_id: int, *, content_related: bool) -> int:
        """Generate and advance the outbound seq_no for a specific MTProto session."""
        counters = self._counters_for(session_id)
        seq_no = counters.outbound_content_count * 2 + (1 if content_related else 0)
        if content_related:
            counters.outbound_content_count += 1
        return seq_no

    def touch_updates_state(
        self, pts_inc: int = 0, qts_inc: int = 0, seq_inc: int = 0,
    ) -> None:
        self.pts += pts_inc
        self.qts += qts_inc
        self.seq += seq_inc
        self.date = int(time.time())


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
    # PQ factorization
    pq: int = 0
    p: int = 0
    q: int = 0
    # DH params (server side)
    dh_secret_a: int = 0
    g_a: int = 0


class SessionStore:
    def __init__(self, repository: AuthSessionRepository | None = None) -> None:
        self._handshakes: dict[int, HandshakeState] = {}
        self._sessions: dict[int, AuthSession] = {}
        self._by_user: dict[int, set[int]] = {}
        self._repository = repository

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
            # MTProto session_id is created by the client in encrypted data;
            # the handshake session id is only a local pre-auth correlation key.
            session_id=0,
        )
        self._sessions[auth_key_id] = session
        self._handshakes.pop(session_id, None)
        self._save_session(session)
        return session

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

    def _save_session(self, session: AuthSession) -> None:
        if self._repository is None:
            return
        self._repository.save(session)

    def bind_user(self, auth_key_id: int, user_id: int) -> None:
        session = self._sessions.get(auth_key_id)
        if session is not None:
            if session.user_id is not None and session.user_id != user_id:
                old = self._by_user.get(session.user_id)
                if old is not None:
                    old.discard(auth_key_id)
            session.user_id = user_id
            self._by_user.setdefault(user_id, set()).add(auth_key_id)
            self._save_session(session)

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

    def bind_temp_auth_key(
        self,
        *,
        temp_auth_key_id: int,
        perm_auth_key_id: int,
        nonce: int,
        temp_session_id: int,
        expires_at: int,
    ) -> bool:
        """Bind a temporary auth key to a permanent key.

        MTProto allows one active temp key per permanent key; rebinding replaces
        the previous temp binding for the permanent auth key.
        """
        temp_session = self.get_session(temp_auth_key_id)
        perm_session = self.get_session(perm_auth_key_id)
        if temp_session is None or perm_session is None:
            return False
        if expires_at <= int(time.time()):
            return False

        previous = perm_session.temp_auth_key_binding
        if previous is not None:
            previous_temp = self._sessions.get(previous.temp_auth_key_id)
            if previous_temp is None:
                previous_temp = self.get_session(previous.temp_auth_key_id)
            if previous_temp is not None:
                previous_temp.temp_auth_key_binding = None
                self._save_session(previous_temp)

        binding = TempAuthKeyBinding(
            perm_auth_key_id=perm_auth_key_id,
            temp_auth_key_id=temp_auth_key_id,
            nonce=nonce,
            temp_session_id=temp_session_id,
            expires_at=expires_at,
        )
        perm_session.temp_auth_key_binding = binding
        temp_session.temp_auth_key_binding = binding
        temp_session.bind_mtproto_session(temp_session_id)
        self._save_session(perm_session)
        self._save_session(temp_session)
        return True

    def update_layer(self, auth_key_id: int, layer: int) -> bool:
        if layer <= 0:
            return False
        session = self._sessions.get(auth_key_id)
        if session is None:
            return False
        session.layer = layer
        self._save_session(session)
        return True

    def register_future_salts_for_auth_key(
        self,
        auth_key_id: int,
        entries: list[tuple[int, int, int]],
    ) -> bool:
        """Persist future salt windows for ``auth_key_id`` (see ``get_future_salts``)."""
        session = self.get_session(auth_key_id)
        if session is None:
            return False
        session.register_future_salt_entries(entries)
        self._save_session(session)
        return True

    def destroy_mtproto_session(self, auth_key_id: int, target_session_id: int) -> bool:
        """Forget counters/state for ``target_session_id`` under ``auth_key_id``.

        Mirrors MTProto ``destroy_session``: returns whether the session existed.
        """
        session = self.get_session(auth_key_id)
        if session is None:
            return False
        if not session.forget_mtproto_session(target_session_id):
            return False
        self._save_session(session)
        return True

    def get_sessions_for_user(self, user_id: int) -> list[AuthSession]:
        """Return all sessions bound to a user_id."""
        key_ids = self._by_user.get(user_id, set())
        return [
            self._sessions[kid]
            for kid in key_ids
            if kid in self._sessions
        ]
