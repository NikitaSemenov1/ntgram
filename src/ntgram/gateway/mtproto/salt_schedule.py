from __future__ import annotations

import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

SERVER_SALT_INTERVAL_SEC = 1800
SERVER_SALT_GRACE_WINDOW_SEC = 1800
PREVIOUS_SALTS_LIMIT = 4

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from ntgram.gateway.mtproto.session_store import AuthSession, SessionStore


@dataclass(slots=True)
class SaltSchedule:
    """Mutable salt-window state attached to an `AuthSession`."""

    server_salt: int
    server_salt_valid_since: int = field(default_factory=lambda: int(time.time()))
    server_salt_valid_until: int = field(
        default_factory=lambda: int(time.time()) + SERVER_SALT_INTERVAL_SEC,
    )
    accepted_future_salts: dict[int, tuple[int, int]] = field(default_factory=dict)
    previous_salts: dict[int, int] = field(default_factory=dict)
    server_salt_dirty: bool = False

    def register_future_salt_entries(
        self, entries: list[tuple[int, int, int]],
    ) -> None:
        """Register (valid_since, valid_until, salt) triples from get_future_salts."""
        now = int(time.time())
        expired = [
            s for s, (_, vu) in self.accepted_future_salts.items() if vu < now
        ]
        for salt in expired:
            self.accepted_future_salts.pop(salt, None)
        for valid_since, valid_until, salt in entries:
            if salt == self.server_salt or salt == 0:
                continue
            self.accepted_future_salts[salt] = (valid_since, valid_until)

    def _evict_expired_previous_salts(self, now: int) -> None:
        expired = [s for s, exp in self.previous_salts.items() if exp < now]
        for salt in expired:
            self.previous_salts.pop(salt, None)

    def _record_previous_salt(self, previous_salt: int, now: int) -> None:
        """Push previous_salt into the grace-window ring (FIFO, bounded)."""
        if previous_salt == 0:
            return
        self.previous_salts[previous_salt] = now + SERVER_SALT_GRACE_WINDOW_SEC
        self._evict_expired_previous_salts(now)
        while len(self.previous_salts) > PREVIOUS_SALTS_LIMIT:
            oldest = min(self.previous_salts.items(), key=lambda kv: kv[1])[0]
            self.previous_salts.pop(oldest, None)

    def rotate_if_needed(self, now: int | None = None) -> bool:
        """Promote the next scheduled salt to current when the window ends."""
        now = int(time.time()) if now is None else now
        if now <= self.server_salt_valid_until:
            return False
        candidates = [
            (vs, vu, salt)
            for salt, (vs, vu) in self.accepted_future_salts.items()
            if vs <= now <= vu
        ]
        source = "scheduled_future_salt"
        if not candidates:
            valid_since = now
            valid_until = now + SERVER_SALT_INTERVAL_SEC
            salt = secrets.randbits(64)
            while salt == 0 or salt == self.server_salt:
                salt = secrets.randbits(64)
            source = "random_fallback"
        else:
            valid_since, valid_until, salt = max(candidates, key=lambda i: i[0])
        previous_salt = self.server_salt
        previous_valid_until = self.server_salt_valid_until
        self._record_previous_salt(previous_salt, now)
        self.server_salt = salt
        self.server_salt_valid_since = valid_since
        self.server_salt_valid_until = valid_until
        self.accepted_future_salts.pop(salt, None)
        self.server_salt_dirty = True
        logger.info(
            "server salt rotated: source=%s previous_salt=%s new_salt=%s "
            "previous_valid_until=%s new_valid_until=%s now=%s "
            "previous_salts_kept=%s",
            source,
            previous_salt,
            salt,
            previous_valid_until,
            valid_until,
            now,
            len(self.previous_salts),
        )
        return True

    def is_accepted(self, salt: int) -> bool:
        """True if salt matches current, a future window, or a recent prev."""
        self.rotate_if_needed()
        now = int(time.time())
        if salt == self.server_salt:
            return True
        window = self.accepted_future_salts.get(salt)
        if window is not None:
            valid_since, valid_until = window
            if valid_since <= now <= valid_until:
                return True

        expires_at = self.previous_salts.get(salt)
        if expires_at is not None:
            if expires_at >= now:
                return True
            
            self.previous_salts.pop(salt, None)
        return False


@dataclass(slots=True, frozen=True)
class FutureSaltEntry:
    """Single MTProto future_salt triple."""

    valid_since: int
    valid_until: int
    salt: int


@dataclass(slots=True, frozen=True)
class FutureSaltsPlan:
    """Result of `plan_future_salts`."""

    schedule: list[FutureSaltEntry]
    new_entries: list[FutureSaltEntry]


def plan_future_salts(
    session: AuthSession, num: int, now: int,
) -> FutureSaltsPlan:
    """Build the future_salts reply for an authenticated session."""
    num = max(1, min(64, int(num)))
    salt = session.salt

    schedule: list[FutureSaltEntry] = [
        FutureSaltEntry(
            valid_since=salt.server_salt_valid_since,
            valid_until=salt.server_salt_valid_until,
            salt=salt.server_salt,
        ),
    ]
    schedule.extend(
        FutureSaltEntry(valid_since=vs, valid_until=vu, salt=s)
        for s, (vs, vu) in salt.accepted_future_salts.items()
        if vu >= now
    )
    schedule.sort(key=lambda e: e.valid_since)

    used: set[int] = {e.salt for e in schedule}
    new_entries: list[FutureSaltEntry] = []
    next_valid_since = (
        max(e.valid_since for e in schedule) + SERVER_SALT_INTERVAL_SEC
    )
    while len(schedule) + len(new_entries) < num:
        candidate = 0
        for _ in range(64):
            cand = int.from_bytes(
                secrets.token_bytes(8), "little", signed=False,
            )
            if cand != 0 and cand not in used:
                candidate = cand
                break
        if candidate == 0:
            break
        used.add(candidate)
        valid_since = next_valid_since
        valid_until = valid_since + SERVER_SALT_INTERVAL_SEC
        new_entries.append(
            FutureSaltEntry(
                valid_since=valid_since,
                valid_until=valid_until,
                salt=candidate,
            ),
        )
        next_valid_since += SERVER_SALT_INTERVAL_SEC

    if new_entries:
        schedule.extend(new_entries)
        schedule.sort(key=lambda e: e.valid_since)

    return FutureSaltsPlan(
        schedule=schedule[:num],
        new_entries=new_entries,
    )


class SaltScheduleService:
    """Narrow facade for persisting future-salt registrations."""

    __slots__ = ("_sessions",)

    def __init__(self, sessions: SessionStore) -> None:
        self._sessions = sessions

    def register_future_salts_for_auth_key(
        self,
        auth_key_id: int,
        entries: list[tuple[int, int, int]],
    ) -> bool:
        """Persist future salt windows for auth_key_id."""
        session = self._sessions.get_session(auth_key_id)
        if session is None:
            return False
        session.salt.register_future_salt_entries(entries)
        self._sessions.save_session(auth_key_id)
        return True
