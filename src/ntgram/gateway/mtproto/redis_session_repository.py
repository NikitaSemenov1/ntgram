from __future__ import annotations

import json
import logging
from typing import Any

from ntgram.gateway.mtproto.session_store import (
    AuthSession,
    AuthSessionRepository,
    TempAuthKeyBinding,
)

logger = logging.getLogger(__name__)


class RedisAuthSessionRepository(AuthSessionRepository):
    """Persist completed MTProto auth sessions in Redis.

    The repository stores only restart-critical auth material and binding state.
    Per-process replay windows, pending outgoing messages, and seq counters stay
    in memory because they are runtime flow-control state.
    """

    def __init__(self, dsn: str, *, key_prefix: str = "ntgram:mtproto") -> None:
        import redis

        self._redis = redis.Redis.from_url(dsn, decode_responses=True)
        self._key_prefix = key_prefix.rstrip(":")

    def ping(self) -> None:
        """Validate Redis connectivity at gateway startup."""
        self._redis.ping()

    def load(self, auth_key_id: int) -> AuthSession | None:
        raw = self._redis.get(self._key(auth_key_id))
        if raw is None:
            return None
        try:
            data = json.loads(raw)
            return self._decode_session(data)
        except Exception as exc:
            logger.warning(
                "failed to load auth session from Redis: auth_key_id=%s error=%s",
                auth_key_id,
                exc,
            )
            return None

    def save(self, session: AuthSession) -> None:
        payload = json.dumps(self._encode_session(session), separators=(",", ":"))
        self._redis.set(self._key(session.auth_key_id), payload)

    def _key(self, auth_key_id: int) -> str:
        return f"{self._key_prefix}:auth_session:{auth_key_id}"

    @staticmethod
    def _encode_binding(binding: TempAuthKeyBinding | None) -> dict[str, Any] | None:
        if binding is None:
            return None
        return {
            "perm_auth_key_id": binding.perm_auth_key_id,
            "temp_auth_key_id": binding.temp_auth_key_id,
            "nonce": binding.nonce,
            "temp_session_id": binding.temp_session_id,
            "expires_at": binding.expires_at,
            "bound_at": binding.bound_at,
        }

    @staticmethod
    def _decode_binding(data: object) -> TempAuthKeyBinding | None:
        if not isinstance(data, dict):
            return None
        return TempAuthKeyBinding(
            perm_auth_key_id=int(data["perm_auth_key_id"]),
            temp_auth_key_id=int(data["temp_auth_key_id"]),
            nonce=int(data["nonce"]),
            temp_session_id=int(data["temp_session_id"]),
            expires_at=int(data["expires_at"]),
            bound_at=float(data.get("bound_at", 0.0)),
        )

    @classmethod
    def _encode_session(cls, session: AuthSession) -> dict[str, Any]:
        return {
            "auth_key_id": session.auth_key_id,
            "auth_key": session.auth_key.hex(),
            "server_salt": session.server_salt,
            "session_id": session.session_id,
            "known_session_ids": sorted(session.known_session_ids),
            "user_id": session.user_id,
            "created_at": session.created_at,
            "qts": session.qts,
            "pts": session.pts,
            "seq": session.seq,
            "layer": session.layer,
            "date": session.date,
            "temp_auth_key_binding": cls._encode_binding(
                session.temp_auth_key_binding,
            ),
            "accepted_future_salts": [
                [vs, vu, salt]
                for salt, (vs, vu) in sorted(
                    session.accepted_future_salts.items(),
                    key=lambda item: item[0],
                )
            ],
        }

    @classmethod
    def _decode_session(cls, data: dict[str, Any]) -> AuthSession:
        session = AuthSession(
            auth_key_id=int(data["auth_key_id"]),
            auth_key=bytes.fromhex(str(data["auth_key"])),
            server_salt=int(data["server_salt"]),
            session_id=int(data.get("session_id", 0)),
            known_session_ids={
                int(item) for item in data.get("known_session_ids", [])
            },
            user_id=(
                int(data["user_id"]) if data.get("user_id") is not None else None
            ),
            created_at=float(data.get("created_at", 0.0)),
            qts=int(data.get("qts", 0)),
            pts=int(data.get("pts", 0)),
            seq=int(data.get("seq", 0)),
            layer=int(data.get("layer", 0)),
            date=int(data.get("date", 0)),
            temp_auth_key_binding=cls._decode_binding(
                data.get("temp_auth_key_binding"),
            ),
        )
        for item in data.get("accepted_future_salts", []):
            if isinstance(item, (list, tuple)) and len(item) == 3:
                vs, vu, s = int(item[0]), int(item[1]), int(item[2])
                session.accepted_future_salts[s] = (vs, vu)
        if session.session_id != 0:
            session.known_session_ids.add(session.session_id)
            session._counters_for(session.session_id)
        for sid in session.known_session_ids:
            session._counters_for(sid)
        return session
