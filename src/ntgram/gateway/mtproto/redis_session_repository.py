from __future__ import annotations

import json
import logging
import time
from typing import Any

from ntgram.gateway.mtproto.salt_schedule import (
    SERVER_SALT_INTERVAL_SEC,
    SaltSchedule,
)
from ntgram.gateway.mtproto.seq_counters import (
    MtprotoSessionCounters,
    SessionCounterStore,
)
from ntgram.gateway.mtproto.session_store import (
    AuthSession,
    AuthSessionRepository,
    TempAuthKeyBinding,
)

logger = logging.getLogger(__name__)


class RedisAuthSessionRepository(AuthSessionRepository):
    """Persist completed MTProto auth sessions in Redis (nested JSON layout)."""

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

    # encode

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
    def _encode_salt(salt: SaltSchedule) -> dict[str, Any]:
        return {
            "server_salt": salt.server_salt,
            "valid_since": salt.server_salt_valid_since,
            "valid_until": salt.server_salt_valid_until,
            "accepted_future_salts": [
                [vs, vu, s]
                for s, (vs, vu) in sorted(
                    salt.accepted_future_salts.items(),
                    key=lambda item: item[0],
                )
            ],
            "previous_salts": [
                [s, exp]
                for s, exp in sorted(
                    salt.previous_salts.items(), key=lambda item: item[0],
                )
            ],
        }

    @staticmethod
    def _encode_counters(counters: SessionCounterStore) -> list[dict[str, Any]]:
        return [
            {
                "session_id": sid,
                "in_content": c.inbound_content_count,
                "out_content": c.outbound_content_count,
            }
            for sid, c in sorted(
                counters.counters.items(), key=lambda item: item[0],
            )
        ]

    @classmethod
    def _encode_session(cls, session: AuthSession) -> dict[str, Any]:
        return {
            "auth_key_id": session.auth_key_id,
            "auth_key": session.auth_key.hex(),
            "session_id": session.session_id,
            "known_session_ids": sorted(session.known_session_ids),
            "user_id": session.user_id,
            "layer": session.layer,
            "created_at": session.created_at,
            "salt": cls._encode_salt(session.salt),
            "counters": cls._encode_counters(session.counters),
            "temp_auth_key_binding": cls._encode_binding(
                session.temp_auth_key_binding,
            ),
        }

    # decode

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

    @staticmethod
    def _decode_salt(data: dict[str, Any]) -> SaltSchedule:
        salt = SaltSchedule(
            server_salt=int(data["server_salt"]),
            server_salt_valid_since=int(data["valid_since"]),
            server_salt_valid_until=int(data["valid_until"]),
        )
        for item in data.get("accepted_future_salts", []):
            if isinstance(item, (list, tuple)) and len(item) == 3:
                vs, vu, s = int(item[0]), int(item[1]), int(item[2])
                salt.accepted_future_salts[s] = (vs, vu)
        now = int(time.time())
        for item in data.get("previous_salts", []):
            if isinstance(item, (list, tuple)) and len(item) == 2:
                s, exp = int(item[0]), int(item[1])
                if exp >= now:
                    salt.previous_salts[s] = exp
        
        if salt.server_salt_valid_until < now:
            salt.server_salt_valid_until = now + SERVER_SALT_INTERVAL_SEC
            if salt.server_salt_valid_since > salt.server_salt_valid_until:
                salt.server_salt_valid_since = salt.server_salt_valid_until
            salt.server_salt_dirty = True
        return salt

    @staticmethod
    def _decode_counters(
        auth_key_id: int, data: list[Any],
    ) -> SessionCounterStore:
        store = SessionCounterStore(auth_key_id=auth_key_id)
        for item in data or []:
            if not isinstance(item, dict):
                continue
            sid = int(item["session_id"])
            store.counters[sid] = MtprotoSessionCounters(
                inbound_content_count=int(item.get("in_content", 0)),
                outbound_content_count=int(item.get("out_content", 0)),
            )
        return store

    @classmethod
    def _decode_session(cls, data: dict[str, Any]) -> AuthSession:
        auth_key_id = int(data["auth_key_id"])
        salt = cls._decode_salt(data["salt"])
        counters = cls._decode_counters(auth_key_id, data.get("counters", []))

        session = AuthSession(
            auth_key_id=auth_key_id,
            auth_key=bytes.fromhex(str(data["auth_key"])),
            session_id=int(data.get("session_id", 0)),
            known_session_ids={
                int(item) for item in data.get("known_session_ids", [])
            },
            user_id=(
                int(data["user_id"]) if data.get("user_id") is not None else None
            ),
            layer=int(data.get("layer", 0)),
            created_at=float(data.get("created_at", 0.0)),
            temp_auth_key_binding=cls._decode_binding(
                data.get("temp_auth_key_binding"),
            ),
            salt=salt,
            counters=counters,
        )
        # Ensure the active session_id and any known ones have counter slots.
        if session.session_id != 0:
            session.known_session_ids.add(session.session_id)
            session.counters.for_session(session.session_id)
        for sid in session.known_session_ids:
            session.counters.for_session(sid)
        return session
