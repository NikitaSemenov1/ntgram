from __future__ import annotations

from unittest.mock import patch

from ntgram.gateway.mtproto.redis_session_repository import (
    RedisAuthSessionRepository,
)
from ntgram.gateway.mtproto.salt_schedule import (
    SERVER_SALT_INTERVAL_SEC,
    SaltSchedule,
)
from ntgram.gateway.mtproto.seq_counters import (
    MtprotoSessionCounters,
    SessionCounterStore,
)
from ntgram.gateway.mtproto.session_store import AuthSession, TempAuthKeyBinding
# Use a far-future timestamp so the load-side extend logic never fires for
# tests that simply verify the wire payload round-trips unchanged.
_FUTURE_VALID_SINCE = 9_000_000_000
_FUTURE_VALID_UNTIL = 9_000_001_800


def test_redis_session_repository_roundtrip_nested_payload() -> None:
    counters = SessionCounterStore(auth_key_id=123)
    counters.counters[789] = MtprotoSessionCounters(
        inbound_content_count=4,
        outbound_content_count=7,
    )
    session = AuthSession(
        auth_key_id=123,
        auth_key=b"k" * 256,
        session_id=789,
        known_session_ids={789, 790},
        user_id=42,
        layer=214,
        salt=SaltSchedule(
            server_salt=456,
            server_salt_valid_since=_FUTURE_VALID_SINCE,
            server_salt_valid_until=_FUTURE_VALID_UNTIL,
            accepted_future_salts={111: (1, 2_000_000_000)},
        ),
        counters=counters,
        temp_auth_key_binding=TempAuthKeyBinding(
            perm_auth_key_id=123,
            temp_auth_key_id=999,
            nonce=1,
            temp_session_id=2,
            expires_at=4_102_444_800,
            bound_at=3.5,
        ),
    )

    payload = RedisAuthSessionRepository._encode_session(session)
    restored = RedisAuthSessionRepository._decode_session(payload)

    assert restored.auth_key_id == session.auth_key_id
    assert restored.auth_key == session.auth_key
    assert restored.session_id == session.session_id
    assert restored.known_session_ids == session.known_session_ids
    assert restored.user_id == session.user_id
    assert restored.layer == session.layer
    assert restored.temp_auth_key_binding == session.temp_auth_key_binding
    # Salt schedule round-trips through the nested payload.
    assert restored.salt.server_salt == session.salt.server_salt
    assert restored.salt.server_salt_valid_since == session.salt.server_salt_valid_since
    assert restored.salt.server_salt_valid_until == session.salt.server_salt_valid_until
    assert restored.salt.accepted_future_salts == session.salt.accepted_future_salts
    # updates (pts/qts/seq/date) are no longer stored on AuthSession (t19).
    # Per-session counters survive the round-trip.
    assert 789 in restored.counters.counters
    assert restored.counters.counters[789].inbound_content_count == 4
    assert restored.counters.counters[789].outbound_content_count == 7


def test_redis_decode_tolerates_missing_optional_blocks() -> None:
    """Optional ``counters`` / ``temp_auth_key_binding`` may be absent."""
    payload = {
        "auth_key_id": 7,
        "auth_key": ("aa" * 256),
        "session_id": 0,
        "known_session_ids": [],
        "user_id": None,
        "layer": 0,
        "created_at": 0,
        "salt": {
            "server_salt": 99,
            "valid_since": _FUTURE_VALID_SINCE,
            "valid_until": _FUTURE_VALID_UNTIL,
            "accepted_future_salts": [],
        },
    }
    session = RedisAuthSessionRepository._decode_session(payload)
    assert session.salt.server_salt == 99
    assert session.counters.counters == {}
    assert session.temp_auth_key_binding is None


def test_load_extends_expired_valid_until_and_marks_dirty() -> None:
    """A salt window that expired during gateway downtime must be extended on
    load instead of forcing an immediate rotation on the first decode."""
    payload = {
        "auth_key_id": 1,
        "auth_key": "aa" * 256,
        "session_id": 0,
        "known_session_ids": [],
        "user_id": None,
        "layer": 0,
        "created_at": 0,
        "salt": {
            "server_salt": 0xDEADBEEF,
            "valid_since": 1_000,
            "valid_until": 2_000,  # in the past relative to ``now``
            "accepted_future_salts": [],
        },
    }
    fixed_now = 5_000_000_000
    with patch("ntgram.gateway.mtproto.redis_session_repository.time.time",
               return_value=fixed_now):
        session = RedisAuthSessionRepository._decode_session(payload)
    # Salt itself is preserved — clients holding it remain valid.
    assert session.salt.server_salt == 0xDEADBEEF
    # Window has been pushed forward and flagged as dirty so the next
    # ``mark_server_salt_clean`` will persist it back to Redis.
    assert session.salt.server_salt_valid_until == fixed_now + SERVER_SALT_INTERVAL_SEC
    assert session.salt.server_salt_dirty is True


def test_load_keeps_valid_until_when_still_in_window() -> None:
    """When the persisted window is still in the future, do not touch it."""
    payload = {
        "auth_key_id": 2,
        "auth_key": "bb" * 256,
        "session_id": 0,
        "known_session_ids": [],
        "user_id": None,
        "layer": 0,
        "created_at": 0,
        "salt": {
            "server_salt": 7,
            "valid_since": _FUTURE_VALID_SINCE,
            "valid_until": _FUTURE_VALID_UNTIL,
            "accepted_future_salts": [],
        },
    }
    session = RedisAuthSessionRepository._decode_session(payload)
    assert session.salt.server_salt_valid_until == _FUTURE_VALID_UNTIL
    assert session.salt.server_salt_dirty is False


def test_previous_salts_roundtrip_through_redis() -> None:
    """Previous-salt grace ring must survive Redis save/load so that the
    grace window itself is honoured across gateway restarts."""
    salt = SaltSchedule(
        server_salt=1,
        server_salt_valid_since=_FUTURE_VALID_SINCE,
        server_salt_valid_until=_FUTURE_VALID_UNTIL,
    )
    salt.previous_salts[10] = _FUTURE_VALID_UNTIL + 1000
    salt.previous_salts[20] = _FUTURE_VALID_UNTIL + 2000

    payload = RedisAuthSessionRepository._encode_salt(salt)
    assert payload["previous_salts"] == [
        [10, _FUTURE_VALID_UNTIL + 1000],
        [20, _FUTURE_VALID_UNTIL + 2000],
    ]
    restored = RedisAuthSessionRepository._decode_salt(payload)
    assert restored.previous_salts == {
        10: _FUTURE_VALID_UNTIL + 1000,
        20: _FUTURE_VALID_UNTIL + 2000,
    }


def test_load_drops_expired_previous_salts() -> None:
    """Expired entries in the persisted grace ring must not resurrect on load."""
    fixed_now = 5_000_000_000
    payload = {
        "server_salt": 1,
        "valid_since": _FUTURE_VALID_SINCE,
        "valid_until": _FUTURE_VALID_UNTIL,
        "accepted_future_salts": [],
        "previous_salts": [
            [42, fixed_now - 1],          # already expired
            [43, fixed_now + 100],         # still valid
        ],
    }
    with patch("ntgram.gateway.mtproto.redis_session_repository.time.time",
               return_value=fixed_now):
        salt = RedisAuthSessionRepository._decode_salt(payload)
    assert 42 not in salt.previous_salts
    assert salt.previous_salts == {43: fixed_now + 100}
