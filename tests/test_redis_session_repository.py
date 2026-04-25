from __future__ import annotations

from ntgram.gateway.mtproto.redis_session_repository import RedisAuthSessionRepository
from ntgram.gateway.mtproto.session_store import AuthSession, TempAuthKeyBinding


def test_redis_session_repository_roundtrip_payload() -> None:
    session = AuthSession(
        auth_key_id=123,
        auth_key=b"k" * 256,
        server_salt=456,
        session_id=789,
        known_session_ids={789, 790},
        user_id=42,
        layer=214,
        accepted_future_salts={111: (1, 2_000_000_000)},
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
    assert restored.server_salt == session.server_salt
    assert restored.session_id == session.session_id
    assert restored.known_session_ids == session.known_session_ids
    assert restored.user_id == session.user_id
    assert restored.layer == session.layer
    assert restored.temp_auth_key_binding == session.temp_auth_key_binding
    assert restored.accepted_future_salts == session.accepted_future_salts
