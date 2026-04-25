from __future__ import annotations

from ntgram.gateway.mtproto.session_store import AuthSession, SessionStore


class MemoryAuthSessionRepository:
    def __init__(self) -> None:
        self.sessions: dict[int, AuthSession] = {}

    def load(self, auth_key_id: int) -> AuthSession | None:
        return self.sessions.get(auth_key_id)

    def save(self, session: AuthSession) -> None:
        self.sessions[session.auth_key_id] = session


def test_ack_outgoing_messages_removes_pending_entries() -> None:
    store = SessionStore()
    session = store.complete_handshake(
        session_id=1,
        auth_key=b"x" * 256,
        new_nonce=1,
        server_nonce=2,
    )
    first_msg_id = 101
    second_msg_id = 202
    unknown_msg_id = 303

    assert store.register_outgoing_msg(session.auth_key_id, first_msg_id) is True
    assert store.register_outgoing_msg(session.auth_key_id, second_msg_id) is True

    removed = store.ack_outgoing_msgs(
        session.auth_key_id,
        [first_msg_id, unknown_msg_id],
    )
    assert removed == 1
    assert first_msg_id not in session.pending_outgoing_msg_ids
    assert second_msg_id in session.pending_outgoing_msg_ids


def test_register_outgoing_message_for_unknown_auth_key_is_noop() -> None:
    store = SessionStore()
    assert store.register_outgoing_msg(999, 12345) is False
    assert store.ack_outgoing_msgs(999, [12345]) == 0


def test_update_layer_updates_existing_session_only() -> None:
    store = SessionStore()
    session = store.complete_handshake(
        session_id=1,
        auth_key=b"y" * 256,
        new_nonce=3,
        server_nonce=4,
    )
    assert store.update_layer(session.auth_key_id, 201) is True
    assert session.layer == 201
    assert store.update_layer(session.auth_key_id, 0) is False
    assert store.update_layer(999, 201) is False


def test_complete_handshake_persists_auth_session() -> None:
    repo = MemoryAuthSessionRepository()
    store = SessionStore(repo)
    session = store.complete_handshake(
        session_id=1,
        auth_key=b"p" * 256,
        new_nonce=5,
        server_nonce=6,
    )

    assert repo.sessions[session.auth_key_id] is session
    restored_store = SessionStore(repo)
    restored = restored_store.get_session(session.auth_key_id)
    assert restored is session


def test_bind_temp_auth_key_persists_binding_for_both_sessions() -> None:
    repo = MemoryAuthSessionRepository()
    store = SessionStore(repo)
    perm = store.complete_handshake(
        session_id=10,
        auth_key=b"p" * 256,
        new_nonce=5,
        server_nonce=6,
    )
    temp = store.complete_handshake(
        session_id=11,
        auth_key=b"t" * 256,
        new_nonce=7,
        server_nonce=8,
    )

    assert store.bind_temp_auth_key(
        temp_auth_key_id=temp.auth_key_id,
        perm_auth_key_id=perm.auth_key_id,
        nonce=1,
        temp_session_id=123,
        expires_at=4_102_444_800,
    )

    assert repo.sessions[perm.auth_key_id].temp_auth_key_binding is not None
    assert repo.sessions[temp.auth_key_id].temp_auth_key_binding is not None


def test_destroy_mtproto_session_forgets_known_session_id() -> None:
    store = SessionStore()
    session = store.complete_handshake(
        session_id=1,
        auth_key=b"d" * 256,
        new_nonce=1,
        server_nonce=2,
    )
    session.bind_mtproto_session(100)
    session.bind_mtproto_session(200)
    assert store.destroy_mtproto_session(session.auth_key_id, 100) is True
    assert 100 not in session.known_session_ids
    assert 200 in session.known_session_ids
    assert store.destroy_mtproto_session(session.auth_key_id, 100) is False
