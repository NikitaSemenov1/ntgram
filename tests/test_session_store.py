from __future__ import annotations

from ntgram.gateway.mtproto.session_store import AuthSession, SessionStore


class MemoryAuthSessionRepository:
    def __init__(self) -> None:
        self.sessions: dict[int, AuthSession] = {}

    def load(self, auth_key_id: int) -> AuthSession | None:
        return self.sessions.get(auth_key_id)

    def save(self, session: AuthSession) -> None:
        self.sessions[session.auth_key_id] = session


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


def test_non_content_server_seq_no_does_not_advance_content_counter() -> None:
    """Delegating method ``next_server_seq_no`` keeps non-content/content split."""
    store = SessionStore()
    session = store.complete_handshake(
        session_id=3,
        auth_key=b"h" * 256,
        new_nonce=5,
        server_nonce=6,
    )
    session_id = 300
    session.bind_mtproto_session(session_id)

    assert session.next_server_seq_no(session_id, content_related=False) == 0
    assert session.next_server_seq_no(session_id, content_related=True) == 1


def test_unbind_user_clears_user_and_reverse_index() -> None:
    store = SessionStore()
    session = store.complete_handshake(
        session_id=4,
        auth_key=b"u" * 256,
        new_nonce=1,
        server_nonce=2,
    )
    store.bind_user(session.auth_key_id, 77)
    assert store.get_sessions_for_user(77)
    store.unbind_user(session.auth_key_id)
    assert session.user_id is None
    assert store.get_sessions_for_user(77) == []


def test_save_session_persists_through_repository() -> None:
    repo = MemoryAuthSessionRepository()
    store = SessionStore(repo)
    session = store.complete_handshake(
        session_id=1,
        auth_key=b"s" * 256,
        new_nonce=1,
        server_nonce=2,
    )
    session.layer = 167
    assert store.save_session(session.auth_key_id) is True
    assert repo.sessions[session.auth_key_id].layer == 167


def test_save_session_unknown_auth_key_is_noop() -> None:
    repo = MemoryAuthSessionRepository()
    store = SessionStore(repo)
    assert store.save_session(99999) is False
