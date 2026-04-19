from __future__ import annotations

from ntgram.gateway.mtproto.session_store import SessionStore


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
