from __future__ import annotations

from ntgram.gateway.mtproto.outbox_service import OutboxService
from ntgram.gateway.mtproto.session_store import SessionStore


def _make_session(store: SessionStore, key: bytes, *, session_id: int = 1):
    return store.complete_handshake(
        session_id=session_id,
        auth_key=key,
        new_nonce=1,
        server_nonce=2,
    )


def test_ack_outgoing_messages_removes_pending_entries() -> None:
    store = SessionStore()
    outbox = OutboxService(store)
    session = _make_session(store, b"x" * 256)
    first_msg_id = 101
    second_msg_id = 202
    unknown_msg_id = 303

    assert outbox.register_outgoing_msg(session.auth_key_id, first_msg_id) is True
    assert outbox.register_outgoing_msg(session.auth_key_id, second_msg_id) is True
    assert outbox.register_outgoing_msg(
        session.auth_key_id,
        404,
        req_msg_id=505,
        seq_no=1,
        bytes_count=128,
    ) is True

    removed = outbox.ack_outgoing_msgs(
        session.auth_key_id,
        [first_msg_id, unknown_msg_id, 404],
    )
    assert removed == 2
    assert first_msg_id not in session.outbox.pending_outgoing_msg_ids
    assert second_msg_id in session.outbox.pending_outgoing_msg_ids
    assert 505 not in session.outbox.pending_outgoing_rpcs


def test_register_outgoing_message_for_unknown_auth_key_is_noop() -> None:
    store = SessionStore()
    outbox = OutboxService(store)
    assert outbox.register_outgoing_msg(999, 12345) is False
    assert outbox.ack_outgoing_msgs(999, [12345]) == 0


def test_drop_rpc_answer_returns_pending_metadata_and_forgets_it() -> None:
    store = SessionStore()
    outbox = OutboxService(store)
    session = _make_session(store, b"r" * 256)

    assert outbox.register_outgoing_msg(
        session.auth_key_id,
        7001,
        req_msg_id=6001,
        seq_no=3,
        bytes_count=256,
    )

    dropped = outbox.drop_rpc_answer(session.auth_key_id, 6001)
    assert dropped is not None
    assert getattr(dropped, "msg_id") == 7001
    assert getattr(dropped, "seq_no") == 3
    assert getattr(dropped, "bytes_count") == 256
    assert 7001 not in session.outbox.pending_outgoing_msg_ids
    assert 6001 not in session.outbox.pending_outgoing_rpcs
    assert outbox.drop_rpc_answer(session.auth_key_id, 6001) is None


def test_drop_rpc_answer_marks_running_rpc() -> None:
    store = SessionStore()
    outbox = OutboxService(store)
    session = _make_session(store, b"q" * 256)

    assert outbox.register_running_rpc(session.auth_key_id, 8001)
    assert outbox.drop_rpc_answer(session.auth_key_id, 8001) == "running"
    assert outbox.finish_running_rpc(session.auth_key_id, 8001) is True
    assert outbox.finish_running_rpc(session.auth_key_id, 8001) is False


def test_finish_running_rpc_for_unknown_auth_key_returns_false() -> None:
    store = SessionStore()
    outbox = OutboxService(store)
    assert outbox.finish_running_rpc(999, 8001) is False
    assert outbox.drop_rpc_answer(999, 8001) is None
