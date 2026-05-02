from __future__ import annotations

import pytest

pytest.importorskip("asyncpg")
pytest.importorskip("grpc")

from ntgram.gen import chat_pb2

from tests._chat_service_factory import make_chat_service


@pytest.mark.asyncio
async def test_send_message_creates_one_row_per_participant_with_correct_out() -> None:
    svc, pool, updates = make_chat_service()
    pool.add_dialog(2001, owner_user_id=1, peer_id=2, is_group=False)
    pool.add_dialog(2001, owner_user_id=2, peer_id=1, is_group=False)

    resp = await svc.SendMessage(
        chat_pb2.SendMessageRequest(
            actor_user_id=1, dialog_id=2001, text="hello",
            random_id=42,
        ),
        None,
    )

    assert resp.meta.ok
    assert resp.actor_user_message_box_id > 0
    assert resp.dialog_message_id > 0
    assert resp.pts == 1
    assert {p.user_id for p in resp.participants} == {1, 2}

    actor_box = next(p for p in resp.participants if p.user_id == 1)
    peer_box = next(p for p in resp.participants if p.user_id == 2)

    assert actor_box.user_message_box_id == resp.actor_user_message_box_id

    actor_rows = pool.boxes_for(1)
    peer_rows = pool.boxes_for(2)
    assert len(actor_rows) == 1
    assert len(peer_rows) == 1
    assert actor_rows[0].out is True
    assert peer_rows[0].out is False
    assert actor_rows[0].random_id == 42
    assert peer_rows[0].random_id is None
    assert actor_rows[0].dialog_message_id == peer_rows[0].dialog_message_id

    # Top dialog state was updated for both owners; only peer has unread+1.
    assert pool.get_dialog(2001, 1).unread_count == 0
    assert pool.get_dialog(2001, 2).unread_count == 1
    assert pool.get_dialog(2001, 1).top_user_message_box_id == actor_box.user_message_box_id
    assert pool.get_dialog(2001, 2).top_user_message_box_id == peer_box.user_message_box_id

    # Per-recipient updateNewMessage went through UpdatesServiceStub.
    assert {r["user_id"] for r in updates.recorded} == {1, 2}
    for r in updates.recorded:
        assert r["update_type"] == "updateNewMessage"


@pytest.mark.asyncio
async def test_send_message_idempotency_by_random_id() -> None:
    svc, pool, _ = make_chat_service()
    pool.add_dialog(2001, owner_user_id=1, peer_id=2, is_group=False)
    pool.add_dialog(2001, owner_user_id=2, peer_id=1, is_group=False)

    first = await svc.SendMessage(
        chat_pb2.SendMessageRequest(
            actor_user_id=1, dialog_id=2001, text="hello", random_id=777,
        ),
        None,
    )
    assert first.meta.ok

    second = await svc.SendMessage(
        chat_pb2.SendMessageRequest(
            actor_user_id=1, dialog_id=2001, text="hello", random_id=777,
        ),
        None,
    )
    assert second.meta.ok
    assert second.actor_user_message_box_id == first.actor_user_message_box_id
    assert second.dialog_message_id == first.dialog_message_id
    assert {p.user_id for p in second.participants} == {1, 2}

    # Still only one row per user; random_id was not double-inserted.
    assert len(pool.boxes_for(1)) == 1
    assert len(pool.boxes_for(2)) == 1


@pytest.mark.asyncio
async def test_send_message_empty_text_rejected() -> None:
    svc, pool, _ = make_chat_service()
    pool.add_dialog(2001, owner_user_id=1, peer_id=2, is_group=False)
    pool.add_dialog(2001, owner_user_id=2, peer_id=1, is_group=False)

    resp = await svc.SendMessage(
        chat_pb2.SendMessageRequest(
            actor_user_id=1, dialog_id=2001, text="   ", random_id=1,
        ),
        None,
    )
    assert not resp.meta.ok
    assert resp.meta.error.message == "MESSAGE_EMPTY"
