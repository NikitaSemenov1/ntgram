from __future__ import annotations

import json

import pytest

pytest.importorskip("asyncpg")
pytest.importorskip("grpc")

from ntgram.gen import chat_pb2
from ntgram.services.chat.service import ChatService

from tests._chat_service_factory import make_chat_service
from tests._fake_chat_pool import FakeChatPool


async def _send(svc: ChatService, sender: int, dialog_id: int, text: str) -> int:
    resp = await svc.SendMessage(
        chat_pb2.SendMessageRequest(
            actor_user_id=sender, dialog_id=dialog_id, text=text,
        ),
        None,
    )
    assert resp.meta.ok
    return resp.actor_user_message_box_id


def _setup_pm_dialog(pool: FakeChatPool) -> None:
    pool.add_dialog(2001, owner_user_id=1, peer_id=2, is_group=False)
    pool.add_dialog(2001, owner_user_id=2, peer_id=1, is_group=False)


@pytest.mark.asyncio
async def test_delete_revoke_false_pm_actor_only() -> None:
    svc, pool, updates = make_chat_service()
    _setup_pm_dialog(pool)
    actor_ubid = await _send(svc, sender=1, dialog_id=2001, text="hi")

    resp = await svc.DeleteMessages(
        chat_pb2.DeleteMessagesRequest(
            actor_user_id=1,
            user_message_box_ids=[actor_ubid],
            revoke=False,
        ),
        None,
    )
    assert resp.meta.ok
    assert resp.pts_count == 1
    assert list(resp.deleted_ids) == [actor_ubid]

    deleted_actor = [b for b in pool.boxes_for(1) if b.deleted]
    assert len(deleted_actor) == 1
    assert deleted_actor[0].user_message_box_id == actor_ubid
    assert all(not b.deleted for b in pool.boxes_for(2))

    del_updates = [
        u for u in updates.recorded
        if u["update_type"] == "updateDeleteMessages"
    ]
    assert len(del_updates) == 1
    assert del_updates[0]["user_id"] == 1
    assert del_updates[0]["update_data"]["messages"] == [actor_ubid]


@pytest.mark.asyncio
async def test_delete_revoke_true_pm_fanouts_to_both_sides() -> None:
    svc, pool, updates = make_chat_service()
    _setup_pm_dialog(pool)
    actor_ubid = await _send(svc, sender=1, dialog_id=2001, text="hi")

    peer_box = next(b for b in pool.boxes_for(2) if not b.out)
    peer_ubid = peer_box.user_message_box_id

    resp = await svc.DeleteMessages(
        chat_pb2.DeleteMessagesRequest(
            actor_user_id=1,
            user_message_box_ids=[actor_ubid],
            revoke=True,
        ),
        None,
    )
    assert resp.meta.ok
    assert resp.pts_count == 1
    assert list(resp.deleted_ids) == [actor_ubid]

    assert all(b.deleted for b in pool.state.boxes)

    del_updates = sorted(
        (u for u in updates.recorded
         if u["update_type"] == "updateDeleteMessages"),
        key=lambda u: u["user_id"],
    )
    assert {u["user_id"] for u in del_updates} == {1, 2}
    actor_upd = next(u for u in del_updates if u["user_id"] == 1)
    peer_upd = next(u for u in del_updates if u["user_id"] == 2)
    assert actor_upd["update_data"]["messages"] == [actor_ubid]
    assert peer_upd["update_data"]["messages"] == [peer_ubid]


@pytest.mark.asyncio
async def test_delete_revoke_true_non_sender_is_forbidden() -> None:
    svc, pool, _ = make_chat_service()
    _setup_pm_dialog(pool)

    await _send(svc, sender=2, dialog_id=2001, text="from peer")
    inbox = next(b for b in pool.boxes_for(1) if not b.out)

    resp = await svc.DeleteMessages(
        chat_pb2.DeleteMessagesRequest(
            actor_user_id=1,
            user_message_box_ids=[inbox.user_message_box_id],
            revoke=True,
        ),
        None,
    )
    assert not resp.meta.ok
    assert resp.meta.error.message == "MESSAGE_DELETE_FORBIDDEN"
    assert all(not b.deleted for b in pool.state.boxes)


@pytest.mark.asyncio
async def test_delete_revoke_false_idempotent_on_already_deleted() -> None:
    svc, pool, _ = make_chat_service()
    _setup_pm_dialog(pool)
    actor_ubid = await _send(svc, sender=1, dialog_id=2001, text="hi")

    first = await svc.DeleteMessages(
        chat_pb2.DeleteMessagesRequest(
            actor_user_id=1,
            user_message_box_ids=[actor_ubid],
            revoke=False,
        ),
        None,
    )
    assert first.meta.ok
    assert first.pts_count == 1
    pts_after_first = first.pts

    second = await svc.DeleteMessages(
        chat_pb2.DeleteMessagesRequest(
            actor_user_id=1,
            user_message_box_ids=[actor_ubid],
            revoke=False,
        ),
        None,
    )
    assert second.meta.ok
    assert second.pts_count == 0
    assert list(second.deleted_ids) == []
    assert second.pts == pts_after_first


@pytest.mark.asyncio
async def test_delete_revoke_false_envelope_contains_actor_update() -> None:
    svc, pool, _ = make_chat_service()
    _setup_pm_dialog(pool)
    actor_ubid = await _send(svc, sender=1, dialog_id=2001, text="hi")

    resp = await svc.DeleteMessages(
        chat_pb2.DeleteMessagesRequest(
            actor_user_id=1,
            user_message_box_ids=[actor_ubid],
            revoke=False,
        ),
        None,
    )
    assert resp.meta.ok
    assert resp.HasField("updates")
    items = list(resp.updates.updates)
    assert len(items) == 1
    parsed = json.loads(items[0].raw_update_json)
    assert parsed["constructor"] == "updateDeleteMessages"
    assert parsed["messages"] == [actor_ubid]
    assert parsed["pts_count"] == 1


@pytest.mark.asyncio
async def test_delete_empty_request_returns_noop() -> None:
    svc, pool, _ = make_chat_service()
    _setup_pm_dialog(pool)

    resp = await svc.DeleteMessages(
        chat_pb2.DeleteMessagesRequest(
            actor_user_id=1, user_message_box_ids=[],
        ),
        None,
    )
    assert resp.meta.ok
    assert resp.pts_count == 0
    assert list(resp.deleted_ids) == []
