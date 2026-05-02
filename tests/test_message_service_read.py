from __future__ import annotations

import pytest

pytest.importorskip("asyncpg")
pytest.importorskip("grpc")

from ntgram.gen import chat_pb2
from ntgram.services.chat.service import ChatService

from tests._chat_service_factory import make_chat_service


async def _send(svc: ChatService, sender: int, dialog_id: int, text: str) -> int:
    resp = await svc.SendMessage(
        chat_pb2.SendMessageRequest(
            actor_user_id=sender, dialog_id=dialog_id, text=text,
        ),
        None,
    )
    assert resp.meta.ok
    return resp.actor_user_message_box_id


@pytest.mark.asyncio
async def test_read_history_marks_inbox_and_emits_outbox_receipt() -> None:
    svc, pool, updates = make_chat_service()
    pool.add_dialog(2001, owner_user_id=1, peer_id=2, is_group=False)
    pool.add_dialog(2001, owner_user_id=2, peer_id=1, is_group=False)

    await _send(svc, sender=2, dialog_id=2001, text="hello A")
    await _send(svc, sender=2, dialog_id=2001, text="how are you?")

    resp = await svc.ReadHistory(
        chat_pb2.ReadHistoryRequest(actor_user_id=1, dialog_id=2001, max_id=0),
        None,
    )
    assert resp.meta.ok
    assert resp.pts > 0
    assert resp.pts_count == 1
    assert len(resp.receipts) == 1
    rcp = resp.receipts[0]
    assert rcp.sender_user_id == 2
    assert rcp.sender_dialog_id == 2001
    assert rcp.max_outbox_id > 0
    assert rcp.pts > 0

    assert all(b.read for b in pool.boxes_for(1) if not b.out)
    assert pool.get_dialog(2001, 1).read_inbox_max_id == max(
        b.user_message_box_id for b in pool.boxes_for(1)
    )
    assert pool.get_dialog(2001, 2).read_outbox_max_id == max(
        b.user_message_box_id for b in pool.boxes_for(2)
    )

    inbox_updates = [
        u for u in updates.recorded
        if u["user_id"] == 1 and u["update_type"] == "updateReadHistoryInbox"
    ]
    outbox_updates = [
        u for u in updates.recorded
        if u["user_id"] == 2 and u["update_type"] == "updateReadHistoryOutbox"
    ]
    assert inbox_updates
    assert outbox_updates


@pytest.mark.asyncio
async def test_read_history_no_messages_is_a_noop() -> None:
    """Empty dialog: no-op short-circuit.

    With ``max_id=0`` the service falls back to dialog ``top_message``;
    when there is nothing to read the response is ``pts_count=0`` and the
    actor's pts is not incremented.
    """
    svc, pool, _ = make_chat_service()
    pool.add_dialog(2001, owner_user_id=1, peer_id=2, is_group=False)
    pool.add_dialog(2001, owner_user_id=2, peer_id=1, is_group=False)

    resp = await svc.ReadHistory(
        chat_pb2.ReadHistoryRequest(actor_user_id=1, dialog_id=2001, max_id=0),
        None,
    )
    assert resp.meta.ok
    assert resp.pts == 0
    assert resp.pts_count == 0
    assert list(resp.receipts) == []


@pytest.mark.asyncio
async def test_delete_messages_empty_request_is_noop() -> None:
    """Empty ``user_message_box_ids`` short-circuits without bumping pts."""
    svc, pool, _ = make_chat_service()
    pool.add_dialog(2001, owner_user_id=1, peer_id=2, is_group=False)
    pool.add_dialog(2001, owner_user_id=2, peer_id=1, is_group=False)

    await _send(svc, sender=1, dialog_id=2001, text="msg")

    resp = await svc.DeleteMessages(
        chat_pb2.DeleteMessagesRequest(
            actor_user_id=1, user_message_box_ids=[],
        ),
        None,
    )
    assert resp.meta.ok
    assert list(resp.deleted_ids) == []
    assert resp.pts_count == 0
    assert all(not b.deleted for b in pool.state.boxes)
