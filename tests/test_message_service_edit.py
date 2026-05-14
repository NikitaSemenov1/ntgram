from __future__ import annotations

import json

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
async def test_edit_message_propagates_to_all_participants() -> None:
    svc, pool, updates = make_chat_service()
    pool.add_dialog(2001, owner_user_id=1, peer_id=2, is_group=False)
    pool.add_dialog(2001, owner_user_id=2, peer_id=1, is_group=False)

    actor_ubid = await _send(svc, sender=1, dialog_id=2001, text="hi")

    sender_box = next(
        b for b in pool.boxes_for(1) if b.user_message_box_id == actor_ubid
    )
    dmid = sender_box.dialog_message_id
    assert pool.state.messages[dmid].text == "hi"

    resp = await svc.EditMessage(
        chat_pb2.EditMessageRequest(
            actor_user_id=1,
            user_message_box_id=actor_ubid,
            new_text="hello edited",
        ),
        None,
    )
    assert resp.meta.ok
    assert resp.actor_user_message_box_id == actor_ubid
    assert resp.dialog_message_id == dmid
    assert resp.edit_date > 0

    # Edit propagates by mutating the single ``messages`` row.
    edited_msg = pool.state.messages[dmid]
    assert edited_msg.text == "hello edited"
    assert edited_msg.edit_date == resp.edit_date

    edit_pts = [
        u for u in updates.recorded
        if u["update_type"] == "updateEditMessage"
    ]
    assert {u["user_id"] for u in edit_pts} == {1, 2}
    for u in edit_pts:
        msg = u["update_data"]["message"]
        assert msg["constructor"] == "message"
        assert msg["message"] == "hello edited"
        assert msg["edit_date"] == resp.edit_date


@pytest.mark.asyncio
async def test_edit_message_rejects_non_author() -> None:
    svc, pool, _ = make_chat_service()
    pool.add_dialog(2001, owner_user_id=1, peer_id=2, is_group=False)
    pool.add_dialog(2001, owner_user_id=2, peer_id=1, is_group=False)

    await _send(svc, sender=1, dialog_id=2001, text="from one")
    peer_box = next(b for b in pool.boxes_for(2) if not b.out)

    resp = await svc.EditMessage(
        chat_pb2.EditMessageRequest(
            actor_user_id=2,
            user_message_box_id=peer_box.user_message_box_id,
            new_text="i didn't write this",
        ),
        None,
    )
    assert not resp.meta.ok
    assert resp.meta.error.message == "MESSAGE_AUTHOR_REQUIRED"
    assert all(m.edit_date == 0 for m in pool.state.messages.values())


@pytest.mark.asyncio
async def test_edit_message_rejects_empty_text() -> None:
    svc, pool, _ = make_chat_service()
    pool.add_dialog(2001, owner_user_id=1, peer_id=2, is_group=False)
    pool.add_dialog(2001, owner_user_id=2, peer_id=1, is_group=False)

    actor_ubid = await _send(svc, sender=1, dialog_id=2001, text="hi")
    resp = await svc.EditMessage(
        chat_pb2.EditMessageRequest(
            actor_user_id=1,
            user_message_box_id=actor_ubid,
            new_text="   \t\n   ",
        ),
        None,
    )
    assert not resp.meta.ok
    assert resp.meta.error.message == "MESSAGE_EMPTY"


@pytest.mark.asyncio
async def test_edit_message_rejects_unknown_id() -> None:
    svc, pool, _ = make_chat_service()
    pool.add_dialog(2001, owner_user_id=1, peer_id=2, is_group=False)
    pool.add_dialog(2001, owner_user_id=2, peer_id=1, is_group=False)

    resp = await svc.EditMessage(
        chat_pb2.EditMessageRequest(
            actor_user_id=1,
            user_message_box_id=999,
            new_text="ghost edit",
        ),
        None,
    )
    assert not resp.meta.ok
    assert resp.meta.error.message == "MESSAGE_ID_INVALID"


@pytest.mark.asyncio
async def test_edit_message_rejects_deleted_message() -> None:
    """A message previously soft-deleted on the actor side cannot be edited."""
    svc, pool, _ = make_chat_service()
    pool.add_dialog(2001, owner_user_id=1, peer_id=2, is_group=False)
    pool.add_dialog(2001, owner_user_id=2, peer_id=1, is_group=False)

    actor_ubid = await _send(svc, sender=1, dialog_id=2001, text="hi")
    for b in pool.state.boxes:
        if b.user_id == 1 and b.user_message_box_id == actor_ubid:
            b.deleted = True

    resp = await svc.EditMessage(
        chat_pb2.EditMessageRequest(
            actor_user_id=1,
            user_message_box_id=actor_ubid,
            new_text="too late",
        ),
        None,
    )
    assert not resp.meta.ok
    assert resp.meta.error.message == "MESSAGE_ID_INVALID"


@pytest.mark.asyncio
async def test_edit_message_envelope_carries_actor_update() -> None:
    svc, pool, _ = make_chat_service()
    pool.add_dialog(2001, owner_user_id=1, peer_id=2, is_group=False)
    pool.add_dialog(2001, owner_user_id=2, peer_id=1, is_group=False)

    actor_ubid = await _send(svc, sender=1, dialog_id=2001, text="orig")
    resp = await svc.EditMessage(
        chat_pb2.EditMessageRequest(
            actor_user_id=1,
            user_message_box_id=actor_ubid,
            new_text="edited",
        ),
        None,
    )
    assert resp.meta.ok
    assert resp.HasField("updates")
    items = list(resp.updates.updates)
    assert len(items) == 1
    parsed = json.loads(items[0].raw_update_json)
    assert parsed["constructor"] == "updateEditMessage"
    assert parsed["message"]["id"] == actor_ubid
    assert parsed["message"]["out"] is True
    assert parsed["message"]["message"] == "edited"
