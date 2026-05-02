from __future__ import annotations

import json

import pytest

pytest.importorskip("asyncpg")
pytest.importorskip("grpc")

from ntgram.gen import account_pb2, chat_pb2

from tests._chat_service_factory import make_chat_service


@pytest.mark.asyncio
async def test_create_group_chat_emits_service_message_per_member() -> None:
    """Each participant must get a ``messageService`` row + pts update."""
    svc, pool, updates = make_chat_service(
        profiles=[
            account_pb2.Profile(user_id=1, first_name="A", last_name="", username="a"),
            account_pb2.Profile(user_id=2, first_name="B", last_name="", username="b"),
            account_pb2.Profile(user_id=3, first_name="C", last_name="", username="c"),
        ],
    )

    resp = await svc.CreateGroupChat(
        chat_pb2.CreateGroupChatRequest(
            actor_user_id=1, title="Squad", member_user_ids=[2, 3],
        ),
        None,
    )

    assert resp.meta.ok
    assert resp.chat_id > 0
    assert resp.dialog_id > 0
    assert resp.date_unix > 0
    assert resp.HasField("updates")

    # Chat row created with denormalised counts.
    assert len(pool.state.chats) == 1
    chat = pool.state.chats[0]
    assert chat.chat_id == resp.chat_id
    assert chat.participants_count == 3  # creator + 2 invited
    assert chat.version == 2  # bulk_add_members increment

    # 3 chat_members rows (creator + 2 invited).
    assert {m.user_id for m in pool.state.chat_members} == {1, 2, 3}
    for m in pool.state.chat_members:
        assert m.inviter_user_id == 1

    # 3 dialog rows (one per participant, sharing one dialog_id).
    dlg_ids = {d.dialog_id for d in pool.state.dialogs}
    assert dlg_ids == {resp.dialog_id}
    assert {d.owner_user_id for d in pool.state.dialogs} == {1, 2, 3}

    # One message_boxes row per participant for the service message.
    assert len(pool.state.boxes) == 3
    assert {b.user_id for b in pool.state.boxes} == {1, 2, 3}
    actor_box = next(b for b in pool.state.boxes if b.user_id == 1)
    assert actor_box.out is True
    assert actor_box.text == ""
    assert actor_box.peer_id == resp.chat_id

    # PTS update per participant (recorded via UpdatesServiceStub).
    assert len(updates.recorded) == 3
    for rec in updates.recorded:
        assert rec["update_type"] == "updateNewMessage"
        msg = rec["update_data"]["message"]
        assert msg["constructor"] == "messageService"
        assert msg["action"]["constructor"] == "messageActionChatCreate"
        assert msg["action"]["title"] == "Squad"
        assert set(msg["action"]["users"]) == {1, 2, 3}

    # UpdateEnvelope carries the actor's update with raw_update_json.
    items = list(resp.updates.updates)
    assert len(items) == 1
    actor_update = json.loads(items[0].raw_update_json)
    assert actor_update["constructor"] == "updateNewMessage"
    assert actor_update["message"]["constructor"] == "messageService"
    assert actor_update["message"]["out"] is True

    # Embedded users + chats.
    assert {u.user_id for u in resp.users} == {1, 2, 3}
    assert len(resp.chats) == 1
    assert resp.chats[0].chat_id == resp.chat_id
    assert resp.chats[0].participants_count == 3
    assert resp.chats[0].version == 2


@pytest.mark.asyncio
async def test_create_group_chat_rejects_empty_title() -> None:
    svc, _, _ = make_chat_service()
    resp = await svc.CreateGroupChat(
        chat_pb2.CreateGroupChatRequest(
            actor_user_id=1, title="   ", member_user_ids=[2],
        ),
        None,
    )
    assert not resp.meta.ok
    assert resp.meta.error.message == "CHAT_TITLE_EMPTY"


@pytest.mark.asyncio
async def test_create_group_chat_dedupes_actor_in_member_ids() -> None:
    """Passing the actor's id in ``member_user_ids`` must not duplicate them."""
    svc, pool, _ = make_chat_service()

    resp = await svc.CreateGroupChat(
        chat_pb2.CreateGroupChatRequest(
            actor_user_id=1, title="Solo+1", member_user_ids=[1, 1, 2, 2],
        ),
        None,
    )
    assert resp.meta.ok

    # Distinct participants only: 1 (creator) + 2.
    assert {b.user_id for b in pool.state.boxes} == {1, 2}
    chat = pool.state.chats[0]
    assert chat.participants_count == 2
