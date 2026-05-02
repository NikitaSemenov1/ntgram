from __future__ import annotations

import json

import pytest

pytest.importorskip("asyncpg")
pytest.importorskip("grpc")

from ntgram.gen import chat_pb2
from ntgram.services.chat.service import ChatService

from tests._chat_service_factory import make_chat_service


async def _seed_group(svc: ChatService, *, members: list[int]) -> int:
    """Create a chat with ``members[0]`` as creator + the rest invited.

    Returns the new chat_id.
    """
    actor, *invited = members
    resp = await svc.CreateGroupChat(
        chat_pb2.CreateGroupChatRequest(
            actor_user_id=actor, title="Crew", member_user_ids=invited,
        ),
        None,
    )
    assert resp.meta.ok
    return int(resp.chat_id)


@pytest.mark.asyncio
async def test_add_chat_user_emits_action_and_bumps_version() -> None:
    svc, pool, updates = make_chat_service()
    chat_id = await _seed_group(svc, members=[1, 2])
    boxes_before = len(pool.state.boxes)
    pts_before = len(updates.recorded)
    chat_v_before = pool.state.chats[0].version

    resp = await svc.AddChatUser(
        chat_pb2.AddChatUserRequest(
            actor_user_id=1, chat_id=chat_id, user_id=3,
        ),
        None,
    )
    assert resp.meta.ok
    assert resp.HasField("updates")

    # New member is now in chat_members (creator + 2 + new = {1, 2, 3}).
    assert {m.user_id for m in pool.state.chat_members if m.chat_id == chat_id} == {1, 2, 3}
    new_member = next(
        m for m in pool.state.chat_members
        if m.chat_id == chat_id and m.user_id == 3
    )
    assert new_member.inviter_user_id == 1

    # Service message row per participant of the *new* roster (3 rows).
    new_boxes = pool.state.boxes[boxes_before:]
    assert {b.user_id for b in new_boxes} == {1, 2, 3}
    new_pts = updates.recorded[pts_before:]
    assert len(new_pts) == 3
    for u in new_pts:
        msg = u["update_data"]["message"]
        assert msg["constructor"] == "messageService"
        assert msg["action"]["constructor"] == "messageActionChatAddUser"
        assert msg["action"]["users"] == [3]

    chat_v_after = pool.state.chats[0].version
    assert chat_v_after > chat_v_before
    assert pool.state.chats[0].participants_count == 3

    # Actor envelope is the actor's update.
    items = list(resp.updates.updates)
    assert len(items) == 1
    actor_msg = json.loads(items[0].raw_update_json)
    assert actor_msg["constructor"] == "updateNewMessage"
    assert actor_msg["message"]["action"]["users"] == [3]


@pytest.mark.asyncio
async def test_add_chat_user_rejects_non_member_actor() -> None:
    svc, _, _ = make_chat_service()
    chat_id = await _seed_group(svc, members=[1, 2])
    resp = await svc.AddChatUser(
        chat_pb2.AddChatUserRequest(
            actor_user_id=99, chat_id=chat_id, user_id=3,
        ),
        None,
    )
    assert not resp.meta.ok
    assert resp.meta.error.message == "USER_NOT_PARTICIPANT"


@pytest.mark.asyncio
async def test_add_chat_user_rejects_existing_member() -> None:
    svc, _, _ = make_chat_service()
    chat_id = await _seed_group(svc, members=[1, 2])
    resp = await svc.AddChatUser(
        chat_pb2.AddChatUserRequest(
            actor_user_id=1, chat_id=chat_id, user_id=2,
        ),
        None,
    )
    assert not resp.meta.ok
    assert resp.meta.error.message == "USER_ALREADY_PARTICIPANT"


@pytest.mark.asyncio
async def test_edit_chat_title_emits_action_and_bumps_version() -> None:
    svc, pool, updates = make_chat_service()
    chat_id = await _seed_group(svc, members=[1, 2, 3])
    boxes_before = len(pool.state.boxes)
    pts_before = len(updates.recorded)
    v_before = pool.state.chats[0].version

    resp = await svc.EditChatTitle(
        chat_pb2.EditChatTitleRequest(
            actor_user_id=1, chat_id=chat_id, title="Renamed",
        ),
        None,
    )
    assert resp.meta.ok
    assert resp.HasField("updates")

    # Title persisted, version bumped (update_title +1).
    assert pool.state.chats[0].title == "Renamed"
    assert pool.state.chats[0].version == v_before + 1

    # Service messages recorded for all members.
    new_boxes = pool.state.boxes[boxes_before:]
    assert {b.user_id for b in new_boxes} == {1, 2, 3}
    new_pts = updates.recorded[pts_before:]
    assert len(new_pts) == 3
    for u in new_pts:
        msg = u["update_data"]["message"]
        assert msg["constructor"] == "messageService"
        assert msg["action"]["constructor"] == "messageActionChatEditTitle"
        assert msg["action"]["title"] == "Renamed"


@pytest.mark.asyncio
async def test_edit_chat_title_rejects_empty_and_long() -> None:
    svc, _, _ = make_chat_service()
    chat_id = await _seed_group(svc, members=[1, 2])

    empty = await svc.EditChatTitle(
        chat_pb2.EditChatTitleRequest(
            actor_user_id=1, chat_id=chat_id, title="   ",
        ),
        None,
    )
    assert not empty.meta.ok
    assert empty.meta.error.message == "CHAT_TITLE_EMPTY"

    too_long = await svc.EditChatTitle(
        chat_pb2.EditChatTitleRequest(
            actor_user_id=1, chat_id=chat_id, title="x" * 200,
        ),
        None,
    )
    assert not too_long.meta.ok
    assert too_long.meta.error.message == "CHAT_TITLE_TOO_LONG"
