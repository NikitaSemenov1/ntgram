from __future__ import annotations

import json

import pytest

pytest.importorskip("asyncpg")
pytest.importorskip("grpc")

from ntgram.gen import chat_pb2, common_pb2
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
    events_before = len(pool.state.chat_events)
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

    # New member is now in thread_participants (creator + 2 + new = {1, 2, 3}).
    threads = [t for t in pool.state.threads if t.chat_id == chat_id]
    assert len(threads) == 1
    thread_id = threads[0].thread_id
    assert {
        p.user_id for p in pool.state.thread_participants
        if p.thread_id == thread_id
    } == {1, 2, 3}
    new_member = next(
        p for p in pool.state.thread_participants
        if p.thread_id == thread_id and p.user_id == 3
    )
    assert new_member.inviter_user_id == 1

    # Lifecycle event persisted in chat_events (not in messages/message_boxes).
    new_events = pool.state.chat_events[events_before:]
    assert len(new_events) == 1
    assert new_events[0].kind == "chat_add_user"
    assert new_events[0].chat_id == chat_id

    # PTS push fans out one updateNewMessage per participant of the new roster.
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
    events_before = len(pool.state.chat_events)
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

    # Lifecycle event persisted in chat_events.
    new_events = pool.state.chat_events[events_before:]
    assert len(new_events) == 1
    assert new_events[0].kind == "chat_edit_title"
    new_pts = updates.recorded[pts_before:]
    assert len(new_pts) == 3
    pts_uids = {u["user_id"] for u in new_pts}
    assert pts_uids == {1, 2, 3}
    for u in new_pts:
        msg = u["update_data"]["message"]
        assert msg["constructor"] == "messageService"
        assert msg["action"]["constructor"] == "messageActionChatEditTitle"
        assert msg["action"]["title"] == "Renamed"


@pytest.mark.asyncio
async def test_add_chat_user_reuses_thread_so_new_member_sees_history() -> None:
    """Regression: ``AddChatUser`` must not allocate a new thread_id.

    Before the thread-centric rework ``AddChatUser`` created a fresh
    ``dialog_id`` for the new member's ``dialogs`` row while existing
    messages stayed pinned to the original group ``dialog_id``. The
    new participant's history was therefore empty. After the fix the
    chat is bound to exactly one ``thread_id`` and adding a member only
    adds rows to ``thread_participants`` + ``dialog_state``, leaving
    history visible.
    """
    svc, pool, _ = make_chat_service()
    chat_id = await _seed_group(svc, members=[1, 2])

    # User 1 sends a couple of messages before user 3 joins.
    for text, rid in (("first", 1001), ("second", 1002)):
        send = await svc.SendMessage(
            chat_pb2.SendMessageRequest(
                actor_user_id=1, text=text, random_id=rid,
                peer=common_pb2.InputPeer(actor_user_id=1, chat_id=chat_id),
            ),
            None,
        )
        assert send.meta.ok, send.meta.error.message
    # ``threads`` must still hold a single row for this chat after sends.
    threads_for_chat = [t for t in pool.state.threads if t.chat_id == chat_id]
    assert len(threads_for_chat) == 1
    original_thread_id = threads_for_chat[0].thread_id

    add = await svc.AddChatUser(
        chat_pb2.AddChatUserRequest(
            actor_user_id=1, chat_id=chat_id, user_id=3,
        ),
        None,
    )
    assert add.meta.ok

    # Critical invariant: still ONE thread, with the same id.
    threads_after = [t for t in pool.state.threads if t.chat_id == chat_id]
    assert len(threads_after) == 1
    assert threads_after[0].thread_id == original_thread_id

    # And user 3 has a dialog_state attached to that very thread, so
    # ``ListMessages`` / history queries find the old rows via thread_id.
    state3 = next(
        d for d in pool.state.dialog_states
        if d.thread_id == original_thread_id and d.owner_user_id == 3
    )
    assert state3.peer_chat_id == chat_id


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
