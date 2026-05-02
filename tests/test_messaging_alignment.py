from __future__ import annotations

import pytest

pytest.importorskip("asyncpg")
pytest.importorskip("grpc")

from ntgram.gen import account_pb2, chat_pb2
from ntgram.services.chat.dao import ChatDAO

from tests._chat_service_factory import make_chat_service
from tests._fake_chat_pool import FakeChatPool, _ChatMemberRec, _ChatRec


# ---------------------------------------------------------------------------
# SendMessage — idempotent replay
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_message_idempotent_replay_returns_same_envelope() -> None:
    """A duplicate send (same random_id) must replay the same UpdateEnvelope."""
    svc, pool, _ = make_chat_service()
    pool.add_dialog(2001, owner_user_id=1, peer_id=2, is_group=False)
    pool.add_dialog(2001, owner_user_id=2, peer_id=1, is_group=False)

    first = await svc.SendMessage(
        chat_pb2.SendMessageRequest(
            actor_user_id=1, dialog_id=2001, text="hello", random_id=999,
        ),
        None,
    )
    assert first.meta.ok
    assert first.HasField("updates")
    first_updates = list(first.updates.updates)
    assert len(first_updates) == 2
    assert first_updates[0].WhichOneof("update") == "message_id"
    assert first_updates[1].WhichOneof("update") == "new_message"

    second = await svc.SendMessage(
        chat_pb2.SendMessageRequest(
            actor_user_id=1, dialog_id=2001, text="hello", random_id=999,
        ),
        None,
    )
    assert second.meta.ok
    assert second.actor_user_message_box_id == first.actor_user_message_box_id
    assert second.pts == first.pts
    assert second.HasField("updates")
    second_updates = list(second.updates.updates)
    assert len(second_updates) == 2

    assert second_updates[0].message_id.message_id == first_updates[0].message_id.message_id
    assert second_updates[0].message_id.random_id == first_updates[0].message_id.random_id
    assert second_updates[1].new_message.message_id == first_updates[1].new_message.message_id
    assert second_updates[1].new_message.pts == first_updates[1].new_message.pts


# ---------------------------------------------------------------------------
# SendMessage — group write rejected when actor is not a participant
# ---------------------------------------------------------------------------


def _seed_group_state(
    pool: FakeChatPool,
    *,
    chat_id: int,
    dialog_id: int,
    members: list[int],
    creator: int,
) -> None:
    """Seed minimal chat / chat_members / dialog rows for a group test."""
    pool.state.chats.append(
        _ChatRec(
            chat_id=chat_id, title="g", created_by=creator,
            version=1, participants_count=len(members), date_unix=1,
        ),
    )
    for uid in members:
        pool.state.chat_members.append(
            _ChatMemberRec(
                chat_id=chat_id, user_id=uid,
                inviter_user_id=creator, joined_at_unix=1,
            ),
        )
        pool.add_dialog(dialog_id, owner_user_id=uid, peer_id=chat_id, is_group=True)


@pytest.mark.asyncio
async def test_send_message_to_chat_without_membership_fails() -> None:
    """Group send: actor must appear in chat_members or we return 403.

    The membership check now goes through ``ChatDAO.get_member_ids`` —
    no extra RPC.
    """
    svc, pool, _ = make_chat_service()
    chat_id = 3001
    dialog_id = 2002
    # Members include user 10 only (the creator); user 20 sees the dialog
    # row but is not in chat_members, so the write must be rejected.
    pool.add_dialog(dialog_id, owner_user_id=20, peer_id=chat_id, is_group=True)
    pool.add_dialog(dialog_id, owner_user_id=10, peer_id=chat_id, is_group=True)
    pool.state.chats.append(
        _ChatRec(
            chat_id=chat_id, title="g", created_by=10,
            version=1, participants_count=1, date_unix=1,
        ),
    )
    pool.state.chat_members.append(
        _ChatMemberRec(
            chat_id=chat_id, user_id=10,
            inviter_user_id=10, joined_at_unix=1,
        ),
    )

    resp = await svc.SendMessage(
        chat_pb2.SendMessageRequest(
            actor_user_id=20, dialog_id=dialog_id, text="hi", random_id=1,
        ),
        None,
    )
    assert not resp.meta.ok
    assert resp.meta.error.message == "CHAT_WRITE_FORBIDDEN"


@pytest.mark.asyncio
async def test_send_message_to_chat_member_succeeds() -> None:
    svc, pool, _ = make_chat_service()
    chat_id = 3002
    dialog_id = 2003
    _seed_group_state(
        pool, chat_id=chat_id, dialog_id=dialog_id,
        members=[10, 20], creator=10,
    )

    resp = await svc.SendMessage(
        chat_pb2.SendMessageRequest(
            actor_user_id=20, dialog_id=dialog_id, text="hi", random_id=1,
        ),
        None,
    )
    assert resp.meta.ok
    assert resp.actor_user_message_box_id > 0
    assert {p.user_id for p in resp.participants} == {10, 20}


# ---------------------------------------------------------------------------
# ReadHistory — no-op short-circuit
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_read_history_noop_when_already_read() -> None:
    svc, pool, _ = make_chat_service()
    pool.add_dialog(2001, owner_user_id=1, peer_id=2, is_group=False)
    pool.add_dialog(2001, owner_user_id=2, peer_id=1, is_group=False)

    send = await svc.SendMessage(
        chat_pb2.SendMessageRequest(
            actor_user_id=2, dialog_id=2001, text="hi", random_id=1,
        ),
        None,
    )
    inbox_msg_id = next(
        p.user_message_box_id for p in send.participants if p.user_id == 1
    )

    first = await svc.ReadHistory(
        chat_pb2.ReadHistoryRequest(
            actor_user_id=1, dialog_id=2001, max_id=inbox_msg_id,
        ),
        None,
    )
    assert first.meta.ok
    assert first.pts_count == 1
    pts_after_first = first.pts

    second = await svc.ReadHistory(
        chat_pb2.ReadHistoryRequest(
            actor_user_id=1, dialog_id=2001, max_id=inbox_msg_id,
        ),
        None,
    )
    assert second.meta.ok
    assert second.pts_count == 0
    assert second.pts == pts_after_first


# ---------------------------------------------------------------------------
# ReadHistory — PM / group peer encoding
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_read_history_pm_update_carries_peer_user() -> None:
    svc, pool, updates = make_chat_service()
    pool.add_dialog(2001, owner_user_id=1, peer_id=2, is_group=False)
    pool.add_dialog(2001, owner_user_id=2, peer_id=1, is_group=False)

    await svc.SendMessage(
        chat_pb2.SendMessageRequest(
            actor_user_id=2, dialog_id=2001, text="msg", random_id=1,
        ),
        None,
    )
    await svc.ReadHistory(
        chat_pb2.ReadHistoryRequest(actor_user_id=1, dialog_id=2001, max_id=0),
        None,
    )

    inbox = [
        u for u in updates.recorded
        if u["user_id"] == 1 and u["update_type"] == "updateReadHistoryInbox"
    ]
    assert inbox, "expected at least one updateReadHistoryInbox row"
    last = inbox[-1]["update_data"]
    assert last["peer"]["constructor"] == "peerUser"
    assert int(last["peer"]["user_id"]) == 2  # other user

    outbox = [
        u for u in updates.recorded
        if u["user_id"] == 2 and u["update_type"] == "updateReadHistoryOutbox"
    ]
    assert outbox, "expected updateReadHistoryOutbox for sender"
    last_out = outbox[-1]["update_data"]
    assert last_out["peer"]["constructor"] == "peerUser"
    assert int(last_out["peer"]["user_id"]) == 1  # reader


@pytest.mark.asyncio
async def test_read_history_group_update_carries_peer_chat() -> None:
    svc, pool, updates = make_chat_service()
    chat_id = 3003
    dialog_id = 2010
    _seed_group_state(
        pool, chat_id=chat_id, dialog_id=dialog_id,
        members=[1, 2], creator=2,
    )

    await svc.SendMessage(
        chat_pb2.SendMessageRequest(
            actor_user_id=2, dialog_id=dialog_id, text="hi", random_id=1,
        ),
        None,
    )
    await svc.ReadHistory(
        chat_pb2.ReadHistoryRequest(
            actor_user_id=1, dialog_id=dialog_id, max_id=0,
        ),
        None,
    )

    inbox = [
        u for u in updates.recorded
        if u["user_id"] == 1 and u["update_type"] == "updateReadHistoryInbox"
    ][-1]["update_data"]
    assert inbox["peer"]["constructor"] == "peerChat"
    assert int(inbox["peer"]["chat_id"]) == chat_id

    outbox = [
        u for u in updates.recorded
        if u["user_id"] == 2 and u["update_type"] == "updateReadHistoryOutbox"
    ][-1]["update_data"]
    assert outbox["peer"]["constructor"] == "peerChat"
    assert int(outbox["peer"]["chat_id"]) == chat_id


# ---------------------------------------------------------------------------
# ChatDAO low-level helpers
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_peer_outbox_for_inbox_excludes_reader() -> None:
    """The reader's own outbox rows must not show up in receipts."""
    pool = FakeChatPool()
    pool.add_dialog(2001, owner_user_id=1, peer_id=2, is_group=False)
    pool.add_dialog(2001, owner_user_id=2, peer_id=1, is_group=False)
    dao = ChatDAO(pool)

    pool.add_message_box(
        user_id=1, user_message_box_id=10, dialog_message_id=100,
        dialog_id=2001, peer_type=0, peer_id=1,
        from_user_id=1, out=True, text="self-out", date_unix=1,
    )
    pool.add_message_box(
        user_id=1, user_message_box_id=11, dialog_message_id=100,
        dialog_id=2001, peer_type=0, peer_id=2,
        from_user_id=1, out=False, text="self-in", date_unix=1,
    )
    pool.add_message_box(
        user_id=2, user_message_box_id=20, dialog_message_id=100,
        dialog_id=2001, peer_type=0, peer_id=1,
        from_user_id=1, out=True, text="peer-out", date_unix=1,
    )

    receipts = await dao.peer_outbox_for_inbox(
        reader_user_id=1, dialog_id=2001, max_inbox_ubid=11,
    )
    assert {r.sender_user_id for r in receipts} == set()


@pytest.mark.asyncio
async def test_find_dialog_by_peer_pm_and_group() -> None:
    pool = FakeChatPool()
    pool.add_dialog(2050, owner_user_id=1, peer_id=2, is_group=False)
    pool.add_dialog(2051, owner_user_id=1, peer_id=3001, is_group=True)
    dao = ChatDAO(pool)

    assert await dao.find_dialog_by_peer(1, is_group=False, peer_id=2) == 2050
    assert await dao.find_dialog_by_peer(1, is_group=True, peer_id=3001) == 2051
    assert await dao.find_dialog_by_peer(1, is_group=True, peer_id=9999) is None
    assert await dao.find_dialog_by_peer(1, is_group=False, peer_id=3001) is None


@pytest.mark.asyncio
async def test_send_message_embeds_users_for_pm() -> None:
    """SendMessageResponse.users must contain (actor, peer) for PM."""
    svc, pool, _ = make_chat_service(
        profiles=[
            account_pb2.Profile(user_id=1, first_name="A", last_name="", username="a"),
            account_pb2.Profile(user_id=2, first_name="B", last_name="", username="b"),
        ],
    )
    pool.add_dialog(2001, owner_user_id=1, peer_id=2, is_group=False)
    pool.add_dialog(2001, owner_user_id=2, peer_id=1, is_group=False)

    resp = await svc.SendMessage(
        chat_pb2.SendMessageRequest(
            actor_user_id=1, dialog_id=2001, text="hi", random_id=1,
        ),
        None,
    )
    assert resp.meta.ok
    user_ids = {u.user_id for u in resp.users}
    assert user_ids == {1, 2}
