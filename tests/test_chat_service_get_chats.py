from __future__ import annotations

import pytest

pytest.importorskip("asyncpg")
pytest.importorskip("grpc")

from ntgram.gen import account_pb2, chat_pb2

from tests._chat_service_factory import make_chat_service
from tests._fake_chat_pool import FakeChatPool, _ChatRec


def _profiles() -> list[account_pb2.Profile]:
    return [
        account_pb2.Profile(user_id=1, first_name="A", last_name="", username="a"),
        account_pb2.Profile(user_id=2, first_name="B", last_name="", username="b"),
    ]


@pytest.mark.asyncio
async def test_get_chats_batch_returns_minimal_chats() -> None:
    pool = FakeChatPool()
    pool.state.chats.extend([
        _ChatRec(chat_id=10, title="Alpha", created_by=1,
                 version=2, participants_count=3, date_unix=1000),
        _ChatRec(chat_id=20, title="Beta", created_by=2,
                 version=5, participants_count=10, date_unix=2000),
    ])
    svc, _, _ = make_chat_service(pool, profiles=_profiles())

    resp = await svc.GetChatsBatch(
        chat_pb2.GetChatsBatchRequest(chat_ids=[10, 20, 999]),
        None,
    )
    assert resp.meta.ok
    by_id = {c.chat_id: c for c in resp.chats}
    assert set(by_id) == {10, 20}
    assert by_id[10].title == "Alpha"
    assert by_id[10].version == 2
    assert by_id[10].participants_count == 3
    assert by_id[10].date_unix == 1000
    assert by_id[10].creator_user_id == 1


@pytest.mark.asyncio
async def test_get_chats_batch_short_circuits_on_empty() -> None:
    svc, _, _ = make_chat_service()
    resp = await svc.GetChatsBatch(
        chat_pb2.GetChatsBatchRequest(chat_ids=[]), None,
    )
    assert resp.meta.ok
    assert list(resp.chats) == []


@pytest.mark.asyncio
async def test_get_full_chat_returns_participants_with_inviter() -> None:
    pool = FakeChatPool()
    pool.state.chats.append(
        _ChatRec(chat_id=11, title="Crew", created_by=1,
                 version=2, participants_count=2, date_unix=999),
    )
    pool.add_thread(thread_id=2100, chat_id=11)
    pool.add_thread_participant(2100, 1, inviter_user_id=0, joined_at_unix=999)
    pool.add_thread_participant(2100, 2, inviter_user_id=1, joined_at_unix=1000)
    svc, _, _ = make_chat_service(pool, profiles=_profiles())

    resp = await svc.GetFullChat(
        chat_pb2.GetFullChatRequest(chat_id=11), None,
    )
    assert resp.meta.ok
    assert resp.chat_id == 11
    assert resp.creator_id == 1
    assert resp.version == 2
    assert resp.participants_count == 2
    assert resp.date_unix == 999

    by_uid = {p.user_id: p for p in resp.participants}
    assert by_uid[1].kind == 0  # creator
    assert by_uid[2].kind == 1  # member
    assert by_uid[2].inviter_user_id == 1
    assert by_uid[2].date_unix == 1000

    assert {u.user_id for u in resp.users} == {1, 2}
