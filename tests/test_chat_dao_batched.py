from __future__ import annotations

import pytest

pytest.importorskip("asyncpg")

from ntgram.services.chat.dao import ChatDAO, ChatRow


def _chat(
    chat_id: int,
    title: str,
    created_by: int,
    *,
    version: int = 1,
    participants_count: int = 1,
    date_unix: int = 0,
) -> dict:
    return {
        "chat_id": chat_id,
        "title": title,
        "created_by": created_by,
        "version": version,
        "participants_count": participants_count,
        "date_unix": date_unix,
    }


class _FakeChatPool:
    """Minimal asyncpg-shaped pool tailored for ChatDAO batched SELECTs."""

    def __init__(
        self,
        *,
        chats: list[dict],
        dialog_states: list[dict] | None = None,
    ) -> None:
        self.chats = chats
        self.dialog_states = dialog_states or []
        self.calls: list[str] = []

    async def fetch(self, sql: str, *args):
        s = " ".join(sql.split())
        self.calls.append(s)
        if "FROM chats" in s and "chat_id = ANY" in s:
            ids = {int(i) for i in args[0]}
            return [c for c in self.chats if int(c["chat_id"]) in ids]
        raise NotImplementedError(s)

    async def fetchrow(self, sql: str, *args):
        s = " ".join(sql.split())
        self.calls.append(s)
        if (
            "SELECT thread_id FROM dialog_state" in s
            and "peer_chat_id = $2" in s
        ):
            owner, chat_id = int(args[0]), int(args[1])
            for d in self.dialog_states:
                if (
                    int(d["owner_user_id"]) == owner
                    and int(d.get("peer_chat_id", 0)) == chat_id
                ):
                    return {"thread_id": int(d["thread_id"])}
            return None
        if (
            "SELECT thread_id FROM dialog_state" in s
            and "peer_user_id = $2" in s
        ):
            owner, peer_uid = int(args[0]), int(args[1])
            for d in self.dialog_states:
                if (
                    int(d["owner_user_id"]) == owner
                    and int(d.get("peer_user_id", 0)) == peer_uid
                ):
                    return {"thread_id": int(d["thread_id"])}
            return None
        raise NotImplementedError(s)


@pytest.mark.asyncio
async def test_get_chats_batch_returns_only_existing() -> None:
    pool = _FakeChatPool(
        chats=[
            _chat(1, "Alpha", 10, version=3, participants_count=5, date_unix=1000),
            _chat(2, "Beta", 20),
        ],
    )
    dao = ChatDAO(pool)
    out = await dao.get_chats_batch([1, 2, 999])
    assert set(out.keys()) == {1, 2}
    assert isinstance(out[1], ChatRow)
    assert out[1].title == "Alpha"
    assert out[1].version == 3
    assert out[1].participants_count == 5
    assert out[1].date_unix == 1000


@pytest.mark.asyncio
async def test_get_chats_batch_empty_short_circuits() -> None:
    pool = _FakeChatPool(chats=[])
    dao = ChatDAO(pool)
    out = await dao.get_chats_batch([])
    assert out == {}
    assert pool.calls == []


@pytest.mark.asyncio
async def test_chat_dao_find_thread_by_peer_pm_and_group() -> None:
    pool = _FakeChatPool(
        chats=[],
        dialog_states=[
            {"thread_id": 200, "owner_user_id": 1, "peer_user_id": 2,
             "peer_chat_id": 0},
            {"thread_id": 201, "owner_user_id": 1, "peer_user_id": 0,
             "peer_chat_id": 100},
        ],
    )
    dao = ChatDAO(pool)
    assert await dao.find_thread_by_peer(1, peer_user_id=2) == 200
    assert await dao.find_thread_by_peer(1, peer_chat_id=100) == 201
    assert await dao.find_thread_by_peer(1, peer_chat_id=999) is None
    assert await dao.find_thread_by_peer(1, peer_user_id=999) is None
