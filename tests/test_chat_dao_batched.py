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
    """Minimal asyncpg-shaped pool tailored for ChatDAO batch SELECTs."""

    def __init__(
        self,
        *,
        chats: list[dict],
        members: list[dict],
        dialogs: list[dict] | None = None,
    ) -> None:
        self.chats = chats
        self.members = members
        self.dialogs = dialogs or []
        self.calls: list[str] = []

    async def fetch(self, sql: str, *args):
        s = " ".join(sql.split())
        self.calls.append(s)
        if "FROM chats" in s and "chat_id = ANY" in s:
            ids = set(int(i) for i in args[0])
            return [c for c in self.chats if int(c["chat_id"]) in ids]
        if "FROM chat_members" in s and "chat_id = ANY" in s and "GROUP BY" in s:
            ids = set(int(i) for i in args[0])
            counts: dict[int, int] = {}
            for m in self.members:
                cid = int(m["chat_id"])
                if cid in ids:
                    counts[cid] = counts.get(cid, 0) + 1
            return [{"chat_id": cid, "cnt": cnt} for cid, cnt in counts.items()]
        raise NotImplementedError(s)

    async def fetchrow(self, sql: str, *args):
        s = " ".join(sql.split())
        self.calls.append(s)
        if (
            "SELECT dialog_id FROM dialogs" in s
            and "owner_user_id = $1" in s
            and "is_group = $2" in s
            and "peer_id = $3" in s
        ):
            owner, is_group, peer_id = int(args[0]), bool(args[1]), int(args[2])
            for d in self.dialogs:
                if (
                    int(d["owner_user_id"]) == owner
                    and bool(d["is_group"]) == is_group
                    and int(d["peer_id"]) == peer_id
                ):
                    return {"dialog_id": int(d["dialog_id"])}
            return None
        raise NotImplementedError(s)


@pytest.mark.asyncio
async def test_get_chats_batch_returns_only_existing() -> None:
    pool = _FakeChatPool(
        chats=[
            _chat(1, "Alpha", 10, version=3, participants_count=5, date_unix=1000),
            _chat(2, "Beta", 20),
        ],
        members=[],
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
    pool = _FakeChatPool(chats=[], members=[])
    dao = ChatDAO(pool)
    out = await dao.get_chats_batch([])
    assert out == {}
    assert pool.calls == []


@pytest.mark.asyncio
async def test_get_members_count_batch_groups_correctly() -> None:
    pool = _FakeChatPool(
        chats=[],
        members=[
            {"chat_id": 1, "user_id": 10},
            {"chat_id": 1, "user_id": 11},
            {"chat_id": 1, "user_id": 12},
            {"chat_id": 2, "user_id": 20},
        ],
    )
    dao = ChatDAO(pool)
    out = await dao.get_members_count_batch([1, 2, 3])
    assert out == {1: 3, 2: 1}


@pytest.mark.asyncio
async def test_get_members_count_batch_empty_short_circuits() -> None:
    pool = _FakeChatPool(chats=[], members=[])
    dao = ChatDAO(pool)
    out = await dao.get_members_count_batch([])
    assert out == {}
    assert pool.calls == []


@pytest.mark.asyncio
async def test_chat_dao_find_dialog_by_peer() -> None:
    pool = _FakeChatPool(
        chats=[],
        members=[],
        dialogs=[
            {"dialog_id": 200, "owner_user_id": 1, "peer_id": 2, "is_group": False},
            {"dialog_id": 201, "owner_user_id": 1, "peer_id": 100, "is_group": True},
        ],
    )
    dao = ChatDAO(pool)
    assert await dao.find_dialog_by_peer(1, is_group=False, peer_id=2) == 200
    assert await dao.find_dialog_by_peer(1, is_group=True, peer_id=100) == 201
    assert await dao.find_dialog_by_peer(1, is_group=True, peer_id=999) is None
