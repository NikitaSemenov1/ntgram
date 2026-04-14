from __future__ import annotations

from dataclasses import dataclass

import asyncpg


@dataclass(slots=True, frozen=True)
class ChatRow:
    chat_id: int
    title: str
    created_by: int


@dataclass(slots=True, frozen=True)
class DialogRow:
    dialog_id: int
    owner_user_id: int
    peer_id: int
    is_group: bool


class ChatDAO:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def next_chat_id(self) -> int:
        row = await self._pool.fetchrow(
            "UPDATE id_sequences SET next_val = next_val + 1 "
            "WHERE name = 'chat_id' RETURNING next_val"
        )
        return row["next_val"]  # type: ignore[index]

    async def next_dialog_id(self) -> int:
        row = await self._pool.fetchrow(
            "UPDATE id_sequences SET next_val = next_val + 1 "
            "WHERE name = 'dialog_id' RETURNING next_val"
        )
        return row["next_val"]  # type: ignore[index]

    async def create_chat(self, chat_id: int, title: str, creator_id: int) -> None:
        await self._pool.execute(
            "INSERT INTO chats (chat_id, title, is_group, created_by) VALUES ($1, $2, true, $3)",
            chat_id, title, creator_id,
        )

    async def get_chat(self, chat_id: int) -> ChatRow | None:
        row = await self._pool.fetchrow(
            "SELECT chat_id, title, created_by FROM chats WHERE chat_id = $1", chat_id,
        )
        return ChatRow(**row) if row else None  # type: ignore[arg-type]

    async def update_title(self, chat_id: int, title: str) -> None:
        await self._pool.execute("UPDATE chats SET title = $1 WHERE chat_id = $2", title, chat_id)

    async def add_member(self, chat_id: int, user_id: int) -> None:
        await self._pool.execute(
            "INSERT INTO chat_members (chat_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            chat_id, user_id,
        )

    async def remove_member(self, chat_id: int, user_id: int) -> None:
        await self._pool.execute(
            "DELETE FROM chat_members WHERE chat_id = $1 AND user_id = $2", chat_id, user_id,
        )

    async def get_members(self, chat_id: int) -> list[int]:
        rows = await self._pool.fetch(
            "SELECT user_id FROM chat_members WHERE chat_id = $1", chat_id,
        )
        return [r["user_id"] for r in rows]

    async def count_members(self, chat_id: int) -> int:
        row = await self._pool.fetchrow(
            "SELECT count(*) as cnt FROM chat_members WHERE chat_id = $1", chat_id,
        )
        return row["cnt"]  # type: ignore[index]

    async def create_dialog(
        self, dialog_id: int, owner_user_id: int, peer_id: int, is_group: bool,
    ) -> None:
        await self._pool.execute(
            "INSERT INTO dialogs (dialog_id, owner_user_id, peer_id, is_group) "
            "VALUES ($1, $2, $3, $4)",
            dialog_id, owner_user_id, peer_id, is_group,
        )

    async def find_private_dialog(self, user_a: int, user_b: int) -> int | None:
        row = await self._pool.fetchrow(
            """SELECT d1.dialog_id FROM dialogs d1
               JOIN dialogs d2 ON d1.dialog_id = d2.dialog_id
               WHERE d1.owner_user_id = $1 AND d1.peer_id = $2 AND d1.is_group = false
                 AND d2.owner_user_id = $2 AND d2.peer_id = $1 AND d2.is_group = false
               LIMIT 1""",
            user_a, user_b,
        )
        return row["dialog_id"] if row else None

    async def list_dialogs(self, user_id: int) -> list[DialogRow]:
        rows = await self._pool.fetch(
            "SELECT dialog_id, owner_user_id, peer_id, is_group "
            "FROM dialogs WHERE owner_user_id = $1",
            user_id,
        )
        return [DialogRow(**r) for r in rows]  # type: ignore[arg-type]
