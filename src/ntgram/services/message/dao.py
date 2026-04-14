from __future__ import annotations

import json
import time
from dataclasses import dataclass

import asyncpg


@dataclass(slots=True, frozen=True)
class MessageRow:
    message_id: int
    dialog_id: int
    from_user_id: int
    message_text: str
    date_unix: int


class MessageDAO:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def next_message_id(self) -> int:
        row = await self._pool.fetchrow(
            "UPDATE id_sequences SET next_val = next_val + 1 "
            "WHERE name = 'message_id' RETURNING next_val"
        )
        return row["next_val"]  # type: ignore[index]

    async def find_by_random_id(self, from_user_id: int, random_id: int) -> int | None:
        row = await self._pool.fetchrow(
            "SELECT message_id FROM messages WHERE from_user_id = $1 AND random_id = $2",
            from_user_id, random_id,
        )
        return row["message_id"] if row else None

    async def create_message(
        self,
        message_id: int,
        dialog_id: int,
        from_user_id: int,
        text: str,
        date_unix: int,
        random_id: int | None,
    ) -> None:
        await self._pool.execute(
            "INSERT INTO messages "
            "(message_id, dialog_id, from_user_id, message_text, date_unix, random_id) "
            "VALUES ($1, $2, $3, $4, $5, $6)",
            message_id, dialog_id, from_user_id, text, date_unix, random_id,
        )

    async def message_exists(self, message_id: int) -> bool:
        row = await self._pool.fetchrow("SELECT 1 FROM messages WHERE message_id = $1", message_id)
        return row is not None

    async def get_history(self, dialog_id: int, user_id: int, limit: int) -> list[MessageRow]:
        rows = await self._pool.fetch(
            """SELECT m.message_id, m.dialog_id, m.from_user_id, m.message_text, m.date_unix
               FROM messages m
               WHERE m.dialog_id = $1
                 AND NOT EXISTS (
                     SELECT 1 FROM message_deletions md
                     WHERE md.message_id = m.message_id AND md.deleted_for_user_id = $2
                 )
               ORDER BY m.message_id DESC LIMIT $3""",
            dialog_id, user_id, limit,
        )
        return [MessageRow(**r) for r in rows]  # type: ignore[arg-type]

    async def delete_messages(self, message_ids: list[int], deleted_for_user_id: int) -> list[int]:
        deleted = []
        for mid in message_ids:
            if await self.message_exists(mid):
                await self._pool.execute(
                    "INSERT INTO message_deletions "
                    "(dialog_id, message_id, deleted_by, deleted_for_user_id) "
                    "SELECT dialog_id, $1, $2, $2 FROM messages "
                    "WHERE message_id = $1 ON CONFLICT DO NOTHING",
                    mid, deleted_for_user_id,
                )
                deleted.append(mid)
        return deleted

    async def delete_messages_for_all(
        self, message_ids: list[int], member_ids: list[int],
    ) -> list[int]:
        deleted = []
        for mid in message_ids:
            if not await self.message_exists(mid):
                continue
            deleted.append(mid)
            for uid in member_ids:
                await self._pool.execute(
                    "INSERT INTO message_deletions "
                    "(dialog_id, message_id, deleted_by, deleted_for_user_id) "
                    "SELECT dialog_id, $1, $2, $2 FROM messages "
                    "WHERE message_id = $1 ON CONFLICT DO NOTHING",
                    mid, uid,
                )
        return deleted

    async def update_read_inbox(self, owner_user_id: int, dialog_id: int, max_id: int) -> None:
        await self._pool.execute(
            "UPDATE dialogs SET read_inbox_max_id = GREATEST(read_inbox_max_id, $1) "
            "WHERE dialog_id = $2 AND owner_user_id = $3",
            max_id, dialog_id, owner_user_id,
        )

    async def increment_pts(self, user_id: int) -> int:
        row = await self._pool.fetchrow(
            """INSERT INTO update_state
               (user_id, session_id, pts, qts, seq, state_date_unix)
               VALUES ($1, 0, 1, 0, 0, $2)
               ON CONFLICT (user_id, session_id)
               DO UPDATE SET pts = update_state.pts + 1,
               state_date_unix = $2
               RETURNING pts""",
            user_id, int(time.time()),
        )
        return row["pts"]  # type: ignore[index]

    async def record_pts_update(self, user_id: int, pts: int, update_type: str, data: dict) -> None:
        await self._pool.execute(
            "INSERT INTO user_pts_updates (user_id, pts, update_type, update_data, date_unix) "
            "VALUES ($1, $2, $3, $4, $5)",
            user_id, pts, update_type, json.dumps(data), int(time.time()),
        )

    async def get_state(self, user_id: int) -> tuple[int, int, int, int]:
        """Returns (pts, qts, seq, date)."""
        row = await self._pool.fetchrow(
            "SELECT pts, qts, seq, state_date_unix "
            "FROM update_state WHERE user_id = $1 AND session_id = 0",
            user_id,
        )
        if row is None:
            return (0, 0, 0, 0)
        return (row["pts"], row["qts"], row["seq"], row["state_date_unix"])

    async def get_pts_updates_since(
        self, user_id: int, since_pts: int, limit: int = 5000,
    ) -> list[dict]:
        rows = await self._pool.fetch(
            "SELECT pts, update_type, update_data, date_unix "
            "FROM user_pts_updates "
            "WHERE user_id = $1 AND pts > $2 ORDER BY pts LIMIT $3",
            user_id, since_pts, limit,
        )
        return [dict(r) for r in rows]

    async def get_dialog_participants(
        self, dialog_id: int,
    ) -> list[int]:
        """Return all user_ids who have this dialog (both sides of PM, or all group members)."""
        rows = await self._pool.fetch(
            "SELECT owner_user_id FROM dialogs WHERE dialog_id = $1",
            dialog_id,
        )
        return [r["owner_user_id"] for r in rows]

    async def increment_pts_for_users(
        self, user_ids: list[int],
    ) -> dict[int, int]:
        """Increment PTS for multiple users, return {user_id: new_pts}."""
        result: dict[int, int] = {}
        now = int(time.time())
        for uid in user_ids:
            row = await self._pool.fetchrow(
                """INSERT INTO update_state
                   (user_id, session_id, pts, qts, seq, state_date_unix)
                   VALUES ($1, 0, 1, 0, 0, $2)
                   ON CONFLICT (user_id, session_id)
                   DO UPDATE SET pts = update_state.pts + 1,
                   state_date_unix = $2
                   RETURNING pts""",
                uid, now,
            )
            result[uid] = row["pts"]  # type: ignore[index]
        return result

    async def record_pts_updates_for_users(
        self,
        user_pts: dict[int, int],
        update_type: str,
        data: dict,
    ) -> None:
        """Write a PTS update row for each user."""
        now = int(time.time())
        for uid, pts in user_pts.items():
            await self._pool.execute(
                "INSERT INTO user_pts_updates "
                "(user_id, pts, update_type, update_data, date_unix) "
                "VALUES ($1, $2, $3, $4, $5)",
                uid, pts, update_type, json.dumps(data), now,
            )
