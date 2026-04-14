from __future__ import annotations

from datetime import datetime, timedelta, timezone

import asyncpg

ONLINE_TTL = timedelta(minutes=5)


class StatusDAO:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def set_online(self, user_id: int, session_id: int) -> None:
        await self._pool.execute(
            "UPDATE sessions SET is_online = true, updated_at = now() "
            "WHERE session_id = $1 AND user_id = $2",
            session_id, user_id,
        )

    async def set_offline(self, user_id: int, session_id: int) -> None:
        await self._pool.execute(
            "UPDATE sessions SET is_online = false, updated_at = now() "
            "WHERE session_id = $1 AND user_id = $2",
            session_id, user_id,
        )

    async def count_online_sessions(self, user_id: int) -> int:
        cutoff = datetime.now(timezone.utc) - ONLINE_TTL
        row = await self._pool.fetchrow(
            "SELECT count(*) as cnt FROM sessions "
            "WHERE user_id = $1 AND is_online = true AND updated_at > $2",
            user_id, cutoff,
        )
        return row["cnt"]  # type: ignore[index]

    async def get_last_seen(self, user_id: int) -> int:
        row = await self._pool.fetchrow(
            "SELECT extract(epoch from max(updated_at))::bigint as ts "
            "FROM sessions WHERE user_id = $1",
            user_id,
        )
        return row["ts"] if row and row["ts"] else 0
