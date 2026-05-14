from __future__ import annotations

import json
import time

import asyncpg


class UpdatesDAO:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    # PTS allocator

    async def increment_pts(self, user_id: int) -> int:
        row = await self._pool.fetchrow(
            """INSERT INTO update_state (user_id, pts, state_date_unix)
               VALUES ($1, 1, $2)
               ON CONFLICT (user_id)
               DO UPDATE SET pts = update_state.pts + 1,
                             state_date_unix = $2
               RETURNING pts""",
            int(user_id), int(time.time()),
        )
        return int(row["pts"])  # type: ignore[index]

    async def increment_pts_for_users(
        self, user_ids: list[int],
    ) -> dict[int, int]:
        result: dict[int, int] = {}
        if not user_ids:
            return result
        now = int(time.time())
        for uid in user_ids:
            row = await self._pool.fetchrow(
                """INSERT INTO update_state (user_id, pts, state_date_unix)
                   VALUES ($1, 1, $2)
                   ON CONFLICT (user_id)
                   DO UPDATE SET pts = update_state.pts + 1,
                                 state_date_unix = $2
                   RETURNING pts""",
                int(uid), now,
            )
            result[int(uid)] = int(row["pts"])  # type: ignore[index]
        return result

    # pts_update log

    async def record_pts_update(
        self,
        user_id: int,
        pts: int,
        update_type: str,
        data: dict | str,
        *,
        date_unix: int | None = None,
    ) -> None:
        """Persist one user_pts_updates row + NOTIFY subscriber."""
        sql = (
            "INSERT INTO user_pts_updates "
            "(user_id, pts, update_type, update_data, date_unix) "
            "VALUES ($1, $2, $3, $4, $5)"
        )
        payload = data if isinstance(data, str) else json.dumps(data)
        args = (
            int(user_id), int(pts), str(update_type), payload,
            int(date_unix) if date_unix else int(time.time()),
        )
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute(sql, *args)
                # NOTIFY inside the same transaction so subscribers wake after commit.
                await conn.execute(f"NOTIFY updates_{int(user_id)}, ''")

    async def record_pts_update_batch(
        self,
        items: list[tuple[int, int, str, dict | str, int | None]],
    ) -> None:
        """Persist many rows in one transaction."""
        if not items:
            return
        sql = (
            "INSERT INTO user_pts_updates "
            "(user_id, pts, update_type, update_data, date_unix) "
            "VALUES ($1, $2, $3, $4, $5)"
        )
        notified: set[int] = set()
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                for uid, pts, upd_type, data, date_unix in items:
                    payload = data if isinstance(data, str) else json.dumps(data)
                    await conn.execute(
                        sql,
                        int(uid), int(pts), str(upd_type), payload,
                        int(date_unix) if date_unix else int(time.time()),
                    )
                    notified.add(int(uid))
                for uid in notified:
                    await conn.execute(f"NOTIFY updates_{uid}, ''")

    # Reads (used by GetState / GetDifference / Subscribe)

    async def get_state(self, user_id: int) -> tuple[int, int, int, int]:
        """Return (pts, qts, seq, state_date_unix).
        """
        row = await self._pool.fetchrow(
            "SELECT pts, state_date_unix "
            "FROM update_state WHERE user_id = $1",
            int(user_id),
        )
        if row is None:
            return (0, 0, 0, 0)
        return (
            int(row["pts"]), 0, 0,
            int(row["state_date_unix"]),
        )

    async def get_pts_updates_since(
        self, user_id: int, since_pts: int, limit: int = 5000,
    ) -> list[dict]:
        rows = await self._pool.fetch(
            "SELECT pts, update_type, update_data, date_unix "
            "FROM user_pts_updates "
            "WHERE user_id = $1 AND pts > $2 ORDER BY pts LIMIT $3",
            int(user_id), int(since_pts), int(limit),
        )
        return [dict(r) for r in rows]
