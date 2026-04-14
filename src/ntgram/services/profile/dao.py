from __future__ import annotations

from dataclasses import dataclass

import asyncpg


@dataclass(slots=True, frozen=True)
class ProfileRow:
    user_id: int
    first_name: str
    last_name: str
    bio: str


class ProfileDAO:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def get_profile(self, user_id: int) -> ProfileRow | None:
        row = await self._pool.fetchrow(
            """SELECT u.user_id, u.first_name, u.last_name, coalesce(p.bio, '') as bio
               FROM users u LEFT JOIN user_profiles p ON u.user_id = p.user_id
               WHERE u.user_id = $1""",
            user_id,
        )
        return ProfileRow(**row) if row else None  # type: ignore[arg-type]

    async def upsert_profile(self, user_id: int, first_name: str, last_name: str, bio: str) -> None:
        await self._pool.execute(
            "UPDATE users SET first_name = $2, last_name = $3 WHERE user_id = $1",
            user_id, first_name, last_name,
        )
        await self._pool.execute(
            """INSERT INTO user_profiles (user_id, bio, updated_at) VALUES ($1, $2, now())
               ON CONFLICT (user_id) DO UPDATE SET bio = $2, updated_at = now()""",
            user_id, bio,
        )
