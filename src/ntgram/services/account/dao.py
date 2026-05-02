from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

import asyncpg


@dataclass(slots=True, frozen=True)
class UserRow:
    user_id: int
    phone: str
    first_name: str
    last_name: str
    username: str | None = None
    bio: str = ""


@dataclass(slots=True, frozen=True)
class PhoneCodeRow:
    phone: str
    code: str
    hash: str
    expires_at: datetime


class AccountDAO:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def next_user_id(self) -> int:
        row = await self._pool.fetchrow(
            "UPDATE id_sequences SET next_val = next_val + 1 "
            "WHERE name = 'user_id' RETURNING next_val"
        )
        return row["next_val"]  # type: ignore[index]

    async def create_user(self, user_id: int, phone: str, first_name: str, last_name: str) -> None:
        await self._pool.execute(
            "INSERT INTO users (user_id, phone, first_name, last_name) VALUES ($1, $2, $3, $4)",
            user_id, phone, first_name, last_name,
        )

    async def get_user_by_id(self, user_id: int) -> UserRow | None:
        row = await self._pool.fetchrow(
            "SELECT user_id, phone, first_name, last_name, username FROM users WHERE user_id = $1",
            user_id,
        )
        if row is None:
            return None
        return UserRow(
            user_id=row["user_id"],
            phone=row["phone"],
            first_name=row["first_name"],
            last_name=row["last_name"],
            username=row["username"],
        )

    async def get_user_by_phone(self, phone: str) -> UserRow | None:
        row = await self._pool.fetchrow(
            "SELECT user_id, phone, first_name, last_name, username FROM users WHERE phone = $1",
            phone,
        )
        if row is None:
            return None
        return UserRow(
            user_id=row["user_id"],
            phone=row["phone"],
            first_name=row["first_name"],
            last_name=row["last_name"],
            username=row["username"],
        )

    async def get_user_id_by_username(self, username: str) -> int | None:
        """username must already be normalized (lowercase)."""
        row = await self._pool.fetchrow(
            "SELECT user_id FROM users WHERE username = $1",
            username,
        )
        if row is None:
            return None
        return int(row["user_id"])

    async def get_user_by_username(self, username: str) -> UserRow | None:
        """Exact match on stored username (already normalized lowercase)."""
        row = await self._pool.fetchrow(
            """
            SELECT u.user_id, u.phone, u.first_name, u.last_name, u.username,
                   coalesce(p.bio, '') AS bio
            FROM users u
            LEFT JOIN user_profiles p USING (user_id)
            WHERE u.username = $1
            """,
            username,
        )
        if row is None:
            return None
        return UserRow(
            user_id=row["user_id"],
            phone=row["phone"],
            first_name=row["first_name"],
            last_name=row["last_name"],
            username=row["username"],
            bio=row["bio"],
        )

    async def search_usernames_prefix(
        self, prefix: str, limit: int, exclude_user_id: int,
    ) -> list[UserRow]:
        """Prefix match on users.username; prefix must be safe for LIKE (no %/_)."""
        rows = await self._pool.fetch(
            """
            SELECT u.user_id, u.phone, u.first_name, u.last_name, u.username,
                   coalesce(p.bio, '') AS bio
            FROM users u
            LEFT JOIN user_profiles p USING (user_id)
            WHERE u.username IS NOT NULL
              AND u.username LIKE $1 || '%'
              AND u.user_id != $2
            ORDER BY u.username
            LIMIT $3
            """,
            prefix,
            exclude_user_id,
            limit,
        )
        return [
            UserRow(
                user_id=r["user_id"],
                phone=r["phone"],
                first_name=r["first_name"],
                last_name=r["last_name"],
                username=r["username"],
                bio=r["bio"],
            )
            for r in rows
        ]

    async def set_username(self, user_id: int, username: str | None) -> None:
        await self._pool.execute(
            "UPDATE users SET username = $2 WHERE user_id = $1",
            user_id,
            username,
        )

    async def get_profile(self, user_id: int) -> UserRow | None:
        """Fetch user row joined with bio from user_profiles."""
        row = await self._pool.fetchrow(
            """SELECT u.user_id, u.phone, u.first_name, u.last_name,
                      coalesce(p.bio, '') AS bio, u.username
               FROM users u LEFT JOIN user_profiles p ON u.user_id = p.user_id
               WHERE u.user_id = $1""",
            user_id,
        )
        if row is None:
            return None
        return UserRow(
            user_id=row["user_id"],
            phone=row["phone"],
            first_name=row["first_name"],
            last_name=row["last_name"],
            bio=row["bio"],
            username=row["username"],
        )

    async def upsert_profile(
        self, user_id: int, first_name: str, last_name: str, bio: str,
    ) -> None:
        await self._pool.execute(
            "UPDATE users SET first_name = $2, last_name = $3 WHERE user_id = $1",
            user_id, first_name, last_name,
        )
        await self._pool.execute(
            """INSERT INTO user_profiles (user_id, bio, updated_at) VALUES ($1, $2, now())
               ON CONFLICT (user_id) DO UPDATE SET bio = $2, updated_at = now()""",
            user_id, bio,
        )

    async def save_phone_code(
        self, phone: str, code: str, hash_val: str, expires_at: datetime,
    ) -> None:
        await self._pool.execute(
            """INSERT INTO phone_codes (phone, code, hash, expires_at) VALUES ($1, $2, $3, $4)
               ON CONFLICT (phone) DO UPDATE SET code = $2, hash = $3, expires_at = $4""",
            phone, code, hash_val, expires_at,
        )

    async def get_phone_code(self, phone: str) -> PhoneCodeRow | None:
        row = await self._pool.fetchrow(
            "SELECT phone, code, hash, expires_at FROM phone_codes WHERE phone = $1",
            phone,
        )
        return PhoneCodeRow(**row) if row else None  # type: ignore[arg-type]

    async def delete_phone_code(self, phone: str) -> None:
        await self._pool.execute("DELETE FROM phone_codes WHERE phone = $1", phone)
