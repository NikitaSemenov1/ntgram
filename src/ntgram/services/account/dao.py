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
            "SELECT user_id, phone, first_name, last_name FROM users WHERE user_id = $1",
            user_id,
        )
        return UserRow(**row) if row else None  # type: ignore[arg-type]

    async def get_user_by_phone(self, phone: str) -> UserRow | None:
        row = await self._pool.fetchrow(
            "SELECT user_id, phone, first_name, last_name FROM users WHERE phone = $1",
            phone,
        )
        return UserRow(**row) if row else None  # type: ignore[arg-type]

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
