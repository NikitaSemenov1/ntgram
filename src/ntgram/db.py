from __future__ import annotations

import asyncpg


async def create_pool(dsn: str, *, min_size: int = 2, max_size: int = 10) -> asyncpg.Pool:
    """Create and return an asyncpg connection pool."""
    pool = await asyncpg.create_pool(dsn, min_size=min_size, max_size=max_size)
    if pool is None:
        raise RuntimeError(f"failed to create connection pool for {dsn}")
    return pool
