from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

_TTL_SEC = 30 * 24 * 3600  # 30 days


class PtsCursor:
    """Redis-backed per-auth_key_id last-delivered-pts cursor."""

    KEY_PREFIX = "ntgram:pts_cursor"
    TTL_SEC = _TTL_SEC

    def __init__(self, dsn: str) -> None:
        from redis.asyncio import Redis  # type: ignore[import-untyped]
        self._redis: Redis = Redis.from_url(dsn, decode_responses=True)

    def _key(self, auth_key_id: int) -> str:
        return f"{self.KEY_PREFIX}:{auth_key_id}"

    async def get(self, auth_key_id: int) -> int | None:
        """Return the stored cursor pts, or None if not found."""
        try:
            val = await self._redis.get(self._key(auth_key_id))
            if val is None:
                return None
            return int(val)
        except Exception as exc:
            logger.debug("pts_cursor.get failed: auth_key_id=%d error=%s", auth_key_id, exc)
            return None

    async def set(self, auth_key_id: int, pts: int) -> None:
        """Update cursor to max(existing, pts) and refresh TTL."""
        try:
            key = self._key(auth_key_id)
            existing_raw = await self._redis.get(key)
            existing = int(existing_raw) if existing_raw is not None else None
            if existing is None or pts > existing:
                await self._redis.set(key, str(pts), ex=self.TTL_SEC)
            else:
                # Refresh TTL even if value didn't change.
                await self._redis.expire(key, self.TTL_SEC)
        except Exception as exc:
            logger.debug("pts_cursor.set failed: auth_key_id=%d pts=%d error=%s", auth_key_id, pts, exc)

    async def delete(self, auth_key_id: int) -> None:
        """Remove the cursor entry (e.g. on explicit sign-out)."""
        try:
            await self._redis.delete(self._key(auth_key_id))
        except Exception as exc:
            logger.debug("pts_cursor.delete failed: auth_key_id=%d error=%s", auth_key_id, exc)

    async def close(self) -> None:
        await self._redis.aclose()
