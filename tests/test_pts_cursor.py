from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("fakeredis")


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _make_cursor():
    """Create a PtsCursor backed by an in-process FakeRedis instance."""
    from fakeredis.aioredis import FakeRedis  # type: ignore[import-untyped]
    from ntgram.gateway.push.pts_cursor import PtsCursor

    fake = FakeRedis()
    c = object.__new__(PtsCursor)
    c._redis = fake
    return c


# ---------------------------------------------------------------------------
# Tests — each uses a fresh cursor backed by a fresh FakeRedis server.
# ---------------------------------------------------------------------------


def test_get_missing_returns_none() -> None:
    """get() for a key that was never set must return None."""
    c = _make_cursor()

    async def _t():
        return await c.get(12345)

    assert asyncio.run(_t()) is None


def test_set_and_get() -> None:
    """After set(pts=10), get() must return 10."""
    c = _make_cursor()

    async def _t():
        await c.set(99, 10)
        return await c.get(99)

    assert asyncio.run(_t()) == 10


def test_set_increases() -> None:
    """set() with a higher value updates the cursor."""
    c = _make_cursor()

    async def _t():
        await c.set(1, 5)
        await c.set(1, 20)
        return await c.get(1)

    assert asyncio.run(_t()) == 20


def test_set_never_decreases() -> None:
    """set() with a lower value must NOT decrease the stored cursor."""
    c = _make_cursor()

    async def _t():
        await c.set(2, 100)
        await c.set(2, 50)  # attempt to decrease
        return await c.get(2)

    assert asyncio.run(_t()) == 100


def test_delete_removes_cursor() -> None:
    """delete() must remove the key so get() returns None again."""
    c = _make_cursor()

    async def _t():
        await c.set(3, 42)
        await c.delete(3)
        return await c.get(3)

    assert asyncio.run(_t()) is None


def test_different_auth_keys_are_independent() -> None:
    """Separate auth_key_ids have independent cursors."""
    c = _make_cursor()

    async def _t():
        await c.set(10, 5)
        await c.set(20, 99)
        v10 = await c.get(10)
        v20 = await c.get(20)
        return v10, v20

    v10, v20 = asyncio.run(_t())
    assert v10 == 5
    assert v20 == 99
