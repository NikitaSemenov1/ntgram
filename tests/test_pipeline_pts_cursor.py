from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_fake_cursor(initial: int | None = None):
    """Return a minimal mock PtsCursor with optional initial value."""
    from fakeredis.aioredis import FakeRedis  # type: ignore[import-untyped]
    from ntgram.gateway.push.pts_cursor import PtsCursor

    fake = FakeRedis()
    c = object.__new__(PtsCursor)
    c._redis = fake

    if initial is not None:
        asyncio.run(_async_set(c, 9999, initial))  # prime key=9999 for test
    return c


async def _async_set(cursor, auth_key_id: int, pts: int) -> None:
    await cursor.set(auth_key_id, pts)


def _make_sessions(user_id: int = 42):
    pytest.importorskip("grpc")
    from ntgram.gateway.mtproto.session_store import SessionStore
    sessions = SessionStore()
    session = sessions.complete_handshake(
        session_id=1, auth_key=b"k" * 256, new_nonce=1, server_nonce=2,
    )
    sessions.bind_user(session.auth_key_id, user_id)
    return sessions, session.auth_key_id


# ---------------------------------------------------------------------------
# Test: cursor provides since_pts to run_subscriber
# ---------------------------------------------------------------------------


def test_ensure_push_slot_uses_cursor_pts() -> None:
    """When cursor has pts=77, run_subscriber is called with since_pts=77."""
    pytest.importorskip("grpc")
    from ntgram.gateway.connection.context import ConnectionContext
    from ntgram.gateway.connection.pipeline import ConnectionPipeline
    from ntgram.gateway.mtproto.session_store import SessionStore
    from ntgram.gateway.push_registry import PushRegistry
    from ntgram.gateway.push.pts_cursor import PtsCursor

    sessions, auth_key_id = _make_sessions(user_id=42)

    # Cursor returns 77.
    fake_cursor = MagicMock(spec=PtsCursor)
    fake_cursor.get = AsyncMock(return_value=77)

    captured: dict = {}

    async def fake_run_subscriber(slot, updates_client, account_client, chat_client, *, since_pts=0):
        captured["since_pts"] = since_pts
        # Immediately return — we just capture the argument.

    updates_client = MagicMock()
    updates_client.get_state = AsyncMock(return_value=MagicMock(pts=100))  # should NOT be called

    pipeline = ConnectionPipeline(
        sessions=sessions,
        outbox=MagicMock(),
        handshake=MagicMock(),
        router=MagicMock(),
        store=MagicMock(),
        outbound=MagicMock(),
        push_registry=PushRegistry(),
        rpc_drop_answer=MagicMock(),
        updates_client=updates_client,
        account_client=MagicMock(),
        chat_client=MagicMock(),
        pts_cursor=fake_cursor,
    )

    ctx = ConnectionContext(peer=("127.0.0.1", 1234), handshake_session_id=0)

    with patch("ntgram.gateway.push.subscriber.run_subscriber", side_effect=fake_run_subscriber):
        asyncio.run(pipeline._ensure_push_slot(
            ctx,
            auth_key_id=auth_key_id,
            session_id=1,
            user_id=42,
        ))

    assert captured.get("since_pts") == 77, f"expected since_pts=77, got {captured}"
    # state.pts must NOT be consulted when cursor is present.
    updates_client.get_state.assert_not_called()


def test_ensure_push_slot_fallback_to_state_pts() -> None:
    """When cursor has no entry, run_subscriber falls back to state.pts."""
    pytest.importorskip("grpc")
    from ntgram.gateway.connection.context import ConnectionContext
    from ntgram.gateway.connection.pipeline import ConnectionPipeline
    from ntgram.gateway.push_registry import PushRegistry
    from ntgram.gateway.push.pts_cursor import PtsCursor

    sessions, auth_key_id = _make_sessions(user_id=55)

    # Cursor returns None (no entry).
    fake_cursor = MagicMock(spec=PtsCursor)
    fake_cursor.get = AsyncMock(return_value=None)

    captured: dict = {}

    async def fake_run_subscriber(slot, uc, ac, cc, *, since_pts=0):
        captured["since_pts"] = since_pts

    updates_client = MagicMock()
    updates_client.get_state = AsyncMock(return_value=MagicMock(pts=33))

    pipeline = ConnectionPipeline(
        sessions=sessions,
        outbox=MagicMock(),
        handshake=MagicMock(),
        router=MagicMock(),
        store=MagicMock(),
        outbound=MagicMock(),
        push_registry=PushRegistry(),
        rpc_drop_answer=MagicMock(),
        updates_client=updates_client,
        account_client=MagicMock(),
        chat_client=MagicMock(),
        pts_cursor=fake_cursor,
    )

    ctx = ConnectionContext(peer=("127.0.0.1", 2345), handshake_session_id=0)

    with patch("ntgram.gateway.push.subscriber.run_subscriber", side_effect=fake_run_subscriber):
        asyncio.run(pipeline._ensure_push_slot(
            ctx,
            auth_key_id=auth_key_id,
            session_id=1,
            user_id=55,
        ))

    assert captured.get("since_pts") == 33, f"expected since_pts=33, got {captured}"


def test_ensure_push_slot_fallback_when_no_cursor() -> None:
    """When pts_cursor is None (not configured), fallback to state.pts."""
    pytest.importorskip("grpc")
    from ntgram.gateway.connection.context import ConnectionContext
    from ntgram.gateway.connection.pipeline import ConnectionPipeline
    from ntgram.gateway.push_registry import PushRegistry

    sessions, auth_key_id = _make_sessions(user_id=77)

    captured: dict = {}

    async def fake_run_subscriber(slot, uc, ac, cc, *, since_pts=0):
        captured["since_pts"] = since_pts

    updates_client = MagicMock()
    updates_client.get_state = AsyncMock(return_value=MagicMock(pts=50))

    pipeline = ConnectionPipeline(
        sessions=sessions,
        outbox=MagicMock(),
        handshake=MagicMock(),
        router=MagicMock(),
        store=MagicMock(),
        outbound=MagicMock(),
        push_registry=PushRegistry(),
        rpc_drop_answer=MagicMock(),
        updates_client=updates_client,
        account_client=MagicMock(),
        chat_client=MagicMock(),
        pts_cursor=None,  # no cursor
    )

    ctx = ConnectionContext(peer=("127.0.0.1", 3456), handshake_session_id=0)

    with patch("ntgram.gateway.push.subscriber.run_subscriber", side_effect=fake_run_subscriber):
        asyncio.run(pipeline._ensure_push_slot(
            ctx,
            auth_key_id=auth_key_id,
            session_id=1,
            user_id=77,
        ))

    assert captured.get("since_pts") == 50, f"expected since_pts=50, got {captured}"
