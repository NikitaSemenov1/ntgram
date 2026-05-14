from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _InMemoryPtsCursor:
    """Drop-in replacement for :class:`PtsCursor` backed by a plain ``dict``.

    Avoids pulling in ``fakeredis`` for unit tests. Mirrors the real
    semantics in ``ntgram/gateway/push/pts_cursor.py``:

    - ``set(...)`` is monotonic — never decreases the stored value.
    - ``set(..., force=True)`` overwrites unconditionally (used for the
      account-switch-on-same-key scenario).
    """

    def __init__(self) -> None:
        self._store: dict[int, int] = {}

    async def get(self, auth_key_id: int) -> int | None:
        return self._store.get(auth_key_id)

    async def set(
        self, auth_key_id: int, pts: int, *, force: bool = False,
    ) -> None:
        if force:
            self._store[auth_key_id] = pts
            return
        existing = self._store.get(auth_key_id)
        if existing is None or pts > existing:
            self._store[auth_key_id] = pts

    async def delete(self, auth_key_id: int) -> None:
        self._store.pop(auth_key_id, None)


def _make_in_memory_cursor() -> _InMemoryPtsCursor:
    """Return a fresh in-memory cursor for tests."""
    return _InMemoryPtsCursor()


def _make_sessions(user_id: int = 42):
    pytest.importorskip("grpc")
    from ntgram.gateway.mtproto.session_store import SessionStore
    sessions = SessionStore()
    session = sessions.complete_handshake(
        session_id=1, auth_key=b"k" * 256, new_nonce=1, server_nonce=2,
    )
    sessions.bind_user(session.auth_key_id, user_id)
    return sessions, session.auth_key_id


def _build_pipeline(*, sessions, updates_client, pts_cursor=None):
    from ntgram.gateway.connection.pipeline import ConnectionPipeline
    from ntgram.gateway.push_registry import PushRegistry

    return ConnectionPipeline(
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
        pts_cursor=pts_cursor,
    )


# ---------------------------------------------------------------------------
# Path 1: cursor present → use it (normal reconnect)
# ---------------------------------------------------------------------------


def test_ensure_push_slot_uses_cursor_when_present() -> None:
    """When cursor has pts=77, subscriber starts from 77 and state.pts is ignored."""
    pytest.importorskip("grpc")
    from ntgram.gateway.connection.context import ConnectionContext

    sessions, auth_key_id = _make_sessions(user_id=42)
    cursor = _make_in_memory_cursor()
    asyncio.run(cursor.set(auth_key_id, 77))

    captured: dict = {}

    async def fake_run_subscriber(slot, uc, ac, cc, *, since_pts=0):
        captured["since_pts"] = since_pts

    updates_client = MagicMock()
    updates_client.get_state = AsyncMock(return_value=MagicMock(pts=100))

    pipeline = _build_pipeline(
        sessions=sessions, updates_client=updates_client, pts_cursor=cursor,
    )

    ctx = ConnectionContext(peer=("127.0.0.1", 1234), handshake_session_id=0)

    with patch(
        "ntgram.gateway.push.subscriber.run_subscriber",
        side_effect=fake_run_subscriber,
    ):
        asyncio.run(pipeline._ensure_push_slot(
            ctx,
            auth_key_id=auth_key_id,
            session_id=1,
            user_id=42,
        ))

    assert captured.get("since_pts") == 77
    # state.pts must NOT be consulted when cursor is present.
    updates_client.get_state.assert_not_called()


# ---------------------------------------------------------------------------
# Path 2: fresh_login=True → pin cursor to state.pts
# ---------------------------------------------------------------------------


def test_fresh_login_initialises_pts_cursor_to_state_pts() -> None:
    """``fresh_login=True`` pins ``pts_cursor`` to the server's current state.pts."""
    pytest.importorskip("grpc")
    from ntgram.gateway.connection.context import ConnectionContext

    sessions, auth_key_id = _make_sessions(user_id=42)
    cursor = _make_in_memory_cursor()

    captured: dict = {}

    async def fake_run_subscriber(slot, uc, ac, cc, *, since_pts=0):
        captured["since_pts"] = since_pts

    updates_client = MagicMock()
    updates_client.get_state = AsyncMock(return_value=MagicMock(pts=42))

    pipeline = _build_pipeline(
        sessions=sessions, updates_client=updates_client, pts_cursor=cursor,
    )

    ctx = ConnectionContext(peer=("127.0.0.1", 1234), handshake_session_id=0)

    with patch(
        "ntgram.gateway.push.subscriber.run_subscriber",
        side_effect=fake_run_subscriber,
    ):
        asyncio.run(pipeline._ensure_push_slot(
            ctx,
            auth_key_id=auth_key_id,
            session_id=1,
            user_id=42,
            fresh_login=True,
        ))

    assert captured.get("since_pts") == 42
    # Cursor must have been written so future reconnects take the fast path.
    assert asyncio.run(cursor.get(auth_key_id)) == 42


def test_fresh_login_force_resets_pre_existing_cursor() -> None:
    """A new ``auth.signIn`` on a key resets the cursor to current state.pts.

    This is the account-switch-on-same-key scenario: a client may toggle
    between two registered accounts (e.g. via "switch account" UX) without
    calling ``auth.logOut`` first. Without ``force=True`` the monotonic
    ``set`` would leave the previous user's higher cursor in place, masking
    every new update with ``pts <= old_cursor``.
    """
    pytest.importorskip("grpc")
    from ntgram.gateway.connection.context import ConnectionContext

    sessions, auth_key_id = _make_sessions(user_id=42)
    cursor = _make_in_memory_cursor()
    asyncio.run(cursor.set(auth_key_id, 999))  # stale value from previous user

    captured: dict = {}

    async def fake_run_subscriber(slot, uc, ac, cc, *, since_pts=0):
        captured["since_pts"] = since_pts

    updates_client = MagicMock()
    updates_client.get_state = AsyncMock(return_value=MagicMock(pts=5))

    pipeline = _build_pipeline(
        sessions=sessions, updates_client=updates_client, pts_cursor=cursor,
    )

    ctx = ConnectionContext(peer=("127.0.0.1", 1234), handshake_session_id=0)

    with patch(
        "ntgram.gateway.push.subscriber.run_subscriber",
        side_effect=fake_run_subscriber,
    ):
        asyncio.run(pipeline._ensure_push_slot(
            ctx,
            auth_key_id=auth_key_id,
            session_id=1,
            user_id=42,
            fresh_login=True,
        ))

    assert captured.get("since_pts") == 5
    # Cursor must be force-overwritten so the new user's subscriber starts
    # exactly at their own state.pts.
    assert asyncio.run(cursor.get(auth_key_id)) == 5


def test_account_switch_on_same_connection_replaces_push_slot() -> None:
    """``auth.signIn`` as a different user on the same TCP tears down the old slot.

    Ensures the previous account's push subscriber is cancelled and a fresh
    slot is registered for the new ``user_id``.
    """
    pytest.importorskip("grpc")
    from ntgram.gateway.connection.context import ConnectionContext
    from ntgram.gateway.push_registry import PushSlot

    sessions, auth_key_id = _make_sessions(user_id=100)
    cursor = _make_in_memory_cursor()

    captured: list[int] = []

    async def fake_run_subscriber(slot, uc, ac, cc, *, since_pts=0):
        captured.append(since_pts)

    updates_client = MagicMock()
    updates_client.get_state = AsyncMock(return_value=MagicMock(pts=0))

    pipeline = _build_pipeline(
        sessions=sessions, updates_client=updates_client, pts_cursor=cursor,
    )

    ctx = ConnectionContext(peer=("127.0.0.1", 8901), handshake_session_id=0)

    # Pre-populate with a slot for user=100 (simulating an earlier signIn on
    # the same TCP connection).
    stale_task_cancelled = asyncio.Event()

    async def _stale_task_body():
        try:
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            stale_task_cancelled.set()
            raise

    async def _drive():
        stale_task = asyncio.create_task(_stale_task_body())
        # Let the stale task enter its sleep so it can later observe cancel.
        await asyncio.sleep(0)
        ctx.push_slot = PushSlot(
            user_id=100,
            auth_key_id=auth_key_id,
            session_id=1,
            task=stale_task,
        )
        pipeline._push_registry.register(ctx.push_slot)

        with patch(
            "ntgram.gateway.push.subscriber.run_subscriber",
            side_effect=fake_run_subscriber,
        ):
            await pipeline._ensure_push_slot(
                ctx,
                auth_key_id=auth_key_id,
                session_id=1,
                user_id=200,  # different user this time
                fresh_login=True,
            )

        # Wait for the cancelled task to actually finish so its handler runs.
        try:
            await stale_task
        except asyncio.CancelledError:
            pass

    asyncio.run(_drive())

    assert ctx.push_slot is not None
    assert ctx.push_slot.user_id == 200
    assert stale_task_cancelled.is_set()
    # The new subscriber was started exactly once.
    assert captured == [0]


# ---------------------------------------------------------------------------
# Path 3: cursor absent (legacy session) → safety net + materialise cursor
# ---------------------------------------------------------------------------


def test_legacy_session_uses_safety_window() -> None:
    """No cursor + non-fresh login → ``since_pts = max(0, state.pts - WINDOW)``."""
    pytest.importorskip("grpc")
    from ntgram.gateway.connection.context import ConnectionContext
    from ntgram.gateway.connection.pipeline import SAFE_REPLAY_WINDOW

    sessions, auth_key_id = _make_sessions(user_id=55)
    cursor = _make_in_memory_cursor()  # empty

    captured: dict = {}

    async def fake_run_subscriber(slot, uc, ac, cc, *, since_pts=0):
        captured["since_pts"] = since_pts

    updates_client = MagicMock()
    updates_client.get_state = AsyncMock(return_value=MagicMock(pts=1000))

    pipeline = _build_pipeline(
        sessions=sessions, updates_client=updates_client, pts_cursor=cursor,
    )

    ctx = ConnectionContext(peer=("127.0.0.1", 2345), handshake_session_id=0)

    with patch(
        "ntgram.gateway.push.subscriber.run_subscriber",
        side_effect=fake_run_subscriber,
    ):
        asyncio.run(pipeline._ensure_push_slot(
            ctx,
            auth_key_id=auth_key_id,
            session_id=1,
            user_id=55,
        ))

    expected = max(0, 1000 - SAFE_REPLAY_WINDOW)
    assert captured.get("since_pts") == expected
    # Cursor materialised for subsequent reconnects.
    assert asyncio.run(cursor.get(auth_key_id)) == expected


def test_legacy_session_clamps_safety_window_to_zero() -> None:
    """state.pts smaller than window must clamp ``since_pts`` to 0 (not negative)."""
    pytest.importorskip("grpc")
    from ntgram.gateway.connection.context import ConnectionContext

    sessions, auth_key_id = _make_sessions(user_id=77)
    cursor = _make_in_memory_cursor()  # empty

    captured: dict = {}

    async def fake_run_subscriber(slot, uc, ac, cc, *, since_pts=0):
        captured["since_pts"] = since_pts

    updates_client = MagicMock()
    updates_client.get_state = AsyncMock(return_value=MagicMock(pts=5))

    pipeline = _build_pipeline(
        sessions=sessions, updates_client=updates_client, pts_cursor=cursor,
    )

    ctx = ConnectionContext(peer=("127.0.0.1", 3456), handshake_session_id=0)

    with patch(
        "ntgram.gateway.push.subscriber.run_subscriber",
        side_effect=fake_run_subscriber,
    ):
        asyncio.run(pipeline._ensure_push_slot(
            ctx,
            auth_key_id=auth_key_id,
            session_id=1,
            user_id=77,
        ))

    # state.pts=5 < SAFE_REPLAY_WINDOW=100 → since_pts=0 (replay everything).
    assert captured.get("since_pts") == 0


# ---------------------------------------------------------------------------
# Path 4: pts_cursor wiring absent entirely (degraded mode)
# ---------------------------------------------------------------------------


def test_no_cursor_wiring_still_falls_back_to_state_pts_minus_window() -> None:
    """When ``pts_cursor`` is ``None`` (deployment without Redis), safety net still applies."""
    pytest.importorskip("grpc")
    from ntgram.gateway.connection.context import ConnectionContext
    from ntgram.gateway.connection.pipeline import SAFE_REPLAY_WINDOW

    sessions, auth_key_id = _make_sessions(user_id=88)

    captured: dict = {}

    async def fake_run_subscriber(slot, uc, ac, cc, *, since_pts=0):
        captured["since_pts"] = since_pts

    updates_client = MagicMock()
    updates_client.get_state = AsyncMock(return_value=MagicMock(pts=200))

    pipeline = _build_pipeline(
        sessions=sessions, updates_client=updates_client, pts_cursor=None,
    )

    ctx = ConnectionContext(peer=("127.0.0.1", 4567), handshake_session_id=0)

    with patch(
        "ntgram.gateway.push.subscriber.run_subscriber",
        side_effect=fake_run_subscriber,
    ):
        asyncio.run(pipeline._ensure_push_slot(
            ctx,
            auth_key_id=auth_key_id,
            session_id=1,
            user_id=88,
        ))

    assert captured.get("since_pts") == max(0, 200 - SAFE_REPLAY_WINDOW)


# ---------------------------------------------------------------------------
# Regression: offline message reaches receiver on reconnect
# ---------------------------------------------------------------------------


def test_offline_message_is_replayed_on_reconnect() -> None:
    """End-to-end style: cursor=0 + pts=1 in DAO → ``since_pts=0`` delivered.

    Models the bug fixed by this change: when account A is offline and a
    message with ``pts=1`` is recorded, the subscriber must replay it on A's
    next reconnect rather than starting from ``state.pts=1`` and dropping it
    via ``WHERE pts > 1``.
    """
    pytest.importorskip("grpc")
    from ntgram.gateway.connection.context import ConnectionContext

    sessions, auth_key_id = _make_sessions(user_id=1001)
    cursor = _make_in_memory_cursor()
    asyncio.run(cursor.set(auth_key_id, 0))  # last-delivered = 0

    captured: dict = {}

    async def fake_run_subscriber(slot, uc, ac, cc, *, since_pts=0):
        captured["since_pts"] = since_pts

    updates_client = MagicMock()
    # state.pts is "1" — the bug was that fallback used this value and
    # SQL WHERE pts > 1 dropped the only update. The fix routes through cursor
    # instead, so since_pts=0 is what reaches the subscriber.
    updates_client.get_state = AsyncMock(return_value=MagicMock(pts=1))

    pipeline = _build_pipeline(
        sessions=sessions, updates_client=updates_client, pts_cursor=cursor,
    )

    ctx = ConnectionContext(peer=("127.0.0.1", 5678), handshake_session_id=0)

    with patch(
        "ntgram.gateway.push.subscriber.run_subscriber",
        side_effect=fake_run_subscriber,
    ):
        asyncio.run(pipeline._ensure_push_slot(
            ctx,
            auth_key_id=auth_key_id,
            session_id=1,
            user_id=1001,
        ))

    assert captured.get("since_pts") == 0
    # state.pts must NOT be consulted when cursor is present, even when it is 0.
    updates_client.get_state.assert_not_called()


# ---------------------------------------------------------------------------
# auth.logOut clears the cursor
# ---------------------------------------------------------------------------


def test_auth_logout_clears_pts_cursor() -> None:
    """A successful ``auth.logOut`` deletes the Redis cursor for this auth_key_id."""
    pytest.importorskip("grpc")
    from ntgram.gateway.connection.context import ConnectionContext
    from ntgram.tl.models import TlRequest, TlResponse

    sessions, auth_key_id = _make_sessions(user_id=42)
    cursor = _make_in_memory_cursor()
    asyncio.run(cursor.set(auth_key_id, 123))

    pipeline = _build_pipeline(
        sessions=sessions, updates_client=MagicMock(), pts_cursor=cursor,
    )

    ctx = ConnectionContext(peer=("127.0.0.1", 6789), handshake_session_id=0)

    request = TlRequest(
        constructor="auth.logOut",
        constructor_id=0,
        payload={},
        auth_key_id=auth_key_id,
        session_id=1,
        req_msg_id=42,
        message_id=42,
        seq_no=0,
    )
    response = TlResponse(
        req_msg_id=42,
        result={
            "constructor": "rpc_result",
            "req_msg_id": 42,
            "result": {"constructor": "auth.loggedOut", "flags": 0},
        },
    )

    async def _drive():
        pipeline._maybe_clear_push_state(ctx, request, response)
        # _maybe_clear_push_state schedules the delete; wait for it.
        for task in asyncio.all_tasks() - {asyncio.current_task()}:
            await task

    asyncio.run(_drive())

    assert asyncio.run(cursor.get(auth_key_id)) is None


def test_auth_logout_failure_keeps_pts_cursor() -> None:
    """If ``auth.logOut`` fails (e.g. AUTH_KEY_INVALID), the cursor is NOT cleared."""
    pytest.importorskip("grpc")
    from ntgram.gateway.connection.context import ConnectionContext
    from ntgram.tl.models import TlRequest, TlResponse

    sessions, auth_key_id = _make_sessions(user_id=42)
    cursor = _make_in_memory_cursor()
    asyncio.run(cursor.set(auth_key_id, 123))

    pipeline = _build_pipeline(
        sessions=sessions, updates_client=MagicMock(), pts_cursor=cursor,
    )

    ctx = ConnectionContext(peer=("127.0.0.1", 7890), handshake_session_id=0)

    request = TlRequest(
        constructor="auth.logOut",
        constructor_id=0,
        payload={},
        auth_key_id=auth_key_id,
        session_id=1,
        req_msg_id=42,
        message_id=42,
        seq_no=0,
    )
    # rpc_error response — logOut did not succeed.
    response = TlResponse(
        req_msg_id=42,
        result={
            "constructor": "rpc_result",
            "req_msg_id": 42,
            "result": {
                "constructor": "rpc_error",
                "error_code": 401,
                "error_message": "AUTH_KEY_INVALID",
            },
        },
    )

    pipeline._maybe_clear_push_state(ctx, request, response)

    assert asyncio.run(cursor.get(auth_key_id)) == 123
