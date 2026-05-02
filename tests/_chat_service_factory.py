from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

from ntgram.gen import account_pb2, common_pb2
from ntgram.services.chat.dao import ChatDAO
from ntgram.services.chat.service import ChatService

from tests._fake_chat_pool import FakeChatPool
from tests._fake_updates_stub import FakeUpdatesStub


def make_account_stub(
    *,
    profiles: list[account_pb2.Profile] | None = None,
    user_exists: bool = True,
) -> SimpleNamespace:
    """Return a SimpleNamespace exposing AccountService.GetUser/GetProfiles."""
    return SimpleNamespace(
        GetUser=AsyncMock(
            return_value=account_pb2.GetUserResponse(
                meta=common_pb2.ServiceResponseMeta(ok=user_exists),
            ),
        ),
        GetProfiles=AsyncMock(
            return_value=account_pb2.GetProfilesResponse(
                meta=common_pb2.ServiceResponseMeta(ok=True),
                profiles=profiles or [],
            ),
        ),
    )


def make_chat_service(
    pool: FakeChatPool | None = None,
    *,
    profiles: list[account_pb2.Profile] | None = None,
    account_stub: SimpleNamespace | None = None,
    updates_stub: FakeUpdatesStub | None = None,
    user_exists: bool = True,
) -> tuple[ChatService, FakeChatPool, FakeUpdatesStub]:
    """Build a ChatService with in-memory fakes; return ``(svc, pool, updates_stub)``."""
    if pool is None:
        pool = FakeChatPool()
    if updates_stub is None:
        updates_stub = FakeUpdatesStub()
    if account_stub is None:
        account_stub = make_account_stub(
            profiles=profiles, user_exists=user_exists,
        )

    svc = object.__new__(ChatService)
    svc._pool = pool
    svc._dao = ChatDAO(pool)
    svc._account = account_stub
    svc._updates = updates_stub
    return svc, pool, updates_stub
