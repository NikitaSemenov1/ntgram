from __future__ import annotations

import asyncio
from dataclasses import dataclass

import pytest

pytest.importorskip("asyncpg")
pytest.importorskip("grpc")

from ntgram.gen import account_pb2
from ntgram.services.account.dao import UserRow
from ntgram.services.account.service import (
    STUB_PHONE_CODE,
    STUB_PHONE_CODE_HASH,
    AccountService,
)


@dataclass
class _User:
    user_id: int
    phone: str
    first_name: str = ""
    last_name: str = ""
    username: str | None = None


class _FakeDao:
    def __init__(
        self,
        user: _User | None = None,
        *,
        extra_users: tuple[_User, ...] = (),
        other_username_owner: dict[str, int] | None = None,
    ) -> None:
        self.user = user
        self.extra_users = list(extra_users)
        self.created: list[tuple[int, str, str, str]] = []
        self._username_to_uid: dict[str, int] = dict(other_username_owner or {})
        for u in self._all_users():
            if u.username:
                self._username_to_uid[u.username.lower()] = u.user_id

    def _all_users(self) -> list[_User]:
        out: list[_User] = []
        if self.user is not None:
            out.append(self.user)
        out.extend(self.extra_users)
        return out

    async def get_user_by_phone(self, phone: str) -> _User | None:
        return self.user if self.user and self.user.phone == phone else None

    async def next_user_id(self) -> int:
        return 42

    async def create_user(
        self,
        user_id: int,
        phone: str,
        first_name: str,
        last_name: str,
    ) -> None:
        self.created.append((user_id, phone, first_name, last_name))

    async def get_user_by_id(self, user_id: int) -> _User | None:
        if self.user and self.user.user_id == user_id:
            return self.user
        return None

    async def get_user_id_by_username(self, username: str) -> int | None:
        return self._username_to_uid.get(username)

    async def set_username(self, user_id: int, username: str | None) -> None:
        for u in self._all_users():
            if u.user_id == user_id:
                if u.username:
                    self._username_to_uid.pop(u.username.lower(), None)
                u.username = username
                if username:
                    self._username_to_uid[username.lower()] = user_id
                return
        raise AssertionError("user_id not in fake dao")

    async def get_user_by_username(self, username: str) -> UserRow | None:
        for u in self._all_users():
            if u.username and u.username.lower() == username:
                return UserRow(
                    user_id=u.user_id,
                    phone=u.phone,
                    first_name=u.first_name,
                    last_name=u.last_name,
                    username=u.username,
                )
        return None

    async def search_usernames_prefix(
        self, prefix: str, limit: int, exclude_user_id: int,
    ) -> list[UserRow]:
        matched: list[_User] = []
        for u in self._all_users():
            un = (u.username or "").lower()
            if not un or u.user_id == exclude_user_id:
                continue
            if un.startswith(prefix):
                matched.append(u)
        matched.sort(key=lambda x: (x.username or "").lower())
        return [
            UserRow(
                user_id=u.user_id,
                phone=u.phone,
                first_name=u.first_name,
                last_name=u.last_name,
                username=u.username,
            )
            for u in matched[:limit]
        ]


def _service_with_dao(dao: _FakeDao) -> AccountService:
    service = object.__new__(AccountService)
    service._dao = dao
    return service


def test_send_code_returns_service_level_stub_hash() -> None:
    service = _service_with_dao(_FakeDao())

    response = asyncio.run(
        service.SendCode(account_pb2.SendCodeRequest(phone="+10000000000"), None),
    )

    assert response.meta.ok
    assert response.phone_code_hash == STUB_PHONE_CODE_HASH


def test_sign_in_accepts_stub_code_and_creates_user() -> None:
    dao = _FakeDao()
    service = _service_with_dao(dao)

    response = asyncio.run(
        service.SignIn(
            account_pb2.SignInRequest(
                phone="+10000000000",
                phone_code_hash=STUB_PHONE_CODE_HASH,
                phone_code=STUB_PHONE_CODE,
            ),
            None,
        ),
    )

    assert response.meta.ok
    assert response.user_id == 42
    assert response.is_new_user is True
    assert dao.created == [(42, "10000000000", "", "")]


def test_sign_in_rejects_non_stub_code() -> None:
    service = _service_with_dao(_FakeDao())

    response = asyncio.run(
        service.SignIn(
            account_pb2.SignInRequest(
                phone="+10000000000",
                phone_code_hash=STUB_PHONE_CODE_HASH,
                phone_code="000000",
            ),
            None,
        ),
    )

    assert not response.meta.ok
    assert response.meta.error.message == "PHONE_CODE_INVALID"


def test_sign_up_accepts_valid_hash() -> None:
    dao = _FakeDao()
    service = _service_with_dao(dao)

    response = asyncio.run(
        service.SignUp(
            account_pb2.SignUpRequest(
                phone="+10000000000",
                phone_code_hash=STUB_PHONE_CODE_HASH,
                first_name="Test",
                last_name="User",
            ),
            None,
        ),
    )

    assert response.meta.ok
    assert response.user_id == 42
    assert dao.created == [(42, "10000000000", "Test", "User")]


def test_sign_up_rejects_wrong_hash() -> None:
    service = _service_with_dao(_FakeDao())

    response = asyncio.run(
        service.SignUp(
            account_pb2.SignUpRequest(
                phone="+10000000000",
                phone_code_hash="wrong-hash",
                first_name="Test",
                last_name="User",
            ),
            None,
        ),
    )

    assert not response.meta.ok
    assert response.meta.error.message == "PHONE_CODE_INVALID"


def test_check_username_invalid() -> None:
    service = _service_with_dao(_FakeDao())

    r = asyncio.run(
        service.CheckUsername(account_pb2.CheckUsernameRequest(username="ab"), None),
    )
    assert not r.meta.ok
    assert r.meta.error.message == "USERNAME_INVALID"


def test_check_username_occupied() -> None:
    u = _User(user_id=1, phone="1", username="taken1")
    service = _service_with_dao(_FakeDao(u))

    r = asyncio.run(
        service.CheckUsername(account_pb2.CheckUsernameRequest(username="taken1"), None),
    )
    assert not r.meta.ok
    assert r.meta.error.message == "USERNAME_OCCUPIED"


def test_check_username_available() -> None:
    service = _service_with_dao(_FakeDao())

    r = asyncio.run(
        service.CheckUsername(account_pb2.CheckUsernameRequest(username="valid9"), None),
    )
    assert r.meta.ok


def test_update_username_not_modified() -> None:
    u = _User(user_id=7, phone="x", username="sameuser")
    service = _service_with_dao(_FakeDao(u))

    r = asyncio.run(
        service.UpdateUsername(
            account_pb2.UpdateUsernameRequest(user_id=7, username="SameUser"),
            None,
        ),
    )
    assert not r.meta.ok
    assert r.meta.error.message == "USERNAME_NOT_MODIFIED"


def test_update_username_sets_and_clears() -> None:
    u = _User(user_id=7, phone="x", first_name="F", last_name="L")
    dao = _FakeDao(u)
    service = _service_with_dao(dao)

    r1 = asyncio.run(
        service.UpdateUsername(
            account_pb2.UpdateUsernameRequest(user_id=7, username="newname"),
            None,
        ),
    )
    assert r1.meta.ok
    assert r1.username == "newname"
    assert u.username == "newname"

    r2 = asyncio.run(
        service.UpdateUsername(account_pb2.UpdateUsernameRequest(user_id=7, username=""), None),
    )
    assert r2.meta.ok
    assert r2.username == ""
    assert u.username is None


def test_update_username_occupied_by_other() -> None:
    u = _User(user_id=7, phone="x")
    service = _service_with_dao(
        _FakeDao(u, other_username_owner={"other": 99}),
    )

    r = asyncio.run(
        service.UpdateUsername(
            account_pb2.UpdateUsernameRequest(user_id=7, username="other"),
            None,
        ),
    )
    assert not r.meta.ok
    assert r.meta.error.message == "USERNAME_OCCUPIED"


def test_resolve_username_invalid() -> None:
    service = _service_with_dao(_FakeDao())

    r = asyncio.run(
        service.ResolveUsername(account_pb2.ResolveUsernameRequest(username="ab"), None),
    )
    assert not r.meta.ok
    assert r.meta.error.message == "USERNAME_INVALID"


def test_resolve_username_not_occupied() -> None:
    service = _service_with_dao(_FakeDao())

    r = asyncio.run(
        service.ResolveUsername(
            account_pb2.ResolveUsernameRequest(username="nobody9"),
            None,
        ),
    )
    assert not r.meta.ok
    assert r.meta.error.message == "USERNAME_NOT_OCCUPIED"


def test_resolve_username_ok() -> None:
    u = _User(user_id=3, phone="1", username="findme9", first_name="A", last_name="B")
    service = _service_with_dao(_FakeDao(u))

    r = asyncio.run(
        service.ResolveUsername(account_pb2.ResolveUsernameRequest(username="@FindMe9"), None),
    )
    assert r.meta.ok
    assert r.user_id == 3
    assert r.username == "findme9"


def test_search_usernames_empty_query() -> None:
    service = _service_with_dao(_FakeDao())

    r = asyncio.run(
        service.SearchUsernames(
            account_pb2.SearchUsernamesRequest(actor_user_id=0, q="   ", limit=10),
            None,
        ),
    )
    assert not r.meta.ok
    assert r.meta.error.message == "SEARCH_QUERY_EMPTY"


def test_search_usernames_too_short() -> None:
    service = _service_with_dao(_FakeDao())

    r = asyncio.run(
        service.SearchUsernames(
            account_pb2.SearchUsernamesRequest(actor_user_id=0, q="ab", limit=10),
            None,
        ),
    )
    assert not r.meta.ok
    assert r.meta.error.message == "QUERY_TOO_SHORT"


def test_search_usernames_prefix_and_exclude() -> None:
    self_u = _User(user_id=1, phone="a", username="alphauser")
    other = _User(user_id=2, phone="b", username="alphabeta", first_name="O", last_name="")
    service = _service_with_dao(_FakeDao(self_u, extra_users=(other,)))

    r = asyncio.run(
        service.SearchUsernames(
            account_pb2.SearchUsernamesRequest(actor_user_id=1, q="@alph", limit=10),
            None,
        ),
    )
    assert r.meta.ok
    assert len(r.hits) == 1
    assert r.hits[0].user_id == 2
    assert r.hits[0].username == "alphabeta"

