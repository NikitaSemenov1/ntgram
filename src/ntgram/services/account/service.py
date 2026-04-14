from __future__ import annotations

import hashlib
import re
import secrets
from datetime import datetime, timedelta, timezone

import asyncpg

from ntgram.gen import account_pb2, account_pb2_grpc
from ntgram.services.account.dao import AccountDAO
from ntgram.services.common import err_meta, ok_meta

_PHONE_RE = re.compile(r"^\+\d{7,15}$")
_CODE_TTL = timedelta(minutes=3)


def _normalize_phone(phone: str) -> str:
    return re.sub(r"\s+", "", phone.strip())


def _generate_code() -> tuple[str, str]:
    code = f"{secrets.randbelow(100000):05d}"
    hash_val = hashlib.sha256(code.encode()).hexdigest()[:16]
    return code, hash_val


class AccountService(account_pb2_grpc.AccountServiceServicer):
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._dao = AccountDAO(pool)

    async def SendCode(self, request, context):  # noqa: N802
        phone = _normalize_phone(request.phone)
        if not _PHONE_RE.match(phone):
            return account_pb2.SendCodeResponse(meta=err_meta(400, "PHONE_NUMBER_INVALID"))

        code, hash_val = _generate_code()
        expires_at = datetime.now(timezone.utc) + _CODE_TTL
        await self._dao.save_phone_code(phone, code, hash_val, expires_at)
        return account_pb2.SendCodeResponse(meta=ok_meta(), phone_code_hash=hash_val)

    async def SignIn(self, request, context):  # noqa: N802
        phone = _normalize_phone(request.phone)
        if not request.phone_code:
            return account_pb2.SignInResponse(meta=err_meta(400, "PHONE_CODE_EMPTY"))

        stored = await self._dao.get_phone_code(phone)
        if stored is None or stored.hash != request.phone_code_hash:
            return account_pb2.SignInResponse(meta=err_meta(400, "PHONE_CODE_INVALID"))
        if stored.expires_at < datetime.now(timezone.utc):
            return account_pb2.SignInResponse(meta=err_meta(400, "PHONE_CODE_EXPIRED"))
        if stored.code != request.phone_code:
            return account_pb2.SignInResponse(meta=err_meta(400, "PHONE_CODE_INVALID"))

        user = await self._dao.get_user_by_phone(phone)
        if user is None:
            user_id = await self._dao.next_user_id()
            await self._dao.create_user(user_id, phone, "", "")
            await self._dao.delete_phone_code(phone)
            return account_pb2.SignInResponse(meta=ok_meta(), user_id=user_id, is_new_user=True)

        await self._dao.delete_phone_code(phone)
        return account_pb2.SignInResponse(meta=ok_meta(), user_id=user.user_id, is_new_user=False)

    async def SignUp(self, request, context):  # noqa: N802
        phone = _normalize_phone(request.phone)
        stored = await self._dao.get_phone_code(phone)
        if stored is None or stored.hash != request.phone_code_hash:
            return account_pb2.SignUpResponse(meta=err_meta(400, "PHONE_CODE_INVALID"))

        user = await self._dao.get_user_by_phone(phone)
        if user is None:
            user_id = await self._dao.next_user_id()
            await self._dao.create_user(user_id, phone, request.first_name, request.last_name)
        else:
            user_id = user.user_id
            await self._dao._pool.execute(
                "UPDATE users SET first_name = $1, last_name = $2 WHERE user_id = $3",
                request.first_name, request.last_name, user_id,
            )

        await self._dao.delete_phone_code(phone)
        return account_pb2.SignUpResponse(meta=ok_meta(), user_id=user_id)

    async def LogOut(self, request, context):  # noqa: N802
        # TODO: unbind auth_key -> user when auth_keys table is fully wired
        return account_pb2.LogOutResponse(meta=ok_meta())

    async def GetUser(self, request, context):  # noqa: N802
        user = await self._dao.get_user_by_id(request.user_id)
        if user is None:
            return account_pb2.GetUserResponse(meta=err_meta(404, "USER_NOT_FOUND"))
        return account_pb2.GetUserResponse(
            meta=ok_meta(),
            user_id=user.user_id,
            phone=user.phone,
            first_name=user.first_name,
            last_name=user.last_name,
        )
