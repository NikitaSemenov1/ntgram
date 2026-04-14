from __future__ import annotations

import asyncpg
import grpc

from ntgram.gen import account_pb2_grpc, profile_pb2, profile_pb2_grpc
from ntgram.services.common import err_meta, ok_meta
from ntgram.services.profile.dao import ProfileDAO

MAX_BIO_LENGTH = 128
MAX_FIRST_NAME_LENGTH = 64
MAX_LAST_NAME_LENGTH = 64


class ProfileService(profile_pb2_grpc.ProfileServiceServicer):
    def __init__(self, pool: asyncpg.Pool, account_channel: grpc.aio.Channel) -> None:
        self._dao = ProfileDAO(pool)
        self._account = account_pb2_grpc.AccountServiceStub(account_channel)

    async def GetProfile(self, request, context):  # noqa: N802
        profile = await self._dao.get_profile(request.target_user_id)
        if profile is None:
            return profile_pb2.GetProfileResponse(meta=err_meta(404, "USER_NOT_FOUND"))
        return profile_pb2.GetProfileResponse(
            meta=ok_meta(),
            profile=profile_pb2.Profile(
                user_id=profile.user_id,
                first_name=profile.first_name,
                last_name=profile.last_name,
                bio=profile.bio,
            ),
        )

    async def UpdateProfile(self, request, context):  # noqa: N802
        if len(request.bio) > MAX_BIO_LENGTH:
            return profile_pb2.UpdateProfileResponse(meta=err_meta(400, "BIO_TOO_LONG"))
        if len(request.first_name) > MAX_FIRST_NAME_LENGTH:
            return profile_pb2.UpdateProfileResponse(meta=err_meta(400, "FIRST_NAME_TOO_LONG"))
        if len(request.last_name) > MAX_LAST_NAME_LENGTH:
            return profile_pb2.UpdateProfileResponse(meta=err_meta(400, "LAST_NAME_TOO_LONG"))

        old = await self._dao.get_profile(request.actor_user_id)
        if old is None:
            return profile_pb2.UpdateProfileResponse(meta=err_meta(404, "USER_NOT_FOUND"))

        await self._dao.upsert_profile(
            request.actor_user_id, request.first_name, request.last_name, request.bio,
        )
        _name_changed = (
            old.first_name != request.first_name
            or old.last_name != request.last_name
        )
        updated = await self._dao.get_profile(request.actor_user_id)
        return profile_pb2.UpdateProfileResponse(
            meta=ok_meta(),
            profile=profile_pb2.Profile(
                user_id=updated.user_id,
                first_name=updated.first_name,
                last_name=updated.last_name,
                bio=updated.bio,
            ),
        )
