from __future__ import annotations

from ntgram.errors import RpcFailure
from ntgram.gen import account_pb2, account_pb2_grpc

from ntgram.gateway.grpc_clients._meta import assert_meta_ok
from ntgram.gateway.grpc_clients.dtos import (
    ConfigResult,
    ContentSettingsResult,
    FullUserDto,
    GetUserResult,
    PrivacyRulesResult,
    ProfileDto,
    ResolveUsernameResult,
    SearchUsernameHit,
    SearchUsernamesResult,
    SendCodeResult,
    SignInResult,
    SignUpResult,
    UpdateProfileResult,
    UpdateUsernameResult,
)


class AccountClient:
    """Wraps AccountServiceStub calls into typed DTOs."""

    __slots__ = ("_stub",)

    def __init__(self, stub: account_pb2_grpc.AccountServiceStub) -> None:
        self._stub = stub

    async def send_code(self, phone: str) -> SendCodeResult:
        resp = await self._stub.SendCode(
            account_pb2.SendCodeRequest(phone=phone),
        )
        assert_meta_ok(resp.meta)
        return SendCodeResult(phone_code_hash=resp.phone_code_hash)

    async def cancel_code(self, phone: str, phone_code_hash: str) -> None:
        resp = await self._stub.CancelCode(
            account_pb2.CancelCodeRequest(
                phone=phone,
                phone_code_hash=phone_code_hash,
            ),
        )
        assert_meta_ok(resp.meta)

    async def sign_in(
        self, *, phone: str, phone_code_hash: str, phone_code: str,
    ) -> SignInResult:
        resp = await self._stub.SignIn(
            account_pb2.SignInRequest(
                phone=phone,
                phone_code_hash=phone_code_hash,
                phone_code=phone_code,
            ),
        )
        assert_meta_ok(resp.meta)
        return SignInResult(
            user_id=int(resp.user_id),
            phone=phone,
            is_new_user=bool(resp.is_new_user),
        )

    async def sign_up(
        self,
        *,
        phone: str,
        phone_code_hash: str,
        first_name: str,
        last_name: str,
    ) -> SignUpResult:
        resp = await self._stub.SignUp(
            account_pb2.SignUpRequest(
                phone=phone,
                phone_code_hash=phone_code_hash,
                first_name=first_name,
                last_name=last_name,
            ),
        )
        assert_meta_ok(resp.meta)
        return SignUpResult(
            user_id=int(resp.user_id),
            phone=phone,
            first_name=first_name,
            last_name=last_name,
        )

    async def log_out(self, *, user_id: int, auth_key_id: int) -> None:
        resp = await self._stub.LogOut(
            account_pb2.LogOutRequest(
                user_id=user_id,
                auth_key_id=auth_key_id,
            ),
        )
        assert_meta_ok(resp.meta)

    async def check_username(self, username: str) -> None:
        resp = await self._stub.CheckUsername(
            account_pb2.CheckUsernameRequest(username=username),
        )
        assert_meta_ok(resp.meta)

    async def update_username(
        self, *, actor_user_id: int, username: str,
    ) -> UpdateUsernameResult:
        resp = await self._stub.UpdateUsername(
            account_pb2.UpdateUsernameRequest(
                user_id=actor_user_id, username=username,
            ),
        )
        assert_meta_ok(resp.meta)
        return UpdateUsernameResult(
            user_id=int(resp.user_id),
            first_name=resp.first_name,
            last_name=resp.last_name,
            phone=resp.phone or "",
            username=resp.username or "",
        )

    async def resolve_username(self, username: str) -> ResolveUsernameResult:
        resp = await self._stub.ResolveUsername(
            account_pb2.ResolveUsernameRequest(username=username),
        )
        assert_meta_ok(resp.meta)
        return ResolveUsernameResult(
            user_id=int(resp.user_id),
            first_name=resp.first_name,
            last_name=resp.last_name,
            username=resp.username or "",
            bio=resp.bio or "",
        )

    async def search_usernames(
        self, *, actor_user_id: int, q: str, limit: int,
    ) -> SearchUsernamesResult:
        resp = await self._stub.SearchUsernames(
            account_pb2.SearchUsernamesRequest(
                actor_user_id=actor_user_id,
                q=q,
                limit=limit,
            ),
        )
        assert_meta_ok(resp.meta)
        hits = tuple(
            SearchUsernameHit(
                user_id=int(h.user_id),
                first_name=h.first_name,
                last_name=h.last_name,
                username=h.username or "",
                bio=h.bio or "",
            )
            for h in resp.hits
        )
        return SearchUsernamesResult(hits=hits)

    async def get_user(self, user_id: int) -> GetUserResult:
        """account.GetUser: tolerates non-OK meta; caller decides on fallback."""
        resp = await self._stub.GetUser(
            account_pb2.GetUserRequest(user_id=user_id),
        )
        ok = bool(getattr(resp.meta, "ok", False))
        return GetUserResult(
            user_id=int(resp.user_id) if ok else int(user_id),
            ok=ok,
            phone=resp.phone or "" if ok else "",
            username=resp.username or "" if ok else "",
            first_name=resp.first_name if ok else "",
            last_name=resp.last_name if ok else "",
        )

    async def get_privacy(self, *, user_id: int, key: str) -> PrivacyRulesResult:
        resp = await self._stub.GetPrivacy(
            account_pb2.GetPrivacyRequest(user_id=user_id, key=key),
        )
        assert_meta_ok(resp.meta)
        return PrivacyRulesResult(
            rules=tuple(r.constructor for r in resp.rules),
        )

    async def get_content_settings(self, user_id: int) -> ContentSettingsResult:
        resp = await self._stub.GetContentSettings(
            account_pb2.GetContentSettingsRequest(user_id=user_id),
        )
        assert_meta_ok(resp.meta)
        return ContentSettingsResult(
            sensitive_can_change=bool(resp.sensitive_can_change),
            sensitive_enabled=bool(resp.sensitive_enabled),
        )

    async def get_config(self) -> ConfigResult:
        resp = await self._stub.GetConfig(account_pb2.GetConfigRequest())
        assert_meta_ok(resp.meta)
        return ConfigResult(config_json=resp.config_json)

    # Profile RPCs

    def _profile_dto(self, p: account_pb2.Profile) -> ProfileDto:
        return ProfileDto(
            user_id=int(p.user_id),
            first_name=p.first_name or "",
            last_name=p.last_name or "",
            bio=p.bio or "",
            username=p.username or "",
        )

    async def get_profile(
        self, *, actor_user_id: int, target_user_id: int,
    ) -> ProfileDto:
        resp = await self._stub.GetProfile(
            account_pb2.GetProfileRequest(
                actor_user_id=actor_user_id,
                target_user_id=target_user_id,
            ),
        )
        assert_meta_ok(resp.meta)
        return self._profile_dto(resp.profile)

    async def get_profiles(
        self, *, actor_user_id: int, user_ids: list[int],
    ) -> list[ProfileDto]:
        """Batch profile lookup — single gRPC round trip."""
        if not user_ids:
            return []
        resp = await self._stub.GetProfiles(
            account_pb2.GetProfilesRequest(
                actor_user_id=actor_user_id,
                user_ids=user_ids,
            ),
        )
        assert_meta_ok(resp.meta)
        return [self._profile_dto(p) for p in resp.profiles]

    async def get_full_user(
        self, *, actor_user_id: int, target_user_id: int,
    ) -> FullUserDto:
        resp = await self._stub.GetFullUser(
            account_pb2.GetFullUserRequest(
                actor_user_id=actor_user_id,
                target_user_id=target_user_id,
            ),
        )
        assert_meta_ok(resp.meta)
        return FullUserDto(
            user_id=int(resp.user_id),
            first_name=resp.first_name or "",
            last_name=resp.last_name or "",
            bio=resp.bio or "",
            is_self=bool(resp.is_self),
            phone=resp.phone or "",
            username=resp.username or "",
        )

    async def update_profile(
        self,
        *,
        actor_user_id: int,
        first_name: str,
        last_name: str,
        bio: str,
    ) -> UpdateProfileResult:
        """Map BIO_TOO_LONG -> ABOUT_TOO_LONG for client compatibility."""
        resp = await self._stub.UpdateProfile(
            account_pb2.UpdateProfileRequest(
                actor_user_id=actor_user_id,
                first_name=first_name,
                last_name=last_name,
                bio=bio,
            ),
        )
        try:
            assert_meta_ok(resp.meta)
        except RpcFailure as exc:
            if exc.message == "BIO_TOO_LONG":
                raise RpcFailure(exc.code, "ABOUT_TOO_LONG") from exc
            raise
        return UpdateProfileResult(profile=self._profile_dto(resp.profile))
