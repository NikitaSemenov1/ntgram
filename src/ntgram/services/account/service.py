from __future__ import annotations

import json
import logging
import re
from pathlib import Path

import asyncpg
from asyncpg.exceptions import UniqueViolationError

from ntgram.gen import account_pb2, account_pb2_grpc
from ntgram.services.account.dao import AccountDAO
from ntgram.services.common import err_meta, ok_meta


def _default_help_config_path() -> Path:
    """Bundled help_get_config.json path relative to this service file."""
    return Path(__file__).resolve().parents[4] / "config" / "help_get_config.json"

logger = logging.getLogger(__name__)

_PHONE_DIGITS_RE = re.compile(r"^\d{7,15}$")
_USERNAME_CLAIM_RE = re.compile(r"^[A-Za-z0-9_]{5,32}$")
_SEARCH_USERNAME_PREFIX_RE = re.compile(r"^[a-z0-9_]+$")
STUB_PHONE_CODE = "111111"
STUB_PHONE_CODE_HASH = "stub-phone-code-hash"


def _normalize_claimed_username(raw: str) -> str | None:
    """Non-empty username: 5–32 chars, A-z, digits, underscore; return lowercase or None."""
    s = raw.strip()
    if not s:
        return None
    if not _USERNAME_CLAIM_RE.match(s):
        return None
    return s.lower()


def _normalize_phone(phone: str) -> str:
    """Strip spaces, optional leading +; return digits-only for validation and storage."""
    s = re.sub(r"\s+", "", phone.strip())
    if s.startswith("+"):
        s = s[1:]
    return s


class AccountService(account_pb2_grpc.AccountServiceServicer):
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._dao = AccountDAO(pool)

    async def SendCode(self, request, context):  # noqa: N802
        raw = request.phone
        phone = _normalize_phone(raw)
        if not _PHONE_DIGITS_RE.match(phone):
            logger.warning(
                "SendCode rejected: invalid_phone raw=%r normalized=%r",
                raw,
                phone,
            )
            return account_pb2.SendCodeResponse(meta=err_meta(400, "PHONE_NUMBER_INVALID"))

        logger.debug("SendCode ok: normalized_phone=%r", phone)
        return account_pb2.SendCodeResponse(
            meta=ok_meta(),
            phone_code_hash=STUB_PHONE_CODE_HASH,
        )

    async def CancelCode(self, request, context):  # noqa: N802
        # Stub: no phone_codes row cleanup until real SMS flow exists.
        phone = _normalize_phone(request.phone)
        if not _PHONE_DIGITS_RE.match(phone):
            return account_pb2.CancelCodeResponse(meta=err_meta(400, "PHONE_NUMBER_INVALID"))
        return account_pb2.CancelCodeResponse(meta=ok_meta())

    async def SignIn(self, request, context):  # noqa: N802
        phone = _normalize_phone(request.phone)
        if not request.phone_code:
            return account_pb2.SignInResponse(meta=err_meta(400, "PHONE_CODE_EMPTY"))
        if request.phone_code != STUB_PHONE_CODE:
            return account_pb2.SignInResponse(meta=err_meta(400, "PHONE_CODE_INVALID"))

        user = await self._dao.get_user_by_phone(phone)
        if user is None:
            user_id = await self._dao.next_user_id()
            await self._dao.create_user(user_id, phone, "", "")
            return account_pb2.SignInResponse(meta=ok_meta(), user_id=user_id, is_new_user=True)

        return account_pb2.SignInResponse(meta=ok_meta(), user_id=user.user_id, is_new_user=False)

    async def SignUp(self, request, context):  # noqa: N802
        phone = _normalize_phone(request.phone)
        # signUp is called after the code was already validated during signIn.
        # The phone_code_hash is the proof; the raw code is not re-transmitted.
        if request.phone_code_hash != STUB_PHONE_CODE_HASH:
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

        return account_pb2.SignUpResponse(meta=ok_meta(), user_id=user_id)

    async def LogOut(self, request, context):  # noqa: N802
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
            username=user.username or "",
        )

    async def CheckUsername(self, request, context):  # noqa: N802
        if not isinstance(request.username, str):
            return account_pb2.CheckUsernameResponse(meta=err_meta(400, "USERNAME_INVALID"))
        normalized = _normalize_claimed_username(request.username)
        if normalized is None:
            return account_pb2.CheckUsernameResponse(meta=err_meta(400, "USERNAME_INVALID"))
        owner = await self._dao.get_user_id_by_username(normalized)
        if owner is not None:
            return account_pb2.CheckUsernameResponse(meta=err_meta(400, "USERNAME_OCCUPIED"))
        return account_pb2.CheckUsernameResponse(meta=ok_meta())

    async def UpdateUsername(self, request, context):  # noqa: N802
        user = await self._dao.get_user_by_id(request.user_id)
        if user is None:
            return account_pb2.UpdateUsernameResponse(meta=err_meta(404, "USER_NOT_FOUND"))

        raw = request.username if isinstance(request.username, str) else ""
        stripped = raw.strip()
        current_key = (user.username or "").lower()

        if stripped == "":
            new_stored: str | None = None
            new_key = ""
        else:
            normalized = _normalize_claimed_username(stripped)
            if normalized is None:
                return account_pb2.UpdateUsernameResponse(
                    meta=err_meta(400, "USERNAME_INVALID"),
                )
            new_stored = normalized
            new_key = normalized

        if new_key == current_key:
            return account_pb2.UpdateUsernameResponse(
                meta=err_meta(400, "USERNAME_NOT_MODIFIED"),
            )

        if new_stored is not None:
            owner = await self._dao.get_user_id_by_username(new_stored)
            if owner is not None and owner != user.user_id:
                return account_pb2.UpdateUsernameResponse(
                    meta=err_meta(400, "USERNAME_OCCUPIED"),
                )

        try:
            await self._dao.set_username(user.user_id, new_stored)
        except UniqueViolationError:
            return account_pb2.UpdateUsernameResponse(
                meta=err_meta(400, "USERNAME_OCCUPIED"),
            )

        updated = await self._dao.get_user_by_id(user.user_id)
        assert updated is not None
        return account_pb2.UpdateUsernameResponse(
            meta=ok_meta(),
            user_id=updated.user_id,
            phone=updated.phone,
            first_name=updated.first_name,
            last_name=updated.last_name,
            username=updated.username or "",
        )

    async def ResolveUsername(self, request, context):  # noqa: N802
        raw = request.username if isinstance(request.username, str) else ""
        stripped = raw.strip().lstrip("@")
        normalized = _normalize_claimed_username(stripped)
        if normalized is None:
            return account_pb2.ResolveUsernameResponse(meta=err_meta(400, "USERNAME_INVALID"))
        user = await self._dao.get_user_by_username(normalized)
        if user is None:
            return account_pb2.ResolveUsernameResponse(
                meta=err_meta(400, "USERNAME_NOT_OCCUPIED"),
            )
        return account_pb2.ResolveUsernameResponse(
            meta=ok_meta(),
            user_id=user.user_id,
            phone=user.phone,
            first_name=user.first_name,
            last_name=user.last_name,
            username=user.username or "",
            bio=user.bio,
        )

    async def SearchUsernames(self, request, context):  # noqa: N802
        raw = request.q if isinstance(request.q, str) else ""
        q = raw.strip().lstrip("@").lower()
        if not q:
            return account_pb2.SearchUsernamesResponse(meta=err_meta(400, "SEARCH_QUERY_EMPTY"))
        if len(q) < 3:
            return account_pb2.SearchUsernamesResponse(meta=err_meta(400, "QUERY_TOO_SHORT"))
        if not _SEARCH_USERNAME_PREFIX_RE.match(q):
            return account_pb2.SearchUsernamesResponse(meta=ok_meta())

        limit = int(request.limit) if request.limit else 50
        if limit < 1:
            limit = 50
        limit = min(limit, 50)

        actor = int(request.actor_user_id)
        rows = await self._dao.search_usernames_prefix(q, limit, actor)
        hits = [
            account_pb2.UsernameSearchHit(
                user_id=r.user_id,
                first_name=r.first_name,
                last_name=r.last_name,
                username=r.username or "",
                bio=r.bio,
            )
            for r in rows
        ]
        return account_pb2.SearchUsernamesResponse(meta=ok_meta(), hits=hits)

    # Policy RPCs (moved from gateway static stubs)

    async def GetPrivacy(self, request, context):  # noqa: N802
        """Return default privacy rules per key."""
        key = str(request.key)
        if not key.startswith("inputPrivacyKey"):
            return account_pb2.GetPrivacyResponse(
                meta=err_meta(400, "PRIVACY_KEY_INVALID"),
            )
        if key == "inputPrivacyKeyPhoneNumber":
            rule_ctor = "privacyValueDisallowAll"
        elif key == "inputPrivacyKeyBirthday":
            rule_ctor = "privacyValueAllowContacts"
        else:
            rule_ctor = "privacyValueAllowAll"
        return account_pb2.GetPrivacyResponse(
            meta=ok_meta(),
            rules=[account_pb2.PrivacyRule(constructor=rule_ctor)],
        )

    async def GetPassword(self, request, context):  # noqa: N802
        """Return password status.  2FA SRP not yet implemented."""
        return account_pb2.GetPasswordResponse(
            meta=ok_meta(), has_password=False,
        )

    async def GetContentSettings(self, request, context):  # noqa: N802
        return account_pb2.GetContentSettingsResponse(
            meta=ok_meta(),
            sensitive_can_change=True,
            sensitive_enabled=False,
        )

    # Profile RPCs (merged from ProfileService)

    _MAX_BIO_LENGTH = 128
    _MAX_FIRST_NAME_LENGTH = 64
    _MAX_LAST_NAME_LENGTH = 64

    def _profile_message(self, row) -> account_pb2.Profile:
        return account_pb2.Profile(
            user_id=row.user_id,
            first_name=row.first_name,
            last_name=row.last_name,
            bio=row.bio,
            username=row.username or "",
        )

    async def GetProfile(self, request, context):  # noqa: N802
        row = await self._dao.get_profile(request.target_user_id)
        if row is None:
            return account_pb2.GetProfileResponse(meta=err_meta(404, "USER_NOT_FOUND"))
        return account_pb2.GetProfileResponse(
            meta=ok_meta(), profile=self._profile_message(row),
        )

    async def GetProfiles(self, request, context):  # noqa: N802
        """Batch profile lookup — avoids N+1 round trips from list handlers."""
        profiles = []
        for uid in request.user_ids:
            row = await self._dao.get_profile(int(uid))
            if row is not None:
                profiles.append(self._profile_message(row))
        return account_pb2.GetProfilesResponse(meta=ok_meta(), profiles=profiles)

    async def GetFullUser(self, request, context):  # noqa: N802
        """Load user row + bio; attach phone only when actor == target."""
        if request.actor_user_id <= 0 or request.target_user_id <= 0:
            return account_pb2.GetFullUserResponse(meta=err_meta(400, "USER_ID_INVALID"))
        row = await self._dao.get_profile(request.target_user_id)
        if row is None:
            return account_pb2.GetFullUserResponse(meta=err_meta(404, "USER_NOT_FOUND"))
        is_self = request.actor_user_id == request.target_user_id
        phone = row.phone if is_self else ""
        return account_pb2.GetFullUserResponse(
            meta=ok_meta(),
            user_id=row.user_id,
            first_name=row.first_name,
            last_name=row.last_name,
            bio=row.bio,
            is_self=is_self,
            phone=phone,
            common_chats_count=0,
            username=row.username or "",
        )

    async def UpdateProfile(self, request, context):  # noqa: N802
        if len(request.bio) > self._MAX_BIO_LENGTH:
            return account_pb2.UpdateProfileResponse(meta=err_meta(400, "BIO_TOO_LONG"))
        if len(request.first_name) > self._MAX_FIRST_NAME_LENGTH:
            return account_pb2.UpdateProfileResponse(meta=err_meta(400, "FIRST_NAME_TOO_LONG"))
        if len(request.last_name) > self._MAX_LAST_NAME_LENGTH:
            return account_pb2.UpdateProfileResponse(meta=err_meta(400, "LAST_NAME_TOO_LONG"))

        old = await self._dao.get_profile(request.actor_user_id)
        if old is None:
            return account_pb2.UpdateProfileResponse(meta=err_meta(404, "USER_NOT_FOUND"))

        await self._dao.upsert_profile(
            request.actor_user_id, request.first_name, request.last_name, request.bio,
        )
        updated = await self._dao.get_profile(request.actor_user_id)
        return account_pb2.UpdateProfileResponse(
            meta=ok_meta(), profile=self._profile_message(updated),
        )

    # Config RPC (moved from gateway HelpConfigProvider)

    async def GetConfig(self, request, context):  # noqa: N802
        """Return the config TL payload from the bundled JSON file."""
        try:
            path = _default_help_config_path()
            data = json.loads(path.read_text(encoding="utf-8"))
            config_json = json.dumps(data)
        except Exception as exc:
            return account_pb2.GetConfigResponse(
                meta=err_meta(500, f"CONFIG_LOAD_ERROR: {exc}"),
            )
        return account_pb2.GetConfigResponse(
            meta=ok_meta(), config_json=config_json,
        )
