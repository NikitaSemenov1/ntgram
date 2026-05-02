from __future__ import annotations

from typing import Any

from ntgram.gateway.grpc_clients.dtos import (
    FullUserDto,
    MinimalProfileDto,
    ProfileDto,
    UpdateUsernameResult,
)

_STATUS_EMPTY: dict[str, Any] = {"constructor": "userStatusEmpty"}


# Low-level builders (previously in tl_user_full.py)

def build_public_user_tl(
    *,
    user_id: int,
    first_name: str,
    last_name: str,
    username: str = "",
) -> dict[str, Any]:
    """Minimal non-self user with userStatusEmpty for embedded user lists."""
    out: dict[str, Any] = {
        "constructor": "user",
        "id": int(user_id),
        "access_hash": 1,
        "first_name": first_name or "",
        "last_name": last_name or "",
        "status": _STATUS_EMPTY,
    }
    if username:
        out["username"] = username
    return out


def build_self_user_tl(
    *,
    user_id: int,
    first_name: str,
    last_name: str,
    phone: str = "",
    username: str = "",
) -> dict[str, Any]:
    """Minimal user for account.updateProfile / account.updateUsername (self)."""
    out: dict[str, Any] = {
        "constructor": "user",
        "self": True,
        "id": int(user_id),
        "access_hash": 1,
        "first_name": first_name or "",
        "last_name": last_name or "",
    }
    if phone:
        out["phone"] = phone
    if username:
        out["username"] = username
    return out


def build_users_user_full(
    *,
    peer_id: int,
    actor_user_id: int,
    first_name: str,
    last_name: str,
    bio: str,
    phone: str | None,
    username: str = "",
) -> dict[str, Any]:
    """Assemble users.userFull for users.getFullUser RPC result."""
    is_self = actor_user_id == peer_id
    user_obj: dict[str, Any] = {
        "constructor": "user",
        "id": int(peer_id),
        "access_hash": 1,
        "first_name": first_name or "",
        "last_name": last_name or "",
        "status": _STATUS_EMPTY,
    }
    if is_self:
        user_obj["self"] = True
        if phone:
            user_obj["phone"] = phone
    if username:
        user_obj["username"] = username

    full_user: dict[str, Any] = {
        "constructor": "userFull",
        "id": int(peer_id),
        "settings": {"constructor": "peerSettings"},
        "notify_settings": {"constructor": "peerNotifySettings"},
        "common_chats_count": 0,
        "blocked": False,
        "can_pin_message": True,
        "has_scheduled": False,
        "phone_calls_available": not is_self,
        "phone_calls_private": False,
        "video_calls_available": not is_self,
        "voice_messages_forbidden": False,
        "translations_disabled": False,
        "stories_pinned_available": False,
        "blocked_my_stories_from": False,
        "wallpaper_overridden": False,
    }
    if bio:
        full_user["about"] = bio

    return {
        "constructor": "users.userFull",
        "full_user": full_user,
        "chats": [],
        "users": [user_obj],
    }


# DTO -> TL adapters used by route handlers

def public_user_tl_from_dto(profile: ProfileDto) -> dict[str, Any]:
    """Map a non-self `ProfileDto` into a TL user payload."""
    return build_public_user_tl(
        user_id=profile.user_id,
        first_name=profile.first_name,
        last_name=profile.last_name,
        username=profile.username,
    )


def public_user_tl_from_minimal(profile: MinimalProfileDto) -> dict[str, Any]:
    """Map a `MinimalProfileDto` (embedded in list responses) to TL user."""
    return build_public_user_tl(
        user_id=profile.user_id,
        first_name=profile.first_name,
        last_name=profile.last_name,
        username=profile.username,
    )


def self_user_tl_from_update(result: UpdateUsernameResult) -> dict[str, Any]:
    """Map account.UpdateUsername / UpdateProfile DTO into a self-user TL."""
    return build_self_user_tl(
        user_id=result.user_id,
        first_name=result.first_name,
        last_name=result.last_name,
        phone=result.phone,
        username=result.username,
    )


def self_user_tl_from_profile(
    *, profile: ProfileDto, phone: str, username: str,
) -> dict[str, Any]:
    """Compose a self-user TL from `ProfileDto` + side phone/username."""
    return build_self_user_tl(
        user_id=profile.user_id,
        first_name=profile.first_name,
        last_name=profile.last_name,
        phone=phone,
        username=username,
    )


def users_user_full_tl_from_dto(
    *,
    full: FullUserDto,
    actor_user_id: int,
) -> dict[str, Any]:
    """Map a `FullUserDto` into TL users.userFull for users.getFullUser."""
    phone = full.phone if full.is_self else None
    return build_users_user_full(
        peer_id=full.user_id,
        actor_user_id=actor_user_id,
        first_name=full.first_name,
        last_name=full.last_name,
        bio=full.bio,
        phone=phone,
        username=full.username,
    )
