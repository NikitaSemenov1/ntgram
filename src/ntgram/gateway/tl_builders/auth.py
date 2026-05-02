from __future__ import annotations

import secrets
from typing import Any


def _random_access_hash(user_id: int) -> int:
    token = secrets.randbits(64)
    # Keep in signed int64 range for MTProto wire encoding.
    value = (token ^ user_id) & ((1 << 64) - 1)
    if value >= 1 << 63:
        value -= 1 << 64
    return value


def auth_authorization_tl(
    *,
    user_id: int,
    phone: str,
    first_name: str = "",
    last_name: str = "",
) -> dict[str, Any]:
    """Build TL auth.authorization with a minimal self user."""
    return {
        "constructor": "auth.authorization",
        "user": {
            "constructor": "user",
            "self": True,
            "id": int(user_id),
            # N4: use a random access_hash instead of the hardcoded literal 1.
            "access_hash": _random_access_hash(int(user_id)),
            "first_name": first_name,
            "last_name": last_name,
            "phone": phone,
        },
    }


def auth_authorization_sign_up_required_tl() -> dict[str, Any]:
    """Build TL auth.authorizationSignUpRequired for unregistered phones."""
    return {
        "constructor": "auth.authorizationSignUpRequired",
        "terms_of_service": None,
    }


def user_id_from_auth_rpc_result(nested: object) -> int | None:
    """Read user.id from an auth.authorization result dict."""
    if not isinstance(nested, dict):
        return None
    if nested.get("constructor") != "auth.authorization":
        return None
    user = nested.get("user")
    if not isinstance(user, dict):
        return None
    uid = user.get("id")
    return int(uid) if isinstance(uid, int) else None
