from __future__ import annotations

from typing import Any

from ntgram.errors import RpcFailure


def resolve_input_user_id(actor_user_id: int, raw: Any) -> int:
    """Map InputUser to user_id."""
    if actor_user_id <= 0:
        raise RpcFailure(401, "AUTH_KEY_UNREGISTERED")
    if not isinstance(raw, dict):
        raise RpcFailure(400, "USER_ID_INVALID")
    ctor = raw.get("_constructor") or raw.get("constructor")
    if not isinstance(ctor, str):
        raise RpcFailure(400, "USER_ID_INVALID")
    if ctor == "inputUserSelf":
        return int(actor_user_id)
    if ctor == "inputUser":
        uid = raw.get("user_id")
        if not isinstance(uid, int):
            raise RpcFailure(400, "USER_ID_INVALID")
        if uid <= 0:
            raise RpcFailure(400, "USER_ID_INVALID")
        return int(uid)
    if ctor in ("inputUserEmpty", "inputUserFromMessage"):
        raise RpcFailure(400, "USER_ID_INVALID")
    raise RpcFailure(400, "USER_ID_INVALID")
