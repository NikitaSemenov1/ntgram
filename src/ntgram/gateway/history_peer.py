from __future__ import annotations

from typing import Any, Literal

from ntgram.errors import RpcFailure

HistoryKind = Literal["pm", "group", "self_empty", "invalid", "channel"]


def classify_history_peer(actor_user_id: int, peer: Any) -> tuple[HistoryKind, int]:
    """Return (kind, peer_id) where peer_id is other user id (PM) or chat_id (group)."""
    if actor_user_id <= 0:
        raise RpcFailure(401, "AUTH_KEY_UNREGISTERED")
    if not isinstance(peer, dict):
        raise RpcFailure(400, "PEER_ID_INVALID")
    ctor = peer.get("_constructor") or peer.get("constructor")
    if not isinstance(ctor, str):
        raise RpcFailure(400, "PEER_ID_INVALID")
    if ctor == "inputPeerEmpty":
        return ("invalid", 0)
    if ctor == "inputPeerSelf":
        return ("self_empty", 0)
    if ctor == "inputPeerUser":
        uid = peer.get("user_id")
        if not isinstance(uid, int) or uid <= 0:
            raise RpcFailure(400, "PEER_ID_INVALID")
        if uid == actor_user_id:
            return ("self_empty", 0)
        return ("pm", uid)
    if ctor == "inputPeerChat":
        cid = peer.get("chat_id")
        if not isinstance(cid, int) or cid <= 0:
            raise RpcFailure(400, "PEER_ID_INVALID")
        return ("group", cid)
    if ctor == "inputPeerChannel":
        return ("channel", 0)
    raise RpcFailure(400, "PEER_ID_INVALID")
