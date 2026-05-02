from __future__ import annotations

from typing import Any

from ntgram.tl.builders.updates import build_message_tl as build_message_tl  # noqa: F401


def build_peer_user_tl(user_id: int) -> dict[str, Any]:
    return {"constructor": "peerUser", "user_id": int(user_id)}


def build_peer_chat_tl(chat_id: int) -> dict[str, Any]:
    return {"constructor": "peerChat", "chat_id": int(chat_id)}


def build_chat_minimal_tl(
    *,
    chat_id: int,
    title: str,
    participants_count: int,
    version: int = 1,
    date: int = 0,
    creator: bool = False,
) -> dict[str, Any]:
    """Map to TL chat constructor."""
    out: dict[str, Any] = {
        "constructor": "chat",
        "id": int(chat_id),
        "title": title or "",
        "photo": {"constructor": "chatPhotoEmpty"},
        "participants_count": int(participants_count),
        "date": int(date),
        "version": int(version) if version else 1,
        "default_banned_rights": {"constructor": "chatBannedRights", "until_date": 0},
    }
    if creator:
        out["creator"] = True
    return out
