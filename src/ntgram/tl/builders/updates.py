from __future__ import annotations

from typing import Any

_INT32_MAX = 2**31 - 1
_INT32_MIN = -(2**31)


def _safe_int32(value: int) -> int:
    v = int(value)
    if v > _INT32_MAX:
        return _INT32_MAX
    if v < _INT32_MIN:
        return _INT32_MIN
    return v


# Peer helpers


def peer_user(user_id: int) -> dict[str, Any]:
    return {"constructor": "peerUser", "user_id": int(user_id)}


def peer_chat(chat_id: int) -> dict[str, Any]:
    return {"constructor": "peerChat", "chat_id": int(chat_id)}


# Message builder


def build_message_tl(
    *,
    message_id: int,
    from_user_id: int,
    date: int,
    text: str,
    peer_id_tl: dict[str, Any],
    out: bool,
    # Optional rich fields; pass None/empty to omit from the wire message.
    media: dict[str, Any] | None = None,
    reply_to: dict[str, Any] | None = None,
    entities: list[dict[str, Any]] | None = None,
    views: int | None = None,
    forwards: int | None = None,
    edit_date: int = 0,
) -> dict[str, Any]:
    """TL message dict suitable for embedding in updateNewMessage."""
    result: dict[str, Any] = {
        "constructor": "message",
        # Clamp to int32; MTProto message.id is a signed 32-bit int.
        "id": _safe_int32(message_id),
        "from_id": peer_user(from_user_id),
        "peer_id": peer_id_tl,
        "date": int(date),
        "message": text,
    }
    if out:
        result["out"] = True
    if reply_to is not None:
        result["reply_to"] = reply_to
    if media is not None:
        result["media"] = media
    if entities:
        result["entities"] = entities
    if views is not None:
        result["views"] = int(views)
    if forwards is not None:
        result["forwards"] = int(forwards)
    if edit_date:
        result["edit_date"] = int(edit_date)
    return result


# messageService builder (used for system messages: chat create / add / title)


def build_message_service_tl(
    *,
    message_id: int,
    from_user_id: int,
    peer_id_tl: dict[str, Any],
    date: int,
    action: dict[str, Any],
    out: bool,
) -> dict[str, Any]:
    """TL messageService dict wrapping a MessageAction."""
    result: dict[str, Any] = {
        "constructor": "messageService",
        "id": _safe_int32(message_id),
        "from_id": peer_user(from_user_id),
        "peer_id": peer_id_tl,
        "date": int(date),
        "action": action,
    }
    if out:
        result["out"] = True
    return result


# Update builders


def build_update_new_message(
    *, message: dict[str, Any], pts: int, pts_count: int = 1,
) -> dict[str, Any]:
    """Full TL updateNewMessage dict wrapping a Message."""
    return {
        "constructor": "updateNewMessage",
        "message": message,
        "pts": int(pts),
        "pts_count": int(pts_count),
    }


def build_update_read_history_inbox(
    *,
    peer: dict[str, Any] | None = None,
    peer_user_id: int | None = None,
    max_id: int,
    still_unread: int,
    pts: int,
) -> dict[str, Any]:
    """Build updateReadHistoryInbox."""
    if peer is None:
        if peer_user_id is None:
            raise ValueError("peer or peer_user_id must be provided")
        peer = peer_user(peer_user_id)
    return {
        "constructor": "updateReadHistoryInbox",
        "peer": peer,
        "max_id": int(max_id),
        "still_unread_count": int(still_unread),
        "pts": int(pts),
        "pts_count": 1,
    }


def build_update_read_history_outbox(
    *,
    peer: dict[str, Any] | None = None,
    peer_user_id: int | None = None,
    max_id: int,
    pts: int,
) -> dict[str, Any]:
    """Build updateReadHistoryOutbox."""
    if peer is None:
        if peer_user_id is None:
            raise ValueError("peer or peer_user_id must be provided")
        peer = peer_user(peer_user_id)
    return {
        "constructor": "updateReadHistoryOutbox",
        "peer": peer,
        "max_id": int(max_id),
        "pts": int(pts),
        "pts_count": 1,
    }


def build_update_edit_message_tl(
    *, message: dict[str, Any], pts: int, pts_count: int = 1,
) -> dict[str, Any]:
    """TL updateEditMessage { message, pts, pts_count }."""
    return {
        "constructor": "updateEditMessage",
        "message": message,
        "pts": int(pts),
        "pts_count": int(pts_count),
    }


def build_update_delete_messages_tl(
    *, message_ids: list[int], pts: int, pts_count: int | None = None,
) -> dict[str, Any]:
    """TL updateDeleteMessages { messages, pts, pts_count }."""
    ids = [_safe_int32(int(i)) for i in message_ids]
    pc = int(pts_count) if pts_count is not None else len(ids)
    return {
        "constructor": "updateDeleteMessages",
        "messages": ids,
        "pts": int(pts),
        "pts_count": pc,
    }
