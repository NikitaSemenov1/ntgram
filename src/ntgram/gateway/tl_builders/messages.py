from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from ntgram.gen import common_pb2
from ntgram.gateway.grpc_clients.dtos import MessageRow
from ntgram.gateway.tl_messages import build_message_tl


def build_send_message_updates_tl(
    envelope: common_pb2.UpdateEnvelope,
    users: Sequence[dict[str, Any]] = (),
    chats: Sequence[dict[str, Any]] = (),
) -> dict[str, Any]:
    """Map a service-filled UpdateEnvelope to a TL updates payload."""
    if not envelope.updates:
        raise RuntimeError("build_send_message_updates_tl: UpdateEnvelope.updates is empty")

    updates_tl: list[dict[str, Any]] = []
    for item in envelope.updates:
        if item.raw_update_json:
            try:
                updates_tl.append(json.loads(item.raw_update_json))
            except Exception:
                # Skip malformed payloads — the wire response is still valid.
                continue
            continue
        which = item.WhichOneof("update")
        if which == "message_id":
            u = item.message_id
            updates_tl.append({
                "constructor": "updateMessageID",
                "id": int(u.message_id),
                "random_id": int(u.random_id),
            })
        elif which == "new_message":
            u = item.new_message
            peer_id_tl: dict[str, Any]
            if u.peer_chat_id:
                peer_id_tl = {"constructor": "peerChat", "chat_id": int(u.peer_chat_id)}
            else:
                peer_id_tl = {"constructor": "peerUser", "user_id": int(u.peer_user_id)}
            msg_tl = build_message_tl(
                message_id=int(u.message_id),
                from_user_id=int(u.from_user_id),
                date=int(u.date),
                text=u.text,
                peer_id_tl=peer_id_tl,
                out=bool(u.out),
            )
            updates_tl.append({
                "constructor": "updateNewMessage",
                "message": msg_tl,
                "pts": int(u.pts),
                "pts_count": int(u.pts_count),
            })
        elif which == "read_outbox":
            u = item.read_outbox
            updates_tl.append({
                "constructor": "updateReadHistoryOutbox",
                "peer": {"constructor": "peerUser", "user_id": int(u.peer_user_id)},
                "max_id": int(u.max_id),
                "pts": int(u.pts),
                "pts_count": int(u.pts_count),
            })

    return {
        "constructor": "updates",
        "updates": updates_tl,
        "users": list(users),
        "chats": list(chats),
        "date": int(envelope.date),
        "seq": int(envelope.seq),
    }


def messages_messages_or_slice_tl(
    *,
    rows: Sequence[MessageRow],
    peer_id_tl: dict[str, Any],
    chats: list[dict[str, Any]],
    users: list[dict[str, Any]],
    requested_limit: int,
    total_count: int,
) -> dict[str, Any]:
    """Build either messages.messages or messages.messagesSlice."""
    messages_tl = [
        build_message_tl(
            message_id=m.message_id,
            from_user_id=m.from_user_id,
            date=m.date,
            text=m.text,
            peer_id_tl=peer_id_tl,
            out=m.out,
        )
        for m in rows
    ]
    capped = min(max(requested_limit, 1), 50)
    if len(messages_tl) == capped and total_count >= capped:
        return {
            "constructor": "messages.messagesSlice",
            "flags": 0,
            "count": total_count,
            "messages": messages_tl,
            "chats": chats,
            "users": users,
        }
    return {
        "constructor": "messages.messages",
        "messages": messages_tl,
        "chats": chats,
        "users": users,
    }
