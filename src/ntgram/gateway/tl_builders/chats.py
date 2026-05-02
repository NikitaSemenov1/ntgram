from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from ntgram.gateway.grpc_clients.dtos import (
    ChatParticipantDto,
    GetFullChatResult,
    MinimalChatDto,
)
from ntgram.gateway.tl_messages import build_chat_minimal_tl


def build_chat_tl(
    minimal: MinimalChatDto, *, actor_user_id: int = 0,
) -> dict[str, Any]:
    """TL chat { id, title, participants_count, date, version }."""
    creator = bool(
        actor_user_id and minimal.creator_user_id
        and int(actor_user_id) == int(minimal.creator_user_id),
    )
    return build_chat_minimal_tl(
        chat_id=minimal.chat_id,
        title=minimal.title,
        participants_count=minimal.participants_count,
        version=minimal.version or 1,
        date=minimal.date_unix or 0,
        creator=creator,
    )


def build_chat_participants_tl(
    *,
    chat_id: int,
    creator_user_id: int,
    participants: Sequence[ChatParticipantDto],
    version: int,
) -> dict[str, Any]:
    """TL chatParticipants { chat_id, participants[], version }."""
    items: list[dict[str, Any]] = []
    creator_emitted = False
    for p in participants:
        if int(p.user_id) == int(creator_user_id) and not creator_emitted:
            items.append({
                "constructor": "chatParticipantCreator",
                "user_id": int(p.user_id),
            })
            creator_emitted = True
        else:
            items.append({
                "constructor": "chatParticipant",
                "user_id": int(p.user_id),
                "inviter_id": int(p.inviter_user_id),
                "date": int(p.date_unix),
            })
    if not creator_emitted and creator_user_id:
        items.insert(0, {
            "constructor": "chatParticipantCreator",
            "user_id": int(creator_user_id),
        })
    return {
        "constructor": "chatParticipants",
        "chat_id": int(chat_id),
        "participants": items,
        "version": int(version) or 1,
    }


def build_chat_full_tl(
    full: GetFullChatResult,
    *,
    chats_tl: list[dict[str, Any]],
    users_tl: list[dict[str, Any]],
) -> dict[str, Any]:
    """TL messages.chatFull { full_chat, chats, users }."""
    inner = {
        "constructor": "chatFull",
        "id": int(full.chat_id),
        "about": "",
        "participants": build_chat_participants_tl(
            chat_id=full.chat_id,
            creator_user_id=full.creator_id,
            participants=full.participants,
            version=full.version or 1,
        ),
        "notify_settings": {"constructor": "peerNotifySettings"},
    }
    return {
        "constructor": "messages.chatFull",
        "full_chat": inner,
        "chats": chats_tl,
        "users": users_tl,
    }
