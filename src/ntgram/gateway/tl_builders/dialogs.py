from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from ntgram.gateway.grpc_clients.dtos import DialogRow
from ntgram.gateway.tl_messages import (
    build_chat_minimal_tl,
    build_message_tl,
    build_peer_chat_tl,
    build_peer_user_tl,
)


@dataclass(slots=True, frozen=True)
class DialogsView:
    """Output of `build_dialogs_view`."""

    dialogs_tl: list[dict[str, Any]]
    messages_tl: list[dict[str, Any]]
    chats_tl: list[dict[str, Any]]
    referenced_user_ids: set[int]


def build_dialogs_view(
    *, actor_user_id: int, dialogs: Sequence[DialogRow],
) -> DialogsView:
    """Translate `DialogRow`s into TL dialog / message / chat lists."""
    dialogs_tl: list[dict[str, Any]] = []
    messages_tl: list[dict[str, Any]] = []
    chats_tl: list[dict[str, Any]] = []
    seen_msg: set[int] = set()
    seen_chat: set[int] = set()
    user_ids: set[int] = {actor_user_id}

    for d in dialogs:
        peer_tl = (
            build_peer_chat_tl(d.peer_id)
            if d.is_group
            else build_peer_user_tl(d.peer_id)
        )

        if d.top_message_id > 0:
            user_ids.add(d.top_from_user_id)
            msg_tl = build_message_tl(
                message_id=d.top_message_id,
                from_user_id=d.top_from_user_id,
                date=d.top_message_date,
                text=d.top_message_text,
                peer_id_tl=peer_tl,
                out=d.top_message_out,
            )
            if d.top_message_id not in seen_msg:
                seen_msg.add(d.top_message_id)
                messages_tl.append(msg_tl)
            top_m = d.top_message_id
        else:
            top_m = 0

        if d.is_group and d.peer_id not in seen_chat:
            seen_chat.add(d.peer_id)
            chats_tl.append(
                build_chat_minimal_tl(
                    chat_id=d.peer_id, title="", participants_count=0,
                ),
            )
        if not d.is_group:
            user_ids.add(d.peer_id)

        dialogs_tl.append({
            "constructor": "dialog",
            "flags": 0,
            "peer": peer_tl,
            "top_message": top_m,
            "read_inbox_max_id": d.read_inbox_max_id,
            "read_outbox_max_id": d.read_outbox_max_id,
            "unread_count": d.unread_count,
            "unread_mentions_count": 0,
            "unread_reactions_count": 0,
            "notify_settings": {"constructor": "peerNotifySettings", "flags": 0},
        })

    return DialogsView(
        dialogs_tl=dialogs_tl,
        messages_tl=messages_tl,
        chats_tl=chats_tl,
        referenced_user_ids=user_ids,
    )
