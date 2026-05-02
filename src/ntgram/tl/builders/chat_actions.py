from __future__ import annotations

from typing import Any


def build_action_chat_create(
    *, title: str, user_ids: list[int],
) -> dict[str, Any]:
    """messageActionChatCreate — emitted at chat creation."""
    return {
        "constructor": "messageActionChatCreate",
        "title": title,
        "users": [int(u) for u in user_ids],
    }


def build_action_chat_add_user(
    *, user_ids: list[int],
) -> dict[str, Any]:
    """messageActionChatAddUser — emitted when a user is added."""
    return {
        "constructor": "messageActionChatAddUser",
        "users": [int(u) for u in user_ids],
    }


def build_action_chat_edit_title(*, title: str) -> dict[str, Any]:
    """messageActionChatEditTitle — emitted on title edit."""
    return {
        "constructor": "messageActionChatEditTitle",
        "title": title,
    }
