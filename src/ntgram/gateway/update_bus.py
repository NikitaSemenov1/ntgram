from __future__ import annotations

import logging
import time

from ntgram.gateway.push_registry import PushRegistry

logger = logging.getLogger(__name__)


class UpdateBus:
    """In-process notification bus for server-push updates."""

    def __init__(self, registry: PushRegistry) -> None:
        self._registry = registry

    async def notify_new_message(
        self,
        member_user_ids: list[int],
        *,
        exclude_auth_key_id: int = 0,
        message_id: int,
        dialog_id: int,
        from_user_id: int,
        text: str,
        pts: int,
        date: int = 0,
    ) -> None:
        update = {
            "constructor": "updateNewMessage",
            "message": {
                "message_id": message_id,
                "dialog_id": dialog_id,
                "from_user_id": from_user_id,
                "text": text,
                "date": date or int(time.time()),
            },
            "pts": pts,
            "pts_count": 1,
        }
        for uid in member_user_ids:
            await self._registry.push_to_user(
                uid, update,
                exclude_auth_key_id=exclude_auth_key_id,
            )

    async def notify_delete_messages(
        self,
        member_user_ids: list[int],
        *,
        exclude_auth_key_id: int = 0,
        message_ids: list[int],
        dialog_id: int,
        pts: int,
    ) -> None:
        update = {
            "constructor": "updateDeleteMessages",
            "messages": message_ids,
            "dialog_id": dialog_id,
            "pts": pts,
            "pts_count": 1,
        }
        for uid in member_user_ids:
            await self._registry.push_to_user(
                uid, update,
                exclude_auth_key_id=exclude_auth_key_id,
            )

    async def notify_status_change(
        self,
        user_id: int,
        *,
        online: bool,
        last_seen_unix: int = 0,
    ) -> None:
        """Push updateUserStatus to all connections of the user."""
        if online:
            status = {"constructor": "userStatusOnline", "expires": 300}
        else:
            status = {
                "constructor": "userStatusOffline",
                "was_online": last_seen_unix or int(time.time()),
            }
        update = {
            "constructor": "updateUserStatus",
            "user_id": user_id,
            "status": status,
        }
        await self._registry.push_to_user(user_id, update)
