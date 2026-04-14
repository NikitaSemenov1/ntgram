from __future__ import annotations

import time

import asyncpg
import grpc

from ntgram.gen import (
    chat_pb2,
    chat_pb2_grpc,
    message_pb2,
    message_pb2_grpc,
)
from ntgram.services.common import err_meta, ok_meta
from ntgram.services.message.dao import MessageDAO

MAX_HISTORY_LIMIT = 50


class MessageService(message_pb2_grpc.MessageServiceServicer):
    def __init__(
        self, pool: asyncpg.Pool, chat_channel: grpc.aio.Channel,
    ) -> None:
        self._dao = MessageDAO(pool)
        self._chat = chat_pb2_grpc.ChatServiceStub(chat_channel)

    async def _resolve_members(
        self, dialog_id: int, actor_user_id: int,
    ) -> list[int]:
        """Resolve all participant user_ids for a dialog."""
        members = await self._dao.get_dialog_participants(dialog_id)
        if members:
            return members
        try:
            req = chat_pb2.GetFullChatRequest(chat_id=dialog_id)
            resp = await self._chat.GetFullChat(req)
            if resp.meta.ok:
                return list(resp.member_user_ids)
        except Exception:
            pass
        return [actor_user_id]

    async def SendMessage(self, request, context):  # noqa: N802
        if not request.text or not request.text.strip():
            return message_pb2.SendMessageResponse(
                meta=err_meta(400, "MESSAGE_EMPTY"),
            )

        if request.random_id:
            existing = await self._dao.find_by_random_id(
                request.actor_user_id, request.random_id,
            )
            if existing is not None:
                return message_pb2.SendMessageResponse(
                    meta=ok_meta(), message_id=existing, pts=0,
                )

        message_id = await self._dao.next_message_id()
        date_unix = int(time.time())
        await self._dao.create_message(
            message_id=message_id,
            dialog_id=request.dialog_id,
            from_user_id=request.actor_user_id,
            text=request.text.strip(),
            date_unix=date_unix,
            random_id=request.random_id if request.random_id else None,
        )

        members = await self._resolve_members(
            request.dialog_id, request.actor_user_id,
        )
        user_pts = await self._dao.increment_pts_for_users(members)
        update_data = {
            "message_id": message_id,
            "dialog_id": request.dialog_id,
            "from_user_id": request.actor_user_id,
            "text": request.text.strip(),
            "date": date_unix,
        }
        await self._dao.record_pts_updates_for_users(
            user_pts, "updateNewMessage", update_data,
        )

        sender_pts = user_pts.get(request.actor_user_id, 0)
        return message_pb2.SendMessageResponse(
            meta=ok_meta(), message_id=message_id, pts=sender_pts,
        )

    async def DeleteMessages(self, request, context):  # noqa: N802
        members = await self._resolve_members(
            request.dialog_id, request.actor_user_id,
        )

        if request.revoke:
            deleted = await self._dao.delete_messages_for_all(
                list(request.message_ids), members,
            )
        else:
            deleted = await self._dao.delete_messages(
                list(request.message_ids), request.actor_user_id,
            )

        affected = members if request.revoke else [request.actor_user_id]
        user_pts = await self._dao.increment_pts_for_users(affected)
        if deleted:
            await self._dao.record_pts_updates_for_users(
                user_pts, "updateDeleteMessages",
                {"message_ids": deleted, "dialog_id": request.dialog_id},
            )

        sender_pts = user_pts.get(request.actor_user_id, 0)
        return message_pb2.DeleteMessagesResponse(
            meta=ok_meta(), deleted_ids=deleted, pts=sender_pts,
        )

    async def ListMessages(self, request, context):  # noqa: N802
        limit = min(max(request.limit, 1), MAX_HISTORY_LIMIT)
        rows = await self._dao.get_history(
            request.dialog_id, request.actor_user_id, limit,
        )
        messages = [
            message_pb2.Message(
                message_id=r.message_id,
                from_user_id=r.from_user_id,
                text=r.message_text,
                date=r.date_unix,
            )
            for r in rows
        ]
        return message_pb2.ListMessagesResponse(
            meta=ok_meta(), messages=messages,
        )

    async def ReadHistory(self, request, context):  # noqa: N802
        await self._dao.update_read_inbox(
            request.actor_user_id, request.dialog_id, request.max_id,
        )
        pts = await self._dao.increment_pts(request.actor_user_id)
        return message_pb2.ReadHistoryResponse(
            meta=ok_meta(), pts=pts,
        )
