from __future__ import annotations

import asyncpg
import grpc

from ntgram.gen import account_pb2, account_pb2_grpc, chat_pb2, chat_pb2_grpc
from ntgram.services.chat.dao import ChatDAO
from ntgram.services.common import err_meta, ok_meta

MAX_GROUP_MEMBERS = 200
MAX_TITLE_LENGTH = 128


class ChatService(chat_pb2_grpc.ChatServiceServicer):
    def __init__(self, pool: asyncpg.Pool, account_channel: grpc.aio.Channel) -> None:
        self._dao = ChatDAO(pool)
        self._account = account_pb2_grpc.AccountServiceStub(account_channel)

    async def _user_exists(self, user_id: int) -> bool:
        resp = await self._account.GetUser(account_pb2.GetUserRequest(user_id=user_id))
        return resp.meta.ok

    async def CreatePrivateDialog(self, request, context):  # noqa: N802
        if not await self._user_exists(request.actor_user_id):
            return chat_pb2.CreatePrivateDialogResponse(meta=err_meta(400, "USER_NOT_FOUND"))
        if not await self._user_exists(request.peer_user_id):
            return chat_pb2.CreatePrivateDialogResponse(meta=err_meta(400, "PEER_NOT_FOUND"))

        existing = await self._dao.find_private_dialog(request.actor_user_id, request.peer_user_id)
        if existing is not None:
            return chat_pb2.CreatePrivateDialogResponse(meta=ok_meta(), dialog_id=existing)

        dialog_id = await self._dao.next_dialog_id()
        await self._dao.create_dialog(dialog_id, request.actor_user_id, request.peer_user_id, False)
        await self._dao.create_dialog(dialog_id, request.peer_user_id, request.actor_user_id, False)
        return chat_pb2.CreatePrivateDialogResponse(meta=ok_meta(), dialog_id=dialog_id)

    async def CreateGroupChat(self, request, context):  # noqa: N802
        if not request.title or not request.title.strip():
            return chat_pb2.CreateGroupChatResponse(meta=err_meta(400, "CHAT_TITLE_EMPTY"))
        if len(request.title) > MAX_TITLE_LENGTH:
            return chat_pb2.CreateGroupChatResponse(meta=err_meta(400, "CHAT_TITLE_TOO_LONG"))

        if not await self._user_exists(request.actor_user_id):
            return chat_pb2.CreateGroupChatResponse(meta=err_meta(400, "USER_NOT_FOUND"))

        all_members = {request.actor_user_id, *request.member_user_ids}
        if len(all_members) > MAX_GROUP_MEMBERS:
            return chat_pb2.CreateGroupChatResponse(meta=err_meta(400, "USERS_TOO_MANY"))

        for uid in request.member_user_ids:
            if not await self._user_exists(uid):
                return chat_pb2.CreateGroupChatResponse(meta=err_meta(400, f"USER_NOT_FOUND:{uid}"))

        chat_id = await self._dao.next_chat_id()
        await self._dao.create_chat(chat_id, request.title.strip(), request.actor_user_id)
        dialog_id = await self._dao.next_dialog_id()
        for uid in all_members:
            await self._dao.add_member(chat_id, uid)
            await self._dao.create_dialog(dialog_id, uid, chat_id, True)

        return chat_pb2.CreateGroupChatResponse(meta=ok_meta(), chat_id=chat_id)

    async def AddChatUser(self, request, context):  # noqa: N802
        chat = await self._dao.get_chat(request.chat_id)
        if chat is None:
            return chat_pb2.AddChatUserResponse(meta=err_meta(404, "CHAT_NOT_FOUND"))
        if not await self._user_exists(request.user_id):
            return chat_pb2.AddChatUserResponse(meta=err_meta(400, "USER_NOT_FOUND"))

        members = await self._dao.get_members(request.chat_id)
        if request.actor_user_id not in members:
            return chat_pb2.AddChatUserResponse(meta=err_meta(403, "USER_NOT_PARTICIPANT"))
        if request.user_id in members:
            return chat_pb2.AddChatUserResponse(meta=err_meta(400, "USER_ALREADY_PARTICIPANT"))
        if len(members) >= MAX_GROUP_MEMBERS:
            return chat_pb2.AddChatUserResponse(meta=err_meta(400, "USERS_TOO_MANY"))

        await self._dao.add_member(request.chat_id, request.user_id)
        dialog_id = await self._dao.next_dialog_id()
        await self._dao.create_dialog(dialog_id, request.user_id, request.chat_id, True)
        return chat_pb2.AddChatUserResponse(meta=ok_meta())

    async def DeleteChatUser(self, request, context):  # noqa: N802
        chat = await self._dao.get_chat(request.chat_id)
        if chat is None:
            return chat_pb2.DeleteChatUserResponse(meta=err_meta(404, "CHAT_NOT_FOUND"))

        members = await self._dao.get_members(request.chat_id)
        if request.actor_user_id not in members:
            return chat_pb2.DeleteChatUserResponse(meta=err_meta(403, "USER_NOT_PARTICIPANT"))
        if request.user_id not in members:
            return chat_pb2.DeleteChatUserResponse(meta=err_meta(400, "USER_NOT_PARTICIPANT"))
        if request.user_id == chat.created_by and request.actor_user_id == request.user_id:
            return chat_pb2.DeleteChatUserResponse(meta=err_meta(400, "CREATOR_CANNOT_LEAVE"))

        await self._dao.remove_member(request.chat_id, request.user_id)
        return chat_pb2.DeleteChatUserResponse(meta=ok_meta())

    async def EditChatTitle(self, request, context):  # noqa: N802
        if not request.title or not request.title.strip():
            return chat_pb2.EditChatTitleResponse(meta=err_meta(400, "CHAT_TITLE_EMPTY"))
        if len(request.title) > MAX_TITLE_LENGTH:
            return chat_pb2.EditChatTitleResponse(meta=err_meta(400, "CHAT_TITLE_TOO_LONG"))

        chat = await self._dao.get_chat(request.chat_id)
        if chat is None:
            return chat_pb2.EditChatTitleResponse(meta=err_meta(404, "CHAT_NOT_FOUND"))

        members = await self._dao.get_members(request.chat_id)
        if request.actor_user_id not in members:
            return chat_pb2.EditChatTitleResponse(meta=err_meta(403, "USER_NOT_PARTICIPANT"))

        await self._dao.update_title(request.chat_id, request.title.strip())
        return chat_pb2.EditChatTitleResponse(meta=ok_meta())

    async def GetFullChat(self, request, context):  # noqa: N802
        chat = await self._dao.get_chat(request.chat_id)
        if chat is None:
            return chat_pb2.GetFullChatResponse(meta=err_meta(404, "CHAT_NOT_FOUND"))
        members = await self._dao.get_members(request.chat_id)
        return chat_pb2.GetFullChatResponse(
            meta=ok_meta(),
            chat_id=chat.chat_id,
            title=chat.title,
            creator_id=chat.created_by,
            member_user_ids=members,
        )

    async def ListDialogs(self, request, context):  # noqa: N802
        rows = await self._dao.list_dialogs(request.actor_user_id)
        dialogs = [
            chat_pb2.Dialog(dialog_id=r.dialog_id, peer_id=r.peer_id, is_group=r.is_group)
            for r in rows
        ]
        return chat_pb2.ListDialogsResponse(meta=ok_meta(), dialogs=dialogs)
