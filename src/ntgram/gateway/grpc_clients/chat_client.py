from __future__ import annotations

from ntgram.gen import chat_pb2, chat_pb2_grpc, common_pb2

from ntgram.gateway.grpc_clients._meta import assert_meta_ok
from ntgram.gateway.grpc_clients.dtos import (
    AddChatUserResult,
    ChatParticipantDto,
    CreateGroupChatResult,
    CreatePrivateDialogResult,
    DeleteMessagesResult,
    DialogRow,
    EditChatTitleResult,
    EditMessageResult,
    GetFullChatResult,
    ListDialogsResult,
    ListMessagesResult,
    MessageRow,
    MinimalChatDto,
    MinimalProfileDto,
    ReadHistoryResult,
    SendMessageResult,
)
from ntgram.gateway.route_outcome import MessageParticipant, ReadOutboxReceipt


def _profiles_from(resp_users) -> tuple[MinimalProfileDto, ...]:
    return tuple(
        MinimalProfileDto(
            user_id=int(u.user_id),
            first_name=u.first_name or "",
            last_name=u.last_name or "",
            username=u.username or "",
        )
        for u in resp_users
    )


def _chats_from(resp_chats) -> tuple[MinimalChatDto, ...]:
    return tuple(
        MinimalChatDto(
            chat_id=int(c.chat_id),
            title=c.title or "",
            participants_count=int(c.participants_count or 0),
            version=int(c.version or 1),
            date_unix=int(c.date_unix or 0),
            creator_user_id=int(c.creator_user_id or 0),
        )
        for c in resp_chats
    )


class ChatClient:
    """Wraps ChatServiceStub calls into typed DTOs."""

    __slots__ = ("_stub",)

    def __init__(self, stub: chat_pb2_grpc.ChatServiceStub) -> None:
        self._stub = stub

    async def create_group_chat(
        self,
        *,
        actor_user_id: int,
        title: str,
        member_user_ids: list[int],
    ) -> CreateGroupChatResult:
        resp = await self._stub.CreateGroupChat(
            chat_pb2.CreateGroupChatRequest(
                actor_user_id=actor_user_id,
                title=title,
                member_user_ids=member_user_ids,
            ),
        )
        assert_meta_ok(resp.meta)
        return CreateGroupChatResult(
            chat_id=int(resp.chat_id),
            dialog_id=int(resp.dialog_id),
            date_unix=int(resp.date_unix),
            service_message_id=int(resp.service_message_id),
            updates=resp.updates if resp.HasField("updates") else None,
            users=_profiles_from(resp.users),
            chats=_chats_from(resp.chats),
        )

    async def create_private_dialog(
        self, *, actor_user_id: int, peer_user_id: int,
    ) -> CreatePrivateDialogResult:
        resp = await self._stub.CreatePrivateDialog(
            chat_pb2.CreatePrivateDialogRequest(
                actor_user_id=actor_user_id,
                peer_user_id=peer_user_id,
            ),
        )
        assert_meta_ok(resp.meta)
        return CreatePrivateDialogResult(dialog_id=int(resp.dialog_id))

    async def add_chat_user(
        self, *, actor_user_id: int, chat_id: int, user_id: int,
    ) -> AddChatUserResult:
        resp = await self._stub.AddChatUser(
            chat_pb2.AddChatUserRequest(
                actor_user_id=actor_user_id,
                chat_id=chat_id,
                user_id=user_id,
            ),
        )
        assert_meta_ok(resp.meta)
        return AddChatUserResult(
            updates=resp.updates if resp.HasField("updates") else None,
            users=_profiles_from(resp.users),
            chats=_chats_from(resp.chats),
        )

    async def edit_chat_title(
        self, *, actor_user_id: int, chat_id: int, title: str,
    ) -> EditChatTitleResult:
        resp = await self._stub.EditChatTitle(
            chat_pb2.EditChatTitleRequest(
                actor_user_id=actor_user_id,
                chat_id=chat_id,
                title=title,
            ),
        )
        assert_meta_ok(resp.meta)
        return EditChatTitleResult(
            updates=resp.updates if resp.HasField("updates") else None,
            users=_profiles_from(resp.users),
            chats=_chats_from(resp.chats),
        )

    async def get_full_chat(self, chat_id: int) -> GetFullChatResult:
        """Strict (raises on non-OK meta) variant: used by messages.getFullChat."""
        resp = await self._stub.GetFullChat(
            chat_pb2.GetFullChatRequest(chat_id=chat_id),
        )
        assert_meta_ok(resp.meta)
        return _full_chat_from_resp(resp, ok=True)

    async def try_get_full_chat(self, chat_id: int) -> GetFullChatResult:
        """Tolerant variant: returns ok=False instead of raising."""
        try:
            resp = await self._stub.GetFullChat(
                chat_pb2.GetFullChatRequest(chat_id=chat_id),
            )
        except Exception:
            return GetFullChatResult(
                chat_id=int(chat_id), title="", creator_id=0,
                member_user_ids=(), ok=False,
            )
        ok = bool(getattr(resp.meta, "ok", False))
        return _full_chat_from_resp(resp, ok=ok)

    async def get_chats_batch(
        self, chat_ids: list[int],
    ) -> tuple[MinimalChatDto, ...]:
        resp = await self._stub.GetChatsBatch(
            chat_pb2.GetChatsBatchRequest(chat_ids=list(chat_ids)),
        )
        assert_meta_ok(resp.meta)
        return _chats_from(resp.chats)

    async def list_dialogs(
        self,
        *,
        actor_user_id: int,
        limit: int,
    ) -> ListDialogsResult:
        resp = await self._stub.ListDialogs(
            chat_pb2.ListDialogsRequest(
                actor_user_id=actor_user_id,
                limit=limit,
            ),
        )
        assert_meta_ok(resp.meta)
        rows = tuple(
            DialogRow(
                dialog_id=int(d.dialog_id),
                peer_id=int(d.peer_id),
                is_group=bool(d.is_group),
                read_inbox_max_id=int(d.read_inbox_max_id or 0),
                read_outbox_max_id=int(d.read_outbox_max_id or 0),
                unread_count=int(d.unread_count or 0),
                top_message_id=int(d.top_message_id or 0),
                top_message_date=int(d.top_message_date or 0),
                top_message_text=str(d.top_message_text or ""),
                top_from_user_id=int(d.top_from_user_id or 0),
                top_message_out=bool(d.top_message_out),
            )
            for d in resp.dialogs
        )
        return ListDialogsResult(
            dialogs=rows,
            users=_profiles_from(resp.users),
            chats=_chats_from(resp.chats),
            total_count=int(resp.total_count or 0),
        )

    async def resolve_dialog_members(self, dialog_id: int) -> list[int]:
        """Best-effort group membership lookup; [] on any failure."""
        try:
            resp = await self._stub.GetFullChat(
                chat_pb2.GetFullChatRequest(chat_id=dialog_id),
            )
            if getattr(resp.meta, "ok", False):
                return list(resp.member_user_ids)
        except Exception:
            pass
        return []

    async def find_group_dialog_id(
        self, *, actor_user_id: int, chat_id: int,
    ) -> int | None:
        """Map chat_id to the actor's group dialog_id via ListDialogs."""
        resp = await self._stub.ListDialogs(
            chat_pb2.ListDialogsRequest(
                actor_user_id=actor_user_id, limit=200,
            ),
        )
        assert_meta_ok(resp.meta)
        for d in resp.dialogs:
            if d.is_group and int(d.peer_id) == int(chat_id):
                return int(d.dialog_id)
        return None

    # Message RPCs
    
    async def send_message(
        self,
        *,
        actor_user_id: int,
        dialog_id: int = 0,
        text: str,
        random_id: int,
        peer: common_pb2.InputPeer | None = None,
    ) -> SendMessageResult:
        req = chat_pb2.SendMessageRequest(
            actor_user_id=actor_user_id,
            dialog_id=dialog_id,
            text=text,
            random_id=random_id,
        )
        if peer is not None:
            req.peer.CopyFrom(peer)
        resp = await self._stub.SendMessage(req)
        assert_meta_ok(resp.meta)
        participants = tuple(
            MessageParticipant(
                user_id=int(p.user_id),
                user_message_box_id=int(p.user_message_box_id),
                pts=int(p.pts),
                dialog_id=int(p.dialog_id),
                peer_id=int(p.peer_id),
                is_group=bool(p.is_group),
            )
            for p in resp.participants
        )
        return SendMessageResult(
            actor_user_message_box_id=int(resp.actor_user_message_box_id),
            pts=int(resp.pts),
            date_unix=int(resp.date_unix),
            participants=participants,
            updates=resp.updates if resp.HasField("updates") else None,
            users=_profiles_from(resp.users),
            chats=_chats_from(resp.chats),
        )

    async def delete_messages(
        self,
        *,
        actor_user_id: int,
        user_message_box_ids: list[int],
        revoke: bool,
    ) -> DeleteMessagesResult:
        """Forward TL id/revoke to ChatService.DeleteMessages."""
        resp = await self._stub.DeleteMessages(
            chat_pb2.DeleteMessagesRequest(
                actor_user_id=actor_user_id,
                user_message_box_ids=[int(i) for i in user_message_box_ids],
                revoke=bool(revoke),
            ),
        )
        assert_meta_ok(resp.meta)
        return DeleteMessagesResult(
            pts=int(resp.pts),
            pts_count=int(resp.pts_count),
            deleted_ids=tuple(int(i) for i in resp.deleted_ids),
            updates=resp.updates if resp.HasField("updates") else None,
        )

    async def edit_message(
        self,
        *,
        actor_user_id: int,
        user_message_box_id: int,
        new_text: str,
        new_entities_json: str = "",
    ) -> EditMessageResult:
        resp = await self._stub.EditMessage(
            chat_pb2.EditMessageRequest(
                actor_user_id=actor_user_id,
                user_message_box_id=int(user_message_box_id),
                new_text=new_text,
                new_entities_json=new_entities_json,
            ),
        )
        assert_meta_ok(resp.meta)
        return EditMessageResult(
            actor_user_message_box_id=int(resp.actor_user_message_box_id),
            dialog_message_id=int(resp.dialog_message_id),
            edit_date=int(resp.edit_date),
            updates=resp.updates if resp.HasField("updates") else None,
            users=_profiles_from(resp.users),
            chats=_chats_from(resp.chats),
        )

    async def list_messages(
        self,
        *,
        actor_user_id: int,
        dialog_id: int = 0,
        limit: int,
        offset_id: int,
        offset_date: int,
        add_offset: int,
        max_id: int,
        min_id: int,
        hash_: int,
        peer: common_pb2.InputPeer | None = None,
    ) -> ListMessagesResult:
        req = chat_pb2.ListMessagesRequest(
            actor_user_id=actor_user_id,
            dialog_id=dialog_id,
            limit=limit,
            offset_id=offset_id,
            offset_date=offset_date,
            add_offset=add_offset,
            max_id=max_id,
            min_id=min_id,
            hash=hash_,
        )
        if peer is not None:
            req.peer.CopyFrom(peer)
        resp = await self._stub.ListMessages(req)
        assert_meta_ok(resp.meta)
        messages = tuple(
            MessageRow(
                message_id=int(m.message_id),
                from_user_id=int(m.from_user_id),
                date=int(m.date),
                text=m.text or "",
                out=bool(m.out),
            )
            for m in resp.messages
        )
        return ListMessagesResult(
            messages=messages,
            total_count=int(resp.total_count) if resp.total_count else len(messages),
            users=_profiles_from(resp.users),
            chats=_chats_from(resp.chats),
        )

    async def read_history(
        self,
        *,
        actor_user_id: int,
        dialog_id: int = 0,
        max_id: int,
        peer: common_pb2.InputPeer | None = None,
    ) -> ReadHistoryResult:
        req = chat_pb2.ReadHistoryRequest(
            actor_user_id=actor_user_id,
            dialog_id=dialog_id,
            max_id=max_id,
        )
        if peer is not None:
            req.peer.CopyFrom(peer)
        resp = await self._stub.ReadHistory(req)
        assert_meta_ok(resp.meta)
        receipts = tuple(
            ReadOutboxReceipt(
                sender_user_id=int(r.sender_user_id),
                sender_dialog_id=int(r.sender_dialog_id),
                max_outbox_id=int(r.max_outbox_id),
                pts=int(r.pts),
            )
            for r in resp.receipts
        )
        return ReadHistoryResult(
            pts=int(resp.pts),
            pts_count=int(resp.pts_count),
            receipts=receipts,
        )


def _full_chat_from_resp(resp, *, ok: bool) -> GetFullChatResult:
    if not ok:
        return GetFullChatResult(
            chat_id=int(resp.chat_id) if resp.chat_id else 0,
            title="", creator_id=0,
            member_user_ids=(), ok=False,
        )
    participants = tuple(
        ChatParticipantDto(
            user_id=int(p.user_id),
            inviter_user_id=int(p.inviter_user_id),
            date_unix=int(p.date_unix),
            kind=int(p.kind),
        )
        for p in resp.participants
    )
    return GetFullChatResult(
        chat_id=int(resp.chat_id),
        title=resp.title,
        creator_id=int(resp.creator_id),
        member_user_ids=tuple(int(u) for u in resp.member_user_ids),
        participants=participants,
        users=_profiles_from(resp.users),
        version=int(resp.version or 1),
        participants_count=int(resp.participants_count or 0),
        date_unix=int(resp.date_unix or 0),
        ok=True,
    )
