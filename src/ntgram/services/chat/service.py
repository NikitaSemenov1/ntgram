from __future__ import annotations

import asyncio
import json
import time

import asyncpg
import grpc

from ntgram.gen import (
    account_pb2,
    account_pb2_grpc,
    chat_pb2,
    chat_pb2_grpc,
    common_pb2,
    updates_pb2,
    updates_pb2_grpc,
)
from ntgram.services.chat.dao import (
    ChatDAO,
    ChatRow,
    DialogStateOwnerRow,
    InsertMessageBoxRow,
    InsertMessageRow,
    MessageBoxRow,
    ThreadParticipantAddEntry,
)
from ntgram.services.common import err_meta, ok_meta
from ntgram.tl.builders.chat_actions import (
    build_action_chat_add_user,
    build_action_chat_create,
    build_action_chat_edit_title,
)
from ntgram.tl.builders.updates import (
    build_message_service_tl,
    build_message_tl,
    build_update_delete_messages_tl,
    build_update_edit_message_tl,
    build_update_new_message,
    build_update_read_history_inbox,
    build_update_read_history_outbox,
    peer_chat,
    peer_user,
)

MAX_GROUP_MEMBERS = 200
MAX_TITLE_LENGTH = 128
MAX_HISTORY_LIMIT = 50

# Kept for external interface compatibility (gRPC peer typing).
PEER_TYPE_USER = 0
PEER_TYPE_CHAT = 1


def _is_group_state(row: DialogStateOwnerRow) -> bool:
    return row.peer_chat_id > 0


def _participant_dict(row: DialogStateOwnerRow, thread_id: int) -> dict:
    """Translate a DialogStateOwnerRow to the legacy participant dict."""
    return {
        "user_id": int(row.owner_user_id),
        "dialog_id": int(thread_id),
        "peer_id": int(row.peer_id),
        "is_group": bool(row.is_group),
    }


class ChatService(chat_pb2_grpc.ChatServiceServicer):
    """Implementation of the merged ChatService gRPC interface."""

    def __init__(
        self,
        pool: asyncpg.Pool,
        account_channel: grpc.aio.Channel,
        updates_channel: grpc.aio.Channel,
    ) -> None:
        """Construct the service."""
        self._pool = pool
        self._dao = ChatDAO(pool)
        self._account = account_pb2_grpc.AccountServiceStub(account_channel)
        self._updates = updates_pb2_grpc.UpdatesServiceStub(updates_channel)

    # AccountService helpers

    async def _user_exists(self, user_id: int) -> bool:
        try:
            resp = await self._account.GetUser(
                account_pb2.GetUserRequest(user_id=user_id),
            )
        except Exception:
            return False
        return resp.meta.ok

    async def _get_profiles_batch(
        self, actor_user_id: int, user_ids: set[int],
    ) -> list[common_pb2.MinimalProfile]:
        if not user_ids:
            return []
        try:
            resp = await self._account.GetProfiles(
                account_pb2.GetProfilesRequest(
                    actor_user_id=actor_user_id,
                    user_ids=list(user_ids),
                ),
            )
        except Exception:
            return []
        return [
            common_pb2.MinimalProfile(
                user_id=p.user_id,
                first_name=p.first_name,
                last_name=p.last_name,
                username=p.username,
            )
            for p in resp.profiles
        ]

    @staticmethod
    def _chat_to_minimal(chat: ChatRow) -> common_pb2.MinimalChat:
        return common_pb2.MinimalChat(
            chat_id=int(chat.chat_id),
            title=chat.title,
            participants_count=int(chat.participants_count),
            version=int(chat.version),
            date_unix=int(chat.date_unix),
            creator_user_id=int(chat.created_by),
        )

    # UpdatesService helpers

    async def _alloc_pts_for_users(self, user_ids: list[int]) -> dict[int, int]:
        """Batch IncrementPts via UpdatesServiceStub."""
        if not user_ids:
            return {}
        ids_uniq = list(dict.fromkeys(int(u) for u in user_ids))
        resp = await self._updates.IncrementPtsBatch(
            updates_pb2.IncrementPtsBatchRequest(user_ids=ids_uniq),
        )
        if not resp.meta.ok:
            raise RuntimeError(
                f"UpdatesService.IncrementPtsBatch failed: "
                f"{resp.meta.error.code}/{resp.meta.error.message}",
            )
        return {int(e.user_id): int(e.pts) for e in resp.entries}

    async def _record_pts_updates(
        self,
        items: list[tuple[int, int, str, dict, int]],
        *,
        date_unix: int = 0,
    ) -> None:
        """Batch RecordPtsUpdate via UpdatesServiceStub."""
        if not items:
            return
        pb_items = [
            updates_pb2.RecordPtsUpdateRequest(
                user_id=int(uid),
                pts=int(pts),
                pts_count=int(pts_count or 1),
                update_type=str(upd_type),
                raw_update_json=json.dumps(upd_data),
                date_unix=int(date_unix) if date_unix else 0,
            )
            for uid, pts, upd_type, upd_data, pts_count in items
        ]
        resp = await self._updates.RecordPtsUpdateBatch(
            updates_pb2.RecordPtsUpdateBatchRequest(items=pb_items),
        )
        if not resp.meta.ok:
            raise RuntimeError(
                f"UpdatesService.RecordPtsUpdateBatch failed: "
                f"{resp.meta.error.code}/{resp.meta.error.message}",
            )

    async def _current_pts(self, user_id: int) -> int:
        """Fetch the actor's current PTS via UpdatesService.GetState."""
        try:
            resp = await self._updates.GetState(
                updates_pb2.GetStateRequest(user_id=int(user_id)),
            )
        except Exception:
            return 0
        if not resp.meta.ok:
            return 0
        return int(resp.pts)

    # Peer / participant resolution (private)
    
    async def _resolve_participants(
        self, thread_id: int, actor_user_id: int,
    ) -> list[dict]:
        """[{user_id, dialog_id, peer_id, is_group}] for one thread."""
        del actor_user_id  # actor is implicit in dialog_state rows
        owners = await self._dao.find_dialog_states_by_thread_id(thread_id)
        return [_participant_dict(o, thread_id) for o in owners]

    @staticmethod
    def _peer_type_for(is_group: bool) -> int:
        return PEER_TYPE_CHAT if is_group else PEER_TYPE_USER

    @staticmethod
    def _participant_delivery(
        *, user_id: int, ubid: int, pts: int, participant: dict,
    ) -> chat_pb2.ParticipantDelivery:
        return chat_pb2.ParticipantDelivery(
            user_id=user_id,
            user_message_box_id=ubid,
            pts=pts,
            dialog_id=int(participant["dialog_id"]),
            peer_id=int(participant["peer_id"]),
            is_group=bool(participant["is_group"]),
        )

    async def _resolve_thread_from_peer(
        self, peer: common_pb2.InputPeer,
    ) -> int:
        """Resolve InputPeer to thread_id internally."""
        actor = int(peer.actor_user_id)
        which = peer.WhichOneof("peer")
        if which == "user_id":
            peer_user_id = int(peer.user_id)
            if peer_user_id == actor:
                return -1
            try:
                resp = await self.CreatePrivateDialog(
                    chat_pb2.CreatePrivateDialogRequest(
                        actor_user_id=actor,
                        peer_user_id=peer_user_id,
                    ),
                    None,
                )
                if resp.meta.ok:
                    return int(resp.dialog_id)
            except Exception:
                pass
            return 0
        if which == "chat_id":
            chat_id = int(peer.chat_id)
            thread_id = await self._dao.find_thread_for_chat(chat_id)
            return int(thread_id) if thread_id else 0
        return 0

    async def _embed_chat(
        self, peer_chat_id: int,
    ) -> list[common_pb2.MinimalChat]:
        """Embed MinimalChat for a destination chat (uses local ChatDAO)."""
        if not peer_chat_id:
            return []
        chat = await self._dao.get_chat(int(peer_chat_id))
        if chat is None:
            return []
        return [self._chat_to_minimal(chat)]

    # Chat lifecycle event emitter (replaces _build_chat_service_message)
    
    async def _emit_chat_lifecycle_event(
        self,
        *,
        actor_user_id: int,
        chat_id: int,
        member_ids: list[int],
        kind: str,
        action_tl: dict,
        date_unix: int,
    ) -> tuple[common_pb2.UpdateEnvelope, int]:
        """Persist a chat_events row + fan out messageService updates."""
        peer_tl = peer_chat(chat_id)

        event_id = await self._dao.add_chat_event(
            chat_id=chat_id,
            actor_user_id=actor_user_id,
            kind=kind,
            payload=action_tl,
            date_unix=date_unix,
        )
        del event_id  # currently audit-only; surfaced via service_message_id

        ubid_by_uid: dict[int, int] = {}
        for uid in member_ids:
            ubid_by_uid[uid] = await self._dao.next_user_message_box_id(uid)

        pts_by_uid = await self._alloc_pts_for_users(member_ids)

        pts_updates: list[tuple[int, int, str, dict, int]] = []
        actor_ubid = 0
        actor_pts = 0
        for uid in member_ids:
            ubid = ubid_by_uid[uid]
            pts = pts_by_uid[uid]
            out = (uid == actor_user_id)
            msg_tl = build_message_service_tl(
                message_id=ubid,
                from_user_id=actor_user_id,
                peer_id_tl=peer_tl,
                date=date_unix,
                action=action_tl,
                out=out,
            )
            pts_updates.append(
                (uid, pts, "updateNewMessage",
                 build_update_new_message(message=msg_tl, pts=pts), 1),
            )
            if out:
                actor_ubid = ubid
                actor_pts = pts

        await self._record_pts_updates(pts_updates, date_unix=date_unix)

        actor_msg_tl = build_message_service_tl(
            message_id=actor_ubid,
            from_user_id=actor_user_id,
            peer_id_tl=peer_tl,
            date=date_unix,
            action=action_tl,
            out=True,
        )
        envelope = common_pb2.UpdateEnvelope(
            updates=[
                common_pb2.UpdateItem(
                    raw_update_json=json.dumps(
                        build_update_new_message(message=actor_msg_tl, pts=actor_pts),
                    ),
                    update_type="updateNewMessage",
                    pts=actor_pts,
                ),
            ],
            seq=0,
            date=date_unix,
        )
        return envelope, actor_ubid

    # SendMessage helpers (envelope + idempotency replay)
    
    @staticmethod
    def _build_send_envelope(
        *,
        actor_user_id: int,
        actor_ubid: int,
        actor_pts: int,
        text: str,
        date_unix: int,
        peer_user_id: int = 0,
        peer_chat_id: int = 0,
        random_id: int = 0,
    ) -> common_pb2.UpdateEnvelope:
        """Build the actor-side UpdateEnvelope for a SendMessage rpc_result."""
        msg_id_update = common_pb2.UpdateItem(
            message_id=common_pb2.UpdateMessageId(
                message_id=actor_ubid,
                random_id=random_id,
            ),
        )
        new_msg_update = common_pb2.UpdateItem(
            new_message=common_pb2.UpdateNewMessage(
                message_id=actor_ubid,
                from_user_id=actor_user_id,
                text=text,
                date=date_unix,
                peer_user_id=peer_user_id,
                peer_chat_id=peer_chat_id,
                out=True,
                pts=actor_pts,
                pts_count=1,
            ),
        )
        return common_pb2.UpdateEnvelope(
            updates=[msg_id_update, new_msg_update],
            seq=0,
            date=date_unix,
        )

    async def _build_send_response_from_existing(
        self,
        actor_user_id: int,
        existing: MessageBoxRow,
        random_id: int,
    ) -> chat_pb2.SendMessageResponse:
        """Idempotent reply when a row with the same random_id exists."""
        owners = await self._dao.find_dialog_states_by_thread_id(existing.thread_id)
        peer_map: dict[int, dict] = {
            int(o.owner_user_id): _participant_dict(o, existing.thread_id)
            for o in owners
        }
        copies = await self._dao.get_boxes_by_dialog_message_ids(
            [int(existing.dialog_message_id)],
        )
        deliveries: list[chat_pb2.ParticipantDelivery] = []
        for c in copies:
            uid = int(c.user_id)
            participant = peer_map.get(
                uid,
                {
                    "user_id": uid,
                    "dialog_id": int(existing.thread_id),
                    "peer_id": int(existing.peer_id),
                    "is_group": existing.is_group,
                },
            )
            deliveries.append(
                self._participant_delivery(
                    user_id=uid,
                    ubid=int(c.user_message_box_id),
                    pts=int(c.pts),
                    participant=participant,
                ),
            )

        actor_peer = peer_map.get(actor_user_id)
        peer_user_id = 0
        peer_chat_id = 0
        if actor_peer is not None:
            if actor_peer["is_group"]:
                peer_chat_id = int(actor_peer["peer_id"])
            else:
                peer_user_id = int(actor_peer["peer_id"])
        else:
            if existing.is_group:
                peer_chat_id = int(existing.peer_id)
            else:
                peer_user_id = int(existing.peer_id)

        envelope = self._build_send_envelope(
            actor_user_id=actor_user_id,
            actor_ubid=existing.user_message_box_id,
            actor_pts=existing.pts,
            text=existing.text,
            date_unix=existing.date_unix,
            peer_user_id=peer_user_id,
            peer_chat_id=peer_chat_id,
            random_id=random_id,
        )

        user_ids: set[int] = {actor_user_id}
        if peer_user_id:
            user_ids.add(int(peer_user_id))
        users = await self._get_profiles_batch(actor_user_id, user_ids)
        chats = await self._embed_chat(peer_chat_id)

        return chat_pb2.SendMessageResponse(
            meta=ok_meta(),
            actor_user_message_box_id=existing.user_message_box_id,
            pts=existing.pts,
            dialog_message_id=existing.dialog_message_id,
            date_unix=existing.date_unix,
            participants=deliveries,
            updates=envelope,
            users=users,
            chats=chats,
        )

    # Chat lifecycle

    async def CreatePrivateDialog(self, request, context):  # noqa: N802
        if not await self._user_exists(request.actor_user_id):
            return chat_pb2.CreatePrivateDialogResponse(meta=err_meta(400, "USER_NOT_FOUND"))
        if not await self._user_exists(request.peer_user_id):
            return chat_pb2.CreatePrivateDialogResponse(meta=err_meta(400, "PEER_NOT_FOUND"))

        existing = await self._dao.find_private_thread(
            request.actor_user_id, request.peer_user_id,
        )
        if existing is not None:
            return chat_pb2.CreatePrivateDialogResponse(meta=ok_meta(), dialog_id=existing)

        thread_id = await self._dao.next_thread_id()
        await self._dao.create_thread(thread_id, chat_id=None)
        date_unix = int(time.time())
        await self._dao.bulk_add_thread_participants(
            thread_id,
            [
                ThreadParticipantAddEntry(
                    user_id=int(request.actor_user_id),
                    inviter_user_id=0,
                    joined_at_unix=date_unix,
                ),
                ThreadParticipantAddEntry(
                    user_id=int(request.peer_user_id),
                    inviter_user_id=0,
                    joined_at_unix=date_unix,
                ),
            ],
        )
        await self._dao.create_dialog_state(
            thread_id, int(request.actor_user_id),
            peer_user_id=int(request.peer_user_id),
        )
        await self._dao.create_dialog_state(
            thread_id, int(request.peer_user_id),
            peer_user_id=int(request.actor_user_id),
        )
        return chat_pb2.CreatePrivateDialogResponse(meta=ok_meta(), dialog_id=thread_id)

    async def CreateGroupChat(self, request, context):  # noqa: N802
        title = (request.title or "").strip()
        if not title:
            return chat_pb2.CreateGroupChatResponse(meta=err_meta(400, "CHAT_TITLE_EMPTY"))
        if len(title) > MAX_TITLE_LENGTH:
            return chat_pb2.CreateGroupChatResponse(meta=err_meta(400, "CHAT_TITLE_TOO_LONG"))

        actor = int(request.actor_user_id)
        if not await self._user_exists(actor):
            return chat_pb2.CreateGroupChatResponse(meta=err_meta(400, "USER_NOT_FOUND"))

        invited_ordered: list[int] = []
        seen: set[int] = {actor}
        for uid in request.member_user_ids:
            uid_i = int(uid)
            if uid_i in seen:
                continue
            seen.add(uid_i)
            invited_ordered.append(uid_i)

        all_members = [actor, *invited_ordered]
        if len(all_members) > MAX_GROUP_MEMBERS:
            return chat_pb2.CreateGroupChatResponse(meta=err_meta(400, "USERS_TOO_MANY"))

        for uid in invited_ordered:
            if not await self._user_exists(uid):
                return chat_pb2.CreateGroupChatResponse(
                    meta=err_meta(400, f"USER_NOT_FOUND:{uid}"),
                )

        date_unix = int(time.time())
        chat_id = await self._dao.next_chat_id()
        await self._dao.create_chat(chat_id, title, actor, date_unix)

        thread_id = await self._dao.next_thread_id()
        await self._dao.create_thread(thread_id, chat_id=chat_id)
        await self._dao.bulk_add_thread_participants(
            thread_id,
            [
                ThreadParticipantAddEntry(
                    user_id=uid, inviter_user_id=actor,
                    joined_at_unix=date_unix,
                )
                for uid in all_members
            ],
            chat_id_for_counter=chat_id,
        )
        for uid in all_members:
            await self._dao.create_dialog_state(
                thread_id, uid, peer_chat_id=chat_id,
            )

        action_tl = build_action_chat_create(title=title, user_ids=all_members)
        envelope, actor_msg_id = await self._emit_chat_lifecycle_event(
            actor_user_id=actor,
            chat_id=chat_id,
            member_ids=all_members,
            kind="chat_create",
            action_tl=action_tl,
            date_unix=date_unix,
        )

        chat = await self._dao.get_chat(chat_id)
        users = await self._get_profiles_batch(actor, set(all_members))
        chats: list[common_pb2.MinimalChat] = (
            [self._chat_to_minimal(chat)] if chat is not None else []
        )

        return chat_pb2.CreateGroupChatResponse(
            meta=ok_meta(),
            chat_id=chat_id,
            dialog_id=thread_id,
            date_unix=date_unix,
            service_message_id=actor_msg_id,
            updates=envelope,
            users=users,
            chats=chats,
        )

    async def AddChatUser(self, request, context):  # noqa: N802
        actor = int(request.actor_user_id)
        chat_id = int(request.chat_id)
        new_user = int(request.user_id)

        chat = await self._dao.get_chat(chat_id)
        if chat is None:
            return chat_pb2.AddChatUserResponse(meta=err_meta(404, "CHAT_NOT_FOUND"))
        if not await self._user_exists(new_user):
            return chat_pb2.AddChatUserResponse(meta=err_meta(400, "USER_NOT_FOUND"))

        thread_id = await self._dao.find_thread_for_chat(chat_id)
        if thread_id is None:
            return chat_pb2.AddChatUserResponse(meta=err_meta(500, "CHAT_THREAD_MISSING"))

        members = await self._dao.get_thread_participant_ids(thread_id)
        if actor not in members:
            return chat_pb2.AddChatUserResponse(meta=err_meta(403, "USER_NOT_PARTICIPANT"))
        if new_user in members:
            return chat_pb2.AddChatUserResponse(meta=err_meta(400, "USER_ALREADY_PARTICIPANT"))
        if len(members) >= MAX_GROUP_MEMBERS:
            return chat_pb2.AddChatUserResponse(meta=err_meta(400, "USERS_TOO_MANY"))

        date_unix = int(time.time())
        await self._dao.add_thread_participant(
            thread_id, new_user, actor, date_unix,
            chat_id_for_counter=chat_id,
        )
        await self._dao.create_dialog_state(
            thread_id, new_user, peer_chat_id=chat_id,
        )

        all_members = [*members, new_user]
        action_tl = build_action_chat_add_user(user_ids=[new_user])
        envelope, _ = await self._emit_chat_lifecycle_event(
            actor_user_id=actor,
            chat_id=chat_id,
            member_ids=all_members,
            kind="chat_add_user",
            action_tl=action_tl,
            date_unix=date_unix,
        )

        refreshed = await self._dao.get_chat(chat_id)
        users = await self._get_profiles_batch(actor, set(all_members))
        chats: list[common_pb2.MinimalChat] = (
            [self._chat_to_minimal(refreshed)] if refreshed is not None else []
        )

        return chat_pb2.AddChatUserResponse(
            meta=ok_meta(), updates=envelope, users=users, chats=chats,
        )

    async def EditChatTitle(self, request, context):  # noqa: N802
        actor = int(request.actor_user_id)
        chat_id = int(request.chat_id)
        new_title = (request.title or "").strip()

        if not new_title:
            return chat_pb2.EditChatTitleResponse(meta=err_meta(400, "CHAT_TITLE_EMPTY"))
        if len(new_title) > MAX_TITLE_LENGTH:
            return chat_pb2.EditChatTitleResponse(meta=err_meta(400, "CHAT_TITLE_TOO_LONG"))

        chat = await self._dao.get_chat(chat_id)
        if chat is None:
            return chat_pb2.EditChatTitleResponse(meta=err_meta(404, "CHAT_NOT_FOUND"))

        thread_id = await self._dao.find_thread_for_chat(chat_id)
        if thread_id is None:
            return chat_pb2.EditChatTitleResponse(meta=err_meta(500, "CHAT_THREAD_MISSING"))

        members = await self._dao.get_thread_participant_ids(thread_id)
        if actor not in members:
            return chat_pb2.EditChatTitleResponse(meta=err_meta(403, "USER_NOT_PARTICIPANT"))

        await self._dao.update_title(chat_id, new_title)

        date_unix = int(time.time())
        action_tl = build_action_chat_edit_title(title=new_title)
        envelope, _ = await self._emit_chat_lifecycle_event(
            actor_user_id=actor,
            chat_id=chat_id,
            member_ids=members,
            kind="chat_edit_title",
            action_tl=action_tl,
            date_unix=date_unix,
        )

        refreshed = await self._dao.get_chat(chat_id)
        users = await self._get_profiles_batch(actor, set(members))
        chats: list[common_pb2.MinimalChat] = (
            [self._chat_to_minimal(refreshed)] if refreshed is not None else []
        )

        return chat_pb2.EditChatTitleResponse(
            meta=ok_meta(), updates=envelope, users=users, chats=chats,
        )

    async def GetFullChat(self, request, context):  # noqa: N802
        chat = await self._dao.get_chat(request.chat_id)
        if chat is None:
            return chat_pb2.GetFullChatResponse(meta=err_meta(404, "CHAT_NOT_FOUND"))

        thread_id = await self._dao.find_thread_for_chat(int(request.chat_id))
        members = (
            await self._dao.get_thread_participants(thread_id)
            if thread_id is not None
            else []
        )
        member_ids = [m.user_id for m in members]
        users = await self._get_profiles_batch(int(chat.created_by), set(member_ids))

        participants = [
            chat_pb2.ChatParticipant(
                user_id=int(m.user_id),
                inviter_user_id=int(m.inviter_user_id),
                date_unix=int(m.joined_at_unix),
                kind=0 if int(m.user_id) == int(chat.created_by) else 1,
            )
            for m in members
        ]

        return chat_pb2.GetFullChatResponse(
            meta=ok_meta(),
            chat_id=int(chat.chat_id),
            title=chat.title,
            creator_id=int(chat.created_by),
            member_user_ids=member_ids,
            participants=participants,
            users=users,
            version=int(chat.version),
            participants_count=int(chat.participants_count),
            date_unix=int(chat.date_unix),
        )

    async def GetChatsBatch(self, request, context):  # noqa: N802
        ids = [int(c) for c in request.chat_ids if int(c) > 0]
        if not ids:
            return chat_pb2.GetChatsBatchResponse(meta=ok_meta(), chats=[])
        chats_map = await self._dao.get_chats_batch(ids)
        chats: list[common_pb2.MinimalChat] = [
            self._chat_to_minimal(chats_map[cid])
            for cid in ids
            if cid in chats_map
        ]
        return chat_pb2.GetChatsBatchResponse(meta=ok_meta(), chats=chats)

    async def ListDialogs(self, request, context):  # noqa: N802
        lim = int(request.limit) if request.limit else 100
        lim = max(1, min(lim, 200))
        actor = int(request.actor_user_id)
        total_count, rows = await asyncio.gather(
            self._dao.count_dialogs(actor),
            self._dao.list_dialogs(actor, limit=lim),
        )
        dialogs = [
            chat_pb2.Dialog(
                dialog_id=r.thread_id,
                peer_id=r.peer_id,
                is_group=r.is_group,
                read_inbox_max_id=r.read_inbox_max_id,
                read_outbox_max_id=r.read_outbox_max_id,
                unread_count=r.unread_count,
                top_message_id=r.top_message_id,
                top_from_user_id=r.top_from_user_id,
                top_message_text=r.top_message_text,
                top_message_date=r.top_message_date,
                top_message_out=r.top_message_out,
                top_dialog_message_id=r.top_dialog_message_id,
            )
            for r in rows
        ]

        user_ids: set[int] = set()
        chat_ids: set[int] = set()
        for r in rows:
            if r.peer_chat_id:
                chat_ids.add(int(r.peer_chat_id))
            elif r.peer_user_id:
                user_ids.add(int(r.peer_user_id))
            if r.top_from_user_id:
                user_ids.add(int(r.top_from_user_id))
        user_ids.discard(0)

        users = await self._get_profiles_batch(actor, user_ids)

        chat_id_list = list(chat_ids)
        chats_map = await self._dao.get_chats_batch(chat_id_list)
        chats: list[common_pb2.MinimalChat] = [
            self._chat_to_minimal(chats_map[cid])
            for cid in chat_id_list
            if cid in chats_map
        ]

        return chat_pb2.ListDialogsResponse(
            meta=ok_meta(),
            dialogs=dialogs,
            users=users,
            chats=chats,
            total_count=total_count,
        )

    async def FindDialogsByDialogId(self, request, context):  # noqa: N802
        owners = await self._dao.find_dialog_states_by_thread_id(
            int(request.dialog_id),
        )
        return chat_pb2.FindDialogsByDialogIdResponse(
            meta=ok_meta(),
            owners=[
                chat_pb2.DialogOwner(
                    owner_user_id=o.owner_user_id,
                    peer_id=o.peer_id,
                    is_group=o.is_group,
                )
                for o in owners
            ],
        )

    # RPC: messages

    async def SendMessage(self, request, context):  # noqa: N802
        text = (request.text or "").strip()
        if not text:
            return chat_pb2.SendMessageResponse(meta=err_meta(400, "MESSAGE_EMPTY"))

        actor = int(request.actor_user_id)
        if request.HasField("peer"):
            thread_id = await self._resolve_thread_from_peer(request.peer)
            if thread_id <= 0:
                return chat_pb2.SendMessageResponse(meta=err_meta(400, "PEER_ID_INVALID"))
        else:
            thread_id = int(request.dialog_id)
        random_id = int(request.random_id) if request.random_id else 0

        if random_id:
            cached = await self._dao.find_by_random_id(actor, random_id)
            if cached is not None:
                return await self._build_send_response_from_existing(
                    actor, cached, random_id,
                )

        participants = await self._resolve_participants(thread_id, actor)
        if not participants:
            return chat_pb2.SendMessageResponse(meta=err_meta(400, "PEER_ID_INVALID"))
        if not any(p["user_id"] == actor for p in participants):
            return chat_pb2.SendMessageResponse(meta=err_meta(403, "CHAT_WRITE_FORBIDDEN"))

        # Group membership check (defensive: catches stale dialog_state).
        is_group_send = any(p["is_group"] for p in participants)
        if is_group_send:
            chat_id = next(
                (int(p["peer_id"]) for p in participants
                 if p["is_group"] and int(p["user_id"]) == actor),
                0,
            )
            if chat_id:
                members = await self._dao.get_thread_participant_ids(thread_id)
                if actor not in members:
                    return chat_pb2.SendMessageResponse(
                        meta=err_meta(403, "CHAT_WRITE_FORBIDDEN"),
                    )

        date_unix = int(time.time())
        dialog_message_id = await self._dao.next_dialog_message_id()

        ubid_by_uid: dict[int, int] = {}
        for p in participants:
            uid = int(p["user_id"])
            ubid_by_uid[uid] = await self._dao.next_user_message_box_id(uid)

        member_ids = [int(p["user_id"]) for p in participants]
        pts_by_uid = await self._alloc_pts_for_users(member_ids)

        boxes: list[InsertMessageBoxRow] = []
        deliveries: list[chat_pb2.ParticipantDelivery] = []
        pts_updates: list[tuple[int, int, str, dict, int]] = []
        actor_ubid = 0
        actor_pts = 0

        for p in participants:
            uid = int(p["user_id"])
            is_group = bool(p["is_group"])
            ubid = ubid_by_uid[uid]
            pts = pts_by_uid[uid]
            out = (uid == actor)
            boxes.append(
                InsertMessageBoxRow(
                    user_id=uid,
                    user_message_box_id=ubid,
                    dialog_message_id=dialog_message_id,
                    out=out,
                    random_id=random_id if (out and random_id) else None,
                    pts=pts,
                ),
            )

            await self._dao.update_dialog_top(
                uid, thread_id, ubid, increment_unread=(not out),
            )

            peer_id_tl = (
                peer_chat(int(p["peer_id"])) if is_group
                else peer_user(int(p["peer_id"]))
            )
            msg_tl = build_message_tl(
                message_id=ubid,
                from_user_id=actor,
                date=date_unix,
                text=text,
                peer_id_tl=peer_id_tl,
                out=out,
            )
            update_tl = build_update_new_message(message=msg_tl, pts=pts)
            pts_updates.append((uid, pts, "updateNewMessage", update_tl, 1))

            deliveries.append(
                self._participant_delivery(
                    user_id=uid, ubid=ubid, pts=pts, participant=p,
                ),
            )
            if out:
                actor_ubid = ubid
                actor_pts = pts

        # chat_db: insert messages + message_boxes (one transaction).
        message_row = InsertMessageRow(
            dialog_message_id=dialog_message_id,
            thread_id=thread_id,
            from_user_id=actor,
            text=text,
            date_unix=date_unix,
        )
        await self._dao.insert_message_with_boxes(None, message_row, boxes)

        # updates_db: persist PTS log + NOTIFY (one transaction inside the RPC).
        await self._record_pts_updates(pts_updates, date_unix=date_unix)

        actor_peer = next(
            (p for p in participants if int(p["user_id"]) == actor), None,
        )
        peer_user_id = 0
        peer_chat_id = 0
        if actor_peer:
            if actor_peer.get("is_group"):
                peer_chat_id = int(actor_peer.get("peer_id", 0))
            else:
                pid = int(actor_peer.get("peer_id", 0))
                if pid != actor:
                    peer_user_id = pid

        envelope = self._build_send_envelope(
            actor_user_id=actor,
            actor_ubid=actor_ubid,
            actor_pts=actor_pts,
            text=text,
            date_unix=date_unix,
            peer_user_id=peer_user_id,
            peer_chat_id=peer_chat_id,
            random_id=random_id,
        )

        user_ids: set[int] = {actor}
        if peer_user_id:
            user_ids.add(int(peer_user_id))
        users = await self._get_profiles_batch(actor, user_ids)
        chats = await self._embed_chat(peer_chat_id)

        return chat_pb2.SendMessageResponse(
            meta=ok_meta(),
            actor_user_message_box_id=actor_ubid,
            pts=actor_pts,
            dialog_message_id=dialog_message_id,
            date_unix=date_unix,
            participants=deliveries,
            updates=envelope,
            users=users,
            chats=chats,
        )

    async def EditMessage(self, request, context):  # noqa: N802
        actor = int(request.actor_user_id)
        ubid = int(request.user_message_box_id)
        new_text = (request.new_text or "").strip()
        if not new_text:
            return chat_pb2.EditMessageResponse(meta=err_meta(400, "MESSAGE_EMPTY"))

        live = await self._dao.get_boxes_for_user(actor, [ubid])
        if not live:
            return chat_pb2.EditMessageResponse(meta=err_meta(400, "MESSAGE_ID_INVALID"))
        box = live[0]
        if int(box.from_user_id) != actor:
            return chat_pb2.EditMessageResponse(
                meta=err_meta(403, "MESSAGE_AUTHOR_REQUIRED"),
            )

        dialog_message_id = int(box.dialog_message_id)
        edit_date = int(time.time())

        new_entities_json = (
            request.new_entities_json if request.new_entities_json else None
        )
        await self._dao.update_message_content(
            dialog_message_id,
            new_text,
            new_entities_json,
            edit_date,
        )

        all_copies = await self._dao.get_boxes_by_dialog_message_ids([dialog_message_id])
        if not all_copies:
            return chat_pb2.EditMessageResponse(meta=err_meta(400, "MESSAGE_ID_INVALID"))

        entities_list: list[dict] | None = None
        if new_entities_json:
            try:
                parsed = json.loads(new_entities_json)
                if isinstance(parsed, list):
                    entities_list = parsed
            except Exception:
                entities_list = None

        copy_uids = [int(c.user_id) for c in all_copies]
        pts_by_uid = await self._alloc_pts_for_users(copy_uids)

        actor_pts = 0
        actor_envelope_items: list[common_pb2.UpdateItem] = []
        per_user_pts: list[tuple[int, int, str, dict, int]] = []

        for copy in all_copies:
            uid = int(copy.user_id)
            pts = pts_by_uid[uid]
            is_group = copy.is_group
            peer_id_tl = (
                peer_chat(int(copy.peer_chat_id)) if is_group
                else peer_user(int(copy.peer_user_id))
            )
            msg_tl = build_message_tl(
                message_id=int(copy.user_message_box_id),
                from_user_id=int(copy.from_user_id),
                date=int(copy.date_unix),
                text=new_text,
                peer_id_tl=peer_id_tl,
                out=bool(copy.out),
                entities=entities_list,
                edit_date=edit_date,
            )
            update_tl = build_update_edit_message_tl(message=msg_tl, pts=pts)
            per_user_pts.append((uid, pts, "updateEditMessage", update_tl, 1))
            if uid == actor:
                actor_pts = pts
                actor_envelope_items.append(
                    common_pb2.UpdateItem(
                        raw_update_json=json.dumps(update_tl),
                        update_type="updateEditMessage",
                        pts=pts,
                    ),
                )

        await self._record_pts_updates(per_user_pts, date_unix=edit_date)

        envelope = common_pb2.UpdateEnvelope(
            updates=actor_envelope_items,
            seq=0,
            date=edit_date,
        )

        peer_chat_id = 0
        peer_user_id = 0
        actor_copy = next(
            (c for c in all_copies if int(c.user_id) == actor), None,
        )
        if actor_copy is not None:
            if actor_copy.is_group:
                peer_chat_id = int(actor_copy.peer_chat_id)
            else:
                pid = int(actor_copy.peer_user_id)
                if pid != actor:
                    peer_user_id = pid

        user_ids: set[int] = {actor}
        if peer_user_id:
            user_ids.add(peer_user_id)
        users = await self._get_profiles_batch(actor, user_ids)
        chats = await self._embed_chat(peer_chat_id)

        return chat_pb2.EditMessageResponse(
            meta=ok_meta(),
            dialog_message_id=dialog_message_id,
            actor_user_message_box_id=ubid,
            edit_date=edit_date,
            updates=envelope,
            users=users,
            chats=chats,
        )

    async def DeleteMessages(self, request, context):  # noqa: N802
        actor = int(request.actor_user_id)
        ids = [int(i) for i in request.user_message_box_ids]
        if not ids:
            current_pts = await self._current_pts(actor)
            return chat_pb2.DeleteMessagesResponse(
                meta=ok_meta(), pts=current_pts, pts_count=0, deleted_ids=[],
            )

        actor_boxes = await self._dao.get_boxes_for_user(actor, ids)
        if request.revoke:
            for b in actor_boxes:
                if int(b.from_user_id) != actor:
                    return chat_pb2.DeleteMessagesResponse(
                        meta=err_meta(403, "MESSAGE_DELETE_FORBIDDEN"),
                    )

        if not actor_boxes:
            current_pts = await self._current_pts(actor)
            return chat_pb2.DeleteMessagesResponse(
                meta=ok_meta(), pts=current_pts, pts_count=0, deleted_ids=[],
            )

        if not request.revoke:
            return await self._delete_actor_only(actor, actor_boxes)
        return await self._delete_revoke(actor, actor_boxes)

    async def _delete_actor_only(
        self, actor: int, actor_boxes: list[MessageBoxRow],
    ) -> chat_pb2.DeleteMessagesResponse:
        ubids = [int(b.user_message_box_id) for b in actor_boxes]
        deleted_ids = await self._dao.mark_deleted(actor, ubids)
        if not deleted_ids:
            current_pts = await self._current_pts(actor)
            return chat_pb2.DeleteMessagesResponse(
                meta=ok_meta(), pts=current_pts, pts_count=0, deleted_ids=[],
            )

        pts_by_uid = await self._alloc_pts_for_users([actor])
        actor_pts = pts_by_uid[actor]
        update_tl = build_update_delete_messages_tl(
            message_ids=deleted_ids, pts=actor_pts, pts_count=len(deleted_ids),
        )
        await self._record_pts_updates(
            [(actor, actor_pts, "updateDeleteMessages", update_tl, len(deleted_ids))],
        )

        envelope = common_pb2.UpdateEnvelope(
            updates=[
                common_pb2.UpdateItem(
                    raw_update_json=json.dumps(update_tl),
                    update_type="updateDeleteMessages",
                    pts=actor_pts,
                ),
            ],
            seq=0,
            date=int(time.time()),
        )
        return chat_pb2.DeleteMessagesResponse(
            meta=ok_meta(),
            pts=actor_pts,
            pts_count=len(deleted_ids),
            deleted_ids=deleted_ids,
            updates=envelope,
        )

    async def _delete_revoke(
        self, actor: int, actor_boxes: list[MessageBoxRow],
    ) -> chat_pb2.DeleteMessagesResponse:
        dialog_message_ids = list({int(b.dialog_message_id) for b in actor_boxes})
        all_copies = await self._dao.get_boxes_by_dialog_message_ids(dialog_message_ids)

        by_user: dict[int, list[int]] = {}
        for c in all_copies:
            by_user.setdefault(int(c.user_id), []).append(int(c.user_message_box_id))

        await self._dao.mark_deleted_bulk(
            [(uid, ubid) for uid, ubids in by_user.items() for ubid in ubids],
        )

        affected_uids = list(by_user.keys())
        pts_by_uid = await self._alloc_pts_for_users(affected_uids)

        actor_pts = 0
        actor_envelope_items: list[common_pb2.UpdateItem] = []
        items: list[tuple[int, int, str, dict, int]] = []
        now = int(time.time())
        for uid, ubids in by_user.items():
            pts = pts_by_uid[uid]
            update_tl = build_update_delete_messages_tl(
                message_ids=ubids, pts=pts, pts_count=len(ubids),
            )
            items.append(
                (uid, pts, "updateDeleteMessages", update_tl, len(ubids)),
            )
            if uid == actor:
                actor_pts = pts
                actor_envelope_items.append(
                    common_pb2.UpdateItem(
                        raw_update_json=json.dumps(update_tl),
                        update_type="updateDeleteMessages",
                        pts=pts,
                    ),
                )

        await self._record_pts_updates(items, date_unix=now)

        envelope = common_pb2.UpdateEnvelope(
            updates=actor_envelope_items, seq=0, date=now,
        )
        actor_deleted = by_user.get(actor, [])
        return chat_pb2.DeleteMessagesResponse(
            meta=ok_meta(),
            pts=actor_pts,
            pts_count=len(actor_deleted),
            deleted_ids=actor_deleted,
            updates=envelope,
        )

    async def ListMessages(self, request, context):  # noqa: N802
        actor = int(request.actor_user_id)

        if request.HasField("peer"):
            thread_id = await self._resolve_thread_from_peer(request.peer)
        else:
            thread_id = int(request.dialog_id)

        if thread_id <= 0 or actor <= 0:
            return chat_pb2.ListMessagesResponse(
                meta=ok_meta(), messages=[], total_count=0,
            )

        limit = min(max(int(request.limit), 1), MAX_HISTORY_LIMIT)
        offset_id = int(request.offset_id) if request.offset_id else 0
        # Some clients send offset_id=1 to mean "from the beginning" — treat
        # any ≤ 1 as no upper bound so the first-load query returns data.
        if offset_id == 1:
            offset_id = 0
        min_id = int(request.min_id) if request.min_id else 0
        max_id = int(request.max_id) if request.max_id else 0
        add_offset = int(request.add_offset) if request.add_offset else 0

        total = await self._dao.count_history(
            actor, thread_id,
            offset_id=offset_id, min_id=min_id, max_id=max_id,
        )
        rows = await self._dao.get_history(
            actor, thread_id, limit,
            offset_id=offset_id, min_id=min_id, max_id=max_id,
            add_offset=add_offset,
        )
        rows = list(reversed(rows))
        messages = [
            chat_pb2.Message(
                message_id=r.user_message_box_id,
                from_user_id=r.from_user_id,
                text=r.text,
                date=r.date_unix,
                out=r.out,
                dialog_message_id=r.dialog_message_id,
            )
            for r in rows
        ]

        sender_ids = {int(r.from_user_id) for r in rows if r.from_user_id}
        sender_ids.discard(0)
        users = await self._get_profiles_batch(actor, sender_ids)

        chats: list[common_pb2.MinimalChat] = []
        actor_state = await self._dao.get_dialog_state(actor, thread_id)
        if actor_state is not None and actor_state.is_group:
            chats = await self._embed_chat(int(actor_state.peer_chat_id))

        return chat_pb2.ListMessagesResponse(
            meta=ok_meta(),
            messages=messages,
            total_count=int(total),
            users=users,
            chats=chats,
        )

    async def ReadHistory(self, request, context):  # noqa: N802
        actor = int(request.actor_user_id)

        if request.HasField("peer"):
            thread_id = await self._resolve_thread_from_peer(request.peer)
        else:
            thread_id = int(request.dialog_id)

        if actor <= 0 or thread_id <= 0:
            return chat_pb2.ReadHistoryResponse(meta=err_meta(400, "PEER_ID_INVALID"))

        actor_state = await self._dao.get_dialog_state(actor, thread_id)
        if actor_state is None:
            return chat_pb2.ReadHistoryResponse(meta=err_meta(400, "PEER_ID_INVALID"))

        is_group = actor_state.is_group
        actor_peer_id = int(actor_state.peer_id)
        read_inbox_max_id = int(actor_state.read_inbox_max_id)

        update_peer = peer_chat(actor_peer_id) if is_group else peer_user(actor_peer_id)

        requested_max_id = int(request.max_id) if request.max_id else 0
        effective_max_id = (
            requested_max_id
            if requested_max_id > 0
            else int(actor_state.top_user_message_box_id)
        )

        if effective_max_id <= 0 or read_inbox_max_id >= effective_max_id:
            current_pts = await self._current_pts(actor)
            return chat_pb2.ReadHistoryResponse(
                meta=ok_meta(), pts=current_pts, pts_count=0, receipts=[],
            )

        target_ubid = await self._dao.max_inbox_ubid_in_range(
            actor, thread_id, effective_max_id,
        )
        if target_ubid <= 0:
            current_pts = await self._current_pts(actor)
            return chat_pb2.ReadHistoryResponse(
                meta=ok_meta(), pts=current_pts, pts_count=0, receipts=[],
            )

        receipts = await self._dao.peer_outbox_for_inbox(
            actor, thread_id, target_ubid,
        )

        await self._dao.mark_inbox_read(actor, thread_id, target_ubid)
        await self._dao.update_read_inbox(actor, thread_id, target_ubid)
        await self._dao.reset_unread_count_up_to(actor, thread_id, target_ubid)

        # Allocate PTS for actor + every sender in one batch RPC.
        sender_ids = [int(r.sender_user_id) for r in receipts]
        all_uids = [actor, *sender_ids]
        pts_by_uid = await self._alloc_pts_for_users(all_uids)
        actor_pts = pts_by_uid[actor]

        still_unread = await self._dao.unread_count_for_owner(actor, thread_id)

        items: list[tuple[int, int, str, dict, int]] = [
            (
                actor, actor_pts, "updateReadHistoryInbox",
                build_update_read_history_inbox(
                    peer=update_peer,
                    max_id=target_ubid,
                    still_unread=still_unread,
                    pts=actor_pts,
                ),
                1,
            ),
        ]

        receipts_pb: list[chat_pb2.ReadOutboxReceipt] = []
        for rcp in receipts:
            await self._dao.update_read_outbox(
                rcp.sender_user_id, rcp.sender_thread_id, rcp.max_outbox_id,
            )
            sender_pts = pts_by_uid[int(rcp.sender_user_id)]
            sender_peer = (
                peer_chat(actor_peer_id) if is_group else peer_user(actor)
            )
            items.append(
                (
                    rcp.sender_user_id, sender_pts, "updateReadHistoryOutbox",
                    build_update_read_history_outbox(
                        peer=sender_peer,
                        max_id=rcp.max_outbox_id,
                        pts=sender_pts,
                    ),
                    1,
                ),
            )
            receipts_pb.append(
                chat_pb2.ReadOutboxReceipt(
                    sender_user_id=rcp.sender_user_id,
                    sender_dialog_id=rcp.sender_thread_id,
                    max_outbox_id=rcp.max_outbox_id,
                    pts=sender_pts,
                ),
            )

        await self._record_pts_updates(items)

        return chat_pb2.ReadHistoryResponse(
            meta=ok_meta(),
            pts=actor_pts,
            pts_count=1,
            receipts=receipts_pb,
        )
