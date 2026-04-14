from __future__ import annotations

import json
import time

import grpc

from ntgram.errors import RpcFailure
from ntgram.gateway.router_contracts import ServiceName
from ntgram.gen import (
    account_pb2,
    account_pb2_grpc,
    chat_pb2,
    chat_pb2_grpc,
    message_pb2,
    message_pb2_grpc,
    profile_pb2,
    profile_pb2_grpc,
    status_pb2,
    status_pb2_grpc,
    updates_pb2,
    updates_pb2_grpc,
)
from ntgram.tl.models import TlRequest


class GrpcBridge:
    def __init__(
        self,
        account_addr: str,
        chat_addr: str,
        message_addr: str,
        profile_addr: str,
        status_addr: str,
        updates_addr: str,
    ) -> None:
        self._account_channel = grpc.aio.insecure_channel(account_addr)
        self._chat_channel = grpc.aio.insecure_channel(chat_addr)
        self._message_channel = grpc.aio.insecure_channel(message_addr)
        self._profile_channel = grpc.aio.insecure_channel(profile_addr)
        self._status_channel = grpc.aio.insecure_channel(status_addr)
        self._updates_channel = grpc.aio.insecure_channel(updates_addr)
        self.account = account_pb2_grpc.AccountServiceStub(self._account_channel)
        self.chat = chat_pb2_grpc.ChatServiceStub(self._chat_channel)
        self.message = message_pb2_grpc.MessageServiceStub(self._message_channel)
        self.profile = profile_pb2_grpc.ProfileServiceStub(self._profile_channel)
        self.status = status_pb2_grpc.StatusServiceStub(self._status_channel)
        self.updates = updates_pb2_grpc.UpdatesServiceStub(self._updates_channel)

    async def close(self) -> None:
        await self._account_channel.close()
        await self._chat_channel.close()
        await self._message_channel.close()
        await self._profile_channel.close()
        await self._status_channel.close()
        await self._updates_channel.close()

    async def resolve_dialog_members(
        self, dialog_id: int,
    ) -> list[int]:
        """Resolve all user_ids for a dialog via chat service."""
        try:
            resp = await self.chat.GetFullChat(
                chat_pb2.GetFullChatRequest(chat_id=dialog_id),
            )
            if resp.meta.ok:
                return list(resp.member_user_ids)
        except Exception:
            pass
        return []

    async def get_updates_state(self, user_id: int) -> dict:
        """Get current PTS/QTS/SEQ/date for a user via updates gRPC service."""
        resp = await self.updates.GetState(
            updates_pb2.GetStateRequest(user_id=user_id),
        )
        self._assert_meta_ok(resp.meta)
        return {
            "pts": resp.pts,
            "qts": resp.qts,
            "seq": resp.seq,
            "date": resp.date or int(time.time()),
        }

    async def get_updates_difference(
        self, user_id: int, pts: int,
    ) -> dict:
        """Get PTS updates since `pts` for a user via updates gRPC service."""
        resp = await self.updates.GetDifference(
            updates_pb2.GetDifferenceRequest(user_id=user_id, pts=pts),
        )
        self._assert_meta_ok(resp.meta)
        if not resp.updates:
            return {
                "constructor": "updates.differenceEmpty",
                "date": resp.state.date if resp.state else int(time.time()),
                "seq": resp.state.seq if resp.state else 0,
            }
        other_updates = []
        for u in resp.updates:
            try:
                other_updates.append(json.loads(u.update_data))
            except (json.JSONDecodeError, TypeError):
                pass
        state = resp.state
        return {
            "constructor": "updates.difference",
            "other_updates": other_updates,
            "state": {
                "pts": state.pts if state else 0,
                "qts": state.qts if state else 0,
                "seq": state.seq if state else 0,
                "date": state.date if state else int(time.time()),
            },
        }

    async def call(self, service: ServiceName, method: str, request: TlRequest) -> dict:
        payload = request.payload
        if service == ServiceName.ACCOUNT:
            return await self._call_account(method, payload)
        if service == ServiceName.CHAT:
            return await self._call_chat(method, payload)
        if service == ServiceName.MESSAGE:
            return await self._call_message(method, payload)
        if service == ServiceName.PROFILE:
            return await self._call_profile(method, payload)
        if service == ServiceName.STATUS:
            return await self._call_status(method, payload)
        raise RpcFailure(400, "RPC_METHOD_NOT_SUPPORTED")

    @staticmethod
    def _assert_meta_ok(meta: object) -> None:
        if getattr(meta, "ok", False):
            return
        err = getattr(meta, "error", None)
        code = getattr(err, "code", 500)
        msg = getattr(err, "message", "INTERNAL_SERVER_ERROR")
        raise RpcFailure(code, msg)

    # --- Account ---

    async def _call_account(self, method: str, payload: dict) -> dict:
        if method == "SendCode":
            resp = await self.account.SendCode(account_pb2.SendCodeRequest(phone=payload["phone"]))
            self._assert_meta_ok(resp.meta)
            return {"phone_code_hash": resp.phone_code_hash}
        if method == "SignIn":
            resp = await self.account.SignIn(
                account_pb2.SignInRequest(
                    phone=payload["phone"],
                    phone_code_hash=payload["phone_code_hash"],
                    phone_code=payload["phone_code"],
                )
            )
            self._assert_meta_ok(resp.meta)
            return {"user_id": resp.user_id, "is_new_user": resp.is_new_user}
        if method == "SignUp":
            resp = await self.account.SignUp(
                account_pb2.SignUpRequest(
                    phone=payload["phone"],
                    phone_code_hash=payload["phone_code_hash"],
                    first_name=payload["first_name"],
                    last_name=payload.get("last_name", ""),
                )
            )
            self._assert_meta_ok(resp.meta)
            return {"user_id": resp.user_id}
        if method == "LogOut":
            resp = await self.account.LogOut(
                account_pb2.LogOutRequest(
                    user_id=payload.get("user_id", 0),
                    auth_key_id=payload.get("auth_key_id", 0),
                )
            )
            self._assert_meta_ok(resp.meta)
            return {"ok": True}
        raise RpcFailure(400, "RPC_METHOD_NOT_SUPPORTED")

    # --- Chat ---

    async def _call_chat(self, method: str, payload: dict) -> dict:
        if method == "CreateGroupChat":
            resp = await self.chat.CreateGroupChat(
                chat_pb2.CreateGroupChatRequest(
                    actor_user_id=payload["actor_user_id"],
                    title=payload["title"],
                    member_user_ids=payload.get("member_user_ids", []),
                )
            )
            self._assert_meta_ok(resp.meta)
            return {"chat_id": resp.chat_id}
        if method == "CreatePrivateDialog":
            resp = await self.chat.CreatePrivateDialog(
                chat_pb2.CreatePrivateDialogRequest(
                    actor_user_id=payload["actor_user_id"],
                    peer_user_id=payload["peer_user_id"],
                )
            )
            self._assert_meta_ok(resp.meta)
            return {"dialog_id": resp.dialog_id}
        if method == "AddChatUser":
            resp = await self.chat.AddChatUser(
                chat_pb2.AddChatUserRequest(
                    actor_user_id=payload["actor_user_id"],
                    chat_id=payload["chat_id"],
                    user_id=payload["user_id"],
                )
            )
            self._assert_meta_ok(resp.meta)
            return {"ok": True}
        if method == "DeleteChatUser":
            resp = await self.chat.DeleteChatUser(
                chat_pb2.DeleteChatUserRequest(
                    actor_user_id=payload["actor_user_id"],
                    chat_id=payload["chat_id"],
                    user_id=payload["user_id"],
                )
            )
            self._assert_meta_ok(resp.meta)
            return {"ok": True}
        if method == "EditChatTitle":
            resp = await self.chat.EditChatTitle(
                chat_pb2.EditChatTitleRequest(
                    actor_user_id=payload["actor_user_id"],
                    chat_id=payload["chat_id"],
                    title=payload["title"],
                )
            )
            self._assert_meta_ok(resp.meta)
            return {"ok": True}
        if method == "GetFullChat":
            resp = await self.chat.GetFullChat(
                chat_pb2.GetFullChatRequest(chat_id=payload["chat_id"])
            )
            self._assert_meta_ok(resp.meta)
            return {
                "chat_id": resp.chat_id,
                "title": resp.title,
                "creator_id": resp.creator_id,
                "member_user_ids": list(resp.member_user_ids),
            }
        if method == "ListDialogs":
            resp = await self.chat.ListDialogs(
                chat_pb2.ListDialogsRequest(actor_user_id=payload["actor_user_id"])
            )
            self._assert_meta_ok(resp.meta)
            return {
                "dialogs": [
                    {"dialog_id": d.dialog_id, "peer_id": d.peer_id, "is_group": d.is_group}
                    for d in resp.dialogs
                ]
            }
        raise RpcFailure(400, "RPC_METHOD_NOT_SUPPORTED")

    # --- Message ---

    async def _call_message(self, method: str, payload: dict) -> dict:
        if method == "SendMessage":
            resp = await self.message.SendMessage(
                message_pb2.SendMessageRequest(
                    actor_user_id=payload["actor_user_id"],
                    dialog_id=payload["dialog_id"],
                    text=payload["text"],
                    random_id=payload.get("random_id", 0),
                )
            )
            self._assert_meta_ok(resp.meta)
            return {"message_id": resp.message_id, "pts": resp.pts}
        if method == "DeleteMessages":
            resp = await self.message.DeleteMessages(
                message_pb2.DeleteMessagesRequest(
                    actor_user_id=payload["actor_user_id"],
                    dialog_id=payload["dialog_id"],
                    message_ids=payload.get("message_ids", []),
                    revoke=payload.get("revoke", False),
                )
            )
            self._assert_meta_ok(resp.meta)
            return {"deleted_ids": list(resp.deleted_ids), "pts": resp.pts}
        if method == "ListMessages":
            resp = await self.message.ListMessages(
                message_pb2.ListMessagesRequest(
                    actor_user_id=payload["actor_user_id"],
                    dialog_id=payload["dialog_id"],
                    limit=payload.get("limit", 20),
                )
            )
            self._assert_meta_ok(resp.meta)
            return {
                "messages": [
                    {
                        "message_id": m.message_id,
                        "from_user_id": m.from_user_id,
                        "text": m.text,
                        "date": m.date,
                    }
                    for m in resp.messages
                ]
            }
        if method == "ReadHistory":
            resp = await self.message.ReadHistory(
                message_pb2.ReadHistoryRequest(
                    actor_user_id=payload["actor_user_id"],
                    dialog_id=payload["dialog_id"],
                    max_id=payload.get("max_id", 0),
                )
            )
            self._assert_meta_ok(resp.meta)
            return {"pts": resp.pts}
        raise RpcFailure(400, "RPC_METHOD_NOT_SUPPORTED")

    # --- Profile ---

    async def _call_profile(self, method: str, payload: dict) -> dict:
        if method == "GetProfile":
            resp = await self.profile.GetProfile(
                profile_pb2.GetProfileRequest(
                    actor_user_id=payload["actor_user_id"],
                    target_user_id=payload["target_user_id"],
                )
            )
            self._assert_meta_ok(resp.meta)
            p = resp.profile
            return {
                "user_id": p.user_id, "first_name": p.first_name,
                "last_name": p.last_name, "bio": p.bio,
            }
        if method == "UpdateProfile":
            resp = await self.profile.UpdateProfile(
                profile_pb2.UpdateProfileRequest(
                    actor_user_id=payload["actor_user_id"],
                    first_name=payload["first_name"],
                    last_name=payload.get("last_name", ""),
                    bio=payload.get("bio", ""),
                )
            )
            self._assert_meta_ok(resp.meta)
            p = resp.profile
            return {
                "user_id": p.user_id, "first_name": p.first_name,
                "last_name": p.last_name, "bio": p.bio,
            }
        raise RpcFailure(400, "RPC_METHOD_NOT_SUPPORTED")

    # --- Status ---

    async def _call_status(self, method: str, payload: dict) -> dict:
        if method == "SetOnline":
            resp = await self.status.SetOnline(
                status_pb2.SetOnlineRequest(
                    user_id=payload["user_id"],
                    auth_key_id=payload["auth_key_id"],
                    session_id=payload["session_id"],
                )
            )
            self._assert_meta_ok(resp.meta)
            return {"ok": True, "became_online": resp.became_online}
        if method == "SetOffline":
            resp = await self.status.SetOffline(
                status_pb2.SetOfflineRequest(
                    user_id=payload["user_id"],
                    auth_key_id=payload["auth_key_id"],
                    session_id=payload["session_id"],
                )
            )
            self._assert_meta_ok(resp.meta)
            return {"ok": True, "became_offline": resp.became_offline}
        if method == "GetPresence":
            resp = await self.status.GetPresence(
                status_pb2.GetPresenceRequest(user_id=payload["user_id"])
            )
            self._assert_meta_ok(resp.meta)
            return {"online": resp.online, "last_seen_unix": resp.last_seen_unix}
        raise RpcFailure(400, "RPC_METHOD_NOT_SUPPORTED")
