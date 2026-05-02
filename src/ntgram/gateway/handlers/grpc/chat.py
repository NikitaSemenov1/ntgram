from __future__ import annotations

from ntgram.gateway.grpc_clients._meta import int64_from_tl_long
from ntgram.gateway.handlers.context import RouterContext
from ntgram.gateway.handlers.grpc._common import (
    actor_user_id,
    actor_user_id_from_session,
    run_grpc_route,
)
from ntgram.gateway.route_outcome import RouteOutcome
from ntgram.gateway.tl_builders.chats import (
    build_chat_full_tl,
    build_chat_tl,
)
from ntgram.gateway.tl_builders.dialogs import build_dialogs_view
from ntgram.gateway.tl_builders.messages import build_send_message_updates_tl
from ntgram.gateway.tl_builders.users import public_user_tl_from_minimal
from ntgram.gateway.tl_messages import build_chat_minimal_tl
from ntgram.tl.models import TlRequest, TlResponse


def _users_tl(users) -> list[dict]:
    return [public_user_tl_from_minimal(u) for u in users]


def _chats_tl(chats, *, actor_user_id: int = 0) -> list[dict]:
    return [build_chat_tl(c, actor_user_id=actor_user_id) for c in chats]


async def handle_messages_create_chat(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    """messages.createChat -> messages.invitedUsers { updates, missing_invitees }."""

    async def invoke(clients, req, sess):
        actor = actor_user_id(req, sess, required=True)
        member_ids = req.payload.get("users") or req.payload.get("member_user_ids") or []
        # TL users items are InputUser dicts on the wire — extract user_id.
        normalised: list[int] = []
        for u in member_ids:
            if isinstance(u, dict):
                uid = u.get("user_id")
                if uid is not None:
                    normalised.append(int(uid))
            else:
                normalised.append(int(u))
        result = await clients.chat.create_group_chat(
            actor_user_id=actor,
            title=req.payload["title"],
            member_user_ids=normalised,
        )
        if result.updates is None:
            raise RuntimeError(
                "ChatService.CreateGroupChat returned empty UpdateEnvelope — "
                "service must fill the actor envelope.",
            )
        users_tl = _users_tl(result.users)
        chats_tl = _chats_tl(result.chats, actor_user_id=actor)
        updates_tl = build_send_message_updates_tl(result.updates, users_tl, chats_tl)
        return RouteOutcome.tl_only(
            {
                "constructor": "messages.invitedUsers",
                "updates": updates_tl,
                "missing_invitees": [],
            },
        )

    return await run_grpc_route(ctx, request, invoke=invoke)


async def handle_messages_start_private_chat(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    async def invoke(clients, req, sess):
        actor = actor_user_id(req, sess, required=True)
        result = await clients.chat.create_private_dialog(
            actor_user_id=actor,
            peer_user_id=req.payload["peer_user_id"],
        )
        return RouteOutcome.tl_only({"dialog_id": result.dialog_id})

    return await run_grpc_route(ctx, request, invoke=invoke)


async def handle_messages_add_chat_user(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    """messages.addChatUser -> TL Updates."""

    async def invoke(clients, req, sess):
        actor = actor_user_id(req, sess, required=True)
        raw_user = req.payload.get("user_id")
        if isinstance(raw_user, dict):
            new_user = int(raw_user.get("user_id") or 0)
        else:
            new_user = int64_from_tl_long(raw_user or 0)
        result = await clients.chat.add_chat_user(
            actor_user_id=actor,
            chat_id=int(req.payload["chat_id"]),
            user_id=new_user,
        )
        if result.updates is None:
            raise RuntimeError(
                "ChatService.AddChatUser returned empty UpdateEnvelope.",
            )
        users_tl = _users_tl(result.users)
        chats_tl = _chats_tl(result.chats, actor_user_id=actor)
        return RouteOutcome.tl_only(
            build_send_message_updates_tl(result.updates, users_tl, chats_tl),
        )

    return await run_grpc_route(ctx, request, invoke=invoke)


async def handle_messages_edit_chat_title(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    """messages.editChatTitle -> TL Updates."""

    async def invoke(clients, req, sess):
        actor = actor_user_id(req, sess, required=True)
        result = await clients.chat.edit_chat_title(
            actor_user_id=actor,
            chat_id=int(req.payload["chat_id"]),
            title=req.payload["title"],
        )
        if result.updates is None:
            raise RuntimeError(
                "ChatService.EditChatTitle returned empty UpdateEnvelope.",
            )
        users_tl = _users_tl(result.users)
        chats_tl = _chats_tl(result.chats, actor_user_id=actor)
        return RouteOutcome.tl_only(
            build_send_message_updates_tl(result.updates, users_tl, chats_tl),
        )

    return await run_grpc_route(ctx, request, invoke=invoke)


async def handle_messages_get_full_chat(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    """messages.getFullChat -> TL messages.chatFull."""

    async def invoke(clients, req, sess):
        actor = actor_user_id(req, sess, required=False) or 0
        result = await clients.chat.get_full_chat(int(req.payload["chat_id"]))
        chat_tl = build_chat_minimal_tl(
            chat_id=result.chat_id,
            title=result.title,
            participants_count=int(result.participants_count or 0),
            version=result.version,
            date=result.date_unix,
            creator=(actor and int(actor) == int(result.creator_id)),
        )
        users_tl = _users_tl(result.users)
        chat_full = build_chat_full_tl(
            result, chats_tl=[chat_tl], users_tl=users_tl,
        )
        return RouteOutcome.tl_only(chat_full)

    return await run_grpc_route(ctx, request, invoke=invoke)


async def handle_messages_get_chats(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    """messages.getChats -> TL messages.chats."""

    async def invoke(clients, req, sess):
        actor = actor_user_id(req, sess, required=False) or 0
        raw_ids = req.payload.get("id") or []
        ids: list[int] = []
        for v in raw_ids:
            try:
                ids.append(int(v))
            except (TypeError, ValueError):
                continue
        chats = await clients.chat.get_chats_batch(ids)
        chats_tl = _chats_tl(chats, actor_user_id=actor)
        return RouteOutcome.tl_only(
            {"constructor": "messages.chats", "chats": chats_tl},
        )

    return await run_grpc_route(ctx, request, invoke=invoke)


async def handle_messages_get_dialogs(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    """messages.getDialogs: service embeds users/chats; gateway maps to TL."""

    async def invoke(clients, req, sess):
        actor = actor_user_id_from_session(sess, required=True)
        try:
            limit = int(req.payload.get("limit", 100) or 100)
        except (TypeError, ValueError):
            limit = 100
        limit = max(1, min(limit, 200))
        dialogs = await clients.chat.list_dialogs(
            actor_user_id=actor, limit=limit,
        )
        view = build_dialogs_view(
            actor_user_id=actor, dialogs=dialogs.dialogs,
        )
        users_tl = _users_tl(dialogs.users)
        chats_tl_from_service = _chats_tl(dialogs.chats, actor_user_id=actor)
        total_count = dialogs.total_count
        all_chats = chats_tl_from_service or view.chats_tl
        if total_count > 0:
            return RouteOutcome.tl_only(
                {
                    "constructor": "messages.dialogsSlice",
                    "count": total_count,
                    "dialogs": view.dialogs_tl,
                    "messages": view.messages_tl,
                    "chats": all_chats,
                    "users": users_tl,
                },
            )
        return RouteOutcome.tl_only(
            {
                "constructor": "messages.dialogs",
                "dialogs": view.dialogs_tl,
                "messages": view.messages_tl,
                "chats": all_chats,
                "users": users_tl,
            },
        )

    return await run_grpc_route(ctx, request, invoke=invoke)


CHAT_ROUTE_HANDLERS = {
    "messages.createChat": handle_messages_create_chat,
    "messages.startPrivateChat": handle_messages_start_private_chat,
    "messages.addChatUser": handle_messages_add_chat_user,
    "messages.editChatTitle": handle_messages_edit_chat_title,
    "messages.getFullChat": handle_messages_get_full_chat,
    "messages.getChats": handle_messages_get_chats,
    "messages.getDialogs": handle_messages_get_dialogs,
}
