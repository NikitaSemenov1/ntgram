from __future__ import annotations

from ntgram.errors import RpcFailure
from ntgram.gateway.grpc_clients._meta import int64_from_tl_long
from ntgram.gateway.handlers.context import RouterContext
from ntgram.gateway.handlers.grpc._common import (
    actor_user_id,
    run_grpc_route,
)
from ntgram.gateway.route_outcome import RouteOutcome
from ntgram.gateway.tl_builders.history_peer import (
    decode_input_peer_tl,
    peer_tl_for_history,
)
from ntgram.gateway.tl_builders.messages import (
    build_send_message_updates_tl,
    messages_messages_or_slice_tl,
)
from ntgram.gateway.tl_builders.users import public_user_tl_from_minimal
from ntgram.gateway.tl_messages import build_chat_minimal_tl, build_peer_user_tl
from ntgram.tl.models import TlRequest, TlResponse


async def handle_messages_send_message(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    """messages.sendMessage — one gRPC call, pure proto->TL mapping."""

    async def invoke(clients, req, sess):
        actor = actor_user_id(req, sess, required=True)
        raw_peer = req.payload.get("peer")

        if raw_peer is not None and isinstance(raw_peer, dict):
            view = peer_tl_for_history(actor_user_id=actor, peer=raw_peer)
            proto_peer = view.proto_peer
            peer_tl = view.peer_tl
        else:
            proto_peer = None
            peer_tl = build_peer_user_tl(actor)

        text = req.payload.get("message")
        if not isinstance(text, str):
            text = req.payload.get("text", "")
        if not isinstance(text, str):
            text = ""
        random_id = int64_from_tl_long(req.payload.get("random_id", 0) or 0)

        result = await clients.chat.send_message(
            actor_user_id=actor,
            dialog_id=int(req.payload.get("dialog_id", 0) or 0),
            text=text,
            random_id=random_id,
            peer=proto_peer,
        )

        users_tl = [public_user_tl_from_minimal(u) for u in result.users]
        chats_tl = [
            build_chat_minimal_tl(
                chat_id=c.chat_id,
                title=c.title,
                participants_count=c.participants_count,
            )
            for c in result.chats
        ]

        if result.updates is not None and result.updates.updates:
            tl_payload = build_send_message_updates_tl(
                result.updates, users_tl, chats_tl,
            )
        else:
            tl_payload = build_send_message_updates_tl_legacy(
                actor_user_message_box_id=result.actor_user_message_box_id,
                actor_user_id=actor,
                pts=result.pts,
                date_unix=result.date_unix,
                text=text,
                random_id=random_id,
                peer_id_tl=peer_tl,
                users=users_tl,
                chats=chats_tl,
            )
        return RouteOutcome.tl_only(tl_payload)

    return await run_grpc_route(ctx, request, invoke=invoke)


async def handle_messages_delete_messages(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    """messages.deleteMessages — forward id/revoke to the service."""

    async def invoke(clients, req, sess):
        actor = actor_user_id(req, sess, required=True)
        raw_ids = req.payload.get("id") or []
        if isinstance(raw_ids, list):
            ids = [int(i) for i in raw_ids if isinstance(i, (int, float))]
        else:
            ids = []
        revoke = bool(req.payload.get("revoke", False))

        result = await clients.chat.delete_messages(
            actor_user_id=actor,
            user_message_box_ids=ids,
            revoke=revoke,
        )
        return RouteOutcome.tl_only(
            {
                "constructor": "messages.affectedMessages",
                "pts": result.pts,
                "pts_count": result.pts_count,
            },
        )

    return await run_grpc_route(ctx, request, invoke=invoke)


async def handle_messages_edit_message(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    """messages.editMessage — text edit with per-participant fanout."""

    async def invoke(clients, req, sess):
        actor = actor_user_id(req, sess, required=True)
        ubid = int(req.payload.get("id", 0) or 0)
        text = req.payload.get("message")
        if not isinstance(text, str):
            text = ""

        entities = req.payload.get("entities")
        entities_json = ""
        if isinstance(entities, list) and entities:
            import json as _json
            entities_json = _json.dumps(entities)

        result = await clients.chat.edit_message(
            actor_user_id=actor,
            user_message_box_id=ubid,
            new_text=text,
            new_entities_json=entities_json,
        )

        users_tl = [public_user_tl_from_minimal(u) for u in result.users]
        chats_tl = [
            build_chat_minimal_tl(
                chat_id=c.chat_id,
                title=c.title,
                participants_count=c.participants_count,
                version=c.version,
                date=c.date_unix,
                creator=(int(actor) == int(c.creator_user_id)),
            )
            for c in result.chats
        ]
        if result.updates is not None and result.updates.updates:
            tl_payload = build_send_message_updates_tl(
                result.updates, users_tl, chats_tl,
            )
        else:
            tl_payload = {
                "constructor": "updates",
                "updates": [],
                "users": users_tl,
                "chats": chats_tl,
                "date": int(result.edit_date),
                "seq": 0,
            }
        return RouteOutcome.tl_only(tl_payload)

    return await run_grpc_route(ctx, request, invoke=invoke)


async def handle_messages_get_history(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    """messages.getHistory: peer-decoded, service embeds users/chats."""

    async def invoke(clients, req, sess):
        actor = actor_user_id(req, sess, required=True)
        raw_peer = req.payload.get("peer")

        if raw_peer is not None and isinstance(raw_peer, dict):
            view = peer_tl_for_history(actor_user_id=actor, peer=raw_peer)
            proto_peer = view.proto_peer
            peer_tl = view.peer_tl
        else:
            proto_peer = None
            peer_tl = build_peer_user_tl(actor)

        def _int_payload(key: str, default: int = 0) -> int:
            try:
                return int(req.payload.get(key, default))
            except (TypeError, ValueError):
                return default

        try:
            lim = int(req.payload.get("limit", 20))
        except (TypeError, ValueError):
            lim = 20
        oid = _int_payload("offset_id", 0)
        min_id = _int_payload("min_id", 0)
        max_id = _int_payload("max_id", 0)
        add_off = _int_payload("add_offset", 0)
        hsh = _int_payload("hash", 0)

        result = await clients.chat.list_messages(
            actor_user_id=actor,
            dialog_id=int(req.payload.get("dialog_id", 0) or 0),
            limit=lim,
            offset_id=oid,
            offset_date=int(req.payload.get("offset_date", 0) or 0),
            add_offset=add_off,
            max_id=max_id,
            min_id=min_id,
            hash_=hsh,
            peer=proto_peer,
        )

        # Service embeds users/chats; presence ships via the Subscribe stream.
        users = [public_user_tl_from_minimal(u) for u in result.users]
        chats = [
            build_chat_minimal_tl(
                chat_id=c.chat_id,
                title=c.title,
                participants_count=c.participants_count,
            )
            for c in result.chats
        ]

        tl_payload = messages_messages_or_slice_tl(
            rows=result.messages,
            peer_id_tl=peer_tl,
            chats=chats,
            users=users,
            requested_limit=lim,
            total_count=result.total_count,
        )
        return RouteOutcome.tl_only(tl_payload)

    return await run_grpc_route(ctx, request, invoke=invoke)


async def handle_messages_read_history(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    async def invoke(clients, req, sess):
        actor = actor_user_id(req, sess, required=True)
        raw_peer = req.payload.get("peer")

        if raw_peer is not None and isinstance(raw_peer, dict):
            proto_peer = decode_input_peer_tl(actor, raw_peer)
        else:
            proto_peer = None

        result = await clients.chat.read_history(
            actor_user_id=actor,
            dialog_id=int(req.payload.get("dialog_id", 0) or 0),
            max_id=int(req.payload.get("max_id", 0) or 0),
            peer=proto_peer,
        )
        tl_payload = {
            "constructor": "messages.affectedMessages",
            "pts": result.pts,
            "pts_count": result.pts_count,
        }
        # Push updates flow via UpdatesService.Subscribe stream (t16).
        return RouteOutcome.tl_only(tl_payload)

    return await run_grpc_route(ctx, request, invoke=invoke)


def build_send_message_updates_tl_legacy(
    *,
    actor_user_message_box_id: int,
    actor_user_id: int,
    pts: int,
    date_unix: int,
    text: str,
    random_id: int,
    peer_id_tl: dict,
    users: list[dict] | None = None,
    chats: list[dict] | None = None,
) -> dict:
    from ntgram.gateway.tl_messages import build_message_tl

    msg_tl = build_message_tl(
        message_id=actor_user_message_box_id,
        from_user_id=actor_user_id,
        date=date_unix,
        text=text,
        peer_id_tl=peer_id_tl,
        out=True,
    )
    return {
        "constructor": "updates",
        "updates": [
            {
                "constructor": "updateMessageID",
                "id": actor_user_message_box_id,
                "random_id": random_id,
            },
            {
                "constructor": "updateNewMessage",
                "message": msg_tl,
                "pts": pts,
                "pts_count": 1,
            },
        ],
        "users": users or [],
        "chats": chats or [],
        "date": date_unix,
        "seq": 0,
    }


MESSAGE_ROUTE_HANDLERS = {
    "messages.sendMessage": handle_messages_send_message,
    "messages.editMessage": handle_messages_edit_message,
    "messages.deleteMessages": handle_messages_delete_messages,
    "messages.getHistory": handle_messages_get_history,
    "messages.readHistory": handle_messages_read_history,
}
