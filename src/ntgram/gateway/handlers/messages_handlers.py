from __future__ import annotations

from ntgram.errors import RpcFailure
from ntgram.gateway.handlers.context import RouterContext
from ntgram.gateway.history_peer import classify_history_peer
from ntgram.gateway.mtproto.service_semantics import (
    wrap_rpc_error,
    wrap_rpc_result,
)
from ntgram.gateway.tl_builders.dialogs import build_dialogs_view
from ntgram.gateway.tl_builders.users import public_user_tl_from_minimal
from ntgram.gateway.tl_messages import build_chat_minimal_tl
from ntgram.tl.models import TlRequest, TlResponse


async def handle_messages_get_peer_dialogs(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    """Resolve specific peers and return messages.peerDialogs."""
    session = ctx.sessions.get_session(request.auth_key_id)
    actor_user_id = (
        int(session.user_id) if (session and session.user_id) else 0
    )
    if actor_user_id == 0:
        return wrap_rpc_error(
            request.req_msg_id, 401, "AUTH_KEY_UNREGISTERED",
        )

    peers_raw = request.payload.get("peers") or []
    target_peers: set[tuple[bool, int]] = set()
    for item in peers_raw:
        if not isinstance(item, dict):
            continue
        ctor = item.get("_constructor") or item.get("constructor", "")
        if ctor != "inputDialogPeer":
            continue
        peer = item.get("peer")
        if not isinstance(peer, dict):
            continue
        try:
            kind, pid = classify_history_peer(actor_user_id, peer)
        except RpcFailure:
            continue
        if kind == "pm":
            target_peers.add((False, pid))
        elif kind == "group":
            target_peers.add((True, pid))

    try:
        all_dialogs = await ctx.grpc.chat.list_dialogs(
            actor_user_id=actor_user_id, limit=200,
        )
    except RpcFailure as err:
        return wrap_rpc_error(request.req_msg_id, err.code, err.message)

    filtered = (
        tuple(
            d for d in all_dialogs.dialogs
            if (d.is_group, d.peer_id) in target_peers
        )
        if target_peers
        else ()
    )

    view = build_dialogs_view(actor_user_id=actor_user_id, dialogs=filtered)

    users_tl = [public_user_tl_from_minimal(u) for u in all_dialogs.users]
    chats_tl_extra = [
        build_chat_minimal_tl(
            chat_id=c.chat_id,
            title=c.title,
            participants_count=c.participants_count,
        )
        for c in all_dialogs.chats
    ]

    state = await ctx.grpc.updates.get_state(actor_user_id)
    state_tl = {
        "constructor": "updates.state",
        "pts": state.pts,
        "qts": state.qts,
        "seq": state.seq,
        "date": state.date,
        "unread_count": 0,
    }

    return wrap_rpc_result(
        request.req_msg_id,
        {
            "constructor": "messages.peerDialogs",
            "dialogs": view.dialogs_tl,
            "messages": view.messages_tl,
            "chats": chats_tl_extra or view.chats_tl,
            "users": users_tl,
            "state": state_tl,
        },
    )


MESSAGES_HANDLERS = {
    "messages.getPeerDialogs": handle_messages_get_peer_dialogs,
}
