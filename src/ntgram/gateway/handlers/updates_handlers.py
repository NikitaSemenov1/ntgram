from __future__ import annotations

import logging
import time
from typing import Any

from ntgram.gateway.grpc_clients.dtos import (
    PtsUpdateRow,
    UpdatesDifference,
    UpdatesDifferenceEmpty,
    UpdatesDifferenceTooLong,
)
from ntgram.gateway.handlers.context import RouterContext
from ntgram.gateway.mtproto.salt_schedule import plan_future_salts
from ntgram.gateway.mtproto.service_semantics import (
    wrap_rpc_error,
    wrap_rpc_result,
)
from ntgram.tl.models import TlRequest, TlResponse

logger = logging.getLogger(__name__)


# updates.getState


async def handle_get_state(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    from ntgram.errors import RpcFailure

    session = ctx.sessions.get_session(request.auth_key_id)
    user_id = session.user_id if session else None
    if not user_id:
        return wrap_rpc_error(request.req_msg_id, 401, "AUTH_KEY_UNREGISTERED")

    try:
        state = await ctx.grpc.updates.get_state(user_id)
    except RpcFailure as err:
        return wrap_rpc_error(request.req_msg_id, err.code, err.message)
    except Exception:
        logger.exception("getState gRPC error for user=%d", user_id)
        return wrap_rpc_error(request.req_msg_id, 500, "INTERNAL_SERVER_ERROR")

    return wrap_rpc_result(
        request.req_msg_id,
        {
            "constructor": "updates.state",
            "pts": state.pts,
            "qts": state.qts,
            "seq": state.seq,
            "date": state.date,
            "unread_count": 0,
        },
    )


# updates.getDifference — per-row converters (simplified for full TL JSON shape)


def _pts_update_to_message_tl(row: PtsUpdateRow) -> dict[str, Any] | None:
    """Extract the embedded TL Message for an updateNewMessage row."""
    if row.update_type != "updateNewMessage":
        return None
    return row.update_data.get("message") or None  # type: ignore[return-value]


def _pts_update_to_other_update_tl(row: PtsUpdateRow) -> dict[str, Any] | None:
    """Return the full TL Update dict for secondary updates (read/edit/delete)."""
    if row.update_type == "updateNewMessage":
        return None
    # update_data already IS a full TL Update dict (constructor + all fields).
    d = row.update_data
    if d.get("constructor"):
        return d  # type: ignore[return-value]
    return None


def _collect_peer_ids(rows: tuple[PtsUpdateRow, ...]) -> tuple[set[int], set[int]]:
    """Extract (user_ids, chat_ids) from TL Update dicts in a batch of rows."""
    user_ids: set[int] = set()
    chat_ids: set[int] = set()
    for row in rows:
        d = row.update_data
        if row.update_type == "updateNewMessage":
            msg = d.get("message", {})
            from_id = msg.get("from_id", {})
            if from_id.get("user_id"):
                user_ids.add(int(from_id["user_id"]))
            peer = msg.get("peer_id", {})
            if peer.get("constructor") == "peerUser" and peer.get("user_id"):
                user_ids.add(int(peer["user_id"]))
            elif peer.get("constructor") == "peerChat" and peer.get("chat_id"):
                chat_ids.add(int(peer["chat_id"]))
        elif row.update_type in ("updateReadHistoryOutbox", "updateReadHistoryInbox"):
            peer = d.get("peer", {})
            if peer.get("user_id"):
                user_ids.add(int(peer["user_id"]))
    return user_ids, chat_ids


# updates.getDifference


async def handle_get_difference(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    session = ctx.sessions.get_session(request.auth_key_id)
    if session is None:
        return wrap_rpc_error(
            request.req_msg_id, 401, "AUTH_KEY_INVALID",
        )
    user_id = session.user_id
    if not user_id:
        return wrap_rpc_error(
            request.req_msg_id, 401, "AUTH_KEY_UNREGISTERED",
        )
    try:
        pts = int(request.payload.get("pts", 0))
    except (TypeError, ValueError):
        pts = 0
    diff = await ctx.grpc.updates.get_difference(user_id=user_id, pts=pts)

    if isinstance(diff, UpdatesDifferenceTooLong):
        return wrap_rpc_result(
            request.req_msg_id,
            {
                "constructor": "updates.differenceTooLong",
                "pts": diff.pts,
            },
        )

    if isinstance(diff, UpdatesDifferenceEmpty):
        return wrap_rpc_result(
            request.req_msg_id,
            {
                "constructor": "updates.differenceEmpty",
                "date": diff.date,
                "seq": diff.seq,
            },
        )

    assert isinstance(diff, UpdatesDifference)

    new_messages_tl: list[dict[str, Any]] = []
    other_updates_tl: list[dict[str, Any]] = []
    _read_merge: dict[tuple[str, str], int] = {}

    for row in diff.raw_updates:
        if row.update_type == "updateNewMessage":
            msg = _pts_update_to_message_tl(row)
            if msg is not None:
                new_messages_tl.append(msg)
        elif row.update_type in (
            "updateReadHistoryInbox", "updateReadHistoryOutbox",
        ):
            upd = _pts_update_to_other_update_tl(row)
            if upd is None:
                continue
            peer = upd.get("peer", {})
            peer_key = f"{peer.get('constructor')}:{peer.get('user_id', 0)}:{peer.get('chat_id', 0)}"
            merge_key = (row.update_type, peer_key)
            if merge_key in _read_merge:
                idx = _read_merge[merge_key]
                existing = other_updates_tl[idx]
                if int(upd.get("max_id", 0)) > int(existing.get("max_id", 0)):
                    other_updates_tl[idx] = upd
            else:
                _read_merge[merge_key] = len(other_updates_tl)
                other_updates_tl.append(upd)
        else:
            upd = _pts_update_to_other_update_tl(row)
            if upd is not None:
                other_updates_tl.append(upd)

    user_ids, chat_ids = _collect_peer_ids(diff.raw_updates)
    user_ids.discard(user_id)  # never include self in the peer list

    users_tl: list[dict[str, Any]] = []
    chats_tl: list[dict[str, Any]] = []
    if user_ids or chat_ids:
        try:
            from ntgram.gateway.push.peer_enrichment import fetch_peers_tl
            users_tl, chats_tl = await fetch_peers_tl(
                actor_user_id=user_id,
                user_ids=user_ids,
                chat_ids=chat_ids,
                account_client=ctx.grpc.account,
                chat_client=ctx.grpc.chat,
            )
        except Exception:
            logger.debug("getDifference peer enrichment failed, continuing without peers")

    state_tl = {
        "constructor": "updates.state",
        "pts": diff.state.pts,
        "qts": diff.state.qts,
        "seq": diff.state.seq,
        "date": int(time.time()),
        "unread_count": 0,
    }

    if diff.is_slice:
        return wrap_rpc_result(
            request.req_msg_id,
            {
                "constructor": "updates.differenceSlice",
                "new_messages": new_messages_tl,
                "new_encrypted_messages": [],
                "other_updates": other_updates_tl,
                "chats": chats_tl,
                "users": users_tl,
                "intermediate_state": state_tl,
            },
        )

    return wrap_rpc_result(
        request.req_msg_id,
        {
            "constructor": "updates.difference",
            "new_messages": new_messages_tl,
            "new_encrypted_messages": [],
            "other_updates": other_updates_tl,
            "chats": chats_tl,
            "users": users_tl,
            "state": state_tl,
        },
    )


async def handle_get_future_salts(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    """MTProto get_future_salts: return up to num future server salts."""
    raw = request.payload.get("num", 1)
    try:
        num = int(raw)
    except (TypeError, ValueError):
        num = 1

    session = ctx.sessions.get_session(request.auth_key_id)
    if session is None:
        return wrap_rpc_error(
            request.req_msg_id, 401, "AUTH_KEY_INVALID",
        )

    query_msg_id = request.message_id or request.req_msg_id
    now = int(time.time())
    session.rotate_server_salt_if_needed(now)

    plan = plan_future_salts(session, num, now)
    if plan.new_entries:
        ctx.salt_schedule.register_future_salts_for_auth_key(
            request.auth_key_id,
            [
                (e.valid_since, e.valid_until, e.salt)
                for e in plan.new_entries
            ],
        )
    else:
        # Persist any rotation that happened above.
        ctx.salt_schedule.register_future_salts_for_auth_key(
            request.auth_key_id, [],
        )

    return TlResponse(
        req_msg_id=request.req_msg_id,
        result={
            "constructor": "future_salts",
            "req_msg_id": query_msg_id,
            "now": now,
            "salts": [
                {
                    "constructor": "future_salt",
                    "valid_since": e.valid_since,
                    "valid_until": e.valid_until,
                    "salt": e.salt,
                }
                for e in plan.schedule
            ],
        },
        content_related=False,
    )


UPDATES_HANDLERS = {
    "updates.getState": handle_get_state,
    "updates.getDifference": handle_get_difference,
    "get_future_salts": handle_get_future_salts,
}
