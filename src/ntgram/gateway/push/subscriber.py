from __future__ import annotations

import asyncio
import json
import logging
from typing import TYPE_CHECKING, Any

from ntgram.gen import common_pb2

if TYPE_CHECKING:
    from ntgram.gateway.grpc_clients.account_client import AccountClient
    from ntgram.gateway.grpc_clients.chat_client import ChatClient
    from ntgram.gateway.grpc_clients.updates_client import UpdatesClient
    from ntgram.gateway.push_registry import PushSlot

logger = logging.getLogger(__name__)

_RECONNECT_DELAY_SEC = 2.0


def _parse_update_item(item: common_pb2.UpdateItem) -> dict[str, Any] | None:
    """Convert one UpdateItem to a TL Update dict."""
    if item.raw_update_json:
        try:
            return json.loads(item.raw_update_json)
        except (json.JSONDecodeError, ValueError):
            pass

    which = item.WhichOneof("update")
    if which == "new_message":
        u = item.new_message
        if u.peer_chat_id:
            peer_tl: dict[str, Any] = {"constructor": "peerChat", "chat_id": int(u.peer_chat_id)}
        else:
            peer_tl = {"constructor": "peerUser", "user_id": int(u.peer_user_id)}
        from ntgram.tl.builders.updates import build_message_tl
        msg_tl = build_message_tl(
            message_id=int(u.message_id),
            from_user_id=int(u.from_user_id),
            date=int(u.date),
            text=u.text,
            peer_id_tl=peer_tl,
            out=bool(u.out),
        )
        return {
            "constructor": "updateNewMessage",
            "message": msg_tl,
            "pts": int(u.pts),
            "pts_count": int(u.pts_count),
        }
    if which == "read_outbox":
        u = item.read_outbox
        return {
            "constructor": "updateReadHistoryOutbox",
            "peer": {"constructor": "peerUser", "user_id": int(u.peer_user_id)},
            "max_id": int(u.max_id),
            "pts": int(u.pts),
            "pts_count": int(u.pts_count),
        }
    return None


def _build_updates_from_envelope(
    updates_tl: list[dict[str, Any]],
    users_tl: list[dict[str, Any]],
    chats_tl: list[dict[str, Any]],
    date: int,
) -> dict[str, Any]:
    """Assemble a full updates#74ae4240 TL dict from pre-parsed components."""
    return {
        "constructor": "updates",
        "updates": updates_tl,
        "users": users_tl,
        "chats": chats_tl,
        "date": date,
        "seq": 0,
    }


def _collect_peer_ids(
    updates_tl: list[dict[str, Any]],
) -> tuple[set[int], set[int]]:
    """Extract (user_ids, chat_ids) referenced by a list of TL Update dicts."""
    user_ids: set[int] = set()
    chat_ids: set[int] = set()
    for u in updates_tl:
        constructor = u.get("constructor", "")
        if constructor == "updateNewMessage":
            msg = u.get("message", {})
            from_id = msg.get("from_id", {})
            if from_id.get("user_id"):
                user_ids.add(int(from_id["user_id"]))
            peer = msg.get("peer_id", {})
            if peer.get("constructor") == "peerUser" and peer.get("user_id"):
                user_ids.add(int(peer["user_id"]))
            elif peer.get("constructor") == "peerChat" and peer.get("chat_id"):
                chat_ids.add(int(peer["chat_id"]))
        elif constructor in ("updateReadHistoryOutbox", "updateReadHistoryInbox"):
            peer = u.get("peer", {})
            if peer.get("constructor") == "peerUser" and peer.get("user_id"):
                user_ids.add(int(peer["user_id"]))
            elif peer.get("constructor") == "peerChat" and peer.get("chat_id"):
                chat_ids.add(int(peer["chat_id"]))
            elif peer.get("user_id"):
                user_ids.add(int(peer["user_id"]))
    return user_ids, chat_ids


async def run_subscriber(
    slot: "PushSlot",
    updates_client: "UpdatesClient",
    account_client: "AccountClient",
    chat_client: "ChatClient",
    *,
    since_pts: int = 0,
) -> None:
    """Long-running task: subscribe and push enriched updates to slot.queue."""
    while True:
        try:
            stream = updates_client.subscribe(
                user_id=slot.user_id,
                since_pts=since_pts,
            )
            async for envelope in stream:
                if not envelope.updates:
                    continue

                # Parse all UpdateItems into TL dicts.
                updates_tl: list[dict[str, Any]] = []
                for item in envelope.updates:
                    parsed = _parse_update_item(item)
                    if parsed is not None:
                        updates_tl.append(parsed)

                if not updates_tl:
                    continue

                # Advance since_pts.
                max_pts = max(
                    (int(item.pts) for item in envelope.updates if item.pts),
                    default=since_pts,
                )
                if max_pts > since_pts:
                    since_pts = max_pts

                # Enrich with peer info.
                user_ids, chat_ids = _collect_peer_ids(updates_tl)
                user_ids.discard(slot.user_id)
                from ntgram.gateway.push.peer_enrichment import fetch_peers_tl
                users_tl, chats_tl = await fetch_peers_tl(
                    actor_user_id=slot.user_id,
                    user_ids=user_ids,
                    chat_ids=chat_ids,
                    account_client=account_client,
                    chat_client=chat_client,
                )

                update_dict = _build_updates_from_envelope(
                    updates_tl, users_tl, chats_tl, int(envelope.date),
                )

                logger.info(
                    "push enqueued: user_id=%d updates=%d users=%d chats=%d max_pts=%d",
                    slot.user_id,
                    len(updates_tl),
                    len(users_tl),
                    len(chats_tl),
                    max_pts,
                )
                try:
                    slot.queue.put_nowait(update_dict)
                except asyncio.QueueFull:
                    try:
                        await asyncio.wait_for(
                            slot.queue.put(update_dict), timeout=2.0,
                        )
                    except (asyncio.TimeoutError, asyncio.QueueFull):
                        logger.warning(
                            "push subscriber: queue persistently full for user=%d;"
                            " closing stream to force getDifference",
                            slot.user_id,
                        )
                        try:
                            slot.queue.put_nowait(None)
                        except asyncio.QueueFull:
                            pass
                        return

        except asyncio.CancelledError:
            return
        except Exception as exc:
            logger.debug(
                "push subscriber: stream error for user=%d: %s; reconnecting in %ss",
                slot.user_id, exc, _RECONNECT_DELAY_SEC,
            )
            await asyncio.sleep(_RECONNECT_DELAY_SEC)
