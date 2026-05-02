from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from ntgram.errors import RpcFailure
from ntgram.gen import common_pb2
from ntgram.gateway.history_peer import classify_history_peer
from ntgram.gateway.tl_messages import build_peer_chat_tl, build_peer_user_tl

ResolutionKind = Literal["self_empty", "pm", "group"]


@dataclass(slots=True, frozen=True)
class HistoryPeerView:
    """TL slice of an input peer — no gRPC data, no resolution."""

    peer_tl: dict[str, Any]
    kind: ResolutionKind
    target_id: int
    chat_id: int
    proto_peer: common_pb2.InputPeer


def peer_tl_for_history(
    *, actor_user_id: int, peer: Any,
) -> HistoryPeerView:
    """Classify TL InputPeer dict and produce a `HistoryPeerView`."""
    kind, pid = classify_history_peer(actor_user_id, peer)
    if kind == "invalid":
        raise RpcFailure(400, "PEER_ID_INVALID")
    if kind == "channel":
        raise RpcFailure(400, "CHANNEL_PRIVATE")
    if kind == "self_empty":
        proto = common_pb2.InputPeer(actor_user_id=actor_user_id, user_id=actor_user_id)
        return HistoryPeerView(
            peer_tl=build_peer_user_tl(actor_user_id),
            kind="self_empty",
            target_id=0,
            chat_id=0,
            proto_peer=proto,
        )
    if kind == "pm":
        proto = common_pb2.InputPeer(actor_user_id=actor_user_id, user_id=pid)
        return HistoryPeerView(
            peer_tl=build_peer_user_tl(pid),
            kind="pm",
            target_id=pid,
            chat_id=0,
            proto_peer=proto,
        )
    # kind == "group"
    proto = common_pb2.InputPeer(actor_user_id=actor_user_id, chat_id=pid)
    return HistoryPeerView(
        peer_tl=build_peer_chat_tl(pid),
        kind="group",
        target_id=pid,
        chat_id=pid,
        proto_peer=proto,
    )


def decode_input_peer_tl(
    actor_user_id: int, peer: Any,
) -> common_pb2.InputPeer:
    """Pure TL->proto decoder: map a TL InputPeer dict to proto InputPeer."""
    view = peer_tl_for_history(actor_user_id=actor_user_id, peer=peer)
    return view.proto_peer
