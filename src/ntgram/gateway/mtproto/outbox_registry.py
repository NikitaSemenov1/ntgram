from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True, frozen=True)
class PendingOutgoingRpc:
    """Metadata needed by rpc_drop_answer for an unacked RPC response."""

    req_msg_id: int
    msg_id: int
    seq_no: int
    bytes_count: int


@dataclass(slots=True)
class OutboxRegistry:
    """Outgoing-message bookkeeping per `AuthSession`."""

    pending_outgoing_msg_ids: set[int] = field(default_factory=set)
    pending_outgoing_rpcs: dict[int, PendingOutgoingRpc] = field(default_factory=dict)
    running_rpc_req_msg_ids: set[int] = field(default_factory=set)
    dropped_running_rpc_req_msg_ids: set[int] = field(default_factory=set)

    def register_outgoing(
        self,
        msg_id: int,
        *,
        req_msg_id: int = 0,
        seq_no: int = 0,
        bytes_count: int = 0,
    ) -> None:
        self.pending_outgoing_msg_ids.add(msg_id)
        if req_msg_id:
            self.pending_outgoing_rpcs[req_msg_id] = PendingOutgoingRpc(
                req_msg_id=req_msg_id,
                msg_id=msg_id,
                seq_no=seq_no,
                bytes_count=bytes_count,
            )

    def ack(self, msg_ids: list[int]) -> int:
        """Clear pending entries acked by msgs_ack; return number removed."""
        removed = 0
        for msg_id in msg_ids:
            if msg_id in self.pending_outgoing_msg_ids:
                self.pending_outgoing_msg_ids.remove(msg_id)
                removed += 1
                for req_msg_id, meta in list(self.pending_outgoing_rpcs.items()):
                    if meta.msg_id == msg_id:
                        self.pending_outgoing_rpcs.pop(req_msg_id, None)
        return removed

    def register_running(self, req_msg_id: int) -> None:
        self.running_rpc_req_msg_ids.add(req_msg_id)

    def finish_running(self, req_msg_id: int) -> bool:
        """Return True when this RPC was dropped while running."""
        self.running_rpc_req_msg_ids.discard(req_msg_id)
        if req_msg_id not in self.dropped_running_rpc_req_msg_ids:
            return False
        self.dropped_running_rpc_req_msg_ids.discard(req_msg_id)
        return True

    def drop_rpc_answer(
        self, req_msg_id: int,
    ) -> PendingOutgoingRpc | str | None:
        """Apply rpc_drop_answer semantics."""
        meta = self.pending_outgoing_rpcs.pop(req_msg_id, None)
        if meta is not None:
            self.pending_outgoing_msg_ids.discard(meta.msg_id)
            return meta
        if req_msg_id in self.running_rpc_req_msg_ids:
            self.dropped_running_rpc_req_msg_ids.add(req_msg_id)
            return "running"
        return None
