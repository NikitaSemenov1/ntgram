from __future__ import annotations

from ntgram.gateway.mtproto.outbox_registry import PendingOutgoingRpc
from ntgram.gateway.mtproto.session_store import SessionStore


class OutboxService:
    """Narrow facade for outbound-RPC tracking."""

    __slots__ = ("_sessions",)

    def __init__(self, sessions: SessionStore) -> None:
        self._sessions = sessions

    def register_outgoing_msg(
        self,
        auth_key_id: int,
        msg_id: int,
        *,
        req_msg_id: int = 0,
        seq_no: int = 0,
        bytes_count: int = 0,
    ) -> bool:
        session = self._sessions.get_session(auth_key_id)
        if session is None:
            return False
        session.outbox.register_outgoing(
            msg_id,
            req_msg_id=req_msg_id,
            seq_no=seq_no,
            bytes_count=bytes_count,
        )
        return True

    def ack_outgoing_msgs(self, auth_key_id: int, msg_ids: list[int]) -> int:
        session = self._sessions.get_session(auth_key_id)
        if session is None:
            return 0
        return session.outbox.ack(msg_ids)

    def register_running_rpc(self, auth_key_id: int, req_msg_id: int) -> bool:
        session = self._sessions.get_session(auth_key_id)
        if session is None:
            return False
        session.outbox.register_running(req_msg_id)
        return True

    def finish_running_rpc(self, auth_key_id: int, req_msg_id: int) -> bool:
        """Return True when this RPC was dropped while running."""
        session = self._sessions.get_session(auth_key_id)
        if session is None:
            return False
        return session.outbox.finish_running(req_msg_id)

    def drop_rpc_answer(
        self, auth_key_id: int, req_msg_id: int,
    ) -> PendingOutgoingRpc | str | None:
        """Drop or mark a response requested by rpc_drop_answer."""
        session = self._sessions.get_session(auth_key_id)
        if session is None:
            return None
        return session.outbox.drop_rpc_answer(req_msg_id)
