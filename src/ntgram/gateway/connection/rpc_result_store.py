from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass

from ntgram.tl.models import TlRequest, TlResponse


@dataclass(slots=True, frozen=True)
class RpcResultKey:
    """Composite key shared by idempotency and resend lookups."""

    auth_key_id: int
    session_id: int
    req_msg_id: int


class RpcResultStore:
    """Bounded LRU of completed RPC TlResponses."""

    DEFAULT_MAXSIZE = 4096

    def __init__(self, *, maxsize: int = DEFAULT_MAXSIZE) -> None:
        if maxsize <= 0:
            raise ValueError("RpcResultStore maxsize must be positive")
        self._maxsize = maxsize
        # Maps key -> (constructor, response).
        self._entries: OrderedDict[
            RpcResultKey, tuple[str, TlResponse],
        ] = OrderedDict()

    def __len__(self) -> int:
        return len(self._entries)

    @staticmethod
    def _key_for(request: TlRequest) -> RpcResultKey:
        return RpcResultKey(
            auth_key_id=request.auth_key_id,
            session_id=request.session_id,
            req_msg_id=request.req_msg_id,
        )

    def get(self, request: TlRequest) -> TlResponse | None:
        """Return cached response for an idempotency lookup, or None."""
        entry = self._entries.get(self._key_for(request))
        if entry is None:
            return None
        constructor, response = entry
        if constructor != request.constructor:
            return None
        self._entries.move_to_end(self._key_for(request))
        return response

    def get_for_resend(
        self, session_id: int, req_msg_id: int,
    ) -> TlResponse | None:
        """Return any cached response for msg_resend_req lookup."""
        for key, (_, response) in self._entries.items():
            if key.session_id == session_id and key.req_msg_id == req_msg_id:
                self._entries.move_to_end(key)
                return response
        return None

    def put(self, request: TlRequest, response: TlResponse) -> None:
        key = self._key_for(request)
        self._entries[key] = (request.constructor, response)
        self._entries.move_to_end(key)
        while len(self._entries) > self._maxsize:
            self._entries.popitem(last=False)

    def drop(
        self, auth_key_id: int, session_id: int, req_msg_id: int,
    ) -> None:
        self._entries.pop(
            RpcResultKey(
                auth_key_id=auth_key_id,
                session_id=session_id,
                req_msg_id=req_msg_id,
            ),
            None,
        )
