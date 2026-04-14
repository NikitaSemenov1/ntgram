from __future__ import annotations

import gzip
from dataclasses import dataclass, field

from ntgram.tl.models import TlRequest, TlResponse


class ServiceSemanticsError(ValueError):
    """Raised on invalid service-message semantics."""


@dataclass(slots=True)
class ServiceContext:
    pending_results: dict[int, TlResponse] = field(default_factory=dict)
    acked_ids: set[int] = field(default_factory=set)


def decode_service_request(request: TlRequest) -> list[TlRequest]:
    if request.constructor == "msg_container":
        items = request.payload.get("messages", [])
        if not isinstance(items, list):
            raise ServiceSemanticsError("msg_container.messages must be list")
        decoded: list[TlRequest] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            decoded.append(
                TlRequest(
                    constructor_id=int(item.get("constructor_id", 0)),
                    constructor=str(item["constructor"]),
                    req_msg_id=int(item.get("req_msg_id", request.req_msg_id)),
                    auth_key_id=request.auth_key_id,
                    session_id=request.session_id,
                    payload=dict(item.get("payload", {})),
                )
            )
        return decoded
    if request.constructor == "gzip_packed":
        packed = request.payload.get("packed_data")
        if not isinstance(packed, str):
            raise ServiceSemanticsError("gzip_packed.packed_data must be hex string")
        _ = gzip.decompress(bytes.fromhex(packed))
        # Current phase keeps decoded payload in the parent request body.
        inner = request.payload.get("inner_request")
        if not isinstance(inner, dict):
            raise ServiceSemanticsError("gzip_packed.inner_request is required")
        return [
            TlRequest(
                constructor_id=int(inner.get("constructor_id", 0)),
                constructor=str(inner["constructor"]),
                req_msg_id=int(inner.get("req_msg_id", request.req_msg_id)),
                auth_key_id=request.auth_key_id,
                session_id=request.session_id,
                payload=dict(inner.get("payload", {})),
            )
        ]
    return [request]


def handle_control_message(context: ServiceContext, request: TlRequest) -> TlResponse | None:
    if request.constructor == "ping":
        ping_id = int(request.payload.get("ping_id", 0))
        return TlResponse(
            req_msg_id=request.req_msg_id,
            result={"constructor": "pong", "msg_id": request.req_msg_id, "ping_id": ping_id},
        )
    if request.constructor == "msgs_ack":
        ack_ids = request.payload.get("msg_ids", [])
        if isinstance(ack_ids, list):
            context.acked_ids.update(int(item) for item in ack_ids if isinstance(item, int))
        return None
    if request.constructor == "msg_resend_req":
        msg_ids = request.payload.get("msg_ids", [])
        if not isinstance(msg_ids, list):
            raise ServiceSemanticsError("msg_resend_req.msg_ids must be list")
        for msg_id in msg_ids:
            if isinstance(msg_id, int) and msg_id in context.pending_results:
                return context.pending_results[msg_id]
        return TlResponse(
            req_msg_id=request.req_msg_id,
            result={"constructor": "rpc_answer_unknown"},
        )
    return None


def wrap_rpc_result(req_msg_id: int, result: dict) -> TlResponse:
    return TlResponse(
        req_msg_id=req_msg_id,
        result={"constructor": "rpc_result", "req_msg_id": req_msg_id, "result": result},
    )


def wrap_rpc_error(req_msg_id: int, error_code: int, error_message: str) -> TlResponse:
    return TlResponse(
        req_msg_id=req_msg_id,
        result={
            "constructor": "rpc_result",
            "req_msg_id": req_msg_id,
            "result": {
                "constructor": "rpc_error",
                "error_code": error_code,
                "error_message": error_message,
            },
        },
        error_code=error_code,
        error_message=error_message,
    )

