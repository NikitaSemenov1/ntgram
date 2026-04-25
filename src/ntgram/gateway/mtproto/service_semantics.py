from __future__ import annotations

import gzip
import logging
from dataclasses import dataclass, field

from ntgram.tl.codec import decode_tl_request
from ntgram.tl.models import TlRequest, TlResponse

MAX_CONTAINER_MESSAGES = 1024

logger = logging.getLogger(__name__)


class ServiceSemanticsError(ValueError):
    """Raised on invalid service-message semantics."""


@dataclass(slots=True)
class ServiceContext:
    pending_results: dict[int, TlResponse] = field(default_factory=dict)
    acked_ids: set[int] = field(default_factory=set)


def _unwrap_query_request(
    request: TlRequest,
    query_field: str,
    error_prefix: str,
    invoke_layer: int | None = None,
) -> TlRequest:
    inner = request.payload.get(query_field)
    if not isinstance(inner, dict):
        raise ServiceSemanticsError(f"{error_prefix}.{query_field} is required")
    constructor = inner.get("_constructor") or inner.get("constructor")
    if not isinstance(constructor, str):
        raise ServiceSemanticsError(
            f"{error_prefix}.{query_field} constructor is required"
        )
    payload = dict(inner)
    payload.pop("_constructor", None)
    payload.pop("constructor", None)
    payload.pop("constructor_id", None)
    return TlRequest(
        constructor_id=int(inner.get("constructor_id", 0)),
        constructor=constructor,
        req_msg_id=request.req_msg_id,
        auth_key_id=request.auth_key_id,
        session_id=request.session_id,
        message_id=request.message_id,
        seq_no=request.seq_no,
        invoke_layer=invoke_layer if invoke_layer is not None else request.invoke_layer,
        payload=payload,
    )


def decode_service_request(request: TlRequest) -> list[TlRequest]:
    if request.constructor == "msg_container":
        items = request.payload.get("messages", [])
        if not isinstance(items, list):
            raise ServiceSemanticsError("msg_container.messages must be list")
        if len(items) > MAX_CONTAINER_MESSAGES:
            raise ServiceSemanticsError("msg_container.messages exceeds 1024")
        decoded: list[TlRequest] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            constructor = str(item["constructor"])
            if constructor == "msg_container":
                raise ServiceSemanticsError("nested msg_container is not allowed")
            inner_msg_id = int(item.get("req_msg_id", request.req_msg_id))
            if request.message_id is not None and inner_msg_id >= request.message_id:
                raise ServiceSemanticsError("container msg_id must be greater than inner msg_id")
            nested_request = TlRequest(
                constructor_id=int(item.get("constructor_id", 0)),
                constructor=constructor,
                req_msg_id=inner_msg_id,
                auth_key_id=request.auth_key_id,
                session_id=request.session_id,
                message_id=inner_msg_id,
                seq_no=int(item.get("seq_no", request.seq_no or 0)),
                invoke_layer=request.invoke_layer,
                payload=dict(item.get("payload", {})),
            )
            decoded.extend(decode_service_request(nested_request))
        return decoded
    if request.constructor == "gzip_packed":
        packed = request.payload.get("packed_data")
        if isinstance(packed, str):
            packed_bytes = bytes.fromhex(packed)
        elif isinstance(packed, (bytes, bytearray, memoryview)):
            packed_bytes = bytes(packed)
        else:
            raise ServiceSemanticsError("gzip_packed.packed_data must be bytes")
        try:
            inner_request = decode_tl_request(gzip.decompress(packed_bytes))
        except Exception as exc:
            raise ServiceSemanticsError("gzip_packed payload is invalid TL") from exc
        nested_request = TlRequest(
            constructor_id=inner_request.constructor_id,
            constructor=inner_request.constructor,
            req_msg_id=request.req_msg_id,
            auth_key_id=request.auth_key_id,
            session_id=request.session_id,
            message_id=request.message_id,
            seq_no=request.seq_no,
            invoke_layer=request.invoke_layer,
            payload=inner_request.payload,
        )
        return decode_service_request(nested_request)
    if request.constructor == "invokeWithLayer":
        raw_layer = request.payload.get("layer")
        invoke_layer = raw_layer if isinstance(raw_layer, int) and raw_layer > 0 else request.invoke_layer
        query = request.payload.get("query")
        inner_ctor: str | None = None
        if isinstance(query, dict):
            ic = query.get("_constructor") or query.get("constructor")
            inner_ctor = str(ic) if isinstance(ic, str) else None
        logger.info(
            "invokeWithLayer: auth_key_id=%s session_id=%s layer_raw=%r layer_effective=%s inner_query=%s",
            request.auth_key_id,
            request.session_id,
            raw_layer,
            invoke_layer,
            inner_ctor,
        )
        return decode_service_request(
            _unwrap_query_request(
                request,
                "query",
                "invokeWithLayer",
                invoke_layer=invoke_layer,
            )
        )
    if request.constructor == "initConnection":
        return decode_service_request(
            _unwrap_query_request(request, "query", "initConnection")
        )
    return [request]


def handle_control_message(context: ServiceContext, request: TlRequest) -> TlResponse | None:
    if request.constructor in ("ping", "ping_delay_disconnect"):
        # ping_delay_disconnect: disconnect_delay is ignored (no server-side timer).
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

