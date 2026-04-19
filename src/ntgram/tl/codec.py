"""TL codec: encode/decode MTProto messages using schema-driven serialization.

Handles both unencrypted messages (auth_key_id=0 header) and raw TL bodies
(from inside the encrypted layer).
"""
from __future__ import annotations

import struct
from typing import Any

from ntgram.tl.models import TlRequest, TlResponse
from ntgram.tl.registry import default_schema_registry
from ntgram.tl.serializer import (
    TlSerializerError,
    _Reader,
    deserialize_by_spec,
    serialize_object,
)

_SCHEMA = default_schema_registry()
_MSG_CONTAINER_CID = _SCHEMA.constructors_by_name["msg_container"].id


class TlCodecError(ValueError):
    """Raised when TL payload is malformed."""


# ---------------------------------------------------------------------------
# Decode
# ---------------------------------------------------------------------------

def decode_tl_request(data: bytes) -> TlRequest:
    """Decode a TL request from wire bytes.

    Auto-detects the format:
    - Unencrypted: auth_key_id(8)=0 + msg_id(8) + data_length(4) + tl_body
    - Raw TL body: constructor_id(4) + fields (from encrypted layer)
    """
    if len(data) < 4:
        raise TlCodecError("data too short")

    auth_key_id = 0
    req_msg_id = 0
    session_id = 0

    if len(data) >= 20:
        maybe_akid = struct.unpack("<Q", data[:8])[0]
        if maybe_akid == 0:
            auth_key_id = 0
            req_msg_id = struct.unpack("<q", data[8:16])[0]
            body_len = struct.unpack("<I", data[16:20])[0]
            if 20 + body_len <= len(data):
                tl_body = data[20: 20 + body_len]
                return _deserialize_tl_body(tl_body, auth_key_id, req_msg_id, session_id)

    return _deserialize_tl_body(data, auth_key_id, req_msg_id, session_id)


def _deserialize_tl_body(
    data: bytes,
    auth_key_id: int,
    req_msg_id: int,
    session_id: int,
) -> TlRequest:
    """Deserialize a raw TL body (constructor_id + fields)."""
    reader = _Reader(data)
    cid = reader.read_int32()

    if cid == _MSG_CONTAINER_CID:
        messages_count = reader.read_int32()
        if messages_count < 0:
            raise TlCodecError("msg_container.messages count must be non-negative")
        messages: list[dict[str, Any]] = []
        for _ in range(messages_count):
            msg_id = reader.read_int64()
            seqno = reader.read_int32()
            body_len = reader.read_int32()
            if body_len < 0 or body_len > reader.remaining:
                raise TlCodecError("msg_container message body length is invalid")
            body = reader._read(body_len)
            constructor_name, fields = decode_tl_object(body)
            constructor_id = struct.unpack("<i", body[:4])[0]
            messages.append(
                {
                    "constructor_id": constructor_id,
                    "constructor": constructor_name,
                    "req_msg_id": msg_id,
                    "seq_no": seqno,
                    "payload": fields,
                },
            )
        return TlRequest(
            constructor_id=cid,
            constructor="msg_container",
            req_msg_id=req_msg_id,
            auth_key_id=auth_key_id,
            session_id=session_id,
            payload={"messages": messages},
        )

    spec = _SCHEMA.methods_by_id.get(cid)
    if spec is not None:
        fields = deserialize_by_spec(spec, reader, _SCHEMA)
        return TlRequest(
            constructor_id=cid,
            constructor=spec.method,
            req_msg_id=req_msg_id,
            auth_key_id=auth_key_id,
            session_id=session_id,
            payload=fields,
        )

    cspec = _SCHEMA.constructors_by_id.get(cid)
    if cspec is not None:
        fields = deserialize_by_spec(cspec, reader, _SCHEMA)
        return TlRequest(
            constructor_id=cid,
            constructor=cspec.predicate,
            req_msg_id=req_msg_id,
            auth_key_id=auth_key_id,
            session_id=session_id,
            payload=fields,
        )

    raise TlCodecError(f"unknown constructor id: {cid:#010x}")


# ---------------------------------------------------------------------------
# Encode
# ---------------------------------------------------------------------------

def encode_tl_response(response: TlResponse) -> bytes:
    """Encode a TlResponse as TL bytes.

    The response.result dict must have a 'constructor' key indicating
    which TL constructor to serialize as. For error responses with empty
    result, an rpc_error is generated.
    """
    result = response.result
    if not result and response.error_code is not None:
        result = {
            "constructor": "rpc_result",
            "req_msg_id": response.req_msg_id,
            "result": {
                "constructor": "rpc_error",
                "error_code": response.error_code,
                "error_message": response.error_message or "UNKNOWN",
            },
        }
    if not result:
        return b""

    constructor = result.get("constructor")
    if constructor is None:
        raise TlCodecError("response.result must have 'constructor'")

    fields = {k: v for k, v in result.items() if k != "constructor"}

    _prepare_nested(fields)

    try:
        return serialize_object(constructor, fields, _SCHEMA)
    except TlSerializerError as exc:
        raise TlCodecError(f"encode failed for {constructor}: {exc}") from exc


def _prepare_nested(fields: dict[str, Any]) -> None:
    """Recursively rename 'constructor' to '_constructor' for nested dicts."""
    for key, val in fields.items():
        if isinstance(val, dict) and "constructor" in val:
            val["_constructor"] = val.pop("constructor")
            _prepare_nested(val)
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, dict) and "constructor" in item:
                    item["_constructor"] = item.pop("constructor")
                    _prepare_nested(item)


def encode_tl_object(name: str, fields: dict[str, Any]) -> bytes:
    """Convenience: serialize a named TL object."""
    return serialize_object(name, fields, _SCHEMA)


def decode_tl_object(data: bytes) -> tuple[str, dict[str, Any]]:
    """Deserialize a boxed TL object, returns (name, fields)."""
    reader = _Reader(data)

    cid = reader.read_int32()
    spec = _SCHEMA.constructors_by_id.get(cid)
    if spec is not None:
        fields = deserialize_by_spec(spec, reader, _SCHEMA)
        return spec.predicate, fields

    mspec = _SCHEMA.methods_by_id.get(cid)
    if mspec is not None:
        fields = deserialize_by_spec(mspec, reader, _SCHEMA)
        return mspec.method, fields

    raise TlCodecError(f"unknown constructor id: {cid:#010x}")


# ---------------------------------------------------------------------------
# Unencrypted message helpers
# ---------------------------------------------------------------------------

def wrap_unencrypted(msg_id: int, tl_body: bytes) -> bytes:
    """Wrap TL body in an unencrypted MTProto message (auth_key_id=0)."""
    return (
        struct.pack("<Q", 0)
        + struct.pack("<q", msg_id)
        + struct.pack("<I", len(tl_body))
        + tl_body
    )


def unwrap_unencrypted(data: bytes) -> tuple[int, bytes]:
    """Unwrap an unencrypted MTProto message. Returns (msg_id, tl_body)."""
    if len(data) < 20:
        raise TlCodecError("unencrypted message too short")
    auth_key_id = struct.unpack("<Q", data[:8])[0]
    if auth_key_id != 0:
        raise TlCodecError(f"expected auth_key_id=0, got {auth_key_id}")
    msg_id = struct.unpack("<q", data[8:16])[0]
    body_len = struct.unpack("<I", data[16:20])[0]
    return msg_id, data[20: 20 + body_len]
