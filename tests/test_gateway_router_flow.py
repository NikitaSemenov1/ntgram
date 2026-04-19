from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from ntgram.tl.codec import (
    decode_tl_object,
    decode_tl_request,
    encode_tl_response,
)
from ntgram.tl.models import TlResponse
from ntgram.tl.registry import default_schema_registry
from ntgram.tl.serializer import serialize_object


@pytest.mark.skip(reason="requires Postgres -- services now use asyncpg DAO")
async def test_router_end_to_end_flow() -> None:
    pass


@pytest.mark.asyncio
async def test_trace_constructors_are_supported() -> None:
    trace_path = Path(__file__).parent / "traces/client_core_trace.json"
    constructors = [
        entry["constructor"]
        for entry in json.loads(trace_path.read_text())
    ]
    assert "auth.sendCode" in constructors
    assert "updates.getDifference" in constructors


def test_binary_tl_request_response_roundtrip() -> None:
    """Round-trip: serialize a TL method, decode it, then encode a response."""
    schema = default_schema_registry()
    spec = schema.methods_by_name["ping"]

    body = serialize_object("ping", {"ping_id": 42}, schema)

    request = decode_tl_request(body)
    assert request.constructor == "ping"
    assert request.payload["ping_id"] == 42

    response = TlResponse(
        req_msg_id=77,
        result={
            "constructor": "pong",
            "msg_id": 77,
            "ping_id": 42,
        },
    )
    encoded_response = encode_tl_response(response)
    name, fields = decode_tl_object(encoded_response)
    assert name == "pong"
    assert fields["ping_id"] == 42


@pytest.mark.asyncio
async def test_help_get_config_returns_serializable_config() -> None:
    pytest.importorskip("grpc")
    from ntgram.gateway.mtproto.session_store import SessionStore
    from ntgram.gateway.push_registry import PushRegistry
    from ntgram.gateway.router import GatewayRouter
    from ntgram.gateway.update_bus import UpdateBus
    from ntgram.tl.models import TlRequest

    router = GatewayRouter(
        grpc_bridge=AsyncMock(),
        sessions=SessionStore(),
        update_bus=UpdateBus(PushRegistry()),
    )
    response = await router.dispatch(
        TlRequest(
            constructor_id=0,
            constructor="help.getConfig",
            req_msg_id=101,
            auth_key_id=0,
            session_id=1,
            payload={},
        )
    )
    encoded = encode_tl_response(response)
    name, fields = decode_tl_object(encoded)
    assert name == "rpc_result"
    inner = fields["result"]
    assert inner["_constructor"] == "rpc_error"
    assert inner["error_code"] == 400
    assert inner["error_message"] == "ERR_NOT_IMPLEMENTED"
