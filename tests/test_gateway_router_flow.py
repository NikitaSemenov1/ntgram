from __future__ import annotations

import json
from pathlib import Path

import pytest

from ntgram.tl.codec import (
    decode_tl_request,
    encode_tl_response,
    decode_tl_object,
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
