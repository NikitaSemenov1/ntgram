from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from ntgram.tl.codec import (
    decode_tl_object,
    decode_tl_request,
    encode_tl_object,
    encode_tl_response,
)
from ntgram.tl.models import TlRequest, TlResponse
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


def test_help_get_config_returns_serializable_config() -> None:
    pytest.importorskip("grpc")
    from ntgram.gateway.mtproto.session_store import SessionStore
    from ntgram.gateway.push_registry import PushRegistry
    from ntgram.gateway.router import GatewayRouter
    from ntgram.gateway.update_bus import UpdateBus
    router = GatewayRouter(
        grpc_bridge=AsyncMock(),
        sessions=SessionStore(),
        update_bus=UpdateBus(PushRegistry()),
    )

    async def _dispatch() -> TlResponse:
        return await router.dispatch(
            TlRequest(
                constructor_id=0,
                constructor="help.getConfig",
                req_msg_id=101,
                auth_key_id=0,
                session_id=1,
                payload={},
            ),
        )

    response = asyncio.run(_dispatch())
    encoded = encode_tl_response(response)
    name, fields = decode_tl_object(encoded)
    assert name == "rpc_result"
    inner = fields["result"]
    assert inner["_constructor"] == "config"
    assert inner.get("this_dc") == 1
    assert isinstance(inner.get("dc_options"), list)


def test_help_get_nearest_dc_returns_serializable_nearest_dc() -> None:
    pytest.importorskip("grpc")
    from ntgram.gateway.mtproto.session_store import SessionStore
    from ntgram.gateway.push_registry import PushRegistry
    from ntgram.gateway.router import GatewayRouter
    from ntgram.gateway.update_bus import UpdateBus

    router = GatewayRouter(
        grpc_bridge=AsyncMock(),
        sessions=SessionStore(),
        update_bus=UpdateBus(PushRegistry()),
    )

    async def _dispatch() -> TlResponse:
        return await router.dispatch(
            TlRequest(
                constructor_id=0,
                constructor="help.getNearestDc",
                req_msg_id=102,
                auth_key_id=0,
                session_id=1,
                payload={},
            ),
        )

    response = asyncio.run(_dispatch())
    encoded = encode_tl_response(response)
    name, fields = decode_tl_object(encoded)
    assert name == "rpc_result"
    inner = fields["result"]
    assert inner["_constructor"] == "nearestDc"
    assert inner["this_dc"] == 1
    assert inner["nearest_dc"] == 1


def test_get_future_salts_returns_rpc_result_future_salts() -> None:
    pytest.importorskip("grpc")
    from ntgram.gateway.mtproto.session_store import SessionStore
    from ntgram.gateway.push_registry import PushRegistry
    from ntgram.gateway.router import GatewayRouter
    from ntgram.gateway.update_bus import UpdateBus

    store = SessionStore()
    session = store.complete_handshake(
        session_id=1,
        auth_key=b"f" * 256,
        new_nonce=9,
        server_nonce=8,
    )
    session.bind_mtproto_session(7001)
    router = GatewayRouter(
        grpc_bridge=AsyncMock(),
        sessions=store,
        update_bus=UpdateBus(PushRegistry()),
    )
    query_msg_id = ((int(time.time()) << 32) | 4) & ~3

    async def _dispatch() -> TlResponse:
        return await router.dispatch(
            TlRequest(
                constructor_id=0,
                constructor="get_future_salts",
                req_msg_id=query_msg_id,
                auth_key_id=session.auth_key_id,
                session_id=7001,
                message_id=query_msg_id,
                payload={"num": 3},
            ),
        )

    response = asyncio.run(_dispatch())
    encoded = encode_tl_response(response)
    name, fields = decode_tl_object(encoded)
    assert name == "rpc_result"
    inner = fields["result"]
    assert inner["_constructor"] == "future_salts"
    assert inner["req_msg_id"] == query_msg_id
    assert inner["now"] > 0
    assert isinstance(inner["salts"], list)
    assert len(inner["salts"]) == 3
    for item in inner["salts"]:
        assert item["_constructor"] == "future_salt"
        assert item["valid_since"] <= item["valid_until"]
    assert len(store.get_session(session.auth_key_id).accepted_future_salts) == 3


def test_bind_temp_auth_key_returns_bool_true() -> None:
    pytest.importorskip("grpc")
    from ntgram.gateway.mtproto.encrypted_layer import (
        encode_bind_temp_auth_key_inner_message,
    )
    from ntgram.gateway.mtproto.session_store import SessionStore
    from ntgram.gateway.push_registry import PushRegistry
    from ntgram.gateway.router import GatewayRouter
    from ntgram.gateway.update_bus import UpdateBus

    store = SessionStore()
    perm_session = store.complete_handshake(
        session_id=1,
        auth_key=b"p" * 256,
        new_nonce=10,
        server_nonce=20,
    )
    temp_session = store.complete_handshake(
        session_id=2,
        auth_key=b"t" * 256,
        new_nonce=11,
        server_nonce=21,
    )
    temp_session_id = 123456789
    nonce = 42
    expires_at = int(time.time()) + 3600
    inner = encode_tl_object(
        "bind_auth_key_inner",
        {
            "nonce": nonce,
            "temp_auth_key_id": temp_session.auth_key_id,
            "perm_auth_key_id": perm_session.auth_key_id,
            "temp_session_id": temp_session_id,
            "expires_at": expires_at,
        },
    )
    msg_id = ((int(time.time()) << 32) | 4) & ~3
    encrypted_message = encode_bind_temp_auth_key_inner_message(
        perm_session,
        msg_id=msg_id,
        message_data=inner,
    )
    router = GatewayRouter(
        grpc_bridge=AsyncMock(),
        sessions=store,
        update_bus=UpdateBus(PushRegistry()),
    )

    async def _dispatch() -> TlResponse:
        return await router.dispatch(
            TlRequest(
                constructor_id=0,
                constructor="auth.bindTempAuthKey",
                req_msg_id=1001,
                auth_key_id=temp_session.auth_key_id,
                session_id=temp_session_id,
                payload={
                    "perm_auth_key_id": perm_session.auth_key_id,
                    "nonce": nonce,
                    "expires_at": expires_at,
                    "encrypted_message": encrypted_message,
                },
            ),
        )

    response = asyncio.run(_dispatch())
    encoded = encode_tl_response(response)
    name, fields = decode_tl_object(encoded)
    assert name == "rpc_result"
    assert fields["result"]["_constructor"] == "boolTrue"
    assert store.get_session(perm_session.auth_key_id).temp_auth_key_binding is not None
    assert store.get_session(temp_session.auth_key_id).temp_auth_key_binding is not None


def test_destroy_session_returns_ok_or_none() -> None:
    pytest.importorskip("grpc")
    from ntgram.gateway.mtproto.session_store import SessionStore
    from ntgram.gateway.push_registry import PushRegistry
    from ntgram.gateway.router import GatewayRouter
    from ntgram.gateway.update_bus import UpdateBus

    store = SessionStore()
    session = store.complete_handshake(
        session_id=1,
        auth_key=b"d" * 256,
        new_nonce=1,
        server_nonce=2,
    )
    session.bind_mtproto_session(777)
    router = GatewayRouter(
        grpc_bridge=AsyncMock(),
        sessions=store,
        update_bus=UpdateBus(PushRegistry()),
    )

    async def _dispatch_destroy(target: int) -> TlResponse:
        return await router.dispatch(
            TlRequest(
                constructor_id=0,
                constructor="destroy_session",
                req_msg_id=500,
                auth_key_id=session.auth_key_id,
                session_id=777,
                payload={"session_id": target},
            ),
        )

    r_ok = asyncio.run(_dispatch_destroy(777))
    enc_ok = encode_tl_response(r_ok)
    name_ok, fields_ok = decode_tl_object(enc_ok)
    assert name_ok == "rpc_result"
    assert fields_ok["result"]["_constructor"] == "destroy_session_ok"

    r_none = asyncio.run(_dispatch_destroy(777))
    enc_none = encode_tl_response(r_none)
    _, fields_none = decode_tl_object(enc_none)
    assert fields_none["result"]["_constructor"] == "destroy_session_none"


def test_langpack_get_languages_returns_empty_vector() -> None:
    pytest.importorskip("grpc")
    from ntgram.gateway.mtproto.session_store import SessionStore
    from ntgram.gateway.push_registry import PushRegistry
    from ntgram.gateway.router import GatewayRouter
    from ntgram.gateway.update_bus import UpdateBus

    router = GatewayRouter(
        grpc_bridge=AsyncMock(),
        sessions=SessionStore(),
        update_bus=UpdateBus(PushRegistry()),
    )

    async def _dispatch() -> TlResponse:
        return await router.dispatch(
            TlRequest(
                constructor_id=0,
                constructor="langpack.getLanguages",
                req_msg_id=600,
                auth_key_id=1,
                session_id=1,
                payload={},
            ),
        )

    response = asyncio.run(_dispatch())
    encoded = encode_tl_response(response)
    name, fields = decode_tl_object(encoded)
    assert name == "rpc_result"
    inner = fields["result"]
    assert isinstance(inner, list)
    assert inner == []
