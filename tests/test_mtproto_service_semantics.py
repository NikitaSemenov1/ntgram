from __future__ import annotations

import gzip

from ntgram.gateway.mtproto.service_semantics import (
    ServiceContext,
    decode_service_request,
    handle_control_message,
    wrap_rpc_error,
    wrap_rpc_result,
)
from ntgram.tl.models import TlRequest


def test_ping_pong_control_message() -> None:
    ctx = ServiceContext()
    response = handle_control_message(
        ctx,
        TlRequest(
            constructor_id=0,
            constructor="ping",
            req_msg_id=10,
            auth_key_id=1,
            session_id=1,
            payload={"ping_id": 55},
        ),
    )
    assert response is not None
    assert response.result["constructor"] == "pong"
    assert response.result["ping_id"] == 55


def test_msg_container_decode() -> None:
    request = TlRequest(
        constructor_id=0,
        constructor="msg_container",
        req_msg_id=1,
        auth_key_id=1,
        session_id=1,
        payload={
            "messages": [
                {"constructor": "auth.sendCode", "constructor_id": 123, "req_msg_id": 2, "payload": {"phone": "+1"}}
            ]
        },
    )
    decoded = decode_service_request(request)
    assert len(decoded) == 1
    assert decoded[0].constructor == "auth.sendCode"


def test_gzip_packed_decode() -> None:
    packed = gzip.compress(b"inner")
    request = TlRequest(
        constructor_id=0,
        constructor="gzip_packed",
        req_msg_id=1,
        auth_key_id=1,
        session_id=1,
        payload={
            "packed_data": packed.hex(),
            "inner_request": {"constructor": "messages.getDialogs", "constructor_id": 456, "payload": {"limit": 20}},
        },
    )
    decoded = decode_service_request(request)
    assert decoded[0].constructor == "messages.getDialogs"


def test_invoke_with_layer_decode() -> None:
    request = TlRequest(
        constructor_id=0,
        constructor="invokeWithLayer",
        req_msg_id=777,
        auth_key_id=1,
        session_id=2,
        payload={
            "layer": 201,
            "query": {
                "_constructor": "help.getConfig",
                "constructor_id": 12345,
            },
        },
    )
    decoded = decode_service_request(request)
    assert len(decoded) == 1
    assert decoded[0].constructor == "help.getConfig"
    assert decoded[0].req_msg_id == 777
    assert decoded[0].invoke_layer == 201
    assert decoded[0].payload == {}


def test_init_connection_decode() -> None:
    request = TlRequest(
        constructor_id=0,
        constructor="initConnection",
        req_msg_id=778,
        auth_key_id=1,
        session_id=2,
        payload={
            "api_id": 1,
            "device_model": "test",
            "query": {
                "_constructor": "help.getConfig",
                "constructor_id": 12345,
                "lang_code": "en",
            },
        },
    )
    decoded = decode_service_request(request)
    assert len(decoded) == 1
    assert decoded[0].constructor == "help.getConfig"
    assert decoded[0].req_msg_id == 778
    assert decoded[0].payload == {"lang_code": "en"}


def test_msg_container_with_invoke_with_layer_decode() -> None:
    request = TlRequest(
        constructor_id=0,
        constructor="msg_container",
        req_msg_id=1,
        auth_key_id=1,
        session_id=1,
        payload={
            "messages": [
                {
                    "constructor": "invokeWithLayer",
                    "constructor_id": 54321,
                    "req_msg_id": 2,
                    "seq_no": 7,
                    "payload": {
                        "layer": 201,
                        "query": {
                            "_constructor": "help.getConfig",
                            "constructor_id": 12345,
                        },
                    },
                }
            ]
        },
    )

    decoded = decode_service_request(request)
    assert len(decoded) == 1
    assert decoded[0].constructor == "help.getConfig"
    assert decoded[0].req_msg_id == 2
    assert decoded[0].message_id == 2
    assert decoded[0].seq_no == 7
    assert decoded[0].invoke_layer == 201
    assert decoded[0].payload == {}


def test_msg_container_with_init_connection_decode() -> None:
    request = TlRequest(
        constructor_id=0,
        constructor="msg_container",
        req_msg_id=1,
        auth_key_id=1,
        session_id=1,
        payload={
            "messages": [
                {
                    "constructor": "initConnection",
                    "constructor_id": 65432,
                    "req_msg_id": 3,
                    "seq_no": 11,
                    "payload": {
                        "api_id": 1,
                        "device_model": "test",
                        "query": {
                            "_constructor": "help.getConfig",
                            "constructor_id": 12345,
                        },
                    },
                }
            ]
        },
    )

    decoded = decode_service_request(request)
    assert len(decoded) == 1
    assert decoded[0].constructor == "help.getConfig"
    assert decoded[0].req_msg_id == 3
    assert decoded[0].message_id == 3
    assert decoded[0].seq_no == 11
    assert decoded[0].payload == {}


def test_rpc_wrappers() -> None:
    ok = wrap_rpc_result(100, {"x": 1})
    err = wrap_rpc_error(101, 400, "BAD_REQUEST")
    assert ok.result["constructor"] == "rpc_result"
    assert err.result["result"]["constructor"] == "rpc_error"


def test_bind_temp_auth_key_returns_bool_true() -> None:
    ctx = ServiceContext()
    response = handle_control_message(
        ctx,
        TlRequest(
            constructor_id=0,
            constructor="auth.bindTempAuthKey",
            req_msg_id=99,
            auth_key_id=123,
            session_id=456,
            payload={},
        ),
    )
    assert response is not None
    assert response.result["constructor"] == "rpc_result"
    assert response.result["result"]["constructor"] == "boolTrue"
