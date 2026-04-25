from __future__ import annotations

import struct

from ntgram.tl.codec import (
    decode_tl_object,
    decode_tl_request,
    encode_tl_object,
    encode_tl_response,
    wrap_unencrypted,
)
from ntgram.tl.models import TlResponse
from ntgram.tl.registry import default_schema_registry
from ntgram.tl.serializer import (
    BOOL_FALSE_CONSTRUCTOR_ID,
    BOOL_TRUE_CONSTRUCTOR_ID,
    _Reader,
    _as_signed_int32,
    _write_int32,
    _write_int64,
    serialize_object,
)


_SCHEMA = default_schema_registry()


# ---------------------------------------------------------------------------
# Handshake constructors (mtproto.json)
# ---------------------------------------------------------------------------

def test_req_pq_multi_roundtrip() -> None:
    """Client -> server: req_pq_multi with int128 nonce."""
    nonce = 0xDEADBEEFCAFEBABE1234567890ABCDEF

    spec = _SCHEMA.methods_by_name["req_pq_multi"]
    body = _write_int32(spec.id) + nonce.to_bytes(16, "little")

    request = decode_tl_request(body)
    assert request.constructor == "req_pq_multi"
    assert request.payload["nonce"] == nonce


def test_resPQ_encode_decode() -> None:
    """Server -> client: resPQ with nonce, server_nonce, pq, fingerprints."""
    nonce = 0xAABBCCDDEEFF00112233445566778899
    server_nonce = 0x11223344556677889900AABBCCDDEEFF
    pq = (17 * 19).to_bytes(8, "big")
    fingerprint = 0xC3B42B026CE86B21

    encoded = serialize_object("resPQ", {
        "nonce": nonce,
        "server_nonce": server_nonce,
        "pq": pq,
        "server_public_key_fingerprints": [fingerprint],
    }, _SCHEMA)

    name, fields = decode_tl_object(encoded)
    assert name == "resPQ"
    assert fields["nonce"] == nonce
    assert fields["server_nonce"] == server_nonce
    assert fields["pq"] == pq
    assert fields["server_public_key_fingerprints"] == [fingerprint]


def test_rpc_error_roundtrip() -> None:
    """rpc_error: error_code(int) + error_message(string)."""
    encoded = encode_tl_object("rpc_error", {
        "error_code": 400,
        "error_message": "PHONE_NUMBER_INVALID",
    })
    name, fields = decode_tl_object(encoded)
    assert name == "rpc_error"
    assert fields["error_code"] == 400
    assert fields["error_message"] == "PHONE_NUMBER_INVALID"


def test_rpc_result_with_rpc_error() -> None:
    """rpc_result wrapping rpc_error (Object field)."""
    response = TlResponse(
        req_msg_id=0x100000004,
        result={
            "constructor": "rpc_result",
            "req_msg_id": 0x100000004,
            "result": {
                "constructor": "rpc_error",
                "error_code": 401,
                "error_message": "AUTH_KEY_INVALID",
            },
        },
    )
    encoded = encode_tl_response(response)

    reader = _Reader(encoded)
    cid = reader.read_int32()
    assert cid == _SCHEMA.constructors_by_name["rpc_result"].id

    req_msg_id = reader.read_int64()
    assert req_msg_id == 0x100000004

    inner_cid = reader.read_int32()
    assert inner_cid == _SCHEMA.constructors_by_name["rpc_error"].id

    error_code = reader.read_int32()
    assert error_code == 401

    error_message = reader.read_string()
    assert error_message == "AUTH_KEY_INVALID"


def test_pong_roundtrip() -> None:
    """pong: msg_id(long) + ping_id(long)."""
    encoded = encode_tl_object("pong", {"msg_id": 123456, "ping_id": 789012})
    name, fields = decode_tl_object(encoded)
    assert name == "pong"
    assert fields["msg_id"] == 123456
    assert fields["ping_id"] == 789012


def test_msgs_ack_roundtrip() -> None:
    """msgs_ack: Vector<long> msg_ids."""
    ids = [100, 200, 300]
    encoded = encode_tl_object("msgs_ack", {"msg_ids": ids})
    name, fields = decode_tl_object(encoded)
    assert name == "msgs_ack"
    assert fields["msg_ids"] == ids


def test_dh_gen_ok_roundtrip() -> None:
    """dh_gen_ok: nonce(int128) + server_nonce(int128) + new_nonce_hash1(int128)."""
    nonce = 0x1234567890ABCDEF1234567890ABCDEF
    sn = 0xFEDCBA9876543210FEDCBA9876543210
    nnh1 = 0xAAAABBBBCCCCDDDDEEEEFFFF00001111
    encoded = encode_tl_object("dh_gen_ok", {
        "nonce": nonce,
        "server_nonce": sn,
        "new_nonce_hash1": nnh1,
    })
    name, fields = decode_tl_object(encoded)
    assert name == "dh_gen_ok"
    assert fields["nonce"] == nonce
    assert fields["server_nonce"] == sn
    assert fields["new_nonce_hash1"] == nnh1


def test_server_DH_inner_data_roundtrip() -> None:
    """server_DH_inner_data: all fields including bytes (dh_prime, g_a)."""
    dh_prime = b"\x01" * 256
    g_a = b"\x02" * 256
    nonce = 0xAA
    server_nonce = 0xBB

    encoded = encode_tl_object("server_DH_inner_data", {
        "nonce": nonce,
        "server_nonce": server_nonce,
        "g": 3,
        "dh_prime": dh_prime,
        "g_a": g_a,
        "server_time": 1700000000,
    })
    name, fields = decode_tl_object(encoded)
    assert name == "server_DH_inner_data"
    assert fields["g"] == 3
    assert fields["dh_prime"] == dh_prime
    assert fields["g_a"] == g_a
    assert fields["server_time"] == 1700000000


# ---------------------------------------------------------------------------
# Unencrypted message wrapping
# ---------------------------------------------------------------------------

def test_unencrypted_message_wrap_unwrap() -> None:
    """Unencrypted MTProto message: auth_key_id=0 + msg_id + len + body."""
    nonce = 0x1234567890ABCDEF1234567890ABCDEF
    body = serialize_object("req_pq_multi", {"nonce": nonce}, _SCHEMA)
    msg_id = 0x5DEADBEEF0000001

    wrapped = wrap_unencrypted(msg_id, body)
    assert struct.unpack("<Q", wrapped[:8])[0] == 0
    assert struct.unpack("<q", wrapped[8:16])[0] == msg_id

    request = decode_tl_request(wrapped)
    assert request.constructor == "req_pq_multi"
    assert request.payload["nonce"] == nonce
    assert request.req_msg_id == msg_id


# ---------------------------------------------------------------------------
# Decode raw TL body (from encrypted layer)
# ---------------------------------------------------------------------------

def test_decode_raw_tl_body() -> None:
    """Decode a ping method from raw TL body (no unencrypted header)."""
    spec = _SCHEMA.methods_by_name["ping"]
    body = _write_int32(spec.id) + _write_int64(42)

    request = decode_tl_request(body)
    assert request.constructor == "ping"
    assert request.payload["ping_id"] == 42


def test_write_int32_accepts_unsigned_bool_constructor_ids() -> None:
    """Bool constructor ids are uint32 in schema and must pack as signed int32."""
    encoded_true = _write_int32(BOOL_TRUE_CONSTRUCTOR_ID)
    encoded_false = _write_int32(BOOL_FALSE_CONSTRUCTOR_ID)
    assert encoded_true == struct.pack("<i", _as_signed_int32(BOOL_TRUE_CONSTRUCTOR_ID))
    assert encoded_false == struct.pack("<i", _as_signed_int32(BOOL_FALSE_CONSTRUCTOR_ID))


def test_decode_msg_container_with_single_inner_message() -> None:
    """Decode msg_container containing one ping message."""
    ping_body = serialize_object("ping", {"ping_id": 42}, _SCHEMA)
    container_spec = _SCHEMA.constructors_by_name["msg_container"]
    message_id = 0x1122334455667788
    seqno = 1
    body = (
        _write_int32(container_spec.id)
        + _write_int32(1)
        + _write_int64(message_id)
        + _write_int32(seqno)
        + _write_int32(len(ping_body))
        + ping_body
    )

    request = decode_tl_request(body)
    assert request.constructor == "msg_container"
    messages = request.payload["messages"]
    assert isinstance(messages, list)
    assert len(messages) == 1
    assert messages[0]["constructor"] == "ping"
    assert messages[0]["req_msg_id"] == message_id
    assert messages[0]["payload"]["ping_id"] == 42


def test_langpack_get_languages_decode_empty_body() -> None:
    """Current official clients send ``langpack.getLanguages`` with ctor only (no params)."""
    spec = _SCHEMA.methods_by_name["langpack.getLanguages"]
    body = _write_int32(_as_signed_int32(spec.id))
    request = decode_tl_request(body)
    assert request.constructor == "langpack.getLanguages"
    assert request.payload == {}


# ---------------------------------------------------------------------------
# Generic object fallback for business logic
# ---------------------------------------------------------------------------

def test_rpc_result_with_generic_object() -> None:
    """rpc_result with an inner result that has no TL constructor
    uses the generic Object fallback."""
    response = TlResponse(
        req_msg_id=999,
        result={
            "constructor": "rpc_result",
            "req_msg_id": 999,
            "result": {"phone_code_hash": "abc123"},
        },
    )
    encoded = encode_tl_response(response)
    assert len(encoded) > 0


def test_error_only_response_encodes() -> None:
    """TlResponse with error_code and empty result generates rpc_error."""
    response = TlResponse(
        req_msg_id=100,
        result={},
        error_code=400,
        error_message="BAD_REQUEST",
    )
    encoded = encode_tl_response(response)
    name, fields = decode_tl_object(encoded)
    assert name == "rpc_result"
