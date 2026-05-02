from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

import pytest

from ntgram.errors import RpcFailure

pytest.importorskip("grpc")

from ntgram.gateway.grpc_clients._meta import (
    int64_from_tl_long,
    phone_from_payload,
)
from ntgram.gateway.grpc_clients.account_client import AccountClient
from ntgram.gen import account_pb2
from ntgram.services.common import err_meta, ok_meta


def _client_with_account_stub() -> tuple[AccountClient, AsyncMock]:
    stub = AsyncMock()
    return AccountClient(stub), stub


def test_send_code_returns_phone_code_hash_dto() -> None:
    client, stub = _client_with_account_stub()
    stub.SendCode = AsyncMock(
        return_value=account_pb2.SendCodeResponse(
            meta=ok_meta(), phone_code_hash="hash",
        ),
    )

    result = asyncio.run(client.send_code("+10000000000"))
    assert result.phone_code_hash == "hash"
    request = stub.SendCode.await_args.args[0]
    assert request.phone == "+10000000000"


def test_phone_from_payload_rejects_missing() -> None:
    with pytest.raises(RpcFailure) as exc:
        phone_from_payload({})
    assert exc.value.message == "PHONE_NUMBER_INVALID"


def test_phone_from_payload_accepts_phone_number_or_phone() -> None:
    assert phone_from_payload({"phone_number": "+1"}) == "+1"
    assert phone_from_payload({"phone": "+2"}) == "+2"


def test_cancel_code_passes_through_phone_and_hash() -> None:
    client, stub = _client_with_account_stub()
    stub.CancelCode = AsyncMock(
        return_value=account_pb2.CancelCodeResponse(meta=ok_meta()),
    )

    asyncio.run(client.cancel_code(phone="79248732269", phone_code_hash="h"))
    req = stub.CancelCode.await_args.args[0]
    assert req.phone == "79248732269"
    assert req.phone_code_hash == "h"


def test_sign_in_returns_user_id_and_phone_dto() -> None:
    client, stub = _client_with_account_stub()
    stub.SignIn = AsyncMock(
        return_value=account_pb2.SignInResponse(
            meta=ok_meta(), user_id=123, is_new_user=False,
        ),
    )

    result = asyncio.run(
        client.sign_in(
            phone="+10000000000",
            phone_code_hash="hash",
            phone_code="111111",
        ),
    )
    assert result.user_id == 123
    assert result.phone == "+10000000000"
    request = stub.SignIn.await_args.args[0]
    assert request.phone == "+10000000000"
    assert request.phone_code == "111111"


def test_sign_in_propagates_account_rpc_failure() -> None:
    client, stub = _client_with_account_stub()
    stub.SignIn = AsyncMock(
        return_value=account_pb2.SignInResponse(
            meta=err_meta(400, "PHONE_CODE_INVALID"),
            user_id=0,
            is_new_user=False,
        ),
    )

    with pytest.raises(RpcFailure) as excinfo:
        asyncio.run(
            client.sign_in(
                phone="+10000000000",
                phone_code_hash="hash",
                phone_code="000000",
            ),
        )
    assert excinfo.value.message == "PHONE_CODE_INVALID"


def test_sign_up_passes_hash_and_returns_dto() -> None:
    client, stub = _client_with_account_stub()
    stub.SignUp = AsyncMock(
        return_value=account_pb2.SignUpResponse(meta=ok_meta(), user_id=456),
    )

    result = asyncio.run(
        client.sign_up(
            phone="+10000000000",
            phone_code_hash="hash",
            first_name="Test",
            last_name="User",
        ),
    )
    assert result.user_id == 456
    assert result.first_name == "Test"
    assert result.last_name == "User"
    request = stub.SignUp.await_args.args[0]
    assert request.phone_code_hash == "hash"
    assert request.phone_code == ""  # never re-sent after signIn verification


def test_int64_from_tl_long_fits_protobuf_signed_int64() -> None:
    assert int64_from_tl_long(0) == 0
    assert int64_from_tl_long(2**63 - 1) == 2**63 - 1
    assert int64_from_tl_long(2**63) == -(2**63)
    assert int64_from_tl_long(17908354546386486738) == 17908354546386486738 - 2**64


def test_get_user_tolerates_non_ok_meta() -> None:
    client, stub = _client_with_account_stub()
    stub.GetUser = AsyncMock(
        return_value=account_pb2.GetUserResponse(
            meta=err_meta(404, "USER_NOT_FOUND"),
        ),
    )

    result = asyncio.run(client.get_user(7))
    assert result.ok is False
    assert result.user_id == 7
    assert result.phone == ""
    assert result.username == ""
