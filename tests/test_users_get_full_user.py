from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from ntgram.errors import RpcFailure
from ntgram.gateway.mtproto.service_semantics import wrap_rpc_result
from ntgram.gateway.tl_builders.users import build_users_user_full
from ntgram.tl.codec import decode_tl_object, encode_tl_response


def test_build_users_user_full_serializes() -> None:
    payload = build_users_user_full(
        peer_id=7,
        actor_user_id=2,
        first_name="Fn",
        last_name="Ln",
        bio="about text",
        phone=None,
        username="peerlogin",
    )
    enc = encode_tl_response(wrap_rpc_result(1, payload))
    name, fields = decode_tl_object(enc)
    assert name == "rpc_result"
    inner = fields["result"]
    assert inner["_constructor"] == "users.userFull"
    assert inner["full_user"]["_constructor"] == "userFull"
    assert inner["full_user"]["id"] == 7
    assert inner["full_user"]["about"] == "about text"
    assert inner["users"][0]["id"] == 7
    assert inner["users"][0].get("self") is None
    assert inner["users"][0]["username"] == "peerlogin"


@pytest.mark.asyncio
async def test_account_client_get_full_user_calls_account_service() -> None:
    pytest.importorskip("grpc")
    from ntgram.gateway.grpc_clients.account_client import AccountClient
    from ntgram.gen import account_pb2
    from ntgram.services.common import ok_meta

    stub = AsyncMock()
    stub.GetFullUser = AsyncMock(
        return_value=account_pb2.GetFullUserResponse(
            meta=ok_meta(),
            user_id=3,
            first_name="A",
            last_name="B",
            bio="x",
            is_self=False,
            phone="",
            common_chats_count=0,
            username="u_three",
        ),
    )
    client = AccountClient(stub)

    result = await client.get_full_user(actor_user_id=1, target_user_id=3)

    assert result.user_id == 3
    assert result.username == "u_three"
    assert result.is_self is False
    stub.GetFullUser.assert_awaited_once()
    call_kw = stub.GetFullUser.call_args[0][0]
    assert call_kw.actor_user_id == 1
    assert call_kw.target_user_id == 3


@pytest.mark.asyncio
async def test_account_client_update_profile_returns_dto() -> None:
    pytest.importorskip("grpc")
    from ntgram.gateway.grpc_clients.account_client import AccountClient
    from ntgram.gen import account_pb2
    from ntgram.services.common import ok_meta

    stub = AsyncMock()
    stub.UpdateProfile = AsyncMock(
        return_value=account_pb2.UpdateProfileResponse(
            meta=ok_meta(),
            profile=account_pb2.Profile(
                user_id=5,
                first_name="F0",
                last_name="L0",
                bio="new",
            ),
        ),
    )
    client = AccountClient(stub)

    result = await client.update_profile(
        actor_user_id=5, first_name="F0", last_name="L0", bio="new",
    )
    assert result.profile.user_id == 5
    assert result.profile.first_name == "F0"
    assert result.profile.last_name == "L0"
    assert result.profile.bio == "new"
    up = stub.UpdateProfile.call_args[0][0]
    assert up.first_name == "F0"
    assert up.last_name == "L0"
    assert up.bio == "new"


@pytest.mark.asyncio
async def test_account_client_update_profile_bio_too_long_maps_about_error() -> None:
    pytest.importorskip("grpc")
    from ntgram.gateway.grpc_clients.account_client import AccountClient
    from ntgram.gen import account_pb2
    from ntgram.services.common import err_meta

    stub = AsyncMock()
    stub.UpdateProfile = AsyncMock(
        return_value=account_pb2.UpdateProfileResponse(
            meta=err_meta(400, "BIO_TOO_LONG"),
        ),
    )
    client = AccountClient(stub)

    with pytest.raises(RpcFailure) as ei:
        await client.update_profile(
            actor_user_id=1, first_name="a", last_name="b", bio="x" * 200,
        )
    assert ei.value.message == "ABOUT_TOO_LONG"
