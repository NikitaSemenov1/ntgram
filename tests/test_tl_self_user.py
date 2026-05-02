from __future__ import annotations

from ntgram.gateway.mtproto.service_semantics import wrap_rpc_result
from ntgram.gateway.tl_builders.users import build_self_user_tl
from ntgram.tl.codec import decode_tl_object, encode_tl_response


def test_build_self_user_tl_serializes() -> None:
    enc = encode_tl_response(
        wrap_rpc_result(
            1,
            build_self_user_tl(
                user_id=42,
                first_name="A",
                last_name="B",
                phone="+1",
            ),
        ),
    )
    name, fields = decode_tl_object(enc)
    assert name == "rpc_result"
    inner = fields["result"]
    assert inner["_constructor"] == "user"
    assert inner["self"] is True
    assert inner["id"] == 42
    assert inner["phone"] == "+1"
