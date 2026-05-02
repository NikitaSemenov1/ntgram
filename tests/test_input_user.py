from __future__ import annotations

import pytest

from ntgram.errors import RpcFailure
from ntgram.gateway.mtproto.input_user import resolve_input_user_id


def test_resolve_input_user_self() -> None:
    assert resolve_input_user_id(42, {"_constructor": "inputUserSelf"}) == 42


def test_resolve_input_user_by_id() -> None:
    assert resolve_input_user_id(
        1,
        {"_constructor": "inputUser", "user_id": 99, "access_hash": 1},
    ) == 99


def test_resolve_requires_positive_actor_for_self() -> None:
    with pytest.raises(RpcFailure) as exc:
        resolve_input_user_id(0, {"_constructor": "inputUserSelf"})
    assert exc.value.code == 401


@pytest.mark.parametrize(
    "raw",
    [
        {"_constructor": "inputUserEmpty"},
        {"_constructor": "inputUserFromMessage", "peer": {}, "msg_id": 1, "user_id": 1},
        {},
        {"_constructor": "inputUser", "user_id": 0},
    ],
)
def test_resolve_invalid(raw: dict) -> None:
    with pytest.raises(RpcFailure) as exc:
        resolve_input_user_id(1, raw)
    assert exc.value.code == 400
