from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from ntgram.tl.codec import decode_tl_object, encode_tl_response
from ntgram.tl.models import TlRequest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_request(
    constructor: str,
    payload: dict,
    req_msg_id: int = 1,
    auth_key_id: int = 0,
    session_id: int = 1,
) -> TlRequest:
    return TlRequest(
        constructor_id=0,
        constructor=constructor,
        req_msg_id=req_msg_id,
        auth_key_id=auth_key_id,
        session_id=session_id,
        payload=payload,
    )


def _decode_result(response) -> dict:
    encoded = encode_tl_response(response)
    name, fields = decode_tl_object(encoded)
    assert name == "rpc_result"
    return fields["result"]


def _make_router(grpc_clients, *, user_id: int = 42):
    pytest.importorskip("grpc")
    from ntgram.gateway.mtproto.session_store import SessionStore
    from ntgram.gateway.router import GatewayRouter

    sessions = SessionStore()
    session = sessions.complete_handshake(
        session_id=1, auth_key=b"k" * 256, new_nonce=1, server_nonce=2,
    )
    sessions.bind_user(session.auth_key_id, user_id)
    router = GatewayRouter(grpc_clients=grpc_clients, sessions=sessions)
    return router, session.auth_key_id


def _make_pts_update_row(update_type: str, update_data: dict, pts: int = 5, date: int = 1700000000):
    """Build a PtsUpdateRow using full TL Update dict shapes (new format)."""
    from ntgram.gateway.grpc_clients.dtos import PtsUpdateRow
    return PtsUpdateRow(pts=pts, update_type=update_type, update_data=update_data, date=date)


def _new_message_update_data(
    *,
    message_id: int = 7,
    from_user_id: int = 10,
    peer_id: int = 20,
    is_group: bool = False,
    out: bool = False,
    text: str = "hello",
    date: int = 1700000000,
    pts: int = 5,
) -> dict:
    """Build a full TL updateNewMessage dict (new update_data shape)."""
    from ntgram.tl.builders.updates import build_message_tl, build_update_new_message, peer_chat, peer_user
    peer_tl = peer_chat(peer_id) if is_group else peer_user(peer_id)
    msg = build_message_tl(
        message_id=message_id, from_user_id=from_user_id, date=date,
        text=text, peer_id_tl=peer_tl, out=out,
    )
    return build_update_new_message(message=msg, pts=pts)


def _read_outbox_update_data(*, peer_user_id: int = 10, max_id: int = 2, pts: int = 9) -> dict:
    from ntgram.tl.builders.updates import build_update_read_history_outbox
    return build_update_read_history_outbox(peer_user_id=peer_user_id, max_id=max_id, pts=pts)


def _read_inbox_update_data(*, peer_user_id: int = 10, max_id: int = 1, still_unread: int = 0, pts: int = 8) -> dict:
    from ntgram.tl.builders.updates import build_update_read_history_inbox
    return build_update_read_history_inbox(peer_user_id=peer_user_id, max_id=max_id, still_unread=still_unread, pts=pts)


# ---------------------------------------------------------------------------
# handle_get_state
# ---------------------------------------------------------------------------


def test_get_state_includes_constructor_and_unread_count() -> None:
    from ntgram.gateway.grpc_clients.dtos import UpdatesState

    grpc_clients = MagicMock()
    grpc_clients.updates.get_state = AsyncMock(
        return_value=UpdatesState(pts=7, qts=0, seq=1, date=1700000000),
    )

    router, auth_key_id = _make_router(grpc_clients)
    request = _make_request("updates.getState", {}, req_msg_id=10, auth_key_id=auth_key_id)

    result = _decode_result(asyncio.run(router.dispatch(request)))

    assert result["_constructor"] == "updates.state"
    assert "unread_count" in result
    assert result["pts"] == 7
    assert result["seq"] == 1


def test_get_state_grpc_error_returns_rpc_error() -> None:
    """C2: gRPC errors must produce rpc_error, not silently zero out state."""
    grpc_clients = MagicMock()
    grpc_clients.updates.get_state = AsyncMock(side_effect=Exception("rpc error"))

    router, auth_key_id = _make_router(grpc_clients)
    result = _decode_result(asyncio.run(router.dispatch(
        _make_request("updates.getState", {}, req_msg_id=11, auth_key_id=auth_key_id)
    )))

    # C2: should return rpc_error (500), not a zeroed updates.state.
    assert result["_constructor"] == "rpc_error"
    assert result.get("error_code") == 500


# ---------------------------------------------------------------------------
# handle_get_difference — empty branch
# ---------------------------------------------------------------------------


def test_get_difference_empty_returns_difference_empty() -> None:
    from ntgram.gateway.grpc_clients.dtos import UpdatesDifferenceEmpty

    grpc_clients = MagicMock()
    grpc_clients.updates.get_difference = AsyncMock(
        return_value=UpdatesDifferenceEmpty(date=1700000000, seq=3),
    )

    router, auth_key_id = _make_router(grpc_clients)
    result = _decode_result(asyncio.run(router.dispatch(
        _make_request("updates.getDifference", {"pts": 5}, req_msg_id=20, auth_key_id=auth_key_id)
    )))

    assert result["_constructor"] == "updates.differenceEmpty"
    assert result["seq"] == 3


# ---------------------------------------------------------------------------
# handle_get_difference — non-empty shape
# ---------------------------------------------------------------------------


def test_get_difference_nonempty_has_correct_shape() -> None:
    """Non-empty updates.difference must have all required vectors + state."""
    from ntgram.gateway.grpc_clients.dtos import UpdatesDifference, UpdatesState

    row = _make_pts_update_row("updateNewMessage", _new_message_update_data())
    grpc_clients = MagicMock()
    grpc_clients.updates.get_difference = AsyncMock(
        return_value=UpdatesDifference(
            state=UpdatesState(pts=6, qts=0, seq=1, date=1700000001),
            raw_updates=(row,),
        ),
    )
    grpc_clients.account.get_profiles = AsyncMock(return_value=[])
    grpc_clients.chat.get_full_chat = AsyncMock(side_effect=Exception("no chat"))

    router, auth_key_id = _make_router(grpc_clients, user_id=42)
    result = _decode_result(asyncio.run(router.dispatch(
        _make_request("updates.getDifference", {"pts": 3}, req_msg_id=30, auth_key_id=auth_key_id)
    )))

    assert result["_constructor"] == "updates.difference"
    for key in ("new_messages", "new_encrypted_messages", "other_updates", "chats", "users"):
        assert key in result

    state = result["state"]
    assert state["_constructor"] == "updates.state"
    assert "unread_count" in state
    assert state["pts"] == 6


# ---------------------------------------------------------------------------
# new_messages vs other_updates split
# ---------------------------------------------------------------------------


def test_get_difference_new_message_in_new_messages_not_other_updates() -> None:
    """updateNewMessage → Message in new_messages; other_updates empty."""
    from ntgram.gateway.grpc_clients.dtos import UpdatesDifference, UpdatesState

    row = _make_pts_update_row(
        "updateNewMessage",
        _new_message_update_data(message_id=7, from_user_id=10, peer_id=20, text="test msg"),
        pts=8,
    )
    grpc_clients = MagicMock()
    grpc_clients.updates.get_difference = AsyncMock(
        return_value=UpdatesDifference(
            state=UpdatesState(pts=8, qts=0, seq=0, date=1700000000),
            raw_updates=(row,),
        ),
    )
    grpc_clients.account.get_profiles = AsyncMock(return_value=[])
    grpc_clients.chat.get_full_chat = AsyncMock(side_effect=Exception)

    router, auth_key_id = _make_router(grpc_clients, user_id=42)
    result = _decode_result(asyncio.run(router.dispatch(
        _make_request("updates.getDifference", {"pts": 5}, req_msg_id=31, auth_key_id=auth_key_id)
    )))

    assert len(result["new_messages"]) == 1
    msg = result["new_messages"][0]
    assert msg["_constructor"] == "message"
    assert msg["id"] == 7
    assert msg["message"] == "test msg"
    assert msg["from_id"]["user_id"] == 10
    assert msg["peer_id"]["user_id"] == 20

    assert len(result["other_updates"]) == 0


def test_get_difference_read_outbox_in_other_updates() -> None:
    """updateReadHistoryOutbox → Update in other_updates; new_messages empty."""
    from ntgram.gateway.grpc_clients.dtos import UpdatesDifference, UpdatesState

    row = _make_pts_update_row("updateReadHistoryOutbox", _read_outbox_update_data(peer_user_id=10, max_id=2), pts=9)
    grpc_clients = MagicMock()
    grpc_clients.updates.get_difference = AsyncMock(
        return_value=UpdatesDifference(
            state=UpdatesState(pts=9, qts=0, seq=0, date=1700000000),
            raw_updates=(row,),
        ),
    )
    grpc_clients.account.get_profiles = AsyncMock(return_value=[])
    grpc_clients.chat.get_full_chat = AsyncMock(side_effect=Exception)

    router, auth_key_id = _make_router(grpc_clients, user_id=42)
    result = _decode_result(asyncio.run(router.dispatch(
        _make_request("updates.getDifference", {"pts": 5}, req_msg_id=32, auth_key_id=auth_key_id)
    )))

    assert len(result["new_messages"]) == 0
    assert len(result["other_updates"]) == 1
    upd = result["other_updates"][0]
    assert upd["_constructor"] == "updateReadHistoryOutbox"
    assert upd["peer"]["user_id"] == 10
    assert upd["max_id"] == 2


def test_get_difference_state_date_uses_now() -> None:
    """updates.difference state.date must be int(time.time()), not diff.state.date."""
    from ntgram.gateway.grpc_clients.dtos import UpdatesDifference, UpdatesState

    old_date = 1600000000
    row = _make_pts_update_row("updateNewMessage", _new_message_update_data(date=old_date))
    grpc_clients = MagicMock()
    grpc_clients.updates.get_difference = AsyncMock(
        return_value=UpdatesDifference(
            state=UpdatesState(pts=6, qts=0, seq=1, date=old_date),
            raw_updates=(row,),
        ),
    )
    grpc_clients.account.get_profiles = AsyncMock(return_value=[])
    grpc_clients.chat.get_full_chat = AsyncMock(side_effect=Exception)

    router, auth_key_id = _make_router(grpc_clients, user_id=42)
    before = int(time.time())
    result = _decode_result(asyncio.run(router.dispatch(
        _make_request("updates.getDifference", {"pts": 3}, req_msg_id=33, auth_key_id=auth_key_id)
    )))
    after = int(time.time())

    state_date = result["state"]["date"]
    assert before <= state_date <= after + 1, (
        f"state.date={state_date} should be close to now, not old_date={old_date}"
    )


# ---------------------------------------------------------------------------
# Peer enrichment
# ---------------------------------------------------------------------------


def test_get_difference_enriches_users() -> None:
    from ntgram.gateway.grpc_clients.dtos import ProfileDto, UpdatesDifference, UpdatesState

    row = _make_pts_update_row("updateNewMessage", _new_message_update_data(from_user_id=10, peer_id=42), pts=10)
    grpc_clients = MagicMock()
    grpc_clients.updates.get_difference = AsyncMock(
        return_value=UpdatesDifference(
            state=UpdatesState(pts=10, qts=0, seq=0, date=1700000000),
            raw_updates=(row,),
        ),
    )
    grpc_clients.account.get_profiles = AsyncMock(
        return_value=[ProfileDto(user_id=10, first_name="Alice", last_name="", bio="", username="alice")],
    )
    grpc_clients.chat.get_full_chat = AsyncMock(side_effect=Exception)

    router, auth_key_id = _make_router(grpc_clients, user_id=42)
    result = _decode_result(asyncio.run(router.dispatch(
        _make_request("updates.getDifference", {"pts": 7}, req_msg_id=40, auth_key_id=auth_key_id)
    )))

    users = result["users"]
    assert len(users) == 1, f"expected 1 user, got {users}"
    assert users[0]["id"] == 10


def test_get_difference_enriches_chats() -> None:
    from ntgram.gateway.grpc_clients.dtos import GetFullChatResult, UpdatesDifference, UpdatesState

    row = _make_pts_update_row(
        "updateNewMessage",
        _new_message_update_data(from_user_id=10, peer_id=999, is_group=True),
        pts=11,
    )
    grpc_clients = MagicMock()
    grpc_clients.updates.get_difference = AsyncMock(
        return_value=UpdatesDifference(
            state=UpdatesState(pts=11, qts=0, seq=0, date=1700000000),
            raw_updates=(row,),
        ),
    )
    grpc_clients.account.get_profiles = AsyncMock(return_value=[])
    grpc_clients.chat.get_full_chat = AsyncMock(
        return_value=GetFullChatResult(chat_id=999, title="My Group", creator_id=10, member_user_ids=(10, 42), ok=True),
    )

    router, auth_key_id = _make_router(grpc_clients, user_id=42)
    result = _decode_result(asyncio.run(router.dispatch(
        _make_request("updates.getDifference", {"pts": 8}, req_msg_id=41, auth_key_id=auth_key_id)
    )))

    chats = result["chats"]
    assert len(chats) == 1
    assert chats[0]["id"] == 999
    assert chats[0]["title"] == "My Group"


# ---------------------------------------------------------------------------
# _pts_update_to_message_tl unit tests (new full-JSON shape)
# ---------------------------------------------------------------------------


def test_pts_update_to_message_tl_new_message() -> None:
    """updateNewMessage row must yield the embedded Message TL dict."""
    from ntgram.gateway.grpc_clients.dtos import PtsUpdateRow
    from ntgram.gateway.handlers.updates_handlers import _pts_update_to_message_tl

    update_data = _new_message_update_data(message_id=1, from_user_id=10, peer_id=20, out=True, pts=3)
    row = PtsUpdateRow(pts=3, update_type="updateNewMessage", update_data=update_data, date=1700000000)

    msg = _pts_update_to_message_tl(row)
    assert msg is not None
    assert msg["constructor"] == "message"
    assert msg["id"] == 1
    assert msg["peer_id"]["user_id"] == 20
    assert msg.get("out") is True, "out true-flag must be set"


def test_pts_update_to_message_tl_read_outbox_returns_none() -> None:
    from ntgram.gateway.grpc_clients.dtos import PtsUpdateRow
    from ntgram.gateway.handlers.updates_handlers import _pts_update_to_message_tl

    row = PtsUpdateRow(pts=4, update_type="updateReadHistoryOutbox",
                       update_data=_read_outbox_update_data(), date=1700000000)
    assert _pts_update_to_message_tl(row) is None


def test_pts_update_to_message_tl_group_message_uses_peer_chat() -> None:
    from ntgram.gateway.grpc_clients.dtos import PtsUpdateRow
    from ntgram.gateway.handlers.updates_handlers import _pts_update_to_message_tl

    update_data = _new_message_update_data(peer_id=555, is_group=True)
    row = PtsUpdateRow(pts=6, update_type="updateNewMessage", update_data=update_data, date=1700000000)
    msg = _pts_update_to_message_tl(row)
    assert msg is not None
    assert msg["peer_id"]["constructor"] == "peerChat"
    assert msg["peer_id"]["chat_id"] == 555


# ---------------------------------------------------------------------------
# _pts_update_to_other_update_tl unit tests (new full-JSON shape)
# ---------------------------------------------------------------------------


def test_pts_update_to_other_update_tl_read_outbox() -> None:
    from ntgram.gateway.grpc_clients.dtos import PtsUpdateRow
    from ntgram.gateway.handlers.updates_handlers import _pts_update_to_other_update_tl

    update_data = _read_outbox_update_data(peer_user_id=10, max_id=2, pts=4)
    row = PtsUpdateRow(pts=4, update_type="updateReadHistoryOutbox", update_data=update_data, date=1700000000)
    tl = _pts_update_to_other_update_tl(row)
    assert tl is not None
    assert tl["constructor"] == "updateReadHistoryOutbox"
    assert tl["peer"]["user_id"] == 10
    assert tl["max_id"] == 2
    assert tl["pts"] == 4


def test_pts_update_to_other_update_tl_new_message_returns_none() -> None:
    from ntgram.gateway.grpc_clients.dtos import PtsUpdateRow
    from ntgram.gateway.handlers.updates_handlers import _pts_update_to_other_update_tl

    row = PtsUpdateRow(pts=3, update_type="updateNewMessage",
                       update_data=_new_message_update_data(), date=1700000000)
    assert _pts_update_to_other_update_tl(row) is None


def test_pts_update_to_other_update_tl_unknown_returns_none() -> None:
    from ntgram.gateway.grpc_clients.dtos import PtsUpdateRow
    from ntgram.gateway.handlers.updates_handlers import _pts_update_to_other_update_tl

    row = PtsUpdateRow(pts=5, update_type="updateSomeUnknown",
                       update_data={"foo": "bar"}, date=1700000000)
    assert _pts_update_to_other_update_tl(row) is None
