from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

import pytest

pytest.importorskip("grpc")

from ntgram.gateway.grpc_clients.chat_client import ChatClient
from ntgram.gen import chat_pb2
from ntgram.services.common import ok_meta


def _client_with_chat_stub() -> tuple[ChatClient, AsyncMock]:
    stub = AsyncMock()
    return ChatClient(stub), stub


def test_send_message_returns_dto_with_actor_ubid_and_participants() -> None:
    from ntgram.gateway.route_outcome import MessageParticipant

    client, stub = _client_with_chat_stub()
    stub.SendMessage = AsyncMock(
        return_value=chat_pb2.SendMessageResponse(
            meta=ok_meta(),
            actor_user_message_box_id=42,
            pts=7,
            dialog_message_id=5001,
            date_unix=1700000000,
            participants=[
                chat_pb2.ParticipantDelivery(
                    user_id=1, user_message_box_id=42, pts=7,
                    dialog_id=2001, peer_id=2, is_group=False,
                ),
                chat_pb2.ParticipantDelivery(
                    user_id=2, user_message_box_id=11, pts=3,
                    dialog_id=2001, peer_id=1, is_group=False,
                ),
            ],
        ),
    )

    result = asyncio.run(
        client.send_message(
            actor_user_id=1, dialog_id=2001, text="hello", random_id=999,
        ),
    )

    assert result.actor_user_message_box_id == 42
    assert result.pts == 7
    assert result.date_unix == 1700000000
    assert {p.user_id for p in result.participants} == {1, 2}
    peer_p = next(p for p in result.participants if p.user_id == 2)
    assert isinstance(peer_p, MessageParticipant)
    assert peer_p.user_message_box_id == 11
    assert peer_p.pts == 3
    assert peer_p.is_group is False


def test_delete_messages_forwards_ids_and_revoke() -> None:
    """Client must forward the TL ``id`` vector + ``revoke`` flag verbatim."""
    client, stub = _client_with_chat_stub()
    stub.DeleteMessages = AsyncMock(
        return_value=chat_pb2.DeleteMessagesResponse(
            meta=ok_meta(), pts=12, pts_count=2, deleted_ids=[1, 2],
        ),
    )

    result = asyncio.run(
        client.delete_messages(
            actor_user_id=1,
            user_message_box_ids=[1, 2, 3],
            revoke=True,
        ),
    )

    assert result.pts == 12
    assert result.pts_count == 2
    assert result.deleted_ids == (1, 2)
    request = stub.DeleteMessages.await_args.args[0]
    assert list(request.user_message_box_ids) == [1, 2, 3]
    assert request.revoke is True


def test_edit_message_returns_dto() -> None:
    client, stub = _client_with_chat_stub()
    stub.EditMessage = AsyncMock(
        return_value=chat_pb2.EditMessageResponse(
            meta=ok_meta(),
            actor_user_message_box_id=42,
            dialog_message_id=5001,
            edit_date=1700000777,
        ),
    )

    result = asyncio.run(
        client.edit_message(
            actor_user_id=1,
            user_message_box_id=42,
            new_text="updated",
        ),
    )

    assert result.actor_user_message_box_id == 42
    assert result.dialog_message_id == 5001
    assert result.edit_date == 1700000777
    request = stub.EditMessage.await_args.args[0]
    assert request.new_text == "updated"
    assert request.user_message_box_id == 42


def test_read_history_returns_receipts_dto() -> None:
    from ntgram.gateway.route_outcome import ReadOutboxReceipt

    client, stub = _client_with_chat_stub()
    stub.ReadHistory = AsyncMock(
        return_value=chat_pb2.ReadHistoryResponse(
            meta=ok_meta(),
            pts=8,
            pts_count=1,
            receipts=[
                chat_pb2.ReadOutboxReceipt(
                    sender_user_id=2, sender_dialog_id=2001,
                    max_outbox_id=11, pts=4,
                ),
            ],
        ),
    )

    result = asyncio.run(
        client.read_history(actor_user_id=1, dialog_id=2001, max_id=0),
    )

    assert result.pts == 8
    assert result.pts_count == 1
    assert result.receipts == (
        ReadOutboxReceipt(
            sender_user_id=2,
            sender_dialog_id=2001,
            max_outbox_id=11,
            pts=4,
        ),
    )
