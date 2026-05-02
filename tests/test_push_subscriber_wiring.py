from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

from ntgram.gen import common_pb2
from ntgram.gateway.push_registry import PushSlot


def _make_slot(user_id: int = 20) -> PushSlot:
    return PushSlot(
        user_id=user_id,
        auth_key_id=12345,
        session_id=99,
    )


def _make_new_msg_envelope(
    *,
    message_id: int = 1,
    from_user_id: int = 10,
    peer_user_id: int = 20,
    text: str = "hello",
    pts: int = 5,
    date: int = 1700000000,
) -> common_pb2.UpdateEnvelope:
    return common_pb2.UpdateEnvelope(
        updates=[
            common_pb2.UpdateItem(
                new_message=common_pb2.UpdateNewMessage(
                    message_id=message_id,
                    from_user_id=from_user_id,
                    text=text,
                    date=date,
                    peer_user_id=peer_user_id,
                    out=False,
                    pts=pts,
                    pts_count=1,
                ),
            ),
        ],
        date=date,
        seq=0,
    )


def _make_subscribe_fn(envelope: common_pb2.UpdateEnvelope | None):
    """Return a fake subscribe that yields one envelope then blocks until cancelled."""
    async def _fake_subscribe(*, user_id, since_pts):
        if envelope is not None:
            yield envelope
        # Block until cancelled so the subscriber doesn't tight-loop.
        await asyncio.sleep(9999)

    return _fake_subscribe


async def _run_subscriber_once(
    slot: PushSlot,
    updates_client,
    account_client,
    chat_client,
) -> None:
    """Start subscriber task, let it process one envelope, then cancel."""
    from ntgram.gateway.push.subscriber import run_subscriber

    task = asyncio.create_task(
        run_subscriber(slot, updates_client, account_client, chat_client, since_pts=0)
    )
    for _ in range(20):
        await asyncio.sleep(0)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


def test_subscriber_puts_updates_with_users_into_queue() -> None:
    """Envelope with ``new_message`` → queue receives ``updates`` with users."""
    from ntgram.gateway.grpc_clients.dtos import ProfileDto

    slot = _make_slot(user_id=20)
    envelope = _make_new_msg_envelope(from_user_id=10, peer_user_id=20)

    updates_client = MagicMock()
    updates_client.subscribe = _make_subscribe_fn(envelope)

    account_client = MagicMock()
    account_client.get_profiles = AsyncMock(
        return_value=[
            ProfileDto(user_id=10, first_name="Alice", last_name="", bio="", username="alice"),
        ],
    )
    chat_client = MagicMock()

    asyncio.run(_run_subscriber_once(slot, updates_client, account_client, chat_client))

    assert not slot.queue.empty(), "expected at least one update in queue"
    update = slot.queue.get_nowait()
    assert update["constructor"] == "updates", f"wrong constructor: {update.get('constructor')}"
    assert len(update["updates"]) == 1
    assert update["updates"][0]["constructor"] == "updateNewMessage"
    users = update["users"]
    assert len(users) == 1, f"expected 1 user, got {len(users)}"
    assert users[0]["id"] == 10


def test_subscriber_queue_empty_for_unknown_update_type() -> None:
    """Envelope with no mappable items does not pollute the queue."""
    slot = _make_slot(user_id=20)

    # UpdateEnvelope with an item that has no recognised oneof variant.
    empty_envelope = common_pb2.UpdateEnvelope(
        updates=[common_pb2.UpdateItem()],
        date=1700000000,
        seq=0,
    )

    updates_client = MagicMock()
    updates_client.subscribe = _make_subscribe_fn(empty_envelope)

    account_client = MagicMock()
    account_client.get_profiles = AsyncMock(return_value=[])
    chat_client = MagicMock()

    asyncio.run(_run_subscriber_once(slot, updates_client, account_client, chat_client))

    assert slot.queue.empty(), "queue should be empty for unknown update types"


def test_subscriber_chat_id_fetches_chat_tl() -> None:
    """Envelope with ``peer_chat_id`` triggers chat lookup and embeds chat TL."""
    from ntgram.gateway.grpc_clients.dtos import GetFullChatResult, ProfileDto

    slot = _make_slot(user_id=20)

    envelope = common_pb2.UpdateEnvelope(
        updates=[
            common_pb2.UpdateItem(
                new_message=common_pb2.UpdateNewMessage(
                    message_id=1,
                    from_user_id=10,
                    text="group msg",
                    date=1700000000,
                    peer_chat_id=999,
                    out=False,
                    pts=3,
                    pts_count=1,
                ),
            ),
        ],
        date=1700000000,
        seq=0,
    )

    updates_client = MagicMock()
    updates_client.subscribe = _make_subscribe_fn(envelope)

    account_client = MagicMock()
    account_client.get_profiles = AsyncMock(
        return_value=[
            ProfileDto(user_id=10, first_name="Alice", last_name="", bio="", username="alice"),
        ],
    )

    chat_client = MagicMock()
    chat_client.get_full_chat = AsyncMock(
        return_value=GetFullChatResult(
            chat_id=999,
            title="Test Group",
            creator_id=10,
            member_user_ids=(10, 20),
            ok=True,
        ),
    )

    asyncio.run(_run_subscriber_once(slot, updates_client, account_client, chat_client))

    assert not slot.queue.empty()
    update = slot.queue.get_nowait()
    assert update["constructor"] == "updates"
    chats = update["chats"]
    assert len(chats) == 1
    assert chats[0]["id"] == 999
    assert chats[0]["title"] == "Test Group"
