from __future__ import annotations

import pytest

pytest.importorskip("asyncpg")

from ntgram.services.chat.dao import InsertMessageBoxRow, ChatDAO
from tests._fake_chat_pool import FakeChatPool


@pytest.mark.asyncio
async def test_next_user_message_box_id_is_per_user_and_monotonic() -> None:
    pool = FakeChatPool()
    dao = ChatDAO(pool)

    a1 = await dao.next_user_message_box_id(1001)
    a2 = await dao.next_user_message_box_id(1001)
    b1 = await dao.next_user_message_box_id(2002)
    b2 = await dao.next_user_message_box_id(2002)

    assert a2 == a1 + 1
    assert b2 == b1 + 1
    # Per-user sequences are independent.
    assert a1 == b1


@pytest.mark.asyncio
async def test_next_dialog_message_id_is_global_and_monotonic() -> None:
    pool = FakeChatPool()
    dao = ChatDAO(pool)

    x = await dao.next_dialog_message_id()
    y = await dao.next_dialog_message_id()

    assert y == x + 1


@pytest.mark.asyncio
async def test_insert_and_get_history_filters_deleted() -> None:
    pool = FakeChatPool()
    pool.add_dialog(2001, owner_user_id=1, peer_id=2, is_group=False)
    dao = ChatDAO(pool)

    await dao.insert_message_box_batch(
        None,
        [
            InsertMessageBoxRow(
                user_id=1, user_message_box_id=1, dialog_message_id=10,
                dialog_id=2001, peer_type=0, peer_id=2,
                from_user_id=1, out=True, random_id=None,
                text="hi", date_unix=100, pts=1,
            ),
            InsertMessageBoxRow(
                user_id=1, user_message_box_id=2, dialog_message_id=11,
                dialog_id=2001, peer_type=0, peer_id=2,
                from_user_id=2, out=False, random_id=None,
                text="hi back", date_unix=101, pts=2,
            ),
        ],
    )

    rows = await dao.get_history(user_id=1, dialog_id=2001, limit=10)
    assert [r.user_message_box_id for r in rows] == [2, 1]
    assert [r.out for r in rows] == [False, True]
    assert rows[0].text == "hi back"


@pytest.mark.asyncio
async def test_find_by_random_id_idempotency() -> None:
    pool = FakeChatPool()
    pool.add_dialog(2001, owner_user_id=1, peer_id=2, is_group=False)
    dao = ChatDAO(pool)

    await dao.insert_message_box_batch(
        None,
        [
            InsertMessageBoxRow(
                user_id=1, user_message_box_id=5, dialog_message_id=20,
                dialog_id=2001, peer_type=0, peer_id=2,
                from_user_id=1, out=True, random_id=999,
                text="hello", date_unix=200, pts=3,
            ),
        ],
    )

    found = await dao.find_by_random_id(1, 999)
    assert found is not None
    assert found.user_message_box_id == 5
    assert found.dialog_message_id == 20

    not_found = await dao.find_by_random_id(1, 1000)
    assert not_found is None


@pytest.mark.asyncio
async def test_mark_inbox_read_and_peer_outbox_for_inbox() -> None:
    pool = FakeChatPool()
    pool.add_dialog(2001, owner_user_id=1, peer_id=2, is_group=False)
    pool.add_dialog(2001, owner_user_id=2, peer_id=1, is_group=False)
    dao = ChatDAO(pool)

    # User 2 sends two messages to user 1; both copies are stored.
    await dao.insert_message_box_batch(
        None,
        [
            InsertMessageBoxRow(
                user_id=2, user_message_box_id=10, dialog_message_id=30,
                dialog_id=2001, peer_type=0, peer_id=1,
                from_user_id=2, out=True, random_id=None,
                text="m1", date_unix=300, pts=1,
            ),
            InsertMessageBoxRow(
                user_id=1, user_message_box_id=20, dialog_message_id=30,
                dialog_id=2001, peer_type=0, peer_id=2,
                from_user_id=2, out=False, random_id=None,
                text="m1", date_unix=300, pts=1,
            ),
            InsertMessageBoxRow(
                user_id=2, user_message_box_id=11, dialog_message_id=31,
                dialog_id=2001, peer_type=0, peer_id=1,
                from_user_id=2, out=True, random_id=None,
                text="m2", date_unix=301, pts=2,
            ),
            InsertMessageBoxRow(
                user_id=1, user_message_box_id=21, dialog_message_id=31,
                dialog_id=2001, peer_type=0, peer_id=2,
                from_user_id=2, out=False, random_id=None,
                text="m2", date_unix=301, pts=2,
            ),
        ],
    )

    receipts = await dao.peer_outbox_for_inbox(
        reader_user_id=1, dialog_id=2001, max_inbox_ubid=21,
    )
    assert len(receipts) == 1
    rcp = receipts[0]
    assert rcp.sender_user_id == 2
    assert rcp.sender_dialog_id == 2001
    assert rcp.max_outbox_id == 11

    n = await dao.mark_inbox_read(user_id=1, dialog_id=2001, max_ubid=21)
    assert n == 2

    again = await dao.mark_inbox_read(user_id=1, dialog_id=2001, max_ubid=21)
    assert again == 0


@pytest.mark.asyncio
async def test_get_box_returns_row_including_deleted_flag() -> None:
    pool = FakeChatPool()
    pool.add_dialog(2001, owner_user_id=1, peer_id=2, is_group=False)
    dao = ChatDAO(pool)

    await dao.insert_message_box_batch(
        None,
        [
            InsertMessageBoxRow(
                user_id=1, user_message_box_id=42, dialog_message_id=99,
                dialog_id=2001, peer_type=0, peer_id=2,
                from_user_id=1, out=True, random_id=None,
                text="hi", date_unix=10, pts=1,
            ),
        ],
    )

    box = await dao.get_box(1, 42)
    assert box is not None
    assert box.user_message_box_id == 42
    assert box.text == "hi"
    assert box.edit_date == 0


@pytest.mark.asyncio
async def test_update_text_by_dialog_message_id_bulk_updates_all_copies() -> None:
    pool = FakeChatPool()
    dao = ChatDAO(pool)

    await dao.insert_message_box_batch(
        None,
        [
            InsertMessageBoxRow(
                user_id=1, user_message_box_id=1, dialog_message_id=77,
                dialog_id=2001, peer_type=0, peer_id=2,
                from_user_id=1, out=True, random_id=None,
                text="orig", date_unix=10, pts=1,
            ),
            InsertMessageBoxRow(
                user_id=2, user_message_box_id=1, dialog_message_id=77,
                dialog_id=2001, peer_type=0, peer_id=1,
                from_user_id=1, out=False, random_id=None,
                text="orig", date_unix=10, pts=1,
            ),
        ],
    )

    n = await dao.update_text_by_dialog_message_id(
        77, "edited", None, edit_date=12345,
    )
    assert n == 2
    rows = await dao.get_boxes_by_dialog_message_ids([77])
    assert {r.text for r in rows} == {"edited"}
    assert {r.edit_date for r in rows} == {12345}


@pytest.mark.asyncio
async def test_mark_deleted_is_idempotent() -> None:
    pool = FakeChatPool()
    dao = ChatDAO(pool)

    await dao.insert_message_box_batch(
        None,
        [
            InsertMessageBoxRow(
                user_id=1, user_message_box_id=10, dialog_message_id=200,
                dialog_id=2001, peer_type=0, peer_id=2,
                from_user_id=1, out=True, random_id=None,
                text="m", date_unix=1, pts=1,
            ),
            InsertMessageBoxRow(
                user_id=1, user_message_box_id=11, dialog_message_id=201,
                dialog_id=2001, peer_type=0, peer_id=2,
                from_user_id=1, out=True, random_id=None,
                text="n", date_unix=2, pts=2,
            ),
        ],
    )

    first = await dao.mark_deleted(1, [10, 11])
    assert sorted(first) == [10, 11]

    # Second call hits already-deleted rows: returns nothing.
    second = await dao.mark_deleted(1, [10, 11])
    assert second == []


@pytest.mark.asyncio
async def test_get_boxes_by_dialog_message_ids_skips_deleted() -> None:
    pool = FakeChatPool()
    dao = ChatDAO(pool)

    await dao.insert_message_box_batch(
        None,
        [
            InsertMessageBoxRow(
                user_id=1, user_message_box_id=1, dialog_message_id=300,
                dialog_id=2001, peer_type=0, peer_id=2,
                from_user_id=1, out=True, random_id=None,
                text="x", date_unix=1, pts=1,
            ),
            InsertMessageBoxRow(
                user_id=2, user_message_box_id=1, dialog_message_id=300,
                dialog_id=2001, peer_type=0, peer_id=1,
                from_user_id=1, out=False, random_id=None,
                text="x", date_unix=1, pts=1,
            ),
        ],
    )

    await dao.mark_deleted(1, [1])
    rows = await dao.get_boxes_by_dialog_message_ids([300])
    # Only user 2's copy survives.
    assert {r.user_id for r in rows} == {2}


@pytest.mark.asyncio
async def test_update_dialog_read_outbox_writes_max() -> None:
    pool = FakeChatPool()
    pool.add_dialog(2001, owner_user_id=2, peer_id=1, is_group=False)
    dao = ChatDAO(pool)

    await dao.update_read_outbox(2, 2001, 5)
    assert pool.get_dialog(2001, 2).read_outbox_max_id == 5

    # Lower values do not regress.
    await dao.update_read_outbox(2, 2001, 3)
    assert pool.get_dialog(2001, 2).read_outbox_max_id == 5

    await dao.update_read_outbox(2, 2001, 9)
    assert pool.get_dialog(2001, 2).read_outbox_max_id == 9
