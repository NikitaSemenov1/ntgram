from __future__ import annotations

from dataclasses import dataclass

import asyncpg


# Chat-side row dataclasses


@dataclass(slots=True, frozen=True)
class ChatRow:
    chat_id: int
    title: str
    created_by: int
    version: int = 1
    participants_count: int = 1
    date_unix: int = 0


@dataclass(slots=True, frozen=True)
class MemberRow:
    """One chat_members row (used by GetFullChat / chatParticipants TL)."""

    user_id: int
    inviter_user_id: int
    joined_at_unix: int


@dataclass(slots=True, frozen=True)
class DialogRow:
    dialog_id: int
    owner_user_id: int
    peer_id: int
    is_group: bool


@dataclass(slots=True, frozen=True)
class DialogListRow:
    """One row of list_dialogs including last visible message for the owner."""

    dialog_id: int
    owner_user_id: int
    peer_id: int
    is_group: bool
    read_inbox_max_id: int
    read_outbox_max_id: int
    unread_count: int
    top_message_id: int
    top_from_user_id: int
    top_message_text: str
    top_message_date: int
    top_message_out: bool
    top_dialog_message_id: int


@dataclass(slots=True, frozen=True)
class DialogOwnerRow:
    """Per-owner view of a dialog (used to resolve participants of a thread)."""

    owner_user_id: int
    peer_id: int
    is_group: bool


@dataclass(slots=True, frozen=True)
class MemberAddEntry:
    """One bulk_add_members entry (user, who invited them, when)."""

    user_id: int
    inviter_user_id: int
    joined_at_unix: int


# MessageBox-side dataclasses (formerly in services/message/dao.py)


@dataclass(slots=True, frozen=True)
class MessageBoxRow:
    """A single per-user MessageBox row as stored in the database."""

    user_id: int
    user_message_box_id: int
    dialog_message_id: int
    dialog_id: int
    peer_type: int
    peer_id: int
    from_user_id: int
    out: bool
    text: str
    date_unix: int
    pts: int
    read: bool
    edit_date: int = 0


@dataclass(slots=True, frozen=True)
class InsertMessageBoxRow:
    """Input for batched INSERT INTO message_boxes."""

    user_id: int
    user_message_box_id: int
    dialog_message_id: int
    dialog_id: int
    peer_type: int
    peer_id: int
    from_user_id: int
    out: bool
    random_id: int | None
    text: str
    date_unix: int
    pts: int


@dataclass(slots=True, frozen=True)
class ReadOutboxReceipt:
    """Per-sender receipt produced by readHistory on the reader side."""

    sender_user_id: int
    sender_dialog_id: int
    max_outbox_id: int


class ChatDAO:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def next_chat_id(self) -> int:
        row = await self._pool.fetchrow(
            "UPDATE id_sequences SET next_val = next_val + 1 "
            "WHERE name = 'chat_id' RETURNING next_val"
        )
        return row["next_val"]  # type: ignore[index]

    async def next_dialog_id(self) -> int:
        row = await self._pool.fetchrow(
            "UPDATE id_sequences SET next_val = next_val + 1 "
            "WHERE name = 'dialog_id' RETURNING next_val"
        )
        return row["next_val"]  # type: ignore[index]

    async def create_chat(
        self,
        chat_id: int,
        title: str,
        creator_id: int,
        date_unix: int,
    ) -> None:
        """Insert a fresh chat row."""
        await self._pool.execute(
            """INSERT INTO chats
                  (chat_id, title, is_group, created_by,
                   version, participants_count, date_unix)
               VALUES ($1, $2, true, $3, 1, 0, $4)""",
            chat_id, title, creator_id, int(date_unix),
        )

    async def get_chat(self, chat_id: int) -> ChatRow | None:
        row = await self._pool.fetchrow(
            """SELECT chat_id, title, created_by,
                      version, participants_count, date_unix
               FROM chats WHERE chat_id = $1""",
            chat_id,
        )
        if row is None:
            return None
        return ChatRow(
            chat_id=int(row["chat_id"]),
            title=str(row["title"]),
            created_by=int(row["created_by"]),
            version=int(row["version"] or 1),
            participants_count=int(row["participants_count"] or 1),
            date_unix=int(row["date_unix"] or 0),
        )

    async def update_title(self, chat_id: int, title: str) -> int:
        """Update title and bump version; returns the new version."""
        row = await self._pool.fetchrow(
            """UPDATE chats
               SET title = $1, version = version + 1
               WHERE chat_id = $2
               RETURNING version""",
            title, chat_id,
        )
        return int(row["version"]) if row else 0

    async def add_member(
        self,
        chat_id: int,
        user_id: int,
        inviter_user_id: int,
        joined_at_unix: int,
    ) -> int:
        """Single-row helper around bulk_add_members (returns new version)."""
        added = await self.bulk_add_members(
            chat_id,
            [MemberAddEntry(user_id, inviter_user_id, joined_at_unix)],
        )
        if added == 0:
            return 0
        row = await self._pool.fetchrow(
            "SELECT version FROM chats WHERE chat_id = $1", chat_id,
        )
        return int(row["version"]) if row else 0

    async def bulk_add_members(
        self, chat_id: int, entries: list[MemberAddEntry],
    ) -> int:
        """Insert N members in one transaction; bump version + count once."""
        if not entries:
            return 0
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                inserted = 0
                for e in entries:
                    res = await conn.execute(
                        """INSERT INTO chat_members
                              (chat_id, user_id, inviter_user_id, joined_at)
                           VALUES ($1, $2, $3, to_timestamp($4))
                           ON CONFLICT (chat_id, user_id) DO NOTHING""",
                        chat_id, int(e.user_id), int(e.inviter_user_id),
                        int(e.joined_at_unix),
                    )
                    # asyncpg returns "INSERT 0 N" for execute().
                    if isinstance(res, str) and res.startswith("INSERT"):
                        try:
                            n = int(res.rsplit(" ", 1)[-1])
                        except ValueError:
                            n = 0
                        inserted += n
                if inserted:
                    await conn.execute(
                        """UPDATE chats
                           SET version = version + 1,
                               participants_count = participants_count + $1
                           WHERE chat_id = $2""",
                        inserted, chat_id,
                    )
                return inserted

    async def get_members(self, chat_id: int) -> list[MemberRow]:
        rows = await self._pool.fetch(
            """SELECT user_id, inviter_user_id,
                      EXTRACT(EPOCH FROM joined_at)::bigint AS joined_at_unix
               FROM chat_members
               WHERE chat_id = $1
               ORDER BY joined_at""",
            chat_id,
        )
        return [
            MemberRow(
                user_id=int(r["user_id"]),
                inviter_user_id=int(r["inviter_user_id"] or 0),
                joined_at_unix=int(r["joined_at_unix"] or 0),
            )
            for r in rows
        ]

    async def get_member_ids(self, chat_id: int) -> list[int]:
        """Plain user_id list — kept for membership-check fast paths."""
        rows = await self._pool.fetch(
            "SELECT user_id FROM chat_members WHERE chat_id = $1", chat_id,
        )
        return [int(r["user_id"]) for r in rows]

    async def count_members(self, chat_id: int) -> int:
        row = await self._pool.fetchrow(
            "SELECT count(*) as cnt FROM chat_members WHERE chat_id = $1", chat_id,
        )
        return int(row["cnt"]) if row else 0

    async def create_dialog(
        self, dialog_id: int, owner_user_id: int, peer_id: int, is_group: bool,
    ) -> None:
        await self._pool.execute(
            "INSERT INTO dialogs (dialog_id, owner_user_id, peer_id, is_group) "
            "VALUES ($1, $2, $3, $4)",
            dialog_id, owner_user_id, peer_id, is_group,
        )

    async def find_private_dialog(self, user_a: int, user_b: int) -> int | None:
        row = await self._pool.fetchrow(
            """SELECT d1.dialog_id FROM dialogs d1
               JOIN dialogs d2 ON d1.dialog_id = d2.dialog_id
               WHERE d1.owner_user_id = $1 AND d1.peer_id = $2 AND d1.is_group = false
                 AND d2.owner_user_id = $2 AND d2.peer_id = $1 AND d2.is_group = false
               LIMIT 1""",
            user_a, user_b,
        )
        return row["dialog_id"] if row else None

    async def count_dialogs(self, user_id: int) -> int:
        """Total number of dialogs owned by user_id (for messages.dialogsSlice)."""
        row = await self._pool.fetchrow(
            "SELECT count(*) AS n FROM dialogs WHERE owner_user_id = $1",
            user_id,
        )
        return int(row["n"]) if row else 0

    async def list_dialogs(self, user_id: int, *, limit: int = 100) -> list[DialogListRow]:
        lim = max(1, min(int(limit), 200))
        rows = await self._pool.fetch(
            """
            SELECT d.dialog_id,
                   d.owner_user_id,
                   d.peer_id,
                   d.is_group,
                   d.read_inbox_max_id,
                   d.read_outbox_max_id,
                   d.unread_count,
                   COALESCE(lm.user_message_box_id, 0)::bigint AS top_message_id,
                   COALESCE(lm.from_user_id, 0)::bigint AS top_from_user_id,
                   COALESCE(lm.text, '') AS top_message_text,
                   COALESCE(lm.date_unix, 0)::bigint AS top_message_date,
                   COALESCE(lm.out, false) AS top_message_out,
                   COALESCE(lm.dialog_message_id, 0)::bigint AS top_dialog_message_id
            FROM dialogs d
            LEFT JOIN LATERAL (
                SELECT m.user_message_box_id, m.from_user_id, m.text, m.date_unix,
                       m.out, m.dialog_message_id
                FROM message_boxes m
                WHERE m.user_id = d.owner_user_id
                  AND m.dialog_id = d.dialog_id
                  AND NOT m.deleted
                ORDER BY m.user_message_box_id DESC
                LIMIT 1
            ) lm ON true
            WHERE d.owner_user_id = $1
            ORDER BY COALESCE(lm.date_unix, EXTRACT(EPOCH FROM d.created_at)::bigint) DESC,
                     d.dialog_id DESC
            LIMIT $2
            """,
            user_id,
            lim,
        )
        return [DialogListRow(**dict(r)) for r in rows]

    async def find_dialogs_by_dialog_id(
        self, dialog_id: int,
    ) -> list[DialogOwnerRow]:
        """Return all per-owner rows of a logical dialog (for participant resolution)."""
        rows = await self._pool.fetch(
            "SELECT owner_user_id, peer_id, is_group FROM dialogs WHERE dialog_id = $1",
            dialog_id,
        )
        return [DialogOwnerRow(**dict(r)) for r in rows]

    async def find_dialog_by_peer(
        self, owner_user_id: int, *, is_group: bool, peer_id: int,
    ) -> int | None:
        """Resolve the actor's dialog_id for a (peer_type, peer_id) tuple."""
        row = await self._pool.fetchrow(
            """SELECT dialog_id FROM dialogs
               WHERE owner_user_id = $1
                 AND is_group = $2
                 AND peer_id = $3
               LIMIT 1""",
            owner_user_id, is_group, peer_id,
        )
        return int(row["dialog_id"]) if row else None

    async def get_chats_batch(
        self, chat_ids: list[int],
    ) -> dict[int, ChatRow]:
        """Fetch a set of ChatRows in a single SELECT."""
        if not chat_ids:
            return {}
        rows = await self._pool.fetch(
            """SELECT chat_id, title, created_by,
                      version, participants_count, date_unix
               FROM chats WHERE chat_id = ANY($1::bigint[])""",
            list({int(c) for c in chat_ids}),
        )
        return {
            int(r["chat_id"]): ChatRow(
                chat_id=int(r["chat_id"]),
                title=str(r["title"]),
                created_by=int(r["created_by"]),
                version=int(r["version"] or 1),
                participants_count=int(r["participants_count"] or 1),
                date_unix=int(r["date_unix"] or 0),
            )
            for r in rows
        }

    async def get_members_count_batch(
        self, chat_ids: list[int],
    ) -> dict[int, int]:
        """Return {chat_id: members_count} for a list of chat_ids."""
        if not chat_ids:
            return {}
        rows = await self._pool.fetch(
            """SELECT chat_id, COUNT(*)::int AS cnt
               FROM chat_members
               WHERE chat_id = ANY($1::bigint[])
               GROUP BY chat_id""",
            list({int(c) for c in chat_ids}),
        )
        return {int(r["chat_id"]): int(r["cnt"]) for r in rows}

    # MessageBox DAO (merged from former MessageDAO)

    # ID generators

    async def next_user_message_box_id(self, user_id: int) -> int:
        """Allocate next per-user MessageBox id; rows are created on demand."""
        name = f"user_message_box:{int(user_id)}"
        row = await self._pool.fetchrow(
            """INSERT INTO id_sequences (name, next_val)
               VALUES ($1, 2)
               ON CONFLICT (name) DO UPDATE SET next_val = id_sequences.next_val + 1
               RETURNING next_val - 1 AS allocated""",
            name,
        )
        return int(row["allocated"])  # type: ignore[index]

    async def next_dialog_message_id(self) -> int:
        """Allocate next global dialog_message_id shared across copies."""
        row = await self._pool.fetchrow(
            "UPDATE id_sequences SET next_val = next_val + 1 "
            "WHERE name = 'dialog_message_id' RETURNING next_val",
        )
        return int(row["next_val"])  # type: ignore[index]

    # Idempotency / box reads

    async def find_by_random_id(
        self, user_id: int, random_id: int,
    ) -> MessageBoxRow | None:
        row = await self._pool.fetchrow(
            """SELECT user_id, user_message_box_id, dialog_message_id, dialog_id,
                      peer_type, peer_id, from_user_id, out,
                      text, date_unix, pts, read, edit_date
               FROM message_boxes
               WHERE user_id = $1 AND random_id = $2 AND NOT deleted""",
            user_id, random_id,
        )
        return MessageBoxRow(**dict(row)) if row else None

    async def get_box(
        self, user_id: int, user_message_box_id: int,
    ) -> MessageBoxRow | None:
        """Load a single per-user MessageBox row including deleted flag."""
        row = await self._pool.fetchrow(
            """SELECT user_id, user_message_box_id, dialog_message_id, dialog_id,
                      peer_type, peer_id, from_user_id, out,
                      text, date_unix, pts, read, edit_date, deleted
               FROM message_boxes
               WHERE user_id = $1 AND user_message_box_id = $2""",
            user_id, user_message_box_id,
        )
        if row is None:
            return None
        data = dict(row)
        data.pop("deleted", None)
        return MessageBoxRow(**data)

    async def get_boxes_for_user(
        self, user_id: int, user_message_box_ids: list[int],
    ) -> list[MessageBoxRow]:
        """Batch variant of :meth:`get_box` excluding already-deleted rows."""
        if not user_message_box_ids:
            return []
        rows = await self._pool.fetch(
            """SELECT user_id, user_message_box_id, dialog_message_id, dialog_id,
                      peer_type, peer_id, from_user_id, out,
                      text, date_unix, pts, read, edit_date
               FROM message_boxes
               WHERE user_id = $1
                 AND user_message_box_id = ANY($2::bigint[])
                 AND NOT deleted""",
            user_id, [int(i) for i in user_message_box_ids],
        )
        return [MessageBoxRow(**dict(r)) for r in rows]

    async def get_boxes_by_dialog_message_ids(
        self, dialog_message_ids: list[int],
    ) -> list[MessageBoxRow]:
        """Load *all* per-user copies of the given logical messages."""
        if not dialog_message_ids:
            return []
        rows = await self._pool.fetch(
            """SELECT user_id, user_message_box_id, dialog_message_id, dialog_id,
                      peer_type, peer_id, from_user_id, out,
                      text, date_unix, pts, read, edit_date
               FROM message_boxes
               WHERE dialog_message_id = ANY($1::bigint[])
                 AND NOT deleted""",
            [int(i) for i in dialog_message_ids],
        )
        return [MessageBoxRow(**dict(r)) for r in rows]

    # Edit / delete

    async def update_text_by_dialog_message_id(
        self,
        dialog_message_id: int,
        new_text: str,
        new_entities_json: str | None,
        edit_date: int,
    ) -> int:
        """Bulk update text/entities/edit_date on every per-user copy."""
        entities_arg: str | None = (
            new_entities_json if new_entities_json else None
        )
        row = await self._pool.fetchrow(
            """WITH updated AS (
                  UPDATE message_boxes
                     SET text = $2,
                         entities = CASE WHEN $3::text IS NULL
                                         THEN NULL
                                         ELSE $3::jsonb END,
                         edit_date = $4
                   WHERE dialog_message_id = $1
                     AND NOT deleted
                  RETURNING 1
               )
               SELECT COUNT(*)::int AS c FROM updated""",
            int(dialog_message_id), new_text, entities_arg, int(edit_date),
        )
        return int(row["c"]) if row else 0

    async def mark_deleted(
        self, user_id: int, user_message_box_ids: list[int],
    ) -> list[int]:
        """Mark the actor's own boxes as deleted, returning effective ids."""
        if not user_message_box_ids:
            return []
        rows = await self._pool.fetch(
            """UPDATE message_boxes
                  SET deleted = true
                WHERE user_id = $1
                  AND user_message_box_id = ANY($2::bigint[])
                  AND NOT deleted
              RETURNING user_message_box_id""",
            int(user_id), [int(i) for i in user_message_box_ids],
        )
        return [int(r["user_message_box_id"]) for r in rows]

    async def mark_deleted_bulk(
        self, rows: list[tuple[int, int]],
    ) -> int:
        """Bulk soft-delete (user_id, user_message_box_id) pairs."""
        if not rows:
            return 0
        by_user: dict[int, list[int]] = {}
        for uid, ubid in rows:
            by_user.setdefault(int(uid), []).append(int(ubid))
        total = 0
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                for uid, ubids in by_user.items():
                    res = await conn.fetch(
                        """UPDATE message_boxes
                              SET deleted = true
                            WHERE user_id = $1
                              AND user_message_box_id = ANY($2::bigint[])
                              AND NOT deleted
                          RETURNING user_message_box_id""",
                        uid, ubids,
                    )
                    total += len(res)
        return total

    # Batch insert

    async def insert_message_box_batch(
        self, conn: asyncpg.Connection | None, rows: list[InsertMessageBoxRow],
    ) -> None:
        """Insert rows either on a passed connection or via the pool."""
        if not rows:
            return
        records = [
            (
                r.user_id, r.user_message_box_id, r.dialog_message_id,
                r.dialog_id, r.peer_type, r.peer_id, r.from_user_id, r.out,
                r.random_id, r.text, r.date_unix, r.pts,
            )
            for r in rows
        ]
        sql = (
            "INSERT INTO message_boxes "
            "(user_id, user_message_box_id, dialog_message_id, dialog_id, "
            "peer_type, peer_id, from_user_id, out, random_id, text, "
            "date_unix, pts) "
            "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)"
        )
        if conn is not None:
            await conn.executemany(sql, records)
        else:
            async with self._pool.acquire() as c:
                await c.executemany(sql, records)

    # Reads

    async def get_history(
        self,
        user_id: int,
        dialog_id: int,
        limit: int,
        *,
        offset_id: int = 0,
        min_id: int = 0,
        max_id: int = 0,
        add_offset: int = 0,
    ) -> list[MessageBoxRow]:
        off = max(0, int(add_offset))
        rows = await self._pool.fetch(
            """SELECT user_id, user_message_box_id, dialog_message_id, dialog_id,
                      peer_type, peer_id, from_user_id, out,
                      text, date_unix, pts, read, edit_date
               FROM message_boxes
               WHERE user_id = $1 AND dialog_id = $2 AND NOT deleted
                 AND ($3 = 0 OR user_message_box_id < $3)
                 AND ($4 = 0 OR user_message_box_id >= $4)
                 AND ($5 = 0 OR user_message_box_id <= $5)
               ORDER BY user_message_box_id DESC
               LIMIT $6 OFFSET $7""",
            user_id, dialog_id, offset_id, min_id, max_id, limit, off,
        )
        return [MessageBoxRow(**dict(r)) for r in rows]

    async def count_history(
        self,
        user_id: int,
        dialog_id: int,
        *,
        offset_id: int = 0,
        min_id: int = 0,
        max_id: int = 0,
    ) -> int:
        row = await self._pool.fetchrow(
            """SELECT COUNT(*)::int AS c FROM message_boxes
               WHERE user_id = $1 AND dialog_id = $2 AND NOT deleted
                 AND ($3 = 0 OR user_message_box_id < $3)
                 AND ($4 = 0 OR user_message_box_id >= $4)
                 AND ($5 = 0 OR user_message_box_id <= $5)""",
            user_id, dialog_id, offset_id, min_id, max_id,
        )
        return int(row["c"]) if row else 0

    # Read tracking

    async def mark_inbox_read(
        self,
        user_id: int,
        dialog_id: int,
        max_ubid: int,
    ) -> int:
        row = await self._pool.fetchrow(
            """WITH updated AS (
                  UPDATE message_boxes
                     SET read = true
                   WHERE user_id = $1 AND dialog_id = $2
                     AND user_message_box_id <= $3
                     AND out = false
                     AND read = false
                     AND NOT deleted
                  RETURNING 1
               )
               SELECT COUNT(*)::int AS c FROM updated""",
            user_id, dialog_id, max_ubid,
        )
        return int(row["c"]) if row else 0

    async def peer_outbox_for_inbox(
        self, reader_user_id: int, dialog_id: int, max_inbox_ubid: int,
    ) -> list[ReadOutboxReceipt]:
        """For inbox rows just read, locate matching outbox rows on senders."""
        rows = await self._pool.fetch(
            """WITH inbox_just_read AS (
                  SELECT dialog_message_id, from_user_id
                  FROM message_boxes
                  WHERE user_id = $1 AND dialog_id = $2
                    AND user_message_box_id <= $3
                    AND out = false
                    AND NOT deleted
               )
               SELECT s.user_id AS sender_user_id,
                      s.dialog_id AS sender_dialog_id,
                      MAX(s.user_message_box_id)::bigint AS max_outbox_id
               FROM message_boxes s
               JOIN inbox_just_read i
                 ON i.dialog_message_id = s.dialog_message_id
                AND i.from_user_id = s.user_id
               WHERE s.out = true AND NOT s.deleted
                 AND s.user_id <> $1
               GROUP BY s.user_id, s.dialog_id""",
            reader_user_id, dialog_id, max_inbox_ubid,
        )
        return [
            ReadOutboxReceipt(
                sender_user_id=int(r["sender_user_id"]),
                sender_dialog_id=int(r["sender_dialog_id"]),
                max_outbox_id=int(r["max_outbox_id"]),
            )
            for r in rows
        ]

    # Dialog bookkeeping

    async def update_read_inbox(
        self, owner_user_id: int, dialog_id: int, max_id: int,
    ) -> None:
        await self._pool.execute(
            "UPDATE dialogs SET read_inbox_max_id = GREATEST(read_inbox_max_id, $1) "
            "WHERE dialog_id = $2 AND owner_user_id = $3",
            max_id, dialog_id, owner_user_id,
        )

    async def update_read_outbox(
        self, sender_user_id: int, sender_dialog_id: int, max_outbox_id: int,
    ) -> None:
        await self._pool.execute(
            "UPDATE dialogs SET read_outbox_max_id = GREATEST(read_outbox_max_id, $1) "
            "WHERE dialog_id = $2 AND owner_user_id = $3",
            max_outbox_id, sender_dialog_id, sender_user_id,
        )

    async def reset_unread_count_up_to(
        self, owner_user_id: int, dialog_id: int, max_id: int,
    ) -> None:
        await self._pool.execute(
            """UPDATE dialogs d
               SET unread_count = COALESCE((
                   SELECT COUNT(*)::int FROM message_boxes m
                   WHERE m.user_id = d.owner_user_id
                     AND m.dialog_id = d.dialog_id
                     AND m.out = false
                     AND m.read = false
                     AND NOT m.deleted
               ), 0)
               WHERE d.dialog_id = $1 AND d.owner_user_id = $2""",
            dialog_id, owner_user_id,
        )

    async def update_dialog_top(
        self,
        owner_user_id: int,
        dialog_id: int,
        ubid: int,
        date_unix: int,
        *,
        increment_unread: bool,
    ) -> None:
        await self._pool.execute(
            """UPDATE dialogs
               SET top_user_message_box_id = GREATEST(top_user_message_box_id, $1),
                   top_message_date = GREATEST(top_message_date, $2),
                   unread_count = unread_count + CASE WHEN $3 THEN 1 ELSE 0 END
               WHERE dialog_id = $4 AND owner_user_id = $5""",
            ubid, date_unix, increment_unread, dialog_id, owner_user_id,
        )

    async def get_dialog_for_owner(
        self, owner_user_id: int, dialog_id: int,
    ) -> dict | None:
        row = await self._pool.fetchrow(
            """SELECT dialog_id, owner_user_id, peer_id, is_group,
                      read_inbox_max_id, read_outbox_max_id, unread_count,
                      top_user_message_box_id, top_message_date
               FROM dialogs WHERE dialog_id = $1 AND owner_user_id = $2""",
            dialog_id, owner_user_id,
        )
        return dict(row) if row else None

    async def get_dialog_owners(self, dialog_id: int) -> list[dict]:
        """Return [{owner_user_id, peer_id, is_group}] for the dialog."""
        rows = await self._pool.fetch(
            """SELECT owner_user_id, peer_id, is_group
               FROM dialogs WHERE dialog_id = $1""",
            dialog_id,
        )
        return [dict(r) for r in rows]

    async def unread_count_for_owner(
        self, owner_user_id: int, dialog_id: int,
    ) -> int:
        row = await self._pool.fetchrow(
            """SELECT COUNT(*)::int AS c FROM message_boxes
               WHERE user_id = $1 AND dialog_id = $2
                 AND out = false AND read = false AND NOT deleted""",
            owner_user_id, dialog_id,
        )
        return int(row["c"]) if row else 0

    async def max_inbox_ubid_in_range(
        self, user_id: int, dialog_id: int, max_ubid: int,
    ) -> int:
        """Return the highest inbox copy ≤ max_ubid (0 if none)."""
        row = await self._pool.fetchrow(
            """SELECT MAX(user_message_box_id)::bigint AS m
               FROM message_boxes
               WHERE user_id = $1 AND dialog_id = $2
                 AND out = false AND NOT deleted
                 AND user_message_box_id <= $3""",
            user_id, dialog_id, max_ubid,
        )
        return int(row["m"]) if row and row["m"] else 0
