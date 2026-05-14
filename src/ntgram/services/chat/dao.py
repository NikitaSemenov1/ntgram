from __future__ import annotations

import json
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
class ThreadRow:
    """One threads row.

    chat_id == 0 means a pm thread (chat_id IS NULL in the DB).
    chat_id > 0 means a group thread bound to that chat.
    """

    thread_id: int
    chat_id: int     # 0 for pm, >0 for group


@dataclass(slots=True, frozen=True)
class ThreadParticipantRow:
    """One thread_participants row."""

    user_id: int
    inviter_user_id: int
    joined_at_unix: int


@dataclass(slots=True, frozen=True)
class ThreadParticipantAddEntry:
    """One bulk_add_thread_participants entry."""

    user_id: int
    inviter_user_id: int
    joined_at_unix: int


@dataclass(slots=True, frozen=True)
class DialogStateRow:
    """Per-owner view of a thread (dialog_state)."""

    thread_id: int
    owner_user_id: int
    peer_user_id: int   # 0 if group
    peer_chat_id: int   # 0 if pm
    read_inbox_max_id: int = 0
    read_outbox_max_id: int = 0
    unread_count: int = 0
    top_user_message_box_id: int = 0

    @property
    def is_group(self) -> bool:
        return self.peer_chat_id > 0

    @property
    def peer_id(self) -> int:
        """Legacy single-value peer (chat_id for group, user_id for pm)."""
        return self.peer_chat_id if self.peer_chat_id else self.peer_user_id


@dataclass(slots=True, frozen=True)
class DialogListRow:
    """One row of list_dialogs including last visible message."""

    thread_id: int
    owner_user_id: int
    peer_user_id: int
    peer_chat_id: int
    read_inbox_max_id: int
    read_outbox_max_id: int
    unread_count: int
    top_message_id: int
    top_from_user_id: int
    top_message_text: str
    top_message_date: int
    top_message_out: bool
    top_dialog_message_id: int

    @property
    def is_group(self) -> bool:
        return self.peer_chat_id > 0

    @property
    def peer_id(self) -> int:
        return self.peer_chat_id if self.peer_chat_id else self.peer_user_id


@dataclass(slots=True, frozen=True)
class DialogStateOwnerRow:
    """Per-owner projection used for participant resolution."""

    owner_user_id: int
    peer_user_id: int
    peer_chat_id: int

    @property
    def is_group(self) -> bool:
        return self.peer_chat_id > 0

    @property
    def peer_id(self) -> int:
        return self.peer_chat_id if self.peer_chat_id else self.peer_user_id


# MessageBox-side dataclasses


@dataclass(slots=True, frozen=True)
class MessageBoxRow:
    """Flat read DTO: per-user box joined with message content + thread info."""

    user_id: int
    user_message_box_id: int
    dialog_message_id: int
    thread_id: int
    peer_user_id: int
    peer_chat_id: int
    from_user_id: int
    out: bool
    text: str
    date_unix: int
    pts: int
    read: bool
    edit_date: int = 0

    @property
    def is_group(self) -> bool:
        return self.peer_chat_id > 0

    @property
    def peer_id(self) -> int:
        return self.peer_chat_id if self.peer_chat_id else self.peer_user_id


@dataclass(slots=True, frozen=True)
class InsertMessageRow:
    """Content row for INSERT INTO messages."""

    dialog_message_id: int
    thread_id: int
    from_user_id: int
    text: str
    date_unix: int


@dataclass(slots=True, frozen=True)
class InsertMessageBoxRow:
    """Per-user copy row for INSERT INTO message_boxes."""

    user_id: int
    user_message_box_id: int
    dialog_message_id: int
    out: bool
    random_id: int | None
    pts: int


@dataclass(slots=True, frozen=True)
class ReadOutboxReceipt:
    """Per-sender receipt produced by readHistory on the reader side."""

    sender_user_id: int
    sender_thread_id: int
    max_outbox_id: int


_BOX_JOIN_SELECT = """
    mb.user_id,
    mb.user_message_box_id,
    mb.dialog_message_id,
    msg.thread_id,
    coalesce(ds.peer_user_id, 0)::bigint AS peer_user_id,
    coalesce(ds.peer_chat_id, 0)::bigint AS peer_chat_id,
    msg.from_user_id,
    mb.out,
    msg.text,
    msg.date_unix,
    mb.pts,
    mb.read,
    msg.edit_date
"""

_BOX_JOIN_FROM = """
    FROM message_boxes mb
    JOIN messages msg ON msg.dialog_message_id = mb.dialog_message_id
    LEFT JOIN dialog_state ds
        ON ds.owner_user_id = mb.user_id AND ds.thread_id = msg.thread_id
"""


def _row_to_message_box(row: asyncpg.Record) -> MessageBoxRow:
    return MessageBoxRow(
        user_id=int(row["user_id"]),
        user_message_box_id=int(row["user_message_box_id"]),
        dialog_message_id=int(row["dialog_message_id"]),
        thread_id=int(row["thread_id"] or 0),
        peer_user_id=int(row["peer_user_id"] or 0),
        peer_chat_id=int(row["peer_chat_id"] or 0),
        from_user_id=int(row["from_user_id"] or 0),
        out=bool(row["out"]),
        text=str(row["text"] or ""),
        date_unix=int(row["date_unix"] or 0),
        pts=int(row["pts"] or 0),
        read=bool(row["read"]),
        edit_date=int(row["edit_date"] or 0),
    )


class ChatDAO:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    # ID allocators
    
    async def next_chat_id(self) -> int:
        row = await self._pool.fetchrow(
            "UPDATE id_sequences SET next_val = next_val + 1 "
            "WHERE name = 'chat_id' RETURNING next_val"
        )
        return row["next_val"]  # type: ignore[index]

    async def next_thread_id(self) -> int:
        row = await self._pool.fetchrow(
            "UPDATE id_sequences SET next_val = next_val + 1 "
            "WHERE name = 'thread_id' RETURNING next_val"
        )
        return row["next_val"]  # type: ignore[index]

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

    # Chats
    
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
                  (chat_id, title, created_by,
                   version, participants_count, date_unix)
               VALUES ($1, $2, $3, 1, 0, $4)""",
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

    # Threads
    
    async def create_thread(
        self, thread_id: int, chat_id: int | None,
    ) -> None:
        """Insert a fresh thread row."""
        await self._pool.execute(
            "INSERT INTO threads (thread_id, chat_id) VALUES ($1, $2)",
            int(thread_id), int(chat_id) if chat_id else None,
        )

    async def get_thread(self, thread_id: int) -> ThreadRow | None:
        row = await self._pool.fetchrow(
            "SELECT thread_id, chat_id FROM threads WHERE thread_id = $1",
            int(thread_id),
        )
        if row is None:
            return None
        return ThreadRow(
            thread_id=int(row["thread_id"]),
            chat_id=int(row["chat_id"] or 0),
        )

    async def find_thread_for_chat(self, chat_id: int) -> int | None:
        """Return the (single) thread_id bound to a group chat_id."""
        row = await self._pool.fetchrow(
            "SELECT thread_id FROM threads WHERE chat_id = $1 LIMIT 1",
            int(chat_id),
        )
        return int(row["thread_id"]) if row else None

    # Thread participants
    
    async def add_thread_participant(
        self,
        thread_id: int,
        user_id: int,
        inviter_user_id: int,
        joined_at_unix: int,
        *,
        chat_id_for_counter: int = 0,
    ) -> int:
        """Insert one participant, returns the new chat.version when applicable."""
        added = await self.bulk_add_thread_participants(
            thread_id,
            [ThreadParticipantAddEntry(user_id, inviter_user_id, joined_at_unix)],
            chat_id_for_counter=chat_id_for_counter,
        )
        if added == 0:
            return 0
        if chat_id_for_counter <= 0:
            return 0
        row = await self._pool.fetchrow(
            "SELECT version FROM chats WHERE chat_id = $1",
            int(chat_id_for_counter),
        )
        return int(row["version"]) if row else 0

    async def bulk_add_thread_participants(
        self,
        thread_id: int,
        entries: list[ThreadParticipantAddEntry],
        *,
        chat_id_for_counter: int = 0,
    ) -> int:
        """Insert N participants in one transaction."""
        if not entries:
            return 0
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                inserted = 0
                for e in entries:
                    res = await conn.execute(
                        """INSERT INTO thread_participants
                              (thread_id, user_id, inviter_user_id, joined_at)
                           VALUES ($1, $2, $3, to_timestamp($4))
                           ON CONFLICT (thread_id, user_id) DO NOTHING""",
                        int(thread_id), int(e.user_id), int(e.inviter_user_id),
                        int(e.joined_at_unix),
                    )
                    if isinstance(res, str) and res.startswith("INSERT"):
                        try:
                            n = int(res.rsplit(" ", 1)[-1])
                        except ValueError:
                            n = 0
                        inserted += n
                if inserted and int(chat_id_for_counter) > 0:
                    await conn.execute(
                        """UPDATE chats
                           SET version = version + 1,
                               participants_count = participants_count + $1
                           WHERE chat_id = $2""",
                        inserted, int(chat_id_for_counter),
                    )
                return inserted

    async def get_thread_participants(
        self, thread_id: int,
    ) -> list[ThreadParticipantRow]:
        rows = await self._pool.fetch(
            """SELECT user_id, inviter_user_id,
                      EXTRACT(EPOCH FROM joined_at)::bigint AS joined_at_unix
               FROM thread_participants
               WHERE thread_id = $1
               ORDER BY joined_at""",
            int(thread_id),
        )
        return [
            ThreadParticipantRow(
                user_id=int(r["user_id"]),
                inviter_user_id=int(r["inviter_user_id"] or 0),
                joined_at_unix=int(r["joined_at_unix"] or 0),
            )
            for r in rows
        ]

    async def get_thread_participant_ids(self, thread_id: int) -> list[int]:
        """Plain user_id list — kept for membership-check fast paths."""
        rows = await self._pool.fetch(
            "SELECT user_id FROM thread_participants WHERE thread_id = $1",
            int(thread_id),
        )
        return [int(r["user_id"]) for r in rows]

    # Dialog state
    
    async def create_dialog_state(
        self,
        thread_id: int,
        owner_user_id: int,
        *,
        peer_user_id: int = 0,
        peer_chat_id: int = 0,
    ) -> None:
        """Insert a per-owner dialog_state row. Exactly one peer_* > 0."""
        await self._pool.execute(
            """INSERT INTO dialog_state
                  (thread_id, owner_user_id, peer_user_id, peer_chat_id)
               VALUES ($1, $2, $3, $4)""",
            int(thread_id), int(owner_user_id),
            int(peer_user_id) if peer_user_id else None,
            int(peer_chat_id) if peer_chat_id else None,
        )

    async def find_private_thread(
        self, user_a: int, user_b: int,
    ) -> int | None:
        """Locate the existing pm thread between two users."""
        row = await self._pool.fetchrow(
            """SELECT ds1.thread_id FROM dialog_state ds1
               JOIN dialog_state ds2 ON ds1.thread_id = ds2.thread_id
               JOIN threads t ON t.thread_id = ds1.thread_id
               WHERE t.chat_id IS NULL
                 AND ds1.owner_user_id = $1 AND ds1.peer_user_id = $2
                 AND ds2.owner_user_id = $2 AND ds2.peer_user_id = $1
               LIMIT 1""",
            int(user_a), int(user_b),
        )
        return int(row["thread_id"]) if row else None

    async def count_dialogs(self, user_id: int) -> int:
        """Total number of dialogs owned by user_id."""
        row = await self._pool.fetchrow(
            "SELECT count(*) AS n FROM dialog_state WHERE owner_user_id = $1",
            int(user_id),
        )
        return int(row["n"]) if row else 0

    async def list_dialogs(
        self, user_id: int, *, limit: int = 100,
    ) -> list[DialogListRow]:
        lim = max(1, min(int(limit), 200))
        rows = await self._pool.fetch(
            """
            SELECT ds.thread_id,
                   ds.owner_user_id,
                   COALESCE(ds.peer_user_id, 0)::bigint AS peer_user_id,
                   COALESCE(ds.peer_chat_id, 0)::bigint AS peer_chat_id,
                   ds.read_inbox_max_id,
                   ds.read_outbox_max_id,
                   ds.unread_count,
                   COALESCE(lm.user_message_box_id, 0)::bigint AS top_message_id,
                   COALESCE(lm.from_user_id, 0)::bigint AS top_from_user_id,
                   COALESCE(lm.text, '') AS top_message_text,
                   COALESCE(lm.date_unix, 0)::bigint AS top_message_date,
                   COALESCE(lm.out, false) AS top_message_out,
                   COALESCE(lm.dialog_message_id, 0)::bigint AS top_dialog_message_id
            FROM dialog_state ds
            LEFT JOIN LATERAL (
                SELECT mb.user_message_box_id, msg.from_user_id, msg.text,
                       msg.date_unix, mb.out, mb.dialog_message_id
                FROM message_boxes mb
                JOIN messages msg ON msg.dialog_message_id = mb.dialog_message_id
                WHERE mb.user_id = ds.owner_user_id
                  AND msg.thread_id = ds.thread_id
                  AND NOT mb.deleted
                ORDER BY mb.user_message_box_id DESC
                LIMIT 1
            ) lm ON true
            WHERE ds.owner_user_id = $1
            ORDER BY COALESCE(lm.date_unix, EXTRACT(EPOCH FROM ds.created_at)::bigint) DESC,
                     ds.thread_id DESC
            LIMIT $2
            """,
            int(user_id),
            lim,
        )
        return [DialogListRow(**dict(r)) for r in rows]

    async def find_dialog_states_by_thread_id(
        self, thread_id: int,
    ) -> list[DialogStateOwnerRow]:
        """Return all per-owner dialog_state rows for a thread."""
        rows = await self._pool.fetch(
            """SELECT owner_user_id,
                      COALESCE(peer_user_id, 0)::bigint AS peer_user_id,
                      COALESCE(peer_chat_id, 0)::bigint AS peer_chat_id
               FROM dialog_state WHERE thread_id = $1""",
            int(thread_id),
        )
        return [DialogStateOwnerRow(**dict(r)) for r in rows]

    async def find_thread_by_peer(
        self,
        owner_user_id: int,
        *,
        peer_user_id: int = 0,
        peer_chat_id: int = 0,
    ) -> int | None:
        """Resolve the actor's thread_id for a typed peer (user xor chat)."""
        if peer_chat_id:
            row = await self._pool.fetchrow(
                """SELECT thread_id FROM dialog_state
                   WHERE owner_user_id = $1 AND peer_chat_id = $2
                   LIMIT 1""",
                int(owner_user_id), int(peer_chat_id),
            )
        else:
            row = await self._pool.fetchrow(
                """SELECT thread_id FROM dialog_state
                   WHERE owner_user_id = $1 AND peer_user_id = $2
                   LIMIT 1""",
                int(owner_user_id), int(peer_user_id),
            )
        return int(row["thread_id"]) if row else None

    async def get_dialog_state(
        self, owner_user_id: int, thread_id: int,
    ) -> DialogStateRow | None:
        row = await self._pool.fetchrow(
            """SELECT thread_id, owner_user_id,
                      COALESCE(peer_user_id, 0)::bigint AS peer_user_id,
                      COALESCE(peer_chat_id, 0)::bigint AS peer_chat_id,
                      read_inbox_max_id, read_outbox_max_id, unread_count,
                      top_user_message_box_id
               FROM dialog_state WHERE thread_id = $1 AND owner_user_id = $2""",
            int(thread_id), int(owner_user_id),
        )
        return DialogStateRow(**dict(row)) if row else None

    async def get_dialog_state_owners(self, thread_id: int) -> list[DialogStateOwnerRow]:
        """Alias of :meth:`find_dialog_states_by_thread_id` for readability."""
        return await self.find_dialog_states_by_thread_id(thread_id)

    # Messages / message_boxes — reads
    
    async def find_by_random_id(
        self, user_id: int, random_id: int,
    ) -> MessageBoxRow | None:
        row = await self._pool.fetchrow(
            f"""SELECT {_BOX_JOIN_SELECT}
                {_BOX_JOIN_FROM}
                WHERE mb.user_id = $1 AND mb.random_id = $2 AND NOT mb.deleted""",
            user_id, random_id,
        )
        return _row_to_message_box(row) if row else None

    async def get_box(
        self, user_id: int, user_message_box_id: int,
    ) -> MessageBoxRow | None:
        """Load a single per-user MessageBox row."""
        row = await self._pool.fetchrow(
            f"""SELECT {_BOX_JOIN_SELECT}
                {_BOX_JOIN_FROM}
                WHERE mb.user_id = $1 AND mb.user_message_box_id = $2""",
            user_id, user_message_box_id,
        )
        return _row_to_message_box(row) if row else None

    async def get_boxes_for_user(
        self, user_id: int, user_message_box_ids: list[int],
    ) -> list[MessageBoxRow]:
        """Batch variant of :meth:`get_box` excluding already-deleted rows."""
        if not user_message_box_ids:
            return []
        rows = await self._pool.fetch(
            f"""SELECT {_BOX_JOIN_SELECT}
                {_BOX_JOIN_FROM}
                WHERE mb.user_id = $1
                  AND mb.user_message_box_id = ANY($2::bigint[])
                  AND NOT mb.deleted""",
            user_id, [int(i) for i in user_message_box_ids],
        )
        return [_row_to_message_box(r) for r in rows]

    async def get_boxes_by_dialog_message_ids(
        self, dialog_message_ids: list[int],
    ) -> list[MessageBoxRow]:
        """Load *all* per-user copies of the given logical messages."""
        if not dialog_message_ids:
            return []
        rows = await self._pool.fetch(
            f"""SELECT {_BOX_JOIN_SELECT}
                {_BOX_JOIN_FROM}
                WHERE mb.dialog_message_id = ANY($1::bigint[])
                  AND NOT mb.deleted""",
            [int(i) for i in dialog_message_ids],
        )
        return [_row_to_message_box(r) for r in rows]

    async def get_history(
        self,
        user_id: int,
        thread_id: int,
        limit: int,
        *,
        offset_id: int = 0,
        min_id: int = 0,
        max_id: int = 0,
        add_offset: int = 0,
    ) -> list[MessageBoxRow]:
        off = max(0, int(add_offset))
        rows = await self._pool.fetch(
            f"""SELECT {_BOX_JOIN_SELECT}
                {_BOX_JOIN_FROM}
                WHERE mb.user_id = $1 AND msg.thread_id = $2 AND NOT mb.deleted
                  AND ($3 = 0 OR mb.user_message_box_id < $3)
                  AND ($4 = 0 OR mb.user_message_box_id >= $4)
                  AND ($5 = 0 OR mb.user_message_box_id <= $5)
                ORDER BY mb.user_message_box_id DESC
                LIMIT $6 OFFSET $7""",
            user_id, thread_id, offset_id, min_id, max_id, limit, off,
        )
        return [_row_to_message_box(r) for r in rows]

    async def count_history(
        self,
        user_id: int,
        thread_id: int,
        *,
        offset_id: int = 0,
        min_id: int = 0,
        max_id: int = 0,
    ) -> int:
        row = await self._pool.fetchrow(
            """SELECT COUNT(*)::int AS c
               FROM message_boxes mb
               JOIN messages msg ON msg.dialog_message_id = mb.dialog_message_id
               WHERE mb.user_id = $1 AND msg.thread_id = $2 AND NOT mb.deleted
                 AND ($3 = 0 OR mb.user_message_box_id < $3)
                 AND ($4 = 0 OR mb.user_message_box_id >= $4)
                 AND ($5 = 0 OR mb.user_message_box_id <= $5)""",
            user_id, thread_id, offset_id, min_id, max_id,
        )
        return int(row["c"]) if row else 0

    # Messages / message_boxes — writes
    
    async def update_message_content(
        self,
        dialog_message_id: int,
        new_text: str,
        new_entities_json: str | None,
        edit_date: int,
    ) -> int:
        """Replace text/entities/edit_date on the single messages row."""
        entities_arg: str | None = (
            new_entities_json if new_entities_json else None
        )
        row = await self._pool.fetchrow(
            """WITH updated AS (
                  UPDATE messages
                     SET text = $2,
                         entities = CASE WHEN $3::text IS NULL
                                         THEN NULL
                                         ELSE $3::jsonb END,
                         edit_date = $4
                   WHERE dialog_message_id = $1
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

    async def insert_message_with_boxes(
        self,
        conn: asyncpg.Connection | None,
        message: InsertMessageRow,
        boxes: list[InsertMessageBoxRow],
    ) -> None:
        """Insert one messages row plus N per-user message_boxes rows."""
        if not boxes:
            return

        msg_sql = (
            "INSERT INTO messages "
            "(dialog_message_id, thread_id, from_user_id, text, date_unix) "
            "VALUES ($1, $2, $3, $4, $5)"
        )
        msg_args = (
            int(message.dialog_message_id),
            int(message.thread_id),
            int(message.from_user_id),
            message.text,
            int(message.date_unix),
        )

        box_sql = (
            "INSERT INTO message_boxes "
            "(user_id, user_message_box_id, dialog_message_id, "
            "out, random_id, pts) "
            "VALUES ($1, $2, $3, $4, $5, $6)"
        )
        box_records = [
            (
                int(b.user_id), int(b.user_message_box_id),
                int(b.dialog_message_id), bool(b.out), b.random_id,
                int(b.pts),
            )
            for b in boxes
        ]

        async def _run(c: asyncpg.Connection) -> None:
            async with c.transaction():
                await c.execute(msg_sql, *msg_args)
                await c.executemany(box_sql, box_records)

        if conn is not None:
            await _run(conn)
        else:
            async with self._pool.acquire() as c:
                await _run(c)

    # Chat events
    
    async def add_chat_event(
        self,
        chat_id: int,
        actor_user_id: int,
        kind: str,
        payload: dict,
        date_unix: int,
    ) -> int:
        """INSERT a chat-lifecycle event and return its event_id."""
        row = await self._pool.fetchrow(
            """INSERT INTO chat_events
                  (chat_id, actor_user_id, kind, payload, date_unix)
               VALUES ($1, $2, $3, $4::jsonb, $5)
               RETURNING event_id""",
            int(chat_id), int(actor_user_id), str(kind),
            json.dumps(payload or {}), int(date_unix),
        )
        return int(row["event_id"]) if row else 0

    # Read tracking
    
    async def mark_inbox_read(
        self,
        user_id: int,
        thread_id: int,
        max_ubid: int,
    ) -> int:
        row = await self._pool.fetchrow(
            """WITH updated AS (
                  UPDATE message_boxes mb
                     SET read = true
                   FROM messages msg
                   WHERE msg.dialog_message_id = mb.dialog_message_id
                     AND mb.user_id = $1
                     AND msg.thread_id = $2
                     AND mb.user_message_box_id <= $3
                     AND mb.out = false
                     AND mb.read = false
                     AND NOT mb.deleted
                  RETURNING 1
               )
               SELECT COUNT(*)::int AS c FROM updated""",
            user_id, thread_id, max_ubid,
        )
        return int(row["c"]) if row else 0

    async def peer_outbox_for_inbox(
        self, reader_user_id: int, thread_id: int, max_inbox_ubid: int,
    ) -> list[ReadOutboxReceipt]:
        """For inbox rows just read, locate matching outbox rows on senders."""
        rows = await self._pool.fetch(
            """WITH inbox_just_read AS (
                  SELECT mb.dialog_message_id, msg.from_user_id
                  FROM message_boxes mb
                  JOIN messages msg ON msg.dialog_message_id = mb.dialog_message_id
                  WHERE mb.user_id = $1 AND msg.thread_id = $2
                    AND mb.user_message_box_id <= $3
                    AND mb.out = false
                    AND NOT mb.deleted
               )
               SELECT smb.user_id AS sender_user_id,
                      smsg.thread_id AS sender_thread_id,
                      MAX(smb.user_message_box_id)::bigint AS max_outbox_id
               FROM message_boxes smb
               JOIN messages smsg ON smsg.dialog_message_id = smb.dialog_message_id
               JOIN inbox_just_read i
                 ON i.dialog_message_id = smb.dialog_message_id
                AND i.from_user_id = smb.user_id
               WHERE smb.out = true AND NOT smb.deleted
                 AND smb.user_id <> $1
               GROUP BY smb.user_id, smsg.thread_id""",
            reader_user_id, thread_id, max_inbox_ubid,
        )
        return [
            ReadOutboxReceipt(
                sender_user_id=int(r["sender_user_id"]),
                sender_thread_id=int(r["sender_thread_id"]),
                max_outbox_id=int(r["max_outbox_id"]),
            )
            for r in rows
        ]

    # Dialog state bookkeeping
    
    async def update_read_inbox(
        self, owner_user_id: int, thread_id: int, max_id: int,
    ) -> None:
        await self._pool.execute(
            "UPDATE dialog_state SET read_inbox_max_id = GREATEST(read_inbox_max_id, $1) "
            "WHERE thread_id = $2 AND owner_user_id = $3",
            max_id, thread_id, owner_user_id,
        )

    async def update_read_outbox(
        self, sender_user_id: int, sender_thread_id: int, max_outbox_id: int,
    ) -> None:
        await self._pool.execute(
            "UPDATE dialog_state SET read_outbox_max_id = GREATEST(read_outbox_max_id, $1) "
            "WHERE thread_id = $2 AND owner_user_id = $3",
            max_outbox_id, sender_thread_id, sender_user_id,
        )

    async def reset_unread_count_up_to(
        self, owner_user_id: int, thread_id: int, max_id: int,
    ) -> None:
        # max_id is no longer needed (we just resync to the actual unread
        # count) but kept in the signature so call sites stay stable.
        del max_id
        await self._pool.execute(
            """UPDATE dialog_state ds
               SET unread_count = COALESCE((
                   SELECT COUNT(*)::int
                   FROM message_boxes mb
                   JOIN messages msg ON msg.dialog_message_id = mb.dialog_message_id
                   WHERE mb.user_id = ds.owner_user_id
                     AND msg.thread_id = ds.thread_id
                     AND mb.out = false
                     AND mb.read = false
                     AND NOT mb.deleted
               ), 0)
               WHERE ds.thread_id = $1 AND ds.owner_user_id = $2""",
            thread_id, owner_user_id,
        )

    async def update_dialog_top(
        self,
        owner_user_id: int,
        thread_id: int,
        ubid: int,
        *,
        increment_unread: bool,
    ) -> None:
        await self._pool.execute(
            """UPDATE dialog_state
               SET top_user_message_box_id = GREATEST(top_user_message_box_id, $1),
                   unread_count = unread_count + CASE WHEN $2 THEN 1 ELSE 0 END
               WHERE thread_id = $3 AND owner_user_id = $4""",
            ubid, increment_unread, thread_id, owner_user_id,
        )

    async def unread_count_for_owner(
        self, owner_user_id: int, thread_id: int,
    ) -> int:
        row = await self._pool.fetchrow(
            """SELECT COUNT(*)::int AS c
               FROM message_boxes mb
               JOIN messages msg ON msg.dialog_message_id = mb.dialog_message_id
               WHERE mb.user_id = $1 AND msg.thread_id = $2
                 AND mb.out = false AND mb.read = false AND NOT mb.deleted""",
            owner_user_id, thread_id,
        )
        return int(row["c"]) if row else 0

    async def max_inbox_ubid_in_range(
        self, user_id: int, thread_id: int, max_ubid: int,
    ) -> int:
        """Return the highest inbox copy ≤ max_ubid (0 if none)."""
        row = await self._pool.fetchrow(
            """SELECT MAX(mb.user_message_box_id)::bigint AS m
               FROM message_boxes mb
               JOIN messages msg ON msg.dialog_message_id = mb.dialog_message_id
               WHERE mb.user_id = $1 AND msg.thread_id = $2
                 AND mb.out = false AND NOT mb.deleted
                 AND mb.user_message_box_id <= $3""",
            user_id, thread_id, max_ubid,
        )
        return int(row["m"]) if row and row["m"] else 0
