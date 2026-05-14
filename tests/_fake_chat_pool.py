from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class _ThreadRec:
    thread_id: int
    chat_id: int = 0   # 0 means pm (chat_id IS NULL in DB); >0 means group


@dataclass
class _ThreadParticipantRec:
    thread_id: int
    user_id: int
    inviter_user_id: int
    joined_at_unix: int


@dataclass
class _DialogStateRec:
    thread_id: int
    owner_user_id: int
    peer_user_id: int = 0
    peer_chat_id: int = 0
    read_inbox_max_id: int = 0
    read_outbox_max_id: int = 0
    unread_count: int = 0
    top_user_message_box_id: int = 0
    created_at_unix: int = 0


@dataclass
class _MessageRec:
    """Logical message content (one row per ``dialog_message_id``)."""

    dialog_message_id: int
    thread_id: int
    from_user_id: int
    text: str = ""
    date_unix: int = 0
    edit_date: int = 0
    entities: str | None = None


@dataclass
class _MboxRec:
    """Per-user copy of a logical message."""

    user_id: int
    user_message_box_id: int
    dialog_message_id: int
    out: bool
    random_id: int | None = None
    pts: int = 0
    read: bool = False
    deleted: bool = False


@dataclass
class _ChatRec:
    chat_id: int
    title: str
    created_by: int
    version: int = 1
    participants_count: int = 1
    date_unix: int = 0


@dataclass
class _ChatEventRec:
    event_id: int
    chat_id: int
    actor_user_id: int
    kind: str
    payload: str   # raw JSON
    date_unix: int


@dataclass
class _State:
    sequences: dict[str, int] = field(default_factory=dict)
    threads: list[_ThreadRec] = field(default_factory=list)
    thread_participants: list[_ThreadParticipantRec] = field(default_factory=list)
    dialog_states: list[_DialogStateRec] = field(default_factory=list)
    messages: dict[int, _MessageRec] = field(default_factory=dict)
    boxes: list[_MboxRec] = field(default_factory=list)
    chats: list[_ChatRec] = field(default_factory=list)
    chat_events: list[_ChatEventRec] = field(default_factory=list)


class FakeChatPool:
    """Subset of ``asyncpg.Pool`` used by ChatDAO."""

    def __init__(self) -> None:
        self.state = _State()
        self._chat_event_seq = 0

    # ------------------------------------------------------------------
    # Test seed helpers
    # ------------------------------------------------------------------

    def add_thread(
        self, thread_id: int, chat_id: int = 0,
    ) -> None:
        self.state.threads.append(
            _ThreadRec(thread_id=thread_id, chat_id=chat_id),
        )

    def add_thread_participant(
        self,
        thread_id: int,
        user_id: int,
        *,
        inviter_user_id: int = 0,
        joined_at_unix: int = 0,
    ) -> None:
        if joined_at_unix == 0:
            joined_at_unix = int(time.time())
        self.state.thread_participants.append(
            _ThreadParticipantRec(
                thread_id=thread_id, user_id=user_id,
                inviter_user_id=inviter_user_id,
                joined_at_unix=joined_at_unix,
            ),
        )

    def add_dialog_state(
        self,
        thread_id: int,
        owner_user_id: int,
        *,
        peer_user_id: int = 0,
        peer_chat_id: int = 0,
    ) -> None:
        self.state.dialog_states.append(
            _DialogStateRec(
                thread_id=thread_id,
                owner_user_id=owner_user_id,
                peer_user_id=peer_user_id,
                peer_chat_id=peer_chat_id,
                created_at_unix=int(time.time()),
            ),
        )

    # Backward-compat helper for tests that still talk in "dialog" terms.
    def add_dialog(
        self,
        dialog_id: int,        # treated as thread_id
        owner_user_id: int,
        peer_id: int,
        is_group: bool,
    ) -> None:
        """Seed a thread + dialog_state in one call (legacy test ergonomics)."""
        if not any(t.thread_id == dialog_id for t in self.state.threads):
            self.add_thread(
                thread_id=dialog_id,
                chat_id=peer_id if is_group else 0,
            )
        self.add_dialog_state(
            thread_id=dialog_id,
            owner_user_id=owner_user_id,
            peer_user_id=0 if is_group else peer_id,
            peer_chat_id=peer_id if is_group else 0,
        )

    def add_message_box(
        self,
        *,
        user_id: int,
        user_message_box_id: int,
        dialog_message_id: int,
        dialog_id: int,                # treated as thread_id
        peer_type: int,                # noqa: ARG002 — kept for test API compat
        peer_id: int,                  # noqa: ARG002 — derived from dialog_state
        from_user_id: int,
        out: bool,
        text: str = "",
        date_unix: int = 0,
        pts: int = 0,
        random_id: int | None = None,
    ) -> None:
        """Seed a per-user box + lazily create the shared message record."""
        d = int(date_unix) if date_unix else int(time.time())
        msg = self.state.messages.get(int(dialog_message_id))
        if msg is None:
            self.state.messages[int(dialog_message_id)] = _MessageRec(
                dialog_message_id=int(dialog_message_id),
                thread_id=int(dialog_id),
                from_user_id=int(from_user_id),
                text=str(text),
                date_unix=d,
            )
        self.state.boxes.append(
            _MboxRec(
                user_id=int(user_id),
                user_message_box_id=int(user_message_box_id),
                dialog_message_id=int(dialog_message_id),
                out=bool(out),
                random_id=int(random_id) if random_id is not None else None,
                pts=int(pts),
            ),
        )

    def get_dialog_state(
        self, thread_id: int, owner_user_id: int,
    ) -> _DialogStateRec:
        for d in self.state.dialog_states:
            if d.thread_id == thread_id and d.owner_user_id == owner_user_id:
                return d
        raise KeyError(
            f"no dialog_state thread_id={thread_id} owner={owner_user_id}",
        )

    # Backward-compat helper for older tests that read pool state directly.
    def get_dialog(
        self, dialog_id: int, owner_user_id: int,
    ) -> _DialogStateRec:
        return self.get_dialog_state(dialog_id, owner_user_id)

    def boxes_for(self, user_id: int) -> list[_MboxRec]:
        return [b for b in self.state.boxes if b.user_id == user_id]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _ds_for(
        self, thread_id: int, owner_user_id: int,
    ) -> _DialogStateRec | None:
        for d in self.state.dialog_states:
            if d.thread_id == thread_id and d.owner_user_id == owner_user_id:
                return d
        return None

    def _msg_thread_id(self, dialog_message_id: int) -> int:
        msg = self.state.messages.get(int(dialog_message_id))
        return msg.thread_id if msg else 0

    def _box_join_row(self, b: _MboxRec) -> dict:
        msg = self.state.messages.get(b.dialog_message_id)
        thread_id = msg.thread_id if msg else 0
        ds = self._ds_for(thread_id, b.user_id) if thread_id else None
        return {
            "user_id": b.user_id,
            "user_message_box_id": b.user_message_box_id,
            "dialog_message_id": b.dialog_message_id,
            "thread_id": thread_id,
            "peer_user_id": ds.peer_user_id if ds else 0,
            "peer_chat_id": ds.peer_chat_id if ds else 0,
            "from_user_id": msg.from_user_id if msg else 0,
            "out": b.out,
            "text": msg.text if msg else "",
            "date_unix": msg.date_unix if msg else 0,
            "pts": b.pts,
            "read": b.read,
            "edit_date": msg.edit_date if msg else 0,
        }

    # ------------------------------------------------------------------
    # asyncpg-like API (subset)
    # ------------------------------------------------------------------

    async def fetchrow(self, sql: str, *args):
        return self._fetchrow(sql, args)

    async def fetch(self, sql: str, *args):
        return self._fetch(sql, args)

    async def execute(self, sql: str, *args):
        return self._execute(sql, args)

    def acquire(self) -> "_FakeAcquire":
        return _FakeAcquire(self)

    # ------------------------------------------------------------------
    # _fetchrow dispatch
    # ------------------------------------------------------------------

    def _fetchrow(self, sql: str, args: tuple):
        s = " ".join(sql.split())

        # ChatDAO.next_user_message_box_id (per-user sequence row).
        if "INSERT INTO id_sequences" in s and "RETURNING next_val - 1 AS allocated" in s:
            name = args[0]
            cur = self.state.sequences.get(name, 1)
            self.state.sequences[name] = cur + 1
            return {"allocated": cur}

        # ChatDAO.next_dialog_message_id
        if "UPDATE id_sequences" in s and "name = 'dialog_message_id'" in s:
            cur = self.state.sequences.get("dialog_message_id", 5000) + 1
            self.state.sequences["dialog_message_id"] = cur
            return {"next_val": cur}

        # ChatDAO.next_chat_id / next_thread_id
        if "UPDATE id_sequences SET next_val = next_val + 1 WHERE name = 'chat_id'" in s:
            cur = self.state.sequences.get("chat_id", 3000) + 1
            self.state.sequences["chat_id"] = cur
            return {"next_val": cur}
        if "UPDATE id_sequences SET next_val = next_val + 1 WHERE name = 'thread_id'" in s:
            cur = self.state.sequences.get("thread_id", 2000) + 1
            self.state.sequences["thread_id"] = cur
            return {"next_val": cur}

        # Fallback for unknown id sequences (shouldn't happen in tests).
        if "UPDATE id_sequences SET next_val = next_val + 1 WHERE name =" in s:
            return None

        # ChatDAO.get_chat
        if (
            "SELECT chat_id, title, created_by" in s
            and "FROM chats WHERE chat_id = $1" in s
        ):
            cid = int(args[0])
            for c in self.state.chats:
                if c.chat_id == cid:
                    return _chat_row(c)
            return None

        # ChatDAO.update_title returning version
        if "UPDATE chats" in s and "SET title = $1, version = version + 1" in s:
            title, cid = args[0], int(args[1])
            for c in self.state.chats:
                if c.chat_id == cid:
                    c.title = str(title)
                    c.version += 1
                    return {"version": c.version}
            return None

        # ChatDAO.add_thread_participant follow-up SELECT version
        if "SELECT version FROM chats WHERE chat_id = $1" in s:
            cid = int(args[0])
            for c in self.state.chats:
                if c.chat_id == cid:
                    return {"version": c.version}
            return None

        # ChatDAO.get_thread
        if "SELECT thread_id, chat_id FROM threads WHERE thread_id = $1" in s:
            tid = int(args[0])
            for t in self.state.threads:
                if t.thread_id == tid:
                    return {
                        "thread_id": t.thread_id,
                        "chat_id": t.chat_id if t.chat_id else None,
                    }
            return None

        # ChatDAO.find_thread_for_chat
        if "SELECT thread_id FROM threads WHERE chat_id = $1" in s:
            cid = int(args[0])
            for t in self.state.threads:
                if t.chat_id == cid:
                    return {"thread_id": t.thread_id}
            return None

        # ChatDAO.find_by_random_id
        if (
            "FROM message_boxes mb" in s
            and "JOIN messages msg" in s
            and "mb.random_id = $2" in s
        ):
            uid, rid = int(args[0]), int(args[1])
            for b in self.state.boxes:
                if b.user_id == uid and b.random_id == rid and not b.deleted:
                    return self._box_join_row(b)
            return None

        # ChatDAO.get_box
        if (
            "FROM message_boxes mb" in s
            and "JOIN messages msg" in s
            and "mb.user_id = $1 AND mb.user_message_box_id = $2" in s
        ):
            uid, ubid = int(args[0]), int(args[1])
            for b in self.state.boxes:
                if b.user_id == uid and b.user_message_box_id == ubid:
                    return self._box_join_row(b)
            return None

        # ChatDAO.update_message_content
        if (
            "WITH updated AS" in s
            and "UPDATE messages" in s
            and "SET text = $2" in s
            and "edit_date = $4" in s
        ):
            dmid = int(args[0])
            new_text = str(args[1])
            entities = args[2]
            edit_date = int(args[3])
            msg = self.state.messages.get(dmid)
            if msg is None:
                return {"c": 0}
            msg.text = new_text
            msg.entities = str(entities) if entities is not None else None
            msg.edit_date = edit_date
            return {"c": 1}

        # ChatDAO.max_inbox_ubid_in_range
        if (
            "SELECT MAX(mb.user_message_box_id)::bigint AS m" in s
            and "mb.user_message_box_id <= $3" in s
        ):
            uid, tid, max_id = int(args[0]), int(args[1]), int(args[2])
            candidates = [
                b.user_message_box_id
                for b in self.state.boxes
                if b.user_id == uid
                and self._msg_thread_id(b.dialog_message_id) == tid
                and not b.out and not b.deleted
                and b.user_message_box_id <= max_id
            ]
            return {"m": max(candidates) if candidates else None}

        # ChatDAO.unread_count_for_owner
        if (
            "SELECT COUNT(*)::int AS c" in s
            and "FROM message_boxes mb" in s
            and "JOIN messages msg" in s
            and "mb.read = false" in s
            and "mb.user_id = $1 AND msg.thread_id = $2" in s
            and "($3 = 0" not in s
        ):
            uid, tid = int(args[0]), int(args[1])
            n = sum(
                1 for b in self.state.boxes
                if b.user_id == uid
                and self._msg_thread_id(b.dialog_message_id) == tid
                and not b.out and not b.read and not b.deleted
            )
            return {"c": n}

        # ChatDAO.mark_inbox_read returns count
        if (
            "UPDATE message_boxes mb" in s
            and "SET read = true" in s
            and "WITH updated AS" in s
        ):
            uid, tid, max_ubid = int(args[0]), int(args[1]), int(args[2])
            count = 0
            for b in self.state.boxes:
                if (
                    b.user_id == uid
                    and self._msg_thread_id(b.dialog_message_id) == tid
                    and not b.out and not b.read and not b.deleted
                    and b.user_message_box_id <= max_ubid
                ):
                    b.read = True
                    count += 1
            return {"c": count}

        # ChatDAO.count_history
        if (
            "SELECT COUNT(*)::int AS c" in s
            and "FROM message_boxes mb" in s
            and "JOIN messages msg" in s
            and "($3 = 0" in s
        ):
            uid, tid, off, mn, mx = (
                int(args[0]), int(args[1]), int(args[2]),
                int(args[3]), int(args[4]),
            )
            n = 0
            for b in self.state.boxes:
                if (
                    b.user_id != uid
                    or self._msg_thread_id(b.dialog_message_id) != tid
                    or b.deleted
                ):
                    continue
                if off and not (b.user_message_box_id < off):
                    continue
                if mn and not (b.user_message_box_id >= mn):
                    continue
                if mx and not (b.user_message_box_id <= mx):
                    continue
                n += 1
            return {"c": n}

        # ChatDAO.get_dialog_state
        if (
            "SELECT thread_id, owner_user_id," in s
            and "FROM dialog_state WHERE thread_id = $1 AND owner_user_id = $2" in s
        ):
            tid, uid = int(args[0]), int(args[1])
            ds = self._ds_for(tid, uid)
            if ds is None:
                return None
            return {
                "thread_id": ds.thread_id,
                "owner_user_id": ds.owner_user_id,
                "peer_user_id": ds.peer_user_id,
                "peer_chat_id": ds.peer_chat_id,
                "read_inbox_max_id": ds.read_inbox_max_id,
                "read_outbox_max_id": ds.read_outbox_max_id,
                "unread_count": ds.unread_count,
                "top_user_message_box_id": ds.top_user_message_box_id,
            }

        # ChatDAO.find_thread_by_peer (chat)
        if (
            "SELECT thread_id FROM dialog_state" in s
            and "peer_chat_id = $2" in s
        ):
            owner, chat_id = int(args[0]), int(args[1])
            for d in self.state.dialog_states:
                if d.owner_user_id == owner and d.peer_chat_id == chat_id:
                    return {"thread_id": d.thread_id}
            return None

        # ChatDAO.find_thread_by_peer (user)
        if (
            "SELECT thread_id FROM dialog_state" in s
            and "peer_user_id = $2" in s
        ):
            owner, peer_uid = int(args[0]), int(args[1])
            for d in self.state.dialog_states:
                if d.owner_user_id == owner and d.peer_user_id == peer_uid:
                    return {"thread_id": d.thread_id}
            return None

        # ChatDAO.find_private_thread
        if (
            "SELECT ds1.thread_id FROM dialog_state ds1" in s
            and "JOIN dialog_state ds2" in s
            and "JOIN threads t" in s
        ):
            a, b = int(args[0]), int(args[1])
            for t in self.state.threads:
                if t.chat_id != 0:
                    continue
                ds_a = self._ds_for(t.thread_id, a)
                ds_b = self._ds_for(t.thread_id, b)
                if (
                    ds_a is not None and ds_a.peer_user_id == b
                    and ds_b is not None and ds_b.peer_user_id == a
                ):
                    return {"thread_id": t.thread_id}
            return None

        # ChatDAO.count_dialogs
        if "SELECT count(*) AS n FROM dialog_state WHERE owner_user_id = $1" in s:
            uid = int(args[0])
            return {"n": sum(1 for d in self.state.dialog_states if d.owner_user_id == uid)}

        # ChatDAO.add_chat_event
        if "INSERT INTO chat_events" in s and "RETURNING event_id" in s:
            chat_id, actor, kind, payload_json, date_unix = args[:5]
            self._chat_event_seq += 1
            self.state.chat_events.append(
                _ChatEventRec(
                    event_id=self._chat_event_seq,
                    chat_id=int(chat_id),
                    actor_user_id=int(actor),
                    kind=str(kind),
                    payload=str(payload_json),
                    date_unix=int(date_unix),
                ),
            )
            return {"event_id": self._chat_event_seq}

        raise NotImplementedError(f"FakeChatPool.fetchrow: {s[:160]}")

    # ------------------------------------------------------------------
    # _fetch dispatch
    # ------------------------------------------------------------------

    def _fetch(self, sql: str, args: tuple):
        s = " ".join(sql.split())

        # ChatDAO.get_chats_batch
        if (
            "SELECT chat_id, title, created_by" in s
            and "FROM chats WHERE chat_id = ANY($1::bigint[])" in s
        ):
            ids = {int(i) for i in args[0]}
            return [_chat_row(c) for c in self.state.chats if c.chat_id in ids]

        # ChatDAO.get_thread_participants
        if (
            "SELECT user_id, inviter_user_id" in s
            and "FROM thread_participants WHERE thread_id = $1" in s
        ):
            tid = int(args[0])
            participants = sorted(
                (
                    p for p in self.state.thread_participants
                    if p.thread_id == tid
                ),
                key=lambda p: p.joined_at_unix,
            )
            return [
                {
                    "user_id": p.user_id,
                    "inviter_user_id": p.inviter_user_id,
                    "joined_at_unix": p.joined_at_unix,
                }
                for p in participants
            ]

        # ChatDAO.get_thread_participant_ids
        if "SELECT user_id FROM thread_participants WHERE thread_id = $1" in s:
            tid = int(args[0])
            return [
                {"user_id": p.user_id}
                for p in self.state.thread_participants if p.thread_id == tid
            ]

        # ChatDAO.get_boxes_for_user
        if (
            "FROM message_boxes mb" in s
            and "JOIN messages msg" in s
            and "mb.user_id = $1" in s
            and "mb.user_message_box_id = ANY($2::bigint[])" in s
            and "NOT mb.deleted" in s
        ):
            uid = int(args[0])
            ids = {int(i) for i in args[1]}
            return [
                self._box_join_row(b)
                for b in self.state.boxes
                if b.user_id == uid and b.user_message_box_id in ids
                and not b.deleted
            ]

        # ChatDAO.get_boxes_by_dialog_message_ids
        if (
            "FROM message_boxes mb" in s
            and "JOIN messages msg" in s
            and "mb.dialog_message_id = ANY($1::bigint[])" in s
            and "NOT mb.deleted" in s
        ):
            dmids = {int(i) for i in args[0]}
            return [
                self._box_join_row(b)
                for b in self.state.boxes
                if b.dialog_message_id in dmids and not b.deleted
            ]

        # ChatDAO.mark_deleted (single user variant)
        if (
            "UPDATE message_boxes" in s
            and "SET deleted = true" in s
            and "WHERE user_id = $1" in s
            and "user_message_box_id = ANY($2::bigint[])" in s
            and "RETURNING user_message_box_id" in s
        ):
            uid = int(args[0])
            ids = {int(i) for i in args[1]}
            out: list[dict] = []
            for b in self.state.boxes:
                if (
                    b.user_id == uid
                    and b.user_message_box_id in ids
                    and not b.deleted
                ):
                    b.deleted = True
                    out.append({"user_message_box_id": b.user_message_box_id})
            return out

        # ChatDAO.get_history
        if (
            "FROM message_boxes mb" in s
            and "JOIN messages msg" in s
            and "ORDER BY mb.user_message_box_id DESC" in s
        ):
            uid, tid, off, mn, mx, lim, ofs = (
                int(args[0]), int(args[1]), int(args[2]),
                int(args[3]), int(args[4]), int(args[5]), int(args[6]),
            )
            res: list[dict] = []
            for b in self.state.boxes:
                if (
                    b.user_id != uid
                    or self._msg_thread_id(b.dialog_message_id) != tid
                    or b.deleted
                ):
                    continue
                if off and not (b.user_message_box_id < off):
                    continue
                if mn and not (b.user_message_box_id >= mn):
                    continue
                if mx and not (b.user_message_box_id <= mx):
                    continue
                res.append(self._box_join_row(b))
            res.sort(key=lambda r: r["user_message_box_id"], reverse=True)
            return res[ofs : ofs + lim]

        # ChatDAO.peer_outbox_for_inbox
        if "WITH inbox_just_read AS" in s and "JOIN inbox_just_read" in s:
            reader, tid, max_inbox = (
                int(args[0]), int(args[1]), int(args[2]),
            )
            inbox_pairs: set[tuple[int, int]] = set()
            for b in self.state.boxes:
                if (
                    b.user_id == reader
                    and self._msg_thread_id(b.dialog_message_id) == tid
                    and not b.out and not b.deleted
                    and b.user_message_box_id <= max_inbox
                ):
                    msg = self.state.messages.get(b.dialog_message_id)
                    from_uid = msg.from_user_id if msg else 0
                    inbox_pairs.add((b.dialog_message_id, from_uid))
            grouped: dict[tuple[int, int], int] = {}
            for b in self.state.boxes:
                if b.out and not b.deleted and b.user_id != reader:
                    if (b.dialog_message_id, b.user_id) in inbox_pairs:
                        sender_tid = self._msg_thread_id(b.dialog_message_id)
                        key = (b.user_id, sender_tid)
                        cur = grouped.get(key, 0)
                        if b.user_message_box_id > cur:
                            grouped[key] = b.user_message_box_id
            return [
                {
                    "sender_user_id": uid,
                    "sender_thread_id": tid_s,
                    "max_outbox_id": max_o,
                }
                for (uid, tid_s), max_o in grouped.items()
            ]

        # ChatDAO.find_dialog_states_by_thread_id
        if (
            "SELECT owner_user_id," in s
            and "FROM dialog_state WHERE thread_id = $1" in s
        ):
            tid = int(args[0])
            return [
                {
                    "owner_user_id": d.owner_user_id,
                    "peer_user_id": d.peer_user_id,
                    "peer_chat_id": d.peer_chat_id,
                }
                for d in self.state.dialog_states if d.thread_id == tid
            ]

        # ChatDAO.list_dialogs
        if (
            "FROM dialog_state ds" in s
            and "LEFT JOIN LATERAL" in s
            and "ORDER BY" in s
        ):
            uid = int(args[0])
            lim = int(args[1])
            rows: list[dict] = []
            for d in self.state.dialog_states:
                if d.owner_user_id != uid:
                    continue
                last = max(
                    (
                        b for b in self.state.boxes
                        if b.user_id == uid
                        and self._msg_thread_id(b.dialog_message_id) == d.thread_id
                        and not b.deleted
                    ),
                    key=lambda b: b.user_message_box_id,
                    default=None,
                )
                msg = (
                    self.state.messages.get(last.dialog_message_id)
                    if last is not None else None
                )
                rows.append(
                    {
                        "thread_id": d.thread_id,
                        "owner_user_id": d.owner_user_id,
                        "peer_user_id": d.peer_user_id,
                        "peer_chat_id": d.peer_chat_id,
                        "read_inbox_max_id": d.read_inbox_max_id,
                        "read_outbox_max_id": d.read_outbox_max_id,
                        "unread_count": d.unread_count,
                        "top_message_id": int(last.user_message_box_id) if last else 0,
                        "top_from_user_id": int(msg.from_user_id) if msg else 0,
                        "top_message_text": msg.text if msg else "",
                        "top_message_date": int(msg.date_unix) if msg else 0,
                        "top_message_out": bool(last.out) if last else False,
                        "top_dialog_message_id": (
                            int(last.dialog_message_id) if last else 0
                        ),
                    },
                )
            rows.sort(
                key=lambda r: (r["top_message_date"], r["thread_id"]),
                reverse=True,
            )
            return rows[:lim]

        raise NotImplementedError(f"FakeChatPool.fetch: {s[:160]}")

    # ------------------------------------------------------------------
    # _execute dispatch
    # ------------------------------------------------------------------

    def _execute(self, sql: str, args: tuple):
        s = " ".join(sql.split())

        # ChatDAO.create_chat
        if (
            "INSERT INTO chats" in s
            and "(chat_id, title, created_by," in s
        ):
            cid, title, creator, date_unix = (
                int(args[0]), str(args[1]), int(args[2]), int(args[3]),
            )
            self.state.chats.append(
                _ChatRec(
                    chat_id=cid, title=title, created_by=creator,
                    version=1, participants_count=0, date_unix=date_unix,
                ),
            )
            return None

        # ChatDAO.create_thread
        if "INSERT INTO threads (thread_id, chat_id)" in s:
            tid, chat_id = args[0], args[1]
            self.state.threads.append(
                _ThreadRec(
                    thread_id=int(tid),
                    chat_id=int(chat_id) if chat_id else 0,
                ),
            )
            return None

        # ChatDAO.bulk_add_thread_participants single insert
        if (
            "INSERT INTO thread_participants" in s
            and "(thread_id, user_id, inviter_user_id, joined_at)" in s
        ):
            tid, uid, inviter, joined = (
                int(args[0]), int(args[1]), int(args[2]), int(args[3]),
            )
            existing = any(
                p.thread_id == tid and p.user_id == uid
                for p in self.state.thread_participants
            )
            if existing:
                return "INSERT 0 0"
            self.state.thread_participants.append(
                _ThreadParticipantRec(
                    thread_id=tid, user_id=uid,
                    inviter_user_id=inviter, joined_at_unix=joined,
                ),
            )
            return "INSERT 0 1"

        # ChatDAO.bulk_add_thread_participants chat counter bump
        if (
            "UPDATE chats" in s
            and "version = version + 1" in s
            and "participants_count = participants_count + $1" in s
        ):
            inserted, cid = int(args[0]), int(args[1])
            for c in self.state.chats:
                if c.chat_id == cid:
                    c.version += 1
                    c.participants_count += inserted
            return None

        # ChatDAO.create_dialog_state
        if (
            "INSERT INTO dialog_state" in s
            and "(thread_id, owner_user_id, peer_user_id, peer_chat_id)" in s
        ):
            tid, owner, peer_uid, peer_cid = args[:4]
            self.state.dialog_states.append(
                _DialogStateRec(
                    thread_id=int(tid),
                    owner_user_id=int(owner),
                    peer_user_id=int(peer_uid) if peer_uid else 0,
                    peer_chat_id=int(peer_cid) if peer_cid else 0,
                    created_at_unix=int(time.time()),
                ),
            )
            return None

        # ChatDAO.insert_message_with_boxes — `messages` insert.
        if (
            "INSERT INTO messages" in s
            and "(dialog_message_id, thread_id, from_user_id, text, date_unix)" in s
        ):
            dmid, tid, from_uid, text_, date_unix = (
                int(args[0]), int(args[1]), int(args[2]),
                str(args[3]), int(args[4]),
            )
            self.state.messages[dmid] = _MessageRec(
                dialog_message_id=dmid,
                thread_id=tid,
                from_user_id=from_uid,
                text=text_,
                date_unix=date_unix,
            )
            return None

        # ChatDAO.insert_message_with_boxes — `message_boxes` insert.
        if (
            "INSERT INTO message_boxes" in s
            and "(user_id, user_message_box_id, dialog_message_id," in s
            and "out, random_id, pts)" in s
        ):
            uid, ubid, dmid, out_, rid, pts = args[:6]
            self.state.boxes.append(
                _MboxRec(
                    user_id=int(uid),
                    user_message_box_id=int(ubid),
                    dialog_message_id=int(dmid),
                    out=bool(out_),
                    random_id=int(rid) if rid is not None else None,
                    pts=int(pts),
                ),
            )
            return None

        # ChatDAO.update_read_inbox
        if "UPDATE dialog_state SET read_inbox_max_id" in s:
            max_id, tid, owner = int(args[0]), int(args[1]), int(args[2])
            for d in self.state.dialog_states:
                if d.thread_id == tid and d.owner_user_id == owner:
                    if max_id > d.read_inbox_max_id:
                        d.read_inbox_max_id = max_id
            return None

        # ChatDAO.update_read_outbox
        if "UPDATE dialog_state SET read_outbox_max_id" in s:
            max_id, tid, owner = int(args[0]), int(args[1]), int(args[2])
            for d in self.state.dialog_states:
                if d.thread_id == tid and d.owner_user_id == owner:
                    if max_id > d.read_outbox_max_id:
                        d.read_outbox_max_id = max_id
            return None

        # ChatDAO.update_dialog_top
        if "UPDATE dialog_state" in s and "top_user_message_box_id" in s:
            ubid, inc, tid, owner = (
                int(args[0]), bool(args[1]),
                int(args[2]), int(args[3]),
            )
            for d in self.state.dialog_states:
                if d.thread_id == tid and d.owner_user_id == owner:
                    d.top_user_message_box_id = max(
                        d.top_user_message_box_id, ubid,
                    )
                    if inc:
                        d.unread_count += 1
            return None

        # ChatDAO.reset_unread_count_up_to
        if "UPDATE dialog_state ds" in s and "unread_count = COALESCE" in s:
            tid, owner = int(args[0]), int(args[1])
            for d in self.state.dialog_states:
                if d.thread_id == tid and d.owner_user_id == owner:
                    d.unread_count = sum(
                        1
                        for b in self.state.boxes
                        if b.user_id == owner
                        and self._msg_thread_id(b.dialog_message_id) == tid
                        and not b.out and not b.read and not b.deleted
                    )
            return None

        # NOTIFY is no-op in tests (and shouldn't reach here at all in the
        # split architecture — UpdatesDAO owns the channel).
        if s.strip().upper().startswith("NOTIFY "):
            return None

        raise NotImplementedError(f"FakeChatPool.execute: {s[:160]}")


def _chat_row(c: _ChatRec) -> dict:
    return {
        "chat_id": c.chat_id,
        "title": c.title,
        "created_by": c.created_by,
        "version": c.version,
        "participants_count": c.participants_count,
        "date_unix": c.date_unix,
    }


class _FakeAcquire:
    def __init__(self, pool: FakeChatPool) -> None:
        self._pool = pool

    async def __aenter__(self) -> "_FakeConn":
        return _FakeConn(self._pool)

    async def __aexit__(self, *exc_info) -> None:
        return None


class _FakeTx:
    """Async context manager for ``conn.transaction()`` in tests."""

    async def __aenter__(self) -> "_FakeTx":
        return self

    async def __aexit__(self, *exc_info) -> None:
        return None


class _FakeConn:
    def __init__(self, pool: FakeChatPool) -> None:
        self._pool = pool

    def transaction(self) -> _FakeTx:
        return _FakeTx()

    async def executemany(self, sql: str, records: list[tuple]) -> None:
        for rec in records:
            await self._pool.execute(sql, *rec)

    async def execute(self, sql: str, *args):
        return await self._pool.execute(sql, *args)

    async def fetch(self, sql: str, *args):
        return await self._pool.fetch(sql, *args)

    async def fetchrow(self, sql: str, *args):
        return await self._pool.fetchrow(sql, *args)
