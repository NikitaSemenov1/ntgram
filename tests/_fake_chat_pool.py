from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class _DialogRec:
    dialog_id: int
    owner_user_id: int
    peer_id: int
    is_group: bool
    read_inbox_max_id: int = 0
    read_outbox_max_id: int = 0
    unread_count: int = 0
    top_user_message_box_id: int = 0
    top_message_date: int = 0


@dataclass
class _MboxRec:
    user_id: int
    user_message_box_id: int
    dialog_message_id: int
    dialog_id: int
    peer_type: int
    peer_id: int
    from_user_id: int
    out: bool
    random_id: int | None = None
    text: str = ""
    date_unix: int = 0
    pts: int = 0
    read: bool = False
    deleted: bool = False
    edit_date: int = 0
    entities: str | None = None


@dataclass
class _ChatRec:
    chat_id: int
    title: str
    created_by: int
    version: int = 1
    participants_count: int = 1
    date_unix: int = 0


@dataclass
class _ChatMemberRec:
    chat_id: int
    user_id: int
    inviter_user_id: int
    joined_at_unix: int


@dataclass
class _State:
    sequences: dict[str, int] = field(default_factory=dict)
    dialogs: list[_DialogRec] = field(default_factory=list)
    boxes: list[_MboxRec] = field(default_factory=list)
    chats: list[_ChatRec] = field(default_factory=list)
    chat_members: list[_ChatMemberRec] = field(default_factory=list)


class FakeChatPool:
    """Subset of ``asyncpg.Pool`` used by ChatDAO."""

    def __init__(self) -> None:
        self.state = _State()

    # ------------------------------------------------------------------
    # Test seed helpers
    # ------------------------------------------------------------------

    def add_dialog(
        self,
        dialog_id: int,
        owner_user_id: int,
        peer_id: int,
        is_group: bool,
    ) -> None:
        self.state.dialogs.append(
            _DialogRec(dialog_id, owner_user_id, peer_id, is_group),
        )

    def add_message_box(
        self,
        *,
        user_id: int,
        user_message_box_id: int,
        dialog_message_id: int,
        dialog_id: int,
        peer_type: int,
        peer_id: int,
        from_user_id: int,
        out: bool,
        text: str = "",
        date_unix: int = 0,
        pts: int = 0,
        random_id: int | None = None,
    ) -> None:
        self.state.boxes.append(
            _MboxRec(
                user_id=user_id,
                user_message_box_id=user_message_box_id,
                dialog_message_id=dialog_message_id,
                dialog_id=dialog_id,
                peer_type=peer_type,
                peer_id=peer_id,
                from_user_id=from_user_id,
                out=out,
                text=text,
                date_unix=date_unix if date_unix else int(time.time()),
                pts=pts,
                random_id=random_id,
            ),
        )

    def get_dialog(self, dialog_id: int, owner_user_id: int) -> _DialogRec:
        for d in self.state.dialogs:
            if d.dialog_id == dialog_id and d.owner_user_id == owner_user_id:
                return d
        raise KeyError(f"no dialog {dialog_id} for owner {owner_user_id}")

    def boxes_for(self, user_id: int) -> list[_MboxRec]:
        return [b for b in self.state.boxes if b.user_id == user_id]

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

        # ChatDAO.next_chat_id / next_dialog_id
        if "UPDATE id_sequences SET next_val = next_val + 1 WHERE name = 'chat_id'" in s:
            cur = self.state.sequences.get("chat_id", 3000) + 1
            self.state.sequences["chat_id"] = cur
            return {"next_val": cur}
        if "UPDATE id_sequences SET next_val = next_val + 1 WHERE name = 'dialog_id'" in s:
            cur = self.state.sequences.get("dialog_id", 2000) + 1
            self.state.sequences["dialog_id"] = cur
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

        # ChatDAO.add_member follow-up SELECT version
        if "SELECT version FROM chats WHERE chat_id = $1" in s:
            cid = int(args[0])
            for c in self.state.chats:
                if c.chat_id == cid:
                    return {"version": c.version}
            return None

        # ChatDAO.count_members
        if "SELECT count(*) as cnt FROM chat_members WHERE chat_id = $1" in s:
            cid = int(args[0])
            n = sum(1 for m in self.state.chat_members if m.chat_id == cid)
            return {"cnt": n}

        # ChatDAO.find_by_random_id
        if "SELECT" in s and "FROM message_boxes" in s and "random_id = $2" in s:
            uid, rid = int(args[0]), int(args[1])
            for b in self.state.boxes:
                if b.user_id == uid and b.random_id == rid and not b.deleted:
                    return _row_from_mbox(b)
            return None

        # ChatDAO.get_box (projection includes ``deleted``).
        if (
            "FROM message_boxes" in s
            and "WHERE user_id = $1 AND user_message_box_id = $2" in s
            and "deleted" in s.split("FROM")[0]
        ):
            uid, ubid = int(args[0]), int(args[1])
            for b in self.state.boxes:
                if b.user_id == uid and b.user_message_box_id == ubid:
                    row = _row_from_mbox(b)
                    row["deleted"] = b.deleted
                    return row
            return None

        # ChatDAO.update_text_by_dialog_message_id
        if (
            "WITH updated AS" in s
            and "UPDATE message_boxes" in s
            and "SET text = $2" in s
            and "edit_date = $4" in s
        ):
            dmid = int(args[0])
            new_text = str(args[1])
            entities = args[2]
            edit_date = int(args[3])
            n = 0
            for b in self.state.boxes:
                if b.dialog_message_id == dmid and not b.deleted:
                    b.text = new_text
                    b.entities = (
                        str(entities) if entities is not None else None
                    )
                    b.edit_date = edit_date
                    n += 1
            return {"c": n}

        # ChatDAO.max_inbox_ubid_in_range
        if (
            "SELECT MAX(user_message_box_id)::bigint AS m" in s
            and "user_message_box_id <= $3" in s
        ):
            uid, did, max_id = int(args[0]), int(args[1]), int(args[2])
            candidates = [
                b.user_message_box_id
                for b in self.state.boxes
                if b.user_id == uid and b.dialog_id == did
                and not b.out and not b.deleted
                and b.user_message_box_id <= max_id
            ]
            return {"m": max(candidates) if candidates else None}

        # ChatDAO.unread_count_for_owner
        if (
            "SELECT COUNT(*)::int AS c FROM message_boxes" in s
            and "AND read = false" in s
            and "WHERE user_id = $1 AND dialog_id = $2" in s
        ):
            uid, did = int(args[0]), int(args[1])
            n = sum(
                1 for b in self.state.boxes
                if b.user_id == uid and b.dialog_id == did
                and not b.out and not b.read and not b.deleted
            )
            return {"c": n}

        # ChatDAO.mark_inbox_read returns count
        if "UPDATE message_boxes" in s and "SET read = true" in s and "WITH updated AS" in s:
            uid, did, max_ubid = int(args[0]), int(args[1]), int(args[2])
            count = 0
            for b in self.state.boxes:
                if (
                    b.user_id == uid and b.dialog_id == did
                    and not b.out and not b.read and not b.deleted
                    and b.user_message_box_id <= max_ubid
                ):
                    b.read = True
                    count += 1
            return {"c": count}

        # ChatDAO.count_history
        if "SELECT COUNT(*)::int AS c FROM message_boxes" in s and "AND ($3 = 0" in s:
            uid, did, off, mn, mx = (
                int(args[0]), int(args[1]), int(args[2]),
                int(args[3]), int(args[4]),
            )
            n = 0
            for b in self.state.boxes:
                if b.user_id != uid or b.dialog_id != did or b.deleted:
                    continue
                if off and not (b.user_message_box_id < off):
                    continue
                if mn and not (b.user_message_box_id >= mn):
                    continue
                if mx and not (b.user_message_box_id <= mx):
                    continue
                n += 1
            return {"c": n}

        # ChatDAO.get_dialog_for_owner
        if (
            "SELECT dialog_id, owner_user_id, peer_id, is_group" in s
            and "WHERE dialog_id = $1 AND owner_user_id = $2" in s
        ):
            did, uid = int(args[0]), int(args[1])
            try:
                d = self.get_dialog(did, uid)
            except KeyError:
                return None
            return {
                "dialog_id": d.dialog_id,
                "owner_user_id": d.owner_user_id,
                "peer_id": d.peer_id,
                "is_group": d.is_group,
                "read_inbox_max_id": d.read_inbox_max_id,
                "read_outbox_max_id": d.read_outbox_max_id,
                "unread_count": d.unread_count,
                "top_user_message_box_id": d.top_user_message_box_id,
                "top_message_date": d.top_message_date,
            }

        # ChatDAO.find_dialog_by_peer
        if (
            "SELECT dialog_id FROM dialogs" in s
            and "owner_user_id = $1" in s
            and "is_group = $2" in s
            and "peer_id = $3" in s
        ):
            owner, is_group, peer_id = int(args[0]), bool(args[1]), int(args[2])
            for d in self.state.dialogs:
                if (
                    d.owner_user_id == owner
                    and bool(d.is_group) == is_group
                    and d.peer_id == peer_id
                ):
                    return {"dialog_id": d.dialog_id}
            return None

        # ChatDAO.find_private_dialog
        if (
            "SELECT d1.dialog_id FROM dialogs d1" in s
            and "JOIN dialogs d2" in s
        ):
            a, b = int(args[0]), int(args[1])
            seen: dict[int, set[tuple[int, int]]] = {}
            for d in self.state.dialogs:
                seen.setdefault(d.dialog_id, set()).add(
                    (d.owner_user_id, d.peer_id),
                )
            for did, pairs in seen.items():
                if (a, b) in pairs and (b, a) in pairs:
                    return {"dialog_id": did}
            return None

        # ChatDAO.count_dialogs
        if "SELECT count(*) AS n FROM dialogs WHERE owner_user_id = $1" in s:
            uid = int(args[0])
            return {"n": sum(1 for d in self.state.dialogs if d.owner_user_id == uid)}

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

        # ChatDAO.get_members
        if (
            "SELECT user_id, inviter_user_id" in s
            and "FROM chat_members WHERE chat_id = $1" in s
        ):
            cid = int(args[0])
            members = sorted(
                (m for m in self.state.chat_members if m.chat_id == cid),
                key=lambda m: m.joined_at_unix,
            )
            return [
                {
                    "user_id": m.user_id,
                    "inviter_user_id": m.inviter_user_id,
                    "joined_at_unix": m.joined_at_unix,
                }
                for m in members
            ]

        # ChatDAO.get_member_ids
        if "SELECT user_id FROM chat_members WHERE chat_id = $1" in s:
            cid = int(args[0])
            return [
                {"user_id": m.user_id}
                for m in self.state.chat_members if m.chat_id == cid
            ]

        # ChatDAO.get_members_count_batch
        if (
            "SELECT chat_id, COUNT(*)::int AS cnt" in s
            and "FROM chat_members" in s
            and "GROUP BY chat_id" in s
        ):
            ids = {int(i) for i in args[0]}
            counts: dict[int, int] = {}
            for m in self.state.chat_members:
                if m.chat_id in ids:
                    counts[m.chat_id] = counts.get(m.chat_id, 0) + 1
            return [{"chat_id": cid, "cnt": cnt} for cid, cnt in counts.items()]

        # ChatDAO.get_boxes_for_user
        if (
            "FROM message_boxes" in s
            and "WHERE user_id = $1" in s
            and "user_message_box_id = ANY($2::bigint[])" in s
            and "AND NOT deleted" in s
            and "ORDER BY" not in s
        ):
            uid = int(args[0])
            ids = {int(i) for i in args[1]}
            return [
                _row_from_mbox(b)
                for b in self.state.boxes
                if b.user_id == uid and b.user_message_box_id in ids
                and not b.deleted
            ]

        # ChatDAO.get_boxes_by_dialog_message_ids
        if (
            "FROM message_boxes" in s
            and "WHERE dialog_message_id = ANY($1::bigint[])" in s
            and "AND NOT deleted" in s
        ):
            dmids = {int(i) for i in args[0]}
            return [
                _row_from_mbox(b)
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
        if "FROM message_boxes" in s and "ORDER BY user_message_box_id DESC" in s:
            uid, did, off, mn, mx, lim, ofs = (
                int(args[0]), int(args[1]), int(args[2]),
                int(args[3]), int(args[4]), int(args[5]), int(args[6]),
            )
            res: list[dict] = []
            for b in self.state.boxes:
                if b.user_id != uid or b.dialog_id != did or b.deleted:
                    continue
                if off and not (b.user_message_box_id < off):
                    continue
                if mn and not (b.user_message_box_id >= mn):
                    continue
                if mx and not (b.user_message_box_id <= mx):
                    continue
                res.append(_row_from_mbox(b))
            res.sort(key=lambda r: r["user_message_box_id"], reverse=True)
            return res[ofs : ofs + lim]

        # ChatDAO.peer_outbox_for_inbox
        if "WITH inbox_just_read AS" in s and "JOIN inbox_just_read" in s:
            reader, did, max_inbox = (
                int(args[0]), int(args[1]), int(args[2]),
            )
            inbox_pairs = {
                (b.dialog_message_id, b.from_user_id)
                for b in self.state.boxes
                if b.user_id == reader and b.dialog_id == did
                and not b.out and not b.deleted
                and b.user_message_box_id <= max_inbox
            }
            grouped: dict[tuple[int, int], int] = {}
            for b in self.state.boxes:
                if b.out and not b.deleted and b.user_id != reader:
                    if (b.dialog_message_id, b.user_id) in inbox_pairs:
                        key = (b.user_id, b.dialog_id)
                        cur = grouped.get(key, 0)
                        if b.user_message_box_id > cur:
                            grouped[key] = b.user_message_box_id
            return [
                {
                    "sender_user_id": uid,
                    "sender_dialog_id": did_s,
                    "max_outbox_id": max_o,
                }
                for (uid, did_s), max_o in grouped.items()
            ]

        # ChatDAO.get_dialog_owners
        if "SELECT owner_user_id, peer_id, is_group FROM dialogs" in s:
            did = int(args[0])
            return [
                {
                    "owner_user_id": d.owner_user_id,
                    "peer_id": d.peer_id,
                    "is_group": d.is_group,
                }
                for d in self.state.dialogs if d.dialog_id == did
            ]

        # ChatDAO.find_dialogs_by_dialog_id (legacy alias of the same query)
        if "SELECT owner_user_id, peer_id, is_group FROM dialogs WHERE dialog_id = $1" in s:
            did = int(args[0])
            return [
                {
                    "owner_user_id": d.owner_user_id,
                    "peer_id": d.peer_id,
                    "is_group": d.is_group,
                }
                for d in self.state.dialogs if d.dialog_id == did
            ]

        # ChatDAO.list_dialogs
        if (
            "FROM dialogs d" in s
            and "LEFT JOIN LATERAL" in s
            and "ORDER BY" in s
        ):
            uid = int(args[0])
            lim = int(args[1])
            rows: list[dict] = []
            for d in self.state.dialogs:
                if d.owner_user_id != uid:
                    continue
                last = max(
                    (
                        b for b in self.state.boxes
                        if b.user_id == uid and b.dialog_id == d.dialog_id
                        and not b.deleted
                    ),
                    key=lambda b: b.user_message_box_id,
                    default=None,
                )
                rows.append(
                    {
                        "dialog_id": d.dialog_id,
                        "owner_user_id": d.owner_user_id,
                        "peer_id": d.peer_id,
                        "is_group": d.is_group,
                        "read_inbox_max_id": d.read_inbox_max_id,
                        "read_outbox_max_id": d.read_outbox_max_id,
                        "unread_count": d.unread_count,
                        "top_message_id": int(last.user_message_box_id) if last else 0,
                        "top_from_user_id": int(last.from_user_id) if last else 0,
                        "top_message_text": last.text if last else "",
                        "top_message_date": int(last.date_unix) if last else 0,
                        "top_message_out": bool(last.out) if last else False,
                        "top_dialog_message_id": (
                            int(last.dialog_message_id) if last else 0
                        ),
                    },
                )
            rows.sort(
                key=lambda r: (r["top_message_date"], r["dialog_id"]),
                reverse=True,
            )
            return rows[:lim]

        if "SELECT owner_user_id FROM dialogs WHERE dialog_id" in s:
            did = int(args[0])
            return [
                {"owner_user_id": d.owner_user_id}
                for d in self.state.dialogs if d.dialog_id == did
            ]

        raise NotImplementedError(f"FakeChatPool.fetch: {s[:160]}")

    # ------------------------------------------------------------------
    # _execute dispatch
    # ------------------------------------------------------------------

    def _execute(self, sql: str, args: tuple):
        s = " ".join(sql.split())

        # ChatDAO.create_chat
        if (
            "INSERT INTO chats" in s
            and "(chat_id, title, is_group, created_by," in s
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

        # ChatDAO.bulk_add_members single insert
        if (
            "INSERT INTO chat_members" in s
            and "(chat_id, user_id, inviter_user_id, joined_at)" in s
        ):
            cid, uid, inviter, joined = (
                int(args[0]), int(args[1]), int(args[2]), int(args[3]),
            )
            existing = any(
                m.chat_id == cid and m.user_id == uid
                for m in self.state.chat_members
            )
            if existing:
                return "INSERT 0 0"
            self.state.chat_members.append(
                _ChatMemberRec(
                    chat_id=cid, user_id=uid,
                    inviter_user_id=inviter, joined_at_unix=joined,
                ),
            )
            return "INSERT 0 1"

        # ChatDAO.bulk_add_members chat counter bump
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

        # ChatDAO.create_dialog
        if "INSERT INTO dialogs" in s and "(dialog_id, owner_user_id, peer_id, is_group)" in s:
            did, owner, peer_id, is_group = (
                int(args[0]), int(args[1]), int(args[2]), bool(args[3]),
            )
            self.state.dialogs.append(
                _DialogRec(
                    dialog_id=did, owner_user_id=owner,
                    peer_id=peer_id, is_group=is_group,
                ),
            )
            return None

        # ChatDAO.insert_message_box_batch (single row variant)
        if "INSERT INTO message_boxes" in s and "$12" in s:
            (uid, ubid, dmid, did, ptype, pid, fr, out_,
             rid, text_, date_unix, pts) = args[:12]
            self.state.boxes.append(
                _MboxRec(
                    user_id=int(uid),
                    user_message_box_id=int(ubid),
                    dialog_message_id=int(dmid),
                    dialog_id=int(did),
                    peer_type=int(ptype),
                    peer_id=int(pid),
                    from_user_id=int(fr),
                    out=bool(out_),
                    random_id=int(rid) if rid is not None else None,
                    text=str(text_),
                    date_unix=int(date_unix),
                    pts=int(pts),
                ),
            )
            return None

        # ChatDAO.update_read_inbox
        if "UPDATE dialogs SET read_inbox_max_id" in s:
            max_id, did, owner = int(args[0]), int(args[1]), int(args[2])
            for d in self.state.dialogs:
                if d.dialog_id == did and d.owner_user_id == owner:
                    if max_id > d.read_inbox_max_id:
                        d.read_inbox_max_id = max_id
            return None

        # ChatDAO.update_read_outbox
        if "UPDATE dialogs SET read_outbox_max_id" in s:
            max_id, did, owner = int(args[0]), int(args[1]), int(args[2])
            for d in self.state.dialogs:
                if d.dialog_id == did and d.owner_user_id == owner:
                    if max_id > d.read_outbox_max_id:
                        d.read_outbox_max_id = max_id
            return None

        # ChatDAO.update_dialog_top
        if "UPDATE dialogs" in s and "top_user_message_box_id" in s:
            ubid, date_unix, inc, did, owner = (
                int(args[0]), int(args[1]), bool(args[2]),
                int(args[3]), int(args[4]),
            )
            for d in self.state.dialogs:
                if d.dialog_id == did and d.owner_user_id == owner:
                    d.top_user_message_box_id = max(
                        d.top_user_message_box_id, ubid,
                    )
                    d.top_message_date = max(d.top_message_date, date_unix)
                    if inc:
                        d.unread_count += 1
            return None

        # ChatDAO.reset_unread_count_up_to
        if "UPDATE dialogs d SET unread_count = COALESCE" in s:
            did, owner = int(args[0]), int(args[1])
            for d in self.state.dialogs:
                if d.dialog_id == did and d.owner_user_id == owner:
                    d.unread_count = sum(
                        1
                        for b in self.state.boxes
                        if b.user_id == owner and b.dialog_id == did
                        and not b.out and not b.read and not b.deleted
                    )
            return None

        # NOTIFY is no-op in tests (and shouldn't reach here at all in the
        # split architecture — UpdatesDAO owns the channel).
        if s.strip().upper().startswith("NOTIFY "):
            return None

        raise NotImplementedError(f"FakeChatPool.execute: {s[:160]}")


def _row_from_mbox(b: _MboxRec) -> dict:
    return {
        "user_id": b.user_id,
        "user_message_box_id": b.user_message_box_id,
        "dialog_message_id": b.dialog_message_id,
        "dialog_id": b.dialog_id,
        "peer_type": b.peer_type,
        "peer_id": b.peer_id,
        "from_user_id": b.from_user_id,
        "out": b.out,
        "text": b.text,
        "date_unix": b.date_unix,
        "pts": b.pts,
        "read": b.read,
        "edit_date": b.edit_date,
    }


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
