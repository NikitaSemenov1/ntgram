from __future__ import annotations

import time
from dataclasses import dataclass

from ntgram.gateway.mtproto.session_store import AuthSession
from ntgram.tl.models import TlResponse


@dataclass(slots=True, frozen=True)
class UpdateState:
    pts: int
    qts: int
    seq: int
    date: int


def apply_update_counters(session: AuthSession, pts_count: int = 0, qts_count: int = 0, seq_count: int = 0) -> UpdateState:
    session.touch_updates_state(pts_inc=pts_count, qts_inc=qts_count, seq_inc=seq_count)
    return UpdateState(pts=session.pts, qts=session.qts, seq=session.seq, date=session.date)


def build_difference_response(session: AuthSession, req_msg_id: int, updates: list[dict]) -> TlResponse:
    now = int(time.time())
    return TlResponse(
        req_msg_id=req_msg_id,
        result={
            "constructor": "updates.differenceSlice",
            "new_messages": [u for u in updates if u.get("kind") == "message"],
            "other_updates": [u for u in updates if u.get("kind") != "message"],
            "state": {
                "pts": session.pts,
                "qts": session.qts,
                "seq": session.seq,
                "date": now,
            },
        },
    )

