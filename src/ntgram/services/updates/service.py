from __future__ import annotations

import json
import logging

import asyncpg

from ntgram.gen import updates_pb2, updates_pb2_grpc
from ntgram.services.message.dao import MessageDAO

logger = logging.getLogger(__name__)

_OK_META = {"ok": True}


def _ok_meta():
    from ntgram.gen import common_pb2
    return common_pb2.ServiceResponseMeta(ok=True)


def _err_meta(code: int, message: str):
    from ntgram.gen import common_pb2
    return common_pb2.ServiceResponseMeta(
        ok=False,
        error=common_pb2.ErrorDetail(code=code, message=message),
    )


class UpdatesService(updates_pb2_grpc.UpdatesServiceServicer):
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._dao = MessageDAO(pool)

    async def GetState(self, request, context):
        user_id = request.user_id
        if user_id <= 0:
            return updates_pb2.GetStateResponse(
                meta=_err_meta(400, "USER_ID_INVALID"),
            )
        pts, qts, seq, date = await self._dao.get_state(user_id)
        return updates_pb2.GetStateResponse(
            meta=_ok_meta(),
            pts=pts,
            qts=qts,
            seq=seq,
            date=date,
        )

    async def GetDifference(self, request, context):
        user_id = request.user_id
        since_pts = request.pts
        if user_id <= 0:
            return updates_pb2.GetDifferenceResponse(
                meta=_err_meta(400, "USER_ID_INVALID"),
            )
        rows = await self._dao.get_pts_updates_since(user_id, since_pts)
        pts, qts, seq, date = await self._dao.get_state(user_id)

        updates = []
        for row in rows:
            update_data = row.get("update_data", "{}")
            if isinstance(update_data, dict):
                update_data = json.dumps(update_data)
            updates.append(
                updates_pb2.PtsUpdate(
                    pts=row["pts"],
                    update_type=row["update_type"],
                    update_data=update_data,
                    date=row.get("date_unix", 0),
                )
            )

        state = updates_pb2.GetStateResponse(
            meta=_ok_meta(),
            pts=pts,
            qts=qts,
            seq=seq,
            date=date,
        )
        return updates_pb2.GetDifferenceResponse(
            meta=_ok_meta(),
            updates=updates,
            state=state,
        )
