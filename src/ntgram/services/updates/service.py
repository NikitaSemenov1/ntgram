from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

import asyncpg

from ntgram.gen import common_pb2, updates_pb2, updates_pb2_grpc
from ntgram.services.updates.dao import UpdatesDAO

logger = logging.getLogger(__name__)

_DIFF_SLICE_LIMIT = 5000
_DIFF_TOO_LONG_LIMIT = 10_000
_HEARTBEAT_SEC = 30.0


def _ok_meta():
    return common_pb2.ServiceResponseMeta(ok=True)


def _err_meta(code: int, message: str):
    return common_pb2.ServiceResponseMeta(
        ok=False,
        error=common_pb2.ErrorDetail(code=code, message=message),
    )


def _rows_to_update_items(rows: list[dict]) -> list[common_pb2.UpdateItem]:
    items: list[common_pb2.UpdateItem] = []
    for row in rows:
        raw = row.get("update_data", "{}")
        if isinstance(raw, dict):
            raw_json = json.dumps(raw)
        elif isinstance(raw, str):
            raw_json = raw
        else:
            raw_json = "{}"
        items.append(
            common_pb2.UpdateItem(
                raw_update_json=raw_json,
                update_type=str(row.get("update_type", "")),
                pts=int(row.get("pts", 0)),
            ),
        )
    return items


class UpdatesService(updates_pb2_grpc.UpdatesServiceServicer):
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool
        self._dao = UpdatesDAO(pool)

    async def GetState(self, request, context):  # noqa: N802
        user_id = request.user_id
        if user_id <= 0:
            return updates_pb2.GetStateResponse(
                meta=_err_meta(400, "USER_ID_INVALID"),
            )
        pts, qts, seq, date = await self._dao.get_state(user_id)
        if date == 0:
            date = int(time.time())
        return updates_pb2.GetStateResponse(
            meta=_ok_meta(),
            pts=pts,
            qts=qts,
            seq=seq,
            date=date,
        )

    async def GetDifference(self, request, context):  # noqa: N802
        user_id = request.user_id
        since_pts = request.pts
        if user_id <= 0:
            return updates_pb2.GetDifferenceResponse(
                meta=_err_meta(400, "USER_ID_INVALID"),
            )

        rows = await self._dao.get_pts_updates_since(
            user_id, since_pts, limit=_DIFF_TOO_LONG_LIMIT + 1,
        )
        pts, qts, seq, date = await self._dao.get_state(user_id)
        if date == 0:
            date = int(time.time())

        state = updates_pb2.GetStateResponse(
            meta=_ok_meta(), pts=pts, qts=qts, seq=seq, date=date,
        )

        if not rows:
            return updates_pb2.GetDifferenceResponse(
                meta=_ok_meta(), updates=[], state=state,
            )

        if len(rows) > _DIFF_TOO_LONG_LIMIT:
            return updates_pb2.GetDifferenceResponse(
                meta=_ok_meta(),
                state=state,
                is_too_long=True,
            )

        is_slice = len(rows) > _DIFF_SLICE_LIMIT
        slice_rows = rows[:_DIFF_SLICE_LIMIT]
        updates = _rows_to_update_items(slice_rows)

        if is_slice:
            slice_pts = int(slice_rows[-1].get("pts", pts))
            slice_state = updates_pb2.GetStateResponse(
                meta=_ok_meta(), pts=slice_pts, qts=qts, seq=seq, date=date,
            )
            return updates_pb2.GetDifferenceResponse(
                meta=_ok_meta(),
                updates=updates,
                state=slice_state,
                is_slice=True,
            )

        return updates_pb2.GetDifferenceResponse(
            meta=_ok_meta(), updates=updates, state=state,
        )

    # Write RPCs
    
    async def IncrementPts(self, request, context):  # noqa: N802
        user_id = int(request.user_id)
        if user_id <= 0:
            return updates_pb2.IncrementPtsResponse(
                meta=_err_meta(400, "USER_ID_INVALID"),
            )
        pts = await self._dao.increment_pts(user_id)
        return updates_pb2.IncrementPtsResponse(meta=_ok_meta(), pts=pts)

    async def IncrementPtsBatch(self, request, context):  # noqa: N802
        ids = [int(u) for u in request.user_ids]
        if not ids:
            return updates_pb2.IncrementPtsBatchResponse(
                meta=_ok_meta(), entries=[],
            )
        mapping = await self._dao.increment_pts_for_users(ids)
        entries = [
            updates_pb2.UserPts(user_id=uid, pts=mapping[uid])
            for uid in ids
        ]
        return updates_pb2.IncrementPtsBatchResponse(
            meta=_ok_meta(), entries=entries,
        )

    async def RecordPtsUpdate(self, request, context):  # noqa: N802
        user_id = int(request.user_id)
        if user_id <= 0:
            return updates_pb2.RecordPtsUpdateResponse(
                meta=_err_meta(400, "USER_ID_INVALID"),
            )
        await self._dao.record_pts_update(
            user_id=user_id,
            pts=int(request.pts),
            update_type=str(request.update_type or ""),
            data=str(request.raw_update_json or "{}"),
            pts_count=int(request.pts_count) if request.pts_count else 1,
            date_unix=int(request.date_unix) if request.date_unix else None,
        )
        return updates_pb2.RecordPtsUpdateResponse(meta=_ok_meta())

    async def RecordPtsUpdateBatch(self, request, context):  # noqa: N802
        items = [
            (
                int(it.user_id), int(it.pts),
                str(it.update_type or ""),
                str(it.raw_update_json or "{}"),
                int(it.pts_count) if it.pts_count else 1,
                int(it.date_unix) if it.date_unix else None,
            )
            for it in request.items
            if int(it.user_id) > 0
        ]
        await self._dao.record_pts_update_batch(items)
        return updates_pb2.RecordPtsUpdateBatchResponse(meta=_ok_meta())

    async def Subscribe(self, request, context):  # noqa: N802
        """Stream UpdateEvent messages to the caller."""
        user_id = request.user_id
        if user_id <= 0:
            return

        since_pts = int(request.since_pts) if request.since_pts else 0
        channel = f"updates_{user_id}"

        while True:
            # asyncio.Event signalled by NOTIFY; avoids tight polling.
            notify_event: asyncio.Event = asyncio.Event()
            conn: asyncpg.Connection | None = None
            listener_fn = None
            try:
                conn = await self._pool.acquire()

                def _on_notify(
                    _conn: Any,
                    _pid: int,
                    _ch: str,
                    _payload: str,
                    _ev: asyncio.Event = notify_event,
                ) -> None:
                    _ev.set()

                listener_fn = _on_notify
                await conn.add_listener(channel, listener_fn)

                # Flush any updates that arrived while disconnected.
                since_pts = await self._flush(conn, user_id, since_pts, context)

                while True:
                    # Block until NOTIFY or heartbeat timeout.
                    notify_event.clear()
                    try:
                        await asyncio.wait_for(
                            notify_event.wait(), timeout=_HEARTBEAT_SEC,
                        )
                    except asyncio.TimeoutError:
                        pass

                    since_pts = await self._flush(conn, user_id, since_pts, context)

            except asyncio.CancelledError:
                return
            except Exception as exc:
                logger.debug(
                    "subscribe: error for user=%d: %s; reconnecting",
                    user_id, exc,
                )
                await asyncio.sleep(1.0)
            finally:
                if conn is not None:
                    if listener_fn is not None:
                        try:
                            await conn.remove_listener(channel, listener_fn)
                        except Exception:
                            pass
                    await self._pool.release(conn)

    async def _flush(
        self,
        conn: asyncpg.Connection,
        user_id: int,
        since_pts: int,
        context,
    ) -> int:
        """Emit all pending updates for user_id since since_pts."""
        try:
            rows = await self._dao.get_pts_updates_since(user_id, since_pts)
        except Exception as exc:
            logger.debug("subscribe _flush error user=%d: %s", user_id, exc)
            return since_pts

        if not rows:
            return since_pts

        update_items = _rows_to_update_items(rows)
        if not update_items:
            return since_pts

        new_since = max(int(r.get("pts", since_pts)) for r in rows)
        envelope = common_pb2.UpdateEnvelope(
            updates=update_items,
            seq=0,
            date=int(rows[-1].get("date_unix", 0)),
        )
        await context.write(updates_pb2.UpdateEvent(envelope=envelope))
        return new_since
