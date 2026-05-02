from __future__ import annotations

import json

from ntgram.gen import common_pb2, updates_pb2


class FakeUpdatesStub:
    """Drop-in replacement for ``updates_pb2_grpc.UpdatesServiceStub``."""

    def __init__(self) -> None:
        self._pts: dict[int, int] = {}
        # Each entry is the parsed RecordPtsUpdate request as a dict so
        # tests can assert on ``update_type`` / ``raw_update_json`` /
        # ``pts_count`` without proto round-trips.
        self.recorded: list[dict] = []

    # ------------------------------------------------------------------
    # Test-side accessors
    # ------------------------------------------------------------------

    def pts_for(self, user_id: int) -> int:
        return int(self._pts.get(int(user_id), 0))

    def recorded_for(self, user_id: int) -> list[dict]:
        return [r for r in self.recorded if r["user_id"] == int(user_id)]

    def reset(self) -> None:
        self._pts.clear()
        self.recorded.clear()

    # ------------------------------------------------------------------
    # gRPC stub surface (called by ChatService)
    # ------------------------------------------------------------------

    async def IncrementPts(self, request):  # noqa: N802
        uid = int(request.user_id)
        self._pts[uid] = self._pts.get(uid, 0) + 1
        return updates_pb2.IncrementPtsResponse(
            meta=common_pb2.ServiceResponseMeta(ok=True),
            pts=self._pts[uid],
        )

    async def IncrementPtsBatch(self, request):  # noqa: N802
        entries: list[updates_pb2.UserPts] = []
        for uid_raw in request.user_ids:
            uid = int(uid_raw)
            self._pts[uid] = self._pts.get(uid, 0) + 1
            entries.append(updates_pb2.UserPts(user_id=uid, pts=self._pts[uid]))
        return updates_pb2.IncrementPtsBatchResponse(
            meta=common_pb2.ServiceResponseMeta(ok=True),
            entries=entries,
        )

    async def RecordPtsUpdate(self, request):  # noqa: N802
        self.recorded.append(_record_to_dict(request))
        return updates_pb2.RecordPtsUpdateResponse(
            meta=common_pb2.ServiceResponseMeta(ok=True),
        )

    async def RecordPtsUpdateBatch(self, request):  # noqa: N802
        for item in request.items:
            self.recorded.append(_record_to_dict(item))
        return updates_pb2.RecordPtsUpdateBatchResponse(
            meta=common_pb2.ServiceResponseMeta(ok=True),
        )

    async def GetState(self, request):  # noqa: N802
        uid = int(request.user_id)
        return updates_pb2.GetStateResponse(
            meta=common_pb2.ServiceResponseMeta(ok=True),
            pts=int(self._pts.get(uid, 0)),
            qts=0, seq=0, date=0,
        )


def _record_to_dict(item) -> dict:
    """Convert a ``RecordPtsUpdateRequest`` proto to a plain test dict."""
    raw = getattr(item, "raw_update_json", "") or ""
    try:
        update_data = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        update_data = {}
    return {
        "user_id": int(item.user_id),
        "pts": int(item.pts),
        "pts_count": int(item.pts_count) if item.pts_count else 1,
        "update_type": str(item.update_type or ""),
        "update_data": update_data,
        "date_unix": int(item.date_unix) if item.date_unix else 0,
    }
