from __future__ import annotations

import asyncpg

from ntgram.gen import status_pb2, status_pb2_grpc
from ntgram.services.common import ok_meta
from ntgram.services.status.dao import StatusDAO


class StatusService(status_pb2_grpc.StatusServiceServicer):
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._dao = StatusDAO(pool)

    async def SetOnline(self, request, context):  # noqa: N802
        was_online = await self._dao.count_online_sessions(request.user_id)
        await self._dao.set_online(request.user_id, request.session_id)
        became_online = was_online == 0
        return status_pb2.SetOnlineResponse(meta=ok_meta(), became_online=became_online)

    async def SetOffline(self, request, context):  # noqa: N802
        await self._dao.set_offline(request.user_id, request.session_id)
        still_online = await self._dao.count_online_sessions(request.user_id)
        became_offline = still_online == 0
        return status_pb2.SetOfflineResponse(meta=ok_meta(), became_offline=became_offline)

    async def GetPresence(self, request, context):  # noqa: N802
        online_count = await self._dao.count_online_sessions(request.user_id)
        last_seen = await self._dao.get_last_seen(request.user_id)
        return status_pb2.GetPresenceResponse(
            meta=ok_meta(), online=online_count > 0, last_seen_unix=last_seen,
        )
