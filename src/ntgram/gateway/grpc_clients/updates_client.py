from __future__ import annotations

import json
from collections.abc import AsyncIterator

from ntgram.gen import common_pb2, updates_pb2, updates_pb2_grpc

from ntgram.gateway.grpc_clients._meta import assert_meta_ok
from ntgram.gateway.grpc_clients.dtos import (
    PtsUpdateRow,
    UpdatesDifference,
    UpdatesDifferenceEmpty,
    UpdatesDifferenceTooLong,
    UpdatesDifferenceResult,
    UpdatesState,
)


class UpdatesClient:
    """Wraps UpdatesServiceStub calls into typed DTOs."""

    __slots__ = ("_stub",)

    def __init__(self, stub: updates_pb2_grpc.UpdatesServiceStub) -> None:
        self._stub = stub

    async def get_state(self, user_id: int) -> UpdatesState:
        resp = await self._stub.GetState(
            updates_pb2.GetStateRequest(user_id=user_id),
        )
        assert_meta_ok(resp.meta)
        return UpdatesState(
            pts=int(resp.pts),
            qts=int(resp.qts),
            seq=int(resp.seq),
            date=int(resp.date),
        )

    def subscribe(
        self, *, user_id: int, since_pts: int,
    ) -> AsyncIterator[common_pb2.UpdateEnvelope]:
        """Open a streaming subscription; yields raw UpdateEnvelope protos."""
        stream = self._stub.Subscribe(
            updates_pb2.SubscribeRequest(user_id=user_id, since_pts=since_pts),
        )

        async def _gen() -> AsyncIterator[common_pb2.UpdateEnvelope]:
            async for event in stream:
                yield event.envelope

        return _gen()

    async def get_difference(
        self, *, user_id: int, pts: int,
    ) -> UpdatesDifferenceResult:
        resp = await self._stub.GetDifference(
            updates_pb2.GetDifferenceRequest(user_id=user_id, pts=pts),
        )
        assert_meta_ok(resp.meta)

        state = resp.state
        state_dto = UpdatesState(
            pts=int(state.pts) if state else 0,
            qts=int(state.qts) if state else 0,
            seq=int(state.seq) if state else 0,
            date=int(state.date) if state else 0,
        )

        if resp.is_too_long:
            return UpdatesDifferenceTooLong(pts=state_dto.pts)

        if not resp.updates:
            return UpdatesDifferenceEmpty(
                date=state_dto.date,
                seq=state_dto.seq,
            )

        raw_updates: list[PtsUpdateRow] = []
        for u in resp.updates:
            try:
                data = json.loads(u.update_data)
            except (json.JSONDecodeError, TypeError):
                data = {}
            raw_updates.append(
                PtsUpdateRow(
                    pts=int(u.pts),
                    update_type=str(u.update_type),
                    update_data=data,
                    date=int(u.date),
                ),
            )
        return UpdatesDifference(
            state=state_dto,
            raw_updates=tuple(raw_updates),
            is_slice=bool(resp.is_slice),
        )
