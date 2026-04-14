from __future__ import annotations

import logging
import time

from ntgram.errors import METHOD_NOT_SUPPORTED, RpcFailure
from ntgram.gateway.grpc_bridge import GrpcBridge
from ntgram.gateway.mtproto.service_semantics import (
    ServiceContext,
    handle_control_message,
    wrap_rpc_error,
    wrap_rpc_result,
)
from ntgram.gateway.mtproto.session_store import SessionStore
from ntgram.gateway.router_contracts import (
    ROUTES_BY_CONSTRUCTOR,
    ROUTES_BY_CONSTRUCTOR_ID,
    ServiceName,
)
from ntgram.gateway.update_bus import UpdateBus
from ntgram.tl.models import TlRequest, TlResponse

logger = logging.getLogger(__name__)


class GatewayRouter:
    def __init__(
        self,
        grpc_bridge: GrpcBridge,
        sessions: SessionStore,
        update_bus: UpdateBus,
    ) -> None:
        self._grpc = grpc_bridge
        self._sessions = sessions
        self._update_bus = update_bus
        self._service_context: dict[int, ServiceContext] = {}

    async def dispatch(self, request: TlRequest) -> TlResponse:
        control_response = handle_control_message(
            self._service_context.setdefault(
                request.session_id, ServiceContext(),
            ),
            request,
        )
        if control_response is not None:
            return control_response

        if request.constructor == "updates.getState":
            return await self._handle_get_state(request)

        if request.constructor == "updates.getDifference":
            return await self._handle_get_difference(request)

        route = ROUTES_BY_CONSTRUCTOR_ID.get(request.constructor_id)
        if route is None:
            route = ROUTES_BY_CONSTRUCTOR.get(request.constructor)
        if route is None:
            raise METHOD_NOT_SUPPORTED

        try:
            result = await self._grpc.call(
                route.service, route.method, request,
            )

            if route.service == ServiceName.MESSAGE:
                await self._fanout_message_update(request, result)
            elif route.service == ServiceName.STATUS:
                await self._fanout_status_update(result)

            response = wrap_rpc_result(request.req_msg_id, result)
            ctx = self._service_context.setdefault(
                request.session_id, ServiceContext(),
            )
            ctx.pending_results[request.req_msg_id] = response
            return response
        except RpcFailure as err:
            return wrap_rpc_error(
                request.req_msg_id, err.code, err.message,
            )

    async def _handle_get_state(
        self, request: TlRequest,
    ) -> TlResponse:
        session = self._sessions.get_session(request.auth_key_id)
        user_id = session.user_id if session else None
        if user_id:
            try:
                state = await self._grpc.get_updates_state(user_id)
                return wrap_rpc_result(request.req_msg_id, state)
            except Exception:
                logger.debug("getState gRPC failed, returning zeros")
        return wrap_rpc_result(
            request.req_msg_id,
            {"pts": 0, "qts": 0, "seq": 0, "date": int(time.time())},
        )

    async def _handle_get_difference(
        self, request: TlRequest,
    ) -> TlResponse:
        session = self._sessions.get_session(request.auth_key_id)
        if session is None:
            return wrap_rpc_error(
                request.req_msg_id, 401, "AUTH_KEY_INVALID",
            )
        user_id = session.user_id
        if not user_id:
            return wrap_rpc_error(
                request.req_msg_id, 401, "AUTH_KEY_UNREGISTERED",
            )
        pts = request.payload.get("pts", 0)
        try:
            diff = await self._grpc.get_updates_difference(user_id, pts)
            return wrap_rpc_result(request.req_msg_id, diff)
        except Exception:
            logger.debug("getDifference gRPC failed, returning empty")
            return wrap_rpc_result(
                request.req_msg_id,
                {
                    "constructor": "updates.differenceEmpty",
                    "date": int(time.time()),
                    "seq": 0,
                },
            )

    async def _fanout_message_update(
        self, request: TlRequest, result: dict,
    ) -> None:
        """Push message update to all dialog participants."""
        dialog_id = request.payload.get("dialog_id", 0)
        if not dialog_id:
            return

        try:
            members = await self._grpc.resolve_dialog_members(dialog_id)
        except Exception:
            members = []

        if not members:
            return

        constructor = request.constructor
        if constructor == "messages.sendMessage":
            await self._update_bus.notify_new_message(
                members,
                exclude_auth_key_id=request.auth_key_id,
                message_id=result.get("message_id", 0),
                dialog_id=dialog_id,
                from_user_id=request.payload.get("actor_user_id", 0),
                text=request.payload.get("text", ""),
                pts=result.get("pts", 0),
            )
        elif constructor == "messages.deleteMessages":
            deleted = result.get("deleted_ids", [])
            if deleted:
                await self._update_bus.notify_delete_messages(
                    members,
                    exclude_auth_key_id=request.auth_key_id,
                    message_ids=deleted,
                    dialog_id=dialog_id,
                    pts=result.get("pts", 0),
                )

    async def _fanout_status_update(self, result: dict) -> None:
        """Push status change if became_online/became_offline."""
        if result.get("became_online"):
            user_id = result.get("user_id", 0)
            if user_id:
                await self._update_bus.notify_status_change(
                    user_id, online=True,
                )
        elif result.get("became_offline"):
            user_id = result.get("user_id", 0)
            if user_id:
                await self._update_bus.notify_status_change(
                    user_id, online=False,
                )
