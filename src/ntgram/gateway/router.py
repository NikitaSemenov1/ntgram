from __future__ import annotations

import logging

from ntgram.errors import METHOD_NOT_SUPPORTED
from ntgram.gateway.connection.rpc_result_store import RpcResultStore
from ntgram.gateway.grpc_clients import GrpcClients
from ntgram.gateway.handlers import (
    AUTH_HANDLERS,
    HELP_HANDLERS,
    MESSAGES_HANDLERS,
    STATIC_STUBS,
    UPDATES_HANDLERS,
    HandlerRegistry,
    RouterContext,
)
from ntgram.gateway.handlers.grpc import GRPC_ROUTE_HANDLERS
from ntgram.gateway.help_config_provider import HelpConfigProvider
from ntgram.gateway.mtproto.service_semantics import (
    ServiceContext,
    handle_control_message,
)
from ntgram.gateway.mtproto.outbox_service import OutboxService
from ntgram.gateway.mtproto.salt_schedule import SaltScheduleService
from ntgram.gateway.mtproto.session_store import SessionStore
from ntgram.gateway.mtproto.temp_auth_key_binder import BindTempAuthKeyService
from ntgram.gateway.router_contracts import CONSTRUCTOR_ID_TO_NAME
from ntgram.tl.models import TlRequest, TlResponse

logger = logging.getLogger(__name__)


class GatewayRouter:
    def __init__(
        self,
        grpc_clients: GrpcClients,
        sessions: SessionStore,
        rpc_result_store: RpcResultStore | None = None,
        *,
        help_get_config_path: str | None = None,
        help_config: HelpConfigProvider | None = None,
        outbox: OutboxService | None = None,
        salt_schedule: SaltScheduleService | None = None,
    ) -> None:
        self._grpc = grpc_clients
        self._sessions = sessions
        self._store = (
            rpc_result_store if rpc_result_store is not None else RpcResultStore()
        )
        self._help_config = help_config or HelpConfigProvider(help_get_config_path)
        self._bind_temp_auth_key_service = BindTempAuthKeyService(sessions)
        self._outbox = outbox if outbox is not None else OutboxService(sessions)
        self._salt_schedule = (
            salt_schedule if salt_schedule is not None
            else SaltScheduleService(sessions)
        )
        self._service_context: dict[int, ServiceContext] = {}

        self._ctx = RouterContext(
            sessions=self._sessions,
            grpc=self._grpc,
            store=self._store,
            help_config=self._help_config,
            bind_temp_auth_key_service=self._bind_temp_auth_key_service,
            outbox=self._outbox,
            salt_schedule=self._salt_schedule,
        )

        self._registry = HandlerRegistry()
        self._registry.register_all(STATIC_STUBS)
        self._registry.register_all(AUTH_HANDLERS)
        self._registry.register_all(UPDATES_HANDLERS)
        self._registry.register_all(HELP_HANDLERS)
        self._registry.register_all(MESSAGES_HANDLERS)
        # gRPC routes: 1-to-1 explicit handlers
        for constructor, handler in GRPC_ROUTE_HANDLERS.items():
            if constructor in self._registry:
                continue
            self._registry.register(constructor, handler)

    async def dispatch(self, request: TlRequest) -> TlResponse:
        control_response = handle_control_message(
            self._service_context.setdefault(
                request.session_id, ServiceContext(),
            ),
            request,
            self._store,
        )
        if control_response is not None:
            return control_response

        handler = self._registry.lookup(request.constructor)
        if handler is None:
            name = CONSTRUCTOR_ID_TO_NAME.get(request.constructor_id)
            if name is not None:
                handler = self._registry.lookup(name)
        if handler is None:
            raise METHOD_NOT_SUPPORTED

        return await handler(self._ctx, request)
