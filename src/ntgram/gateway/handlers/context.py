from __future__ import annotations

from dataclasses import dataclass

from ntgram.gateway.connection.rpc_result_store import RpcResultStore
from ntgram.gateway.grpc_clients import GrpcClients
from ntgram.gateway.help_config_provider import HelpConfigProvider
from ntgram.gateway.mtproto.outbox_service import OutboxService
from ntgram.gateway.mtproto.salt_schedule import SaltScheduleService
from ntgram.gateway.mtproto.session_store import SessionStore
from ntgram.gateway.mtproto.temp_auth_key_binder import BindTempAuthKeyService


@dataclass(slots=True, frozen=True)
class RouterContext:
    """Per-router dependency bundle."""

    sessions: SessionStore
    grpc: GrpcClients
    store: RpcResultStore
    help_config: HelpConfigProvider
    bind_temp_auth_key_service: BindTempAuthKeyService
    outbox: OutboxService
    salt_schedule: SaltScheduleService
