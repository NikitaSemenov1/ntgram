from ntgram.gateway.handlers.grpc.account import ACCOUNT_ROUTE_HANDLERS
from ntgram.gateway.handlers.grpc.chat import CHAT_ROUTE_HANDLERS
from ntgram.gateway.handlers.grpc.message import MESSAGE_ROUTE_HANDLERS
from ntgram.gateway.handlers.grpc.profile import PROFILE_ROUTE_HANDLERS
from ntgram.gateway.handlers.registry import RpcHandler


GRPC_ROUTE_HANDLERS: dict[str, RpcHandler] = {
    **ACCOUNT_ROUTE_HANDLERS,
    **CHAT_ROUTE_HANDLERS,
    **MESSAGE_ROUTE_HANDLERS,
    **PROFILE_ROUTE_HANDLERS,
}

__all__ = [
    "ACCOUNT_ROUTE_HANDLERS",
    "CHAT_ROUTE_HANDLERS",
    "GRPC_ROUTE_HANDLERS",
    "MESSAGE_ROUTE_HANDLERS",
    "PROFILE_ROUTE_HANDLERS",
]
