from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

from ntgram.errors import RpcFailure
from ntgram.gateway.handlers.context import RouterContext
from ntgram.gateway.mtproto.service_semantics import (
    wrap_rpc_error,
    wrap_rpc_result,
)
from ntgram.gateway.route_outcome import RouteOutcome
from ntgram.tl.models import TlRequest, TlResponse

if TYPE_CHECKING:
    from ntgram.gateway.grpc_clients import GrpcClients
    from ntgram.gateway.mtproto.session_store import AuthSession


GrpcInvoke = Callable[
    ["GrpcClients", TlRequest, "AuthSession | None"],
    Awaitable[RouteOutcome],
]


async def run_grpc_route(
    ctx: RouterContext,
    request: TlRequest,
    *,
    invoke: GrpcInvoke,
    on_success: Callable[[RouterContext, TlRequest], None] | None = None,
) -> TlResponse:
    """Execute a single gRPC route end-to-end."""
    sess = ctx.sessions.get_session(request.auth_key_id)
    try:
        outcome = await invoke(ctx.grpc, request, sess)
    except RpcFailure as err:
        return wrap_rpc_error(request.req_msg_id, err.code, err.message)

    if on_success is not None:
        on_success(ctx, request)
    # Fanout removed (t16): push updates flow via UpdatesService.Subscribe stream.
    response = wrap_rpc_result(request.req_msg_id, outcome.tl_payload)
    ctx.store.put(request, response)
    return response


def actor_user_id_from_session(
    sess: AuthSession | None, *, required: bool = False,
) -> int:
    """Return sess.user_id or 0; raise AUTH_KEY_UNREGISTERED if required."""
    uid = int(sess.user_id) if (sess and sess.user_id) else 0
    if required and uid <= 0:
        raise RpcFailure(401, "AUTH_KEY_UNREGISTERED")
    return uid


def actor_user_id(
    request: TlRequest, sess: AuthSession | None, *, required: bool = False,
) -> int:
    """Resolve actor_user_id for a route."""
    raw = request.payload.get("actor_user_id")
    if isinstance(raw, int) and raw > 0:
        return raw
    return actor_user_id_from_session(sess, required=required)
