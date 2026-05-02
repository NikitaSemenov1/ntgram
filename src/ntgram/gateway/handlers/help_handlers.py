from __future__ import annotations

from ntgram.gateway.handlers.context import RouterContext
from ntgram.gateway.mtproto.service_semantics import wrap_rpc_result
from ntgram.tl.models import TlRequest, TlResponse


async def handle_help_get_config(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    """Return TL config from JSON via `HelpConfigProvider`."""
    return wrap_rpc_result(
        request.req_msg_id, dict(ctx.help_config.load()),
    )


HELP_HANDLERS = {
    "help.getConfig": handle_help_get_config,
}
