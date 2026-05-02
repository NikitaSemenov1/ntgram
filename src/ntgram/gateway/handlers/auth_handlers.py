from __future__ import annotations

from ntgram.gateway.handlers.context import RouterContext
from ntgram.gateway.mtproto.service_semantics import (
    wrap_rpc_error,
    wrap_rpc_result,
)
from ntgram.gateway.mtproto.temp_auth_key_binder import (
    BindError,
    BindErrorCode,
    BindOk,
    BindRequest,
)
from ntgram.tl.models import TlRequest, TlResponse


async def handle_bind_temp_auth_key(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    """Map `BindTempAuthKeyService` outcome to TL."""
    bind_req = BindRequest(
        temp_auth_key_id=request.auth_key_id,
        perm_auth_key_id=int(request.payload.get("perm_auth_key_id", 0)),
        nonce=int(request.payload.get("nonce", 0)),
        expires_at=int(request.payload.get("expires_at", 0)),
        temp_session_id=request.session_id,
        expected_msg_id=request.req_msg_id,
        encrypted_message=request.payload.get("encrypted_message", b""),
    )
    result = ctx.bind_temp_auth_key_service.bind(bind_req)
    if isinstance(result, BindOk):
        return wrap_rpc_result(
            request.req_msg_id, {"constructor": "boolTrue"},
        )
    assert isinstance(result, BindError)
    if result.code is BindErrorCode.PERM_AUTH_KEY_MISSING:
        return wrap_rpc_result(
            request.req_msg_id, {"constructor": "boolFalse"},
        )
    return wrap_rpc_error(request.req_msg_id, 400, result.code.value)


async def handle_destroy_session(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    """MTProto destroy_session: forget another session_id for this auth key."""
    raw_sid = request.payload.get("session_id", 0)
    try:
        target_session_id = int(raw_sid)
    except (TypeError, ValueError):
        target_session_id = 0
    if request.auth_key_id == 0:
        ctor = "destroy_session_none"
    elif ctx.sessions.destroy_mtproto_session(
        request.auth_key_id, target_session_id,
    ):
        ctor = "destroy_session_ok"
    else:
        ctor = "destroy_session_none"
    return wrap_rpc_result(
        request.req_msg_id,
        {"constructor": ctor, "session_id": target_session_id},
    )


async def handle_account_update_status(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    return wrap_rpc_result(request.req_msg_id, {"constructor": "boolTrue"})


AUTH_HANDLERS = {
    "auth.bindTempAuthKey": handle_bind_temp_auth_key,
    "destroy_session": handle_destroy_session,
    "account.updateStatus": handle_account_update_status,
}
