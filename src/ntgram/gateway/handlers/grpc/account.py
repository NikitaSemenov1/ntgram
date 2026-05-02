from __future__ import annotations

from ntgram.gateway.grpc_clients._meta import phone_from_payload
from ntgram.gateway.handlers.context import RouterContext
from ntgram.gateway.handlers.grpc._common import (
    actor_user_id_from_session,
    run_grpc_route,
)
from ntgram.gateway.route_outcome import RouteOutcome
from ntgram.gateway.tl_builders.auth import (
    auth_authorization_sign_up_required_tl,
    auth_authorization_tl,
)
from ntgram.gateway.grpc_clients.dtos import ProfileDto
from ntgram.gateway.tl_builders.users import (
    public_user_tl_from_dto,
    self_user_tl_from_update,
)
from ntgram.tl.models import TlRequest, TlResponse


async def handle_auth_send_code(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    async def invoke(clients, req, _sess):
        result = await clients.account.send_code(phone_from_payload(req.payload))
        return RouteOutcome.tl_only(
            {
                "constructor": "auth.sentCode",
                "type": {
                    "constructor": "auth.sentCodeTypeSms",
                    "length": 6,
                },
                "phone_code_hash": result.phone_code_hash,
            },
        )

    return await run_grpc_route(ctx, request, invoke=invoke)


async def handle_auth_cancel_code(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    async def invoke(clients, req, _sess):
        await clients.account.cancel_code(
            phone=phone_from_payload(req.payload),
            phone_code_hash=req.payload.get("phone_code_hash") or "",
        )
        return RouteOutcome.tl_only({"constructor": "boolTrue"})

    return await run_grpc_route(ctx, request, invoke=invoke)


async def handle_auth_sign_in(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    async def invoke(clients, req, _sess):
        phone = phone_from_payload(req.payload)
        result = await clients.account.sign_in(
            phone=phone,
            phone_code_hash=req.payload["phone_code_hash"],
            phone_code=req.payload["phone_code"],
        )
        if result.is_new_user:
            return RouteOutcome.tl_only(auth_authorization_sign_up_required_tl())
        return RouteOutcome.tl_only(
            auth_authorization_tl(user_id=result.user_id, phone=phone),
        )

    return await run_grpc_route(ctx, request, invoke=invoke)


async def handle_auth_sign_up(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    async def invoke(clients, req, _sess):
        from ntgram.errors import RpcFailure

        phone = phone_from_payload(req.payload)
        first_name = req.payload["first_name"]
        last_name = req.payload.get("last_name", "")
        if not isinstance(first_name, str):
            raise RpcFailure(400, "FIRSTNAME_INVALID")
        if not isinstance(last_name, str):
            last_name = ""
        result = await clients.account.sign_up(
            phone=phone,
            phone_code_hash=req.payload["phone_code_hash"],
            first_name=first_name,
            last_name=last_name,
        )
        return RouteOutcome.tl_only(
            auth_authorization_tl(
                user_id=result.user_id,
                phone=phone,
                first_name=first_name,
                last_name=last_name,
            ),
        )

    return await run_grpc_route(ctx, request, invoke=invoke)


async def handle_auth_log_out(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    async def invoke(clients, req, sess):
        user_id = int(sess.user_id) if (sess and sess.user_id) else 0
        await clients.account.log_out(
            user_id=user_id, auth_key_id=req.auth_key_id,
        )
        return RouteOutcome.tl_only(
            {"constructor": "auth.loggedOut", "flags": 0},
        )

    def on_success(ctx_: RouterContext, req: TlRequest) -> None:
        ctx_.sessions.unbind_user(req.auth_key_id)

    return await run_grpc_route(
        ctx, request, invoke=invoke, on_success=on_success,
    )


async def handle_account_check_username(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    async def invoke(clients, req, _sess):
        from ntgram.errors import RpcFailure

        un = req.payload.get("username")
        if not isinstance(un, str):
            raise RpcFailure(400, "USERNAME_INVALID")
        await clients.account.check_username(un)
        return RouteOutcome.tl_only({"constructor": "boolTrue"})

    return await run_grpc_route(ctx, request, invoke=invoke)


async def handle_account_update_username(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    async def invoke(clients, req, sess):
        from ntgram.errors import RpcFailure

        actor = actor_user_id_from_session(sess, required=True)
        un = req.payload.get("username")
        if not isinstance(un, str):
            raise RpcFailure(400, "USERNAME_INVALID")
        result = await clients.account.update_username(
            actor_user_id=actor, username=un,
        )
        return RouteOutcome.tl_only(self_user_tl_from_update(result))

    return await run_grpc_route(ctx, request, invoke=invoke)


async def handle_contacts_resolve_username(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    async def invoke(clients, req, _sess):
        from ntgram.errors import RpcFailure

        un = req.payload.get("username")
        if not isinstance(un, str):
            raise RpcFailure(400, "USERNAME_INVALID")
        result = await clients.account.resolve_username(un)
        user_tl = public_user_tl_from_dto(
            ProfileDto(
                user_id=result.user_id,
                first_name=result.first_name,
                last_name=result.last_name,
                bio=result.bio,
                username=result.username,
            ),
        )
        return RouteOutcome.tl_only(
            {
                "constructor": "contacts.resolvedPeer",
                "peer": {
                    "constructor": "peerUser",
                    "user_id": result.user_id,
                },
                "chats": [],
                "users": [user_tl],
            },
        )

    return await run_grpc_route(ctx, request, invoke=invoke)


async def handle_contacts_search(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    async def invoke(clients, req, sess):
        from ntgram.errors import RpcFailure

        q = req.payload.get("q")
        if not isinstance(q, str):
            raise RpcFailure(400, "SEARCH_QUERY_EMPTY")
        try:
            limit = int(req.payload.get("limit", 0))
        except (TypeError, ValueError):
            limit = 0
        actor = actor_user_id_from_session(sess)
        result = await clients.account.search_usernames(
            actor_user_id=actor, q=q, limit=limit,
        )
        results = [
            {"constructor": "peerUser", "user_id": h.user_id}
            for h in result.hits
        ]
        users = [
            public_user_tl_from_dto(
                ProfileDto(
                    user_id=h.user_id,
                    first_name=h.first_name,
                    last_name=h.last_name,
                    bio=h.bio,
                    username=h.username,
                ),
            )
            for h in result.hits
        ]
        return RouteOutcome.tl_only(
            {
                "constructor": "contacts.found",
                "my_results": [],
                "results": results,
                "chats": [],
                "users": users,
            },
        )

    return await run_grpc_route(ctx, request, invoke=invoke)


ACCOUNT_ROUTE_HANDLERS = {
    "auth.sendCode": handle_auth_send_code,
    "auth.cancelCode": handle_auth_cancel_code,
    "auth.signIn": handle_auth_sign_in,
    "auth.signUp": handle_auth_sign_up,
    "auth.logOut": handle_auth_log_out,
    "account.checkUsername": handle_account_check_username,
    "account.updateUsername": handle_account_update_username,
    "contacts.resolveUsername": handle_contacts_resolve_username,
    "contacts.search": handle_contacts_search,
}
