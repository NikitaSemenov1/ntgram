from __future__ import annotations

from ntgram.gateway.grpc_clients.dtos import UpdateUsernameResult
from ntgram.gateway.handlers.context import RouterContext
from ntgram.gateway.handlers.grpc._common import (
    actor_user_id,
    run_grpc_route,
)
from ntgram.gateway.mtproto.input_user import resolve_input_user_id
from ntgram.gateway.route_outcome import RouteOutcome
from ntgram.gateway.tl_builders.users import (
    self_user_tl_from_update,
    users_user_full_tl_from_dto,
)
from ntgram.tl.models import TlRequest, TlResponse


async def handle_account_get_profile(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    async def invoke(clients, req, sess):
        actor = actor_user_id(req, sess, required=True)
        target = req.payload.get("target_user_id", actor)
        profile = await clients.account.get_profile(
            actor_user_id=actor,
            target_user_id=int(target),
        )
        return RouteOutcome.tl_only(
            {
                "user_id": profile.user_id,
                "first_name": profile.first_name,
                "last_name": profile.last_name,
                "bio": profile.bio,
                "username": profile.username,
            },
        )

    return await run_grpc_route(ctx, request, invoke=invoke)


async def handle_account_update_profile(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    """account.updateProfile + GetUser enrichment."""

    async def invoke(clients, req, sess):
        actor = actor_user_id(req, sess, required=True)
        cur = await clients.account.get_profile(
            actor_user_id=actor, target_user_id=actor,
        )
        first_name = (
            req.payload["first_name"]
            if "first_name" in req.payload
            else cur.first_name
        )
        last_name = (
            req.payload["last_name"]
            if "last_name" in req.payload
            else cur.last_name
        )
        bio = req.payload["about"] if "about" in req.payload else cur.bio

        result = await clients.account.update_profile(
            actor_user_id=actor,
            first_name=first_name,
            last_name=last_name,
            bio=bio,
        )
        gu = await clients.account.get_user(actor)
        merged = UpdateUsernameResult(
            user_id=result.profile.user_id,
            first_name=result.profile.first_name,
            last_name=result.profile.last_name,
            phone=gu.phone,
            username=gu.username,
        )
        return RouteOutcome.tl_only(self_user_tl_from_update(merged))

    return await run_grpc_route(ctx, request, invoke=invoke)


async def handle_users_get_full_user(
    ctx: RouterContext, request: TlRequest,
) -> TlResponse:
    async def invoke(clients, req, sess):
        actor = actor_user_id(req, sess, required=True)
        target = resolve_input_user_id(actor, req.payload.get("id"))
        full = await clients.account.get_full_user(
            actor_user_id=actor, target_user_id=target,
        )
        return RouteOutcome.tl_only(
            users_user_full_tl_from_dto(full=full, actor_user_id=actor),
        )

    return await run_grpc_route(ctx, request, invoke=invoke)


PROFILE_ROUTE_HANDLERS = {
    "account.getProfile": handle_account_get_profile,
    "account.updateProfile": handle_account_update_profile,
    "users.getFullUser": handle_users_get_full_user,
}
