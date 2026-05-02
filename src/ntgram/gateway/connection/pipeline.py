from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ntgram.errors import RpcFailure
from ntgram.gateway.connection.context import ConnectionContext
from ntgram.gateway.connection.frame_decoder import FrameInbound
from ntgram.gateway.connection.outbound_encoder import OutboundEncoder
from ntgram.gateway.connection.rpc_result_store import RpcResultStore
from ntgram.gateway.mtproto.auth_handshake import AuthHandshakeProcessor
from ntgram.gateway.mtproto.encrypted_layer import EncryptedLayerError
from ntgram.gateway.mtproto.service_semantics import (
    ServiceSemanticsError,
    decode_service_request,
    wrap_rpc_error,
)
from ntgram.gateway.mtproto.outbox_service import OutboxService
from ntgram.gateway.mtproto.session_store import SessionStore
from ntgram.gateway.push_registry import PushRegistry, PushSlot
from ntgram.tl.codec import TlCodecError
from ntgram.tl.models import TlRequest, TlResponse

if TYPE_CHECKING:
    from ntgram.gateway.grpc_clients.account_client import AccountClient
    from ntgram.gateway.grpc_clients.chat_client import ChatClient
    from ntgram.gateway.grpc_clients.updates_client import UpdatesClient
    from ntgram.gateway.push.pts_cursor import PtsCursor
    from ntgram.gateway.router import GatewayRouter

logger = logging.getLogger(__name__)


_NON_CONTENT_CONSTRUCTORS: frozenset[str] = frozenset({
    "msgs_ack",
    "msg_container",
    "msg_copy",
    "gzip_packed",
    "ping",
    "ping_delay_disconnect",
    "http_wait",
    "msgs_state_req",
    "msg_resend_req",
    "destroy_session",
})


@dataclass(slots=True, frozen=True)
class _DispatchOutcome:
    """A single (request, response) pair queued for outbound encoding."""

    request: TlRequest
    response: TlResponse


class ConnectionPipeline:
    def __init__(
        self,
        *,
        sessions: SessionStore,
        outbox: OutboxService,
        handshake: AuthHandshakeProcessor,
        router: GatewayRouter,
        store: RpcResultStore,
        outbound: OutboundEncoder,
        push_registry: PushRegistry,
        rpc_drop_answer: Callable[[TlRequest], TlResponse],
        updates_client: UpdatesClient | None = None,
        account_client: AccountClient | None = None,
        chat_client: ChatClient | None = None,
        pts_cursor: PtsCursor | None = None,
    ) -> None:
        self._sessions = sessions
        self._outbox = outbox
        self._handshake = handshake
        self._router = router
        self._store = store
        self._outbound = outbound
        self._push_registry = push_registry
        self._handle_rpc_drop_answer = rpc_drop_answer
        self._updates_client = updates_client
        self._account_client = account_client
        self._chat_client = chat_client
        self._pts_cursor = pts_cursor

    async def process_frame(
        self,
        *,
        ctx: ConnectionContext,
        frame_inbound: FrameInbound,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Run a single decoded frame through the pipeline."""
        request = frame_inbound.request
        encrypted_inbound = frame_inbound.encrypted_inbound

        ctx.current_auth_key_id = request.auth_key_id
        ctx.current_session_id = request.session_id

        self._log_inbound(ctx, request, encrypted_inbound)
        self._log_msg_container(ctx.peer, request)

        # Top-level seq_no validation for encrypted frames.
        if encrypted_inbound and request.auth_key_id != 0:
            seq_session = self._sessions.get_session(request.auth_key_id)
            if seq_session is not None:
                try:
                    self._validate_inbound_seq_no(
                        seq_session, request, top_level=True,
                    )
                except EncryptedLayerError as err:
                    logger.warning("encrypted seqno error: %s", err)
                    await self._outbound.send_encrypted_error(
                        ctx=ctx,
                        writer=writer,
                        err=err,
                        auth_key_id=request.auth_key_id,
                    )
                    return

        # Handshake
        hs_result = self._handshake.handle(request)
        if hs_result.handled:
            response = hs_result.response or wrap_rpc_error(
                request.req_msg_id, 500, "HANDSHAKE_INTERNAL",
            )
            await self._outbound.send_response(
                ctx=ctx,
                writer=writer,
                request=request,
                response=response,
                encrypted_inbound=encrypted_inbound,
                source="handshake",
                register_outgoing=False,
            )
            return

        # Pre-auth
        if request.auth_key_id == 0:
            if request.constructor == "msgs_ack":
                logger.info(
                    "pre-auth msgs_ack skipped: peer=%s req_msg_id=%s",
                    ctx.peer, request.req_msg_id,
                )
                return
            raise TlCodecError(
                f"unsupported pre-auth constructor: {request.constructor}"
            )

        # Top-level msgs_ack on an authenticated session.
        if request.constructor == "msgs_ack":
            ack_ids = self._extract_ack_ids(request.payload)
            removed_count = self._outbox.ack_outgoing_msgs(
                request.auth_key_id, ack_ids,
            )
            logger.info(
                "post-auth msgs_ack processed: peer=%s auth_key_id=%s session_id=%s ack_count=%s removed=%s",
                ctx.peer,
                request.auth_key_id,
                request.session_id,
                len(ack_ids),
                removed_count,
            )
            return

        # Auth check.
        if (
            request.auth_key_id != 0
            and self._sessions.get_session(request.auth_key_id) is None
        ):
            response = wrap_rpc_error(
                request.req_msg_id, 401, "AUTH_KEY_INVALID",
            )
            await self._outbound.send_response(
                ctx=ctx,
                writer=writer,
                request=request,
                response=response,
                encrypted_inbound=encrypted_inbound,
                source="auth_check",
                register_outgoing=False,
            )
            return

        # Restore push slot for reconnected (already-authenticated) sessions.
        if ctx.push_slot is None:
            session = self._sessions.get_session(request.auth_key_id)
            if session is not None and session.user_id is not None:
                await self._ensure_push_slot(
                    ctx,
                    auth_key_id=request.auth_key_id,
                    session_id=request.session_id,
                    user_id=session.user_id,
                )

        # Decode msg_container / gzip_packed / invokeWithLayer / initConnection.
        try:
            service_requests = decode_service_request(request)
        except ServiceSemanticsError as err:
            logger.warning(
                "service semantics error: peer=%s constructor=%s error=%s",
                ctx.peer, request.constructor, err,
            )
            if encrypted_inbound and request.auth_key_id != 0:
                await self._outbound.send_encrypted_error(
                    ctx=ctx,
                    writer=writer,
                    err=EncryptedLayerError(
                        "invalid container/service message",
                        error_code=64,
                        bad_msg_id=request.message_id or request.req_msg_id,
                        bad_msg_seqno=request.seq_no or 0,
                    ),
                    auth_key_id=request.auth_key_id,
                )
            return

        # Layer persistence + container seq_no validation.
        if request.auth_key_id != 0:
            self._maybe_persist_layer(ctx, request, service_requests)
            if request.constructor == "msg_container":
                if not await self._validate_container_seq_no(
                    ctx, request, service_requests, writer,
                ):
                    return

        # Dispatch loop with idempotency.
        outcomes = await self._dispatch_service_requests(
            ctx, service_requests,
        )
        if not outcomes:
            return

        # Outbound flush.
        for outcome in outcomes:
            await self._outbound.send_response(
                ctx=ctx,
                writer=writer,
                request=outcome.request,
                response=outcome.response,
                encrypted_inbound=encrypted_inbound,
                source="rpc_dispatch",
            )

    # Helpers

    @staticmethod
    def _is_non_content(constructor: str) -> bool:
        return constructor in _NON_CONTENT_CONSTRUCTORS

    @classmethod
    def _validate_inbound_seq_no(
        cls,
        session,
        request: TlRequest,
        *,
        top_level: bool,
    ) -> None:
        seq_no = request.seq_no or 0
        if top_level and request.constructor == "msg_container":
            if seq_no & 1:
                raise EncryptedLayerError(
                    "msg_container must be non-content",
                    error_code=34,
                    bad_msg_id=request.message_id or request.req_msg_id,
                    bad_msg_seqno=seq_no,
                )
            return
        error_code = session.validate_inbound_seq_no(
            request.session_id,
            seq_no,
            content_related=not cls._is_non_content(request.constructor),
        )
        if error_code is not None:
            raise EncryptedLayerError(
                "bad msg_seqno",
                error_code=error_code,
                bad_msg_id=request.message_id or request.req_msg_id,
                bad_msg_seqno=seq_no,
            )

    @staticmethod
    def _extract_ack_ids(payload: dict) -> list[int]:
        raw_ids = payload.get("msg_ids", [])
        if not isinstance(raw_ids, list):
            return []
        return [int(item) for item in raw_ids if isinstance(item, int)]

    def _maybe_persist_layer(
        self,
        ctx: ConnectionContext,
        request: TlRequest,
        service_requests: list[TlRequest],
    ) -> None:
        for service_request in service_requests:
            if service_request.invoke_layer is not None:
                layer_val = service_request.invoke_layer
                self._sessions.update_layer(request.auth_key_id, layer_val)
                logger.info(
                    "mtproto layer persisted: peer=%s auth_key_id=%s session_id=%s layer=%s",
                    ctx.peer,
                    request.auth_key_id,
                    service_request.session_id,
                    layer_val,
                )
                return

    async def _validate_container_seq_no(
        self,
        ctx: ConnectionContext,
        request: TlRequest,
        service_requests: list[TlRequest],
        writer: asyncio.StreamWriter,
    ) -> bool:
        """Returns True on success, False after the error has been sent."""
        seq_session = self._sessions.get_session(request.auth_key_id)
        if seq_session is None:
            return True
        try:
            rpc_only = [
                sr for sr in service_requests if sr.constructor != "msgs_ack"
            ]
            full_replay = bool(rpc_only) and all(
                self._store.get(sr) is not None for sr in rpc_only
            )
            for service_request in service_requests:
                if full_replay and service_request.constructor != "msgs_ack":
                    continue
                self._validate_inbound_seq_no(
                    seq_session, service_request, top_level=False,
                )
        except EncryptedLayerError as err:
            logger.warning("container seqno error: %s", err)
            await self._outbound.send_encrypted_error(
                ctx=ctx,
                writer=writer,
                err=err,
                auth_key_id=request.auth_key_id,
            )
            return False
        return True

    async def _dispatch_service_requests(
        self,
        ctx: ConnectionContext,
        service_requests: list[TlRequest],
    ) -> list[_DispatchOutcome]:
        outcomes: list[_DispatchOutcome] = []
        for service_request in service_requests:
            if service_request.constructor == "msgs_ack":
                ack_ids = self._extract_ack_ids(service_request.payload)
                removed_count = self._outbox.ack_outgoing_msgs(
                    service_request.auth_key_id, ack_ids,
                )
                logger.info(
                    "container msgs_ack processed: peer=%s auth_key_id=%s session_id=%s ack_count=%s removed=%s",
                    ctx.peer,
                    service_request.auth_key_id,
                    service_request.session_id,
                    len(ack_ids),
                    removed_count,
                )
                continue

            if service_request.constructor == "rpc_drop_answer":
                response = self._store.get(service_request)
                if response is None:
                    response = self._handle_rpc_drop_answer(service_request)
                    self._store.put(service_request, response)
                outcomes.append(_DispatchOutcome(service_request, response))
                continue

            cached = self._store.get(service_request)
            if cached is not None:
                response = cached
            else:
                response = await self._dispatch_one(service_request)
                self._store.put(service_request, response)
            outcomes.append(_DispatchOutcome(service_request, response))
            self._maybe_bind_user(ctx, service_request, response)
        return outcomes

    async def _dispatch_one(self, request: TlRequest) -> TlResponse:
        self._outbox.register_running_rpc(
            request.auth_key_id, request.req_msg_id,
        )
        try:
            response = await self._router.dispatch(request)
        except RpcFailure as err:
            if err.message == "RPC_METHOD_NOT_SUPPORTED":
                raise TlCodecError(
                    f"unsupported RPC method: {request.constructor}"
                ) from err
            response = wrap_rpc_error(
                request.req_msg_id, err.code, err.message,
            )
        if self._outbox.finish_running_rpc(
            request.auth_key_id, request.req_msg_id,
        ):
            response = TlResponse(
                req_msg_id=request.req_msg_id,
                result={
                    "constructor": "rpc_result",
                    "req_msg_id": request.req_msg_id,
                    "result": {
                        "constructor": "rpc_answer_dropped_running",
                    },
                },
            )
        return response

    def _maybe_bind_user(
        self,
        ctx: ConnectionContext,
        request: TlRequest,
        response: TlResponse,
    ) -> None:
        """Pick up a freshly authenticated user from auth.signIn / auth.signUp."""
        if request.constructor not in {"auth.signIn", "auth.signUp"}:
            return
        nested = (
            response.result.get("result", {})
            if isinstance(response.result, dict) else {}
        )
        from ntgram.gateway.tl_builders.auth import user_id_from_auth_rpc_result

        user_id = user_id_from_auth_rpc_result(nested)
        if not isinstance(user_id, int) or request.auth_key_id == 0:
            return
        self._sessions.bind_user(request.auth_key_id, user_id)
        ctx.current_user_id = user_id
        asyncio.ensure_future(
            self._ensure_push_slot(
                ctx,
                auth_key_id=request.auth_key_id,
                session_id=request.session_id,
                user_id=user_id,
            )
        )

    async def _ensure_push_slot(
        self,
        ctx: ConnectionContext,
        *,
        auth_key_id: int,
        session_id: int,
        user_id: int,
    ) -> None:
        """Create and register a push slot (idempotent) then start subscriber task."""
        if ctx.push_slot is not None:
            return

        sess = self._sessions.get_session(auth_key_id)
        slot = PushSlot(
            user_id=user_id,
            auth_key_id=auth_key_id,
            session_id=session_id,
            session=sess,
        )
        self._push_registry.register(slot)
        ctx.push_slot = slot

        if (
            self._updates_client is not None
            and self._account_client is not None
            and self._chat_client is not None
        ):
            since_pts = 0
            try:
                if self._pts_cursor is not None:
                    cursor_pts = await self._pts_cursor.get(auth_key_id)
                    if cursor_pts is not None:
                        since_pts = cursor_pts
                        logger.debug(
                            "push subscriber starting from cursor pts=%d auth_key_id=%d",
                            since_pts, auth_key_id,
                        )
                if since_pts == 0:
                    state = await self._updates_client.get_state(user_id)
                    since_pts = state.pts
            except Exception:
                pass

            from ntgram.gateway.push.subscriber import run_subscriber
            slot.task = asyncio.create_task(
                run_subscriber(
                    slot,
                    self._updates_client,
                    self._account_client,
                    self._chat_client,
                    since_pts=since_pts,
                ),
                name=f"push-subscriber-user-{user_id}",
            )

    @staticmethod
    def _log_inbound(
        ctx: ConnectionContext,
        request: TlRequest,
        encrypted_inbound: bool,
    ) -> None:
        logger.info(
            "inbound message: peer=%s constructor=%s req_msg_id=%s msg_id=%s seq_no=%s auth_key_id=%s session_id=%s encrypted=%s",
            ctx.peer,
            request.constructor,
            request.req_msg_id,
            request.message_id,
            request.seq_no,
            request.auth_key_id,
            request.session_id,
            encrypted_inbound,
        )

    @staticmethod
    def _log_msg_container(peer: object, request: TlRequest) -> None:
        if request.constructor != "msg_container":
            return
        messages = request.payload.get("messages")
        if not isinstance(messages, list):
            logger.info(
                "msg_container malformed: peer=%s messages_type=%s",
                peer, type(messages).__name__,
            )
            return
        logger.info(
            "msg_container unpacked: peer=%s auth_key_id=%s session_id=%s messages=%s",
            peer,
            request.auth_key_id,
            request.session_id,
            len(messages),
        )
        for index, item in enumerate(messages):
            if not isinstance(item, dict):
                logger.info(
                    "msg_container item: peer=%s index=%s malformed_item_type=%s",
                    peer, index, type(item).__name__,
                )
                continue
            logger.info(
                "msg_container item: peer=%s index=%s constructor=%s req_msg_id=%s seq_no=%s",
                peer,
                index,
                item.get("constructor"),
                item.get("req_msg_id"),
                item.get("seq_no"),
            )
