from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from ntgram.gateway.connection.msg_id import MsgIdGenerator
from ntgram.gateway.mtproto.encrypted_layer import (
    EncryptedLayerError,
    encode_encrypted_message,
)
from ntgram.gateway.mtproto.outbox_service import OutboxService
from ntgram.gateway.mtproto.session_store import SessionStore
from ntgram.gateway.transport.abridged import write_abridged_packet
from ntgram.tl.codec import encode_tl_response, wrap_unencrypted
from ntgram.tl.models import TlRequest, TlResponse

if TYPE_CHECKING:
    from ntgram.gateway.connection.context import ConnectionContext

logger = logging.getLogger(__name__)


class OutboundEncoder:
    """Serialise -> encrypt -> register -> write a server reply."""

    def __init__(
        self,
        sessions: SessionStore,
        outbox: OutboxService,
        msg_id: MsgIdGenerator | None = None,
    ) -> None:
        self._sessions = sessions
        self._outbox = outbox
        self._msg_id = msg_id if msg_id is not None else MsgIdGenerator()

    async def send_response(
        self,
        *,
        ctx: ConnectionContext,
        writer: asyncio.StreamWriter,
        request: TlRequest,
        response: TlResponse,
        encrypted_inbound: bool,
        source: str,
        register_outgoing: bool = True,
    ) -> None:
        """Encode + send a regular RPC / handshake reply."""
        encoded = encode_tl_response(response)
        server_msg_id: int | None = None
        if encrypted_inbound and request.auth_key_id != 0:
            session = self._sessions.get_session(request.auth_key_id)
            if session is not None:
                server_msg_id = self._msg_id.encrypted_response()
                server_seq_no = session.next_server_seq_no(
                    request.session_id,
                    content_related=response.content_related,
                )
                encoded = encode_encrypted_message(
                    session=session,
                    session_id=request.session_id,
                    msg_id=server_msg_id,
                    seq_no=server_seq_no,
                    message_data=encoded,
                    direction="server",
                )
                if register_outgoing and response.content_related:
                    self._outbox.register_outgoing_msg(
                        request.auth_key_id,
                        server_msg_id,
                        req_msg_id=request.req_msg_id,
                        seq_no=server_seq_no,
                        bytes_count=len(encoded),
                    )
        elif not encrypted_inbound and request.auth_key_id == 0:
            # Pre-auth handshake replies travel as wrap_unencrypted-prefixed.
            server_msg_id = self._msg_id.server()
            encoded = wrap_unencrypted(server_msg_id, encoded)
        self._log_outbound(
            ctx=ctx,
            response=response,
            source=source,
            encrypted=encrypted_inbound,
            auth_key_id=request.auth_key_id,
            session_id=request.session_id,
            request_constructor=request.constructor,
            request_req_msg_id=request.req_msg_id,
            server_msg_id=server_msg_id,
        )
        await write_abridged_packet(
            writer, encoded, encrypt=ctx.transport_encrypt,
        )

    async def send_encrypted_error(
        self,
        *,
        ctx: ConnectionContext,
        writer: asyncio.StreamWriter,
        err: EncryptedLayerError,
        auth_key_id: int,
    ) -> None:
        """Send bad_msg_notification or bad_server_salt over the encrypted layer."""
        if err.error_code is None:
            return
        if auth_key_id == 0:
            return
        session = self._sessions.get_session(auth_key_id)
        if session is None:
            return

        if err.error_code == 48:
            result: dict = {
                "constructor": "bad_server_salt",
                "bad_msg_id": err.bad_msg_id,
                "bad_msg_seqno": err.bad_msg_seqno,
                "error_code": 48,
                "new_server_salt": (
                    err.new_server_salt
                    if err.new_server_salt is not None
                    else session.server_salt
                ),
            }
        else:
            result = {
                "constructor": "bad_msg_notification",
                "bad_msg_id": err.bad_msg_id,
                "bad_msg_seqno": err.bad_msg_seqno,
                "error_code": err.error_code,
            }

        response = TlResponse(
            req_msg_id=0,
            result=result,
            error_code=err.error_code,
            error_message=str(err),
        )
        encoded = encode_tl_response(response)
        server_msg_id = self._msg_id.encrypted_response()
        reply_session_id = (
            err.context_session_id
            if err.context_session_id is not None
            else session.session_id
        )
        response_seq_no = session.next_server_seq_no(
            reply_session_id,
            content_related=False,
        )
        encoded = encode_encrypted_message(
            session,
            reply_session_id,
            server_msg_id,
            response_seq_no,
            encoded,
            direction="server",
        )
        self._log_outbound(
            ctx=ctx,
            response=response,
            source="encrypted_error",
            encrypted=True,
            auth_key_id=auth_key_id,
            session_id=session.session_id,
            request_constructor="encrypted_message",
            request_req_msg_id=0,
            server_msg_id=server_msg_id,
        )
        self._outbox.register_outgoing_msg(auth_key_id, server_msg_id)
        await write_abridged_packet(
            writer, encoded, encrypt=ctx.transport_encrypt,
        )

    @staticmethod
    def _log_outbound(
        *,
        ctx: ConnectionContext,
        response: TlResponse,
        source: str,
        encrypted: bool,
        auth_key_id: int,
        session_id: int,
        request_constructor: str | None,
        request_req_msg_id: int | None,
        server_msg_id: int | None = None,
    ) -> None:
        outer_constructor = "<empty>"
        inner_constructor = "-"
        if isinstance(response.result, dict):
            raw_outer = response.result.get("constructor")
            if isinstance(raw_outer, str):
                outer_constructor = raw_outer
            if outer_constructor == "rpc_result":
                nested = response.result.get("result")
                if isinstance(nested, dict):
                    raw_inner = nested.get("constructor")
                    if isinstance(raw_inner, str):
                        inner_constructor = raw_inner
        logger.info(
            "outbound response: peer=%s source=%s request_constructor=%s "
            "request_req_msg_id=%s response_req_msg_id=%s constructor=%s "
            "inner_constructor=%s auth_key_id=%s session_id=%s "
            "server_msg_id=%s encrypted=%s",
            ctx.peer,
            source,
            request_constructor,
            request_req_msg_id,
            response.req_msg_id,
            outer_constructor,
            inner_constructor,
            auth_key_id,
            session_id,
            server_msg_id,
            encrypted,
        )
