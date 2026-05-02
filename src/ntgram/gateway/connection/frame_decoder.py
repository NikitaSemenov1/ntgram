from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

from ntgram.gateway.connection.context import ConnectionContext
from ntgram.gateway.mtproto.encrypted_layer import (
    EncryptedLayerError,
    decode_encrypted_message,
)
from ntgram.gateway.mtproto.session_store import SessionStore
from ntgram.gateway.transport.abridged import (
    AbridgedFrame,
    compute_quick_ack_token,
    write_abridged_quick_ack,
)
from ntgram.tl.codec import TlCodecError, decode_tl_request
from ntgram.tl.models import TlRequest

logger = logging.getLogger(__name__)


@dataclass(slots=True, frozen=True)
class FrameInbound:
    """Result of a successful frame decode."""

    request: TlRequest
    encrypted_inbound: bool
    raw_auth_key_id: int


class FrameDecoder:
    """Decode a single `AbridgedFrame` into a `FrameInbound`."""

    _PRE_AUTH_REBIND_CONSTRUCTORS = frozenset(
        {"req_pq_multi", "req_DH_params", "set_client_DH_params"},
    )

    def __init__(self, sessions: SessionStore) -> None:
        self._sessions = sessions

    async def decode(
        self,
        *,
        ctx: ConnectionContext,
        frame: AbridgedFrame,
        writer: asyncio.StreamWriter,
    ) -> FrameInbound:
        raw_auth_key_id = (
            int.from_bytes(frame.payload[:8], "little", signed=False)
            if len(frame.payload) >= 8
            else 0
        )
        session = self._sessions.get_session(raw_auth_key_id)
        if raw_auth_key_id != 0 and session is not None:
            try:
                inbound_session_id, inbound_msg_id, inbound_seq_no, inner_message = (
                    decode_encrypted_message(session, frame.payload)
                )
            finally:
                # decode_encrypted_message may rotate the salt schedule
                # before raising on bad_server_salt.
                self._sessions.mark_server_salt_clean(session.auth_key_id)

            if frame.quick_ack_requested:
                token = compute_quick_ack_token(
                    frame.payload,
                    auth_key=session.auth_key,
                    x=0,
                )
                await write_abridged_quick_ack(
                    writer, token, encrypt=ctx.transport_encrypt,
                )

            try:
                inner_request = decode_tl_request(inner_message)
            except TlCodecError as err:
                logger.warning(
                    "decode encrypted inner TL failed: %s, peer=%s",
                    err,
                    ctx.peer,
                )
                raise EncryptedLayerError(
                    "invalid encrypted inner TL",
                    error_code=64,
                    bad_msg_id=inbound_msg_id,
                    bad_msg_seqno=inbound_seq_no,
                    context_session_id=inbound_session_id,
                ) from err
            except Exception as err:
                raise TlCodecError(
                    f"decode encrypted inner TL failed: {err}"
                ) from err

            request = TlRequest(
                constructor_id=inner_request.constructor_id,
                constructor=inner_request.constructor,
                req_msg_id=inbound_msg_id,
                auth_key_id=(
                    inner_request.auth_key_id
                    if inner_request.auth_key_id != 0
                    else raw_auth_key_id
                ),
                session_id=inbound_session_id,
                message_id=inbound_msg_id,
                seq_no=inbound_seq_no,
                payload=inner_request.payload,
            )
            return FrameInbound(
                request=request,
                encrypted_inbound=True,
                raw_auth_key_id=raw_auth_key_id,
            )

        try:
            request = decode_tl_request(frame.payload)
        except Exception as err:
            raise TlCodecError(
                f"decode plain TL failed: {err}"
            ) from err
        if (
            request.auth_key_id == 0
            and request.constructor in self._PRE_AUTH_REBIND_CONSTRUCTORS
        ):
            request = TlRequest(
                constructor_id=request.constructor_id,
                constructor=request.constructor,
                req_msg_id=request.req_msg_id,
                auth_key_id=request.auth_key_id,
                session_id=ctx.handshake_session_id,
                message_id=request.message_id,
                seq_no=request.seq_no,
                payload=request.payload,
            )
        return FrameInbound(
            request=request,
            encrypted_inbound=False,
            raw_auth_key_id=raw_auth_key_id,
        )
