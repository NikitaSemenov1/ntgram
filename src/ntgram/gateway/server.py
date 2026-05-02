from __future__ import annotations

import asyncio
import logging
import secrets
import time

from ntgram.gateway.connection.context import ConnectionContext
from ntgram.gateway.connection.frame_decoder import FrameDecoder
from ntgram.gateway.connection.msg_id import MsgIdGenerator
from ntgram.gateway.connection.outbound_encoder import OutboundEncoder
from ntgram.gateway.connection.pipeline import ConnectionPipeline
from ntgram.gateway.connection.rpc_result_store import RpcResultStore
from ntgram.gateway.grpc_clients import GrpcClients
from ntgram.gateway.help_config_provider import HelpConfigProvider
from ntgram.gateway.mtproto.auth_handshake import AuthHandshakeProcessor
from ntgram.gateway.mtproto.encrypted_layer import (
    EncryptedLayerError,
    encode_encrypted_message,
)
from ntgram.gateway.mtproto.outbox_registry import PendingOutgoingRpc
from ntgram.gateway.mtproto.outbox_service import OutboxService
from ntgram.gateway.mtproto.rsa_keys import load_rsa_keypair
from ntgram.gateway.mtproto.redis_session_repository import RedisAuthSessionRepository
from ntgram.gateway.mtproto.salt_schedule import SaltScheduleService
from ntgram.gateway.push.pts_cursor import PtsCursor
from ntgram.gateway.mtproto.service_semantics import wrap_rpc_result
from ntgram.gateway.mtproto.session_store import SessionStore
from ntgram.gateway.push_registry import PushRegistry, PushSlot
from ntgram.gateway.router import GatewayRouter
from ntgram.gateway.transport.abridged import (
    ABRIDGED_MARKER,
    TRANSPORT_ERROR_BAD_LENGTH,
    TRANSPORT_ERROR_BAD_PACKET,
    AbridgedProtocolError,
    read_abridged_packet,
    write_abridged_packet,
    write_transport_error,
)
from ntgram.gateway.transport.obfuscation import (
    ObfuscationProtocolError,
    parse_obfuscation_init,
)
from ntgram.settings import GatewaySettings, RedisSettings, ServiceSettings
from ntgram.tl.codec import TlCodecError, encode_tl_response
from ntgram.tl.models import TlRequest, TlResponse

logger = logging.getLogger(__name__)


class GatewayServer:
    def __init__(
        self,
        gateway_settings: GatewaySettings,
        service_settings: ServiceSettings,
        redis_settings: RedisSettings | None = None,
    ) -> None:
        self._gateway_settings = gateway_settings
        redis_repository = RedisAuthSessionRepository(
            (redis_settings or RedisSettings()).dsn,
        )
        redis_repository.ping()
        self._grpc_clients = GrpcClients.from_addresses(
            account_addr=service_settings.account_addr,
            chat_addr=service_settings.chat_addr,
            updates_addr=service_settings.updates_addr,
        )
        self._sessions = SessionStore(redis_repository)
        self._outbox = OutboxService(self._sessions)
        self._salt_schedule = SaltScheduleService(self._sessions)
        self._push_registry = PushRegistry()
        self._pts_cursor = PtsCursor((redis_settings or RedisSettings()).dsn)
        rsa_keypair = load_rsa_keypair(
            gateway_settings.rsa_private_key_path,
            gateway_settings.rsa_public_key_path,
        )
        self._handshake = AuthHandshakeProcessor(
            self._sessions, rsa_keypair,
        )
        self._rpc_result_store = RpcResultStore()
        self._msg_id = MsgIdGenerator()
        self._outbound = OutboundEncoder(
            self._sessions, self._outbox, self._msg_id,
        )
        self._frame_decoder = FrameDecoder(self._sessions)
        self._help_config = HelpConfigProvider(
            gateway_settings.help_get_config_path or None,
        )
        self._router = GatewayRouter(
            self._grpc_clients,
            self._sessions,
            self._rpc_result_store,
            help_config=self._help_config,
            outbox=self._outbox,
            salt_schedule=self._salt_schedule,
        )
        self._pipeline = ConnectionPipeline(
            sessions=self._sessions,
            outbox=self._outbox,
            handshake=self._handshake,
            router=self._router,
            store=self._rpc_result_store,
            outbound=self._outbound,
            push_registry=self._push_registry,
            rpc_drop_answer=self._handle_rpc_drop_answer,
            updates_client=self._grpc_clients.updates,
            account_client=self._grpc_clients.account,
            chat_client=self._grpc_clients.chat,
            pts_cursor=self._pts_cursor,
        )

    def _handle_rpc_drop_answer(self, request: TlRequest) -> TlResponse:
        """Forget an unacked RPC response by original req_msg_id."""
        req_msg_id = int(request.payload.get("req_msg_id", 0) or 0)
        dropped = self._outbox.drop_rpc_answer(request.auth_key_id, req_msg_id)
        store = getattr(self, "_rpc_result_store", None)
        if store is not None:
            store.drop(request.auth_key_id, request.session_id, req_msg_id)
        if isinstance(dropped, PendingOutgoingRpc):
            result = {
                "constructor": "rpc_answer_dropped",
                "msg_id": dropped.msg_id,
                "seq_no": dropped.seq_no,
                "bytes": dropped.bytes_count,
            }
        elif dropped == "running":
            result = {"constructor": "rpc_answer_dropped_running"}
        else:
            result = {"constructor": "rpc_answer_unknown"}
        return wrap_rpc_result(request.req_msg_id, result)

    async def _init_transport(
        self,
        ctx: ConnectionContext,
        reader: asyncio.StreamReader,
    ) -> None:
        """Sniff the first byte to detect plain abridged vs obfuscated framing."""
        first = await reader.readexactly(1)
        if first[0] == ABRIDGED_MARKER:
            return
        init_payload = first + await reader.readexactly(63)
        obfuscated = parse_obfuscation_init(init_payload)
        ctx.transport_encrypt = obfuscated.encrypt
        ctx.transport_decrypt = obfuscated.decrypt

    async def close(self) -> None:
        await self._grpc_clients.close()

    async def serve(self) -> None:
        server = await asyncio.start_server(
            self._handle_client,
            self._gateway_settings.host,
            self._gateway_settings.port,
        )
        logger.info(
            "gateway listening on %s:%s",
            self._gateway_settings.host,
            self._gateway_settings.port,
        )
        async with server:
            await server.serve_forever()

    def _encode_push_update(
        self, push_slot: PushSlot, update: dict,
    ) -> bytes:
        """Encode a server-push update as TL, optionally encrypting."""
        response = TlResponse(
            req_msg_id=0,
            result=update,
        )
        encoded = encode_tl_response(response)
        if push_slot.session is not None:
            server_msg_id = self._msg_id.server_push()
            encoded = encode_encrypted_message(
                session=push_slot.session,
                session_id=push_slot.session_id,
                msg_id=server_msg_id,
                seq_no=push_slot.session.next_server_seq_no(push_slot.session_id, content_related=True),
                message_data=encoded,
                direction="server",
            )
            self._outbox.register_outgoing_msg(
                push_slot.auth_key_id, server_msg_id,
            )
        return encoded

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        ctx = ConnectionContext(
            peer=writer.get_extra_info("peername"),
            handshake_session_id=secrets.randbits(63) | 1,
        )
        logger.info("new connection from %s", ctx.peer)
        try:
            await self._init_transport(ctx, reader)
            while True:
                frame = await self._read_or_push(
                    reader,
                    writer,
                    ctx.push_slot,
                    decrypt=ctx.transport_decrypt,
                    encrypt=ctx.transport_encrypt,
                )
                if frame is None:
                    continue
                try:
                    frame_inbound = await self._frame_decoder.decode(
                        ctx=ctx, frame=frame, writer=writer,
                    )
                except EncryptedLayerError as err:
                    raw_auth_key_id = (
                        int.from_bytes(frame.payload[:8], "little", signed=False)
                        if len(frame.payload) >= 8 else 0
                    )
                    self._log_encrypted_layer_error(ctx.peer, err, raw_auth_key_id)
                    await self._outbound.send_encrypted_error(
                        ctx=ctx,
                        writer=writer,
                        err=err,
                        auth_key_id=raw_auth_key_id,
                    )
                    continue
                await self._pipeline.process_frame(
                    ctx=ctx, frame_inbound=frame_inbound, writer=writer,
                )
        except AbridgedProtocolError as err:
            logger.warning(
                "transport protocol error: %s, peer=%s",
                err, ctx.peer,
            )
            error_code = (
                TRANSPORT_ERROR_BAD_LENGTH
                if "length" in str(err).lower()
                else TRANSPORT_ERROR_BAD_PACKET
            )
            try:
                await write_transport_error(
                    writer, error_code, encrypt=ctx.transport_encrypt,
                )
            except Exception:
                logger.debug(
                    "failed to write transport error to peer=%s", ctx.peer,
                )
        except ObfuscationProtocolError as err:
            logger.warning(
                "obfuscation protocol error: %s, peer=%s",
                err, ctx.peer,
            )
            try:
                await write_transport_error(
                    writer, TRANSPORT_ERROR_BAD_PACKET, encrypt=None,
                )
            except Exception:
                logger.debug(
                    "failed to write obfuscation transport error to peer=%s",
                    ctx.peer,
                )
        except TlCodecError as err:
            logger.warning("tl codec error: %s, peer=%s", err, ctx.peer)
            try:
                await write_transport_error(
                    writer, TRANSPORT_ERROR_BAD_PACKET, encrypt=ctx.transport_encrypt,
                )
            except Exception:
                logger.debug(
                    "failed to write transport error for TL parse peer=%s",
                    ctx.peer,
                )
        except (asyncio.IncompleteReadError, ConnectionError) as err:
            logger.info("connection closed: %s", ctx.peer)
        except Exception:
            logger.exception("connection failure: %s", ctx.peer)
        finally:
            if ctx.push_slot is not None:
                # Cancel the subscriber task first to stop any in-flight gRPC calls.
                task = ctx.push_slot.task
                if task is not None and not task.done():
                    task.cancel()
                    try:
                        await task
                    except (asyncio.CancelledError, Exception):
                        pass
                self._push_registry.unregister(ctx.push_slot)
            writer.close()
            await writer.wait_closed()

    def _log_encrypted_layer_error(
        self,
        peer,
        err: EncryptedLayerError,
        raw_auth_key_id: int,
    ) -> None:
        """Emit a structured log line with salt context for diagnostics."""
        if err.error_code == 48 and raw_auth_key_id != 0:
            session = self._sessions.get_session(raw_auth_key_id)
            if session is not None:
                # INFO: suppressed because of unexpected client behavior.
                logger.info(
                    "encrypted layer error: %s peer=%s auth_key_id=%s "
                    "context_session_id=%s bad_msg_id=%s bad_msg_seqno=%s "
                    "inbound_salt=%s current_salt=%s new_server_salt=%s "
                    "valid_until=%s accepted_future_salts=%s",
                    err,
                    peer,
                    raw_auth_key_id,
                    err.context_session_id,
                    err.bad_msg_id,
                    err.bad_msg_seqno,
                    err.inbound_salt,
                    session.server_salt,
                    err.new_server_salt,
                    session.server_salt_valid_until,
                    len(session.accepted_future_salts),
                )
                return
        logger.warning(
            "encrypted layer error: %s peer=%s auth_key_id=%s error_code=%s "
            "bad_msg_id=%s bad_msg_seqno=%s context_session_id=%s",
            err,
            peer,
            raw_auth_key_id,
            err.error_code,
            err.bad_msg_id,
            err.bad_msg_seqno,
            err.context_session_id,
        )

    async def _read_or_push(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        push_slot: PushSlot | None,
        decrypt=None,
        encrypt=None,
    ):
        """Wait for either an inbound frame or a push update."""
        read_coro = read_abridged_packet(reader, decrypt=decrypt)

        if push_slot is None:
            return await read_coro

        read_task = asyncio.ensure_future(read_coro)
        push_task = asyncio.ensure_future(push_slot.queue.get())

        done, pending = await asyncio.wait(
            {read_task, push_task},
            return_when=asyncio.FIRST_COMPLETED,
        )

        for task in pending:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

        if push_task in done:
            update = push_task.result()
            try:
                encoded = self._encode_push_update(push_slot, update)
                await write_abridged_packet(
                    writer, encoded, encrypt=encrypt,
                )
                # Bump the persistent cursor so reconnect starts from here.
                max_pts = max(
                    (u.get("pts", 0) for u in update.get("updates", []) if isinstance(u, dict)),
                    default=0,
                )
                if max_pts and self._pts_cursor is not None:
                    await self._pts_cursor.set(push_slot.auth_key_id, max_pts)
                logger.info(
                    "push delivered: user_id=%d auth_key_id=%d session_id=%d updates=%d",
                    push_slot.user_id,
                    push_slot.auth_key_id,
                    push_slot.session_id,
                    len(update.get("updates", [])),
                )
            except Exception:
                logger.debug("failed to write push update")
            if read_task in done:
                return read_task.result()
            return None

        return read_task.result()

