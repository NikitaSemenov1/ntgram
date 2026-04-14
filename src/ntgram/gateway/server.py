from __future__ import annotations

import asyncio
import logging
import secrets
import time
from enum import StrEnum

from ntgram.gateway.grpc_bridge import GrpcBridge
from ntgram.gateway.mtproto.auth_handshake import AuthHandshakeProcessor
from ntgram.gateway.mtproto.encrypted_layer import (
    EncryptedLayerError,
    decode_encrypted_message,
    encode_encrypted_message,
)
from ntgram.gateway.mtproto.rsa_keys import load_rsa_keypair
from ntgram.gateway.mtproto.service_semantics import (
    decode_service_request,
    wrap_rpc_error,
)
from ntgram.gateway.mtproto.session_store import SessionStore
from ntgram.gateway.push_registry import PushRegistry, PushSlot
from ntgram.gateway.router import GatewayRouter
from ntgram.gateway.router_contracts import ServiceName
from ntgram.gateway.transport.abridged import (
    TRANSPORT_ERROR_BAD_LENGTH,
    TRANSPORT_ERROR_BAD_PACKET,
    AbridgedProtocolError,
    compute_quick_ack_token,
    read_abridged_marker,
    read_abridged_packet,
    write_abridged_packet,
    write_abridged_quick_ack,
    write_transport_error,
)
from ntgram.gateway.update_bus import UpdateBus
from ntgram.settings import GatewaySettings, ServiceSettings
from ntgram.tl.codec import (
    TlCodecError,
    decode_tl_request,
    encode_tl_response,
    wrap_unencrypted,
)
from ntgram.tl.models import TlRequest, TlResponse

logger = logging.getLogger(__name__)


class TransportState(StrEnum):
    INIT = "init"
    ABRIDGED_MARKER = "abridged_marker"
    FRAMES = "frames"


class GatewayServer:
    def __init__(
        self,
        gateway_settings: GatewaySettings,
        service_settings: ServiceSettings,
    ) -> None:
        self._gateway_settings = gateway_settings
        self._grpc_bridge = GrpcBridge(
            account_addr=service_settings.account_addr,
            chat_addr=service_settings.chat_addr,
            message_addr=service_settings.message_addr,
            profile_addr=service_settings.profile_addr,
            status_addr=service_settings.status_addr,
            updates_addr=service_settings.updates_addr,
        )
        self._sessions = SessionStore()
        self._push_registry = PushRegistry()
        self._update_bus = UpdateBus(self._push_registry)
        rsa_keypair = load_rsa_keypair(
            gateway_settings.rsa_private_key_path,
            gateway_settings.rsa_public_key_path,
        )
        self._handshake = AuthHandshakeProcessor(
            self._sessions, rsa_keypair,
        )
        self._router = GatewayRouter(
            self._grpc_bridge, self._sessions, self._update_bus,
        )

    @staticmethod
    def _make_server_msg_id() -> int:
        value = (int(time.time()) << 32) | secrets.randbits(30)
        value -= value % 4
        return value + 1

    async def close(self) -> None:
        await self._grpc_bridge.close()

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
            result={
                "constructor": "updateShort",
                "update": update,
                "date": int(time.time()),
            },
        )
        encoded = encode_tl_response(response)
        if push_slot.session is not None:
            encoded = encode_encrypted_message(
                session=push_slot.session,
                session_id=push_slot.session_id,
                msg_id=self._make_server_msg_id(),
                seq_no=1,
                message_data=encoded,
                direction="server",
            )
        return encoded

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer = writer.get_extra_info("peername")
        logger.info("new connection from %s", peer)
        current_user_id: int | None = None
        current_auth_key_id: int = 0
        current_session_id: int = 0
        transport_state = TransportState.INIT
        push_slot: PushSlot | None = None
        try:
            transport_state = TransportState.ABRIDGED_MARKER
            await read_abridged_marker(reader)
            transport_state = TransportState.FRAMES

            while True:
                frame = await self._read_or_push(
                    reader, writer, push_slot,
                )
                if frame is None:
                    continue

                if frame.quick_ack_requested:
                    token = compute_quick_ack_token(frame.payload)
                    await write_abridged_quick_ack(
                        writer, token, encrypt=None,
                    )

                encrypted_inbound = False
                inbound_msg_id = 0
                inbound_seq_no = 0
                try:
                    maybe_auth_key_id = (
                        int.from_bytes(frame.payload[:8], "little", signed=False)
                        if len(frame.payload) >= 8 else 0
                    )
                    session = self._sessions.get_session(maybe_auth_key_id)
                    if maybe_auth_key_id != 0 and session is not None:
                        _, inbound_msg_id, inbound_seq_no, inner_message = (
                            decode_encrypted_message(session, frame.payload)
                        )
                        request = decode_tl_request(inner_message)
                        encrypted_inbound = True
                        request = TlRequest(
                            constructor_id=request.constructor_id,
                            constructor=request.constructor,
                            req_msg_id=request.req_msg_id,
                            auth_key_id=request.auth_key_id,
                            session_id=request.session_id,
                            message_id=inbound_msg_id,
                            seq_no=inbound_seq_no,
                            payload=request.payload,
                        )
                    else:
                        request = decode_tl_request(frame.payload)
                except EncryptedLayerError as err:
                    logger.warning("encrypted layer error: %s", err)
                    await self._handle_encrypted_error(
                        err, maybe_auth_key_id, writer,
                    )
                    continue

                current_auth_key_id = request.auth_key_id
                current_session_id = request.session_id

                hs_result = self._handshake.handle(request)
                if hs_result.handled:
                    response = hs_result.response or wrap_rpc_error(
                        request.req_msg_id, 500, "HANDSHAKE_INTERNAL",
                    )
                    encoded = encode_tl_response(response)
                    if not encrypted_inbound:
                        encoded = wrap_unencrypted(
                            self._make_server_msg_id(), encoded,
                        )
                    await write_abridged_packet(
                        writer, encoded, encrypt=None,
                    )
                    continue

                if (
                    request.auth_key_id != 0
                    and self._sessions.get_session(request.auth_key_id) is None
                ):
                    response = wrap_rpc_error(
                        request.req_msg_id, 401, "AUTH_KEY_INVALID",
                    )
                    encoded = encode_tl_response(response)
                    await write_abridged_packet(
                        writer, encoded, encrypt=None,
                    )
                    continue

                actor_user_id = (
                    request.payload.get("actor_user_id")
                    or request.payload.get("user_id")
                )
                if (
                    isinstance(actor_user_id, int)
                    and actor_user_id > 0
                    and current_user_id is None
                ):
                    current_user_id = actor_user_id
                    try:
                        await self._grpc_bridge.call(
                            ServiceName.STATUS,
                            "SetOnline",
                            TlRequest(
                                constructor_id=0,
                                constructor="status.setOnline",
                                req_msg_id=request.req_msg_id,
                                auth_key_id=request.auth_key_id,
                                session_id=request.session_id,
                                payload={
                                    "user_id": actor_user_id,
                                    "auth_key_id": request.auth_key_id,
                                    "session_id": request.session_id,
                                },
                            ),
                        )
                    except Exception:
                        logger.debug("SetOnline failed for user %s", actor_user_id)

                service_requests = decode_service_request(request)
                response = TlResponse(
                    req_msg_id=request.req_msg_id, result={},
                )
                for service_request in service_requests:
                    response = await self._router.dispatch(
                        service_request,
                    )

                if request.constructor in {"auth.signIn", "auth.signUp"}:
                    nested = (
                        response.result.get("result", {})
                        if isinstance(response.result, dict) else {}
                    )
                    user_id = nested.get("user_id")
                    if isinstance(user_id, int) and request.auth_key_id != 0:
                        self._sessions.bind_user(
                            request.auth_key_id, user_id,
                        )
                        current_user_id = user_id
                        sess = self._sessions.get_session(
                            request.auth_key_id,
                        )
                        push_slot = PushSlot(
                            user_id=user_id,
                            auth_key_id=request.auth_key_id,
                            session_id=request.session_id,
                            session=sess,
                        )
                        self._push_registry.register(push_slot)

                encoded = encode_tl_response(response)
                if encrypted_inbound and request.auth_key_id != 0:
                    session = self._sessions.get_session(
                        request.auth_key_id,
                    )
                    if session is not None:
                        encoded = encode_encrypted_message(
                            session=session,
                            session_id=request.session_id,
                            msg_id=self._make_server_msg_id(),
                            seq_no=(request.seq_no or 0) + 1,
                            message_data=encoded,
                            direction="server",
                        )
                await write_abridged_packet(
                    writer, encoded, encrypt=None,
                )
        except AbridgedProtocolError as err:
            logger.warning(
                "transport protocol error: %s, peer=%s, state=%s",
                err, peer, transport_state,
            )
            error_code = (
                TRANSPORT_ERROR_BAD_LENGTH
                if "length" in str(err).lower()
                else TRANSPORT_ERROR_BAD_PACKET
            )
            try:
                await write_transport_error(
                    writer, error_code, encrypt=None,
                )
            except Exception:
                logger.debug(
                    "failed to write transport error to peer=%s", peer,
                )
        except TlCodecError as err:
            logger.warning("tl codec error: %s, peer=%s", err, peer)
            try:
                await write_transport_error(
                    writer, TRANSPORT_ERROR_BAD_PACKET, encrypt=None,
                )
            except Exception:
                logger.debug(
                    "failed to write transport error for TL parse peer=%s",
                    peer,
                )
        except (asyncio.IncompleteReadError, ConnectionError):
            logger.info("connection closed: %s", peer)
        except Exception:
            logger.exception(
                "connection failure: %s, state=%s", peer, transport_state,
            )
        finally:
            if push_slot is not None:
                self._push_registry.unregister(push_slot)
            if current_user_id is not None:
                try:
                    await self._grpc_bridge.call(
                        ServiceName.STATUS,
                        "SetOffline",
                        TlRequest(
                            constructor_id=0,
                            constructor="status.setOffline",
                            req_msg_id=0,
                            auth_key_id=current_auth_key_id,
                            session_id=current_session_id,
                            payload={
                                "user_id": current_user_id,
                                "auth_key_id": current_auth_key_id,
                                "session_id": current_session_id,
                            },
                        ),
                    )
                except Exception:
                    logger.exception(
                        "failed to set offline for user %s",
                        current_user_id,
                    )
            writer.close()
            await writer.wait_closed()

    async def _read_or_push(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        push_slot: PushSlot | None,
    ):
        """Wait for either an inbound frame or a push update.

        Returns the AbridgedFrame if a client packet arrived,
        or None if a push update was written (caller should continue loop).
        """
        read_coro = read_abridged_packet(reader, decrypt=None)

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
                    writer, encoded, encrypt=None,
                )
            except Exception:
                logger.debug("failed to write push update")
            if read_task in done:
                return read_task.result()
            return None

        return read_task.result()

    async def _handle_encrypted_error(
        self,
        err: EncryptedLayerError,
        maybe_auth_key_id: int,
        writer: asyncio.StreamWriter,
    ) -> None:
        if "bad_server_salt" not in str(err).lower():
            return
        if maybe_auth_key_id == 0:
            return
        session_for_salt = self._sessions.get_session(maybe_auth_key_id)
        if session_for_salt is None:
            return
        response = TlResponse(
            req_msg_id=0,
            result={
                "constructor": "bad_server_salt",
                "new_server_salt": session_for_salt.server_salt,
            },
            error_code=48,
            error_message="BAD_SERVER_SALT",
        )
        encoded = encode_tl_response(response)
        encoded = encode_encrypted_message(
            session_for_salt,
            session_for_salt.session_id,
            self._make_server_msg_id(),
            1,
            encoded,
            direction="server",
        )
        await write_abridged_packet(writer, encoded, encrypt=None)
