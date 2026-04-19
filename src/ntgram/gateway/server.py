from __future__ import annotations

import asyncio
import logging
import secrets
import time
from enum import StrEnum

from ntgram.errors import RpcFailure
from ntgram.gateway.grpc_bridge import GrpcBridge
from ntgram.gateway.mtproto.auth_handshake import AuthHandshakeProcessor
from ntgram.gateway.mtproto.encrypted_layer import (
    EncryptedLayerError,
    decode_encrypted_message,
    encode_encrypted_message,
)
from ntgram.gateway.mtproto.rsa_keys import load_rsa_keypair
from ntgram.gateway.mtproto.service_semantics import (
    ServiceSemanticsError,
    decode_service_request,
    wrap_rpc_error,
)
from ntgram.gateway.mtproto.session_store import SessionStore
from ntgram.gateway.push_registry import PushRegistry, PushSlot
from ntgram.gateway.router import GatewayRouter
from ntgram.gateway.router_contracts import ServiceName
from ntgram.gateway.transport.abridged import (
    ABRIDGED_MARKER,
    TRANSPORT_ERROR_BAD_LENGTH,
    TRANSPORT_ERROR_BAD_PACKET,
    AbridgedProtocolError,
    compute_quick_ack_token,
    read_abridged_packet,
    write_abridged_packet,
    write_abridged_quick_ack,
    write_transport_error,
)
from ntgram.gateway.transport.obfuscation import (
    ObfuscationProtocolError,
    parse_obfuscation_init,
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

    @staticmethod
    def _make_encrypted_server_msg_id() -> int:
        """Generate msg_id compatible with encrypted_layer validation."""
        value = (int(time.time()) << 32) | secrets.randbits(30)
        return value - (value % 4)

    @staticmethod
    def _extract_ack_ids(payload: dict) -> list[int]:
        raw_ids = payload.get("msg_ids", [])
        if not isinstance(raw_ids, list):
            return []
        return [int(item) for item in raw_ids if isinstance(item, int)]

    @staticmethod
    def _log_msg_container(peer: object, request: TlRequest) -> None:
        if request.constructor != "msg_container":
            return
        messages = request.payload.get("messages")
        if not isinstance(messages, list):
            logger.info("msg_container malformed: peer=%s messages_type=%s", peer, type(messages).__name__)
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
                    peer,
                    index,
                    type(item).__name__,
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

    @staticmethod
    def _log_outbound_response(
        peer: object,
        response: TlResponse,
        *,
        source: str,
        encrypted: bool,
        auth_key_id: int,
        session_id: int,
        request_constructor: str | None = None,
        request_req_msg_id: int | None = None,
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
            "outbound response: peer=%s source=%s request_constructor=%s request_req_msg_id=%s response_req_msg_id=%s constructor=%s inner_constructor=%s auth_key_id=%s session_id=%s encrypted=%s",
            peer,
            source,
            request_constructor,
            request_req_msg_id,
            response.req_msg_id,
            outer_constructor,
            inner_constructor,
            auth_key_id,
            session_id,
            encrypted,
        )

    def _bind_authenticated_user(
        self,
        request: TlRequest,
        response: TlResponse,
        push_slot: PushSlot | None,
    ) -> tuple[int | None, PushSlot | None]:
        if request.constructor not in {"auth.signIn", "auth.signUp"}:
            return None, push_slot
        nested = (
            response.result.get("result", {})
            if isinstance(response.result, dict) else {}
        )
        user_id = nested.get("user_id")
        if not isinstance(user_id, int) or request.auth_key_id == 0:
            return None, push_slot
        self._sessions.bind_user(request.auth_key_id, user_id)
        if push_slot is None:
            sess = self._sessions.get_session(request.auth_key_id)
            push_slot = PushSlot(
                user_id=user_id,
                auth_key_id=request.auth_key_id,
                session_id=request.session_id,
                session=sess,
            )
            self._push_registry.register(push_slot)
        return user_id, push_slot

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
            server_msg_id = self._make_encrypted_server_msg_id()
            encoded = encode_encrypted_message(
                session=push_slot.session,
                session_id=push_slot.session_id,
                msg_id=server_msg_id,
                seq_no=1,
                message_data=encoded,
                direction="server",
            )
            self._sessions.register_outgoing_msg(
                push_slot.auth_key_id, server_msg_id,
            )
        return encoded

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer = writer.get_extra_info("peername")
        logger.info("new connection from %s", peer)
        handshake_session_id = secrets.randbits(63) | 1
        current_user_id: int | None = None
        current_auth_key_id: int = 0
        current_session_id: int = 0
        transport_state = TransportState.INIT
        push_slot: PushSlot | None = None
        transport_encrypt = None
        transport_decrypt = None
        try:
            transport_state = TransportState.ABRIDGED_MARKER
            first = await reader.readexactly(1)
            if first[0] != ABRIDGED_MARKER:
                init_payload = first + await reader.readexactly(63)
                obfuscated = parse_obfuscation_init(init_payload)
                transport_encrypt = obfuscated.encrypt
                transport_decrypt = obfuscated.decrypt
            transport_state = TransportState.FRAMES

            while True:
                frame = await self._read_or_push(
                    reader,
                    writer,
                    push_slot,
                    decrypt=transport_decrypt,
                    encrypt=transport_encrypt,
                )
                if frame is None:
                    continue

                if frame.quick_ack_requested:
                    token = compute_quick_ack_token(frame.payload)
                    await write_abridged_quick_ack(
                        writer, token, encrypt=transport_encrypt,
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
                        try:
                            request = decode_tl_request(inner_message)
                        except Exception as err:
                            raise TlCodecError(
                                f"decode encrypted inner TL failed: {err}"
                            ) from err
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
                        try:
                            request = decode_tl_request(frame.payload)
                        except Exception as err:
                            raise TlCodecError(
                                f"decode plain TL failed: {err}"
                            ) from err
                except EncryptedLayerError as err:
                    logger.warning("encrypted layer error: %s", err)
                    await self._handle_encrypted_error(
                        err, maybe_auth_key_id, writer, transport_encrypt,
                    )
                    continue

                if (
                    encrypted_inbound
                    and maybe_auth_key_id != 0
                    and request.auth_key_id == 0
                ):
                    # Client may omit auth_key_id in inner TL envelope.
                    request = TlRequest(
                        constructor_id=request.constructor_id,
                        constructor=request.constructor,
                        req_msg_id=request.req_msg_id,
                        auth_key_id=maybe_auth_key_id,
                        session_id=request.session_id,
                        message_id=request.message_id,
                        seq_no=request.seq_no,
                        payload=request.payload,
                    )

                current_auth_key_id = request.auth_key_id
                current_session_id = request.session_id

                logger.info(
                    "inbound message: peer=%s constructor=%s req_msg_id=%s auth_key_id=%s session_id=%s encrypted=%s",
                    peer,
                    request.constructor,
                    request.req_msg_id,
                    request.auth_key_id,
                    request.session_id,
                    encrypted_inbound,
                )
                self._log_msg_container(peer, request)

                if request.auth_key_id == 0 and request.constructor in {
                    "req_pq_multi", "req_DH_params", "set_client_DH_params",
                }:
                    # Unencrypted auth flow has no session_id in wire format.
                    # Keep handshake state isolated per TCP connection.
                    request = TlRequest(
                        constructor_id=request.constructor_id,
                        constructor=request.constructor,
                        req_msg_id=request.req_msg_id,
                        auth_key_id=request.auth_key_id,
                        session_id=handshake_session_id,
                        message_id=request.message_id,
                        seq_no=request.seq_no,
                        payload=request.payload,
                    )
                    current_session_id = request.session_id

                hs_result = self._handshake.handle(request)
                if hs_result.handled:
                    response = hs_result.response or wrap_rpc_error(
                        request.req_msg_id, 500, "HANDSHAKE_INTERNAL",
                    )
                    self._log_outbound_response(
                        peer,
                        response,
                        source="handshake",
                        encrypted=encrypted_inbound,
                        auth_key_id=request.auth_key_id,
                        session_id=request.session_id,
                        request_constructor=request.constructor,
                        request_req_msg_id=request.req_msg_id,
                    )
                    encoded = encode_tl_response(response)
                    if not encrypted_inbound:
                        encoded = wrap_unencrypted(
                            self._make_server_msg_id(), encoded,
                        )
                    await write_abridged_packet(
                        writer, encoded, encrypt=transport_encrypt,
                    )
                    continue

                if request.auth_key_id == 0:
                    if request.constructor == "msgs_ack":
                        logger.info(
                            "pre-auth msgs_ack skipped: peer=%s req_msg_id=%s",
                            peer,
                            request.req_msg_id,
                        )
                        continue
                    raise TlCodecError(
                        f"unsupported pre-auth constructor: {request.constructor}"
                    )

                if request.constructor == "msgs_ack":
                    ack_ids = self._extract_ack_ids(request.payload)
                    removed_count = self._sessions.ack_outgoing_msgs(
                        request.auth_key_id,
                        ack_ids,
                    )
                    logger.info(
                        "post-auth msgs_ack processed: peer=%s auth_key_id=%s session_id=%s ack_count=%s removed=%s",
                        peer,
                        request.auth_key_id,
                        request.session_id,
                        len(ack_ids),
                        removed_count,
                    )
                    continue

                if (
                    request.auth_key_id != 0
                    and self._sessions.get_session(request.auth_key_id) is None
                ):
                    response = wrap_rpc_error(
                        request.req_msg_id, 401, "AUTH_KEY_INVALID",
                    )
                    self._log_outbound_response(
                        peer,
                        response,
                        source="auth_check",
                        encrypted=encrypted_inbound,
                        auth_key_id=request.auth_key_id,
                        session_id=request.session_id,
                        request_constructor=request.constructor,
                        request_req_msg_id=request.req_msg_id,
                    )
                    encoded = encode_tl_response(response)
                    await write_abridged_packet(
                        writer, encoded, encrypt=transport_encrypt,
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

                try:
                    service_requests = decode_service_request(request)
                except ServiceSemanticsError as err:
                    logger.warning(
                        "service semantics error: peer=%s constructor=%s error=%s",
                        peer,
                        request.constructor,
                        err,
                    )
                    continue
                if request.auth_key_id != 0:
                    for service_request in service_requests:
                        if service_request.invoke_layer is not None:
                            self._sessions.update_layer(
                                request.auth_key_id,
                                service_request.invoke_layer,
                            )
                            break
                
                responses_to_send: list[tuple[TlRequest, TlResponse]] = []
                for service_request in service_requests:
                    if service_request.constructor == "msgs_ack":
                        ack_ids = self._extract_ack_ids(service_request.payload)
                        removed_count = self._sessions.ack_outgoing_msgs(
                            service_request.auth_key_id,
                            ack_ids,
                        )
                        logger.info(
                            "container msgs_ack processed: peer=%s auth_key_id=%s session_id=%s ack_count=%s removed=%s",
                            peer,
                            service_request.auth_key_id,
                            service_request.session_id,
                            len(ack_ids),
                            removed_count,
                        )
                        continue
                    try:
                        response = await self._router.dispatch(
                            service_request,
                        )
                    except RpcFailure as err:
                        if err.message == "RPC_METHOD_NOT_SUPPORTED":
                            raise TlCodecError(
                                f"unsupported RPC method: {service_request.constructor}"
                            ) from err
                        response = wrap_rpc_error(
                            service_request.req_msg_id,
                            err.code,
                            err.message,
                        )
                    responses_to_send.append((service_request, response))
                    bound_user_id, push_slot = self._bind_authenticated_user(
                        service_request,
                        response,
                        push_slot,
                    )
                    if bound_user_id is not None:
                        current_user_id = bound_user_id

                if not responses_to_send:
                    continue

                for response_request, response in responses_to_send:
                    self._log_outbound_response(
                        peer,
                        response,
                        source="rpc_dispatch",
                        encrypted=encrypted_inbound,
                        auth_key_id=response_request.auth_key_id,
                        session_id=response_request.session_id,
                        request_constructor=response_request.constructor,
                        request_req_msg_id=response_request.req_msg_id,
                    )
                    encoded = encode_tl_response(response)
                    if encrypted_inbound and response_request.auth_key_id != 0:
                        session = self._sessions.get_session(
                            response_request.auth_key_id,
                        )
                        if session is not None:
                            server_msg_id = self._make_encrypted_server_msg_id()
                            encoded = encode_encrypted_message(
                                session=session,
                                session_id=response_request.session_id,
                                msg_id=server_msg_id,
                                seq_no=(response_request.seq_no or request.seq_no or 0) + 1,
                                message_data=encoded,
                                direction="server",
                            )
                            self._sessions.register_outgoing_msg(
                                response_request.auth_key_id,
                                server_msg_id,
                            )
                    await write_abridged_packet(
                        writer, encoded, encrypt=transport_encrypt,
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
                    writer, error_code, encrypt=transport_encrypt,
                )
            except Exception:
                logger.debug(
                    "failed to write transport error to peer=%s", peer,
                )
        except ObfuscationProtocolError as err:
            logger.warning(
                "obfuscation protocol error: %s, peer=%s, state=%s",
                err, peer, transport_state,
            )
            try:
                await write_transport_error(
                    writer, TRANSPORT_ERROR_BAD_PACKET, encrypt=None,
                )
            except Exception:
                logger.debug(
                    "failed to write obfuscation transport error to peer=%s",
                    peer,
                )
        except TlCodecError as err:
            logger.warning("tl codec error: %s, peer=%s", err, peer)
            try:
                await write_transport_error(
                    writer, TRANSPORT_ERROR_BAD_PACKET, encrypt=transport_encrypt,
                )
            except Exception:
                logger.debug(
                    "failed to write transport error for TL parse peer=%s",
                    peer,
                )
        except (asyncio.IncompleteReadError, ConnectionError) as err:
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
        decrypt=None,
        encrypt=None,
    ):
        """Wait for either an inbound frame or a push update.

        Returns the AbridgedFrame if a client packet arrived,
        or None if a push update was written (caller should continue loop).
        """
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
        encrypt=None,
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
        self._log_outbound_response(
            writer.get_extra_info("peername"),
            response,
            source="encrypted_error",
            encrypted=True,
            auth_key_id=maybe_auth_key_id,
            session_id=session_for_salt.session_id,
            request_constructor="encrypted_message",
            request_req_msg_id=0,
        )
        encoded = encode_tl_response(response)
        server_msg_id = self._make_encrypted_server_msg_id()
        encoded = encode_encrypted_message(
            session_for_salt,
            session_for_salt.session_id,
            server_msg_id,
            1,
            encoded,
            direction="server",
        )
        self._sessions.register_outgoing_msg(
            maybe_auth_key_id,
            server_msg_id,
        )
        await write_abridged_packet(writer, encoded, encrypt=encrypt)
