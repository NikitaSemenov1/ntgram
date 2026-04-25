from __future__ import annotations

import json
import logging
import secrets
import time
from pathlib import Path
from typing import Any

from ntgram.errors import METHOD_NOT_SUPPORTED, RpcFailure
from ntgram.gateway.grpc_bridge import GrpcBridge
from ntgram.gateway.mtproto.encrypted_layer import (
    EncryptedLayerError,
    decode_bind_temp_auth_key_inner_message,
)
from ntgram.gateway.mtproto.service_semantics import (
    ServiceContext,
    handle_control_message,
    wrap_rpc_error,
    wrap_rpc_result,
)
from ntgram.gateway.mtproto.session_store import SessionStore
from ntgram.gateway.router_contracts import (
    ROUTES_BY_CONSTRUCTOR,
    ROUTES_BY_CONSTRUCTOR_ID,
    ServiceName,
)
from ntgram.gateway.update_bus import UpdateBus
from ntgram.tl.codec import decode_tl_request
from ntgram.tl.models import TlRequest, TlResponse
from ntgram.tl.registry import default_schema_registry
from ntgram.tl.serializer import _serialize_value

logger = logging.getLogger(__name__)


class GatewayRouter:
    def __init__(
        self,
        grpc_bridge: GrpcBridge,
        sessions: SessionStore,
        update_bus: UpdateBus,
        *,
        help_get_config_path: str | None = None,
    ) -> None:
        self._grpc = grpc_bridge
        self._sessions = sessions
        self._update_bus = update_bus
        self._help_get_config_path = help_get_config_path
        self._help_get_config_payload: dict[str, Any] | None = None
        self._service_context: dict[int, ServiceContext] = {}

    async def dispatch(self, request: TlRequest) -> TlResponse:
        if request.constructor == "auth.bindTempAuthKey":
            return self._handle_bind_temp_auth_key(request)

        control_response = handle_control_message(
            self._service_context.setdefault(
                request.session_id, ServiceContext(),
            ),
            request,
        )
        if control_response is not None:
            return control_response

        if request.constructor == "updates.getState":
            return await self._handle_get_state(request)

        if request.constructor == "updates.getDifference":
            return await self._handle_get_difference(request)

        if request.constructor == "help.getConfig":
            return self._handle_help_get_config(request)
        if request.constructor == "help.getNearestDc":
            return self._handle_help_get_nearest_dc(request)

        if request.constructor == "destroy_session":
            return self._handle_destroy_session(request)

        if request.constructor == "get_future_salts":
            return await self._handle_get_future_salts(request)

        if request.constructor == "langpack.getLanguages":
            return self._handle_langpack_get_languages(request)

        route = ROUTES_BY_CONSTRUCTOR_ID.get(request.constructor_id)
        if route is None:
            route = ROUTES_BY_CONSTRUCTOR.get(request.constructor)
        if route is None:
            raise METHOD_NOT_SUPPORTED

        try:
            result = await self._grpc.call(
                route.service, route.method, request,
            )

            if route.service == ServiceName.MESSAGE:
                await self._fanout_message_update(request, result)
            elif route.service == ServiceName.STATUS:
                await self._fanout_status_update(result)

            response = wrap_rpc_result(request.req_msg_id, result)
            ctx = self._service_context.setdefault(
                request.session_id, ServiceContext(),
            )
            ctx.pending_results[request.req_msg_id] = response
            return response
        except RpcFailure as err:
            return wrap_rpc_error(
                request.req_msg_id, err.code, err.message,
            )

    async def _handle_get_state(
        self, request: TlRequest,
    ) -> TlResponse:
        session = self._sessions.get_session(request.auth_key_id)
        user_id = session.user_id if session else None
        if user_id:
            try:
                state = await self._grpc.get_updates_state(user_id)
                return wrap_rpc_result(request.req_msg_id, state)
            except Exception:
                logger.debug("getState gRPC failed, returning zeros")
        return wrap_rpc_result(
            request.req_msg_id,
            {"pts": 0, "qts": 0, "seq": 0, "date": int(time.time())},
        )

    async def _handle_get_difference(
        self, request: TlRequest,
    ) -> TlResponse:
        session = self._sessions.get_session(request.auth_key_id)
        if session is None:
            return wrap_rpc_error(
                request.req_msg_id, 401, "AUTH_KEY_INVALID",
            )
        user_id = session.user_id
        if not user_id:
            return wrap_rpc_error(
                request.req_msg_id, 401, "AUTH_KEY_UNREGISTERED",
            )
        pts = request.payload.get("pts", 0)
        try:
            diff = await self._grpc.get_updates_difference(user_id, pts)
            return wrap_rpc_result(request.req_msg_id, diff)
        except Exception:
            logger.debug("getDifference gRPC failed, returning empty")
            return wrap_rpc_result(
                request.req_msg_id,
                {
                    "constructor": "updates.differenceEmpty",
                    "date": int(time.time()),
                    "seq": 0,
                },
            )

    def _handle_bind_temp_auth_key(self, request: TlRequest) -> TlResponse:
        """Bind temporary auth key to permanent auth key.

        The outer method is sent using the temp key. Its encrypted_message is a
        special MTProto v1 encrypted binding message under the permanent key.
        """
        error_message = "TEMP_AUTH_KEY_BIND_INVALID"
        perm_auth_key_id = int(request.payload.get("perm_auth_key_id", 0))
        nonce = int(request.payload.get("nonce", 0))
        expires_at = int(request.payload.get("expires_at", 0))
        encrypted_message = request.payload.get("encrypted_message", b"")
        if not isinstance(encrypted_message, (bytes, bytearray, memoryview)):
            logger.debug("auth.bindTempAuthKey: encrypted_message must be bytes")
            return wrap_rpc_error(
                request.req_msg_id, 400, "ENCRYPTED_MESSAGE_INVALID",
            )

        enc = bytes(encrypted_message)
        perm_session = self._sessions.get_session(perm_auth_key_id)
        temp_session = self._sessions.get_session(request.auth_key_id)
        if temp_session is None:
            logger.debug(
                "auth.bindTempAuthKey: temp auth key not found "
                "(temp_auth_key_id=%s)",
                request.auth_key_id,
            )
            return wrap_rpc_error(request.req_msg_id, 400, "TEMP_AUTH_KEY_EMPTY")
        if perm_session is None:
            logger.debug(
                "auth.bindTempAuthKey: permanent auth key not found "
                "(perm_auth_key_id=%s temp_auth_key_id=%s)",
                perm_auth_key_id,
                request.auth_key_id,
            )
            return wrap_rpc_result(
                request.req_msg_id,
                {"constructor": "boolFalse"},
            )

        try:
            _inner_mid, _inner_seq, inner_body = (
                decode_bind_temp_auth_key_inner_message(
                    perm_session,
                    enc,
                    expected_msg_id=request.req_msg_id,
                )
            )
            inner_request = decode_tl_request(inner_body)
            if inner_request.constructor != "bind_auth_key_inner":
                raise ValueError("inner constructor mismatch")

            inner = inner_request.payload
            checks = {
                "nonce": int(inner.get("nonce", 0)) == nonce,
                "temp_auth_key_id": int(inner.get("temp_auth_key_id", 0))
                == request.auth_key_id,
                "perm_auth_key_id": int(inner.get("perm_auth_key_id", 0))
                == perm_auth_key_id,
                "temp_session_id": int(inner.get("temp_session_id", 0))
                == request.session_id,
                "expires_at": int(inner.get("expires_at", 0)) == expires_at,
                "not_expired": expires_at > int(time.time()),
            }
            if not all(checks.values()):
                if not checks["expires_at"] or not checks["not_expired"]:
                    raise ValueError("expires_at invalid")
                raise ValueError("binding fields mismatch")

            existing = temp_session.temp_auth_key_binding
            if (
                existing is not None
                and existing.perm_auth_key_id != perm_auth_key_id
            ):
                raise ValueError("temp auth key already bound")

            if not self._sessions.bind_temp_auth_key(
                temp_auth_key_id=request.auth_key_id,
                perm_auth_key_id=perm_auth_key_id,
                nonce=nonce,
                temp_session_id=request.session_id,
                expires_at=expires_at,
            ):
                raise ValueError("store binding failed")

            return wrap_rpc_result(
                request.req_msg_id,
                {"constructor": "boolTrue"},
            )
        except (EncryptedLayerError, ValueError) as exc:
            if isinstance(exc, EncryptedLayerError):
                error_message = "ENCRYPTED_MESSAGE_INVALID"
            elif str(exc) == "expires_at invalid":
                error_message = "EXPIRES_AT_INVALID"
            elif str(exc) == "temp auth key already bound":
                error_message = "TEMP_AUTH_KEY_ALREADY_BOUND"
            elif str(exc) in {
                "binding fields mismatch",
                "inner constructor mismatch",
                "store binding failed",
            }:
                error_message = "ENCRYPTED_MESSAGE_INVALID"
            logger.warning("auth.bindTempAuthKey failed: %s", exc)
            return wrap_rpc_error(request.req_msg_id, 400, error_message)

    async def _fanout_message_update(
        self, request: TlRequest, result: dict,
    ) -> None:
        """Push message update to all dialog participants."""
        dialog_id = request.payload.get("dialog_id", 0)
        if not dialog_id:
            return

        try:
            members = await self._grpc.resolve_dialog_members(dialog_id)
        except Exception:
            members = []

        if not members:
            return

        constructor = request.constructor
        if constructor == "messages.sendMessage":
            await self._update_bus.notify_new_message(
                members,
                exclude_auth_key_id=request.auth_key_id,
                message_id=result.get("message_id", 0),
                dialog_id=dialog_id,
                from_user_id=request.payload.get("actor_user_id", 0),
                text=request.payload.get("text", ""),
                pts=result.get("pts", 0),
            )
        elif constructor == "messages.deleteMessages":
            deleted = result.get("deleted_ids", [])
            if deleted:
                await self._update_bus.notify_delete_messages(
                    members,
                    exclude_auth_key_id=request.auth_key_id,
                    message_ids=deleted,
                    dialog_id=dialog_id,
                    pts=result.get("pts", 0),
                )

    async def _fanout_status_update(self, result: dict) -> None:
        """Push status change if became_online/became_offline."""
        if result.get("became_online"):
            user_id = result.get("user_id", 0)
            if user_id:
                await self._update_bus.notify_status_change(
                    user_id, online=True,
                )
        elif result.get("became_offline"):
            user_id = result.get("user_id", 0)
            if user_id:
                await self._update_bus.notify_status_change(
                    user_id, online=False,
                )

    @staticmethod
    def _help_get_config_file_default() -> Path:
        """`ntgram/config/help_get_config.json` (sibling of `src/` in the ntgram repo)."""
        return Path(__file__).resolve().parents[3] / "config" / "help_get_config.json"

    def _resolve_help_get_config_path(self) -> Path:
        raw = (self._help_get_config_path or "").strip()
        if raw:
            return Path(raw)
        return self._help_get_config_file_default()

    def _load_help_get_config_raw(self) -> dict[str, Any]:
        if self._help_get_config_payload is not None:
            return self._help_get_config_payload
        path = self._resolve_help_get_config_path()
        if not path.is_file():
            raise FileNotFoundError(f"help.getConfig JSON not found: {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("help_get_config.json must decode to a JSON object")
        if data.get("constructor") != "config":
            raise ValueError('help_get_config.json must have "constructor": "config"')
        self._help_get_config_payload = data
        return data

    def _handle_help_get_config(self, request: TlRequest) -> TlResponse:
        """Return TL `config` from JSON (see `ntgram/config/help_get_config.json`)."""
        return wrap_rpc_result(
            request.req_msg_id,
            dict(self._load_help_get_config_raw()),
        )

    def _handle_destroy_session(self, request: TlRequest) -> TlResponse:
        """MTProto ``destroy_session``: forget another ``session_id`` for this auth key."""
        raw_sid = request.payload.get("session_id", 0)
        try:
            target_session_id = int(raw_sid)
        except (TypeError, ValueError):
            target_session_id = 0
        if request.auth_key_id == 0:
            ctor = "destroy_session_none"
        elif self._sessions.destroy_mtproto_session(
            request.auth_key_id, target_session_id,
        ):
            ctor = "destroy_session_ok"
        else:
            ctor = "destroy_session_none"
        return wrap_rpc_result(
            request.req_msg_id,
            {"constructor": ctor, "session_id": target_session_id},
        )

    async def _handle_get_future_salts(self, request: TlRequest) -> TlResponse:
        """MTProto ``get_future_salts``: return up to ``num`` future server salts (spec 1..64)."""
        raw = request.payload.get("num", 1)
        try:
            num = int(raw)
        except (TypeError, ValueError):
            num = 1
        num = max(1, min(64, num))

        session = self._sessions.get_session(request.auth_key_id)
        if session is None:
            return wrap_rpc_error(
                request.req_msg_id,
                401,
                "AUTH_KEY_INVALID",
            )

        query_msg_id = request.message_id or request.req_msg_id
        now = int(time.time())
        used: set[int] = {session.server_salt, *session.accepted_future_salts}
        entries: list[tuple[int, int, int]] = []
        salts_list: list[dict[str, Any]] = []
        for i in range(num):
            candidate = 0
            for _ in range(64):
                cand = int.from_bytes(secrets.token_bytes(8), "little", signed=False)
                if cand != 0 and cand not in used:
                    candidate = cand
                    break
            if candidate == 0:
                break
            used.add(candidate)
            valid_since = now + i * 300
            valid_until = valid_since + 7200
            entries.append((valid_since, valid_until, candidate))
            salts_list.append(
                {
                    "constructor": "future_salt",
                    "valid_since": valid_since,
                    "valid_until": valid_until,
                    "salt": candidate,
                },
            )

        self._sessions.register_future_salts_for_auth_key(
            request.auth_key_id,
            entries,
        )

        return wrap_rpc_result(
            request.req_msg_id,
            {
                "constructor": "future_salts",
                "req_msg_id": query_msg_id,
                "now": now,
                "salts": salts_list,
            },
        )

    @staticmethod
    def _handle_langpack_get_languages(request: TlRequest) -> TlResponse:
        """Return ``Vector<LangPackLanguage>`` (empty stub until langpack is wired to services)."""
        buf = bytearray()
        _serialize_value(
            buf,
            "Vector<LangPackLanguage>",
            [],
            default_schema_registry(),
        )
        return wrap_rpc_result(request.req_msg_id, bytes(buf))

    @staticmethod
    def _handle_help_get_nearest_dc(request: TlRequest) -> TlResponse:
        """Return the current/nearest DC for early PFS bootstrap."""
        return wrap_rpc_result(
            request.req_msg_id,
            {
                "constructor": "nearestDc",
                "country": "",
                "this_dc": 1,
                "nearest_dc": 1,
            },
        )
