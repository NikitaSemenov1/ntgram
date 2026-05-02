from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from enum import Enum

from ntgram.gateway.mtproto.encrypted_layer import (
    EncryptedLayerError,
    decode_bind_temp_auth_key_inner_message,
)
from ntgram.gateway.mtproto.session_store import (
    SessionStore,
    TempAuthKeyBinding,
)
from ntgram.tl.codec import decode_tl_request

logger = logging.getLogger(__name__)


class BindErrorCode(Enum):
    """Discriminator for failure variants in `BindError`."""

    ENCRYPTED_MESSAGE_INVALID = "ENCRYPTED_MESSAGE_INVALID"
    TEMP_AUTH_KEY_EMPTY = "TEMP_AUTH_KEY_EMPTY"
    PERM_AUTH_KEY_MISSING = "PERM_AUTH_KEY_MISSING"
    EXPIRES_AT_INVALID = "EXPIRES_AT_INVALID"
    TEMP_AUTH_KEY_ALREADY_BOUND = "TEMP_AUTH_KEY_ALREADY_BOUND"


@dataclass(slots=True, frozen=True)
class BindRequest:
    """Inputs for :meth:`BindTempAuthKeyService.bind`."""

    temp_auth_key_id: int
    perm_auth_key_id: int
    nonce: int
    expires_at: int
    temp_session_id: int
    expected_msg_id: int
    encrypted_message: bytes


@dataclass(slots=True, frozen=True)
class BindOk:
    """Successful binding outcome."""


@dataclass(slots=True, frozen=True)
class BindError:
    """Failed binding outcome with a stable error symbol."""

    code: BindErrorCode


BindResult = BindOk | BindError


class BindTempAuthKeyService:
    """Stateless service over `SessionStore`."""

    __slots__ = ("_sessions",)

    def __init__(self, sessions: SessionStore) -> None:
        self._sessions = sessions

    def bind(self, req: BindRequest) -> BindResult:
        if not isinstance(
            req.encrypted_message, (bytes, bytearray, memoryview),
        ):
            logger.debug("auth.bindTempAuthKey: encrypted_message must be bytes")
            return BindError(BindErrorCode.ENCRYPTED_MESSAGE_INVALID)

        enc = bytes(req.encrypted_message)
        temp_session = self._sessions.get_session(req.temp_auth_key_id)
        if temp_session is None:
            logger.debug(
                "auth.bindTempAuthKey: temp auth key not found "
                "(temp_auth_key_id=%s)",
                req.temp_auth_key_id,
            )
            return BindError(BindErrorCode.TEMP_AUTH_KEY_EMPTY)

        perm_session = self._sessions.get_session(req.perm_auth_key_id)
        if perm_session is None:
            logger.debug(
                "auth.bindTempAuthKey: permanent auth key not found "
                "(perm_auth_key_id=%s temp_auth_key_id=%s)",
                req.perm_auth_key_id,
                req.temp_auth_key_id,
            )
            return BindError(BindErrorCode.PERM_AUTH_KEY_MISSING)

        try:
            _inner_mid, _inner_seq, inner_body = (
                decode_bind_temp_auth_key_inner_message(
                    perm_session,
                    enc,
                    expected_msg_id=req.expected_msg_id,
                )
            )
            inner_request = decode_tl_request(inner_body)
            if inner_request.constructor != "bind_auth_key_inner":
                raise ValueError("inner constructor mismatch")

            inner = inner_request.payload
            checks = {
                "nonce": int(inner.get("nonce", 0)) == req.nonce,
                "temp_auth_key_id": int(inner.get("temp_auth_key_id", 0))
                == req.temp_auth_key_id,
                "perm_auth_key_id": int(inner.get("perm_auth_key_id", 0))
                == req.perm_auth_key_id,
                "temp_session_id": int(inner.get("temp_session_id", 0))
                == req.temp_session_id,
                "expires_at": int(inner.get("expires_at", 0)) == req.expires_at,
                "not_expired": req.expires_at > int(time.time()),
            }
            if not all(checks.values()):
                if not checks["expires_at"] or not checks["not_expired"]:
                    raise ValueError("expires_at invalid")
                raise ValueError("binding fields mismatch")

            existing = temp_session.temp_auth_key_binding
            if (
                existing is not None
                and existing.perm_auth_key_id != req.perm_auth_key_id
            ):
                raise ValueError("temp auth key already bound")

            if not self._apply_binding(
                temp_session=temp_session,
                perm_session=perm_session,
                nonce=req.nonce,
                temp_session_id=req.temp_session_id,
                expires_at=req.expires_at,
            ):
                raise ValueError("store binding failed")
        except EncryptedLayerError as exc:
            logger.warning("auth.bindTempAuthKey decrypt failed: %s", exc)
            return BindError(BindErrorCode.ENCRYPTED_MESSAGE_INVALID)
        except ValueError as exc:
            msg = str(exc)
            if msg == "expires_at invalid":
                code = BindErrorCode.EXPIRES_AT_INVALID
            elif msg == "temp auth key already bound":
                code = BindErrorCode.TEMP_AUTH_KEY_ALREADY_BOUND
            else:
                code = BindErrorCode.ENCRYPTED_MESSAGE_INVALID
            logger.warning("auth.bindTempAuthKey failed: %s", exc)
            return BindError(code)

        return BindOk()

    def _apply_binding(
        self,
        *,
        temp_session,
        perm_session,
        nonce: int,
        temp_session_id: int,
        expires_at: int,
    ) -> bool:
        """Two-session transactional bind: replace any previous temp binding,
        record the new one on both sessions, and persist."""
        if expires_at <= int(time.time()):
            return False

        previous = perm_session.temp_auth_key_binding
        if previous is not None:
            previous_temp = self._sessions.get_session(previous.temp_auth_key_id)
            if previous_temp is not None:
                previous_temp.temp_auth_key_binding = None
                self._sessions.save_session(previous_temp.auth_key_id)

        binding = TempAuthKeyBinding(
            perm_auth_key_id=perm_session.auth_key_id,
            temp_auth_key_id=temp_session.auth_key_id,
            nonce=nonce,
            temp_session_id=temp_session_id,
            expires_at=expires_at,
        )
        perm_session.temp_auth_key_binding = binding
        temp_session.temp_auth_key_binding = binding
        temp_session.bind_mtproto_session(temp_session_id)
        self._sessions.save_session(perm_session.auth_key_id)
        self._sessions.save_session(temp_session.auth_key_id)
        return True
