"""MTProto auth key exchange: full DH + RSA implementation.

Implements the handshake flow per https://core.telegram.org/mtproto/auth_key:
  req_pq_multi  -> resPQ
  req_DH_params -> server_DH_params_ok
  set_client_DH_params -> dh_gen_ok / dh_gen_retry / dh_gen_fail
"""
from __future__ import annotations

import hashlib
import logging
import os
import secrets
import time
from dataclasses import dataclass

from ntgram.gateway.mtproto.dh_params import (
    DH_G,
    DH_PRIME,
    DH_PRIME_BYTES,
    compute_auth_key,
    generate_dh_pair,
)
from ntgram.gateway.mtproto.encrypted_layer import _aes_ige_encrypt_blockwise
from ntgram.gateway.mtproto.rsa_keys import RsaKeyPair
from ntgram.gateway.mtproto.rsa_pad import RsaPadError, rsa_pad_decrypt
from ntgram.gateway.mtproto.session_store import SessionStore
from ntgram.gateway.mtproto.tmp_aes import tmp_aes_decrypt
from ntgram.tl.codec import encode_tl_object
from ntgram.tl.models import TlRequest, TlResponse
from ntgram.tl.serializer import _Reader, deserialize_from_reader

logger = logging.getLogger(__name__)


@dataclass(slots=True, frozen=True)
class HandshakeResult:
    handled: bool
    response: TlResponse | None


def _make_pq() -> tuple[int, int, int]:
    """Generate a 64-bit-ish semi-prime pq = p * q where p < q.

    We avoid optional dependencies and use a deterministic Miller-Rabin test
    suitable for 32-bit candidates.
    """
    while True:
        p = (1 << 30) | secrets.randbits(30) | 1
        if _is_probable_prime_32(p):
            break
    while True:
        q = (1 << 30) | secrets.randbits(30) | 1
        if q != p and _is_probable_prime_32(q):
            break
    if p > q:
        p, q = q, p
    return p, q, p * q


def _is_probable_prime_32(value: int) -> bool:
    if value < 2:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29)
    for prime in small_primes:
        if value == prime:
            return True
        if value % prime == 0:
            return False

    d = value - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    # Sufficient fixed bases for 32-bit integers.
    for base in (2, 3, 5, 7, 11):
        if base % value == 0:
            continue
        x = pow(base, d, value)
        if x == 1 or x == value - 1:
            continue
        composite = True
        for _ in range(s - 1):
            x = (x * x) % value
            if x == value - 1:
                composite = False
                break
        if composite:
            return False
    return True


def _int_to_bytes_tl(value: int) -> bytes:
    """Encode an integer as big-endian bytes (minimal length, no leading zeros)."""
    if value == 0:
        return b"\x00"
    length = (value.bit_length() + 7) // 8
    return value.to_bytes(length, "big")


def _is_dh_public_value_safe(value: int) -> bool:
    """Check DH public value using Telegram's recommended tighter range."""
    lower = 1 << (2048 - 64)
    upper = DH_PRIME - lower
    return lower <= value <= upper


def _new_nonce_hash(new_nonce: int, tag: int, auth_key_aux_hash: int) -> int:
    """Compute new_nonce_hash{1,2,3} per spec.

    SHA1(new_nonce_bytes + tag_byte + auth_key_aux_hash_bytes), take lower 128 bits.
    """
    nn = new_nonce.to_bytes(32, "little")
    aux = auth_key_aux_hash.to_bytes(8, "little")
    data = nn + bytes([tag]) + aux
    sha1 = hashlib.sha1(data).digest()
    return int.from_bytes(sha1[-16:], "little")


class AuthHandshakeProcessor:
    """Processes MTProto auth key exchange constructors.

    Flow: req_pq_multi -> req_DH_params -> set_client_DH_params
    """

    def __init__(self, sessions: SessionStore, rsa_keypair: RsaKeyPair) -> None:
        self._sessions = sessions
        self._rsa_keypair = rsa_keypair
        self._p, self._q, self._pq = _make_pq()

    def handle(self, request: TlRequest) -> HandshakeResult:
        if request.constructor in {
            "req_pq_multi", "req_DH_params", "set_client_DH_params",
        }:
            hs = self._sessions.get_or_create_handshake(request.session_id)
            logger.info(
                "handshake step received: session_id=%s stage=%s constructor=%s req_msg_id=%s",
                request.session_id,
                hs.stage,
                request.constructor,
                request.req_msg_id,
            )
        if request.constructor == "req_pq_multi":
            response = self._on_req_pq_multi(request)
            self._log_handshake_response(request, response)
            return HandshakeResult(True, response)
        if request.constructor == "req_DH_params":
            response = self._on_req_dh_params(request)
            self._log_handshake_response(request, response)
            return HandshakeResult(True, response)
        if request.constructor == "set_client_DH_params":
            response = self._on_set_client_dh_params(request)
            self._log_handshake_response(request, response)
            return HandshakeResult(True, response)
        return HandshakeResult(False, None)

    # ------------------------------------------------------------------
    # Stage 1: req_pq_multi -> resPQ
    # ------------------------------------------------------------------

    def _on_req_pq_multi(self, request: TlRequest) -> TlResponse:
        hs = self._sessions.get_or_create_handshake(request.session_id)
        nonce = request.payload.get("nonce", 0)
        if nonce == 0:
            return self._error_response(request, "NONCE_INVALID")

        server_nonce = secrets.randbits(128)
        hs.nonce = nonce
        hs.server_nonce = server_nonce
        hs.p = self._p
        hs.q = self._q
        hs.pq = self._pq
        hs.stage = "pq_sent"

        pq_bytes = _int_to_bytes_tl(self._pq)

        return TlResponse(
            req_msg_id=request.req_msg_id,
            result={
                "constructor": "resPQ",
                "nonce": nonce,
                "server_nonce": server_nonce,
                "pq": pq_bytes,
                "server_public_key_fingerprints": [self._rsa_keypair.fingerprint],
            },
        )

    # ------------------------------------------------------------------
    # Stage 2: req_DH_params -> server_DH_params_ok
    # ------------------------------------------------------------------

    def _on_req_dh_params(self, request: TlRequest) -> TlResponse:
        hs = self._sessions.get_or_create_handshake(request.session_id)

        if hs.stage not in ("pq_sent", "dh_params_sent"):
            return self._error_response(request, "HANDSHAKE_STATE_INVALID")
        if hs.nonce is None or hs.server_nonce is None:
            return self._error_response(request, "HANDSHAKE_STATE_INVALID")

        req_nonce = request.payload.get("nonce", 0)
        req_server_nonce = request.payload.get("server_nonce", 0)
        if req_nonce != hs.nonce or req_server_nonce != hs.server_nonce:
            return self._error_response(request, "NONCE_MISMATCH")

        public_key_fingerprint = int(request.payload.get("public_key_fingerprint", 0))
        if public_key_fingerprint != self._rsa_keypair.fingerprint:
            return self._error_response(request, "PUBLIC_KEY_FINGERPRINT_MISMATCH")

        encrypted_data = request.payload.get("encrypted_data", b"")
        if isinstance(encrypted_data, str):
            encrypted_data = bytes.fromhex(encrypted_data)

        try:
            inner_data_padded = rsa_pad_decrypt(
                encrypted_data, self._rsa_keypair.private_key,
            )
        except (RsaPadError, ValueError) as exc:
            logger.warning("RSA_PAD decrypt failed: %s", exc)
            return self._error_response(request, "RSA_PAD_FAILED")

        try:
            from ntgram.tl.registry import default_schema_registry
            registry = default_schema_registry()
            reader = _Reader(inner_data_padded)
            name, fields = deserialize_from_reader(reader, registry)
        except Exception as exc:
            logger.warning("failed to parse p_q_inner_data: %s", exc)
            return self._error_response(request, "INNER_DATA_INVALID")

        if name not in ("p_q_inner_data_dc", "p_q_inner_data_temp_dc"):
            return self._error_response(request, "INNER_DATA_CONSTRUCTOR_INVALID")

        if fields.get("nonce") != hs.nonce:
            return self._error_response(request, "NONCE_MISMATCH")
        if fields.get("server_nonce") != hs.server_nonce:
            return self._error_response(request, "SERVER_NONCE_MISMATCH")

        client_p = int.from_bytes(fields.get("p", b""), "big")
        client_q = int.from_bytes(fields.get("q", b""), "big")
        if (client_p, client_q) != (hs.p, hs.q):
            return self._error_response(request, "PQ_FACTORIZATION_MISMATCH")

        new_nonce = fields.get("new_nonce", 0)
        hs.new_nonce = new_nonce

        a, g_a = generate_dh_pair()
        hs.dh_secret_a = a
        hs.g_a = g_a

        inner_tl = encode_tl_object("server_DH_inner_data", {
            "nonce": hs.nonce,
            "server_nonce": hs.server_nonce,
            "g": DH_G,
            "dh_prime": DH_PRIME_BYTES,
            "g_a": g_a.to_bytes(256, "big"),
            "server_time": int(time.time()),
        })

        # answer_with_hash = SHA1(answer) + answer + random padding (mod 16)
        sha1_answer = hashlib.sha1(inner_tl).digest()
        answer_with_hash = sha1_answer + inner_tl
        pad_len = (16 - (len(answer_with_hash) % 16)) % 16
        answer_with_hash += os.urandom(pad_len) if pad_len else b""

        from ntgram.gateway.mtproto.tmp_aes import compute_tmp_aes_key_iv
        tmp_key, tmp_iv = compute_tmp_aes_key_iv(hs.server_nonce, new_nonce)
        encrypted_answer = _aes_ige_encrypt_blockwise(answer_with_hash, tmp_key, tmp_iv)

        hs.stage = "dh_params_sent"

        return TlResponse(
            req_msg_id=request.req_msg_id,
            result={
                "constructor": "server_DH_params_ok",
                "nonce": hs.nonce,
                "server_nonce": hs.server_nonce,
                "encrypted_answer": encrypted_answer,
            },
        )

    # ------------------------------------------------------------------
    # Stage 3: set_client_DH_params -> dh_gen_ok / retry / fail
    # ------------------------------------------------------------------

    def _on_set_client_dh_params(self, request: TlRequest) -> TlResponse:
        hs = self._sessions.get_or_create_handshake(request.session_id)

        if hs.stage != "dh_params_sent":
            return self._error_response(request, "HANDSHAKE_STATE_INVALID")
        if hs.nonce is None or hs.server_nonce is None or hs.new_nonce is None:
            return self._error_response(request, "HANDSHAKE_STATE_INVALID")

        req_nonce = request.payload.get("nonce", 0)
        req_server_nonce = request.payload.get("server_nonce", 0)
        if req_nonce != hs.nonce or req_server_nonce != hs.server_nonce:
            return self._error_response(request, "NONCE_MISMATCH")

        encrypted_data = request.payload.get("encrypted_data", b"")
        if isinstance(encrypted_data, str):
            encrypted_data = bytes.fromhex(encrypted_data)

        try:
            decrypted = tmp_aes_decrypt(encrypted_data, hs.server_nonce, hs.new_nonce)
        except Exception as exc:
            logger.warning("tmp_aes decrypt failed: %s", exc)
            return self._dh_gen_fail(request, hs, "TMP_AES_DECRYPT_FAILED")

        if len(decrypted) < 20:
            return self._dh_gen_fail(request, hs, "CLIENT_DH_TOO_SHORT")
        sha1_prefix = decrypted[:20]
        inner_payload = decrypted[20:]

        try:
            from ntgram.tl.registry import default_schema_registry
            registry = default_schema_registry()
            reader = _Reader(inner_payload)
            name, fields = deserialize_from_reader(reader, registry)
        except Exception as exc:
            logger.warning("failed to parse client_DH_inner_data: %s", exc)
            return self._dh_gen_fail(request, hs, "CLIENT_DH_PARSE_FAILED")

        consumed = inner_payload[:reader.offset]
        expected_sha1 = hashlib.sha1(consumed).digest()
        if expected_sha1 != sha1_prefix:
            logger.warning("client_DH_inner_data SHA1 mismatch")
            return self._dh_gen_fail(request, hs, "CLIENT_DH_SHA1_MISMATCH")

        if name != "client_DH_inner_data":
            return self._dh_gen_fail(request, hs, "CLIENT_DH_CONSTRUCTOR_INVALID")

        if fields.get("nonce") != hs.nonce or fields.get("server_nonce") != hs.server_nonce:
            return self._dh_gen_fail(request, hs, "CLIENT_DH_NONCE_MISMATCH")

        g_b_bytes = fields.get("g_b", b"")
        g_b = int.from_bytes(g_b_bytes, "big")

        if not _is_dh_public_value_safe(g_b):
            return self._dh_gen_fail(request, hs, "CLIENT_G_B_OUT_OF_RANGE")

        try:
            auth_key = compute_auth_key(g_b, hs.dh_secret_a)
        except ValueError:
            return self._dh_gen_fail(request, hs, "AUTH_KEY_DERIVATION_FAILED")

        auth_key_aux_hash = SessionStore.make_auth_key_aux_hash(auth_key)

        session = self._sessions.complete_handshake(
            session_id=request.session_id,
            auth_key=auth_key,
            new_nonce=hs.new_nonce,
            server_nonce=hs.server_nonce,
        )
        logger.info(
            "handshake completed: session_id=%s auth_key_id=%s",
            request.session_id,
            session.auth_key_id,
        )

        nnh1 = _new_nonce_hash(hs.new_nonce, 1, auth_key_aux_hash)

        return TlResponse(
            req_msg_id=request.req_msg_id,
            result={
                "constructor": "dh_gen_ok",
                "nonce": hs.nonce,
                "server_nonce": hs.server_nonce,
                "new_nonce_hash1": nnh1,
            },
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _dh_gen_fail(self, request: TlRequest, hs, reason: str = "UNKNOWN") -> TlResponse:
        logger.warning(
            "handshake dh_gen_fail: stage=%s reason=%s",
            hs.stage,
            reason,
        )
        nnh3 = 0
        if hs.new_nonce is not None:
            nnh3 = _new_nonce_hash(hs.new_nonce, 3, 0)
        return TlResponse(
            req_msg_id=request.req_msg_id,
            result={
                "constructor": "dh_gen_fail",
                "nonce": hs.nonce or 0,
                "server_nonce": hs.server_nonce or 0,
                "new_nonce_hash3": nnh3,
            },
        )

    @staticmethod
    def _error_response(request: TlRequest, message: str) -> TlResponse:
        logger.warning(
            "handshake error response: session_id=%s constructor=%s error=%s",
            request.session_id,
            request.constructor,
            message,
        )
        return TlResponse(
            req_msg_id=request.req_msg_id,
            result={},
            error_code=400,
            error_message=message,
        )

    @staticmethod
    def _log_handshake_response(request: TlRequest, response: TlResponse) -> None:
        if response.error_code is not None:
            logger.warning(
                "handshake step failed: session_id=%s constructor=%s error_code=%s error_message=%s",
                request.session_id,
                request.constructor,
                response.error_code,
                response.error_message,
            )
            return
        result_constructor = (
            response.result.get("constructor")
            if isinstance(response.result, dict)
            else None
        )
        logger.info(
            "handshake step sent: session_id=%s constructor=%s response_constructor=%s",
            request.session_id,
            request.constructor,
            result_constructor,
        )
