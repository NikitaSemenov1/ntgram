from __future__ import annotations

import hashlib
import secrets
import struct
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from ntgram.gateway.mtproto.session_store import AuthSession


class EncryptedLayerError(ValueError):
    """Raised when encrypted MTProto envelope is invalid."""

    def __init__(
        self,
        message: str,
        *,
        error_code: int | None = None,
        bad_msg_id: int = 0,
        bad_msg_seqno: int = 0,
        new_server_salt: int | None = None,
        context_session_id: int | None = None,
    ) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.bad_msg_id = bad_msg_id
        self.bad_msg_seqno = bad_msg_seqno
        self.new_server_salt = new_server_salt
        self.context_session_id = context_session_id


def _xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def _aes_ige_encrypt_blockwise(data: bytes, key: bytes, iv: bytes) -> bytes:
    if len(data) % 16 != 0 or len(iv) != 32:
        raise EncryptedLayerError("invalid IGE encryption input")
    cipher = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    c_prev = iv[:16]
    p_prev = iv[16:]
    out = bytearray()
    for offset in range(0, len(data), 16):
        block = data[offset : offset + 16]
        x = _xor_bytes(block, c_prev)
        y = cipher.update(x)
        c = _xor_bytes(y, p_prev)
        out.extend(c)
        c_prev = c
        p_prev = block
    return bytes(out)


def _aes_ige_decrypt_blockwise(data: bytes, key: bytes, iv: bytes) -> bytes:
    if len(data) % 16 != 0 or len(iv) != 32:
        raise EncryptedLayerError("invalid IGE decryption input")
    cipher = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    c_prev = iv[:16]
    p_prev = iv[16:]
    out = bytearray()
    for offset in range(0, len(data), 16):
        block = data[offset : offset + 16]
        x = _xor_bytes(block, p_prev)
        y = cipher.update(x)
        p = _xor_bytes(y, c_prev)
        out.extend(p)
        c_prev = block
        p_prev = p
    return bytes(out)


def _kdf_aes_key_iv(auth_key: bytes, msg_key: bytes, x: int) -> tuple[bytes, bytes]:
    if len(auth_key) < 128:
        raise EncryptedLayerError("auth_key too short")
    if len(msg_key) != 16:
        raise EncryptedLayerError("msg_key must be 16 bytes")
    sha256_a = hashlib.sha256(msg_key + auth_key[x : x + 36]).digest()
    sha256_b = hashlib.sha256(auth_key[40 + x : 40 + x + 36] + msg_key).digest()
    aes_key = sha256_a[:8] + sha256_b[8:24] + sha256_a[24:32]
    aes_iv = sha256_b[:8] + sha256_a[8:24] + sha256_b[24:32]
    return aes_key, aes_iv


def _kdf_v1_aes_key_iv(auth_key: bytes, msg_key: bytes, x: int) -> tuple[bytes, bytes]:
    """MTProto v1 AES key/IV derivation used by auth.bindTempAuthKey."""
    if len(auth_key) < 128:
        raise EncryptedLayerError("auth_key too short")
    if len(msg_key) != 16:
        raise EncryptedLayerError("msg_key must be 16 bytes")
    sha1_a = hashlib.sha1(msg_key + auth_key[x : x + 32]).digest()
    sha1_b = hashlib.sha1(
        auth_key[32 + x : 48 + x]
        + msg_key
        + auth_key[48 + x : 64 + x],
    ).digest()
    sha1_c = hashlib.sha1(auth_key[64 + x : 96 + x] + msg_key).digest()
    sha1_d = hashlib.sha1(msg_key + auth_key[96 + x : 128 + x]).digest()
    aes_key = sha1_a[:8] + sha1_b[8:20] + sha1_c[4:16]
    aes_iv = sha1_a[8:20] + sha1_b[:8] + sha1_c[16:20] + sha1_d[:8]
    return aes_key, aes_iv


def _compute_msg_key(auth_key: bytes, plaintext: bytes, x: int) -> bytes:
    digest = hashlib.sha256(auth_key[88 + x : 88 + x + 32] + plaintext).digest()
    return digest[8:24]


def _compute_v1_msg_key(plaintext: bytes) -> bytes:
    """MTProto v1 msg_key is the lower 128 bits of SHA1(plaintext)."""
    return hashlib.sha1(plaintext).digest()[4:20]


def _validate_client_msg_id(msg_id: int, seq_no: int = 0) -> None:
    now = int(time.time())
    msg_time = msg_id >> 32
    if msg_time < now - 300:
        raise EncryptedLayerError(
            "msg_id too low",
            error_code=16,
            bad_msg_id=msg_id,
            bad_msg_seqno=seq_no,
        )
    if msg_time > now + 30:
        raise EncryptedLayerError(
            "msg_id too high",
            error_code=17,
            bad_msg_id=msg_id,
            bad_msg_seqno=seq_no,
        )
    if msg_id % 4 != 0:
        raise EncryptedLayerError(
            "msg_id parity violation",
            error_code=18,
            bad_msg_id=msg_id,
            bad_msg_seqno=seq_no,
        )
    if (msg_id & 0xFFFFFFFF) == 0:
        raise EncryptedLayerError(
            "msg_id fractional part is empty",
            error_code=18,
            bad_msg_id=msg_id,
            bad_msg_seqno=seq_no,
        )


def _validate_server_msg_id(msg_id: int) -> None:
    if msg_id % 4 not in (1, 3):
        raise EncryptedLayerError("server msg_id parity violation")


def encode_encrypted_message(
    session: AuthSession,
    session_id: int,
    msg_id: int,
    seq_no: int,
    message_data: bytes,
    direction: str = "client",
) -> bytes:
    if direction == "server":
        _validate_server_msg_id(msg_id)
    else:
        _validate_client_msg_id(msg_id, seq_no)
    data_len = len(message_data)
    header = (
        struct.pack("<Q", session.server_salt)
        + struct.pack("<Q", session_id)
        + struct.pack("<Q", msg_id)
        + struct.pack("<I", seq_no)
        + struct.pack("<I", data_len)
    )
    plaintext = header + message_data
    pad_len = 16 - (len(plaintext) % 16)
    if pad_len < 12:
        pad_len += 16
    plaintext += secrets.token_bytes(pad_len)
    x = 8 if direction == "server" else 0
    msg_key = _compute_msg_key(session.auth_key, plaintext, x=x)
    aes_key, aes_iv = _kdf_aes_key_iv(session.auth_key, msg_key, x=x)
    encrypted = _aes_ige_encrypt_blockwise(plaintext, aes_key, aes_iv)
    return struct.pack("<Q", session.auth_key_id) + msg_key + encrypted


def encode_bind_temp_auth_key_inner_message(
    session: AuthSession,
    *,
    msg_id: int,
    message_data: bytes,
    random_bytes: bytes | None = None,
) -> bytes:
    """Encode auth.bindTempAuthKey encrypted_message per MTProto v1 spec.

    This helper mirrors the client-side format documented for the method and is
    primarily useful for tests.
    """
    if random_bytes is None:
        random_bytes = secrets.token_bytes(16)
    if len(random_bytes) != 16:
        raise EncryptedLayerError("bind random must be int128")
    if len(message_data) != 40:
        raise EncryptedLayerError("bind_auth_key_inner must be 40 bytes")
    _validate_client_msg_id(msg_id, 0)
    plaintext_body = (
        random_bytes
        + struct.pack("<Q", msg_id)
        + struct.pack("<I", 0)
        + struct.pack("<I", len(message_data))
        + message_data
    )
    msg_key = _compute_v1_msg_key(plaintext_body)
    pad_len = (16 - (len(plaintext_body) % 16)) % 16
    if pad_len:
        plaintext = plaintext_body + secrets.token_bytes(pad_len)
    else:
        plaintext = plaintext_body
    aes_key, aes_iv = _kdf_v1_aes_key_iv(session.auth_key, msg_key, x=0)
    encrypted = _aes_ige_encrypt_blockwise(plaintext, aes_key, aes_iv)
    return struct.pack("<Q", session.auth_key_id) + msg_key + encrypted


def decode_bind_temp_auth_key_inner_message(
    session: AuthSession,
    payload: bytes,
    *,
    expected_msg_id: int,
) -> tuple[int, int, bytes]:
    """Decode auth.bindTempAuthKey encrypted_message per MTProto v1 spec."""
    if len(payload) < 24:
        raise EncryptedLayerError("encrypted payload too short")
    auth_key_id = struct.unpack("<Q", payload[:8])[0]
    if auth_key_id != session.auth_key_id:
        raise EncryptedLayerError("auth_key_id mismatch")
    msg_key = payload[8:24]
    ciphertext = payload[24:]
    if len(ciphertext) == 0 or len(ciphertext) % 16 != 0:
        raise EncryptedLayerError("invalid encrypted body size")
    aes_key, aes_iv = _kdf_v1_aes_key_iv(session.auth_key, msg_key, x=0)
    plaintext = _aes_ige_decrypt_blockwise(ciphertext, aes_key, aes_iv)
    if len(plaintext) < 32:
        raise EncryptedLayerError("plaintext too short")

    msg_id = struct.unpack("<Q", plaintext[16:24])[0]
    seq_no = struct.unpack("<I", plaintext[24:28])[0]
    message_data_length = struct.unpack("<I", plaintext[28:32])[0]
    if msg_id != expected_msg_id:
        raise EncryptedLayerError("bind msg_id mismatch")
    if seq_no != 0:
        raise EncryptedLayerError("bind seq_no must be zero")
    if message_data_length != 40:
        raise EncryptedLayerError("bind message_data_length must be 40")
    if 32 + message_data_length > len(plaintext):
        raise EncryptedLayerError("bad bind message_data_length")

    signed_plaintext = plaintext[: 32 + message_data_length]
    expected_msg_key = _compute_v1_msg_key(signed_plaintext)
    if expected_msg_key != msg_key:
        raise EncryptedLayerError("msg_key mismatch")
    padding_len = len(plaintext) - len(signed_plaintext)
    if padding_len >= 16:
        raise EncryptedLayerError("bad bind padding length")
    _validate_client_msg_id(msg_id, seq_no)
    return msg_id, seq_no, plaintext[32 : 32 + message_data_length]


def decode_encrypted_message(session: AuthSession, payload: bytes) -> tuple[int, int, int, bytes]:
    if len(payload) < 24:
        raise EncryptedLayerError("encrypted payload too short")
    auth_key_id = struct.unpack("<Q", payload[:8])[0]
    if auth_key_id != session.auth_key_id:
        raise EncryptedLayerError("auth_key_id mismatch")
    msg_key = payload[8:24]
    ciphertext = payload[24:]
    if len(ciphertext) == 0 or len(ciphertext) % 16 != 0:
        raise EncryptedLayerError("invalid encrypted body size")
    aes_key, aes_iv = _kdf_aes_key_iv(session.auth_key, msg_key, x=0)
    plaintext = _aes_ige_decrypt_blockwise(ciphertext, aes_key, aes_iv)
    expected_msg_key = _compute_msg_key(session.auth_key, plaintext, x=0)
    if expected_msg_key != msg_key:
        raise EncryptedLayerError("msg_key mismatch")
    if len(plaintext) < 32:
        raise EncryptedLayerError("plaintext too short")

    server_salt = struct.unpack("<Q", plaintext[:8])[0]
    session_id = struct.unpack("<Q", plaintext[8:16])[0]
    msg_id = struct.unpack("<Q", plaintext[16:24])[0]
    seq_no = struct.unpack("<I", plaintext[24:28])[0]
    message_data_length = struct.unpack("<I", plaintext[28:32])[0]
    if not session.is_accepted_server_salt(server_salt):
        raise EncryptedLayerError(
            "bad_server_salt",
            error_code=48,
            bad_msg_id=msg_id,
            bad_msg_seqno=seq_no,
            new_server_salt=session.server_salt,
            context_session_id=session_id,
        )
    if not session.bind_mtproto_session(session_id):
        raise EncryptedLayerError(
            "session_id mismatch",
            error_code=64,
            bad_msg_id=msg_id,
            bad_msg_seqno=seq_no,
        )
    if message_data_length % 4 != 0 or 32 + message_data_length > len(plaintext):
        raise EncryptedLayerError(
            "bad message_data_length",
            error_code=64,
            bad_msg_id=msg_id,
            bad_msg_seqno=seq_no,
        )
    padding_len = len(plaintext) - 32 - message_data_length
    if padding_len < 12 or padding_len > 1024:
        raise EncryptedLayerError(
            "bad padding length",
            error_code=64,
            bad_msg_id=msg_id,
            bad_msg_seqno=seq_no,
        )
    _validate_client_msg_id(msg_id, seq_no)
    message_data = plaintext[32 : 32 + message_data_length]
    if not session.touch_msg_id(msg_id):
        raise EncryptedLayerError(
            "replay_or_old_msg_id",
            error_code=16,
            bad_msg_id=msg_id,
            bad_msg_seqno=seq_no,
        )
    return session_id, msg_id, seq_no, message_data

