from __future__ import annotations

import hashlib
import struct
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from ntgram.gateway.mtproto.session_store import AuthSession


class EncryptedLayerError(ValueError):
    """Raised when encrypted MTProto envelope is invalid."""


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


def _compute_msg_key(auth_key: bytes, plaintext: bytes, x: int) -> bytes:
    digest = hashlib.sha256(auth_key[88 + x : 88 + x + 32] + plaintext).digest()
    return digest[8:24]


def _validate_msg_id(msg_id: int) -> None:
    now = int(time.time())
    msg_time = msg_id >> 32
    if msg_time < now - 300 or msg_time > now + 30:
        raise EncryptedLayerError("msg_id time window violation")
    if msg_id % 4 != 0:
        raise EncryptedLayerError("msg_id parity violation")


def encode_encrypted_message(
    session: AuthSession,
    session_id: int,
    msg_id: int,
    seq_no: int,
    message_data: bytes,
    direction: str = "client",
) -> bytes:
    _validate_msg_id(msg_id)
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
    plaintext += b"\x00" * pad_len
    x = 8 if direction == "server" else 0
    msg_key = _compute_msg_key(session.auth_key, plaintext, x=x)
    aes_key, aes_iv = _kdf_aes_key_iv(session.auth_key, msg_key, x=x)
    encrypted = _aes_ige_encrypt_blockwise(plaintext, aes_key, aes_iv)
    return struct.pack("<Q", session.auth_key_id) + msg_key + encrypted


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
    if server_salt != session.server_salt:
        raise EncryptedLayerError("bad_server_salt")
    session_id = struct.unpack("<Q", plaintext[8:16])[0]
    msg_id = struct.unpack("<Q", plaintext[16:24])[0]
    seq_no = struct.unpack("<I", plaintext[24:28])[0]
    message_data_length = struct.unpack("<I", plaintext[28:32])[0]
    if message_data_length < 0 or 32 + message_data_length > len(plaintext):
        raise EncryptedLayerError("bad message_data_length")
    _validate_msg_id(msg_id)
    message_data = plaintext[32 : 32 + message_data_length]
    if not session.touch_msg_id(msg_id):
        raise EncryptedLayerError("replay_or_old_msg_id")
    return session_id, msg_id, seq_no, message_data

