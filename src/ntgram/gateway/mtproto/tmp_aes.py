"""Temporary AES key/IV derivation for MTProto handshake.

Used to encrypt server_DH_inner_data and decrypt client_DH_inner_data
during the auth key exchange.

From https://core.telegram.org/mtproto/auth_key (step 6):
  tmp_aes_key := SHA1(new_nonce + server_nonce) + substr(SHA1(server_nonce + new_nonce), 0, 12)
  tmp_aes_iv  := substr(SHA1(server_nonce + new_nonce), 12, 8) + SHA1(new_nonce + new_nonce) + substr(new_nonce, 0, 4)
"""
from __future__ import annotations

import hashlib

from ntgram.gateway.mtproto.encrypted_layer import (
    _aes_ige_decrypt_blockwise,
    _aes_ige_encrypt_blockwise,
)


def _nonce_bytes(nonce: int, length: int) -> bytes:
    """Convert a nonce integer to bytes (little-endian) of given length."""
    return nonce.to_bytes(length, "little")


def compute_tmp_aes_key_iv(
    server_nonce: int,
    new_nonce: int,
) -> tuple[bytes, bytes]:
    """Derive tmp_aes_key (32 bytes) and tmp_aes_iv (32 bytes) from nonces.

    server_nonce: 128-bit integer
    new_nonce: 256-bit integer
    """
    sn = _nonce_bytes(server_nonce, 16)
    nn = _nonce_bytes(new_nonce, 32)

    sha1_nn_sn = hashlib.sha1(nn + sn).digest()  # 20 bytes
    sha1_sn_nn = hashlib.sha1(sn + nn).digest()  # 20 bytes
    sha1_nn_nn = hashlib.sha1(nn + nn).digest()  # 20 bytes

    tmp_aes_key = sha1_nn_sn + sha1_sn_nn[:12]  # 32 bytes
    tmp_aes_iv = sha1_sn_nn[12:] + sha1_nn_nn + nn[:4]  # 8 + 20 + 4 = 32 bytes

    return tmp_aes_key, tmp_aes_iv


def tmp_aes_encrypt(data: bytes, server_nonce: int, new_nonce: int) -> bytes:
    """AES-256-IGE encrypt using tmp_aes_key/iv derived from nonces."""
    key, iv = compute_tmp_aes_key_iv(server_nonce, new_nonce)
    return _aes_ige_encrypt_blockwise(data, key, iv)


def tmp_aes_decrypt(data: bytes, server_nonce: int, new_nonce: int) -> bytes:
    """AES-256-IGE decrypt using tmp_aes_key/iv derived from nonces."""
    key, iv = compute_tmp_aes_key_iv(server_nonce, new_nonce)
    return _aes_ige_decrypt_blockwise(data, key, iv)
