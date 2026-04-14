"""RSA_PAD server-side decryption for MTProto auth key exchange.

Implements the reverse of RSA_PAD as described in:
https://core.telegram.org/mtproto/auth_key  (section 4.1)

Client-side RSA_PAD (encrypt):
  1. data_with_padding = data + random_padding (total 192 bytes)
  2. data_pad_reversed = BYTE_REVERSE(data_with_padding)
  3. temp_key = random 32 bytes
  4. data_with_hash = data_pad_reversed + SHA256(temp_key + data_with_padding)  (224 bytes)
  5. aes_encrypted = AES256_IGE(data_with_hash, temp_key, iv=0)  (224 bytes)
  6. temp_key_xor = temp_key XOR SHA256(aes_encrypted)  (32 bytes)
  7. key_aes_encrypted = temp_key_xor + aes_encrypted  (256 bytes)
  8. encrypted_data = RSA(key_aes_encrypted, server_pubkey)  (256 bytes)

Server-side decrypt (this module) reverses steps 8..1.
"""
from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives.asymmetric import rsa

from ntgram.gateway.mtproto.encrypted_layer import (
    _aes_ige_decrypt_blockwise,
    _xor_bytes,
)


class RsaPadError(ValueError):
    pass


def rsa_pad_decrypt(
    encrypted_data: bytes,
    private_key: rsa.RSAPrivateKey,
) -> bytes:
    """Decrypt RSA_PAD encrypted data (server side).

    Returns the original TL-serialized p_q_inner_data (up to 144 bytes).
    """
    if len(encrypted_data) != 256:
        raise RsaPadError(f"encrypted_data must be 256 bytes, got {len(encrypted_data)}")

    # Step 8 reverse: raw RSA decrypt (modular exponentiation with private exponent)
    priv_numbers = private_key.private_numbers()
    n = priv_numbers.public_numbers.n
    d = priv_numbers.d
    enc_int = int.from_bytes(encrypted_data, "big")
    dec_int = pow(enc_int, d, n)
    key_aes_encrypted = dec_int.to_bytes(256, "big")

    # Step 7 reverse: split into temp_key_xor (32) + aes_encrypted (224)
    temp_key_xor = key_aes_encrypted[:32]
    aes_encrypted = key_aes_encrypted[32:]

    # Step 6 reverse: recover temp_key
    temp_key = _xor_bytes(temp_key_xor, hashlib.sha256(aes_encrypted).digest())

    # Step 5 reverse: AES-IGE decrypt with zero IV
    zero_iv = b"\x00" * 32
    data_with_hash = _aes_ige_decrypt_blockwise(aes_encrypted, temp_key, zero_iv)

    # Step 4 reverse: data_with_hash = data_pad_reversed (192) + sha256_hash (32)
    data_pad_reversed = data_with_hash[:192]
    expected_hash = data_with_hash[192:]

    # Step 2 reverse: recover data_with_padding
    data_with_padding = bytes(reversed(data_pad_reversed))

    computed_hash = hashlib.sha256(temp_key + data_with_padding).digest()
    if computed_hash != expected_hash:
        raise RsaPadError("RSA_PAD hash verification failed")

    return data_with_padding


def rsa_pad_encrypt(
    data: bytes,
    public_key: rsa.RSAPublicKey,
) -> bytes:
    """Encrypt using RSA_PAD (client side). Used for testing."""
    import os

    if len(data) > 144:
        raise RsaPadError(f"data too long: {len(data)} > 144")

    pub_numbers = public_key.public_numbers()
    n = pub_numbers.n
    e = pub_numbers.e

    while True:
        # Step 1
        padding_len = 192 - len(data)
        data_with_padding = data + os.urandom(padding_len)

        # Step 2
        data_pad_reversed = bytes(reversed(data_with_padding))

        # Step 3
        temp_key = os.urandom(32)

        # Step 4
        hash_val = hashlib.sha256(temp_key + data_with_padding).digest()
        data_with_hash = data_pad_reversed + hash_val

        # Step 5
        zero_iv = b"\x00" * 32
        from ntgram.gateway.mtproto.encrypted_layer import _aes_ige_encrypt_blockwise
        aes_encrypted = _aes_ige_encrypt_blockwise(data_with_hash, temp_key, zero_iv)

        # Step 6
        temp_key_xor = _xor_bytes(temp_key, hashlib.sha256(aes_encrypted).digest())

        # Step 7
        key_aes_encrypted = temp_key_xor + aes_encrypted

        # Step 8: check that it's less than n
        as_int = int.from_bytes(key_aes_encrypted, "big")
        if as_int >= n:
            continue

        encrypted = pow(as_int, e, n)
        return encrypted.to_bytes(256, "big")
