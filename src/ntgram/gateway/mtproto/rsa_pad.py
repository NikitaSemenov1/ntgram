from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives.asymmetric import rsa

from ntgram.gateway.mtproto.aes import (
    aes_ige_decrypt,
    aes_ige_encrypt,
    xor_bytes,
)


class RsaPadError(ValueError):
    pass


def rsa_pad_decrypt(
    encrypted_data: bytes,
    private_key: rsa.RSAPrivateKey,
) -> bytes:
    """Decrypt RSA_PAD encrypted data (server side)."""
    if len(encrypted_data) != 256:
        raise RsaPadError(f"encrypted_data must be 256 bytes, got {len(encrypted_data)}")

    # raw RSA decrypt (modular exponentiation with private exponent)
    priv_numbers = private_key.private_numbers()
    n = priv_numbers.public_numbers.n
    d = priv_numbers.d
    enc_int = int.from_bytes(encrypted_data, "big")
    dec_int = pow(enc_int, d, n)
    key_aes_encrypted = dec_int.to_bytes(256, "big")

    # split into temp_key_xor (32) + aes_encrypted (224)
    temp_key_xor = key_aes_encrypted[:32]
    aes_encrypted = key_aes_encrypted[32:]

    # recover temp_key
    temp_key = xor_bytes(temp_key_xor, hashlib.sha256(aes_encrypted).digest())

    # AES-IGE decrypt with zero IV
    zero_iv = b"\x00" * 32
    data_with_hash = aes_ige_decrypt(aes_encrypted, temp_key, zero_iv)

    # data_with_hash = data_pad_reversed (192) + sha256_hash (32)
    data_pad_reversed = data_with_hash[:192]
    expected_hash = data_with_hash[192:]

    # recover data_with_padding
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
        padding_len = 192 - len(data)
        data_with_padding = data + os.urandom(padding_len)

        data_pad_reversed = bytes(reversed(data_with_padding))

        temp_key = os.urandom(32)

        hash_val = hashlib.sha256(temp_key + data_with_padding).digest()
        data_with_hash = data_pad_reversed + hash_val

        zero_iv = b"\x00" * 32
        aes_encrypted = aes_ige_encrypt(data_with_hash, temp_key, zero_iv)

        temp_key_xor = xor_bytes(temp_key, hashlib.sha256(aes_encrypted).digest())

        key_aes_encrypted = temp_key_xor + aes_encrypted

        as_int = int.from_bytes(key_aes_encrypted, "big")
        if as_int >= n:
            continue

        encrypted = pow(as_int, e, n)
        return encrypted.to_bytes(256, "big")
