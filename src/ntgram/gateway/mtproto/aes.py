from __future__ import annotations

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class AesIgeError(ValueError):
    """Raised on malformed AES-IGE input (block-size or IV-length violations)."""


def xor_bytes(left: bytes, right: bytes) -> bytes:
    """Pairwise XOR of two equal-length byte strings."""
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def aes_ige_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-256-IGE encryption."""
    if len(data) % 16 != 0 or len(iv) != 32:
        raise AesIgeError("invalid IGE encryption input")
    cipher = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    c_prev = iv[:16]
    p_prev = iv[16:]
    out = bytearray()
    for offset in range(0, len(data), 16):
        block = data[offset : offset + 16]
        x = xor_bytes(block, c_prev)
        y = cipher.update(x)
        c = xor_bytes(y, p_prev)
        out.extend(c)
        c_prev = c
        p_prev = block
    return bytes(out)


def aes_ige_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-256-IGE decryption (inverse of `aes_ige_encrypt`)."""
    if len(data) % 16 != 0 or len(iv) != 32:
        raise AesIgeError("invalid IGE decryption input")
    cipher = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    c_prev = iv[:16]
    p_prev = iv[16:]
    out = bytearray()
    for offset in range(0, len(data), 16):
        block = data[offset : offset + 16]
        x = xor_bytes(block, p_prev)
        y = cipher.update(x)
        p = xor_bytes(y, c_prev)
        out.extend(p)
        c_prev = block
        p_prev = p
    return bytes(out)
