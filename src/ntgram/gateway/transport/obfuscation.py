from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


INIT_PAYLOAD_LEN = 64
OBFUSCATED_ABRIDGED_PROTOCOL_ID = b"\xef\xef\xef\xef"
_FORBIDDEN_PREFIXES = {
    b"HEAD",
    b"POST",
    b"GET ",
    b"OPTI",
    b"\xdd\xdd\xdd\xdd",
    b"\xee\xee\xee\xee",
}


@dataclass(slots=True, frozen=True)
class ObfuscationSession:
    protocol_id: bytes
    encrypt: Callable[[bytes], bytes]
    decrypt: Callable[[bytes], bytes]


class ObfuscationProtocolError(RuntimeError):
    """Raised when MTProto transport obfuscation payload is invalid."""


def _new_ctr_encryptor(key: bytes, iv: bytes):
    return Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()


def _new_ctr_decryptor(key: bytes, iv: bytes):
    return Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()


def _validate_wire_init(init_payload: bytes) -> None:
    prefix = init_payload[:4]
    if prefix in _FORBIDDEN_PREFIXES:
        raise ObfuscationProtocolError("forbidden obfuscation init prefix")
    if init_payload[0] == 0xEF:
        raise ObfuscationProtocolError("obfuscation init collides with abridged marker")
    if init_payload[4:8] == b"\x00\x00\x00\x00":
        raise ObfuscationProtocolError("obfuscation init has zero transport bytes")


def parse_obfuscation_init(init_payload: bytes) -> ObfuscationSession:
    """Parse MTProto transport obfuscation init payload.

    Returns stateful callables to encrypt/decrypt subsequent transport bytes.
    """
    if len(init_payload) != INIT_PAYLOAD_LEN:
        raise ObfuscationProtocolError(
            f"invalid obfuscation init length: {len(init_payload)}",
        )

    inbound_key = init_payload[8:40]
    inbound_iv = init_payload[40:56]
    reversed_init = init_payload[::-1]
    outbound_key = reversed_init[8:40]
    outbound_iv = reversed_init[40:56]

    _validate_wire_init(init_payload)

    decryptor = _new_ctr_decryptor(inbound_key, inbound_iv)
    decryptor.update(init_payload[:56])
    decrypted_tail = decryptor.update(init_payload[56:64])
    protocol_id = decrypted_tail[:4]
    if protocol_id != OBFUSCATED_ABRIDGED_PROTOCOL_ID:
        raise ObfuscationProtocolError(
            "unsupported obfuscated transport protocol identifier",
        )

    encryptor = _new_ctr_encryptor(outbound_key, outbound_iv)
    return ObfuscationSession(
        protocol_id=protocol_id,
        encrypt=encryptor.update,
        decrypt=decryptor.update,
    )
